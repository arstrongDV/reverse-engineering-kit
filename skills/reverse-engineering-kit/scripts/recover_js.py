#!/usr/bin/env python3
"""Recover readable JavaScript from a bundle, a source map, an asar archive or an Electron app
into decompiled/js/, and map an Electron app's IPC channels and risky settings.

Never fetches anything: a source map on a server is listed, not downloaded."""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import struct
from pathlib import Path

from _common import (
    EXIT_MISSING_TOOL,
    EXIT_OK,
    EXIT_UNSUPPORTED,
    EXIT_USAGE,
    KitError,
    add_work_flag,
    build_parser,
    emit,
    fail,
    resolve_work_dir,
    run_tool,
    safe_file_name,
    stage_input,
    tail,
    write_atomic,
)
from doctor import TOOLS, this_os
from triage import HEAD_SIZE, MINIFIED_LINE_LENGTH, clean, identify, triage_target

JS_TYPES = ("javascript", "source-map", "asar", "electron-app")
JS_SUFFIXES = (".js", ".mjs", ".cjs")
SKIP_FOLDERS = {"node_modules", ".git"}
MAX_FILES = 5000
MAX_EXTRACT = 2 * 1024**3
MAX_SOURCE_MAP = 64 * 1024 * 1024
MAX_WEBCRACK = 20
TIMEOUT = 600
SHOWN = 15
WINDOWS_RESERVED = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{n}" for n in range(10)),
    *(f"lpt{n}" for n in range(10)),
}

SOURCE_MAP_URL = re.compile(r"[#@]\s*sourceMappingURL=(\S+)")
IPC_MAIN = re.compile(r"ipcMain\.(handle|handleOnce|on|once)\(\s*[\"'`]([^\"'`]{1,100})[\"'`]")
IPC_RENDERER = re.compile(
    r"ipcRenderer\.(invoke|send|sendSync|on|once|postMessage)\(\s*[\"'`]([^\"'`]{1,100})[\"'`]"
)
BRIDGE = re.compile(r"contextBridge\.exposeInMainWorld\(\s*[\"'`]([^\"'`]{1,100})[\"'`]")
PRELOAD = re.compile(
    r"preload\s*:\s*(?:path\.(?:join|resolve)\([^)]{0,120}?)?[\"'`]([^\"'`]{1,120}\.js)[\"'`]"
)
RISKY = (
    (re.compile(r"nodeIntegration\s*:\s*(?:true|!0)"), "nodeIntegration is on"),
    (re.compile(r"contextIsolation\s*:\s*(?:false|!1)"), "contextIsolation is off"),
    (re.compile(r"webSecurity\s*:\s*(?:false|!1)"), "webSecurity is off"),
    (re.compile(r"sandbox\s*:\s*(?:false|!1)"), "sandbox is off"),
    (re.compile(r"allowRunningInsecureContent\s*:\s*(?:true|!0)"), "insecure content is allowed"),
    (re.compile(r"shell\.openExternal\("), "opens URLs with shell.openExternal"),
    (re.compile(r"setAsDefaultProtocolClient\(|registerFileProtocol\("), "registers a protocol"),
)


def pick_target(work: Path, given: str | None) -> tuple[Path, str]:
    candidates = [Path(given)] if given else sorted((work / "original").glob("*"))
    found = []
    for path in candidates:
        if not path.exists():
            continue
        kind = triage_target(path)["type"] if path.is_dir() else file_type(path)
        if kind in JS_TYPES or (path.is_dir() and given):
            found.append((path, kind))
        elif given:
            raise KitError(
                f"{path.name} is {kind}, not JavaScript or an Electron app", EXIT_UNSUPPORTED
            )
    if given and not found:
        raise KitError(f"{given} does not exist")
    if len(found) != 1:
        names = ", ".join(path.name for path, _ in found) or "none"
        raise KitError(
            f"name the bundle or app (JavaScript targets in original/: {names})", EXIT_USAGE
        )
    return found[0]


def file_type(path: Path) -> str:
    with path.open("rb") as file:
        return identify(path, file.read(HEAD_SIZE))["type"]


def safe_parts(name: str) -> list[str] | None:
    """Return the path parts an archive entry may use, or None if it could leave the folder."""
    parts = re.split(r"[\\/]", name)
    if any(part in ("", ".", "..") or ":" in part or "\0" in part for part in parts):
        return None
    return [
        part + "_" if part.lower().split(".")[0] in WINDOWS_RESERVED else part for part in parts
    ]


def read_asar_header(path: Path) -> tuple[dict, int]:
    with path.open("rb") as file:
        head = file.read(16)
        if len(head) < 16 or head[:4] != b"\x04\0\0\0":
            raise KitError(f"{path.name} is not an asar archive", EXIT_UNSUPPORTED)
        pickle_size, _, length = struct.unpack_from("<III", head, 4)
        if length > min(path.stat().st_size, MAX_SOURCE_MAP):
            raise KitError(
                f"{path.name} claims a file table larger than the file", EXIT_UNSUPPORTED
            )
        tree = json.loads(file.read(length))
    return tree, 8 + pickle_size


def extract_asar(path: Path, target: Path) -> tuple[int, list[str]]:
    """Extract with the checks the asar tool lacks: every path stays inside the target folder."""
    tree, data_start = read_asar_header(path)
    size = path.stat().st_size
    unpacked = path.with_name(path.name + ".unpacked")
    shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True)
    root = target.resolve()
    written, total, skipped = 0, 0, []
    stack = [([], tree)]
    with path.open("rb") as archive:
        while stack:
            prefix, node = stack.pop()
            for name, entry in (node.get("files") or {}).items():
                parts = safe_parts(name)
                if parts is None or not isinstance(entry, dict):
                    skipped.append(f"unsafe name {clean(name)!r}")
                    continue
                relative = [*prefix, *parts]
                if "files" in entry:
                    stack.append((relative, entry))
                    continue
                destination = target.joinpath(*relative)
                if root not in destination.resolve().parents:
                    skipped.append(f"path outside the folder: {clean('/'.join(relative))}")
                    continue
                if "link" in entry:
                    skipped.append(f"link not followed: {clean('/'.join(relative))}")
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                length = int(entry.get("size", 0))
                if entry.get("unpacked"):
                    source = unpacked.joinpath(*relative)
                    if source.is_file() and not source.is_symlink():
                        shutil.copyfile(source, destination)
                    else:
                        skipped.append(f"unpacked file missing: {clean('/'.join(relative))}")
                    continue
                start = data_start + int(entry.get("offset", 0))
                if start + length > size or total + length > MAX_EXTRACT:
                    skipped.append(
                        f"entry beyond the end of the archive: {clean('/'.join(relative))}"
                    )
                    continue
                archive.seek(start)
                destination.write_bytes(archive.read(length))
                written += 1
                total += length
    return written, skipped


def js_files(folder: Path) -> list[Path]:
    found = []
    for directory, folders, names in os.walk(folder):
        folders[:] = [name for name in folders if name not in SKIP_FOLDERS]
        found += [Path(directory) / name for name in names if name.endswith(JS_SUFFIXES)]
        if len(found) >= MAX_FILES:
            break
    return sorted(found)[:MAX_FILES]


def unquote(text: str) -> str:
    return re.sub(r"%([0-9A-Fa-f]{2})", lambda match: chr(int(match[1], 16)), text)


def load_source_map(script: Path, text: str, root: Path) -> tuple[dict | None, str | None]:
    # The last comment wins, as in browsers: a bundler appends its own after any earlier one.
    references = SOURCE_MAP_URL.findall(text)
    sibling = script.with_name(script.name + ".map")
    reference = references[-1] if references else sibling.name if sibling.is_file() else None
    if not reference:
        return None, None
    if reference.startswith("data:"):
        header, _, body = reference.partition(",")
        raw = base64.b64decode(body) if header.endswith(";base64") else unquote(body)
        return json.loads(raw), "inline"
    if re.match(r"[a-z][a-z0-9+.-]*://", reference, re.IGNORECASE):
        return None, f"remote, not fetched: {clean(reference)[:120]}"
    path = (script.parent / unquote(reference.split("?")[0])).resolve()
    if root.resolve() not in path.parents or not path.is_file():
        return None, f"missing: {clean(reference)[:120]}"
    if path.stat().st_size > MAX_SOURCE_MAP:
        return None, f"too large: {clean(reference)[:120]}"
    return json.loads(path.read_text("utf-8", errors="replace")), path.name


def write_sources(source_map: dict, target: Path) -> tuple[int, int]:
    """Write each original source a map carries, with paths cleaned so none leaves the folder."""
    sources = source_map.get("sources") or []
    contents = source_map.get("sourcesContent") or []
    written = 0
    for index, name in enumerate(sources):
        content = contents[index] if index < len(contents) else None
        if not isinstance(content, str) or not isinstance(name, str):
            continue
        name = re.sub(r"^[a-z]+:/*", "", name)
        parts = [
            safe_file_name(part) for part in re.split(r"[\\/]", name) if part not in ("", ".", "..")
        ]
        destination = target.joinpath(*(parts or [f"source_{index}.js"]))
        if destination.exists():
            destination = destination.with_name(f"{destination.stem}_{index}{destination.suffix}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8", errors="backslashreplace")
        written += 1
    return written, len(sources)


def run_webcrack(script: Path, target: Path) -> str | None:
    webcrack = shutil.which("webcrack")
    if not webcrack:
        return None
    shutil.rmtree(target, ignore_errors=True)
    done = run_tool([webcrack, str(script), "-o", str(target)], TIMEOUT)
    if not (target / "deobfuscated.js").is_file():
        raise KitError(f"webcrack failed on {script.name}:\n{tail(done.stdout, 8)}")
    return (target / "deobfuscated.js").as_posix()


def needs_webcrack(text: str) -> bool:
    lines = text.count("\n") + 1
    return len(text) // lines > MINIFIED_LINE_LENGTH or "_0x" in text


def map_electron(folder: Path, work: Path) -> dict | None:
    package = folder / "package.json"
    if not package.is_file():
        return None
    try:
        manifest = json.loads(package.read_text("utf-8", errors="replace"))
    except ValueError:
        manifest = {}
    result = {
        "name": clean(str(manifest.get("name", ""))),
        "main": clean(str(manifest.get("main", "index.js"))),
        "ipc_main": {},
        "ipc_renderer": {},
        "bridges": [],
        "preloads": [],
        "risky": [],
    }
    for path in js_files(folder):
        text = path.read_text("utf-8", errors="replace")
        where = path.relative_to(work).as_posix()
        for kind, channel in IPC_MAIN.findall(text):
            result["ipc_main"].setdefault(clean(channel), {"kind": kind, "file": where})
        for kind, channel in IPC_RENDERER.findall(text):
            result["ipc_renderer"].setdefault(clean(channel), {"kind": kind, "file": where})
        result["bridges"] += [clean(name) for name in BRIDGE.findall(text)]
        result["preloads"] += [clean(name) for name in PRELOAD.findall(text)]
        for pattern, label in RISKY:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                result["risky"].append(f"{label}: {where}:{line}")
    result["unhandled_channels"] = sorted(set(result["ipc_renderer"]) - set(result["ipc_main"]))
    return result


def recover(work: Path, path: Path, kind: str) -> dict:
    output = work / "decompiled" / "js"
    output.mkdir(parents=True, exist_ok=True)
    summary = {
        "target": clean(path.name),
        "type": kind,
        "warnings": [],
        "source_maps": [],
        "webcrack": [],
    }
    root = path if path.is_dir() else path.parent
    if kind == "asar" or (
        path.is_dir() and kind == "electron-app" and not (path / "package.json").is_file()
    ):
        archive = path if kind == "asar" else next(path.rglob("app.asar"), None)
        if archive is None:
            raise KitError(f"no app.asar in {path.name}", EXIT_UNSUPPORTED)
        root = output / "app"
        written, skipped = extract_asar(archive, root)
        summary["extracted"] = {"folder": root.relative_to(work).as_posix(), "files": written}
        summary["warnings"] += skipped[:SHOWN]
    scripts = js_files(root) if root.is_dir() and (path.is_dir() or kind == "asar") else [path]
    if kind == "source-map":
        written, total = write_sources(
            json.loads(path.read_text("utf-8")), output / "sources" / safe_file_name(path.stem)
        )
        summary["source_maps"].append({"map": path.name, "sources": written, "listed": total})
        scripts = []
    missing_webcrack = False
    for script in scripts:
        text = script.read_text("utf-8", errors="replace")
        label = script.relative_to(root).as_posix() if script.is_relative_to(root) else script.name
        try:
            source_map, origin = load_source_map(script, text, root)
        except (ValueError, OSError) as error:
            source_map, origin = None, f"unreadable: {error}"
        if source_map:
            target = output / "sources" / safe_file_name(label)
            written, total = write_sources(source_map, target)
            summary["source_maps"].append(
                {"script": clean(label), "map": origin, "sources": written, "listed": total}
            )
            if written:
                continue
        elif origin:
            summary["source_maps"].append({"script": clean(label), "map": origin, "sources": 0})
        if needs_webcrack(text) and len(summary["webcrack"]) < MAX_WEBCRACK:
            staged = stage_input(script, work) if not script.is_relative_to(work) else script
            result = run_webcrack(staged, output / "webcrack" / safe_file_name(label))
            if result is None:
                missing_webcrack = True
            else:
                summary["webcrack"].append(
                    {"script": clean(label), "output": Path(result).relative_to(work).as_posix()}
                )
    if missing_webcrack:
        hint = next(tool.hints[this_os()] for tool in TOOLS if tool.name == "webcrack")
        summary["warnings"].append(
            f"webcrack is not installed, so minified files stay as they are. {hint}"
        )
    summary["electron"] = map_electron(root, work) if root.is_dir() else None
    summary["status"] = "partial" if missing_webcrack else "ok"
    return summary


def render(summary: dict) -> str:
    lines = [f"{summary['target']}: {summary['type']}"]
    if "extracted" in summary:
        extracted = summary["extracted"]
        lines.append(f"  extracted {extracted['files']} files into {extracted['folder']}/")
    for item in summary["source_maps"][:SHOWN]:
        script = item.get("script", item["map"])
        lines.append(f"  source map for {script}: {item['map']}, {item['sources']} sources written")
    for item in summary["webcrack"][:SHOWN]:
        lines.append(f"  webcrack: {item['script']} -> {item['output']}")
    electron = summary.get("electron")
    if electron:
        lines.append(f"  electron app {electron['name']}, main: {electron['main']}")
        lines.append(f"  preload scripts: {', '.join(electron['preloads']) or 'none found'}")
        lines.append(f"  exposed to pages: {', '.join(electron['bridges']) or 'nothing'}")
        lines.append("  IPC handled in the main process:")
        lines += [
            f"    {name} ({item['kind']}) in {item['file']}"
            for name, item in list(electron["ipc_main"].items())[:30]
        ]
        if electron["unhandled_channels"]:
            lines.append(
                f"  sent but not handled here: {', '.join(electron['unhandled_channels'])}"
            )
        lines += [f"  risky: {text}" for text in electron["risky"][:SHOWN]]
    lines += [f"  warning: {text}" for text in summary["warnings"]]
    return "\n".join(lines)


def main() -> int:
    parser = build_parser(__doc__)
    add_work_flag(parser)
    parser.add_argument(
        "target",
        nargs="?",
        help="a bundle, map, asar or app folder (default: the one in original/)",
    )
    args = parser.parse_args()
    try:
        work = resolve_work_dir(args.work)
        path, kind = pick_target(work, args.target)
        summary = recover(work, path, kind)
    except (KitError, OSError, ValueError, RecursionError) as error:
        return fail(error if isinstance(error, KitError) else KitError(str(error)), args.json)
    write_atomic(work / "decompiled" / "js" / "summary.json", json.dumps(summary, indent=2) + "\n")
    emit(summary, render(summary), args.json)
    return EXIT_MISSING_TOOL if summary["status"] == "partial" else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
