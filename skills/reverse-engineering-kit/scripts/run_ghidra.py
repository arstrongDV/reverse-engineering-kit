#!/usr/bin/env python3
"""Analyze a native binary with Ghidra headless, and export its functions, imports, strings and
decompiled code to decompiled/ghidra/. Later runs reuse the analysis, so --function is quick."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
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
from doctor import check_ghidra
from triage import HEAD_SIZE, NOTABLE_STRING, clean, identify

SCRIPT_DIR = Path(__file__).resolve().parent / "ghidra"
SCRIPT = "GhidraExport.java"
NATIVE = ("elf", "pe", "macho")
PROJECT = "kit"
TOP = 30
TIMEOUT = 1800
SHOWN = 12
MAX_IMPORTS = 500
MAX_NOTABLE = 25
BYTES = 64
BYTES_REQUEST = re.compile(r"([^:\s]+)(?::(\d{1,4}))?")


def is_native(path: Path) -> bool:
    with path.open("rb") as file:
        return identify(path, file.read(HEAD_SIZE))["type"] in NATIVE


def pick_target(work: Path, given: str | None) -> Path:
    if given:
        path = Path(given)
        if not path.is_file():
            raise KitError(f"{given} is not a file")
        with path.open("rb") as file:
            kind = identify(path, file.read(HEAD_SIZE))["type"]
        if kind not in NATIVE:
            raise KitError(
                f"{path.name} is {kind}: Ghidra here takes ELF, PE or Mach-O", EXIT_UNSUPPORTED
            )
        return path
    natives = [p for p in sorted((work / "original").glob("*")) if p.is_file() and is_native(p)]
    if len(natives) != 1:
        found = ", ".join(p.name for p in natives) or "none"
        raise KitError(
            f"name the binary to analyze (native files in original/: {found})", EXIT_USAGE
        )
    return natives[0]


def find_launcher() -> Path:
    ghidra = check_ghidra()
    if ghidra["status"] != "ok":
        reason = " ".join(text for text in (ghidra["problem"], ghidra["hint"]) if text)
        raise KitError(f"Ghidra is {ghidra['status']}. {reason}", EXIT_MISSING_TOOL)
    name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    return Path(ghidra["path"]) / "support" / name


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def build_command(launcher: Path, folder: Path, staged: Path, args, reuse: bool) -> list[str]:
    script = ["-scriptPath", str(folder / "script"), "-postScript", SCRIPT]
    script += [str(folder / "export.json"), str(args.top), *args.function]
    for request in args.bytes:
        name, count = BYTES_REQUEST.fullmatch(request).groups()
        script.append(f"bytes:{name}:{count or BYTES}")
    project = folder / "project"
    if reuse:
        return [
            str(launcher),
            str(project),
            PROJECT,
            "-process",
            staged.name,
            "-noanalysis",
            *script,
        ]
    timeout = ["-analysisTimeoutPerFile", str(args.timeout)]
    return [str(launcher), str(project), PROJECT, "-import", str(staged), *timeout, *script]


def analyze(work: Path, path: Path, args) -> tuple[Path, dict, bool]:
    staged = stage_input(path, work)
    folder = work / "decompiled" / "ghidra" / safe_file_name(staged.name)
    state_path = folder / "state.json"
    digest = sha256_of(path)
    state = json.loads(state_path.read_text("utf-8")) if state_path.is_file() else {}
    reuse = not args.fresh and state.get("sha256") == digest and (folder / "project").is_dir()
    if not reuse:
        shutil.rmtree(folder / "project", ignore_errors=True)
        (folder / "project").mkdir(parents=True)
    # Ghidra compiles every .java file on its script path, so the script gets a folder of its own.
    (folder / "script").mkdir(exist_ok=True)
    shutil.copyfile(SCRIPT_DIR / SCRIPT, folder / "script" / SCRIPT)
    export = folder / "export.json"
    export.unlink(missing_ok=True)
    command = build_command(find_launcher(), folder, staged, args, reuse)
    done = run_tool(command, args.timeout + 600)
    (folder / "ghidra.log").write_text(done.stdout, encoding="utf-8", errors="backslashreplace")
    if not export.is_file():
        log = (folder / "ghidra.log").relative_to(work).as_posix()
        raise KitError(f"Ghidra wrote no export. The end of {log}:\n{tail(done.stdout)}")
    write_atomic(state_path, json.dumps({"sha256": digest, "program": staged.name}) + "\n")
    return folder, json.loads(export.read_text("utf-8")), reuse


def save_functions(folder: Path, export: dict) -> list[dict]:
    """Write each decompiled function to its own file, where an agent can read it whole."""
    target = folder / "functions"
    target.mkdir(exist_ok=True)
    saved = []
    for item in export["decompiled"]:
        entry = {"name": clean(item["name"]), "address": clean(item["address"])}
        if "code" in item:
            name = f"{safe_file_name(item['name'])}@{safe_file_name(item['address'])}.c"
            write_atomic(target / name, item["code"])
            entry["file"] = name
        else:
            entry["error"] = clean(item.get("error", "unknown error"))
        saved.append(entry)
    return saved


def summarize(work: Path, folder: Path, export: dict, saved: list[dict], reused: bool) -> dict:
    functions = export["functions"]["items"]
    return {
        "status": "ok",
        "reused_analysis": reused,
        "program": export["program"],
        "export": (folder / "export.json").relative_to(work).as_posix(),
        "functions_folder": (folder / "functions").relative_to(work).as_posix(),
        "counts": {name: export[name]["total"] for name in ("functions", "imports", "strings")},
        "top_functions": [
            {key: item[key] for key in ("name", "address", "size", "callers", "strings", "imports")}
            for item in functions[:SHOWN]
        ],
        "imports_in_use": [item for item in export["imports"]["items"] if item["callers"]][
            :MAX_IMPORTS
        ],
        "notable_strings": [
            item
            for item in export["strings"]["items"]
            if item["functions"] and NOTABLE_STRING.search(item["value"])
        ][:MAX_NOTABLE],
        "decompiled": saved,
        "bytes": export["bytes"],
        "missing": export["missing"],
    }


def render(summary: dict) -> str:
    program = summary["program"]
    counts = summary["counts"]
    lines = [
        f"{clean(program['name'])}: {program['format']}, {program['language']}",
        f"  {counts['functions']} functions, {counts['imports']} imports, "
        f"{counts['strings']} strings",
        "  top functions (by strings and imports used):",
    ]
    for item in summary["top_functions"]:
        uses = f"{item['strings']} strings, imports: {', '.join(item['imports'][:5]) or 'none'}"
        lines.append(f"    {clean(item['name'])} @ {item['address']}: {uses}")
    libraries: dict[str, list[str]] = {}
    for item in summary["imports_in_use"]:
        libraries.setdefault(clean(item["library"]) or "unknown", []).append(clean(item["name"]))
    lines.append("  imports in use, by library:")
    for library, names in libraries.items():
        more = f" and {len(names) - 12} more" if len(names) > 12 else ""
        lines.append(f"    {library}: {', '.join(names[:12])}{more}")
    if summary["notable_strings"]:
        lines.append("  notable strings, and the functions that use them:")
    for item in summary["notable_strings"][:SHOWN]:
        users = ", ".join(clean(name) for name in item["functions"][:3])
        lines.append(f"    {clean(item['value'])[:70]!r}: {users}")
    written = [item for item in summary["decompiled"] if "file" in item]
    failed = [item for item in summary["decompiled"] if "error" in item]
    lines.append(f"  decompiled {len(written)} functions into {summary['functions_folder']}/")
    lines += [f"  could not decompile {item['name']}: {item['error']}" for item in failed]
    for item in summary["bytes"]:
        lines.append(f"  bytes at {clean(item['name'])} ({item['address']}): {item['hex']}")
    lines += [f"  not found: {clean(name)}" for name in summary["missing"]]
    lines.append(f"  full export: {summary['export']}")
    return "\n".join(lines)


def main() -> int:
    parser = build_parser(__doc__)
    add_work_flag(parser)
    parser.add_argument(
        "target", nargs="?", help="the binary (default: the native file in original/)"
    )
    parser.add_argument(
        "--function",
        action="append",
        default=[],
        help="decompile this function, by name or address, instead of the top ones (repeatable)",
    )
    parser.add_argument(
        "--bytes",
        action="append",
        default=[],
        metavar="NAME[:COUNT]",
        help=f"read COUNT bytes (default {BYTES}) at a symbol or address (repeatable)",
    )
    parser.add_argument(
        "--top", type=int, default=TOP, help=f"how many to decompile (default {TOP})"
    )
    parser.add_argument("--fresh", action="store_true", help="analyze again instead of reusing")
    parser.add_argument(
        "--timeout",
        type=int,
        default=TIMEOUT,
        help=f"analysis limit in seconds (default {TIMEOUT})",
    )
    args = parser.parse_args()
    for request in args.bytes:
        if not BYTES_REQUEST.fullmatch(request):
            parser.error(f"--bytes takes NAME or NAME:COUNT, not {request!r}")
    try:
        work = resolve_work_dir(args.work)
        path = pick_target(work, args.target)
        folder, export, reused = analyze(work, path, args)
        saved = save_functions(folder, export)
    except (KitError, OSError, ValueError) as error:
        return fail(error if isinstance(error, KitError) else KitError(str(error)), args.json)
    summary = summarize(work, folder, export, saved, reused)
    emit(summary, render(summary), args.json)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
