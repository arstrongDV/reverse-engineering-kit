#!/usr/bin/env python3
"""List URLs, API paths, IP addresses, HTTP call sites, auth headers and likely secrets in
extracted code, with the file and line of each. Saves decompiled/endpoints.json.

Secrets are always masked: the output says where one is, never what it is."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from _common import (
    EXIT_OK,
    KitError,
    add_work_flag,
    build_parser,
    emit,
    fail,
    resolve_work_dir,
    write_atomic,
)
from triage import clean

MAX_FILES = 20_000
MAX_FILE_SIZE = 32 * 1024 * 1024
MAX_PER_KIND = 300
MAX_PLACES = 5
SHOWN = 20
SNIPPET = 160
SKIP_FOLDERS = {".git", "__pycache__"}
SAVED = "endpoints.json"
# Third-party code: its endpoints are rarely the app's own, so they are tagged and shown last.
LIBRARY_PATH = re.compile(
    r"(?:^|/)(?:node_modules|androidx|android/support|kotlinx?|okhttp3|okio|retrofit2|"
    r"com/google|com/squareup|com/facebook|org/jetbrains|org/apache|io/reactivex|javax)/"
)
NOISE_HOSTS = re.compile(
    r"^(?:www\.)?(?:w3\.org|schemas\.android\.com|schemas\.xmlsoap\.org|schemas\.microsoft\.com|"
    r"xmlpull\.org|apache\.org|json-schema\.org|ns\.adobe\.com|purl\.org|xml\.org|"
    r"developer\.android\.com|reactjs\.org|react\.dev|github\.com/facebook)",
    re.IGNORECASE,
)

URL = re.compile(r"\b(?:https?|wss?|ftp)://[^\s\"'`<>()\[\]{}\\^|]{3,300}")
API_PATH = re.compile(
    r"[\"'`](/(?:api|v\d{1,2}|rest|graphql|auth|oauth2?|login|logout|users?|accounts?|session|"
    r"internal|admin|sync|upload|download|events?|telemetry|collect|orders?|notes?)"
    r"(?:[/?][^\"'`\s]{0,150})?)[\"'`]"
)
IPV4 = re.compile(
    r"[\"'`/@]((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?::\d{1,5})?[\"'`/:]"
)
HEADER = re.compile(
    r"[\"'`](Authorization|Proxy-Authorization|Cookie|X-[A-Za-z0-9-]*(?:Key|Token|Auth|Secret|Signature)"
    r"[A-Za-z0-9-]*)[\"'`]",
    re.IGNORECASE,
)
CALLS = (
    ("retrofit", re.compile(r"@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\(\s*\"([^\"]*)\"")),
    ("fetch", re.compile(r"\bfetch\(")),
    ("axios", re.compile(r"\baxios(?:\.(?:get|post|put|delete|patch|request))?\(")),
    ("xhr", re.compile(r"\.open\(\s*[\"'`](?:GET|POST|PUT|DELETE|PATCH)[\"'`]")),
    ("url-connection", re.compile(r"\bopenConnection\(\)|setRequestMethod\(")),
    ("okhttp", re.compile(r"new Request\.Builder\(\)|\.newCall\(")),
    ("websocket", re.compile(r"new WebSocket\(|\.newWebSocket\(")),
    (
        "winhttp",
        re.compile(r"\bWinHttp(?:Connect|OpenRequest|SendRequest)\b|\bInternetOpenUrl[AW]?\b"),
    ),
    ("socket", re.compile(r"\bconnect\(\s*\w+\s*,|\bsendto\(")),
    ("libcurl", re.compile(r"CURLOPT_URL")),
)
SECRETS = (
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_\w{22,})")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("stripe-key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    (
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    ),
)
ASSIGNED_SECRET = re.compile(
    r"\b(api[_-]?key|app[_-]?key|secret|client[_-]?secret|access[_-]?key|token|passw(?:or)?d)"
    r"[\"'`]?\s*[:=]\s*[\"'`]([^\"'`\s]{6,200})[\"'`]",
    re.IGNORECASE,
)


def mask(value: str) -> str:
    return f"{value[:4]}... ({len(value)} characters)"


def is_text(path: Path) -> bool:
    with path.open("rb") as file:
        return b"\0" not in file.read(4096)


def walk(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    found = []
    for folder, folders, names in os.walk(root):
        folders[:] = sorted(name for name in folders if name not in SKIP_FOLDERS)
        for name in sorted(names):
            path = Path(folder) / name
            if path.is_symlink() or path.stat().st_size > MAX_FILE_SIZE:
                continue
            found.append(path)
            if len(found) >= MAX_FILES:
                return found
    return found


class Findings:
    def __init__(self):
        self.kinds: dict[str, dict[str, dict]] = {}

    def add(self, category: str, value: str, place: str, library: bool, /, **extra) -> None:
        entries = self.kinds.setdefault(category, {})
        entry = entries.get(value)
        if entry is None:
            if len(entries) >= MAX_PER_KIND:
                return
            entry = entries[value] = {"value": value, "count": 0, "places": [], "library": library}
            entry.update(extra)
        entry["count"] += 1
        entry["library"] = entry["library"] and library
        if len(entry["places"]) < MAX_PLACES:
            entry["places"].append(place)

    def as_dict(self) -> dict:
        ordered = {}
        for kind, entries in self.kinds.items():
            items = sorted(
                entries.values(),
                key=lambda item: (item["library"], item.get("noise", False), -item["count"]),
            )
            ordered[kind] = items
        return ordered


def scan_line(findings: Findings, line: str, place: str, library: bool) -> None:
    for match in URL.finditer(line):
        # A template literal leaves its ${ behind when the URL is built from parts.
        url = clean(match[0].rstrip(".,;$"))
        host = re.sub(r"^[a-z]+://", "", url, flags=re.IGNORECASE)
        findings.add("urls", url, place, library, noise=bool(NOISE_HOSTS.match(host)))
    for match in API_PATH.finditer(line):
        findings.add("paths", clean(match[1]), place, library)
    for match in IPV4.finditer(line):
        findings.add("ip_addresses", match[1], place, library)
    for match in HEADER.finditer(line):
        findings.add("headers", clean(match[1]), place, library)
    for name, pattern in CALLS:
        match = pattern.search(line)
        if match:
            snippet = clean(line.strip())[:SNIPPET]
            findings.add("calls", f"{name}: {snippet}", place, library, kind=name)
    for name, pattern in SECRETS:
        for match in pattern.finditer(line):
            findings.add("secrets", f"{name}: {mask(match[0])}", place, library)
    for match in ASSIGNED_SECRET.finditer(line):
        findings.add("secrets", f"{clean(match[1])}: {mask(match[2])}", place, library)


def scan(root: Path, work: Path) -> tuple[dict, int]:
    findings = Findings()
    scanned = 0
    own_output = work / "decompiled" / SAVED
    for path in walk(root):
        if path == own_output or not is_text(path):
            continue
        scanned += 1
        relative = path.relative_to(work).as_posix() if path.is_relative_to(work) else path.name
        library = bool(LIBRARY_PATH.search(relative))
        with path.open(encoding="utf-8", errors="replace") as file:
            for number, line in enumerate(file, 1):
                # Minified bundles put everything on one line, so long lines are cut into pieces.
                for start in range(0, len(line), 4096):
                    scan_line(
                        findings, line[start : start + 4096 + 300], f"{relative}:{number}", library
                    )
    return findings.as_dict(), scanned


def render(result: dict) -> str:
    lines = [f"scanned {result['files']} text files under {result['root']}"]
    for kind, items in result["findings"].items():
        own = [item for item in items if not item["library"] and not item.get("noise")]
        hidden = len(items) - len(own)
        lines.append(
            f"{kind}: {len(own)} in the app"
            + (f", {hidden} in libraries or standard schemas" if hidden else "")
        )
        for item in own[:SHOWN]:
            # Decompiled Java reads better than smali, so point at it when both exist.
            readable = [place for place in item["places"] if ".smali:" not in place]
            place = (readable or item["places"])[0]
            lines.append(f"  {item['value']}  ({item['count']}x, at {place})")
    if result["findings"].get("secrets"):
        lines.append(
            "Secrets are masked. Record where each one is and what it reaches, never its value."
        )
    lines.append(f"full list: {result['saved']}")
    return "\n".join(lines)


def main() -> int:
    parser = build_parser(__doc__)
    add_work_flag(parser)
    parser.add_argument("path", nargs="?", help="a file or folder to scan (default: decompiled/)")
    args = parser.parse_args()
    try:
        work = resolve_work_dir(args.work)
        root = Path(args.path) if args.path else work / "decompiled"
        if not root.exists():
            raise KitError(f"{root} does not exist: decompile or extract the target first")
        findings, scanned = scan(root, work)
    except (KitError, OSError) as error:
        return fail(error if isinstance(error, KitError) else KitError(str(error)), args.json)
    saved = work / "decompiled" / SAVED
    saved.parent.mkdir(exist_ok=True)
    result = {
        "status": "ok",
        "root": clean(
            root.relative_to(work).as_posix() if root.is_relative_to(work) else root.name
        ),
        "files": scanned,
        "findings": findings,
        "saved": saved.relative_to(work).as_posix(),
    }
    write_atomic(saved, json.dumps(result, indent=2) + "\n")
    emit(result, render(result), args.json)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
