#!/usr/bin/env python3
"""Check which analysis tools are installed and print install hints for this OS.

Never installs anything. Exits 2 when a checked tool is missing or cannot work."""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from _common import EXIT_MISSING_TOOL, EXIT_OK, LIEF_HINT, build_parser, emit

GOALS = ("native", "android", "js", "protocols", "dynamic")
VERSION_TIMEOUT = 30
MIN_PYTHON = (3, 10)
PYTHON_HINT = "Install Python 3.10 or newer from https://www.python.org/downloads/"

ANY_VERSION = re.compile(r"\d+(?:\.\d+)+|\d+")
JAVA_VERSION = re.compile(r'version "([\d._]+)')

GHIDRA_ZIP = "ghidra_12.2_PUBLIC_20261016.zip"
GHIDRA_RELEASES = "https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.2_build"
# Ghidra starts on any of these, but its releases only carry decompilers for x86-64 Linux and
# Windows. On the others it cannot decompile until the natives are built.
GHIDRA_PLATFORMS = {
    ("Linux", "x86_64"): "linux_x86_64",
    ("Linux", "aarch64"): "linux_arm_64",
    ("Darwin", "x86_64"): "mac_x86_64",
    ("Darwin", "arm64"): "mac_arm_64",
    ("Windows", "AMD64"): "win_x86_64",
}


@dataclass(frozen=True)
class Tool:
    name: str
    goals: tuple[str, ...]
    hints: dict[str, str]
    flag: str = "--version"
    pattern: re.Pattern = ANY_VERSION


def same_everywhere(hint: str) -> dict[str, str]:
    return dict.fromkeys(("macos", "linux", "windows"), hint)


JAVA = Tool(
    "java",
    ("native", "android"),
    {
        "macos": "brew install openjdk@25",
        "linux": "sudo apt-get install openjdk-25-jdk-headless",
        "windows": "winget install EclipseAdoptium.Temurin.25.JDK",
    },
    flag="-version",
    pattern=JAVA_VERSION,
)
GHIDRA = Tool(
    "ghidra",
    ("native",),
    same_everywhere(
        f"Download {GHIDRA_ZIP} from {GHIDRA_RELEASES}, unzip it, and set GHIDRA_INSTALL_DIR "
        "to that folder"
    ),
)
LIEF = Tool("lief", ("native",), same_everywhere(LIEF_HINT))
TOOLS = (
    GHIDRA,
    JAVA,
    Tool(
        "rizin",
        ("native",),
        {
            "macos": "Install rizin-macos-v0.9.1.pkg from "
            "https://github.com/rizinorg/rizin/releases/tag/v0.9.1",
            "linux": "On x86-64, unpack rizin-v0.9.1-static-x86_64.tar.xz from "
            "https://github.com/rizinorg/rizin/releases/tag/v0.9.1 . There is no arm64 build: "
            "build rizin-src-v0.9.1.tar.xz from the same page with meson and ninja",
            "windows": "Run rizin_installer-v0.9.1-x86_64.exe from "
            "https://github.com/rizinorg/rizin/releases/tag/v0.9.1",
        },
        flag="-v",
    ),
    LIEF,
    Tool(
        "upx",
        ("native",),
        {
            "macos": "brew install upx (tested with 5.3.0)",
            "linux": "Unpack the upx-5.3.0 archive for this CPU from "
            "https://github.com/upx/upx/releases/tag/v5.3.0 and put upx on PATH",
            "windows": "Unzip upx-5.3.0-win64.zip from "
            "https://github.com/upx/upx/releases/tag/v5.3.0 and put upx.exe on PATH",
        },
    ),
    Tool(
        "jadx",
        ("android",),
        same_everywhere(
            "Unzip jadx-1.5.6.zip from https://github.com/skylot/jadx/releases/tag/v1.5.6 and "
            "put its bin folder on PATH"
        ),
    ),
    Tool(
        "apktool",
        ("android",),
        {
            "macos": "brew install apktool (tested with 3.0.3)",
            "linux": "Download apktool_3.0.3.jar from "
            "https://github.com/iBotPeaches/Apktool/releases/tag/v3.0.3 and put a script named "
            "apktool on PATH that runs it with java -jar",
            "windows": "Download apktool_3.0.3.jar from "
            "https://github.com/iBotPeaches/Apktool/releases/tag/v3.0.3 and put a file named "
            "apktool.bat on PATH that runs it with java -jar",
        },
    ),
    Tool(
        "node",
        ("js",),
        {
            "macos": "brew install node@22",
            "linux": "sudo apt-get install nodejs npm (webcrack needs Node 22 or 24)",
            "windows": "winget install OpenJS.NodeJS.22",
        },
    ),
    Tool("webcrack", ("js",), same_everywhere("npm install -g webcrack@2.16.0")),
    Tool("asar", ("js",), same_everywhere("npm install -g @electron/asar@4.3.1")),
    Tool(
        "kaitai-struct-compiler",
        ("protocols",),
        {
            "macos": "brew install kaitai-struct-compiler (tested with 0.11)",
            "linux": "Install kaitai-struct-compiler_0.11_all.deb from "
            "https://github.com/kaitai-io/kaitai_struct_compiler/releases/tag/0.11",
            "windows": "Run kaitai-struct-compiler-0.11.msi from "
            "https://github.com/kaitai-io/kaitai_struct_compiler/releases/tag/0.11",
        },
    ),
    Tool(
        "frida",
        ("dynamic",),
        same_everywhere("python -m pip install frida==17.25.0 frida-tools==14.11.0"),
    ),
)


def this_os() -> str:
    return {"Darwin": "macos", "Windows": "windows"}.get(platform.system(), "linux")


def result(tool: Tool, status: str, version=None, path=None, problem=None, hint=None) -> dict:
    if status != "ok":
        hint = hint or tool.hints[this_os()]
    return {
        "name": tool.name,
        "goals": list(tool.goals),
        "status": status,
        "version": version,
        "path": str(path) if path else None,
        "problem": problem,
        "hint": hint,
    }


def run_version(path: str, tool: Tool) -> tuple[str | None, str | None]:
    """Return the version a tool reports, or why it would not report one."""
    try:
        done = subprocess.run(
            [path, tool.flag],
            capture_output=True,
            text=True,
            errors="replace",
            stdin=subprocess.DEVNULL,
            timeout=VERSION_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return None, f"found, but it would not run: {error}"
    match = tool.pattern.search(done.stdout + done.stderr)
    if done.returncode != 0 or not match:
        return None, f"found, but {tool.flag} failed with exit code {done.returncode}"
    return match[match.lastindex or 0], None


def check_command(tool: Tool) -> dict:
    path = shutil.which(tool.name)
    if not path:
        return result(tool, "missing")
    version, problem = run_version(path, tool)
    return result(tool, "broken" if problem else "ok", version, path, problem)


def java_major(version: str) -> int:
    parts = re.split(r"[._]", version)
    return int(parts[1] if parts[0] == "1" and len(parts) > 1 else parts[0])


def find_ghidra() -> Path | None:
    candidates = []
    if os.environ.get("GHIDRA_INSTALL_DIR"):
        candidates.append(Path(os.environ["GHIDRA_INSTALL_DIR"]))
    for command in ("analyzeHeadless", "ghidraRun"):
        path = shutil.which(command)
        if path:
            candidates += Path(path).resolve().parents[:2]
    return next((c for c in candidates if (c / "Ghidra/application.properties").is_file()), None)


def read_properties(path: Path) -> dict[str, str]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    pairs = (line.split("=", 1) for line in lines if "=" in line and line[0] != "#")
    return {key.strip(): value.strip() for key, value in pairs}


def find_decompiler(root: Path, name: str) -> Path | None:
    """A release keeps decompilers in os/, and buildNatives writes them to build/os/."""
    executable = "decompile.exe" if name.startswith("win") else "decompile"
    feature = root / "Ghidra/Features/Decompiler"
    for path in (feature / "os" / name / executable, feature / "build/os" / name / executable):
        if path.is_file() and os.access(path, os.X_OK):
            return path
    return None


def check_decompiler(root: Path, java_minimum: str) -> tuple[str | None, str | None]:
    """Ghidra reports a version and starts without a decompiler, so look for the file itself."""
    machine = (platform.system(), platform.machine())
    name = GHIDRA_PLATFORMS.get(machine)
    if not name:
        return f"no known Ghidra decompiler for {machine[0]} on {machine[1]}", None
    if find_decompiler(root, name):
        return None, None
    build = (
        f"In {root / 'support' / 'gradle'} run ./gradlew buildNatives (needs JDK {java_minimum}, "
        "gcc or clang, make, and internet access)"
    )
    return f"it starts, but it cannot decompile: no {name} decompiler", build


def check_ghidra() -> dict:
    root = find_ghidra()
    if not root:
        return result(GHIDRA, "missing")
    properties = read_properties(root / "Ghidra" / "application.properties")
    version = properties.get("application.version")
    minimum = properties.get("application.java.min", "0")
    problem, hint = check_decompiler(root, minimum)
    if problem:
        return result(GHIDRA, "broken", version, root, problem, hint)
    path = shutil.which("java")
    java_version = run_version(path, JAVA)[0] if path else None
    if not java_version or java_major(java_version) < int(minimum):
        found = f"found {java_version}" if java_version else "found none"
        problem = f"Ghidra {version} needs JDK {minimum} or newer, {found}"
        return result(GHIDRA, "broken", version, root, problem, JAVA.hints[this_os()])
    return result(GHIDRA, "ok", version, root)


def check_lief() -> dict:
    try:
        import lief
    except ImportError:
        return result(LIEF, "missing")
    return result(LIEF, "ok", lief.__version__.split("-")[0])


def check_python() -> dict:
    version = platform.python_version()
    tool = Tool("python", GOALS, same_everywhere(PYTHON_HINT))
    if sys.version_info < MIN_PYTHON:
        return result(tool, "broken", version, sys.executable, "needs Python 3.10 or newer")
    return result(tool, "ok", version, sys.executable)


def check(tool: Tool) -> dict:
    if tool is GHIDRA:
        return check_ghidra()
    if tool is LIEF:
        return check_lief()
    return check_command(tool)


def render(tools: list[dict]) -> str:
    width = max(len(item["name"]) for item in tools)
    lines = []
    for item in tools:
        line = f"{item['status']:8}{item['name']:{width + 2}}{item['version'] or ''}"
        lines.append(line.rstrip())
        lines += [f"        {text}" for text in (item["problem"], item["hint"]) if text]
    ready = sum(item["status"] == "ok" for item in tools)
    lines.append(f"{ready} of {len(tools)} ready")
    return "\n".join(lines)


def main() -> int:
    parser = build_parser(__doc__)
    parser.add_argument(
        "--for",
        dest="goals",
        action="append",
        choices=GOALS,
        help="check only what this kind of target needs (repeatable)",
    )
    args = parser.parse_args()
    goals = set(args.goals or GOALS)
    tools = [check_python()]
    tools += [check(tool) for tool in TOOLS if goals.intersection(tool.goals)]
    ready = all(item["status"] == "ok" for item in tools)
    payload = {
        "status": "ok" if ready else "missing",
        "os": this_os(),
        "arch": platform.machine(),
        "tools": tools,
    }
    emit(payload, render(tools), args.json)
    return EXIT_OK if ready else EXIT_MISSING_TOOL


if __name__ == "__main__":
    raise SystemExit(main())
