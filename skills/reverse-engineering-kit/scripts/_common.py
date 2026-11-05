"""Contract shared by every kit script: exit codes, argument parsing, stub behaviour."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
from pathlib import Path

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_MISSING_TOOL = 2
EXIT_UNSUPPORTED = 3
EXIT_USAGE = 64

LIEF_HINT = "python -m pip install lief==1.0.0"

SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
# cmd.exe parses the arguments of a .bat or .cmd file a second time, as commands.
BATCH_SAFE_ARGUMENT = re.compile(r"[\w .:\\/=+,@-]*")


class KitError(Exception):
    """A failure the script reports as a message and an exit code, not a traceback."""

    def __init__(self, message: str, exit_code: int = EXIT_ERROR):
        super().__init__(message)
        self.exit_code = exit_code


class ArgumentParser(argparse.ArgumentParser):
    """Move usage errors off argparse's default exit 2, which here means "tool missing"."""

    def error(self, message: str):
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def build_parser(description: str) -> ArgumentParser:
    # Findings quote whatever a target contains, and Windows pipes default to a legacy code page.
    sys.stdout.reconfigure(errors="backslashreplace")
    parser = ArgumentParser(description=description)
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    return parser


def add_work_flag(parser: argparse.ArgumentParser, default: str | None = ".") -> None:
    parser.add_argument(
        "--work",
        default=argparse.SUPPRESS if default is None else default,
        help="the re-work/<target> directory (default: the current directory)",
    )


def resolve_work_dir(path: str) -> Path:
    """Scripts write only inside re-work/<target>/, so refuse any other directory."""
    work = Path(path).resolve()
    if work.parent.name != "re-work" or not work.is_dir():
        raise KitError(f"{path} is not a re-work/<target> directory", EXIT_UNSUPPORTED)
    return work


def write_atomic(path: Path, text: str) -> None:
    """Replace a file in one step, so a crash cannot leave half a ledger or report."""
    temporary = path.with_name(f".{path.name}.tmp")
    # backslashreplace keeps stray bytes from a target as JSON escapes instead of failing.
    temporary.write_text(text, encoding="utf-8", errors="backslashreplace", newline="\n")
    os.replace(temporary, path)


def stage_input(path: Path, work: Path) -> Path:
    """Give tools a copy with a plain name, because a name from a target can hold shell syntax."""
    if SAFE_NAME.fullmatch(path.name):
        return path
    folder = work / "decompiled" / "input"
    folder.mkdir(parents=True, exist_ok=True)
    suffix = "".join(c for c in path.suffix if c.isalnum() or c == ".")[:10]
    staged = folder / f"target{suffix}"
    shutil.copyfile(path, staged)
    return staged


def safe_file_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("._")[:80]
    return cleaned or "unnamed"


def require_tool(name: str, hint: str) -> str:
    path = shutil.which(name)
    if not path:
        raise KitError(f"{name} is not installed. {hint}", EXIT_MISSING_TOOL)
    return path


def run_tool(command: list[str], timeout: int, **options) -> subprocess.CompletedProcess:
    """Run an analysis tool, killing its whole process tree if it overruns."""
    if command[0].lower().endswith((".bat", ".cmd")):
        for argument in command[1:]:
            if not BATCH_SAFE_ARGUMENT.fullmatch(argument):
                raise KitError(
                    f"refusing to pass {argument!r} to {Path(command[0]).name}, because cmd.exe "
                    "would read it as a command. Use a work directory with a plain path.",
                    EXIT_UNSUPPORTED,
                )
    group = {"start_new_session": True} if os.name != "nt" else {}
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            **group,
            **options,
        )
    except OSError as error:
        raise KitError(f"could not run {command[0]}: {error}", EXIT_MISSING_TOOL) from error
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        kill_tree(process)
        raise KitError(f"{Path(command[0]).name} did not finish within {timeout} seconds") from None
    return subprocess.CompletedProcess(command, process.returncode, output, "")


def kill_tree(process: subprocess.Popen) -> None:
    # Ghidra and jadx start a JVM as a child, which a plain kill would leave running.
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], capture_output=True)
    else:
        os.killpg(process.pid, signal.SIGKILL)
    process.communicate()


def tail(text: str, lines: int = 20) -> str:
    return "\n".join(text.strip().splitlines()[-lines:])


def emit(payload: dict, text: str, as_json: bool) -> None:
    print(json.dumps(payload) if as_json else text)


def fail(error: KitError, as_json: bool) -> int:
    if as_json:
        print(json.dumps({"status": "error", "message": str(error)}))
    else:
        print(f"error: {error}", file=sys.stderr)
    return error.exit_code


def not_implemented(script: str, phase: int, as_json: bool) -> int:
    """Report a stub as a failure so nothing can mistake it for a real result."""
    if as_json:
        print(json.dumps({"status": "not_implemented", "script": script, "phase": phase}))
    else:
        print(f"{script}: not implemented yet (Phase {phase})", file=sys.stderr)
    return EXIT_ERROR
