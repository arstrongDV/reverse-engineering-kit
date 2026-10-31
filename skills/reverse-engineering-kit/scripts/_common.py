"""Contract shared by every kit script: exit codes, argument parsing, stub behaviour."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_MISSING_TOOL = 2
EXIT_UNSUPPORTED = 3
EXIT_USAGE = 64


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
