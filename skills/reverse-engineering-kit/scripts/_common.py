"""Contract shared by every kit script: exit codes, argument parsing, stub behaviour."""

from __future__ import annotations

import argparse
import json
import sys

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_MISSING_TOOL = 2
EXIT_UNSUPPORTED = 3
EXIT_USAGE = 64


class ArgumentParser(argparse.ArgumentParser):
    """Move usage errors off argparse's default exit 2, which here means "tool missing"."""

    def error(self, message: str):
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def build_parser(description: str) -> ArgumentParser:
    parser = ArgumentParser(description=description)
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    return parser


def not_implemented(script: str, phase: int, as_json: bool) -> int:
    """Report a stub as a failure so nothing can mistake it for a real result."""
    if as_json:
        print(json.dumps({"status": "not_implemented", "script": script, "phase": phase}))
    else:
        print(f"{script}: not implemented yet (Phase {phase})", file=sys.stderr)
    return EXIT_ERROR
