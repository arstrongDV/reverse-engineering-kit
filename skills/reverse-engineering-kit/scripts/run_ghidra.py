#!/usr/bin/env python3
"""Run the Ghidra headless analyzer on a target with ghidra_export.py as post-script."""

from __future__ import annotations

from _common import build_parser, not_implemented


def main() -> int:
    args = build_parser(__doc__).parse_args()
    return not_implemented("run_ghidra.py", phase=3, as_json=args.json)


if __name__ == "__main__":
    raise SystemExit(main())
