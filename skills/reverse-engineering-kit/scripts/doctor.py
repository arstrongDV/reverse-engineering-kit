#!/usr/bin/env python3
"""Check which analysis tools are installed and print install hints for this OS.

Never installs anything."""

from __future__ import annotations

from _common import build_parser, not_implemented


def main() -> int:
    args = build_parser(__doc__).parse_args()
    return not_implemented("doctor.py", phase=2, as_json=args.json)


if __name__ == "__main__":
    raise SystemExit(main())
