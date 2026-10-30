#!/usr/bin/env python3
"""Render findings.jsonl into REPORT.md."""

from __future__ import annotations

from _common import build_parser, not_implemented


def main() -> int:
    args = build_parser(__doc__).parse_args()
    return not_implemented("make_report.py", phase=1, as_json=args.json)


if __name__ == "__main__":
    raise SystemExit(main())
