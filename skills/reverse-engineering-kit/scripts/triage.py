#!/usr/bin/env python3
"""Identify a target: file type, hashes, section entropy, strings, imports, packer guess."""

from __future__ import annotations

from _common import build_parser, not_implemented


def main() -> int:
    args = build_parser(__doc__).parse_args()
    return not_implemented("triage.py", phase=2, as_json=args.json)


if __name__ == "__main__":
    raise SystemExit(main())
