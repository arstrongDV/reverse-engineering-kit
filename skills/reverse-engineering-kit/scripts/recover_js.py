#!/usr/bin/env python3
"""Recover readable sources from JS bundles and Electron apps."""

from __future__ import annotations

from _common import build_parser, not_implemented


def main() -> int:
    args = build_parser(__doc__).parse_args()
    return not_implemented("recover_js.py", phase=3, as_json=args.json)


if __name__ == "__main__":
    raise SystemExit(main())
