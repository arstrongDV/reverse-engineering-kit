#!/usr/bin/env python3
"""Decompile an APK with jadx and apktool into the standard output layout."""

from __future__ import annotations

from _common import build_parser, not_implemented


def main() -> int:
    args = build_parser(__doc__).parse_args()
    return not_implemented("decompile_apk.py", phase=3, as_json=args.json)


if __name__ == "__main__":
    raise SystemExit(main())
