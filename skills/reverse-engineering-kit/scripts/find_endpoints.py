#!/usr/bin/env python3
"""List URLs, routes and hardcoded credentials found in extracted code."""

from __future__ import annotations

from _common import build_parser, not_implemented


def main() -> int:
    args = build_parser(__doc__).parse_args()
    return not_implemented("find_endpoints.py", phase=3, as_json=args.json)


if __name__ == "__main__":
    raise SystemExit(main())
