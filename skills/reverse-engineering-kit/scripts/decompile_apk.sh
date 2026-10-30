#!/usr/bin/env bash
# Decompile an APK with jadx and apktool into the standard output layout.
# Exit codes: 0 success, 2 missing tool, 3 unsupported input.
set -euo pipefail

case "${1:-}" in
  -h | --help)
    printf 'usage: decompile_apk.sh [-h] [--json]\n\nDecompile an APK with jadx and apktool into the standard output layout.\n'
    exit 0
    ;;
  --json)
    printf '{"status": "not_implemented", "script": "decompile_apk.sh", "phase": 3}\n'
    ;;
  *)
    printf 'decompile_apk.sh: not implemented yet (Phase 3)\n' >&2
    ;;
esac
exit 1
