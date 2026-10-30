#!/usr/bin/env bash
# Run the Ghidra headless analyzer on a target with ghidra_export.py as post-script.
# Exit codes: 0 success, 2 missing tool, 3 unsupported input.
set -euo pipefail

case "${1:-}" in
  -h | --help)
    printf 'usage: run_ghidra.sh [-h] [--json]\n\nRun the Ghidra headless analyzer on a target with ghidra_export.py as post-script.\n'
    exit 0
    ;;
  --json)
    printf '{"status": "not_implemented", "script": "run_ghidra.sh", "phase": 3}\n'
    ;;
  *)
    printf 'run_ghidra.sh: not implemented yet (Phase 3)\n' >&2
    ;;
esac
exit 1
