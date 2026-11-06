# Notes: {{target}}

make_report.py needs text under Authorization, Summary and Gaps. Comments do not count.
`python scripts/ledger.py resume` prints the Hypotheses section and the last session log entry,
so a new session starts from them.

## Authorization

Target: fieldnotes.apk (com.fieldnotes.demo 1.2.0), a test app the user wrote themselves. The user stated authorization to analyze and run it, in a disposable arm64 VM without internet. Result is an endpoint list and auth flow. Static analysis only; the app was not run (no server reachable).

## Hypotheses

<!-- One line each, numbered as findings refer to them, with the state it is in:
- H1: the settings blob is zlib-compressed JSON. Open.
- H2: the first two header bytes are a format version. Supported by F-003.
- H3: the cache file is encrypted. Disproved by F-005.
-->

## Summary

Three POST endpoints on https://api.fieldnotes.example (base URL XOR-obfuscated): /v2/session (login by device_id, returns token), /v2/notes/sync (Bearer), and hidden /internal/diag (Bearer, gated by a debug_menu preference). Every call carries a static X-App-Key header.

## Gaps

- Server responses/schemas unknown: run against a mock server in the VM and capture traffic.
- Findings are confirmed by static cross-check of smali only, not runtime traffic.
- The X-App-Key value is a hardcoded demo constant, not reproduced in the report.
- Assumption: the .example domain is a placeholder.

## Session log

<!-- One entry per session, newest last, under a ### heading with the date:
### 2026-11-05
- Did: decompiled parse_header, read its LOOKUP table with --bytes.
- Showed: F-002 and F-003 inferred; H1 still open.
- Next: write tests/check_parse_header.py and verify F-002 as a function.
-->
