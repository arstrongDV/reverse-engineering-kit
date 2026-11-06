# Reverse Engineering Report: fieldnotes

- **SHA-256:** 2047eaa2117d08e779dde1af9439f1bab65ca953b25aeb4858813699d96efa11
- **Authorization:** Target: fieldnotes.apk (com.fieldnotes.demo 1.2.0), a test app the user wrote themselves. The user stated authorization to analyze and run it, in a disposable arm64 VM without internet. Result is an endpoint list and auth flow. Static analysis only; the app was not run (no server reachable).
- **Generated:** 2026-11-06 22:31 UTC

## Summary

Three POST endpoints on https://api.fieldnotes.example (base URL XOR-obfuscated): /v2/session (login by device_id, returns token), /v2/notes/sync (Bearer), and hidden /internal/diag (Bearer, gated by a debug_menu preference). Every call carries a static X-App-Key header.

## Confirmed findings

- **F-001** Base URL is https://api.fieldnotes.example (XOR 55 int array in Endpoints)
  - Location: Endpoints.java:8-20
  - Evidence: Decoded array; cleartext not present in strings
  - Verified by: tests/check_endpoints.py, a behavior check: 7 cases passed, none failed
- **F-002** POST /v2/session with {device_id} returns JSON token; unauthenticated except X-App-Key
  - Location: ApiClient.java:login
  - Evidence: login() posts, parses token substring
  - Verified by: tests/check_endpoints.py, a behavior check: 7 cases passed, none failed
- **F-003** POST /v2/notes/sync with Authorization: Bearer <token>
  - Location: ApiClient.java:sync
  - Evidence: post(sync(), body, true)
  - Verified by: tests/check_endpoints.py, a behavior check: 7 cases passed, none failed
- **F-004** POST /internal/diag (hidden, reversed string) with Bearer token, only if SharedPreferences debug_menu=true
  - Location: Endpoints.java:diagnostics, MainActivity.work
  - Evidence: StringBuilder.reverse; pref gate
  - Verified by: tests/check_endpoints.py, a behavior check: 7 cases passed, none failed
- **F-005** All requests send static header X-App-Key (hardcoded, split constant); token held in memory only; plain HttpURLConnection, no pinning, no token refresh
  - Location: ApiClient.java:13-30
  - Evidence: appKey() returns constant
  - Verified by: tests/check_endpoints.py, a behavior check: 7 cases passed, none failed

## Observed findings

None.

## Inferred findings

None.

## Gaps and next experiments

- Server responses/schemas unknown: run against a mock server in the VM and capture traffic.
- Findings are confirmed by static cross-check of smali only, not runtime traffic.
- The X-App-Key value is a hardcoded demo constant, not reproduced in the report.
- Assumption: the .example domain is a placeholder.

## Retracted findings

None.
