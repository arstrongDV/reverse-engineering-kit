# Reverse Engineering Report: app

- **SHA-256:** cb66988e14d605df0bf814f12fdd4b3ecf2c946757d22931494ea2480ceb1ad5
- **Authorization:** User states they wrote app.obfuscated.js themselves as a test target and authorized analysis and execution, in a disposable arm64 Ubuntu VM without internet. Result: readable deobfuscated source. Assumption: user cannot answer questions, so reasonable defaults were used.
- **Generated:** 2026-11-06 22:37 UTC

## Summary

The 59-line file is a string-array-obfuscated script that builds a report object (user, event count, first event by time, hash signature, telemetry URL) and prints it as JSON. It performs no network I/O. A readable equivalent is in deliverable/app.readable.js; it matches the original on 5 differential cases.

## Confirmed findings

- **F-001** Obfuscated file is a telemetry-report builder: sorts events by time, emits {user,count,first,signature,target=https://telemetry.example/collect}; nothing is sent over the network
  - Location: app.obfuscated.js:_0x4c71bc
  - Evidence: webcrack output; readable rewrite behaves identically
  - Verified by: tests/check_report.py, a function check: 5 cases passed, none failed
- **F-002** Signature = per-event hex of 31-multiplier rolling hash mod 65521 over 'rekit-benchmark'+name, joined by '-'
  - Location: app.obfuscated.js:_0x3dbba3,_0x80dc6c
  - Evidence: webcrack output
  - Verified by: tests/check_report.py, an algorithm check: 5 cases passed, none failed

## Observed findings

None.

## Inferred findings

None.

## Gaps and next experiments

- The URL telemetry.example/collect is never contacted by this file; whether another component sends the report is unknown (needs the rest of the app).
- Equivalence tested on sampled inputs, not proven exhaustively.

## Retracted findings

None.
