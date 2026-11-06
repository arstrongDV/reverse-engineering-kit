# Notes: app.obfuscated.js

## Authorization
User states they wrote app.obfuscated.js themselves as a test target and authorized analysis and execution, in a disposable arm64 Ubuntu VM without internet. Result: readable deobfuscated source. Assumption: user cannot answer questions, so reasonable defaults were used.

## Hypotheses
- H1: file is a small telemetry/report builder with a custom hash signature. Supported by F-001, F-002.

## Summary
The 59-line file is a string-array-obfuscated script that builds a report object (user, event count, first event by time, hash signature, telemetry URL) and prints it as JSON. It performs no network I/O. A readable equivalent is in deliverable/app.readable.js; it matches the original on 5 differential cases.

## Gaps
- The URL telemetry.example/collect is never contacted by this file; whether another component sends the report is unknown (needs the rest of the app).
- Equivalence tested on sampled inputs, not proven exhaustively.

## Session log
### 2026-11-06
- Did: webcrack, manual renaming, differential test run in the VM under node.
- Showed: F-001, F-002 confirmed.
