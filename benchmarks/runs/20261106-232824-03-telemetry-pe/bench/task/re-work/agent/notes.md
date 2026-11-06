# Notes: {{target}}

make_report.py needs text under Authorization, Summary and Gaps. Comments do not count.
`python scripts/ledger.py resume` prints the Hypotheses section and the last session log entry,
so a new session starts from them.

## Authorization

agent.exe: user-written test target, in /home/bench/task. User states they own it and authorized analysis and running, in a disposable arm64 VM without internet. Output: behavior profile (registry, network, frame format). Assumption: no user Q&A available, so scope is as stated. Not executed: no Wine/emulator on this arm64 VM; static analysis only.


## Hypotheses

<!-- One line each, numbered as findings refer to them, with the state it is in:
- H1: the settings blob is zlib-compressed JSON. Open.
- H2: the first two header bytes are a format version. Supported by F-003.
- H3: the cache file is encrypted. Disproved by F-005.
-->

## Summary

agent.exe is a one-shot telemetry beacon. It reads DeviceId and IntervalSeconds from HKCU\Software\ReKitBench\Telemetry (read-only), then makes one TCP connection to 127.0.0.1:47800 and sends a single 'RKTL' frame (14-byte overhead, text payload, rotate-xor 16-bit checksum) and exits. Registry and network claims are confirmed by string checks only. The frame and checksum are inferred from decompilation, not runtime.


## Gaps

- Never run (no Wine/PE emulator on arm64): capture a real frame on a Windows or Wine host with a listener on 47800 and check it against the checksum model.
- u32 at offset 8 is always 1; its meaning is unknown.
- The interval value is only echoed in the payload; it is not used for sleeping or looping.
- Checksum scope (whole header+payload) is from decompiled code, so confirm it with a capture.


## Session log

<!-- One entry per session, newest last, under a ### heading with the date:
### 2026-11-05
- Did: decompiled parse_header, read its LOOKUP table with --bytes.
- Showed: F-002 and F-003 inferred; H1 still open.
- Next: write tests/check_parse_header.py and verify F-002 as a function.
-->
