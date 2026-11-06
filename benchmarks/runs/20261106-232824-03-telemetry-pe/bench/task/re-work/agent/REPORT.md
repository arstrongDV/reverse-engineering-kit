# Reverse Engineering Report: agent

- **SHA-256:** b56f15fc6acdea09cbf435d69cf342270bd01794b7e4bea2bdc974bc9b3427e0
- **Authorization:** agent.exe: user-written test target, in /home/bench/task. User states they own it and authorized analysis and running, in a disposable arm64 VM without internet. Output: behavior profile (registry, network, frame format). Assumption: no user Q&A available, so scope is as stated. Not executed: no Wine/emulator on this arm64 VM; static analysis only.
- **Generated:** 2026-11-06 22:28 UTC

## Summary

agent.exe is a one-shot telemetry beacon. It reads DeviceId and IntervalSeconds from HKCU\Software\ReKitBench\Telemetry (read-only), then makes one TCP connection to 127.0.0.1:47800 and sends a single 'RKTL' frame (14-byte overhead, text payload, rotate-xor 16-bit checksum) and exits. Registry and network claims are confirmed by string checks only. The frame and checksum are inferred from decompilation, not runtime.

## Confirmed findings

- **F-001** Reads HKCU\Software\ReKitBench\Telemetry values DeviceId (default 'bench-device', max 64B) and IntervalSeconds (REG_DWORD, default 60); read-only (KEY_READ 0x20019), no writes
  - Location: FUN_140001480@140001480
  - Evidence: RegOpenKeyExA(0x80000001,...,0x20019)+RegQueryValueExA; strings present
  - Verified by: tests/check_static.py, a behavior check: 6 cases passed, none failed
- **F-002** Sends one TCP connection to 127.0.0.1:47800 (0xBAB8), single send(), then closes; no recv, no loop/retry; called once from CRT main
  - Location: FUN_140001480@140001480; caller FUN_140001010:150
  - Evidence: socket(2,1,6),htons(0xbab8),inet_addr,connect,send,closesocket; no recv import
  - Verified by: tests/check_static.py, a behavior check: 6 cases passed, none failed

## Observed findings

None.

## Inferred findings

- **F-003** Frame (little-endian): 'RKTL' magic | ver=2 | type=1 | u16 payload_len @6 | u32 =1 @8 (seq/flags, meaning unknown) | ASCII payload 'device=<id>;uptime=<GetTickCount ms>;interval=<n>' | u16 checksum; total=len+14
  - Location: FUN_140001480@140001480
  - Evidence: stack header bytes 52 4b 54 4c 02 01, send length uVar7+0xe
- **F-004** Checksum: c=0; for each byte of header+payload: c=((c<<1)|(c>>15))&0xFFFF ^ byte; appended as u16 LE
  - Location: FUN_140001480 do/while loop
  - Evidence: decompiled loop

## Gaps and next experiments

- Never run (no Wine/PE emulator on arm64): capture a real frame on a Windows or Wine host with a listener on 47800 and check it against the checksum model.
- u32 at offset 8 is always 1; its meaning is unknown.
- The interval value is only echoed in the payload; it is not used for sleeping or looping.
- Checksum scope (whole header+payload) is from decompiled code, so confirm it with a capture.

## Retracted findings

None.
