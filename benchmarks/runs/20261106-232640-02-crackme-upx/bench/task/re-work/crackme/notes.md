# Notes: crackme-packed

## Authorization
User-owned crackme written as a test target; user authorized analysis and running it, inside a disposable arm64 VM. Purpose: identify packer, unpack, find serial.

## Hypotheses
- H1: UPX packed. Confirmed (upx -d works).
- H2: 16-char serial, xor with 4-byte key then rotl3, compared to table. Confirmed by F-002.

## Summary
Packer is UPX; unpacked with `upx -d` to a static arm64 ELF. main (FUN_004007c8) calls FUN_00400740, which needs a 16-char serial. Inverting it gives `RK26-XOR7-ROL3-A`, accepted by the original packed binary and rejecting two wrong inputs.

## Gaps
Thunk FUN_00400290 assumed to be strlen (length 0x10 compared); wrong lengths were rejected in the test, but not disassembled further. Assumption: the serial is unique, since the per-byte transform is a bijection.

## Session log
### 2026-11-06
- Did: triage, upx -d, Ghidra, inverted check, verified.
