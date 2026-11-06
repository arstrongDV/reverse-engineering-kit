# Reverse Engineering Report: crackme

- **SHA-256:** 76fabff2f4be738c5d5013a500e95669f8dd5b370cdc4bfa73be85f39fcb61ce
- **Authorization:** User-owned crackme written as a test target; user authorized analysis and running it, inside a disposable arm64 VM. Purpose: identify packer, unpack, find serial.
- **Generated:** 2026-11-06 22:26 UTC

## Summary

Packer is UPX; unpacked with `upx -d` to a static arm64 ELF. main (FUN_004007c8) calls FUN_00400740, which needs a 16-char serial. Inverting it gives `RK26-XOR7-ROL3-A`, accepted by the original packed binary and rejecting two wrong inputs.

## Confirmed findings

- **F-002** Serial is RK26-XOR7-ROL3-A: 16 chars, rotl3((c^key[i%4])) == table, key 5ac3179e, table at 0x463f68
  - Location: FUN_00400740
  - Evidence: decompiled check inverted in Python
  - Verified by: tests/check_serial.py, a function check: 3 cases passed, none failed

## Observed findings

- **F-001** Packer is UPX (3.x/5.x format, arm64); 'upx -d' unpacks it to a static ELF
  - Location: original/crackme-packed @0x1a0
  - Evidence: UPX! marker, upx -d succeeded 250836->603608 bytes

## Inferred findings

None.

## Gaps and next experiments

Thunk FUN_00400290 assumed to be strlen (length 0x10 compared); wrong lengths were rejected in the test, but not disassembled further. Assumption: the serial is unique, since the per-byte transform is a bijection.

## Retracted findings

None.
