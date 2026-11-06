# Reverse Engineering Report: crackme

- **SHA-256:** SHA256: b6b5890be9b193667d6a8607900478c9da2adfc21332eaa9bf7a3f2d82497b88, crackme: ba5a8d7c95067b3eeb6b915c3d3819410ed49816a5964e05e1da6c19dbbfebbd
- **Authorization:** Target: ./crackme (arm64 ELF), written by the user as a test target. The user authorized analysis and execution in a disposable VM. Result is the serial plus an explanation. Assumption: the user can't answer questions, so I proceeded on this basis.
- **Generated:** 2026-11-06 22:21 UTC

## Summary

Serial is `RK26-XOR7-ROL3-A`. check_serial requires length 16, and each byte c must satisfy rotl3(c ^ KEY[i%4]) == EXPECTED[i]. Inverting that per byte gives the serial, and the binary accepts it.

## Confirmed findings

- **F-001** Valid serial is RK26-XOR7-ROL3-A: 16 chars, each byte c satisfies rotl3(c ^ KEY[i%4]) == EXPECTED[i]
  - Location: check_serial @ 0x1007e8; EXPECTED @ 0x938, KEY @ 0x948
  - Evidence: Ghidra decompile; inverted table in tests/check_serial.py
  - Verified by: tests/check_serial.py, a algorithm check: 3 cases passed, none failed

## Observed findings

None.

## Inferred findings

None.

## Gaps and next experiments

None. The serial is unique, since each step is a bijection per position.

## Retracted findings

None.
