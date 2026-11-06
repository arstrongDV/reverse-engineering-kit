# Reverse Engineering Report: antidebug

- **SHA-256:** ec5fce02fb2ab1e87f373416096dac7ec3245168ee6d1a827562312b5ee83823
- **Authorization:** Target: ./antidebug (arm64 ELF), a test program written by the user, who owns it. The user authorized analysis and execution in a disposable arm64 VM with no network. Purpose: find and document the anti-debug check. Assumption (user unavailable): the "launch code" it prints is a harmless test value, so reporting it is fine.
- **Generated:** 2026-11-06 22:34 UTC

## Summary

antidebug has two stacked anti-debug checks in main (00100b28). First it parses TracerPid from /proc/self/status and treats a nonzero value as a debugger. Then it calls ptrace(PTRACE_TRACEME), and a -1 return (already traced) also counts as a debugger. A debugger gets the decoy "Nothing to see here."; otherwise it prints "The launch code is ORCHID-42", decoded from a XOR 0x2a blob.

## Confirmed findings

- **F-001** main reads /proc/self/status, finds the TracerPid: line and, if its value is nonzero, prints 'Nothing to see here.' and returns 0 (decoy path, no secret)
  - Location: main @ 00100b28
  - Evidence: Decompiled main: fopen/fgets/strncmp('TracerPid:',10)/strtol; string TracerPid in triage
  - Verified by: tests/check_antidebug.py, a behavior check: 2 cases passed, none failed

## Observed findings

- **F-003** When both checks pass, main prints 'The launch code is ' plus 9 bytes at MESSAGE (00100d28) XOR 0x2a = ORCHID-42
  - Location: MESSAGE @ 00100d28
  - Evidence: bytes 65 78 69 62 63 6e 07 1e 18 ^0x2a; observed output

## Inferred findings

- **F-002** If TracerPid is 0 (or the file cannot be opened/has no such line), main calls ptrace(PTRACE_TRACEME); a return of -1 (already traced) takes the same decoy path
  - Location: main @ 00100b28, LAB_00100c2c
  - Evidence: Decompiled main; ptrace import

## Gaps and next experiments

- F-002 (the ptrace branch on its own) is not isolated at runtime. Next: run it with /proc/self/status unreadable, for example in a mount namespace, while already traced, and check for the decoy.
- Bypass was not attempted, as it was not requested.

## Retracted findings

None.
