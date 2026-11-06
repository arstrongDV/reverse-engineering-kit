# Notes: antidebug

## Authorization
Target: ./antidebug (arm64 ELF), a test program written by the user, who owns it. The user authorized analysis and execution in a disposable arm64 VM with no network. Purpose: find and document the anti-debug check. Assumption (user unavailable): the "launch code" it prints is a harmless test value, so reporting it is fine.

## Hypotheses
- H1: TracerPid in /proc/self/status is checked. Supported by F-001, verified by the traced run.
- H2: ptrace(PTRACE_TRACEME) is a second check. Inferred from the decompile only (F-002).
- H3: the message is XOR 0x2a encoded. Observed (F-003).

## Summary
antidebug has two stacked anti-debug checks in main (00100b28). First it parses TracerPid from /proc/self/status and treats a nonzero value as a debugger. Then it calls ptrace(PTRACE_TRACEME), and a -1 return (already traced) also counts as a debugger. A debugger gets the decoy "Nothing to see here."; otherwise it prints "The launch code is ORCHID-42", decoded from a XOR 0x2a blob.

## Gaps
- F-002 (the ptrace branch on its own) is not isolated at runtime. Next: run it with /proc/self/status unreadable, for example in a mount namespace, while already traced, and check for the decoy.
- Bypass was not attempted, as it was not requested.

## Session log
### 2026-11-06
- Did: triage, Ghidra decompile of main, ran the binary untraced and under a ptrace parent.
- Showed: F-001 verified, F-002 and F-003 not yet.
- Next: isolate the ptrace branch.
