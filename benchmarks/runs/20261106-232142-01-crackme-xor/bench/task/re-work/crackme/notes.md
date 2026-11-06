# Notes: {{target}}

make_report.py needs text under Authorization, Summary and Gaps. Comments do not count.
`python scripts/ledger.py resume` prints the Hypotheses section and the last session log entry,
so a new session starts from them.

## Authorization

<!-- What the target is, who owns it, what permits this analysis, and what the result is for. -->
Target: ./crackme (arm64 ELF), written by the user as a test target. The user authorized analysis and execution in a disposable VM. Result is the serial plus an explanation. Assumption: the user can't answer questions, so I proceeded on this basis.

## Hypotheses

<!-- One line each, numbered as findings refer to them, with the state it is in:
- H1: the serial check is a XOR with a fixed key. Open.
- H2: the length must be 16. Supported by F-003.
- H3: the key comes from the network. Disproved by F-005.
-->
- H1: serial is checked byte-wise by XOR with a 4-byte key then rotl3. Confirmed by F-001.

## Summary

<!-- Two or three sentences a reader can act on. Write this last. -->
Serial is `RK26-XOR7-ROL3-A`. check_serial requires length 16, and each byte c must satisfy rotl3(c ^ KEY[i%4]) == EXPECTED[i]. Inverting that per byte gives the serial, and the binary accepts it.

## Gaps

<!-- Each open question with the next experiment that would close it, or "None". -->
None. The serial is unique, since each step is a bijection per position.

## Session log

<!-- One entry per session, newest last, under a ### heading with the date:
### 2026-11-05
- Did: decompiled parse_header, read its LOOKUP table with --bytes.
- Showed: F-002 and F-003 inferred; H1 still open.
- Next: write tests/check_parse_header.py and verify F-002 as a function.
-->
