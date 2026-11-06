# Notes: {{target}}

make_report.py needs text under Authorization, Summary and Gaps. Comments do not count.
`python scripts/ledger.py resume` prints the Hypotheses section and the last session log entry,
so a new session starts from them.

## Authorization

Target: alpha/bravo/charlie.rkf, small data files (not executables). Owner: the user, who wrote them as test targets and authorized analysis. Purpose: a Kaitai Struct spec (rkf.ksy) that parses all three. Static analysis only; nothing was executed.

## Hypotheses

<!-- One line each, numbered as findings refer to them, with the state it is in:
- H1: the settings blob is zlib-compressed JSON. Open.
- H2: the first two header bytes are a format version. Supported by F-003.
- H3: the cache file is encrypted. Disproved by F-005.
-->

## Summary

rkf.ksy parses all three files with kaitai-struct-compiler (Python target) and consumes each to EOF. Format: 'RKF1', u2 version, u2 count, records (u1 type, u2 len, body), CRC-32 trailer. The CRC matches in every file.

## Gaps

- Record types 0 and 4+ are unseen; a sample using them would show whether they exist. Unknown types are not parsed and would fail the spec.
- Version meaning (2 vs 3) is unknown: no difference seen. A producer or parser for the format would settle it.
- Check used the same 3 files as analysis, so it is not an independent capture. Next: write a fresh file and parse it.
- Type 2 body is parsed as s4 without checking len==4. Type 3 bytes are raw.
- Assumed little-endian, UTF-8, CRC-32/zlib over all preceding bytes (verified by recomputation).

## Session log

<!-- One entry per session, newest last, under a ### heading with the date:
### 2026-11-05
- Did: decompiled parse_header, read its LOOKUP table with --bytes.
- Showed: F-002 and F-003 inferred; H1 still open.
- Next: write tests/check_parse_header.py and verify F-002 as a function.
-->

### 2026-11-06
- Did: hexdump, CRC test, wrote rkf.ksy, check.
- Showed: all 3 parse.
- Next: test with fresh samples.
