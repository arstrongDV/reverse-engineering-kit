# Notes: {{target}}

make_report.py needs text under Authorization, Summary and Gaps. Comments do not count.
`python scripts/ledger.py resume` prints the Hypotheses section and the last session log entry,
so a new session starts from them.

## Authorization

<!-- What the target is, who owns it, what permits this analysis, and what the result is for. -->

## Hypotheses

<!-- One line each, numbered as findings refer to them, with the state it is in:
- H1: the settings blob is zlib-compressed JSON. Open.
- H2: the first two header bytes are a format version. Supported by F-003.
- H3: the cache file is encrypted. Disproved by F-005.
-->

## Summary

<!-- Two or three sentences a reader can act on. Write this last. -->

## Gaps

<!-- Each open question with the next experiment that would close it, or "None". -->

## Session log

<!-- One entry per session, newest last, under a ### heading with the date:
### 2026-11-05
- Did: decompiled parse_header, read its LOOKUP table with --bytes.
- Showed: F-002 and F-003 inferred; H1 still open.
- Next: write tests/check_parse_header.py and verify F-002 as a function.
-->
