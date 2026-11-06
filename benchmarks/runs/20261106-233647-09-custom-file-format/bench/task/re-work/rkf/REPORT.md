# Reverse Engineering Report: rkf

- **SHA-256:** alpha.rkf: 9cbf29e326e51b97626cdfd67a741a91426bcb65430c300150e33be120ac39bb, bravo.rkf: cc868611d8627fe9e4d4e4d073fa2c08d484f0ce2927cc8dbfed7fd122745235, charlie.rkf: 86f069dd33da78dbf5afd8a1dcb76ab48454c1ca16549044e7b05c24b5cb81e9
- **Authorization:** Target: alpha/bravo/charlie.rkf, small data files (not executables). Owner: the user, who wrote them as test targets and authorized analysis. Purpose: a Kaitai Struct spec (rkf.ksy) that parses all three. Static analysis only; nothing was executed.
- **Generated:** 2026-11-06 22:36 UTC

## Summary

rkf.ksy parses all three files with kaitai-struct-compiler (Python target) and consumes each to EOF. Format: 'RKF1', u2 version, u2 count, records (u1 type, u2 len, body), CRC-32 trailer. The CRC matches in every file.

## Confirmed findings

- **F-001** RKF layout: 'RKF1', u2 version, u2 record count, records (u1 type, u2 len, body; 1=UTF-8 string, 2=s4, 3=bytes), trailing u4 CRC-32 of all preceding bytes; all little-endian; versions 2 and 3 identical
  - Location: original/*.rkf
  - Evidence: hexdump; CRC32 matches in all 3 files
  - Verified by: tests/check_parser.py, a decoder check: 3 cases passed, none failed, on original/alpha.rkf

## Observed findings

None.

## Inferred findings

None.

## Gaps and next experiments

- Record types 0 and 4+ are unseen; a sample using them would show whether they exist. Unknown types are not parsed and would fail the spec.
- Version meaning (2 vs 3) is unknown: no difference seen. A producer or parser for the format would settle it.
- Check used the same 3 files as analysis, so it is not an independent capture. Next: write a fresh file and parse it.
- Type 2 body is parsed as s4 without checking len==4. Type 3 bytes are raw.
- Assumed little-endian, UTF-8, CRC-32/zlib over all preceding bytes (verified by recomputation).

## Retracted findings

None.
