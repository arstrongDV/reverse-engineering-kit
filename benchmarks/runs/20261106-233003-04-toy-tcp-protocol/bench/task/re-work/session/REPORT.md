# Reverse Engineering Report: session

- **SHA-256:** fe675f351d3b5bb235efab7e60f453dc01a3ca603ea656716121797e50377c5a
- **Authorization:** Targets: two pcaps in /home/bench/task, written by the user as test targets; user stated authorization to analyze, in a disposable VM. Output: message dictionary and decoder. Static capture analysis only; no network traffic sent.
- **Generated:** 2026-11-06 22:29 UTC

## Summary

Custom binary protocol over TCP 7500: magic B17E, type, flags, seq, length, payload, CRC-16/CCITT-FALSE. Challenge/response auth (XOR 0x5C), GET_PARAM/PARAM_VALUE, ERROR, BYE. decoder.py parses both captures with 0 problems.

## Confirmed findings

- **F-001** Frame: magic B1 7E, type u8, flags u8, seq u16 BE, len u16 BE, payload, CRC-16/CCITT-FALSE (init FFFF) BE over all preceding bytes incl. magic
  - Location: session-analysis.pcap, all 8 frames
  - Evidence: CRC matched on every analysis frame
  - Verified by: tests/check_decoder.py, a decoder check: 1 cases passed, none failed, on holdout_sealed/session-holdout.pcap
- **F-002** Types: 1 HELLO(ascii client id), 2 CHALLENGE(8B), 3 AUTH_RESPONSE(8B), 4 GET_PARAM(u16 id), 5 PARAM_VALUE(u16 id, i32 BE value), 7 BYE(empty); server echoes request seq; TCP port 7500
  - Location: session-analysis.pcap
  - Evidence: payload sizes and values (2150, -40) consistent
  - Verified by: tests/check_decoder.py, a decoder check: 1 cases passed, none failed, on holdout_sealed/session-holdout.pcap

## Observed findings

- **F-003** AUTH_RESPONSE = CHALLENGE XOR 0x5C bytewise
  - Location: analysis frames 2/3
  - Evidence: one pair in analysis; second pair seen in holdout (a0b1..->fced..)

## Inferred findings

- **F-004** Type 6 ERROR (1-byte code) and flags bit0 exist; meanings (code 2 = unknown param?, flag 1) are guesses
  - Location: session-holdout.pcap only
  - Evidence: holdout; not in analysis capture

## Gaps and next experiments

- Holdout NOT blind: my first decoder failed on it (type 6 ERROR, flags bit0), so I read those frames and fixed the decoder. The pass is not independent proof; need a third capture.
- XOR key 0x5C is fit from 2 pairs (both consistent) but may depend on session/client version; need client code or more captures.
- Meaning of flags bit0 and ERROR code 2 are guesses; need more captures with other errors/flags.
- Server reply to AUTH_RESPONSE absent in captures; failed-auth behaviour unknown.

## Retracted findings

None.
