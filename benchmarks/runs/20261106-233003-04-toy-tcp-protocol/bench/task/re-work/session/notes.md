# Notes: {{target}}

make_report.py needs text under Authorization, Summary and Gaps. Comments do not count.
`python scripts/ledger.py resume` prints the Hypotheses section and the last session log entry,
so a new session starts from them.

## Authorization

Targets: two pcaps in /home/bench/task, written by the user as test targets; user stated authorization to analyze, in a disposable VM. Output: message dictionary and decoder. Static capture analysis only; no network traffic sent.

## Hypotheses

<!-- One line each, numbered as findings refer to them, with the state it is in:
- H1: the settings blob is zlib-compressed JSON. Open.
- H2: the first two header bytes are a format version. Supported by F-003.
- H3: the cache file is encrypted. Disproved by F-005.
-->

## Summary

Custom binary protocol over TCP 7500: magic B17E, type, flags, seq, length, payload, CRC-16/CCITT-FALSE. Challenge/response auth (XOR 0x5C), GET_PARAM/PARAM_VALUE, ERROR, BYE. decoder.py parses both captures with 0 problems.

## Gaps

- Holdout NOT blind: my first decoder failed on it (type 6 ERROR, flags bit0), so I read those frames and fixed the decoder. The pass is not independent proof; need a third capture.
- XOR key 0x5C is fit from 2 pairs (both consistent) but may depend on session/client version; need client code or more captures.
- Meaning of flags bit0 and ERROR code 2 are guesses; need more captures with other errors/flags.
- Server reply to AUTH_RESPONSE absent in captures; failed-auth behaviour unknown.

## Session log

### 2026-11-06
- Did: analysis pcap decoded, then holdout tested; revised decoder once.
