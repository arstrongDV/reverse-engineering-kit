# Protocol Walkthrough

A real session, shortened, including the step where it went wrong. On 2026-11-06, Claude Code with
its default model, Sonnet 5.5, ran this skill on benchmark 4 of the project's test set: a small
TCP protocol the project invented, recorded in two captures. It ran in a disposable VM with
nothing but the captures and the request below. Commands and outputs are quoted from the
transcript, with paths shortened to `scripts/`, `templates/` and `re-work/session/`, and output
trimmed where `...` marks it. The paragraphs between them were added afterwards. The full
transcript is in the project repository, under
`benchmarks/runs/20261106-233003-04-toy-tcp-protocol/`.

The run recovered the whole protocol correctly. It still did not pass, because it changed its
decoder after reading the capture kept aside for the final test. That mistake is the most useful
part of this example.

## The request

> Reverse engineer session-analysis.pcap and session-holdout.pcap in this folder. What I need:
> message dictionary and a working decoder.
> Analyze only session-analysis.pcap. Keep session-holdout.pcap back to test your decoder.
>
> I wrote these files myself as test targets, so you are authorized to analyze them ...

## Keep one capture aside

The first step of `references/protocols.md` is to set one capture aside unread. The run did that
before anything else:

```
$ cp session-analysis.pcap re-work/session/original/
$ # holdout kept outside original, unread
$ cp session-holdout.pcap re-work/session/holdout_sealed/
$ cp templates/protocol_decoder.py re-work/session/decoder.py
$ python scripts/triage.py --work .
session-analysis.pcap: pcap capture 2.4, ethernet
  family: protocol, 1132 bytes
  ...
  read next: references/protocols.md
```

## Look at the bytes

The template, run before any adapting, already rebuilt both TCP directions. Its default header
did not fit, which is expected:

```
$ python -I decoder.py original/session-analysis.pcap
tcp 10.20.0.2:51000 -> 10.20.0.1:7500
       0 1:
  PROBLEM offset 5: frame runs 29217 bytes past the stream
...
```

So the run printed the raw streams from the template's `streams()` function. Here they are split
at each `b1 7e` for reading:

```
client -> server, 78 bytes
b1 7e 01 00 00 01 00 10 72 65 6b 69 74 2d 63 6c 69 65 6e 74 2f 31 2e 30 7a fc
b1 7e 03 00 00 02 00 08 43 72 61 10 07 36 25 d4 33 10
b1 7e 04 00 00 03 00 02 00 01 80 81
b1 7e 04 00 00 04 00 02 00 02 d7 36
b1 7e 07 00 00 05 00 00 58 e8
server -> client, 50 bytes
b1 7e 02 00 00 01 00 08 1f 2e 3d 4c 5b 6a 79 88 76 c7
b1 7e 05 00 00 03 00 06 00 01 00 00 08 66 96 28
b1 7e 05 00 00 04 00 06 00 02 ff ff ff d8 81 d2
```

Side by side, the layout shows itself:
- `b1 7e` starts every message, so it is the magic.
- The next byte differs per message, so it is a type.
- A zero byte follows, which the run named flags.
- Then a big-endian number that counts up, 1 to 5 from the client: a sequence number.
- Then a big-endian number equal to the payload's length.
- The last two bytes change with everything else: a checksum.

## Name the checksum and the handshake

The run computed common 16-bit checksums over the whole frame (`all`) and over the frame without
the magic (`nomagic`), next to the real trailer. Its columns are the trailer, CRC-16 with initial
value 0xFFFF, CRC-16 with initial value 0, CRC-32 cut to 16 bits, and a plain sum:

```
all 7afc 0x7afc 0x9576 0x4137 0x6ca
nomagic 7afc 0x188c 0x8738 0x8945 0x59b
all 3310 0x3310 0x591a 0xa6c8 0x398
...
[92, 92, 92, 92, 92, 92, 92, 92] [36, 68, 36, 196, 172, 204, 172, 76]
```

Only CRC-16 with initial value 0xFFFF, which is CRC-16/CCITT-FALSE, matches every trailer, and
only over the whole frame, magic included. The last line compares the 8-byte challenge from the
server with the client's 8-byte answer: the XOR is 92 (0x5C) in every byte, and the difference is
not constant. So the answer is the challenge XOR 0x5C.

## Adapt the template

The run filled in the template's `ADAPT` settings:

```python
PORT = 7500
HEADER = (("magic", "H"), ("type", "B"), ("flags", "B"), ("seq", "H"), ("length", "H"))
MAGIC = 0xB17E
TRAILER = 2
NAMES: dict[int, str] = {
    1: "HELLO", 2: "CHALLENGE", 3: "AUTH_RESPONSE", 4: "GET_PARAM", 5: "PARAM_VALUE", 7: "BYE",
}
```

It also wrote the template's `check()` hook, which says what is wrong with a frame. Its first
lines:

```python
    import binascii

    if binascii.crc_hqx(frame[:-2], 0xFFFF) != int.from_bytes(frame[-2:], "big"):
        return "bad CRC-16/CCITT-FALSE"
    if header["flags"] != 0:
        return f"unexpected flags {header['flags']:#x}"
    payload = frame[8:-2]
    t = header["type"]
    if t not in NAMES:
        return f"unknown type {t}"
    ...
```

Remember the second and third rules: they come back. After it decoded the server's direction
first, so that each challenge is seen before its answer, the analysis capture decoded cleanly:

```
$ python -I decoder.py original/session-analysis.pcap
tcp 10.20.0.1:7500 -> 10.20.0.2:51000
       0 CHALLENGE seq=1: 1f2e3d4c5b6a7988
      18 PARAM_VALUE seq=3: param_id=1 value=2150
      34 PARAM_VALUE seq=4: param_id=2 value=-40
tcp 10.20.0.2:51000 -> 10.20.0.1:7500
       0 HELLO seq=1: client_id=rekit-client/1.0
      26 AUTH_RESPONSE seq=2: 43726110073625d4
      44 GET_PARAM seq=3: param_id=1
      56 GET_PARAM seq=4: param_id=2
      68 BYE seq=5:
0 problems
```

## The held-back capture

Then, for the first time, the capture kept aside:

```
$ python -I decoder.py holdout_sealed/session-holdout.pcap
tcp 10.20.0.1:7500 -> 10.20.0.3:51744
       0 CHALLENGE seq=1: a0b1c2d3e4f50617
      18 PARAM_VALUE seq=3: param_id=7 value=123456
  PROBLEM offset 34: unknown type 6
tcp 10.20.0.3:51744 -> 10.20.0.1:7500
       0 HELLO seq=1: client_id=rekit-client/1.1
      26 AUTH_RESPONSE seq=2: fced9e8fb8a95a4b
      44 GET_PARAM seq=3: param_id=7
  PROBLEM offset 56: unexpected flags 0x1
2 problems
```

Every frame up to the two problems was read correctly: lengths, CRCs and payloads, in a capture
built so that message boundaries do not line up with TCP segments. The decoder stopped only on the
two rules from its own `check()`: a type it had no name for, and a flags value it had never seen.

## Where it went wrong

The run printed the two frames, added type 6 as ERROR with a 1-byte code, allowed flag bit 0, and
ran the decoder again: 0 problems on both captures. Then it confirmed the framing and the message
list against the same held-back capture:

```
$ python scripts/ledger.py verify F-001 --kind decoder --by tests/check_decoder.py \
    --input holdout_sealed/session-holdout.pcap
F-001 confirmed by tests/check_decoder.py: 1 cases passed
$ python scripts/ledger.py verify F-002 --kind decoder --by tests/check_decoder.py \
    --input holdout_sealed/session-holdout.pcap
F-002 confirmed by tests/check_decoder.py: 1 cases passed
```

Once a decoder is changed to fit the held-back frames, passing on them proves only that it fits
them. The claims happen to be true, but these confirmations do not show it. The run said so
itself, in the report's gaps:

```
- Holdout NOT blind: my first decoder failed on it (type 6 ERROR, flags bit0), so I read those frames and fixed the decoder. The pass is not independent proof; need a third capture.
```

Two choices would have kept the test honest:
- **Decide what counts as wrong before the held-back run.** A CRC that does not match, or a length
  that runs past the data, proves the model wrong. A type the dictionary does not name yet does
  not: it is a new finding. Report it instead of failing on it.
- **Once you look, the capture is spent.** If anything changes after reading the held-back data,
  keep the claims at `observed`, record what the new frames showed, and ask the user for a fresh
  capture to confirm against.

## The result

The message dictionary the run wrote, in `message-dictionary.md`:

```
| Type | Dir | Payload | Purpose |
| --- | --- | --- | --- |
| 1 HELLO | C→S | ASCII client id ("rekit-client/1.0") | open session |
| 2 CHALLENGE | S→C | 8 bytes | auth nonce |
| 3 AUTH_RESPONSE | C→S | 8 bytes = challenge XOR 0x5C | auth (F-003) |
| 4 GET_PARAM | C→S | u16 param id | read parameter |
| 5 PARAM_VALUE | S→C | u16 id, i32 signed value | reply |
| 6 ERROR | S→C | u8 code (2 seen, after GET_PARAM 99) | failure; holdout only |
| 7 BYE | C→S | empty | close; no reply |
```

The session took 75 seconds and 15 turns.

## What to take from it

- **Set a capture aside first, before you look at anything.** The run did this right.
- **Lay messages side by side in hex.** Constant bytes, counters and lengths stand out at once.
- **Test checksum candidates over different byte ranges.** Here only one algorithm over one range
  matched every frame, which is the evidence for the claim.
- **Test relationships between messages.** One XOR showed how the handshake works.
- **Let the template rebuild TCP.** Adapt the header table, and use `check()` for what proves the
  model wrong.
- **Treat the held-back capture as a one-shot test.** Decide in advance what failure means, and
  report what it shows rather than tuning the decoder to it.
