# Network Protocols and File Formats

Traffic captures, framing, fields, checksums and state machines.

## When to use this

Use this file when `triage.json` reports the family `protocol`: types `pcap`, `pcapng`, `har` or
`unknown`. An unknown type is often a private file format, and the method is the same: find the
structure, write a parser, and prove it on data you did not study.

It also applies when another playbook finds a network protocol in code, such as a frame built in
a native function. Then the code and a capture check each other.

| Tool | Use it for |
| --- | --- |
| `templates/protocol_decoder.py` | A working decoder for pcap and pcapng files, to adapt |
| `templates/message-dictionary.md` | The table of fields and messages, one finding per row |
| `kaitai-struct-compiler` | Turning a file format description (`.ksy`) into a parser |
| `scripts/frida/network.js` | Plaintext before TLS, inside a VM the user confirmed |

## First 15 minutes

1. Keep one capture or sample aside and do not look at it. It is the proof at the end, so with
   only one capture, ask the user for another before you start.
2. Find the conversation: the transport (TCP or UDP), the ports, and who speaks first.
3. Look at the first bytes of several messages side by side, in hex. Constant bytes are a magic
   value or a version. A field that grows by one is a sequence number. A field that matches the
   length of what follows is a length.
4. Copy the template into the work directory and fill in the parts marked `ADAPT`:

```
cp templates/protocol_decoder.py re-work/<target>/decoder.py
python decoder.py decompiled/session-1.pcap
```

   It rebuilds each TCP direction in sequence order, cuts frames with the header table you give
   it, and exits 1 at the first frame that does not fit.
5. Fill in `message-dictionary.md` as you go, with a ledger finding for each field and message.
6. Finally run the decoder on the capture kept aside, through a check the ledger runs. No
   problems there is the check a decoder needs before `confirmed`. Save as
   `tests/check_decoder.py`:

```python
import subprocess
import sys

failed = 0
for capture in sys.argv[1:]:
    run = subprocess.run([sys.executable, "decoder.py", capture], capture_output=True, text=True)
    failed += run.returncode != 0
    print(f"{'PASS' if run.returncode == 0 else 'FAIL'} {capture}: exit {run.returncode}")
sys.exit(1 if failed else 0)
```

```
python scripts/ledger.py verify F-010 --kind decoder --by tests/check_decoder.py --input captures/held-back.pcapng
```

For a file format, write a Kaitai description instead of a decoder, and check it on every sample:

```
kaitai-struct-compiler -t python --outdir decompiled/kaitai format.ksy
```

## Signal → next step

| Signal | Next step |
| --- | --- |
| The same first bytes in every message | A magic value. Set `MAGIC` in the decoder |
| A field equal to the bytes that follow it | A length. Check whether it counts the header and the trailer |
| A field that grows by 1 per message | A sequence number. Check whether replies echo it |
| The last 2 or 4 bytes change with any change elsewhere | A checksum: try CRC-16 variants, CRC-32, a sum, a XOR |
| Random-looking bytes from the server, then a reply derived from them | Challenge and response: find the transform in the client's code |
| An entropy near 8 across the payload | Encrypted or compressed. Look for TLS, then the client's crypto calls |
| Text such as `GET` or JSON | Not binary: read it, and check for HAR or HTTP tooling instead |
| Fields that do not fit any size | Variable-length integers or bit fields; try 7-bit encodings |
| One capture decodes, the other does not | The decoder assumes too much, often about TCP segment boundaries |

Three checksums can be tested with Python's standard library alone, which settles most cases:

```python
import binascii
import functools
import operator
import zlib


def candidates(data):
    return {
        "CRC-16/CCITT-FALSE": binascii.crc_hqx(data, 0xFFFF),
        "CRC-16/XMODEM": binascii.crc_hqx(data, 0),
        "CRC-32": zlib.crc32(data),
        "Adler-32": zlib.adler32(data),
        "sum of bytes, 16 bits": sum(data) & 0xFFFF,
        "XOR of bytes": functools.reduce(operator.xor, data, 0),
    }
```

Run it on the covered bytes of several messages, in both byte orders, and keep the one name that
matches all of them. If none does, the checksum may skip the header, include the length field
twice, or start from another value.

Other structures that recur:

| Pattern | How it looks |
| --- | --- |
| Type, length, value (TLV) | A small type number, a length, then that many bytes, repeated |
| Varint | Bytes with the top bit set continue the number; Protocol Buffers use this |
| Length-prefixed string | A length byte or word, then UTF-8 text |
| Request ID | A number in the request that the reply repeats, so replies can arrive out of order |

Write the state machine as a list in `message-dictionary.md`: which message may follow which,
and what the receiver does with an unexpected one.

A HAR file is a browser's record of HTTP traffic, saved as JSON. Each entry holds a request, with
its method, URL, headers and body, and the response to it. Group the entries by path to get the
API, and remove cookies and `Authorization` headers before quoting any entry in a finding.

## Common traps

- **Assuming one message per packet.** TCP is a byte stream. A message can be split across
  segments, and two can share one. Decode the rebuilt stream, never single packets.
- **Retransmissions.** The same bytes can appear twice. The template keeps the first copy of
  every sequence range.
- **Byte order.** Network protocols are usually big-endian, files from x86 and arm programs
  usually little-endian. Check a length field both ways.
- **Checksum coverage.** A checksum may cover the header, the payload or both. Try each against
  several messages before naming the algorithm.
- **Studying the proof.** Once you have looked at the capture kept aside, it no longer proves
  anything. Ask for a new one.
- **Probing the server.** Sending your own messages to a server the user does not own is
  attacking it. Work from captures and from the client's code.
- **Secrets in captures.** Session tokens and passwords cross the wire. Redact them in findings
  and in the message dictionary.

## Worked example

Benchmark 4 is a toy TCP protocol built for this project, with two captures. The answer is a
message dictionary and a decoder that parses both.

The first capture showed every message starting with `b1 7e` and, two bytes on, a field that
grew by one per request. A 16-bit field before the payload matched its length, and the last two
bytes changed with any change in the message; CRC-16/CCITT-FALSE over the header and payload
matched them all. The template, adapted:

```python
PORT = 7500
MAGIC = 0xB17E
HEADER = (("magic", "H"), ("type", "B"), ("flags", "B"), ("sequence", "H"), ("length", "H"))
TRAILER = 2
NAMES = {1: "HELLO", 2: "CHALLENGE", 3: "RESPONSE", 4: "GET", 5: "VALUE", 6: "ERROR", 7: "BYE"}


def check(frame, header):
    return None if int.from_bytes(frame[-2:], "big") == crc16(frame[:-2]) else "CRC mismatch"
```

It decoded the first capture with no problems. The capture kept aside then also decoded with no
problems, although in it the client's first message is split across two segments and a response
shares a segment with the next request: a decoder that read packet by packet would fail there.
That run, made by `ledger.py verify --kind decoder` with the capture kept aside as `--input`, is
the check that lets the decoder's finding become `confirmed`.

Benchmark 9 is a private file format with three samples, which triage could only call `unknown`.
The 27-byte sample began `52 4b 46 31 02 00 02 00`: the text `RKF1`, then two 16-bit
little-endian numbers, the second matching the number of records that followed. Each record was
a type byte, a 16-bit length and a value, and the last four bytes were a CRC-32 of everything
before them. A `.ksy` description of that, compiled with `kaitai-struct-compiler`, parsed all
three samples and found the record count each header announced.
