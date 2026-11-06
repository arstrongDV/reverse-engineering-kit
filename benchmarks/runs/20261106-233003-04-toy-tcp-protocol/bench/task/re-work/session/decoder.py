"""Protocol decoder template. Copy it into re-work/<target>/, adapt the parts marked ADAPT, and
run: python protocol_decoder.py capture.pcap [--json]

It reads pcap and pcapng files with the standard library, puts each TCP direction back in
sequence order (UDP datagrams are taken one by one), cuts the bytes into frames with the field
table below, and checks every frame. It exits 1 if any frame is wrong, so a passing run on a
capture you did not study is the proof that the decoder is right."""

from __future__ import annotations

import json
import socket
import struct
import sys
from pathlib import Path

# ADAPT: the server port, or None to decode every stream in the capture.
PORT = 7500
# ADAPT: the byte order and the fixed header, as (name, struct code) pairs.
BYTE_ORDER = ">"
HEADER = (("magic", "H"), ("type", "B"), ("flags", "B"), ("seq", "H"), ("length", "H"))
# ADAPT: the value every frame starts with, or None.
MAGIC = 0xB17E
# ADAPT: bytes that follow the payload, such as a 2-byte checksum.
TRAILER = 2
# ADAPT: names for the message types.
NAMES: dict[int, str] = {
    1: "HELLO", 2: "CHALLENGE", 3: "AUTH_RESPONSE", 4: "GET_PARAM", 5: "PARAM_VALUE", 6: "ERROR", 7: "BYE",
}
AUTH_XOR = 0x5C  # single observed pair: response = challenge XOR 0x5C (assumption)
_last_challenge: dict = {}
MAX_SHOWN_PAYLOAD = 64


def payload_length(header: dict) -> int:
    """ADAPT: how many payload bytes follow the header."""
    return header["length"]


def check(frame: bytes, header: dict) -> str | None:
    """ADAPT: return what is wrong with a whole frame (header, payload, trailer), or None."""
    import binascii

    if binascii.crc_hqx(frame[:-2], 0xFFFF) != int.from_bytes(frame[-2:], "big"):
        return "bad CRC-16/CCITT-FALSE"
    if header["flags"] & ~0x01:
        return f"unexpected flags {header['flags']:#x}"
    payload = frame[8:-2]
    t = header["type"]
    if t not in NAMES:
        return f"unknown type {t}"
    if t == 2 and len(payload) != 8 or t == 3 and len(payload) != 8:
        return "challenge/response must be 8 bytes"
    if t == 4 and len(payload) != 2 or t == 5 and len(payload) != 6 or t == 6 and len(payload) != 1 or t == 7 and payload:
        return "bad payload size"
    if t == 3 and bytes(b ^ AUTH_XOR for b in payload) != _last_challenge.get("c"):
        return "auth response does not match challenge XOR key"
    if t == 2:
        _last_challenge["c"] = payload
    return None


def describe(t: int, payload: bytes) -> str:
    if t == 1:
        return "client_id=" + payload.decode("utf-8", "replace")
    if t in (2, 3):
        return payload.hex()
    if t == 4:
        return f"param_id={int.from_bytes(payload, 'big')}"
    if t == 5:
        return f"param_id={int.from_bytes(payload[:2], 'big')} value={int.from_bytes(payload[2:], 'big', signed=True)}"
    if t == 6:
        return f"error_code={payload[0]}"
    return ""


def read_packets(path: Path):
    """Yield (link type, packet) from a pcap or pcapng file."""
    data = path.read_bytes()
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        yield from read_pcapng(data)
        return
    orders = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<"}
    orders[b"\xa1\xb2\x3c\x4d"] = ">"
    if magic not in orders:
        raise ValueError(f"{path.name} is not a pcap or pcapng file")
    order = orders[magic]
    link = struct.unpack_from(f"{order}I", data, 20)[0]
    offset = 24
    while offset + 16 <= len(data):
        size = struct.unpack_from(f"{order}I", data, offset + 8)[0]
        yield link, data[offset + 16 : offset + 16 + size]
        offset += 16 + size


def read_pcapng(data: bytes):
    order, links, offset = "<", [], 0
    while offset + 12 <= len(data):
        kind = struct.unpack_from(f"{order}I", data, offset)[0]
        if kind == 0x0A0D0D0A:
            order = "<" if data[offset + 8 : offset + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            links = []
        length = struct.unpack_from(f"{order}I", data, offset + 4)[0]
        if length < 12:
            break
        if kind == 1:
            links.append(struct.unpack_from(f"{order}H", data, offset + 8)[0])
        elif kind == 6:
            interface, _, _, captured = struct.unpack_from(f"{order}IIII", data, offset + 8)
            yield links[interface], data[offset + 28 : offset + 28 + captured]
        elif kind == 3:
            yield links[0], data[offset + 12 : offset + length - 4]
        offset += length


def ip_payload(link: int, packet: bytes) -> bytes | None:
    """Strip the link layer: Ethernet (with VLAN tags), Linux cooked, loopback or raw IP."""
    if link == 1:
        kind, offset = struct.unpack_from(">H", packet, 12)[0], 14
        while kind == 0x8100:
            kind, offset = struct.unpack_from(">H", packet, offset + 2)[0], offset + 4
        return packet[offset:] if kind in (0x0800, 0x86DD) else None
    if link == 113:
        return packet[16:]
    if link == 276:
        return packet[20:]
    if link == 0:
        return packet[4:]
    if link in (101, 12, 228, 229):
        return packet
    raise ValueError(f"link type {link} is not handled: add it to ip_payload()")


def transport(ip: bytes):
    """Return (protocol, source, target, sequence, payload) for a TCP or UDP packet."""
    if ip[0] >> 4 == 4:
        start, protocol = (ip[0] & 15) * 4, ip[9]
        total = struct.unpack_from(">H", ip, 2)[0]
        source, target = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
        ip = ip[:total]
    elif ip[0] >> 4 == 6:
        start, protocol = 40, ip[6]
        source = socket.inet_ntop(socket.AF_INET6, ip[8:24])
        target = socket.inet_ntop(socket.AF_INET6, ip[24:40])
    else:
        return None
    segment = ip[start:]
    if protocol == 6:
        source_port, target_port, sequence = struct.unpack_from(">HHI", segment)
        flags = segment[13]
        body = segment[(segment[12] >> 4) * 4 :]
        return "tcp", (source, source_port), (target, target_port), sequence, body, flags
    if protocol == 17:
        source_port, target_port = struct.unpack_from(">HH", segment)
        return "udp", (source, source_port), (target, target_port), None, segment[8:], 0
    return None


def streams(path: Path) -> dict:
    """Map (protocol, source, target) to the bytes sent that way, in order."""
    tcp: dict = {}
    datagrams: dict = {}
    for link, packet in read_packets(path):
        ip = ip_payload(link, packet)
        parsed = transport(ip) if ip else None
        if not parsed:
            continue
        protocol, source, target, sequence, body, flags = parsed
        if PORT is not None and PORT not in (source[1], target[1]):
            continue
        key = (protocol, source, target)
        if protocol == "udp":
            datagrams.setdefault(key, []).append(body)
            continue
        state = tcp.setdefault(key, {"next": None, "segments": {}})
        if flags & 0x02:
            state["next"] = (sequence + 1) % 2**32
        elif body:
            state["segments"].setdefault(sequence, body)
    result = {}
    for key, state in tcp.items():
        result[key] = [reassemble(state)]
    result.update(datagrams)
    return result


def reassemble(state: dict) -> bytes:
    """Join segments in sequence order, keeping the first copy of any retransmitted bytes."""
    segments = state["segments"]
    if not segments:
        return b""
    position = state["next"] if state["next"] is not None else min(segments)
    stream = bytearray()
    while True:
        exact = segments.get(position)
        if exact is None:
            overlaps = [s for s in segments if s < position < s + len(segments[s])]
            if not overlaps:
                break
            start = overlaps[0]
            exact = segments[start][position - start :]
        stream += exact
        position = (position + len(exact)) % 2**32
    return bytes(stream)


def frames(data: bytes):
    """Yield (offset, header, frame) for each frame, or raise ValueError where one is wrong."""
    layout = BYTE_ORDER + "".join(code for _, code in HEADER)
    size = struct.calcsize(layout)
    offset = 0
    while offset < len(data):
        if offset + size > len(data):
            raise ValueError(
                f"offset {offset}: {len(data) - offset} bytes left, header needs {size}"
            )
        values = struct.unpack_from(layout, data, offset)
        header = dict(zip((name for name, _ in HEADER), values, strict=True))
        if MAGIC is not None and values[0] != MAGIC:
            raise ValueError(f"offset {offset}: expected magic {MAGIC:#x}, found {values[0]:#x}")
        end = offset + size + payload_length(header) + TRAILER
        if end > len(data):
            raise ValueError(f"offset {offset}: frame runs {end - len(data)} bytes past the stream")
        frame = data[offset:end]
        problem = check(frame, header)
        if problem:
            raise ValueError(f"offset {offset}: {problem}")
        yield offset, header, frame
        offset = end


def decode(path: Path) -> tuple[list[dict], int]:
    report, problems = [], 0
    _last_challenge.clear()
    for (protocol, source, target), chunks in sorted(streams(path).items(), key=lambda kv: kv[0][1][1] != PORT):
        entry = {"stream": f"{protocol} {source[0]}:{source[1]} -> {target[0]}:{target[1]}"}
        entry["messages"] = []
        for chunk in chunks:
            try:
                for offset, header, frame in frames(chunk):
                    name = NAMES.get(header.get("type"), header.get("type"))
                    payload = frame[struct.calcsize(BYTE_ORDER + "".join(c for _, c in HEADER)) :]
                    payload = payload[: len(payload) - TRAILER] if TRAILER else payload
                    entry["messages"].append(
                        {
                            "offset": offset,
                            "name": name,
                            "header": header,
                            "payload": payload[:MAX_SHOWN_PAYLOAD].hex(" "),
                            "decoded": describe(header["type"], payload),
                        }
                    )
            except ValueError as error:
                entry["problem"] = str(error)
                problems += 1
        report.append(entry)
    return report, problems


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python protocol_decoder.py capture.pcap [--json]", file=sys.stderr)
        return 64
    report, problems = decode(Path(sys.argv[1]))
    if "--json" in sys.argv:
        print(json.dumps({"streams": report, "problems": problems}, indent=2))
    else:
        for entry in report:
            print(entry["stream"])
            for message in entry["messages"]:
                print(f"  {message['offset']:6} {message['name']} seq={message['header']['seq']} flags={message['header']['flags']}: {message['decoded']}")
            if "problem" in entry:
                print(f"  PROBLEM {entry['problem']}")
        print(f"{problems} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
