#!/usr/bin/env python3
"""The reference decoder for benchmark 4: reassemble both TCP directions, then print messages."""

import json
import struct
import sys
from pathlib import Path

from protocol import HEADER, HEADER_SIZE, MAGIC, NAMES, crc16

TCP = 6
ETHERNET_SIZE = 14


def read_packets(path: Path):
    data = path.read_bytes()
    offset = 24
    while offset < len(data):
        _, _, size, _ = struct.unpack_from("<IIII", data, offset)
        yield data[offset + 16 : offset + 16 + size]
        offset += 16 + size


def read_streams(path: Path) -> dict:
    segments = {}
    for frame in read_packets(path):
        ip = frame[ETHERNET_SIZE:]
        if ip[9] != TCP:
            continue
        tcp = ip[(ip[0] & 15) * 4 :]
        source, target, sequence = struct.unpack_from(">HHI", tcp)
        payload = tcp[(tcp[12] >> 4) * 4 :]
        if payload:
            segments.setdefault((source, target), {})[sequence] = payload
    return {
        direction: b"".join(chunks[key] for key in sorted(chunks))
        for direction, chunks in segments.items()
    }


def decode(stream: bytes) -> list[dict]:
    messages = []
    offset = 0
    while offset < len(stream):
        magic, kind, flags, sequence, length = struct.unpack_from(HEADER, stream, offset)
        if magic != MAGIC:
            raise ValueError(f"bad magic at offset {offset}")
        end = offset + HEADER_SIZE + length
        crc = struct.unpack_from(">H", stream, end)[0]
        if crc != crc16(stream[offset:end]):
            raise ValueError(f"bad checksum at offset {offset}")
        payload = stream[offset + HEADER_SIZE : end]
        messages.append(
            {"type": NAMES[kind], "flags": flags, "sequence": sequence, "payload": payload.hex()}
        )
        offset = end + 2
    return messages


def main() -> int:
    streams = read_streams(Path(sys.argv[1]))
    print(json.dumps([decode(stream) for stream in streams.values()], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
