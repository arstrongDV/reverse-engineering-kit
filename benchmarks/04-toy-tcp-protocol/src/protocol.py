"""Benchmark 4: the message format of a toy TCP protocol. This file is the answer."""

import struct

MAGIC = 0xB17E
HEADER = ">HBBHH"
HEADER_SIZE = struct.calcsize(HEADER)
RESPONSE_KEY = 0x5C

HELLO = 1
CHALLENGE = 2
RESPONSE = 3
GET = 4
VALUE = 5
ERROR = 6
BYE = 7
NAMES = {
    HELLO: "HELLO",
    CHALLENGE: "CHALLENGE",
    RESPONSE: "RESPONSE",
    GET: "GET",
    VALUE: "VALUE",
    ERROR: "ERROR",
    BYE: "BYE",
}


def crc16(data: bytes) -> int:
    """CRC-16/CCITT-FALSE."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = (crc << 1) ^ 0x1021 if crc & 0x8000 else crc << 1
            crc &= 0xFFFF
    return crc


def encode(kind: int, sequence: int, payload: bytes = b"", flags: int = 0) -> bytes:
    body = struct.pack(HEADER, MAGIC, kind, flags, sequence, len(payload)) + payload
    return body + struct.pack(">H", crc16(body))


def answer(nonce: bytes) -> bytes:
    return bytes(byte ^ RESPONSE_KEY for byte in nonce)
