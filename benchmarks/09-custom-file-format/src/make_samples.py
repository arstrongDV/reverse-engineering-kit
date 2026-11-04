#!/usr/bin/env python3
"""Write the three sample files of benchmark 9. The layout here is the answer."""

import struct
import sys
import zlib
from pathlib import Path

TEXT, NUMBER, BLOB = 1, 2, 3


def record(kind: int, value) -> bytes:
    if kind == TEXT:
        payload = value.encode("utf-8")
    elif kind == NUMBER:
        payload = struct.pack("<i", value)
    else:
        payload = value
    return struct.pack("<BH", kind, len(payload)) + payload


def build(version: int, records: list) -> bytes:
    body = b"RKF1" + struct.pack("<HH", version, len(records))
    body += b"".join(record(kind, value) for kind, value in records)
    return body + struct.pack("<I", zlib.crc32(body))


SAMPLES = {
    "alpha.rkf": build(2, [(TEXT, "alpha"), (NUMBER, 1024)]),
    "bravo.rkf": build(
        2, [(TEXT, "bravo"), (BLOB, bytes(range(32))), (NUMBER, -7), (TEXT, "конец")]
    ),
    "charlie.rkf": build(3, [(BLOB, b""), (TEXT, ""), (NUMBER, 2147483647)]),
}


def main() -> int:
    folder = Path(sys.argv[1])
    folder.mkdir(parents=True, exist_ok=True)
    for name, data in SAMPLES.items():
        (folder / name).write_bytes(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
