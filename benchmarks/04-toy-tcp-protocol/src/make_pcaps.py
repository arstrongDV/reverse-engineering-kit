#!/usr/bin/env python3
"""Write the two capture files of benchmark 4. Runs anywhere: the packets are built by hand."""

import socket
import struct
import sys
from pathlib import Path

from protocol import (
    BYE,
    CHALLENGE,
    ERROR,
    GET,
    HELLO,
    RESPONSE,
    VALUE,
    answer,
    encode,
)

CLIENT_MAC = bytes.fromhex("02005e000002")
SERVER_MAC = bytes.fromhex("02005e000001")
SERVER = ("10.20.0.1", 7500)
FIN, SYN, PSH, ACK = 0x01, 0x02, 0x08, 0x10


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def packet(source, target, sequence, acknowledged, flags, payload=b""):
    source_ip, target_ip = socket.inet_aton(source[0]), socket.inet_aton(target[0])
    tcp = struct.pack(
        ">HHIIBBHHH", source[1], target[1], sequence, acknowledged, 5 << 4, flags, 8192, 0, 0
    )
    pseudo = source_ip + target_ip + struct.pack(">BBH", 0, 6, len(tcp) + len(payload))
    sum_ = checksum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack(">H", sum_) + tcp[18:]
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0x4000, 64, 6, 0, source_ip, target_ip)
    ip = ip[:10] + struct.pack(">H", checksum(ip)) + ip[12:]
    macs = (SERVER_MAC + CLIENT_MAC) if target == SERVER else (CLIENT_MAC + SERVER_MAC)
    return macs + b"\x08\x00" + ip + tcp + payload


class Session:
    def __init__(self, client, start_time):
        self.client = client
        self.time = start_time
        self.frames = []
        self.client_sequence = 1000
        self.server_sequence = 5000
        self.add(client, SERVER, self.client_sequence, 0, SYN)
        self.client_sequence += 1
        self.add(SERVER, client, self.server_sequence, self.client_sequence, SYN | ACK)
        self.server_sequence += 1
        self.add(client, SERVER, self.client_sequence, self.server_sequence, ACK)

    def add(self, source, target, sequence, acknowledged, flags, payload=b""):
        self.time += 0.012
        self.frames.append(
            (self.time, packet(source, target, sequence, acknowledged, flags, payload))
        )

    def client_sends(self, *chunks):
        for chunk in chunks:
            flags = PSH | ACK
            self.add(self.client, SERVER, self.client_sequence, self.server_sequence, flags, chunk)
            self.client_sequence += len(chunk)

    def server_sends(self, *chunks):
        for chunk in chunks:
            flags = PSH | ACK
            self.add(SERVER, self.client, self.server_sequence, self.client_sequence, flags, chunk)
            self.server_sequence += len(chunk)

    def close(self):
        self.add(self.client, SERVER, self.client_sequence, self.server_sequence, FIN | ACK)
        self.client_sequence += 1
        self.add(SERVER, self.client, self.server_sequence, self.client_sequence, FIN | ACK)
        self.server_sequence += 1
        self.add(self.client, SERVER, self.client_sequence, self.server_sequence, ACK)


def analysis_session() -> Session:
    """One message per segment, so the framing is easy to see."""
    nonce = bytes.fromhex("1f2e3d4c5b6a7988")
    session = Session(("10.20.0.2", 51000), 1_790_000_000.0)
    session.client_sends(encode(HELLO, 1, b"rekit-client/1.0"))
    session.server_sends(encode(CHALLENGE, 1, nonce))
    session.client_sends(encode(RESPONSE, 2, answer(nonce)))
    session.client_sends(encode(GET, 3, struct.pack(">H", 1)))
    session.server_sends(encode(VALUE, 3, struct.pack(">Hi", 1, 2150)))
    session.client_sends(encode(GET, 4, struct.pack(">H", 2)))
    session.server_sends(encode(VALUE, 4, struct.pack(">Hi", 2, -40)))
    session.client_sends(encode(BYE, 5))
    session.close()
    return session


def holdout_session() -> Session:
    """Never used during analysis. Messages share and split segments, and an error appears."""
    nonce = bytes.fromhex("a0b1c2d3e4f50617")
    session = Session(("10.20.0.3", 51744), 1_790_000_600.0)
    hello = encode(HELLO, 1, b"rekit-client/1.1")
    session.client_sends(hello[:5], hello[5:])
    session.server_sends(encode(CHALLENGE, 1, nonce))
    response = encode(RESPONSE, 2, answer(nonce))
    first_get = encode(GET, 3, struct.pack(">H", 7))
    session.client_sends(response + first_get[:3], first_get[3:])
    session.server_sends(encode(VALUE, 3, struct.pack(">Hi", 7, 123456)))
    second_get = encode(GET, 4, struct.pack(">H", 99), flags=1)
    session.client_sends(second_get[:9], second_get[9:])
    session.server_sends(encode(ERROR, 4, b"\x02"))
    session.client_sends(encode(BYE, 5))
    session.close()
    return session


def write_pcap(path: Path, session: Session) -> None:
    with path.open("wb") as file:
        file.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for moment, frame in session.frames:
            seconds, fraction = int(moment), int((moment % 1) * 1_000_000)
            file.write(struct.pack("<IIII", seconds, fraction, len(frame), len(frame)))
            file.write(frame)


def main() -> int:
    folder = Path(sys.argv[1])
    folder.mkdir(parents=True, exist_ok=True)
    write_pcap(folder / "session-analysis.pcap", analysis_session())
    write_pcap(folder / "session-holdout.pcap", holdout_session())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
