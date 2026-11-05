"""templates/protocol_decoder.py, adapted to benchmark 4 the way an agent would adapt it."""

import importlib.util
import struct
import subprocess
import sys

import pytest
from conftest import REPO_ROOT, SKILL_DIR

TEMPLATE = SKILL_DIR / "templates" / "protocol_decoder.py"
MAKE_PCAPS = REPO_ROOT / "benchmarks" / "04-toy-tcp-protocol" / "src" / "make_pcaps.py"


def crc16(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021 if crc & 0x8000 else crc << 1) & 0xFFFF
    return crc


@pytest.fixture
def decoder():
    spec = importlib.util.spec_from_file_location("protocol_decoder", TEMPLATE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.PORT = 7500
    module.MAGIC = 0xB17E
    module.TRAILER = 2
    module.HEADER = (
        ("magic", "H"),
        ("type", "B"),
        ("flags", "B"),
        ("sequence", "H"),
        ("length", "H"),
    )
    module.NAMES = {
        1: "HELLO",
        2: "CHALLENGE",
        3: "RESPONSE",
        4: "GET",
        5: "VALUE",
        6: "ERROR",
        7: "BYE",
    }

    def check(frame, header):
        return None if struct.unpack(">H", frame[-2:])[0] == crc16(frame[:-2]) else "CRC mismatch"

    module.check = check
    return module


@pytest.fixture
def captures(tmp_path):
    subprocess.run([sys.executable, str(MAKE_PCAPS), str(tmp_path)], check=True)
    return tmp_path


def names(report):
    return [[message["name"] for message in entry["messages"]] for entry in report]


def test_decodes_the_capture_used_for_analysis(decoder, captures):
    report, problems = decoder.decode(captures / "session-analysis.pcap")
    assert problems == 0
    assert names(report) == [
        ["HELLO", "RESPONSE", "GET", "GET", "BYE"],
        ["CHALLENGE", "VALUE", "VALUE"],
    ]


def test_decodes_the_capture_kept_back_with_split_and_shared_segments(decoder, captures):
    report, problems = decoder.decode(captures / "session-holdout.pcap")
    assert problems == 0
    assert names(report) == [
        ["HELLO", "RESPONSE", "GET", "GET", "BYE"],
        ["CHALLENGE", "VALUE", "ERROR"],
    ]


def test_a_damaged_frame_is_reported_with_its_offset(decoder, captures):
    path = captures / "session-holdout.pcap"
    data = bytearray(path.read_bytes())
    data[data.index(b"rekit-client") + 2] ^= 0xFF
    path.write_bytes(bytes(data))
    report, problems = decoder.decode(path)
    assert problems == 1
    assert "CRC mismatch" in next(entry["problem"] for entry in report if "problem" in entry)


def test_reads_pcapng_too(decoder, captures, tmp_path):
    """Rewrite the pcap as pcapng: a section header, one interface, then enhanced packets."""
    data = (captures / "session-analysis.pcap").read_bytes()
    blocks = [struct.pack("<IIIHHq", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1) + struct.pack("<I", 28)]
    blocks.append(struct.pack("<IIHHI", 1, 20, 1, 0, 65535) + struct.pack("<I", 20))
    offset = 24
    while offset < len(data):
        size = struct.unpack_from("<I", data, offset + 8)[0]
        packet = data[offset + 16 : offset + 16 + size]
        padded = packet + b"\0" * (-len(packet) % 4)
        length = 32 + len(padded)
        blocks.append(
            struct.pack("<IIIIIII", 6, length, 0, 0, 0, size, size)
            + padded
            + struct.pack("<I", length)
        )
        offset += 16 + size
    path = tmp_path / "capture.pcapng"
    path.write_bytes(b"".join(blocks))
    report, problems = decoder.decode(path)
    assert problems == 0
    assert names(report)[0] == ["HELLO", "RESPONSE", "GET", "GET", "BYE"]


def test_the_command_exits_1_when_a_frame_is_wrong(captures):
    """Unadapted, the template reads every frame wrongly, and says so through its exit code."""
    done = subprocess.run(
        [sys.executable, str(TEMPLATE), str(captures / "session-analysis.pcap")],
        capture_output=True,
        text=True,
    )
    assert done.returncode == 1
    assert "PROBLEM" in done.stdout


def test_rejects_a_file_that_is_not_a_capture(decoder, tmp_path):
    path = tmp_path / "x.pcap"
    path.write_bytes(b"not a capture at all")
    with pytest.raises(ValueError):
        decoder.decode(path)
