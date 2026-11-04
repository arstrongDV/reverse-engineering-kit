"""The benchmark targets: definitions and answers always, built files wherever they exist."""

import json
import re
import struct
import subprocess
import sys
import zlib

import pytest
from conftest import REPO_ROOT

from triage import FAMILY_OF, triage_target

BENCHMARKS = REPO_ROOT / "benchmarks"
ENTRIES = sorted(BENCHMARKS.glob("*/expected.json"))


def entry_of(name):
    return json.loads((BENCHMARKS / name / "expected.json").read_text("utf-8"))


def source_of(path):
    return (BENCHMARKS / path).read_text("utf-8")


def hex_table(text, name):
    """Read a C byte table such as: static const unsigned char KEY[4] = {0x5a, ...};"""
    body = re.search(rf"{name}\[[^\]]*\] = \{{(.*?)\}};", text, re.DOTALL)[1]
    return [int(value, 16) for value in re.findall(r"0x[0-9a-f]{2}", body)]


def run_python(script, *args):
    command = [sys.executable, str(BENCHMARKS / script), *map(str, args)]
    return subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=30)


@pytest.mark.parametrize("path", ENTRIES, ids=lambda path: path.parent.name)
def test_every_benchmark_is_fully_defined(path):
    entry = json.loads(path.read_text("utf-8"))
    assert entry["status"] == "built"
    assert entry["expected"]
    assert entry["artifacts"]
    assert entry["triage"]["type"] in FAMILY_OF
    assert entry["triage"]["family"] == FAMILY_OF[entry["triage"]["type"]]


@pytest.mark.parametrize("path", ENTRIES, ids=lambda path: path.parent.name)
def test_every_benchmark_has_source(path):
    files = [item for item in (path.parent / "src").rglob("*") if item.is_file()]
    assert [item for item in files if item.name != ".gitkeep"]


def test_no_built_target_is_tracked_by_git():
    tracked = subprocess.run(
        ["git", "ls-files", "benchmarks"], capture_output=True, text=True, cwd=REPO_ROOT
    ).stdout.splitlines()
    assert not [path for path in tracked if "/build/" in path]


def test_the_crackme_answer_matches_its_source():
    source = source_of("01-crackme-xor/src/crackme.c")
    key = hex_table(source, "KEY")
    table = hex_table(source, "EXPECTED")
    decoded = []
    for index, value in enumerate(table):
        unrotated = (value >> 3) | ((value << 5) & 0xFF)
        decoded.append(unrotated ^ key[index % 4])
    serial = bytes(decoded).decode("ascii")
    assert serial == entry_of("01-crackme-xor")["expected"]["serial"]
    assert serial == entry_of("02-crackme-upx")["expected"]["serial"]
    assert " ".join(f"{byte:02x}" for byte in key) == entry_of("01-crackme-xor")["expected"]["key"]


def test_the_anti_debug_answer_matches_its_source():
    source = source_of("08-anti-debug/src/antidebug.c")
    secret = bytes(byte ^ 0x2A for byte in hex_table(source, "MESSAGE")).decode("ascii")
    assert entry_of("08-anti-debug")["expected"]["message"] == f"The launch code is {secret}"
    assert entry_of("08-anti-debug")["expected"]["message_key"] == "0x2a"


def test_the_android_base_url_matches_its_source():
    source = source_of("05-android-hidden-api/src/java/com/fieldnotes/demo/Endpoints.java")
    body = re.search(r"BASE = \{(.*?)\};", source, re.DOTALL)[1]
    url = bytes(int(value) ^ 0x37 for value in re.findall(r"\d+", body)).decode("ascii")
    assert url == entry_of("05-android-hidden-api")["expected"]["base_url"]
    assert url not in source
    assert "lanretni/" in source
    assert "POST /internal/diag" in entry_of("05-android-hidden-api")["expected"]["endpoints"]


def test_the_telemetry_answer_matches_its_source():
    source = source_of("03-telemetry-pe/src/agent.c")
    expected = entry_of("03-telemetry-pe")["expected"]
    assert f"#define AGENT_PORT {expected['network']['port']}" in source
    assert 'REGISTRY_KEY "Software\\\\ReKitBench\\\\Telemetry"' in source
    assert all(f'"{value}"' in source for value in expected["registry"]["values"])


def test_the_webpack_answer_matches_its_source():
    expected = entry_of("06-webpack-bundle")["expected"]
    assert expected["base_url"] in source_of("06-webpack-bundle/src/app/api/client.js")
    for module in expected["modules"]:
        assert (BENCHMARKS / "06-webpack-bundle/src/app" / f"{module}.js").is_file()


def test_the_electron_answer_matches_its_source():
    expected = entry_of("07-electron-asar")["expected"]
    main = source_of("07-electron-asar/src/app/main.js")
    assert sorted(re.findall(r'ipcMain\.handle\("([^"]+)"', main)) == sorted(
        expected["ipc"]["invoke"]
    )
    assert re.findall(r'ipcMain\.on\("([^"]+)"', main) == expected["ipc"]["send"]
    for name in expected["files"]:
        assert (BENCHMARKS / "07-electron-asar/src/app" / name).is_file()


class TestProtocol:
    @pytest.fixture
    def captures(self, tmp_path):
        assert run_python("04-toy-tcp-protocol/src/make_pcaps.py", tmp_path).returncode == 0
        return tmp_path

    def decode(self, path):
        result = run_python("04-toy-tcp-protocol/src/decoder.py", path)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    def test_the_decoder_reads_the_capture_used_for_analysis(self, captures):
        client, server = self.decode(captures / "session-analysis.pcap")
        assert [m["type"] for m in client] == ["HELLO", "RESPONSE", "GET", "GET", "BYE"]
        assert [m["type"] for m in server] == ["CHALLENGE", "VALUE", "VALUE"]

    def test_the_decoder_reads_the_capture_kept_back(self, captures):
        client, server = self.decode(captures / "session-holdout.pcap")
        assert [m["type"] for m in client] == ["HELLO", "RESPONSE", "GET", "GET", "BYE"]
        assert [m["type"] for m in server] == ["CHALLENGE", "VALUE", "ERROR"]

    def test_the_kept_back_capture_is_harder_than_the_other(self, captures):
        """A message boundary must not line up with a TCP segment here."""
        data = (captures / "session-holdout.pcap").read_bytes()
        assert data.count(b"\xb1\x7e") < 10
        assert (captures / "session-analysis.pcap").read_bytes() != data

    def test_triage_names_both_captures(self, captures):
        for path in captures.glob("*.pcap"):
            report = triage_target(path)
            assert report["type"] == "pcap"
            assert report["details"] == {"link": "ethernet"}


class TestFileFormat:
    @pytest.fixture
    def rkf(self, tmp_path):
        assert run_python("09-custom-file-format/src/make_samples.py", tmp_path).returncode == 0
        return sorted(tmp_path.glob("*.rkf"))

    def test_there_are_three_samples(self, rkf):
        assert [path.name for path in rkf] == ["alpha.rkf", "bravo.rkf", "charlie.rkf"]

    def test_the_samples_match_the_documented_layout(self, rkf):
        for path in rkf:
            data = path.read_bytes()
            assert data[:4] == b"RKF1"
            count = struct.unpack_from("<H", data, 6)[0]
            offset = 8
            for _ in range(count):
                kind, length = struct.unpack_from("<BH", data, offset)
                assert kind in (1, 2, 3)
                offset += 3 + length
            assert offset == len(data) - 4
            assert struct.unpack_from("<I", data, offset)[0] == zlib.crc32(data[:offset])

    def test_triage_does_not_recognize_the_private_format(self, rkf):
        assert {triage_target(path)["type"] for path in rkf} == {"unknown"}


BUILT = [
    (path.parent.name, artifact)
    for path in ENTRIES
    for artifact in json.loads(path.read_text("utf-8"))["artifacts"]
]


@pytest.mark.parametrize("name,artifact", BUILT, ids=[f"{n}/{a}" for n, a in BUILT])
def test_triage_identifies_each_built_target(name, artifact):
    path = BENCHMARKS / name / artifact
    if not path.exists():
        pytest.skip("not built here: run tools/vm/vm.sh build-benchmarks")
    want = entry_of(name)["triage"]
    report = triage_target(path)
    assert report["type"] == want["type"]
    assert report["family"] == want["family"]
    if "packer" in want:
        assert report["packer"]["name"] == want["packer"]
    if "bundler" in want:
        assert report["details"]["bundler"] == want["bundler"]
    if "signal" in want:
        assert want["signal"] in {signal["name"] for signal in report["signals"]}
