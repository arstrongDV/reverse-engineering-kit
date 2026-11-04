"""triage.py: the Phase 2 checkpoint is that it names the type of every test file."""

import json
import os
import random
import re
import subprocess
import sys

import pytest
import samples
from conftest import SKILL_DIR, run_script

import triage
from triage import ANTI_ANALYSIS, FAMILY_OF, ROUTES, triage_target

CHECKPOINT = [
    ("elf-x86-64", "target", samples.elf(), "elf"),
    ("elf-arm64", "target", samples.elf(machine=samples.EM_AARCH64), "elf"),
    ("elf-32-big", "target", samples.elf_header(bits=32, big=True, machine=8), "elf"),
    ("elf-core", "core", samples.elf_header(kind=4), "elf"),
    ("pe-exe", "app.exe", samples.pe(), "pe"),
    ("pe-dll", "lib.dll", samples.pe(dll=True), "pe"),
    ("pe-without-suffix", "target", samples.pe(), "pe"),
    ("dotnet", "app.exe", samples.pe(clr=True), "dotnet"),
    ("macho", "target", samples.macho(), "macho"),
    ("macho-fat", "target", samples.fat((samples.CPU_ARM64, samples.macho())), "macho"),
    ("java-class", "A.class", samples.java_class(), "java-class"),
    ("dex", "classes.dex", samples.dex(), "dex"),
    ("wasm", "a.wasm", samples.wasm(), "wasm"),
    ("pcap", "a.pcap", samples.pcap(), "pcap"),
    ("pcap-big-nano", "a.pcap", samples.pcap(big=True, nanoseconds=True), "pcap"),
    ("pcapng", "a.pcapng", samples.pcapng(), "pcapng"),
    ("asar", "app.asar", samples.asar({"package.json": b"{}", "a/b.js": b"1"}), "asar"),
    ("asar-renamed", "data", samples.asar({"package.json": b"{}"}), "asar"),
    ("apk", "a.apk", samples.zipped("AndroidManifest.xml", "classes.dex", "lib/x86/a.so"), "apk"),
    ("apk-renamed", "a.zip", samples.zipped("AndroidManifest.xml", "classes.dex"), "apk"),
    ("aab", "a.aab", samples.zipped("BundleConfig.pb", "base/dex/classes.dex"), "aab"),
    ("xapk", "a.xapk", samples.zipped("manifest.json", "base.apk", "split.apk"), "xapk"),
    ("aar", "a.aar", samples.zipped("AndroidManifest.xml", "classes.jar"), "aar"),
    ("jar", "a.jar", samples.zipped("META-INF/MANIFEST.MF", "A.class"), "jar"),
    ("ipa", "a.ipa", samples.zipped("Payload/A.app/Info.plist", "Payload/A.app/A"), "ipa"),
    ("zip", "a.zip", samples.zipped("readme.txt"), "zip"),
    ("gzip", "a.gz", samples.gzipped(), "gzip"),
    ("bzip2", "a.bz2", b"BZh91AY&SY" + bytes(range(64)), "bzip2"),
    ("xz", "a.xz", b"\xfd7zXZ\0" + bytes(range(64)), "xz"),
    ("zstd", "a.zst", b"\x28\xb5\x2f\xfd" + bytes(range(64)), "zstd"),
    ("7z", "a.7z", b"7z\xbc\xaf\x27\x1c" + bytes(range(64)), "7z"),
    ("rar", "a.rar", b"Rar!\x1a\x07\x01\0" + bytes(range(64)), "rar"),
    ("tar", "a.tar", samples.tar(), "tar"),
    ("pdf", "a.pdf", b"%PDF-1.7\n", "pdf"),
    ("png", "a.png", b"\x89PNG\r\n\x1a\n" + bytes(range(64)), "png"),
    ("jpeg", "a.jpg", b"\xff\xd8\xff\xe0" + bytes(range(64)), "jpeg"),
    ("gif", "a.gif", b"GIF89a" + bytes(range(64)), "gif"),
    ("sqlite", "a.db", b"SQLite format 3\0" + bytes(range(84)), "sqlite"),
    ("pyc", "a.pyc", b"\xcb\x0d\r\n" + bytes(range(64)), "pyc"),
    ("javascript", "a.js", b"console.log(1)\n", "javascript"),
    ("js-no-suffix", "bundle", b"const a = 1;\nfunction b() { return a; }\n", "javascript"),
    ("webpack", "main.js", samples.MINIFIED_WEBPACK.encode(), "javascript"),
    ("source-map", "a.js.map", samples.SOURCE_MAP, "source-map"),
    ("har", "a.har", samples.HAR, "har"),
    ("json", "a.json", b'{"a": 1}', "json"),
    ("text", "notes.txt", b"Plain words about a function and nothing more.\n", "text"),
    ("html", "a.html", b"<html><script>var a = 1; function b() {}</script></html>", "text"),
    ("script", "run.sh", b"#!/bin/sh\necho hi\n", "text"),
    ("unknown", "data.bin", bytes(range(1, 8)) * 100, "unknown"),
]


def save(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return path


@pytest.mark.parametrize(
    "name,data,expected", [c[1:] for c in CHECKPOINT], ids=[c[0] for c in CHECKPOINT]
)
def test_identifies_the_type_of_every_test_file(tmp_path, name, data, expected):
    assert triage_target(save(tmp_path, name, data))["type"] == expected


def test_the_checkpoint_covers_every_type_triage_can_report():
    folders = {"directory", "electron-app"}
    assert {item[3] for item in CHECKPOINT} | folders == set(FAMILY_OF)


def test_identification_does_not_depend_on_the_file_name(tmp_path):
    elf_named_as_text = save(tmp_path, "readme.txt", samples.elf())
    assert triage_target(elf_named_as_text)["type"] == "elf"
    text_named_as_exe = save(tmp_path, "app.exe", b"just some words\n")
    assert triage_target(text_named_as_exe)["type"] == "text"


def test_reads_architecture_details(tmp_path):
    arm = triage_target(save(tmp_path, "a", samples.elf(machine=samples.EM_AARCH64)))
    assert arm["details"]["arch"] == "arm64"
    assert arm["details"]["bits"] == 64
    big = triage_target(save(tmp_path, "b", samples.elf_header(bits=32, big=True, machine=8)))
    assert big["details"] | {"kind": ""} == {
        "arch": "mips",
        "bits": 32,
        "endian": "big",
        "kind": "",
    }
    dll = triage_target(save(tmp_path, "c", samples.pe(dll=True)))
    assert dll["details"]["kind"] == "dll"
    both = samples.fat((samples.CPU_X86_64, samples.macho()), (samples.CPU_ARM64, samples.macho()))
    universal = triage_target(save(tmp_path, "d", both))
    assert universal["details"]["architectures"] == ["x86-64", "arm64"]
    assert "slice" in universal["warnings"][0]


def test_a_java_class_is_not_mistaken_for_a_fat_binary(tmp_path):
    report = triage_target(save(tmp_path, "a", samples.java_class(major=45)))
    assert report["type"] == "java-class"
    assert report["details"]["java"] == 1


def test_hashes_match_a_second_implementation(tmp_path):
    import hashlib

    path = save(tmp_path, "a.bin", bytes(range(1, 200)))
    report = triage_target(path)
    assert report["hashes"]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert report["hashes"]["md5"] == hashlib.md5(path.read_bytes()).hexdigest()
    assert report["hashes"]["sha1"] == hashlib.sha1(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("data,entropy", [(b"\x01" * 512, 0.0), (bytes(range(256)) * 4, 8.0)])
def test_entropy_of_known_inputs(tmp_path, data, entropy):
    assert triage_target(save(tmp_path, "a.bin", data))["entropy"] == entropy


def test_reads_sections_imports_exports_and_libraries(tmp_path):
    report = triage_target(
        save(tmp_path, "a", samples.elf(imports=("puts", "getenv"), exports=("check_serial",)))
    )
    assert report["imports"] == {"total": 2, "names": ["puts", "getenv"]}
    assert report["exports"] == {"total": 1, "names": ["check_serial"]}
    assert report["libraries"] == ["libc.so.6"]
    assert report["stripped"] is True
    text = next(section for section in report["sections"] if section["name"] == ".text")
    assert text == {"name": ".text", "size": len(samples.CODE), "entropy": 8.0}


def test_reads_a_pe_import_and_export_table(tmp_path):
    imports = (("KERNEL32.dll", ("Sleep",)), ("WS2_32.dll", ("connect",)))
    report = triage_target(
        save(tmp_path, "a.dll", samples.pe(dll=True, imports=imports, exports=("Start", "Stop")))
    )
    assert sorted(report["imports"]["names"]) == ["Sleep", "connect"]
    assert sorted(report["exports"]["names"]) == ["Start", "Stop"]
    assert report["libraries"] == ["KERNEL32.dll", "WS2_32.dll"]
    assert "stripped" not in report


def test_reads_a_macho_symbol_table(tmp_path):
    report = triage_target(save(tmp_path, "a", samples.macho(imports=("_puts",))))
    assert report["imports"]["names"] == ["_puts"]
    assert report["libraries"] == ["/usr/lib/libSystem.B.dylib"]


def test_long_lists_are_capped_but_counted(tmp_path):
    names = tuple(f"fn_{index}" for index in range(triage.MAX_NAMES + 50))
    report = triage_target(save(tmp_path, "a", samples.elf(imports=names)))
    assert report["imports"]["total"] == len(names)
    assert len(report["imports"]["names"]) == triage.MAX_NAMES


def test_strings_are_found_in_both_encodings_and_sorted_by_interest(tmp_path):
    data = bytes(range(1, 8)).join(
        [
            b"https://api.example.test/v1/login",
            "Enter your password".encode("utf-16-le"),
            b"plain words here",
            b"abc",
        ]
    )
    strings = triage_target(save(tmp_path, "a.bin", data))["strings"]
    assert strings["total"] == 3
    assert strings["notable"] == ["https://api.example.test/v1/login", "Enter your password"]
    assert strings["sample"] == ["plain words here"]


def test_noise_is_not_reported_as_a_windows_path(tmp_path):
    data = bytes(range(1, 8)).join([b"xxVuLv:\\#xx", rb"C:\Windows\System32"])
    strings = triage_target(save(tmp_path, "a.bin", data))["strings"]
    assert strings["notable"] == [r"C:\Windows\System32"]


def test_string_output_is_bounded(tmp_path):
    data = b"\x01".join(b"password %06d" % index for index in range(2000))
    strings = triage_target(save(tmp_path, "a.bin", data))["strings"]
    assert strings["total"] == 2000
    assert len(strings["notable"]) == triage.MAX_STRINGS


@pytest.mark.parametrize(
    "name,sections,packer",
    [
        ("sections", (("UPX0", samples.CODE), ("UPX1", samples.CODE)), "UPX"),
        ("vmprotect", ((".text", samples.CODE), (".vmp0", samples.CODE)), "VMProtect"),
        ("marker", ((".text", b"\x90" * 64 + b"UPX!" + b"\x90" * 64),), "UPX"),
    ],
)
def test_names_a_packer_with_its_evidence(tmp_path, name, sections, packer):
    report = triage_target(save(tmp_path, name, samples.elf(sections=sections)))
    assert report["packer"]["name"] == packer
    assert report["packer"]["evidence"]
    assert ANTI_ANALYSIS in report["read_next"]


def test_names_pyinstaller_from_its_cookie(tmp_path):
    data = samples.elf() + triage.PYINSTALLER_MARKER + b"\0" * 64
    assert triage_target(save(tmp_path, "a", data))["packer"]["name"] == "PyInstaller"


def random_bytes(size):
    return random.Random(7).randbytes(size)


def test_reports_an_unknown_packer_from_entropy(tmp_path):
    sections = ((".text", random_bytes(20_000)),)
    packer = triage_target(save(tmp_path, "a", samples.elf(sections=sections)))["packer"]
    assert packer["name"] == "unknown"
    assert any("entropy" in item for item in packer["evidence"])


def test_a_plain_binary_has_no_packer_guess(tmp_path):
    report = triage_target(save(tmp_path, "a", samples.elf()))
    assert report["packer"] is None
    assert report["read_next"] == [ROUTES["native"]]


def test_an_embedded_resource_is_not_called_packed(tmp_path):
    sections = ((".text", b"\x90" * 8192), (".rsrc", random_bytes(20_000)))
    imports = (("KERNEL32.dll", tuple(f"Fn{index}" for index in range(20))),)
    assert (
        triage_target(save(tmp_path, "a", samples.pe(sections=sections, imports=imports)))["packer"]
        is None
    )


@pytest.mark.parametrize(
    "sample",
    [
        samples.elf(imports=("ptrace",)),
        samples.macho(imports=("_ptrace",)),
        samples.pe(imports=(("ntdll.dll", ("NtQueryInformationProcess",)),)),
        samples.elf(sections=((".text", b"\x90" * 32 + b"TracerPid:" + b"\x90" * 32),)),
    ],
    ids=["elf-import", "macho-import", "pe-import", "elf-string"],
)
def test_anti_debug_signals(tmp_path, sample):
    report = triage_target(save(tmp_path, "a", sample))
    assert [signal["name"] for signal in report["signals"]] == ["anti-debug"]
    assert ANTI_ANALYSIS in report["read_next"]


def test_isdebuggerpresent_alone_is_not_a_signal(tmp_path):
    sample = samples.pe(imports=(("KERNEL32.dll", ("IsDebuggerPresent",)),))
    assert triage_target(save(tmp_path, "a.exe", sample))["signals"] == []


@pytest.mark.parametrize(
    "bundle", [samples.MINIFIED_WEBPACK, samples.MINIFIED_WEBPACK_5_112], ids=["var", "const"]
)
def test_reports_what_a_js_file_is_built_with(tmp_path, bundle):
    report = triage_target(save(tmp_path, "main.js", bundle.encode()))
    assert report["details"]["bundler"] == "webpack"
    assert report["details"]["minified"] is True
    assert "strings" not in report


def test_finds_a_source_map_comment(tmp_path):
    data = b"console.log(1)\n//# sourceMappingURL=main.js.map\n"
    report = triage_target(save(tmp_path, "main.js", data))
    assert report["details"]["source_map"] == "main.js.map"


def test_flags_obfuscated_js(tmp_path):
    report = triage_target(save(tmp_path, "a.js", samples.OBFUSCATED_JS.encode()))
    assert len(report["signals"]) == 2
    assert {signal["name"] for signal in report["signals"]} == {"obfuscated-js"}
    assert report["read_next"] == [ROUTES["js"], ANTI_ANALYSIS]


def test_ordinary_js_is_not_called_obfuscated(tmp_path):
    report = triage_target(save(tmp_path, "a.js", b"const total = add(1, 2);\n"))
    assert report["signals"] == []


def test_counts_asar_contents(tmp_path):
    files = {"package.json": b"{}", "a/b/c.js": b"1", "a/addon.node": b"\0"}
    report = triage_target(save(tmp_path, "app.asar", samples.asar(files)))
    assert report["details"] == {"files": 3, "native_modules": 1}


def test_a_deeply_nested_asar_header_cannot_crash_triage(tmp_path):
    header = b'{"files":' * 3
    data = b"\x04\0\0\0\0\0\0\0\0\0\0\0" + (9**8).to_bytes(4, "little") + header
    assert triage_target(save(tmp_path, "a.asar", data))["type"] == "asar"


def test_lists_apk_contents_without_unpacking(tmp_path):
    names = ("AndroidManifest.xml", "classes.dex", "classes2.dex", "lib/arm64-v8a/libx.so")
    report = triage_target(save(tmp_path, "a.apk", samples.zipped(*names)))
    assert report["details"] == {"entries": 4, "dex_files": 2, "abis": ["arm64-v8a"]}
    assert sorted(path.name for path in tmp_path.iterdir()) == ["a.apk"]


def test_a_damaged_zip_is_still_named(tmp_path):
    report = triage_target(save(tmp_path, "a.zip", b"PK\x03\x04" + bytes(range(64))))
    assert report["type"] == "zip"
    assert report["warnings"]


def test_high_entropy_unknown_data_is_flagged(tmp_path):
    report = triage_target(save(tmp_path, "blob", b"\x00" + random_bytes(65536)))
    assert [signal["name"] for signal in report["signals"]] == ["high-entropy"]


def test_finds_an_electron_app_in_a_folder(tmp_path):
    app = tmp_path / "MyApp"
    (app / "resources").mkdir(parents=True)
    (app / "resources" / "app.asar").write_bytes(samples.asar({"package.json": b"{}"}))
    (app / "myapp.exe").write_bytes(samples.pe())
    report = triage_target(app)
    assert report["type"] == "electron-app"
    assert report["details"]["electron_app"] == "resources/app.asar"
    assert report["read_next"] == [ROUTES["js"]]


def test_finds_an_unpacked_electron_app(tmp_path):
    app = tmp_path / "MyApp"
    (app / "Resources" / "app").mkdir(parents=True)
    (app / "Resources" / "app" / "package.json").write_text("{}", "utf-8")
    assert triage_target(app)["type"] == "electron-app"


def test_summarizes_a_plain_folder(tmp_path):
    folder = tmp_path / "bundle"
    folder.mkdir()
    (folder / "a.txt").write_text("hello", "utf-8")
    (folder / "b.txt").write_text("hi", "utf-8")
    report = triage_target(folder)
    assert report["type"] == "directory"
    assert report["size"] == 7
    assert report["details"] == {"files": 2, "common_suffixes": [".txt"]}


class TestSafety:
    def mutate(self, data, seed):
        generator = random.Random(seed)
        changed = bytearray(data[: generator.randrange(1, len(data))])
        for _ in range(16):
            changed[generator.randrange(len(changed))] = generator.randrange(256)
        return bytes(changed)

    @pytest.mark.parametrize("seed", range(6))
    @pytest.mark.parametrize(
        "sample",
        [
            samples.elf(),
            samples.pe(exports=("Start",)),
            samples.macho(),
            samples.fat((samples.CPU_ARM64, samples.macho())),
            samples.asar({"package.json": b"{}"}),
            samples.zipped("AndroidManifest.xml"),
        ],
        ids=["elf", "pe", "macho", "fat", "asar", "zip"],
    )
    def test_damaged_files_never_raise(self, tmp_path, sample, seed):
        report = triage_target(save(tmp_path, "a", self.mutate(sample, seed)))
        json.dumps(report)
        assert report["type"] in FAMILY_OF

    def test_a_claimed_architecture_count_is_capped(self, tmp_path):
        """A hostile header can claim billions. The count here fails fast if the cap is lost."""
        data = b"\xca\xfe\xba\xbf" + (100_000).to_bytes(4, "big") + b"\0" * 8192
        report = triage_target(save(tmp_path, "a", data))
        assert report["type"] == "macho"
        assert len(report["details"]["architectures"]) == triage.MAX_FAT_ENTRIES

    def test_control_characters_in_a_name_are_removed(self):
        assert triage.clean("evil\x1b[2Jname\n") == "evil?[2Jname?"
        assert triage.clean(b"\xff\xfe") == "\ufffd\ufffd"

    def test_a_crash_in_lief_leaves_a_warning(self, tmp_path, monkeypatch):
        done = subprocess.CompletedProcess([], -11, "", "")
        monkeypatch.setattr(triage.subprocess, "run", lambda *a, **k: done)
        report = triage_target(save(tmp_path, "a", samples.elf()))
        assert report["type"] == "elf"
        assert "exit code -11" in report["warnings"][0]
        assert "sections" not in report

    def test_a_hang_in_lief_leaves_a_warning(self, tmp_path, monkeypatch):
        def hang(*args, **kwargs):
            raise subprocess.TimeoutExpired("lief", 1)

        monkeypatch.setattr(triage.subprocess, "run", hang)
        report = triage_target(save(tmp_path, "a", samples.elf()))
        assert "gave up" in report["warnings"][0]

    def test_the_parser_runs_in_a_child_process(self, tmp_path, monkeypatch):
        seen = []
        real = subprocess.run
        monkeypatch.setattr(
            triage.subprocess,
            "run",
            lambda command, **k: seen.append(command) or real(command, **k),
        )
        triage_target(save(tmp_path, "a", samples.elf()))
        assert seen[0][0] == sys.executable
        assert seen[0][2].startswith("--parse-binary=")


def test_the_scan_limit_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(triage, "SCAN_LIMIT", triage.CHUNK_SIZE)
    report = triage_target(save(tmp_path, "a.bin", b"\x01\x02" * triage.CHUNK_SIZE))
    assert "first 1 MiB" in report["warnings"][0]


class TestCommandLine:
    def test_saves_triage_json_for_everything_in_original(self, work):
        (work / "original" / "second.exe").write_bytes(samples.pe())
        result = run_script("triage.py", "--work", str(work), "--json")
        assert result.returncode == 0
        saved = json.loads((work / "triage.json").read_text("utf-8"))
        assert saved == json.loads(result.stdout)
        assert [item["type"] for item in saved["targets"]] == ["pe", "text"]

    def test_runs_from_the_work_directory(self, work):
        assert run_script("triage.py", cwd=work).returncode == 0
        assert (work / "triage.json").exists()

    def test_a_path_is_printed_and_nothing_is_saved(self, work, tmp_path):
        path = save(tmp_path, "lib.so", samples.elf())
        result = run_script("triage.py", str(path), "--json", cwd=work)
        assert json.loads(result.stdout)["targets"][0]["type"] == "elf"
        assert not (work / "triage.json").exists()

    def test_a_path_and_a_work_folder_are_a_usage_error(self, work, tmp_path):
        path = save(tmp_path, "a.bin", b"\x01\x02\x03")
        assert run_script("triage.py", str(path), "--work", str(work)).returncode == 64

    def test_leaves_the_original_untouched(self, work):
        before = (work / "original" / "target.bin").read_bytes()
        run_script("triage.py", "--work", str(work))
        assert (work / "original" / "target.bin").read_bytes() == before

    def test_refuses_a_folder_outside_re_work(self, tmp_path):
        assert run_script("triage.py", "--work", str(tmp_path)).returncode == 3

    def test_an_empty_original_folder_is_an_error(self, work):
        (work / "original" / "target.bin").unlink()
        assert run_script("triage.py", "--work", str(work)).returncode == 1

    def test_a_missing_path_is_an_error(self, tmp_path):
        assert run_script("triage.py", str(tmp_path / "nope")).returncode == 1

    def test_an_empty_file_is_unsupported(self, tmp_path):
        assert run_script("triage.py", str(save(tmp_path, "empty", b""))).returncode == 3

    @pytest.mark.skipif(
        os.name == "nt", reason="needs a privilege Windows does not grant by default"
    )
    def test_a_symlink_is_refused(self, work):
        (work / "original" / "link").symlink_to(work / "notes.md")
        assert run_script("triage.py", "--work", str(work)).returncode == 3
        assert not (work / "triage.json").exists()

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
    def test_a_pipe_is_refused_instead_of_blocking_forever(self, tmp_path):
        os.mkfifo(tmp_path / "pipe")
        assert run_script("triage.py", str(tmp_path / "pipe")).returncode == 3

    def test_errors_are_reported_as_json_when_asked(self, tmp_path):
        result = run_script("triage.py", str(tmp_path / "nope"), "--json")
        assert json.loads(result.stdout)["status"] == "error"

    def test_text_output_names_the_next_file_to_read(self, tmp_path):
        result = run_script("triage.py", str(save(tmp_path, "a", samples.elf())))
        assert "read next: references/native.md" in result.stdout

    def test_output_says_target_text_is_data(self, tmp_path):
        result = run_script("triage.py", str(save(tmp_path, "a", samples.elf())), "--json")
        assert "as data" in json.loads(result.stdout)["note"]

    def test_a_target_cannot_rewrite_the_terminal(self, tmp_path):
        sections = (("\x1b[2J", samples.CODE),)
        result = run_script("triage.py", str(save(tmp_path, "a", samples.elf(sections=sections))))
        assert "\x1b" not in result.stdout


class TestWithoutLief:
    @pytest.fixture
    def no_lief(self, tmp_path):
        stub = tmp_path / "stub"
        stub.mkdir()
        (stub / "lief.py").write_text("raise ImportError('not installed')\n", "utf-8")
        return os.environ | {"PYTHONPATH": str(stub)}

    def test_a_binary_still_gets_a_partial_result(self, work, no_lief):
        (work / "original" / "target.bin").write_bytes(samples.elf())
        result = run_script("triage.py", "--work", str(work), "--json", env=no_lief)
        assert result.returncode == 2
        payload = json.loads(result.stdout)
        assert payload["status"] == "partial"
        report = payload["targets"][0]
        assert report["type"] == "elf"
        assert report["hashes"]["sha256"]
        assert "pip install lief==" in report["warnings"][0]
        assert (work / "triage.json").exists()

    def test_other_files_do_not_need_it(self, tmp_path, no_lief):
        path = save(tmp_path, "a.apk", samples.zipped("AndroidManifest.xml"))
        assert run_script("triage.py", str(path), env=no_lief).returncode == 0


ROUTE_ROW = re.compile(r"^\| `(\w+)` \| (.+?) \| (.+?) \|$", re.MULTILINE)


def routing_table():
    text = (SKILL_DIR / "SKILL.md").read_text("utf-8")
    return {family: (kinds, target) for family, kinds, target in ROUTE_ROW.findall(text)}


def test_skill_md_routes_every_family_triage_can_report():
    assert routing_table().keys() == set(triage.FAMILIES)


@pytest.mark.parametrize("family", triage.FAMILIES)
def test_skill_md_lists_every_type_under_its_family(family):
    listed = re.findall(r"`([\w-]+)`", routing_table()[family][0])
    assert sorted(listed) == sorted(triage.FAMILIES[family])


@pytest.mark.parametrize("family,reference", ROUTES.items())
def test_skill_md_and_triage_send_a_family_to_the_same_file(family, reference):
    assert reference in routing_table()[family][1]
    assert (SKILL_DIR / reference).is_file()


def test_skill_md_routes_signals_to_the_anti_analysis_file():
    assert (SKILL_DIR / ANTI_ANALYSIS).is_file()
    assert ANTI_ANALYSIS in (SKILL_DIR / "SKILL.md").read_text("utf-8")
