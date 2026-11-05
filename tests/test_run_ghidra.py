"""run_ghidra.py against a fake Ghidra install: arguments, reuse, outputs and refusals."""

import json
import os
import platform

import pytest
import samples
from conftest import path_with, python_tool, run_script

from doctor import GHIDRA_PLATFORMS

FAKE_HEADLESS = r"""
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(Path(__file__).parent.parent / "calls.jsonl", "a") as log:
    log.write(json.dumps(args) + "\n")
if os.environ.get("FAKE_GHIDRA_FAIL"):
    print("ERROR something went wrong in analysis")
    sys.exit(0)
at = args.index("-postScript")
script_path = Path(args[args.index("-scriptPath") + 1])
assert (script_path / args[at + 1]).is_file(), "script not copied"
output, top, extra = args[at + 2], int(args[at + 3]), args[at + 4:]
names = [a for a in extra if not a.startswith("bytes:")]
requests = [a.split(":") for a in extra if a.startswith("bytes:")]
known = {"main": "00101000", "check_serial": "00101100", "../../evil": "00101200"}
chosen = names or list(known)[:top]
export = {
    "program": {"name": "target", "format": "ELF", "language": "x86:LE:64:default",
                "compiler": "gcc", "image_base": "00100000", "sha256": "ab"},
    "functions": {"total": 3, "items": [
        {"name": n, "address": a, "size": 40, "callers": 1, "strings": 2, "imports": ["puts"],
         "callees": []} for n, a in known.items()]},
    "imports": {"total": 2, "items": [
        {"name": "puts", "library": "libc.so.6", "callers": ["main"]},
        {"name": "unused", "library": "libc.so.6", "callers": []}]},
    "strings": {"total": 2, "items": [
        {"address": "00102000", "value": "Wrong serial.", "functions": ["main"]},
        {"address": "00102010", "value": "plain", "functions": ["main"]}]},
    "decompiled": [{"name": n, "address": known[n], "code": f"int {n}(void) {{ return 1; }}"}
                   for n in chosen if n in known],
    "bytes": [{"name": r[1], "address": "00103000", "hex": "5a c3 17 9e"[: 3 * int(r[2]) - 1]}
              for r in requests if r[1] == "KEY"],
    "missing": [n for n in names if n not in known] + [r[1] for r in requests if r[1] != "KEY"],
}
Path(output).write_text(json.dumps(export))
print("INFO REPORT: Post-analysis succeeded")
"""


@pytest.fixture
def ghidra(tmp_path):
    root = tmp_path / "ghidra"
    (root / "Ghidra").mkdir(parents=True)
    properties = "application.version=12.2\napplication.java.min=21\n"
    (root / "Ghidra" / "application.properties").write_text(properties, "utf-8")
    name = GHIDRA_PLATFORMS[(platform.system(), platform.machine())]
    decompiler = root / "Ghidra/Features/Decompiler/os" / name
    decompiler.mkdir(parents=True)
    executable = decompiler / ("decompile.exe" if os.name == "nt" else "decompile")
    executable.write_bytes(b"\0")
    executable.chmod(0o755)
    python_tool(root / "support", "analyzeHeadless", FAKE_HEADLESS)
    bin_folder = tmp_path / "bin"
    python_tool(bin_folder, "java", "import sys\nsys.stderr.write('openjdk version \"25\"\\n')\n")
    return path_with(bin_folder) | {"GHIDRA_INSTALL_DIR": str(root)}, root


@pytest.fixture
def binary(work):
    (work / "original" / "target.bin").unlink()
    (work / "original" / "target").write_bytes(samples.elf())
    return work


def ghidra_run(work, environment, *args):
    result = run_script("run_ghidra.py", "--work", str(work), "--json", *args, env=environment)
    return result, (json.loads(result.stdout) if result.stdout.strip() else None)


def calls(root):
    lines = (root / "calls.jsonl").read_text("utf-8").splitlines()
    return [json.loads(line) for line in lines]


def test_exports_and_writes_each_function_to_a_file(binary, ghidra):
    environment, _ = ghidra
    result, summary = ghidra_run(binary, environment)
    assert result.returncode == 0, result.stdout + result.stderr
    folder = binary / "decompiled" / "ghidra" / "target"
    assert (folder / "export.json").is_file()
    assert (folder / "functions" / "main@00101000.c").read_text("utf-8").startswith("int main")
    assert summary["counts"] == {"functions": 3, "imports": 2, "strings": 2}
    assert [item["name"] for item in summary["imports_in_use"]] == ["puts"]
    assert summary["notable_strings"][0]["value"] == "Wrong serial."


def test_a_second_run_reuses_the_analysis(binary, ghidra):
    environment, root = ghidra
    ghidra_run(binary, environment)
    _, summary = ghidra_run(binary, environment, "--function", "check_serial")
    first, second = calls(root)
    assert "-import" in first
    assert "-process" in second and "-noanalysis" in second
    assert summary["reused_analysis"] is True


def test_fresh_and_a_changed_target_analyze_again(binary, ghidra):
    environment, root = ghidra
    ghidra_run(binary, environment)
    ghidra_run(binary, environment, "--fresh")
    (binary / "original" / "target").write_bytes(samples.elf(imports=("strcmp",)))
    ghidra_run(binary, environment)
    assert ["-import" in call for call in calls(root)] == [True, True, True]


def test_functions_and_bytes_are_requested_by_name(binary, ghidra):
    environment, root = ghidra
    args = ["--function", "check_serial", "--function", "nope", "--bytes", "KEY:4", "--bytes", "X"]
    _, summary = ghidra_run(binary, environment, *args)
    call = calls(root)[0]
    assert call[call.index("-postScript") + 4 :] == [
        "check_serial",
        "nope",
        "bytes:KEY:4",
        "bytes:X:64",
    ]
    assert [item["name"] for item in summary["decompiled"]] == ["check_serial"]
    assert summary["bytes"][0]["hex"] == "5a c3 17 9e"
    assert summary["missing"] == ["nope", "X"]


@pytest.mark.parametrize("request_text", ["KEY:many", "KEY:", ":4", "a b"])
def test_a_malformed_bytes_request_is_a_usage_error(binary, ghidra, request_text):
    environment, _ = ghidra
    result, _ = ghidra_run(binary, environment, "--bytes", request_text)
    assert result.returncode == 64


def test_a_function_name_from_the_target_cannot_leave_the_folder(binary, ghidra):
    environment, _ = ghidra
    ghidra_run(binary, environment)
    written = list((binary / "decompiled").rglob("*evil*"))
    assert written
    assert all(
        (binary / "decompiled" / "ghidra" / "target" / "functions") in path.parents
        for path in written
    )


def test_ghidra_writing_no_export_is_an_error_with_the_log(binary, ghidra):
    environment, _ = ghidra
    result, _ = ghidra_run(binary, environment | {"FAKE_GHIDRA_FAIL": "1"})
    assert result.returncode == 1
    assert "something went wrong" in json.loads(result.stdout)["message"]
    assert (binary / "decompiled" / "ghidra" / "target" / "ghidra.log").is_file()


def test_without_ghidra_it_exits_2_with_a_hint(binary, tmp_path):
    result, _ = ghidra_run(binary, path_with(tmp_path / "empty"))
    assert result.returncode == 2
    assert "ghidra_12.2" in json.loads(result.stdout)["message"]


def test_a_non_native_target_is_unsupported(work, ghidra):
    environment, _ = ghidra
    path = work / "original" / "app.apk"
    path.write_bytes(samples.zipped("AndroidManifest.xml"))
    result, _ = ghidra_run(work, environment, str(path))
    assert result.returncode == 3


def test_two_binaries_need_a_choice(binary, ghidra):
    environment, _ = ghidra
    (binary / "original" / "second").write_bytes(samples.pe())
    result, _ = ghidra_run(binary, environment)
    assert result.returncode == 64
    assert "second" in json.loads(result.stdout)["message"]


def test_a_name_with_shell_syntax_reaches_ghidra_as_a_plain_copy(work, ghidra):
    environment, root = ghidra
    (work / "original" / "target.bin").unlink()
    # Legal in a Windows file name, yet each of & space ^ means something to cmd.exe.
    (work / "original" / "a&b ^c.exe").write_bytes(samples.pe())
    result, _ = ghidra_run(work, environment)
    assert result.returncode == 0, result.stdout
    imported = calls(root)[0][calls(root)[0].index("-import") + 1]
    assert imported.endswith("target.exe")


def test_the_original_is_never_modified(binary, ghidra):
    environment, _ = ghidra
    before = (binary / "original" / "target").read_bytes()
    ghidra_run(binary, environment)
    assert (binary / "original" / "target").read_bytes() == before
