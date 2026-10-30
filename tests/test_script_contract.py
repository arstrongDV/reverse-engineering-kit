"""The script contract: --help, --json, exit codes, no network, no downloads."""

import json
import os
import re
import subprocess
import sys

import pytest
from conftest import SCRIPTS_DIR

# Runs inside Ghidra, so it is not a command line tool.
NON_CLI = {"_common.py", "ghidra_export.py"}
PYTHON_CLIS = sorted(p for p in SCRIPTS_DIR.glob("*.py") if p.name not in NON_CLI)
SHELL_CLIS = sorted(SCRIPTS_DIR.glob("*.sh"))

# Remove a script from here in the phase that implements it.
STUBS = PYTHON_CLIS + SHELL_CLIS

posix_only = pytest.mark.skipif(os.name == "nt", reason="shell scripts need a POSIX shell")


def run(script, *args):
    command = [sys.executable, str(script)] if script.suffix == ".py" else ["bash", str(script)]
    return subprocess.run([*command, *args], capture_output=True, text=True, timeout=30)


def ids(paths):
    return [path.name for path in paths]


def test_every_planned_cli_exists():
    assert {path.name for path in PYTHON_CLIS + SHELL_CLIS} == {
        "decompile_apk.sh",
        "doctor.py",
        "find_endpoints.py",
        "ledger.py",
        "make_report.py",
        "recover_js.py",
        "run_ghidra.sh",
        "triage.py",
    }


@pytest.mark.parametrize("script", PYTHON_CLIS, ids=ids(PYTHON_CLIS))
def test_python_help_documents_json_flag(script):
    result = run(script, "--help")
    assert result.returncode == 0
    assert "--json" in result.stdout


@posix_only
@pytest.mark.parametrize("script", SHELL_CLIS, ids=ids(SHELL_CLIS))
def test_shell_help_documents_json_flag(script):
    result = run(script, "--help")
    assert result.returncode == 0
    assert "--json" in result.stdout


@pytest.mark.parametrize("script", PYTHON_CLIS, ids=ids(PYTHON_CLIS))
def test_bad_flag_is_not_reported_as_missing_tool(script):
    assert run(script, "--no-such-flag").returncode == 64


@pytest.mark.parametrize("script", STUBS, ids=ids(STUBS))
def test_stubs_fail_loudly_instead_of_reporting_success(script):
    if script.suffix == ".sh" and os.name == "nt":
        pytest.skip("shell scripts need a POSIX shell")
    result = run(script, "--json")
    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["status"] == "not_implemented"
    assert report["script"] == script.name
    assert report["phase"] in range(1, 6)


NETWORK_IMPORT = re.compile(
    r"^\s*(?:import|from)\s+(?:urllib|http|socket|ftplib|requests|httpx|aiohttp)\b", re.MULTILINE
)
DOWNLOAD_COMMAND = re.compile(r"\b(?:curl|wget|npx)\b")


@pytest.mark.parametrize("script", sorted(SCRIPTS_DIR.rglob("*.py")), ids=lambda p: p.name)
def test_python_scripts_do_not_import_network_modules(script):
    assert not NETWORK_IMPORT.search(script.read_text(encoding="utf-8"))


@pytest.mark.parametrize("script", SHELL_CLIS, ids=ids(SHELL_CLIS))
def test_shell_scripts_do_not_download(script):
    assert not DOWNLOAD_COMMAND.search(script.read_text(encoding="utf-8"))
