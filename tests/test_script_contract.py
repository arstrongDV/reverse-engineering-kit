"""The script contract: --help, --json, exit codes, no network, no downloads."""

import json
import re
import subprocess
import sys

import pytest
from conftest import SCRIPTS_DIR

# Runs inside Ghidra, so it is not a command line tool.
NON_CLI = {"_common.py", "ghidra_export.py"}
CLIS = sorted(p for p in SCRIPTS_DIR.glob("*.py") if p.name not in NON_CLI)

# Remove a script from here in the phase that implements it.
STUBS = CLIS


def run(script, *args):
    command = [sys.executable, str(script), *args]
    return subprocess.run(command, capture_output=True, text=True, timeout=30)


def ids(paths):
    return [path.name for path in paths]


def test_every_planned_cli_exists():
    assert {path.name for path in CLIS} == {
        "decompile_apk.py",
        "doctor.py",
        "find_endpoints.py",
        "ledger.py",
        "make_report.py",
        "recover_js.py",
        "run_ghidra.py",
        "triage.py",
    }


def test_scripts_are_python_so_they_run_on_windows():
    assert not list(SCRIPTS_DIR.rglob("*.sh"))


@pytest.mark.parametrize("script", CLIS, ids=ids(CLIS))
def test_help_documents_json_flag(script):
    result = run(script, "--help")
    assert result.returncode == 0
    assert "--json" in result.stdout


@pytest.mark.parametrize("script", CLIS, ids=ids(CLIS))
def test_bad_flag_is_not_reported_as_missing_tool(script):
    assert run(script, "--no-such-flag").returncode == 64


@pytest.mark.parametrize("script", STUBS, ids=ids(STUBS))
def test_stubs_fail_loudly_instead_of_reporting_success(script):
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
def test_scripts_do_not_import_network_modules(script):
    assert not NETWORK_IMPORT.search(script.read_text(encoding="utf-8"))


@pytest.mark.parametrize("script", sorted(SCRIPTS_DIR.rglob("*.py")), ids=lambda p: p.name)
def test_scripts_do_not_download(script):
    assert not DOWNLOAD_COMMAND.search(script.read_text(encoding="utf-8"))
