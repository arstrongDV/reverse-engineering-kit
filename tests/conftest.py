import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = REPO_ROOT / "skills" / "reverse-engineering-kit"
SCRIPTS_DIR = SKILL_DIR / "scripts"

NOTES = """# Notes: demo

## Authorization

Own crackme, built for this test. The result is for the benchmark suite.

## Summary

The serial check is a single XOR.

## Gaps

- Run the binary under a debugger to see what sub_4011 returns.

## Session log

Started.
"""


def run_script(name, *args, cwd=None, env=None):
    command = [sys.executable, str(SCRIPTS_DIR / name), *args]
    return subprocess.run(
        command, capture_output=True, text=True, encoding="utf-8", timeout=30, cwd=cwd, env=env
    )


def record(work, *extra, check=True):
    """Add one finding and return its id, or the whole result when check is False."""
    fields = {"--claim": "A claim", "--location": "main.c:1", "--evidence": "Read the code"}
    pairs = dict(zip(extra[::2], extra[1::2], strict=True))
    arguments = [item for pair in (fields | pairs).items() for item in pair]
    result = run_script("ledger.py", "--work", str(work), "--json", "add", *arguments)
    if not check:
        return result
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout)["finding"]["id"]


PASSING_CHECK = "for case in ('a', 'b', 'c'):\n    print(f'PASS {case}')\n"


def write_check(work, body=PASSING_CHECK, name="check.py"):
    """Write a check into the work directory's tests/ folder and return the name verify takes."""
    folder = work / "tests"
    folder.mkdir(exist_ok=True)
    (folder / name).write_text(body, encoding="utf-8")
    return f"tests/{name}"


def confirm(work, finding_id, *extra, kind="behavior", check=None):
    """Confirm a finding the only way the ledger allows: by running a check that passes."""
    by = check or write_check(work)
    arguments = ["verify", finding_id, "--by", by, "--kind", kind, *extra]
    result = run_script("ledger.py", "--work", str(work), *arguments)
    assert result.returncode == 0, result.stdout + result.stderr
    return by


@pytest.fixture
def work(tmp_path):
    folder = tmp_path / "re-work" / "demo"
    (folder / "original").mkdir(parents=True)
    (folder / "original" / "target.bin").write_bytes(b"target bytes")
    (folder / "notes.md").write_text(NOTES, encoding="utf-8")
    return folder


def python_tool(folder, name, code):
    """Install a fake tool that runs Python code. Windows gets a .bat, as jadx and apktool use."""
    folder.mkdir(parents=True, exist_ok=True)
    script = folder / f"{name}_fake.py"
    script.write_text(code, encoding="utf-8")
    if os.name == "nt":
        wrapper = folder / f"{name}.bat"
        wrapper.write_text(f'@"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
    else:
        wrapper = folder / name
        wrapper.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8"
        )
        wrapper.chmod(0o755)
    return wrapper


def path_with(folder):
    """The environment with only this folder on PATH, so no real tool can answer."""
    keep = {key: value for key, value in os.environ.items() if key != "GHIDRA_INSTALL_DIR"}
    return keep | {"PATH": str(folder)}
