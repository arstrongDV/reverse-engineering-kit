import json
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


def run_script(name, *args, cwd=None):
    command = [sys.executable, str(SCRIPTS_DIR / name), *args]
    return subprocess.run(
        command, capture_output=True, text=True, encoding="utf-8", timeout=30, cwd=cwd
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


@pytest.fixture
def work(tmp_path):
    folder = tmp_path / "re-work" / "demo"
    (folder / "original").mkdir(parents=True)
    (folder / "original" / "target.bin").write_bytes(b"target bytes")
    (folder / "notes.md").write_text(NOTES, encoding="utf-8")
    return folder
