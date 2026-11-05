"""scripts/frida/*.js: valid JavaScript, written for Frida 17, and observing only."""

import re
import shutil
import subprocess

import pytest
from conftest import SCRIPTS_DIR

TEMPLATES = sorted((SCRIPTS_DIR / "frida").glob("*.js"))
# Frida 17 removed these; a template that uses them fails the moment it loads.
REMOVED_APIS = re.compile(
    r"Module\.(?:findExportByName|getExportByName)\(\s*null|Memory\.read(?:Utf8String|ByteArray|U32)\("
)


def test_the_four_templates_exist():
    assert [path.name for path in TEMPLATES] == [
        "compare.js",
        "crypto.js",
        "network.js",
        "pinning.js",
    ]


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda path: path.name)
def test_is_valid_javascript(path):
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    assert subprocess.run([node, "--check", str(path)], capture_output=True).returncode == 0


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda path: path.name)
def test_uses_only_frida_17_apis(path):
    assert not REMOVED_APIS.search(path.read_text("utf-8"))


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda path: path.name)
def test_says_it_runs_only_in_a_confirmed_sandbox(path):
    header = path.read_text("utf-8")[:600]
    assert "VM" in header


def test_pinning_only_watches_and_lets_failures_fail():
    text = (SCRIPTS_DIR / "frida" / "pinning.js").read_text("utf-8")
    assert "throw error;" in text
    assert "overload.call(this, ...args)" in text
    assert not re.search(r"implementation\s*=\s*function[^{]*\{\s*(?:return\s*;|\})", text)
