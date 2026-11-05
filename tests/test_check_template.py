"""templates/check.py: the differential test agents copy into tests/ and ledger.py verify runs."""

import json

from conftest import SKILL_DIR, python_tool, record, run_script

TEMPLATE = (SKILL_DIR / "templates" / "check.py").read_text("utf-8")
# Accepts exactly the two inputs the model below accepts, as a real crackme would.
FAKE_TARGET = """
import sys
sys.exit(0 if sys.argv[1:] in (["first input"], ["second input"]) else 1)
"""
MODEL = """def model(arguments: list[str]) -> object:
    return 0 if arguments in (["first input"], ["second input"]) else 1
"""


def install_check(work, model=None):
    target = python_tool(work / "original", "target", FAKE_TARGET)
    text = TEMPLATE.replace('TARGET = "original/target"', f"TARGET = {str(target)!r}")
    if model:
        start = text.index("def model(")
        end = text.index("def main(")
        text = text[:start] + model + "\n\n" + text[end:]
    (work / "tests").mkdir()
    (work / "tests" / "check_serial.py").write_text(text, "utf-8")
    return "tests/check_serial.py"


def verify(work, by):
    arguments = ["--json", "verify", "F-001", "--by", by, "--kind", "function"]
    return run_script("ledger.py", "--work", str(work), *arguments)


def test_a_filled_in_template_confirms_a_recovered_function(work):
    record(work, "--confidence", "inferred")
    result = verify(work, install_check(work, MODEL))
    assert result.returncode == 0, result.stdout + result.stderr
    cases = json.loads(result.stdout)["finding"]["verification"]["cases"]
    assert len(cases) == 3
    assert all(case.startswith("PASS ") for case in cases)


def test_the_unfilled_template_fails_instead_of_passing(work):
    record(work, "--confidence", "inferred")
    result = verify(work, install_check(work))
    assert result.returncode == 1
    assert "NotImplementedError" in json.loads(result.stdout)["message"]


def test_a_wrong_model_is_caught(work):
    record(work, "--confidence", "inferred")
    wrong = MODEL.replace('["second input"]', '["third input"]')
    result = verify(work, install_check(work, wrong))
    assert result.returncode == 1
    assert "FAIL ['second input']" in json.loads(result.stdout)["message"]
