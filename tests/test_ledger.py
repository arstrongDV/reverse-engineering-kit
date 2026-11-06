"""findings.jsonl: what ledger.py accepts, what it refuses, and the schema it must match."""

import hashlib
import json
import os
import time

import jsonschema
import pytest
from conftest import SKILL_DIR, confirm, record, run_script, write_check

from ledger import check


def read_ledger(work):
    path = work / "findings.jsonl"
    return [json.loads(line) for line in path.read_text("utf-8").splitlines()]


def ledger(work, *args):
    return run_script("ledger.py", "--work", str(work), *args)


def verify(work, *args):
    return ledger(work, "verify", *args)


def test_add_numbers_findings_in_order(work):
    assert record(work) == "F-001"
    assert record(work) == "F-002"
    assert [item["id"] for item in read_ledger(work)] == ["F-001", "F-002"]


def test_add_starts_at_unknown_unless_told_otherwise(work):
    record(work)
    assert read_ledger(work)[0]["confidence"] == "unknown"


def test_add_cannot_create_a_confirmed_finding(work):
    assert record(work, "--confidence", "confirmed", check=False).returncode == 64
    assert not (work / "findings.jsonl").exists()


def test_add_refuses_a_blank_claim(work):
    result = ledger(work, "add", "--claim", "  ", "--location", "a", "--evidence", "b")
    assert result.returncode == 1
    assert not (work / "findings.jsonl").exists()


def test_list_filters_by_confidence(work):
    record(work, "--confidence", "inferred")
    record(work, "--confidence", "observed")
    result = ledger(work, "--json", "list", "--confidence", "observed")
    assert [item["id"] for item in json.loads(result.stdout)["findings"]] == ["F-002"]


def test_update_moves_confidence_up(work):
    record(work, "--confidence", "inferred")
    assert ledger(work, "update", "F-001", "--confidence", "observed").returncode == 0
    assert read_ledger(work)[0]["confidence"] == "observed"


def test_update_refuses_to_lower_confidence(work):
    record(work, "--confidence", "observed")
    before = (work / "findings.jsonl").read_text("utf-8")
    assert ledger(work, "update", "F-001", "--confidence", "inferred").returncode == 1
    assert (work / "findings.jsonl").read_text("utf-8") == before


def test_update_cannot_reach_confirmed(work):
    record(work)
    assert ledger(work, "update", "F-001", "--confidence", "confirmed").returncode == 64


def test_update_without_changes_is_a_usage_error(work):
    record(work)
    assert ledger(work, "update", "F-001").returncode == 64


def test_verify_runs_the_check_and_stores_its_result(work):
    record(work, "--confidence", "observed")
    by = write_check(work, name="check_serial.py")
    assert verify(work, "F-001", "--by", by, "--kind", "function").returncode == 0
    finding = read_ledger(work)[0]
    assert finding["confidence"] == "confirmed"
    assert finding["verified_by"] == "tests/check_serial.py"
    script = (work / "tests" / "check_serial.py").read_bytes()
    assert finding["verification"] | {"ts": None} == {
        "kind": "function",
        "check": "tests/check_serial.py",
        "sha256": hashlib.sha256(script).hexdigest(),
        "inputs": [],
        "exit_code": 0,
        "passed": 3,
        "failed": 0,
        "cases": ["PASS a", "PASS b", "PASS c"],
        "ts": None,
    }


def test_verify_passes_each_input_to_the_check_and_hashes_it(work):
    record(work)
    (work / "captures").mkdir()
    (work / "captures" / "fresh.pcapng").write_bytes(b"capture")
    body = "import sys\nfor name in sys.argv[1:]:\n    print('PASS', open(name, 'rb').read())\n"
    by = write_check(work, body)
    result = verify(
        work, "F-001", "--by", by, "--kind", "decoder", "--input", "captures/fresh.pcapng"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    record_ = read_ledger(work)[0]["verification"]
    digest = hashlib.sha256(b"capture").hexdigest()
    assert record_["inputs"] == [{"path": "captures/fresh.pcapng", "sha256": digest}]
    assert record_["cases"] == ["PASS b'capture'"]


def test_the_check_runs_in_the_work_directory(work):
    record(work)
    body = "import os\nprint('PASS' if os.path.isfile('notes.md') else 'FAIL')\n"
    assert confirm(work, "F-001", check=write_check(work, body))


def test_a_decoder_check_needs_an_input(work):
    record(work)
    assert verify(work, "F-001", "--by", write_check(work), "--kind", "decoder").returncode == 64


@pytest.mark.parametrize(
    ("kind", "passes", "accepted"),
    [
        ("function", 3, True),
        ("function", 2, False),
        ("algorithm", 2, True),
        ("algorithm", 1, False),
        ("endpoint", 1, True),
        ("behavior", 1, True),
        ("behavior", 0, False),
    ],
)
def test_each_kind_needs_its_number_of_passing_cases(work, kind, passes, accepted):
    record(work)
    by = write_check(work, f"for n in range({passes}):\n    print('PASS', n)\n")
    result = verify(work, "F-001", "--by", by, "--kind", kind)
    assert (result.returncode == 0) is accepted
    assert (read_ledger(work)[0]["confidence"] == "confirmed") is accepted


@pytest.mark.parametrize(
    "body",
    [
        "print('PASS a\\nPASS b\\nPASS c')\nraise SystemExit(1)\n",
        "print('PASS a\\nPASS b\\nPASS c\\nFAIL d')\n",
        "print('PASSED a\\nPASSING b\\nPASS c')\n",
        "raise ValueError('the model is wrong')\n",
        "",
    ],
    ids=["exits-1", "one-fail", "lookalike-lines", "crash", "silent"],
)
def test_a_failing_check_leaves_the_finding_as_it_was(work, body):
    record(work, "--confidence", "observed")
    before = (work / "findings.jsonl").read_text("utf-8")
    result = verify(work, "F-001", "--by", write_check(work, body), "--kind", "function")
    assert result.returncode == 1
    assert "F-001 stays observed" in result.stderr
    assert (work / "findings.jsonl").read_text("utf-8") == before


def test_a_failing_check_shows_its_output(work):
    record(work)
    by = write_check(work, "print('FAIL model says 1, program says 0')\n")
    result = verify(work, "F-001", "--by", by, "--kind", "behavior")
    assert "model says 1, program says 0" in result.stderr


@pytest.mark.parametrize(
    "by",
    [
        "original/run.py",
        "decompiled/run.py",
        "run.py",
        "../run.py",
        "tests/run.sh",
        "tests/none.py",
    ],
)
def test_verify_only_runs_a_python_check_from_tests(work, by):
    record(work)
    marker = work.parent / "ran"
    for folder in ("original", "decompiled", "tests", "."):
        (work / folder).mkdir(exist_ok=True)
        for name in ("run.py", "run.sh"):
            (work / folder / name).write_text(f"open({str(marker)!r}, 'w')\nprint('PASS')\n")
    (work.parent / "run.py").write_text(f"open({str(marker)!r}, 'w')\nprint('PASS')\n")
    (work / "tests" / "run.py").unlink()
    assert verify(work, "F-001", "--by", by, "--kind", "behavior").returncode == 1
    assert not marker.exists()
    assert read_ledger(work)[0]["confidence"] == "unknown"


@pytest.mark.skipif(os.name == "nt", reason="symlinks need extra rights on Windows")
def test_a_link_from_tests_to_a_target_file_is_refused(work):
    record(work)
    (work / "original" / "run.py").write_text("print('PASS')\n")
    (work / "tests").mkdir()
    (work / "tests" / "check.py").symlink_to(work / "original" / "run.py")
    assert verify(work, "F-001", "--by", "tests/check.py", "--kind", "behavior").returncode == 1


def test_an_input_outside_the_work_directory_is_refused(work):
    record(work)
    (work.parent / "elsewhere.bin").write_bytes(b"x")
    by = write_check(work)
    result = verify(work, "F-001", "--by", by, "--kind", "decoder", "--input", "../elsewhere.bin")
    assert result.returncode == 1
    assert "../elsewhere.bin must be inside the work directory" in result.stderr


def test_a_check_that_hangs_is_stopped(work):
    record(work)
    by = write_check(work, "import time\ntime.sleep(60)\nprint('PASS')\n")
    started = time.monotonic()
    result = verify(work, "F-001", "--by", by, "--kind", "behavior", "--timeout", "1")
    assert result.returncode == 1
    assert "did not finish within 1 seconds" in result.stderr
    assert time.monotonic() - started < 20


@pytest.mark.parametrize(
    "command",
    [["verify", "F-001", "--kind", "behavior"], ["verify", "F-001", "--by", "tests/check.py"]],
)
def test_verify_needs_a_check_and_a_kind(work, command):
    record(work)
    write_check(work)
    assert ledger(work, *command).returncode == 64
    assert read_ledger(work)[0]["confidence"] == "unknown"


def test_verify_reports_an_unknown_id(work):
    assert verify(work, "F-404", "--by", write_check(work), "--kind", "behavior").returncode == 1


def test_a_confirmed_claim_cannot_be_edited(work):
    record(work)
    confirm(work, "F-001")
    assert ledger(work, "update", "F-001", "--claim", "something else").returncode == 1
    assert ledger(work, "update", "F-001", "--evidence", "more").returncode == 1


def test_verify_again_replaces_the_record(work):
    record(work)
    by = confirm(work, "F-001")
    write_check(work, "for n in range(4):\n    print('PASS', n)\n")
    result = verify(work, "F-001", "--by", by, "--kind", "function")
    assert result.returncode == 0
    assert "confirmed again" in result.stdout
    assert read_ledger(work)[0]["verification"]["passed"] == 4


def test_a_failed_second_verify_keeps_the_old_record_and_audit_flags_it(work):
    record(work)
    by = confirm(work, "F-001")
    first = read_ledger(work)[0]["verification"]
    write_check(work, "print('FAIL now')\n")
    assert verify(work, "F-001", "--by", by, "--kind", "behavior").returncode == 1
    assert read_ledger(work)[0]["verification"] == first
    assert ledger(work, "audit").returncode == 1


def test_retract_keeps_the_record_and_closes_it(work):
    record(work)
    confirm(work, "F-001")
    assert ledger(work, "retract", "F-001", "--reason", "the test had a bug").returncode == 0
    finding = read_ledger(work)[0]
    assert finding["retracted"] == "the test had a bug"
    assert finding["verification"]["check"] == "tests/check.py"
    assert ledger(work, "update", "F-001", "--claim", "new").returncode == 1
    assert ledger(work, "retract", "F-001", "--reason", "again").returncode == 1
    assert verify(work, "F-001", "--by", "tests/check.py", "--kind", "behavior").returncode == 1


def test_a_hand_edited_confirmed_finding_is_rejected(work):
    record(work)
    finding = read_ledger(work)[0] | {"confidence": "confirmed", "verified_by": "tests/a.py"}
    (work / "findings.jsonl").write_text(json.dumps(finding) + "\n", "utf-8")
    result = ledger(work, "list")
    assert result.returncode == 1
    assert "confirmed needs the verification record" in result.stderr


def test_a_hand_edited_record_of_a_failed_check_is_rejected(work):
    record(work)
    confirm(work, "F-001")
    finding = read_ledger(work)[0]
    finding["verification"]["exit_code"] = 1
    (work / "findings.jsonl").write_text(json.dumps(finding) + "\n", "utf-8")
    assert "exited 0" in ledger(work, "list").stderr


def test_audit_passes_while_checks_and_inputs_are_unchanged(work):
    record(work)
    record(work)
    confirm(work, "F-001")
    result = ledger(work, "audit")
    assert result.returncode == 0
    assert "Checked 1 confirmed finding(s): each matches its check" in result.stdout


@pytest.mark.parametrize("change", ["edit-check", "delete-check", "edit-input"])
def test_audit_finds_a_check_or_input_that_changed(work, change):
    record(work)
    (work / "capture.bin").write_bytes(b"one")
    confirm(work, "F-001", "--input", "capture.bin", kind="decoder")
    if change == "edit-check":
        (work / "tests" / "check.py").write_text("print('PASS')\n", "utf-8")
    elif change == "delete-check":
        (work / "tests" / "check.py").unlink()
    else:
        (work / "capture.bin").write_bytes(b"two")
    result = ledger(work, "audit")
    assert result.returncode == 1
    assert "F-001" in result.stderr


def test_audit_rerun_catches_a_check_that_no_longer_passes(work):
    record(work)
    (work / "state.txt").write_text("ok", "utf-8")
    body = "print('PASS' if open('state.txt').read() == 'ok' else 'FAIL')\n"
    confirm(work, "F-001", check=write_check(work, body))
    (work / "state.txt").write_text("changed", "utf-8")
    assert ledger(work, "audit").returncode == 0
    result = ledger(work, "audit", "--rerun")
    assert result.returncode == 1
    assert "did not pass" in result.stderr


def test_audit_ignores_a_retracted_finding(work):
    record(work)
    confirm(work, "F-001")
    ledger(work, "retract", "F-001", "--reason", "wrong")
    (work / "tests" / "check.py").unlink()
    assert ledger(work, "audit").returncode == 0


def test_audit_does_not_run_a_check_named_by_a_hand_edited_record(work):
    record(work)
    confirm(work, "F-001")
    marker = work.parent / "ran"
    (work / "original" / "run.py").write_text(f"open({str(marker)!r}, 'w')\nprint('PASS')\n")
    finding = read_ledger(work)[0]
    script = (work / "original" / "run.py").read_bytes()
    finding["verification"] |= {
        "check": "original/run.py",
        "sha256": hashlib.sha256(script).hexdigest(),
    }
    (work / "findings.jsonl").write_text(json.dumps(finding) + "\n", "utf-8")
    assert ledger(work, "audit", "--rerun").returncode == 1
    assert not marker.exists()


RESUME_NOTES = """# Notes: demo

## Authorization

Own crackme.

## Hypotheses

- H1: the check is a XOR with a 4-byte key. Supported by F-001.
- H2: the length must be 16. Open.

## Session log

### 2026-11-04
- Did: decompiled check_serial.
- Next: read KEY.

### 2026-11-05
- Did: read KEY and EXPECTED.
- Next: write the differential test for F-002.
"""


def test_resume_shows_where_the_analysis_stands(work):
    (work / "notes.md").write_text(RESUME_NOTES, "utf-8")
    record(work, "--claim", "The key is 4 bytes")
    record(work, "--claim", "check_serial XORs and rotates", "--confidence", "inferred")
    confirm(work, "F-001")
    result = ledger(work, "resume")
    assert result.returncode == 0
    text = result.stdout
    assert "1 inferred" in text and "1 confirmed" in text
    assert "F-002  inferred   check_serial XORs and rotates" in text
    assert "F-001  " not in text.split("Open findings:")[1].split("Confirmed findings")[0]
    assert "H2: the length must be 16" in text
    assert "write the differential test for F-002" in text
    assert "decompiled check_serial" not in text


def test_resume_lists_stale_confirmations(work):
    record(work)
    confirm(work, "F-001")
    (work / "tests" / "check.py").write_text("print('PASS')\n", "utf-8")
    payload = json.loads(ledger(work, "--json", "resume").stdout)
    assert payload["problems"] and payload["problems"][0].startswith("F-001: ")


def test_resume_without_notes_says_how_to_start(work):
    (work / "notes.md").unlink()
    result = ledger(work, "resume")
    assert result.returncode == 0
    assert "templates/notes.md" in result.stdout


def test_damaged_line_is_named(work):
    record(work)
    with (work / "findings.jsonl").open("a", encoding="utf-8") as file:
        file.write("{not json\n")
    result = ledger(work, "list")
    assert result.returncode == 1
    assert "line 2" in result.stderr


def test_repeated_ids_are_rejected(work):
    record(work)
    line = (work / "findings.jsonl").read_text("utf-8")
    (work / "findings.jsonl").write_text(line + line, "utf-8")
    assert ledger(work, "list").returncode == 1


@pytest.mark.parametrize("name", ["notes", "re-work"])
def test_refuses_to_write_outside_a_target_folder(tmp_path, name):
    folder = tmp_path / name
    folder.mkdir()
    result = run_script(
        "ledger.py",
        "--work",
        str(folder),
        "add",
        "--claim",
        "a",
        "--location",
        "b",
        "--evidence",
        "c",
    )
    assert result.returncode == 3
    assert not (folder / "findings.jsonl").exists()


def test_the_current_directory_is_the_default_work_directory(work):
    record(work)
    by = write_check(work)
    result = run_script("ledger.py", "verify", "F-001", "--by", by, "--kind", "behavior", cwd=work)
    assert result.returncode == 0


def test_flags_work_on_either_side_of_the_subcommand(work):
    record(work)
    result = run_script("ledger.py", "list", "--work", str(work), "--json")
    assert json.loads(result.stdout)["status"] == "ok"


def test_errors_are_reported_as_json_when_asked(work):
    result = ledger(work, "--json", "verify", "F-404", "--by", "tests/x.py", "--kind", "behavior")
    assert json.loads(result.stdout)["status"] == "error"


@pytest.mark.parametrize("claim", ["Логін надсилає пароль", "line separator", "a\nb"])
def test_text_from_a_target_survives_a_round_trip(work, claim):
    record(work, "--claim", claim)
    assert ledger(work, "list").returncode == 0
    assert ledger(work, "update", "F-001", "--evidence", "more").returncode == 0
    assert read_ledger_exact(work)[0]["claim"] == claim


def read_ledger_exact(work):
    text = (work / "findings.jsonl").read_text("utf-8")
    return [json.loads(line) for line in text.split("\n") if line]


@pytest.fixture
def validator():
    schema = json.loads((SKILL_DIR / "templates" / "findings.schema.json").read_text("utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def test_everything_the_ledger_writes_matches_the_schema(work, validator):
    record(work, "--confidence", "inferred", "--hypothesis", "H3")
    record(work)
    record(work)
    record(work)
    (work / "capture.bin").write_bytes(b"x")
    confirm(work, "F-002", kind="function")
    confirm(work, "F-003", "--input", "capture.bin", kind="decoder")
    ledger(work, "retract", "F-004", "--reason", "wrong offset")
    for finding in read_ledger(work):
        validator.validate(finding)


GOOD = {
    "id": "F-012",
    "claim": "Login sends credentials to /v1/auth",
    "location": "sources/com/app/Api.java:88",
    "evidence": "line reference",
    "confidence": "inferred",
    "verified_by": None,
    "verification": None,
    "hypothesis": "H3",
    "ts": "2026-11-02T10:14:00Z",
}
RECORD = {
    "kind": "function",
    "check": "tests/check_auth.py",
    "sha256": "a" * 64,
    "inputs": [],
    "exit_code": 0,
    "passed": 3,
    "failed": 0,
    "cases": ["PASS one", "PASS two", "PASS three"],
    "ts": "2026-11-02T10:15:00Z",
}
CONFIRMED = GOOD | {"confidence": "confirmed", "verified_by": "tests/check_auth.py"}


def confirmed_with(**changes):
    return CONFIRMED | {"verification": RECORD | changes}


@pytest.mark.parametrize(
    "finding",
    [
        GOOD,
        GOOD | {"hypothesis": None},
        GOOD | {"retracted": "wrong offset"},
        GOOD | {"id": "F-1234"},
        GOOD | {"id": "F-12"},
        GOOD | {"id": 12},
        GOOD | {"claim": ""},
        GOOD | {"claim": "   "},
        GOOD | {"location": ""},
        GOOD | {"evidence": None},
        GOOD | {"confidence": "certain"},
        GOOD | {"verified_by": 3},
        GOOD | {"hypothesis": "3"},
        GOOD | {"hypothesis": 3},
        GOOD | {"retracted": ""},
        GOOD | {"extra": 1},
        {key: value for key, value in GOOD.items() if key != "ts"},
        {key: value for key, value in GOOD.items() if key != "verification"},
        "not an object",
        GOOD | {"verification": RECORD},
        CONFIRMED,
        CONFIRMED | {"verification": RECORD},
        CONFIRMED | {"verification": RECORD, "retracted": "wrong"},
        CONFIRMED | {"verification": RECORD, "verified_by": ""},
        CONFIRMED | {"verification": RECORD, "verified_by": None},
        CONFIRMED | {"verification": "tests/check_auth.py"},
        confirmed_with(kind="guess"),
        confirmed_with(kind="algorithm", passed=2),
        confirmed_with(kind="algorithm", passed=1),
        confirmed_with(passed=2),
        confirmed_with(passed="3"),
        confirmed_with(kind="behavior", passed=1),
        confirmed_with(kind="behavior", passed=0),
        confirmed_with(exit_code=1),
        confirmed_with(exit_code=True),
        confirmed_with(exit_code=False),
        confirmed_with(failed=1),
        confirmed_with(sha256="abc"),
        confirmed_with(sha256="A" * 64),
        confirmed_with(check=""),
        confirmed_with(cases=[1]),
        confirmed_with(cases="PASS"),
        confirmed_with(kind="decoder", passed=1),
        confirmed_with(kind="decoder", passed=1, inputs=[{"path": "c.pcapng", "sha256": "b" * 64}]),
        confirmed_with(inputs=[{"path": "c.pcapng"}]),
        confirmed_with(inputs=[{"path": "", "sha256": "b" * 64}]),
        confirmed_with(inputs=[{"path": "c", "sha256": "b" * 64, "size": 1}]),
        confirmed_with(extra=1),
        CONFIRMED | {"verification": {k: v for k, v in RECORD.items() if k != "ts"}},
    ],
)
def test_stdlib_check_agrees_with_the_schema(validator, finding):
    assert (not check(finding)) == validator.is_valid(finding)
