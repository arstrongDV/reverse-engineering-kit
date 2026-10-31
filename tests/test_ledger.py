"""findings.jsonl: what ledger.py accepts, what it refuses, and the schema it must match."""

import json

import jsonschema
import pytest
from conftest import SKILL_DIR, record, run_script

from ledger import check


def read_ledger(work):
    path = work / "findings.jsonl"
    return [json.loads(line) for line in path.read_text("utf-8").splitlines()]


def ledger(work, *args):
    return run_script("ledger.py", "--work", str(work), *args)


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


def test_verify_records_what_proved_the_finding(work):
    record(work, "--confidence", "observed")
    assert ledger(work, "verify", "F-001", "--by", "tests/test_auth.py").returncode == 0
    finding = read_ledger(work)[0]
    assert finding["confidence"] == "confirmed"
    assert finding["verified_by"] == "tests/test_auth.py"


@pytest.mark.parametrize("command", [["verify", "F-001"], ["verify", "F-001", "--by", "  "]])
def test_verify_needs_a_named_check(work, command):
    record(work)
    assert ledger(work, *command).returncode in (1, 64)
    assert read_ledger(work)[0]["confidence"] == "unknown"


def test_verify_reports_an_unknown_id(work):
    assert ledger(work, "verify", "F-404", "--by", "x").returncode == 1


def test_a_confirmed_claim_cannot_be_edited(work):
    record(work)
    ledger(work, "verify", "F-001", "--by", "tests/a.py")
    assert ledger(work, "update", "F-001", "--claim", "something else").returncode == 1
    assert ledger(work, "verify", "F-001", "--by", "tests/b.py").returncode == 1
    assert read_ledger(work)[0]["verified_by"] == "tests/a.py"


def test_retract_keeps_the_record_and_closes_it(work):
    record(work)
    ledger(work, "verify", "F-001", "--by", "tests/a.py")
    assert ledger(work, "retract", "F-001", "--reason", "the test had a bug").returncode == 0
    assert read_ledger(work)[0]["retracted"] == "the test had a bug"
    assert ledger(work, "update", "F-001", "--claim", "new").returncode == 1
    assert ledger(work, "retract", "F-001", "--reason", "again").returncode == 1


def test_a_hand_edited_confirmed_finding_is_rejected(work):
    record(work)
    finding = read_ledger(work)[0] | {"confidence": "confirmed"}
    (work / "findings.jsonl").write_text(json.dumps(finding) + "\n", "utf-8")
    result = ledger(work, "list")
    assert result.returncode == 1
    assert "confirmed needs verified_by" in result.stderr


def test_a_damaged_line_is_named(work):
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
    result = run_script("ledger.py", "verify", "F-001", "--by", "tests/a.py", cwd=work)
    assert result.returncode == 0


def test_flags_work_on_either_side_of_the_subcommand(work):
    record(work)
    result = run_script("ledger.py", "list", "--work", str(work), "--json")
    assert json.loads(result.stdout)["status"] == "ok"


def test_errors_are_reported_as_json_when_asked(work):
    result = ledger(work, "--json", "verify", "F-404", "--by", "x")
    assert json.loads(result.stdout)["status"] == "error"


@pytest.mark.parametrize("claim", ["Логін надсилає пароль", "line separator", "a\nb"])
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
    return jsonschema.Draft202012Validator(schema)


def test_everything_the_ledger_writes_matches_the_schema(work, validator):
    record(work, "--confidence", "inferred", "--hypothesis", "H3")
    record(work)
    record(work)
    ledger(work, "verify", "F-002", "--by", "tests/a.py")
    ledger(work, "retract", "F-003", "--reason", "wrong offset")
    for finding in read_ledger(work):
        validator.validate(finding)


GOOD = {
    "id": "F-012",
    "claim": "Login sends credentials to /v1/auth",
    "location": "sources/com/app/Api.java:88",
    "evidence": "line reference",
    "confidence": "inferred",
    "verified_by": None,
    "hypothesis": "H3",
    "ts": "2026-11-02T10:14:00Z",
}


@pytest.mark.parametrize(
    "finding",
    [
        GOOD,
        GOOD | {"hypothesis": None},
        GOOD | {"confidence": "confirmed", "verified_by": "tests/a.py"},
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
        GOOD | {"confidence": "confirmed"},
        GOOD | {"confidence": "confirmed", "verified_by": ""},
        GOOD | {"confidence": "confirmed", "verified_by": "   "},
        GOOD | {"retracted": ""},
        GOOD | {"extra": 1},
        {key: value for key, value in GOOD.items() if key != "ts"},
        "not an object",
    ],
)
def test_stdlib_check_agrees_with_the_schema(validator, finding):
    assert (not check(finding)) == validator.is_valid(finding)
