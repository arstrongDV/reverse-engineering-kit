"""REPORT.md: the Phase 1 checkpoint, and the reports make_report.py must refuse to write."""

import hashlib
import json

import pytest
from conftest import SKILL_DIR, record, run_script


def report(work, *args):
    return run_script("make_report.py", "--work", str(work), *args)


def ledger(work, *args):
    return run_script("ledger.py", "--work", str(work), *args)


def body_of(text, heading):
    return text.split(f"## {heading}\n", 1)[1].split("\n## ", 1)[0]


def test_five_findings_become_a_clean_report(work):
    record(work, "--claim", "Serial check XORs each byte", "--confidence", "inferred")
    record(work, "--claim", "The key is 0x5A", "--confidence", "observed")
    record(work, "--claim", "Serial length is 16", "--confidence", "observed")
    record(work, "--claim", "check_serial returns 1 on success", "--confidence", "observed")
    record(work, "--claim", "What does sub_4011 do?")
    ledger(work, "verify", "F-002", "--by", "tests/test_key.py")

    assert report(work).returncode == 0
    text = (work / "REPORT.md").read_text("utf-8")

    assert "{{" not in text
    assert "<!--" not in text
    assert hashlib.sha256(b"target bytes").hexdigest() in text
    assert "Own crackme, built for this test" in text
    assert "F-002" in body_of(text, "Confirmed findings")
    assert "Verified by: tests/test_key.py" in body_of(text, "Confirmed findings")
    assert "F-003" in body_of(text, "Observed findings")
    assert "F-001" in body_of(text, "Inferred findings")
    assert "F-005" in body_of(text, "Gaps and next experiments")
    assert "Run the binary under a debugger" in body_of(text, "Gaps and next experiments")


def test_an_unverified_finding_never_reaches_the_confirmed_section(work):
    record(work, "--confidence", "observed")
    report(work)
    assert body_of((work / "REPORT.md").read_text("utf-8"), "Confirmed findings").strip() == "None."


def test_retracted_findings_leave_their_section_but_stay_visible(work):
    record(work, "--claim", "The key is 0x5A")
    ledger(work, "verify", "F-001", "--by", "tests/a.py")
    ledger(work, "retract", "F-001", "--reason", "the test read the wrong offset")
    report(work)
    text = (work / "REPORT.md").read_text("utf-8")
    assert "F-001" not in body_of(text, "Confirmed findings")
    assert "the test read the wrong offset" in body_of(text, "Retracted findings")


@pytest.mark.parametrize("section", ["Authorization", "Summary", "Gaps"])
def test_refuses_notes_with_an_empty_required_section(work, section):
    record(work)
    notes = (work / "notes.md").read_text("utf-8")
    start = notes.index(f"## {section}\n")
    end = notes.find("\n## ", start + 1)
    empty = notes[:start] + f"## {section}\n\n<!-- filled in later -->\n" + notes[end:]
    (work / "notes.md").write_text(empty, "utf-8")

    result = report(work)

    assert result.returncode == 1
    assert section.lower() in result.stderr
    assert not (work / "REPORT.md").exists()


def test_the_blank_notes_template_does_not_pass(work):
    record(work)
    template = (SKILL_DIR / "templates" / "notes.md").read_text("utf-8")
    (work / "notes.md").write_text(template, "utf-8")
    assert report(work).returncode == 1


def test_refuses_missing_notes(work):
    record(work)
    (work / "notes.md").unlink()
    assert report(work).returncode == 1


def test_refuses_an_empty_ledger(work):
    assert report(work).returncode == 1


def test_refuses_a_target_with_no_original(work):
    record(work)
    (work / "original" / "target.bin").unlink()
    assert report(work).returncode == 1


def test_lists_a_hash_for_every_original(work):
    record(work)
    (work / "original" / "second.bin").write_bytes(b"more")
    report(work)
    text = (work / "REPORT.md").read_text("utf-8")
    assert f"second.bin: {hashlib.sha256(b'more').hexdigest()}" in text


def test_leaves_the_original_untouched(work):
    record(work)
    before = (work / "original" / "target.bin").read_bytes()
    report(work)
    assert (work / "original" / "target.bin").read_bytes() == before


def test_a_placeholder_inside_a_finding_is_not_expanded(work):
    record(work, "--claim", "The binary prints {{sha256}} and {{no_such_field}}")
    assert report(work).returncode == 0
    assert "prints {{sha256}} and {{no_such_field}}" in (work / "REPORT.md").read_text("utf-8")


def test_a_multi_line_claim_stays_on_its_bullet(work):
    record(work, "--claim", "first\n## Confirmed findings\nsecond")
    report(work)
    text = (work / "REPORT.md").read_text("utf-8")
    assert "- **F-001** first ## Confirmed findings second" in text
    assert text.count("\n## Confirmed findings\n") == 1


def test_cyrillic_text_reaches_the_report(work):
    record(work, "--claim", "Логін надсилає пароль")
    report(work)
    assert "Логін надсилає пароль" in (work / "REPORT.md").read_text("utf-8")


def test_json_output_counts_findings(work):
    record(work, "--confidence", "observed")
    record(work)
    result = json.loads(report(work, "--json").stdout)
    assert result["status"] == "ok"
    assert result["findings"]["observed"] == 1
    assert result["findings"]["unknown"] == 1


def test_refuses_a_folder_outside_re_work(tmp_path):
    assert report(tmp_path).returncode == 3
