"""The benchmark runner's host side: what an agent is told, and how a run is summarized."""

import json

import pytest
from conftest import REPO_ROOT

from bench_task import TaskError, benchmark_dir, prompt_for, stage
from score_run import ScoreError, summarize

ENTRIES = sorted((REPO_ROOT / "benchmarks").glob("*/expected.json"))


@pytest.mark.parametrize("path", ENTRIES, ids=lambda path: path.parent.name)
def test_no_prompt_gives_the_answer_away(path):
    entry = json.loads(path.read_text("utf-8"))
    prompt = prompt_for(entry)
    names = [artifact.removeprefix("build/") for artifact in entry["artifacts"]]
    assert all(name in prompt for name in names)
    # The agent sees the file names whatever the prompt says, so only the rest has to be clean.
    for name in names:
        prompt = prompt.replace(name, "")
    prompt = prompt.lower()
    assert [marker for marker in entry["answer_markers"] if marker.lower() in prompt] == []
    assert entry["target"].lower() not in prompt


def test_the_prompt_names_the_deliverable_and_the_authorization():
    prompt = prompt_for(json.loads(ENTRIES[3].read_text("utf-8")))
    assert "What I need: message dictionary and a working decoder." in prompt
    assert "Keep session-holdout.pcap back" in prompt
    assert "authorized" in prompt
    assert "reverse-engineering-kit skill" in prompt


def test_staging_copies_the_built_targets_and_nothing_else(tmp_path):
    bench = tmp_path / "bench"
    (bench / "build" / "resources").mkdir(parents=True)
    (bench / "src").mkdir()
    (bench / "src" / "answer.c").write_text("secret")
    (bench / "build" / "resources" / "app.asar").write_bytes(b"asar")
    entry = {"artifacts": ["build/resources/app.asar"], "deliverable": "An IPC map"}
    (bench / "expected.json").write_text(json.dumps(entry))
    stage(bench, tmp_path / "out")
    files = sorted(str(p.relative_to(tmp_path / "out")) for p in (tmp_path / "out").rglob("*"))
    assert files == ["prompt.txt", "task", "task/resources", "task/resources/app.asar"]


def test_staging_refuses_a_target_that_was_not_built(tmp_path):
    (tmp_path / "bench").mkdir()
    entry = {"artifacts": ["build/missing"], "deliverable": "Anything"}
    (tmp_path / "bench" / "expected.json").write_text(json.dumps(entry))
    with pytest.raises(TaskError, match="build-benchmarks"):
        stage(tmp_path / "bench", tmp_path / "out")


def test_benchmarks_are_found_by_number():
    assert benchmark_dir("1").name == "01-crackme-xor"
    assert benchmark_dir("10").name == "10-obfuscated-js"
    with pytest.raises(TaskError):
        benchmark_dir("11")


def event(**fields):
    return json.dumps(fields)


@pytest.fixture
def run(tmp_path):
    run = tmp_path / "20261106-120000-01-crackme-xor"
    work = run / "bench" / "task" / "re-work" / "crackme"
    work.mkdir(parents=True)
    skill = {"type": "tool_use", "name": "Skill", "input": {"skill": "reverse-engineering-kit"}}
    (run / "transcript.jsonl").write_text(
        "\n".join(
            [
                event(type="system", subtype="init", model="m", claude_code_version="2"),
                event(type="assistant", message={"content": [skill]}),
                event(type="result", subtype="success", num_turns=40, duration_ms=600000),
            ]
        )
    )
    (run / "exit-code").write_text("0\n")
    record = {"kind": "function", "check": "tests/check.py", "cases": ["PASS a"]}
    findings = [
        {"id": "F-001", "claim": "c1", "confidence": "confirmed", "verification": record},
        {"id": "F-002", "claim": "c2", "confidence": "inferred", "verification": None},
        {"id": "F-003", "claim": "c3", "confidence": "confirmed", "retracted": "wrong"},
    ]
    (work / "findings.jsonl").write_text("\n".join(map(json.dumps, findings)) + "\n")
    (work / "REPORT.md").write_text("The serial is RK26-XOR7-ROL3-A.")
    (work / "decompiled").mkdir()
    (work / "decompiled" / "check_serial.c").write_text("check_serial 5a c3 17 9e")
    return run


def test_a_run_is_summarized_from_its_transcript_and_ledger(run):
    summary = summarize(run)
    assert summary["benchmark"] == "01-crackme-xor"
    assert summary["skill_loaded"] is True
    assert (summary["ended"], summary["turns"], summary["minutes"]) == ("success", 40, 10.0)
    [work] = summary["work_dirs"]
    assert work["path"] == "bench/task/re-work/crackme"
    assert work["confidence"] == {"confirmed": 1, "inferred": 1, "retracted": 1}
    assert [item["id"] for item in work["confirmed"]] == ["F-001"]
    assert work["confirmed"][0]["cases"] == ["PASS a"]


def test_only_what_the_agent_stated_counts_as_a_marker(run):
    [work] = summarize(run)["work_dirs"]
    assert work["markers_stated"] == ["RK26-XOR7-ROL3-A"]
    assert work["markers_missing"] == ["5a c3 17 9e", "check_serial"]


def test_a_work_directory_without_a_ledger_still_counts(run):
    work = run / "bench" / "task" / "re-work" / "crackme"
    (work / "findings.jsonl").unlink()
    (work / "REPORT.md").unlink()
    (work / "triage.json").write_text("{}")
    [summary] = summarize(run)["work_dirs"]
    assert (summary["ledger"], summary["report"]) == (False, False)
    assert summary["confidence"] == {}


def test_a_run_without_a_benchmark_name_is_refused(tmp_path):
    with pytest.raises(ScoreError):
        summarize(tmp_path)
