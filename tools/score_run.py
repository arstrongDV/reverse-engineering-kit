#!/usr/bin/env python3
"""Summarize one benchmark run from dist/runs/ for scoring against its expected.json.

Pass or fail stays a judgment, recorded in benchmarks/RESULTS.md: free-text answers cannot be
matched mechanically. This gathers what the judgment needs: how the run ended, whether the skill
was loaded, every finding with its confidence, the check behind each confirmed one, and which
answer markers the agent itself stated in its report, notes or findings, not in tool output.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCHMARKS = REPO_ROOT / "benchmarks"
SKILL = "reverse-engineering-kit"
STATED = ("REPORT.md", "notes.md", "findings.jsonl")


class ScoreError(Exception):
    pass


def expected_for(run: Path) -> tuple[str, dict]:
    match = re.search(r"-(\d\d-[a-z0-9-]+)$", run.name)
    if not match or not (BENCHMARKS / match[1] / "expected.json").is_file():
        raise ScoreError(f"{run.name} does not end with a benchmark name such as 01-crackme-xor")
    return match[1], json.loads((BENCHMARKS / match[1] / "expected.json").read_text("utf-8"))


def read_transcript(path: Path) -> dict:
    summary = {"model": None, "skill_loaded": False, "ended": "no result event", "turns": None}
    if not path.is_file():
        return summary
    for line in path.read_text("utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") == "system" and event.get("subtype") == "init":
            summary["model"] = event.get("model")
            summary["version"] = event.get("claude_code_version")
        elif event.get("type") == "assistant":
            for block in event.get("message", {}).get("content", []):
                if block.get("type") == "tool_use" and uses_skill(block):
                    summary["skill_loaded"] = True
        elif event.get("type") == "result":
            summary["ended"] = event.get("subtype")
            summary["turns"] = event.get("num_turns")
            summary["minutes"] = round(event.get("duration_ms", 0) / 60000, 1)
            summary["cost_usd"] = event.get("total_cost_usd")
            summary["final"] = (event.get("result") or "")[-1500:]
    return summary


def uses_skill(block: dict) -> bool:
    arguments = block.get("input", {})
    if block.get("name") == "Skill":
        return SKILL in str(arguments.get("skill", arguments.get("command", "")))
    return block.get("name") == "Read" and f"/{SKILL}/SKILL.md" in str(arguments.get("file_path"))


def work_dirs(run: Path) -> list[Path]:
    """Every folder in the agent's home that looks like a work directory the skill set up."""
    marks = ("findings.jsonl", "triage.json", "notes.md")
    return sorted({path.parent for mark in marks for path in (run / "bench").rglob(mark)})


def read_findings(work: Path) -> list[dict]:
    if not (work / "findings.jsonl").is_file():
        return []
    findings = []
    for line in (work / "findings.jsonl").read_text("utf-8", errors="replace").splitlines():
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            findings.append({"id": "?", "claim": f"unreadable line: {line[:80]}"})
    return findings


def stated_text(work: Path) -> str:
    return "\n".join(
        (work / name).read_text("utf-8", errors="replace")
        for name in STATED
        if (work / name).is_file()
    )


def summarize(run: Path) -> dict:
    name, entry = expected_for(run)
    summary = {"run": run.name, "benchmark": name, **read_transcript(run / "transcript.jsonl")}
    exit_code = run / "exit-code"
    summary["exit_code"] = exit_code.read_text().strip() if exit_code.is_file() else None
    summary["work_dirs"] = []
    for work in work_dirs(run):
        findings = read_findings(work)
        text = stated_text(work).lower()
        markers = entry.get("answer_markers", [])
        summary["work_dirs"].append(
            {
                "path": str(work.relative_to(run)),
                "ledger": (work / "findings.jsonl").is_file(),
                "report": (work / "REPORT.md").is_file(),
                "confidence": count_confidence(findings),
                "confirmed": [confirmed(finding) for finding in findings if is_confirmed(finding)],
                "markers_stated": [marker for marker in markers if marker.lower() in text],
                "markers_missing": [marker for marker in markers if marker.lower() not in text],
            }
        )
    return summary


def is_confirmed(finding: dict) -> bool:
    return finding.get("confidence") == "confirmed" and not finding.get("retracted")


def count_confidence(findings: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for finding in findings:
        key = "retracted" if finding.get("retracted") else str(finding.get("confidence"))
        counts[key] = counts.get(key, 0) + 1
    return counts


def confirmed(finding: dict) -> dict:
    record = finding.get("verification") or {}
    return {
        "id": finding.get("id"),
        "claim": finding.get("claim"),
        "check": record.get("check"),
        "kind": record.get("kind"),
        "cases": record.get("cases", []),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("run", type=Path, help="a folder in dist/runs/")
    args = parser.parse_args()
    try:
        summary = summarize(args.run.resolve())
    except ScoreError as error:
        print(f"score_run: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
