#!/usr/bin/env python3
"""Render findings.jsonl and notes.md into REPORT.md."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

from _common import (
    EXIT_OK,
    KitError,
    add_work_flag,
    build_parser,
    emit,
    fail,
    resolve_work_dir,
    write_atomic,
)
from ledger import LEDGER, load_findings, one_line

NOTES = "notes.md"
REPORT = "REPORT.md"
TEMPLATE = Path(__file__).resolve().parent.parent / "templates" / "report.md"
REQUIRED_NOTES = ("authorization", "summary", "gaps")
PLACEHOLDER = re.compile(r"\{\{(\w+)\}\}")


def read_notes(work: Path) -> dict[str, str]:
    path = work / NOTES
    if not path.is_file():
        raise KitError(f"{NOTES} is missing. Start it from templates/notes.md.")
    text = re.sub(r"<!--.*?-->", "", path.read_text(encoding="utf-8"), flags=re.DOTALL)
    sections: dict[str, list[str]] = {}
    current = None
    for line in text.split("\n"):
        if line.startswith("## "):
            current = sections.setdefault(line[3:].strip().lower(), [])
        elif current is not None:
            current.append(line)
    notes = {name: "\n".join(lines).strip() for name, lines in sections.items()}
    empty = [name for name in REQUIRED_NOTES if not notes.get(name)]
    if empty:
        raise KitError(f"{NOTES} needs text under: {', '.join(empty)}")
    return notes


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_originals(work: Path) -> str:
    root = work / "original"
    files = sorted(path for path in root.rglob("*") if path.is_file())
    if not files:
        raise KitError("original/ holds no files, so the report cannot name what it analyzed")
    if len(files) == 1:
        return sha256_of(files[0])
    return ", ".join(f"{path.relative_to(root).as_posix()}: {sha256_of(path)}" for path in files)


def render_finding(finding: dict) -> str:
    lines = [
        f"- **{finding['id']}** {one_line(finding['claim'])}",
        f"  - Location: {one_line(finding['location'])}",
        f"  - Evidence: {one_line(finding['evidence'])}",
    ]
    if finding["verified_by"]:
        lines.append(f"  - Verified by: {one_line(finding['verified_by'])}")
    if "retracted" in finding:
        lines.append(f"  - Retracted: {one_line(finding['retracted'])}")
    return "\n".join(lines)


def render_list(findings: list[dict]) -> str:
    return "\n".join(render_finding(finding) for finding in findings) or "None."


def fill(template: str, values: dict[str, str]) -> str:
    # One pass over the template, so text from a finding is never expanded as a placeholder.
    def value_of(match: re.Match) -> str:
        if match.group(1) not in values:
            raise KitError(f"{TEMPLATE.name} has an unknown placeholder: {match.group(0)}")
        return values[match.group(1)]

    return PLACEHOLDER.sub(value_of, template)


def build_report(work: Path) -> tuple[str, dict[str, int]]:
    notes = read_notes(work)
    findings = load_findings(work)
    if not findings:
        raise KitError(f"{LEDGER} has no findings to report")
    active = [finding for finding in findings if "retracted" not in finding]
    groups = {
        level: [finding for finding in active if finding["confidence"] == level]
        for level in ("confirmed", "observed", "inferred", "unknown")
    }
    retracted = [finding for finding in findings if "retracted" in finding]
    gaps = notes["gaps"]
    if groups["unknown"]:
        gaps += f"\n\nOpen questions from the ledger:\n\n{render_list(groups['unknown'])}"
    report = fill(
        TEMPLATE.read_text(encoding="utf-8"),
        {
            "target": work.name,
            "sha256": hash_originals(work),
            "authorization": one_line(notes["authorization"]),
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "summary": notes["summary"],
            "confirmed": render_list(groups["confirmed"]),
            "observed": render_list(groups["observed"]),
            "inferred": render_list(groups["inferred"]),
            "gaps": gaps,
            "retracted": render_list(retracted),
        },
    )
    counts = {level: len(items) for level, items in groups.items()}
    return report, counts | {"retracted": len(retracted)}


def main() -> int:
    parser = build_parser(__doc__)
    add_work_flag(parser)
    args = parser.parse_args()
    try:
        work = resolve_work_dir(args.work)
        report, counts = build_report(work)
        write_atomic(work / REPORT, report)
    except KitError as error:
        return fail(error, args.json)
    payload = {"status": "ok", "report": str(work / REPORT), "findings": counts}
    emit(payload, f"wrote {work / REPORT}", args.json)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
