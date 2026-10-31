#!/usr/bin/env python3
"""Add, list, update, verify and retract findings in findings.jsonl."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from _common import (
    EXIT_OK,
    EXIT_USAGE,
    ArgumentParser,
    KitError,
    add_work_flag,
    build_parser,
    emit,
    fail,
    resolve_work_dir,
    write_atomic,
)

LEDGER = "findings.jsonl"
CONFIDENCE = ("unknown", "inferred", "observed", "confirmed")
# Only verify can reach the last level, so it is not a value anyone can pass in.
SETTABLE_CONFIDENCE = CONFIDENCE[:-1]
TEXT_FIELDS = ("claim", "location", "evidence")
EDITABLE_FIELDS = (*TEXT_FIELDS, "confidence", "hypothesis")
REQUIRED_FIELDS = {*TEXT_FIELDS, "id", "confidence", "verified_by", "hypothesis", "ts"}
OPTIONAL_FIELDS = {"retracted"}
ID_PATTERN = re.compile(r"F-[0-9]{3,}")
HYPOTHESIS_PATTERN = re.compile(r"H[0-9]+")


def filled(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def valid_timestamp(value: object) -> bool:
    try:
        datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    return isinstance(value, str)


def check(finding: object) -> list[str]:
    """Apply templates/findings.schema.json with the stdlib. A test keeps the two in step."""
    if not isinstance(finding, dict):
        return ["not a JSON object"]
    problems = [f"missing {field}" for field in sorted(REQUIRED_FIELDS - finding.keys())]
    extra = finding.keys() - REQUIRED_FIELDS - OPTIONAL_FIELDS
    problems += [f"unexpected {field}" for field in sorted(extra)]
    if problems:
        return problems

    if not (isinstance(finding["id"], str) and ID_PATTERN.fullmatch(finding["id"])):
        problems.append("id must look like F-012")
    problems += [f"{field} is empty" for field in TEXT_FIELDS if not filled(finding[field])]
    if finding["confidence"] not in CONFIDENCE:
        problems.append(f"confidence must be one of {', '.join(CONFIDENCE)}")
    if not (finding["verified_by"] is None or isinstance(finding["verified_by"], str)):
        problems.append("verified_by must be text or null")
    hypothesis = finding["hypothesis"]
    if not (
        hypothesis is None
        or (isinstance(hypothesis, str) and HYPOTHESIS_PATTERN.fullmatch(hypothesis))
    ):
        problems.append("hypothesis must look like H3")
    if not valid_timestamp(finding["ts"]):
        problems.append("ts must be an ISO 8601 date-time")
    if "retracted" in finding and not filled(finding["retracted"]):
        problems.append("retracted must state a reason")
    if finding["confidence"] == "confirmed" and not filled(finding["verified_by"]):
        problems.append("confirmed needs verified_by")
    return problems


def load_findings(work: Path) -> list[dict]:
    path = work / LEDGER
    if not path.exists():
        return []
    findings = []
    # Not splitlines(): it also breaks on separators such as U+2028 that targets can contain.
    for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), start=1):
        if not line.strip():
            continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError as error:
            raise KitError(f"{LEDGER} line {number} is not valid JSON: {error}") from error
        problems = check(finding)
        if problems:
            raise KitError(f"{LEDGER} line {number}: {'; '.join(problems)}")
        findings.append(finding)
    ids = [finding["id"] for finding in findings]
    duplicates = sorted({value for value in ids if ids.count(value) > 1})
    if duplicates:
        raise KitError(f"{LEDGER} repeats {', '.join(duplicates)}")
    return findings


def save_findings(work: Path, findings: list[dict]) -> None:
    lines = [json.dumps(finding, ensure_ascii=False) + "\n" for finding in findings]
    write_atomic(work / LEDGER, "".join(lines))


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def one_line(text: str) -> str:
    """Targets supply much of this text, so stop it from breaking a list or a report."""
    return " ".join(text.split())


def next_id(findings: list[dict]) -> str:
    highest = max((int(finding["id"][2:]) for finding in findings), default=0)
    return f"F-{highest + 1:03d}"


def find(findings: list[dict], finding_id: str) -> dict:
    for finding in findings:
        if finding["id"] == finding_id:
            return finding
    raise KitError(f"no finding {finding_id}")


def require_valid(finding: dict) -> None:
    problems = check(finding)
    if problems:
        raise KitError("; ".join(problems))


def require_open(finding: dict) -> None:
    """A verified claim must stay the claim that was tested, so it cannot be edited."""
    if "retracted" in finding:
        raise KitError(f"{finding['id']} is retracted: {finding['retracted']}")
    if finding["confidence"] == "confirmed":
        raise KitError(
            f"{finding['id']} is confirmed by {finding['verified_by']}. "
            "If it is wrong, retract it and add a new finding."
        )


def add(work: Path, args: argparse.Namespace) -> None:
    findings = load_findings(work)
    finding = {
        "id": next_id(findings),
        "claim": args.claim,
        "location": args.location,
        "evidence": args.evidence,
        "confidence": args.confidence,
        "verified_by": None,
        "hypothesis": args.hypothesis,
        "ts": now(),
    }
    require_valid(finding)
    save_findings(work, [*findings, finding])
    report = f"{finding['id']} added ({finding['confidence']})"
    emit({"status": "ok", "finding": finding}, report, args.json)


def list_findings(work: Path, args: argparse.Namespace) -> None:
    findings = load_findings(work)
    if args.confidence:
        findings = [item for item in findings if item["confidence"] == args.confidence]
    lines = []
    for finding in findings:
        line = f"{finding['id']}  {finding['confidence']:<9}  {one_line(finding['claim'])}"
        line += f"  [{one_line(finding['location'])}]"
        if "retracted" in finding:
            line += f"  (retracted: {one_line(finding['retracted'])})"
        lines.append(line)
    report = "\n".join(lines) or "no findings"
    emit({"status": "ok", "findings": findings}, report, args.json)


def update(work: Path, args: argparse.Namespace) -> None:
    changes = {
        field: getattr(args, field) for field in EDITABLE_FIELDS if getattr(args, field) is not None
    }
    if not changes:
        raise KitError("nothing to update: pass at least one field", EXIT_USAGE)
    findings = load_findings(work)
    finding = find(findings, args.id)
    require_open(finding)
    if "confidence" in changes:
        before = CONFIDENCE.index(finding["confidence"])
        if CONFIDENCE.index(changes["confidence"]) < before:
            raise KitError(
                f"confidence only moves up, and {finding['id']} is {finding['confidence']}. "
                "If it is wrong, retract it."
            )
    finding.update(changes, ts=now())
    require_valid(finding)
    save_findings(work, findings)
    emit({"status": "ok", "finding": finding}, f"{finding['id']} updated", args.json)


def verify(work: Path, args: argparse.Namespace) -> None:
    findings = load_findings(work)
    finding = find(findings, args.id)
    require_open(finding)
    finding.update(confidence="confirmed", verified_by=args.by, ts=now())
    require_valid(finding)
    save_findings(work, findings)
    report = f"{finding['id']} confirmed by {finding['verified_by']}"
    emit({"status": "ok", "finding": finding}, report, args.json)


def retract(work: Path, args: argparse.Namespace) -> None:
    findings = load_findings(work)
    finding = find(findings, args.id)
    if "retracted" in finding:
        raise KitError(f"{finding['id']} is already retracted")
    finding.update(retracted=args.reason, ts=now())
    require_valid(finding)
    save_findings(work, findings)
    emit({"status": "ok", "finding": finding}, f"{finding['id']} retracted", args.json)


def build_ledger_parser() -> ArgumentParser:
    parser = build_parser(__doc__)
    add_work_flag(parser)
    # Agents put flags on either side of the subcommand, so accept both.
    shared = ArgumentParser(add_help=False)
    shared.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="print machine-readable JSON",
    )
    add_work_flag(shared, default=None)
    commands = parser.add_subparsers(dest="command", required=True)

    command = commands.add_parser("add", parents=[shared], help="record a finding")
    command.add_argument("--claim", required=True, help="what is believed to be true")
    command.add_argument("--location", required=True, help="file, address or capture offset")
    command.add_argument("--evidence", required=True, help="what supports the claim")
    command.add_argument("--confidence", choices=SETTABLE_CONFIDENCE, default="unknown")
    command.add_argument("--hypothesis", help="the hypothesis this tests, such as H3")
    command.set_defaults(run=add)

    command = commands.add_parser("list", parents=[shared], help="show findings")
    command.add_argument("--confidence", choices=CONFIDENCE, help="show one level only")
    command.set_defaults(run=list_findings)

    command = commands.add_parser("update", parents=[shared], help="change an open finding")
    command.add_argument("id")
    command.add_argument("--claim")
    command.add_argument("--location")
    command.add_argument("--evidence")
    command.add_argument("--confidence", choices=SETTABLE_CONFIDENCE)
    command.add_argument("--hypothesis")
    command.set_defaults(run=update)

    command = commands.add_parser("verify", parents=[shared], help="mark a finding confirmed")
    command.add_argument("id")
    command.add_argument("--by", required=True, help="the test, capture or log that proves it")
    command.set_defaults(run=verify)

    command = commands.add_parser("retract", parents=[shared], help="withdraw a wrong finding")
    command.add_argument("id")
    command.add_argument("--reason", required=True, help="what showed it to be wrong")
    command.set_defaults(run=retract)
    return parser


def main() -> int:
    args = build_ledger_parser().parse_args()
    try:
        args.run(resolve_work_dir(args.work), args)
    except KitError as error:
        return fail(error, args.json)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
