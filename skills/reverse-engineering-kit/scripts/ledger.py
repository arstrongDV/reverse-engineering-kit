#!/usr/bin/env python3
"""Add, list, update, verify, audit and retract findings in findings.jsonl, and resume a session."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
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
    run_tool,
    tail,
    write_atomic,
)

LEDGER = "findings.jsonl"
NOTES = "notes.md"
CONFIDENCE = ("unknown", "inferred", "observed", "confirmed")
# Only verify can reach the last level, so it is not a value anyone can pass in.
SETTABLE_CONFIDENCE = CONFIDENCE[:-1]
TEXT_FIELDS = ("claim", "location", "evidence")
EDITABLE_FIELDS = (*TEXT_FIELDS, "confidence", "hypothesis")
REQUIRED_FIELDS = {
    *TEXT_FIELDS,
    "id",
    "confidence",
    "verified_by",
    "verification",
    "hypothesis",
    "ts",
}
OPTIONAL_FIELDS = {"retracted"}
ID_PATTERN = re.compile(r"F-[0-9]{3,}")
HYPOTHESIS_PATTERN = re.compile(r"H[0-9]+")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")

# Checks are the agent's own scripts. Keeping them in one folder means verify can never be
# pointed at a file from the target, such as a program in original/ or code in decompiled/.
CHECKS = "tests"
CHECK_TIMEOUT = 600
# The passing cases each kind of claim needs, from the table in section 6 of SKILL.md.
KINDS = {"function": 3, "algorithm": 2, "decoder": 1, "endpoint": 1, "behavior": 1}
# A decoder must parse a capture that analysis never used, so its check is given one.
NEEDS_INPUT = {"decoder"}
CASE_LINE = re.compile(r"(PASS|FAIL)\b")
MAX_CASES = 50
VERIFICATION_FIELDS = {
    "kind",
    "check",
    "sha256",
    "inputs",
    "exit_code",
    "passed",
    "failed",
    "cases",
    "ts",
}


def filled(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def whole_number(value: object) -> bool:
    # JSON true and false load as bool, which Python also counts as int.
    return isinstance(value, int) and not isinstance(value, bool)


def valid_timestamp(value: object) -> bool:
    try:
        datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    return isinstance(value, str)


def valid_hash(value: object) -> bool:
    return isinstance(value, str) and bool(SHA256_PATTERN.fullmatch(value))


def valid_input(value: object) -> bool:
    return (
        isinstance(value, dict)
        and value.keys() == {"path", "sha256"}
        and filled(value["path"])
        and valid_hash(value["sha256"])
    )


def check_verification(record: object) -> list[str]:
    """The result ledger.py verify stores. Without one, nothing can count as confirmed."""
    if not isinstance(record, dict):
        return ["confirmed needs the verification record that ledger.py verify writes"]
    problems = [
        f"verification is missing {name}" for name in sorted(VERIFICATION_FIELDS - record.keys())
    ]
    extra = record.keys() - VERIFICATION_FIELDS
    problems += [f"verification has unexpected {name}" for name in sorted(extra)]
    if problems:
        return problems

    kind = record["kind"]
    if kind not in KINDS:
        problems.append(f"verification kind must be one of {', '.join(KINDS)}")
    if not filled(record["check"]):
        problems.append("verification must name its check")
    if not valid_hash(record["sha256"]):
        problems.append("verification sha256 must be a SHA-256 in hex")
    inputs = record["inputs"]
    if not (isinstance(inputs, list) and all(valid_input(item) for item in inputs)):
        problems.append("verification inputs must each have a path and a sha256")
    elif kind in NEEDS_INPUT and not inputs:
        problems.append(f"a {kind} check needs an input")
    if not (whole_number(record["exit_code"]) and record["exit_code"] == 0):
        problems.append("the check must have exited 0")
    if not (whole_number(record["failed"]) and record["failed"] == 0):
        problems.append("the check must have no failed cases")
    needed = KINDS.get(kind, 1)
    if not (whole_number(record["passed"]) and record["passed"] >= needed):
        problems.append(f"a {kind} check needs at least {needed} passing cases")
    if not (isinstance(record["cases"], list) and all(isinstance(c, str) for c in record["cases"])):
        problems.append("verification cases must be a list of text")
    if not valid_timestamp(record["ts"]):
        problems.append("verification ts must be an ISO 8601 date-time")
    return problems


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
    if finding["confidence"] == "confirmed":
        if not filled(finding["verified_by"]):
            problems.append("confirmed needs verified_by")
        problems += check_verification(finding["verification"])
    elif finding["verification"] is not None:
        problems.append("only a confirmed finding has a verification record")
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


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def require_not_retracted(finding: dict) -> None:
    if "retracted" in finding:
        raise KitError(f"{finding['id']} is retracted: {finding['retracted']}")


def require_open(finding: dict) -> None:
    """A verified claim must stay the claim that was tested, so it cannot be edited."""
    require_not_retracted(finding)
    if finding["confidence"] == "confirmed":
        raise KitError(
            f"{finding['id']} is confirmed by {finding['verified_by']}. "
            "If it is wrong, retract it and add a new finding."
        )


def relative(work: Path, path: Path) -> str:
    return path.relative_to(work).as_posix()


def check_path(work: Path, name: str) -> Path:
    path = (work / name).resolve()
    if (work / CHECKS) not in path.parents or path.suffix != ".py":
        raise KitError(f"{name} must be a Python script in {CHECKS}/ of the work directory")
    if not path.is_file():
        raise KitError(f"{name} does not exist")
    return path


def input_path(work: Path, name: str) -> Path:
    path = (work / name).resolve()
    if work not in path.parents:
        raise KitError(f"{name} must be inside the work directory")
    if not path.is_file():
        raise KitError(f"{name} does not exist")
    return path


def run_check(work: Path, kind: str, check_file: Path, inputs: list[Path], timeout: int) -> dict:
    """Run a check and judge its output. Returns the record verify stores, or raises."""
    record = {
        "kind": kind,
        "check": relative(work, check_file),
        "sha256": sha256_of(check_file),
        "inputs": [{"path": relative(work, path), "sha256": sha256_of(path)} for path in inputs],
    }
    command = [sys.executable, str(check_file), *(str(path) for path in inputs)]
    try:
        result = run_tool(command, timeout, cwd=work)
    except KitError as error:
        raise KitError(f"{record['check']}: {error}", error.exit_code) from None
    cases = [line.strip() for line in result.stdout.splitlines() if CASE_LINE.match(line.strip())]
    passed = sum(case.startswith("PASS") for case in cases)
    failed = len(cases) - passed
    problems = []
    if result.returncode != 0:
        problems.append(f"it exited {result.returncode}")
    if failed:
        problems.append(f"{failed} of {len(cases)} cases printed FAIL")
    if passed < KINDS[kind]:
        problems.append(f"it printed {passed} of the {KINDS[kind]} PASS lines a {kind} check needs")
    if problems:
        output = tail(result.stdout) or "(no output)"
        raise KitError(f"{record['check']} did not pass: {'; '.join(problems)}.\n{output}")
    cases = [one_line(case)[:200] for case in cases[:MAX_CASES]]
    return record | {"exit_code": 0, "passed": passed, "failed": 0, "cases": cases, "ts": now()}


def verify(work: Path, args: argparse.Namespace) -> None:
    findings = load_findings(work)
    finding = find(findings, args.id)
    require_not_retracted(finding)
    if args.kind in NEEDS_INPUT and not args.input:
        raise KitError(
            f"a {args.kind} check needs --input with a capture that analysis did not use",
            EXIT_USAGE,
        )
    check_file = check_path(work, args.by)
    inputs = [input_path(work, name) for name in args.input]
    try:
        record = run_check(work, args.kind, check_file, inputs, args.timeout)
    except KitError as error:
        state = finding["confidence"]
        raise KitError(f"{finding['id']} stays {state}. {error}", error.exit_code) from None
    again = finding["confidence"] == "confirmed"
    finding.update(confidence="confirmed", verified_by=record["check"], verification=record)
    finding["ts"] = now()
    require_valid(finding)
    save_findings(work, findings)
    report = f"{finding['id']} confirmed{' again' if again else ''} by {record['check']}"
    report += f": {record['passed']} cases passed"
    emit({"status": "ok", "finding": finding}, report, args.json)


def audit_problems(work: Path, findings: list[dict], rerun: bool = False) -> list[str]:
    """Hold each confirmed finding to its record: same check and inputs, and with rerun, a pass."""
    problems = []
    for finding in findings:
        if finding["confidence"] != "confirmed" or "retracted" in finding:
            continue
        record = finding["verification"]
        found = []
        try:
            check_file = check_path(work, record["check"])
            if sha256_of(check_file) != record["sha256"]:
                found.append(f"{record['check']} changed after it was verified")
            inputs = [input_path(work, item["path"]) for item in record["inputs"]]
            for item, path in zip(record["inputs"], inputs, strict=True):
                if sha256_of(path) != item["sha256"]:
                    found.append(f"{item['path']} changed after it was verified")
            if rerun and not found:
                run_check(work, record["kind"], check_file, inputs, CHECK_TIMEOUT)
        except KitError as error:
            found.append(str(error))
        problems += [f"{finding['id']}: {problem}" for problem in found]
    return problems


def audit(work: Path, args: argparse.Namespace) -> None:
    findings = load_findings(work)
    problems = audit_problems(work, findings, args.rerun)
    if problems:
        raise KitError(
            "these confirmed findings no longer match their checks. Fix the check and run verify "
            "again, or retract the finding:\n" + "\n".join(problems)
        )
    confirmed = [f for f in findings if f["confidence"] == "confirmed" and "retracted" not in f]
    report = f"Checked {len(confirmed)} confirmed finding(s): each matches its check and inputs"
    if args.rerun:
        report += ", and each check passed again"
    emit({"status": "ok", "confirmed": len(confirmed), "rerun": args.rerun}, report, args.json)


def notes_sections(work: Path) -> dict[str, str]:
    """The text under each ## heading of notes.md, without comments. Empty if there is no file."""
    path = work / NOTES
    if not path.is_file():
        return {}
    text = re.sub(r"<!--.*?-->", "", path.read_text(encoding="utf-8"), flags=re.DOTALL)
    sections: dict[str, list[str]] = {}
    current = None
    for line in text.split("\n"):
        if line.startswith("## "):
            current = sections.setdefault(line[3:].strip().lower(), [])
        elif current is not None:
            current.append(line)
    return {name: "\n".join(lines).strip() for name, lines in sections.items()}


def last_entry(log: str) -> str:
    """The newest entry of the session log: the text from its last ### heading on."""
    lines = log.split("\n")
    starts = [index for index, line in enumerate(lines) if line.startswith("### ")]
    entry = lines[starts[-1] :] if starts else lines[-12:]
    return "\n".join(entry[:40]).strip()


def resume(work: Path, args: argparse.Namespace) -> None:
    findings = load_findings(work)
    active = [finding for finding in findings if "retracted" not in finding]
    counts = {level: sum(f["confidence"] == level for f in active) for level in CONFIDENCE}
    counts["retracted"] = len(findings) - len(active)
    still_open = [finding for finding in active if finding["confidence"] != "confirmed"]
    problems = audit_problems(work, findings)
    notes = notes_sections(work)
    hypotheses = "\n".join(notes.get("hypotheses", "").split("\n")[:30]).strip()
    session = last_entry(notes.get("session log", ""))

    lines = [", ".join(f"{count} {level}" for level, count in counts.items())]
    lines += ["", "Open findings:"]
    lines += [
        f"  {f['id']}  {f['confidence']:<9}  {one_line(f['claim'])}  [{one_line(f['location'])}]"
        for f in still_open
    ] or ["  none"]
    lines += ["", "Confirmed findings that no longer match their checks:"]
    lines += [f"  {problem}" for problem in problems] or ["  none"]
    if not notes:
        lines += ["", f"{NOTES} is missing. Start it from templates/notes.md."]
    else:
        lines += ["", "Hypotheses:", hypotheses or "  none recorded"]
        lines += ["", "Last session:", session or "  none recorded"]
    payload = {
        "status": "ok",
        "counts": counts,
        "open": [finding["id"] for finding in still_open],
        "problems": problems,
        "hypotheses": hypotheses,
        "last_session": session,
    }
    emit(payload, "\n".join(lines), args.json)


def add(work: Path, args: argparse.Namespace) -> None:
    findings = load_findings(work)
    finding = {
        "id": next_id(findings),
        "claim": args.claim,
        "location": args.location,
        "evidence": args.evidence,
        "confidence": args.confidence,
        "verified_by": None,
        "verification": None,
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


def retract(work: Path, args: argparse.Namespace) -> None:
    findings = load_findings(work)
    finding = find(findings, args.id)
    if "retracted" in finding:
        raise KitError(f"{finding['id']} is already retracted")
    finding.update(retracted=args.reason, ts=now())
    require_valid(finding)
    save_findings(work, findings)
    emit({"status": "ok", "finding": finding}, f"{finding['id']} retracted", args.json)


def positive(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


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

    command = commands.add_parser(
        "verify", parents=[shared], help="run a check, and mark the finding confirmed if it passes"
    )
    command.add_argument("id")
    command.add_argument(
        "--by",
        required=True,
        help=f"the check: a Python script in {CHECKS}/, such as tests/check_parse_header.py",
    )
    command.add_argument(
        "--kind",
        required=True,
        choices=KINDS,
        help="what the finding is: function and algorithm checks need 3 and 2 passing cases",
    )
    command.add_argument(
        "--input",
        action="append",
        default=[],
        help="a file the check reads, passed to it as an argument and hashed (repeatable)",
    )
    command.add_argument("--timeout", type=positive, default=CHECK_TIMEOUT, help="seconds")
    command.set_defaults(run=verify)

    command = commands.add_parser(
        "audit", parents=[shared], help="test that confirmed findings still match their checks"
    )
    command.add_argument("--rerun", action="store_true", help="also run every check again")
    command.set_defaults(run=audit)

    command = commands.add_parser(
        "resume", parents=[shared], help="where the analysis stands: run this first in a session"
    )
    command.set_defaults(run=resume)

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
