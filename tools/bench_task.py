#!/usr/bin/env python3
"""Stage one benchmark for an agent run: its built targets and the prompt, nothing else.

The prompt says what a user would: which files, what they need, and that they own the targets.
It never quotes `expected` or `target` from expected.json, because those hold the answers.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCHMARKS = REPO_ROOT / "benchmarks"

PROMPT = """\
Reverse engineer {files} in this folder. What I need: {deliverable}.
{note}
I wrote these files myself as test targets, so you are authorized to analyze them and to run them.
You are in a disposable arm64 Ubuntu VM with no internet access, and the analysis tools are
installed. Use the reverse-engineering-kit skill. I cannot answer questions during this run, so
make reasonable assumptions, note them, and finish with the report.
"""


class TaskError(Exception):
    pass


def benchmark_dir(number: str) -> Path:
    matches = sorted(BENCHMARKS.glob(f"{int(number):02d}-*/expected.json"))
    if not matches:
        raise TaskError(f"no benchmark numbered {number}")
    return matches[0].parent


def task_name(artifact: str) -> str:
    """Where a target lands in the task folder: build/resources/app.asar -> resources/app.asar."""
    return artifact.removeprefix("build/")


def prompt_for(entry: dict) -> str:
    names = [task_name(artifact) for artifact in entry["artifacts"]]
    files = names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]
    note = f"{entry['prompt_note']}\n" if entry.get("prompt_note") else ""
    deliverable = entry["deliverable"][0].lower() + entry["deliverable"][1:]
    return PROMPT.format(files=files, deliverable=deliverable, note=note)


def stage(bench: Path, destination: Path) -> None:
    """Copy the built targets to destination/task/ and write destination/prompt.txt."""
    entry = json.loads((bench / "expected.json").read_text("utf-8"))
    for artifact in entry["artifacts"]:
        source = bench / artifact
        if not source.is_file():
            raise TaskError(f"{source} is missing; run tools/vm/vm.sh build-benchmarks")
        target = destination / "task" / task_name(artifact)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    (destination / "prompt.txt").write_text(prompt_for(entry), "utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("number", help="the benchmark number, such as 1 or 01")
    parser.add_argument("destination", type=Path, help="an empty folder")
    args = parser.parse_args()
    try:
        stage(benchmark_dir(args.number), args.destination)
    except TaskError as error:
        print(f"bench_task: {error}", file=sys.stderr)
        return 1
    print(benchmark_dir(args.number).name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
