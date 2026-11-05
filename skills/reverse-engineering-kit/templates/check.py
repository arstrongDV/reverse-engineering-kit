#!/usr/bin/env python3
"""Template for the check that ledger.py verify runs. Copy it to tests/ in the work directory.

verify runs this script with the work directory as the current directory, and passes each
--input file as an argument. It counts the lines that start with PASS or FAIL, and confirms the
finding only when the script exits 0, prints no FAIL, and prints enough PASS lines:

    function   3   the recovered function and the original agree on at least 3 inputs
    algorithm  2   the recovered algorithm or key reproduces 2 independent input/output pairs
    decoder    1   the decoder parses a capture that analysis never used (given with --input)
    endpoint   1   the endpoint appears in traffic, or in a call with a literal URL
    behavior   1   an independent signal agrees with the decompiled logic

This copy is a differential test of a recovered function: it runs the unmodified program and
the Python model on the same inputs and compares them. Running the program means running the
target, so this check, and verify with it, run inside the VM the user confirmed.
"""

from __future__ import annotations

import subprocess
import sys

TARGET = "original/target"
# Include inputs that must fail, not only the answer: a model that agrees on one lucky input
# can still be wrong. Pass arguments as a list, so no shell rewrites $, ! or quotes.
CASES = [
    ["first input"],
    ["second input"],
    ["an input that must be rejected"],
]
TIMEOUT = 30


def original(arguments: list[str]) -> object:
    """What the unmodified program does. Compare whatever the claim is about."""
    result = subprocess.run(
        [TARGET, *arguments], capture_output=True, timeout=TIMEOUT, stdin=subprocess.DEVNULL
    )
    return result.returncode


def model(arguments: list[str]) -> object:
    """What your reading says it does, written in Python with explicit masking such as & 0xFF."""
    raise NotImplementedError("write the recovered logic here")


def main() -> int:
    failures = 0
    for arguments in CASES:
        try:
            expected, actual = original(arguments), model(arguments)
        except Exception as error:  # A crash is a failed case, not a pass.
            print(f"FAIL {arguments!r}: {type(error).__name__}: {error}")
            failures += 1
            continue
        verdict = "PASS" if expected == actual else "FAIL"
        failures += verdict == "FAIL"
        print(f"{verdict} {arguments!r}: program {expected!r}, model {actual!r}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
