# Benchmarks

Ten legal test targets, all written and compiled for this project. They are the quality bar for
each release and the evidence behind any claim about the kit.

## Layout

Each `NN-name/` folder holds `src/` (target source) and `expected.json`: the files to hand over
(`artifacts`), what `triage.py` must report (`triage`), and what a correct run produces
(`expected`). Compiled targets go to `build/`, which is git-ignored: binaries are built, never
committed, and nothing here ships in the skill zip.

## Building

```sh
tools/vm/vm.sh build-benchmarks     # about 5 minutes, with the lid open
tools/vm/vm.sh restore tools        # removes the compilers from the VM again
```

This builds every target inside the Linux VM, including the Windows PE and the Android APK, and
copies them to `benchmarks/*/build/`. Each build checks its own result where it can: the crackmes
accept only the right serial, the obfuscated script prints the same output as the original, and
the samples parse with the Kaitai spec. Benchmarks 1, 2 and 8 are arm64 Linux files, so run them
only in the VM.

## Running a benchmark

An agent must only see the built target. `src/` and `expected.json` contain the answers, and so do
the skill's worked examples, which describe these benchmarks. `tools/vm/vm.sh run-benchmark <n>`
runs Claude Code in the VM with only the built target, a prompt that names the deliverable, and
the blind copy of the skill, which leaves the worked examples out. See
[tools/vm/README.md](../tools/vm/README.md#benchmark-runs) for the setup and what keeps a run
blind.

Each `expected.json` lists `answer_markers`: strings from the answer that only a solved run would
know. Tests check that none of them appears in the blind copy or in any prompt.

## Scoring

- **Pass or fail:** the run's output matches `expected.json`.
- **False confirmations:** count findings marked `confirmed` that are actually wrong. The goal is 0.

`python3 tools/score_run.py dist/runs/<run>` gathers what the judgment needs: how the run ended,
whether the skill was loaded, each finding with its confidence, the check behind each confirmed
one, and which answer markers the agent stated in its own report, notes and findings. Pass or fail
is still judged against `expected.json`, because the answers are free text.

Record every run in [RESULTS.md](RESULTS.md). The release bar is at least 8 of 10 solved.
