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

An agent must only see the built target. `src/` and `expected.json` contain the answers, so copy
the target into an empty directory outside this repo and run the agent there.

## Scoring

- **Pass or fail:** the run's output matches `expected.json`.
- **False confirmations:** count findings marked `confirmed` that are actually wrong. The goal is 0.

Record every run in [RESULTS.md](RESULTS.md). The release bar is at least 8 of 10 solved.
