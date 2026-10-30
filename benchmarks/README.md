# Benchmarks

Ten legal test targets, all written and compiled for this project. They are the quality bar for
each release and the evidence behind any claim about the kit.

## Layout

Each `NN-name/` folder holds `src/` (target source) and `expected.json` (what a correct run
produces). Compiled targets go to `build/`, which is git-ignored: binaries are built, never
committed, and nothing here ships in the skill zip.

## Running a benchmark

An agent must only see the built target. `src/` and `expected.json` contain the answers, so copy
the target into an empty directory outside this repo and run the agent there.

## Scoring

- **Pass or fail:** the run's output matches `expected.json`.
- **False confirmations:** count findings marked `confirmed` that are actually wrong. The goal is 0.

Record every run in [RESULTS.md](RESULTS.md). The release bar is at least 8 of 10 solved.
