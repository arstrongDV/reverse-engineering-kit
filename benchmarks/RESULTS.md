# Benchmark Results

No benchmark has been run yet.

## Method

- **Agent:** Claude Code 2.1.296 in the test VM, started by `tools/vm/vm.sh run-benchmark`. The
  model is whatever Claude Code picks by default, and each run records it. The plan called for a
  second agent as well, such as Codex CLI or Cursor. v1.0 is tested with Claude Code only, because
  no second agent is available to the project.
- **Skill:** the blind copy from `tools/build_zip.py --blind`. It is the release zip without the
  worked examples, which describe these benchmarks and quote their answers. Users get the
  examples, so the shipped skill has more guidance than the one tested here, not less.
- **Isolation:** the agent sees only the built target and a prompt naming the deliverable. It runs
  as a user without `sudo`, can reach Anthropic's API and nothing else, and has WebSearch and
  WebFetch turned off. See [tools/vm/README.md](../tools/vm/README.md#benchmark-runs).
- **Scoring:** a run passes when its output matches `expected.json`. A false confirmation is a
  finding marked `confirmed` that is wrong. `tools/score_run.py` summarizes each run, and the
  verdict and its reason are written here.

## Results

| # | Target | Result | False `confirmed` findings | Run |
| --- | --- | --- | --- | --- |
| 1 | Crackme with an XOR and shift serial check (C, ELF) | not run | not run | |
| 2 | The same crackme, stripped and packed with UPX | not run | not run | |
| 3 | Benign Windows PE telemetry agent | not run | not run | |
| 4 | Toy TCP protocol and 2 pcap files | not run | not run | |
| 5 | Android APK with hidden API endpoints | not run | not run | |
| 6 | Webpack bundle without a source map | not run | not run | |
| 7 | Electron app packaged with asar | not run | not run | |
| 8 | Binary with an anti-debug check | not run | not run | |
| 9 | Custom file format and 3 samples | not run | not run | |
| 10 | Obfuscated JS (string array and flattened control flow) | not run | not run | |
