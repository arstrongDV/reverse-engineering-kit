# Benchmark Results

**9 of 10 solved, and 0 false `confirmed` findings among the 20 the runs confirmed.** The release
bar is at least 8 of 10 and 0 false confirmations. All runs were on 2026-11-06.

## Method

- **Agent:** Claude Code 2.1.296 in the test VM, started by `tools/vm/vm.sh run-benchmark`, with
  its default model, which was `claude-sonnet-5-5` in every run. The plan called for a second
  agent as well, such as Codex CLI or Cursor. v1.0 is tested with Claude Code only, because no
  second agent is available to the project.
- **Skill:** the blind copy from `tools/build_zip.py --blind`. It is the release zip without the
  worked examples, which describe these benchmarks and quote their answers. Users get the
  examples, so the shipped skill has more guidance than the one tested here, not less.
- **Isolation:** the agent sees only the built target and a prompt naming the deliverable. It runs
  as a user without `sudo`, can reach Anthropic's API and nothing else, and has WebSearch and
  WebFetch turned off. See [tools/vm/README.md](../tools/vm/README.md#benchmark-runs).
- **Scoring:** a run passes when its output matches `expected.json`. A false confirmation is a
  finding marked `confirmed` that is wrong. Each confirmed finding below was checked against the
  benchmark's source. `tools/score_run.py` summarizes each run, and the verdict and its reason
  are written here.
- **Evidence:** each run's transcript, prompt, and the notes, findings, checks and report the agent
  wrote are in [runs/](runs/). Tool output and copies of the targets are left out.

## Results

| # | Target | Result | Confirmed (false) | Run |
| --- | --- | --- | --- | --- |
| 1 | Crackme with an XOR and shift serial check (C, ELF) | Solved | 1 (0) | [232142](runs/20261106-232142-01-crackme-xor) |
| 2 | The same crackme, stripped and packed with UPX | Solved | 1 (0) | [232640](runs/20261106-232640-02-crackme-upx) |
| 3 | Benign Windows PE telemetry agent | Solved | 2 (0) | [232824](runs/20261106-232824-03-telemetry-pe) |
| 4 | Toy TCP protocol and 2 pcap files | **Not solved** | 2 (0) | [233003](runs/20261106-233003-04-toy-tcp-protocol) |
| 5 | Android APK with hidden API endpoints | Solved | 5 (0) | [233111](runs/20261106-233111-05-android-hidden-api) |
| 6 | Webpack bundle without a source map | Solved | 3 (0) | [233227](runs/20261106-233227-06-webpack-bundle) |
| 7 | Electron app packaged with asar | Solved | 2 (0) | [233330](runs/20261106-233330-07-electron-asar) |
| 8 | Binary with an anti-debug check | Solved | 1 (0) | [233457](runs/20261106-233457-08-anti-debug) |
| 9 | Custom file format and 3 samples | Solved | 1 (0) | [233647](runs/20261106-233647-09-custom-file-format) |
| 10 | Obfuscated JS (string array and flattened control flow) | Solved | 2 (0) | [233750](runs/20261106-233750-10-obfuscated-js) |

Each run took 30 to 90 seconds and 10 to 15 turns. The ten counted runs cost $1.44 in total, at
API prices, as Claude Code reported it.

## Notes on each run

1. The serial, the 4-byte key, the XOR-then-rotate algorithm and the function. The check runs the
   unmodified binary on the derived serial, a changed one and a short one.
2. The packer, unpacking with `upx -d`, and the same serial, checked against the packed binary.
3. The registry key and both values with their defaults, read-only access, one TCP connection to
   127.0.0.1:47800, the frame layout and the rotate-and-XOR checksum. The run named the sequence
   field's position and size but not its meaning. The PE was not run: the VM cannot run Windows
   code, and the report says so.
4. The framing, the CRC, every message type and the XOR 0x5C response are correct, and the decoder
   handles split and shared TCP segments. It is not solved because the decoder had to parse a
   capture not used during analysis. Its first version parsed every frame of the held-back
   capture but stopped on a message type and a flag bit that only that capture contains. The agent
   then studied those frames and fixed the decoder, and its report says that this made the test
   no longer independent. See the open issue below.
5. The XOR-hidden base URL, all three endpoints, the hidden `/internal/diag` and the `debug_menu`
   setting that enables it, and the auth flow. The app key's value is left out of the report on
   purpose: the skill's safety rules redact keys and tokens.
6. The five modules, the base URL, all three API calls, the bearer auth and the `X-Client` header,
   and a recovered API client that a check runs against the original module.
7. All six packed files, the five IPC channels with their direction, and the `window.notes`
   bridge.
8. Both stacked checks, TracerPid and `ptrace`, the decoy path and the launch code decoded with
   XOR 0x2a. The `ptrace` branch stays `inferred`, since the run could not test it on its own.
9. A Kaitai spec that parses all three samples, checked value by value and against each CRC.
10. Readable code with the endpoint, the salt and all three functions, checked against the
    original obfuscated file on three inputs.

## Open issue: benchmark 4's held-back capture

The held-back capture contains message type 6 and a flag bit that the analysis capture does not,
yet `expected.json` lists type 6 in the dictionary. A blind run cannot know it, so the answer key
is partly impossible. The first decoder failed on that capture, although it had framed it
correctly, because of two rules the run wrote into the template's `check()` hook: an unnamed type
is a problem, and so is a nonzero flag. The template itself accepts every frame by default. Both
the benchmark and the template are left as they are for v1.0.
[examples/protocol-walkthrough.md](../skills/reverse-engineering-kit/examples/protocol-walkthrough.md)
walks through this run.

## Earlier runs

| Run | Skill | Result | Why it does not count |
| --- | --- | --- | --- |
| [231407](runs/20261106-231407-01-crackme-xor), benchmark 1 | `96c2025` | The right serial, verified by hand | It skipped the authorization record, the ledger, `verify` and the report, because `SKILL.md` described them without requiring them. `96a0c71` requires them. |

Skill versions: benchmark 1 counted at `96a0c71`. Benchmarks 2 to 10 ran at `1cac489`, which also
fixes two report bugs that the counted benchmark 1 run found.
