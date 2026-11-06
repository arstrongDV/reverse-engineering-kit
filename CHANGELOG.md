# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project scaffold: skill folder, script stubs, reference outlines, benchmark layout, CI and the
  marketplace zip builder.
- Disposable Linux test VM with snapshots, blocked from the network by default.
- VM tool installer with pinned versions, and working tests for each tool that run offline.
- Findings ledger: `ledger.py` adds, lists, updates, verifies and retracts findings. Only `verify`
  can set `confirmed`, and a confirmed finding cannot be edited.
- `make_report.py` renders `REPORT.md`, and refuses to run without an authorization record.
- `references/legal-safety.md` and the `notes.md` template.
- `doctor.py` checks each tool by running it, prints a pinned install hint for this OS, and reports
  Ghidra as broken when it has no decompiler for this machine.
- `triage.py` identifies 38 file types by content, with hashes, entropy, sections, imports,
  exports, strings, a packer guess and anti-debug or obfuscation signals. LIEF runs in a child
  process, so if it crashes or hangs on a damaged binary, triage keeps a warning and goes on.
- A routing table in `SKILL.md` that matches what `triage.py` reports, kept in step by a test.
- Source, answers and a VM build script for all 10 benchmarks.
- LIEF, UPX, the Kaitai Struct compiler, webcrack and asar in the test VM.
- `run_ghidra.py` runs Ghidra headless and exports functions, imports with their callers, strings
  with their users, and decompiled C, one file per function. Later runs reuse the analysis, and
  `--function` and `--bytes` ask for more.
- `decompile_apk.py` runs jadx and apktool and summarizes the manifest: exported components,
  permissions, deep links, the network security config and frameworks. It unpacks XAPK files,
  because jadx writes no code for them.
- `recover_js.py` recovers sources from source maps, runs webcrack, extracts asar archives with
  path checks, and maps an Electron app's IPC channels and risky settings. It never fetches a
  remote source map.
- `find_endpoints.py` lists URLs, API paths, HTTP calls, auth headers and secrets with file and
  line. Secrets are always masked, and library code is counted separately.
- A working pcap and pcapng decoder template, and Frida 17 hook templates for comparisons,
  crypto, network and certificate pinning. The pinning template only observes.
- The native, Android, JS and Electron, protocol, crackme, anti-analysis and decompiler-error
  references.
- `ledger.py audit` checks that each confirmed finding still matches the check and inputs that
  proved it, and `--rerun` runs every check again.
- `ledger.py resume` prints where an analysis stands: findings by confidence, open findings,
  stale confirmations, the hypotheses and the last session log entry.
- `templates/check.py`, a differential test in the form `verify` runs, and `## Hypotheses`
  and dated session log entries in the `notes.md` template.
- `references/mcp-setup.md`, with GhidraMCP 2.0 headless and r2mcp 1.9.0 setups tested in the
  VM, and `vm.sh check-mcp`, which repeats those tests.
- `build_zip.py --blind` builds the copy of the skill that benchmark runs load: the release zip
  without the worked examples, which quote the benchmark answers. Each `expected.json` lists
  `answer_markers`, and tests check that none of them reaches that copy or any prompt.
- `vm.sh install-agent` and `vm.sh run-benchmark`, which run Claude Code on one benchmark in the
  VM as a user without `sudo`, with only Anthropic's API reachable and the web tools turned off,
  and `tools/score_run.py`, which summarizes a run for scoring.

### Changed

- `run_ghidra` and `decompile_apk` are Python instead of shell, so they run on Windows.
- `vm.sh snapshot` replaces an existing snapshot of the same name instead of failing.
- The Ghidra export is a Java script instead of Python. Ghidra compiles Java itself, while Python
  scripts need PyGhidra, whose bundled packages stop at Python 3.13.
- Analysis tools are started through one runner that kills their whole process tree on timeout,
  gives them a copy of the target under a plain name, and refuses arguments that `cmd.exe` would
  read as commands.
- `ledger.py verify` runs the check it is given, a Python script in the work directory's
  `tests/`, and confirms the finding only if the check passes with enough cases for the claim's
  `--kind`. The finding stores the result and the SHA-256 of the check and its inputs, and
  `make_report.py` refuses a confirmed finding whose check or input has changed. Before, `--by`
  accepted any text without running anything.
- The skill's generic examples use made-up names such as `check_flag` and `parse_header`
  instead of benchmark 1's, and no longer name a benchmark outside the worked examples.
- `SKILL.md` says which steps every analysis needs, however small: the authorization record,
  a finding for each answer, `verify` for each answer that can be checked, and `make_report.py`.
  The first run of benchmark 1 found the right answer but skipped all four.

### Fixed

- `make_report.py` wrote "a algorithm check" and "a endpoint check".
- `SKILL.md` asked for the target's SHA-256 to be recorded without saying where, so an agent saved
  it as a file in `original/`, which the report then hashed as a second target. It now says to
  keep nothing else there, since `make_report.py` records the hashes.
