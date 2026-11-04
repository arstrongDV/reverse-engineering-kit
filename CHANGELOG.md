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

### Changed

- `run_ghidra` and `decompile_apk` are Python instead of shell, so they run on Windows.
- `vm.sh snapshot` replaces an existing snapshot of the same name instead of failing.
