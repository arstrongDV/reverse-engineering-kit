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

### Changed

- `run_ghidra` and `decompile_apk` are Python instead of shell, so they run on Windows.
