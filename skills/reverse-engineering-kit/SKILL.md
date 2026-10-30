---
name: reverse-engineering-kit
description: "Evidence-first reverse engineering of software the user owns or is authorized to analyze: native PE, ELF and Mach-O binaries, Android APK, AAB and XAPK packages, minified JS bundles, Electron apps, network protocols and crackme or CTF challenges. Drives Ghidra, rizin, jadx, apktool, webcrack and Frida, and keeps a findings ledger where no claim counts as confirmed until a test proves it. Use when the user asks to reverse engineer a binary, decompile or disassemble an executable, analyze an APK, recover source from minified JS or an Electron app, decode a network protocol or file format, or solve a crackme."
license: MIT
compatibility: Requires Python 3.10+. Analysis tools are optional per target and are checked by scripts/doctor.py.
metadata:
  author: Arsen Datsenko
  version: "0.1.0"
---

# Reverse Engineering Kit

**Status: scaffold.** Scripts named below are stubs that exit 1 until their build phase lands.
Keep this file under 500 lines; deep detail belongs in `references/`.

## 1. Safety gate

Before any work, establish what the target is, who owns it, what permits the analysis and what
the result is for. Record the answers in `notes.md`.

- Refuse: bypassing DRM or license checks, cheats for online games, writing malware, and attacks
  on systems the user neither owns nor has permission to test.
- Unknown or suspicious samples: static analysis only by default. Dynamic analysis only inside a
  VM the user has confirmed.
- Work on copies, hash the original, and redact tokens, passwords and personal data from reports.

Full policy: [references/legal-safety.md](references/legal-safety.md).

## 2. Setup

1. Run `scripts/doctor.py` and tell the user about missing tools. It never installs anything.
2. Create the work directory, copy the target into `original/` and record its SHA-256:

```
re-work/<target-name>/
├── original/         # untouched copy + SHA-256
├── triage.json
├── decompiled/       # tool output
├── findings.jsonl    # evidence ledger
├── notes.md          # session notes for resuming work
└── REPORT.md
```

## 3. Triage

Run `scripts/triage.py`, then write a two-sentence first impression before going deeper.

## 4. Route

| Triage result | Read next |
| --- | --- |
| PE, ELF or Mach-O | [references/native.md](references/native.md) |
| APK, AAB or XAPK | [references/android.md](references/android.md) |
| JS bundle or Electron app | [references/js-electron.md](references/js-electron.md) |
| Traffic capture or unknown data format | [references/protocols.md](references/protocols.md) |
| Crackme or CTF challenge | [references/crackme-ctf.md](references/crackme-ctf.md) |
| Packer, anti-debug or obfuscation signs | [references/anti-analysis.md](references/anti-analysis.md) |
| About to rely on decompiler output | [references/decompiler-lies.md](references/decompiler-lies.md) |
| A decompiler MCP server is available | [references/mcp-setup.md](references/mcp-setup.md) |

## 5. Analysis loop

State a hypothesis, run the cheapest test that could disprove it, record the result with
`scripts/ledger.py`, and repeat.

Confidence moves one way: `unknown` → `inferred` → `observed` → `confirmed`.
Ledger format: [templates/findings.schema.json](templates/findings.schema.json).

## 6. Prove it

Only `scripts/ledger.py verify` can set `confirmed`, and it needs a recorded check:

| Artifact | Required check before `confirmed` |
| --- | --- |
| Recovered function | Same output as the original on at least 3 inputs (differential test) |
| Protocol decoder | Parses a capture not used during analysis, without errors |
| Recovered algorithm or key | Matches on 2 independent input/output pairs |
| API endpoint | Seen in traffic, or in a call with a literal URL |
| Behavior claim | Decompiled logic plus one independent signal (string, import, runtime) |

## 7. Report

Run `scripts/make_report.py` to produce `REPORT.md` from
[templates/report.md](templates/report.md). List every gap together with the next experiment
that would close it. Protocol work also fills in
[templates/message-dictionary.md](templates/message-dictionary.md) and starts its decoder from
[templates/protocol_decoder.py](templates/protocol_decoder.py).

## 8. Resuming

In a new session, read `notes.md` and `findings.jsonl` before doing anything else.

Worked examples: [examples/crackme-walkthrough.md](examples/crackme-walkthrough.md),
[examples/protocol-walkthrough.md](examples/protocol-walkthrough.md).
