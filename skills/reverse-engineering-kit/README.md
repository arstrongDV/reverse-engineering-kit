# Reverse Engineering Kit

A free, MIT-licensed skill for evidence-first reverse engineering of software you own or are
authorized to analyze.

**Status: pre-release scaffold.** The scripts are stubs and exit 1 until they are implemented.

## Using it

Ask your agent to reverse engineer a target. The skill checks your tools, triages the file, routes
to the right playbook, and records every claim in a findings ledger.

Run `python scripts/doctor.py` to see which tools you have. It prints install commands and never
installs anything itself.

## Safety

The scripts never run a target, download anything, or change the original file, and they only
write inside `re-work/<target>/`.

The skill refuses DRM and license-check bypass, cheats for online games, malware development, and
attacks on systems you do not own or have permission to test.
