# Reverse Engineering Kit

One free, open-source agent skill for reverse engineering binaries, Android packages, JavaScript
and Electron apps, network protocols and crackmes. It drives standard free tools, and it keeps a
findings ledger where no claim counts as confirmed until a test proves it.

> **Status: pre-release.** The findings ledger and report generator work. The other scripts are
> stubs and exit 1 until they are implemented, and no benchmark has been run yet.

## Planned coverage

| Target | Tools | Release |
| --- | --- | --- |
| Native PE, ELF, Mach-O | Ghidra headless, rizin, LIEF | v1.0 |
| Android APK, AAB, XAPK | jadx, apktool | v1.0 |
| JS bundles, Electron | source maps, webcrack, asar | v1.0 |
| Network protocols | traffic captures, Python `struct`, Kaitai Struct | v1.0 |
| Crackme and CTF | debugger, Frida templates | v1.0 |
| .NET, Java JAR | ilspycmd, CFR or Vineflower | v1.1 |
| Packed Python | pyinstxtractor, pycdc | v1.1 |
| WebAssembly | wabt | v1.2 |
| Firmware | binwalk | v1.2 |

## Repository layout

```
skills/reverse-engineering-kit/   The skill: this folder is what ships
├── SKILL.md                      Router, core loop and evidence rules
├── references/                   Playbooks, read only when routed to them
├── scripts/                      Tools that do the mechanical work
├── templates/                    Report, message dictionary, ledger schema, decoder skeleton
└── examples/                     Walkthroughs taken from real benchmark runs
benchmarks/                       Ten legal test targets and their expected results
tests/                            pytest suite, run in CI
tools/build_zip.py                Builds the marketplace zip
tools/vm/                         Disposable Linux test VM with snapshots
```

## Development

```sh
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
ruff check . && ruff format --check .
pytest
python tools/build_zip.py
```

## Legal

Reverse engineering laws differ by country. In the EU, the Software Directive (2009/24/EC) allows
decompilation for interoperability under certain conditions. You are responsible for your own use.
This is not legal advice.

The kit does not support DRM or license-check bypass, cheats for online games, malware development,
or removing commercial protection for piracy.

## License

[MIT](LICENSE)
