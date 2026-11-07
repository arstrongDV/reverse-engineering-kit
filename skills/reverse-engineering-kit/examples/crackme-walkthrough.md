# Crackme Walkthrough

A real session, shortened. On 2026-11-06, Claude Code with its default model, Sonnet 5.5, ran this
skill on benchmark 1 of the project's test set: an arm64 ELF crackme the project wrote. It ran in
a disposable VM with nothing but the binary and the request below. Commands and outputs are quoted
from the transcript, with the skill's path shortened to `scripts/`, plumbing such as `| head` left
off, and output trimmed where `...` marks it. The paragraphs between them were added afterwards.
The full transcript is in the project repository, under
`benchmarks/runs/20261106-232142-01-crackme-xor/`.

## The request

> Reverse engineer crackme in this folder. What I need: correct serial and an explanation.
>
> I wrote these files myself as test targets, so you are authorized to analyze them and to run
> them. You are in a disposable arm64 Ubuntu VM with no internet access ...

That settles the safety gate: the user owns the target and allows running it in the VM. The agent
recorded it under `## Authorization` in `notes.md`:

```
Target: ./crackme (arm64 ELF), written by the user as a test target. The user authorized analysis
and execution in a disposable VM. Result is the serial plus an explanation. ...
```

## Setup and triage

```
$ python3 scripts/doctor.py --for native
ok      python  3.14.4
ok      ghidra  12.2
ok      java    25.0.4.1
ok      rizin   0.9.1
...
6 of 6 ready

$ python3 scripts/triage.py
...
crackme: ELF 64-bit little-endian shared object or PIE, arm64
  family: native, 70616 bytes
  ...
  imports: 10, libraries: libc.so.6
  strings: 73, notable: 5
    usage: crackme <serial>
    Correct serial. Well done.
    Wrong serial.
    crackme.c
    check_serial
  read next: references/native.md
```

No packer and no anti-debug signal, so the route was the native playbook and, for a crackme,
`references/crackme-ctf.md`.

## Find the check

```
$ python3 scripts/run_ghidra.py
crackme: Executable and Linking Format (ELF), AARCH64:LE:64:v8A
  10 functions, 8 imports, 90 strings
  top functions (by strings and imports used):
    main @ 00100870: 3 strings, imports: puts
    check_serial @ 001007e8: 0 strings, imports: strlen
  ...
  notable strings, and the functions that use them:
    'Correct serial. Well done.': main
    'Wrong serial.': main
```

The success message led to `main`, and `main` passes `argv[1]` to `check_serial`. Ghidra's output
for it:

```c
  sVar4 = strlen(param_1);
  if (sVar4 == 0x10) {
    lVar6 = 0;
    do {
      ...
      bVar3 = *(byte *)((long)&KEY + (long)(int)uVar1) ^ param_1[lVar6];
      if ((&EXPECTED)[lVar6] != (byte)((bVar3 >> 5) + bVar3 * '\b')) {
        return 0;
      }
      lVar6 = lVar6 + 1;
    } while (lVar6 != 0x10);
```

The agent's reading, in its own words: "Per byte: rotl3(KEY[i%4] ^ c) == EXPECTED[i]. I need the
KEY and EXPECTED bytes." `(b >> 5) + b * 8` on a byte is a rotation left by 3.

## Read the tables from the file

```
$ rz-bin -s original/crackme 2>/dev/null | grep -E "KEY|EXPECTED"
 58 0x00000938 0x00000938 LOCAL  OBJ    16     EXPECTED
 59 0x00000948 0x00000948 LOCAL  OBJ     4     KEY

$ xxd -s 0x938 -l 20 original/crackme 2>/dev/null || od -Ax -tx1 -j 0x938 -N 20 original/crackme
00000938: 4044 2945 bbdc c266 6b77 2a8e b087 d1fe  @D)E...fkw*.....
00000948: 5ac3 179e                                Z...
```

The constants came from the binary, not from the decompiler's guess at them.
`python scripts/run_ghidra.py --bytes KEY:4 --bytes EXPECTED:16` gives the same bytes.

## Prove it

The check inverts each step, rotating right by 3 and then XORing with the key, and runs the
unmodified binary on the result and on two inputs that must fail. As the agent wrote it, in
`tests/check_serial.py`:

```python
import subprocess,sys
E_=bytes.fromhex("404429 45bbdcc2666b772a8eb087d1fe".replace(" ",""))
K=bytes.fromhex("5ac3179e")
ror=lambda b:((b>>3)|(b<<5))&255
s=bytes(ror(e)^K[i%4] for i,e in enumerate(E_)).decode()
print("serial",s)
def run(a):
    return subprocess.run(["original/crackme",a],capture_output=True,text=True).stdout
ok=True
for name,a,want in [("derived",s,"Correct"),("wrong",s[:-1]+"!","Wrong"),("short","abc","Wrong")]:
    r=want in run(a); print(("PASS " if r else "FAIL ")+name); ok&=r
sys.exit(0 if ok else 1)
```

```
$ python3 tests/check_serial.py
serial RK26-XOR7-ROL3-A
PASS derived
PASS wrong
PASS short

$ python3 scripts/ledger.py add \
    --claim "Valid serial is RK26-XOR7-ROL3-A: 16 chars, each byte c satisfies rotl3(c ^ KEY[i%4]) == EXPECTED[i]" \
    --location "check_serial @ 0x1007e8; EXPECTED @ 0x938, KEY @ 0x948" \
    --evidence "Ghidra decompile; inverted table in tests/check_serial.py" \
    --confidence inferred --hypothesis H1
F-001 added (inferred)

$ python3 scripts/ledger.py verify F-001 --kind algorithm --by tests/check_serial.py
F-001 confirmed by tests/check_serial.py: 3 cases passed
```

## Report

After `## Summary` and `## Gaps` were filled in, `make_report.py` wrote `REPORT.md`. Its "a
algorithm check" is a bug this run found, fixed since.

```
...

## Summary

Serial is `RK26-XOR7-ROL3-A`. check_serial requires length 16, and each byte c must satisfy
rotl3(c ^ KEY[i%4]) == EXPECTED[i]. Inverting that per byte gives the serial, and the binary
accepts it.

## Confirmed findings

- **F-001** Valid serial is RK26-XOR7-ROL3-A: 16 chars, each byte c satisfies rotl3(c ^ KEY[i%4]) == EXPECTED[i]
  - Location: check_serial @ 0x1007e8; EXPECTED @ 0x938, KEY @ 0x948
  - Evidence: Ghidra decompile; inverted table in tests/check_serial.py
  - Verified by: tests/check_serial.py, a algorithm check: 3 cases passed, none failed

## Gaps and next experiments

None. The serial is unique, since each step is a bijection per position.
```

The whole session took 43 seconds and 12 turns.

## What to take from it

- **Strings lead to the check.** The success message named the function that prints it, and that
  function's callee with `argv[1]` was the check.
- **Constants come from the file.** Read tables at their symbols or offsets. Decompiled code shows
  where a table is, not what it holds.
- **The proof runs the real program.** The check derives the answer, then lets the unmodified
  binary judge it, together with two inputs that must fail. A model that only agrees with itself
  proves nothing.
- **The answer lives in the ledger.** The claim records where it came from and what supports it,
  and `confirmed` comes from `verify`, which stored the check's SHA-256 and its cases.

## Where it fell short of the skill

- **It wrote a file into `original/`.** The agent saved the binary's hash as `original/SHA256`, so
  triage reported a second target and the report listed two hashes. `original/` holds the target
  and nothing else, since `make_report.py` records the hashes itself.
- **It computed the answer before recording the hypothesis.** `crackme-ctf.md` asks for the
  hypothesis as an `inferred` finding first, so the ledger shows what was believed before it was
  tested.
- **`--kind function` fits this check better.** The check compares the program's verdict on three
  inputs, including ones that must fail. That is the `function` row of SKILL.md's table, which
  requires three `PASS` lines. `algorithm` requires only two.
