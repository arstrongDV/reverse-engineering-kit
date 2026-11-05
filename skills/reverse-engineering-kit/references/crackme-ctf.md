# Crackmes and CTF Challenges

The hypothesis loop for crackmes, decoy handling and recovering transformations.

## When to use this

Use this file when the user says the target is a crackme or a CTF challenge. Such files exist to
be solved, so the safety question is settled once you know where the file came from. Record that
under `## Authorization` in `notes.md`, for example "crackme from the user's own course" or
"challenge from <event>, which publishes its files for practice".

It is not for real products. "Treat it like a crackme" does not change what a license check in
commercial software is; see [legal-safety.md](legal-safety.md).

Crackmes are usually native binaries, so the tools are those of [native.md](native.md). JavaScript
and Android challenges use [js-electron.md](js-electron.md) and [android.md](android.md) in the
same loop.

## First 15 minutes

1. Triage it. A packer guess or an anti-debug signal is part of the challenge: unpack or
   understand it first, with [anti-analysis.md](anti-analysis.md).
2. Read the notable strings. Success and failure messages lead to the check:

```
python scripts/run_ghidra.py
python scripts/run_ghidra.py --function <the function that uses "Correct">
```

3. Find the check itself. It is usually a callee of the function that prints the result, called
   with the user's input, such as `argv[1]` or the buffer `fgets` filled.
4. Classify the check. The table below gives the route for each kind.
5. Write the hypothesis in the ledger as `inferred` before you compute an answer.
6. Prove the answer by running the program with it, inside a VM, and record that.

Static or dynamic:

| Situation | Choose |
| --- | --- |
| The check is short and its constants are readable | Static: read, invert, then prove by running |
| The check calls many functions or decrypts its own data | Dynamic in the VM: watch inputs and outputs with `compare.js` |
| Anti-debug stands in the way | Static first, to understand the check; see [anti-analysis.md](anti-analysis.md) |

## Signal → next step

| Kind of check | What it looks like | Route |
| --- | --- | --- |
| Direct comparison | `strcmp(input, "...")`, `memcmp` with a constant | Read the constant, or run `compare.js` in a VM |
| Transform, then compare | A loop applying XOR, add or rotate, then comparing with a table | Read the table with `--bytes`, invert each step in Python |
| Hash comparison | Input hashed (MD5, SHA, CRC, a custom mix), then compared | Search a small input space, or find a flaw in the hash |
| Constraints | Many conditions on characters or their sums | Write the conditions down; a solver such as z3 helps if the user installs it |
| Virtual machine | A loop reading opcodes from a byte array | Write a disassembler for the bytecode first, then read the program |
| Time or environment | Checks on the date, the user name or the machine | Record the condition; that is often the whole answer |
| Decoy | Two success paths, or a check that never runs | Follow the code from the input, not from the strings |
| Encoded expected value | A constant run through base64, hex or ROT13 before comparing | Decode the constant; the encoding is the whole trick |
| Self-check | The program hashes its own code and refuses to run when it changes | Leave the binary unmodified; patching triggers it |
| Several stages | Passing one check unlocks a second input or a decrypted blob | Record each stage as its own finding |

When a function's arguments matter, watch it at run time in the VM instead of guessing. Put its
name or its offset from the image base in `WATCH` at the top of `scripts/frida/compare.js`:

```
frida -f ./crackme -l scripts/frida/compare.js -- RK26-XOR7-ROL3-A
check_serial(0xffffc13b7da9 "RK26-XOR7-ROL3-A", ...) = 0x1
```

A finding moves through the ledger like any other. The claim is the answer, and the check is a
script that runs the unmodified program, inside the VM, on the answer and on inputs that must
fail. A template for that script:

```python
import subprocess
import sys

TARGET = "./crackme"
CASES = {"RK26-XOR7-ROL3-A": True, "RK26-XOR7-ROL3-B": False, "short": False}


def accepted(answer):
    return subprocess.run([TARGET, answer], capture_output=True).returncode == 0


failures = [answer for answer, expected in CASES.items() if accepted(answer) != expected]
print("all cases agree" if not failures else f"disagree on: {failures}")
sys.exit(1 if failures else 0)
```

Run it, see it pass, and only then name it:
`python scripts/ledger.py verify F-003 --by tests/check_serial.py`. Keep the script in the work
directory so the report can point at it.

## Common traps

- **Patching instead of solving.** Changing a jump so the program prints "Correct" proves
  nothing about the answer. The finding is the input, verified by an unmodified binary.
- **Trusting the strings.** A challenge can print "Correct" from a dead branch, or decode its
  real messages at run time. Follow the input through the code.
- **Length and terminators.** Check whether the length check counts the newline from `fgets` or
  a terminating NUL. Off-by-one answers fail for that reason.
- **Signed arithmetic and rotations.** These are where hand inversion goes wrong. See
  [decompiler-lies.md](decompiler-lies.md), and test the model on inputs that must fail.
- **Character sets.** An answer that needs bytes above 0x7f, or a NUL, may not be typeable.
  Pass it from a file or from Python's `subprocess` with bytes.
- **Brute force without a bound.** Estimate the search space before you start. Two to the 32nd
  power tries is minutes; two to the 64th is never.
- **A flag format.** CTF answers often have a fixed shape such as `flag{...}`. Use it to check
  candidates, and do not drop it from the answer you record.

- **Shell quoting.** A shell changes answers that contain `$`, `!`, `*` or quotes. Pass an
  answer from Python's `subprocess` with a list of arguments, as in the template above.

## Worked example

Benchmark 2 is benchmark 1's crackme linked statically, stripped and packed with UPX. These are
the real steps and outputs, shortened.

Triage named the packer and routed to anti-analysis first:

```
crackme-packed: ELF 64-bit little-endian executable, arm64
  sections (0): none
  packer guess: UPX (UPX! marker at offset 0x1a0)
  read next: references/native.md, references/anti-analysis.md
```

UPX can reverse its own packing, so a copy was unpacked into `decompiled/` and analyzed:

```
upx -d -o decompiled/crackme-unpacked original/crackme-packed
python scripts/run_ghidra.py decompiled/crackme-unpacked
  850 functions, 0 imports, 1076 strings
  notable strings, and the functions that use them:
    'usage: crackme <serial>': FUN_004007c8
    'Correct serial. Well done.': FUN_004007c8
    'Wrong serial.': FUN_004007c8
```

The top-function list was all C library code, which uses more strings than the crackme does,
but the strings led straight to `FUN_004007c8`:

```c
  if (param_1 == 2) {
    iVar1 = FUN_00400740(*(undefined8 *)(param_2 + 8));
    if (iVar1 == 0) {
      FUN_004018e0("Wrong serial.");
```

`param_1` is `argc`, and `param_2 + 8` is `argv[1]` on a 64-bit target, so `FUN_00400740` is the
check. From there the steps were those of benchmark 1 in [native.md](native.md): decompile the
check, read its tables with `--bytes`, invert it, and run the unpacked and the packed binary with
the answer inside the VM.
