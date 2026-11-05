# Anti-Analysis Techniques

Recognizing and documenting packers, anti-debug checks and obfuscation.

## When to use this

Use this file when `triage.json` sets `packer`, or lists a signal such as `anti-debug`,
`obfuscated-js` or `high-entropy`. Triage adds this file to `read_next` in those cases.

The goal is to understand and document the technique, so that the rest of the analysis can go
on. That is in scope for software the user owns or may analyze, for crackmes and CTF challenges,
and for defensive study of samples. Removing commercial protection so software can be used
without paying, or defeating anti-cheat, stays refused whatever the reason given; see
[legal-safety.md](legal-safety.md).

| Technique | Usual signs in triage or Ghidra |
| --- | --- |
| Packer | `packer` set, few or no imports, no section headers, entropy near 8 |
| Anti-debug | Imports `ptrace`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`; the string `TracerPid` |
| Timing check | Two time reads around a block, then a comparison of the difference |
| VM or sandbox detection | Strings naming hypervisors, MAC address prefixes, registry keys of guest tools |
| String encryption | Few readable strings, a decoder function called before each use |
| JS obfuscation | `obfuscated-js`: many `_0x` names, a string array, a loop around a `switch` |
| Control-flow flattening | One dispatcher loop with a `switch` on a state variable |

## First 15 minutes

1. Name the technique from the evidence, and record it in the ledger as `inferred`, with the
   evidence triage gave. A packer guess is a guess until unpacking works.
2. Decide whether to stay static. Unknown or suspicious samples stay static until the sandbox
   checklist in [legal-safety.md](legal-safety.md) is complete.
3. Unpack or decode on a copy in `decompiled/`. Never change `original/`.
4. Triage the result again, and continue with the playbook for its type.
5. Record each check you find as a finding of its own: what it tests, what the program does when
   it fires, and where it is.

Write each check down the same way, so the report can list them side by side:

| Field | Example |
| --- | --- |
| What it tests | Whether `TracerPid` in `/proc/self/status` is not 0 |
| Where | `main @ 00100b28`, the loop calling `strncmp` |
| What happens when it fires | Prints a decoy line and exits 0 |
| Evidence | Decompiled `main`, plus triage's `TracerPid` string |

Before trusting an unpacked copy:

- Triage it again. It should name a type, have sections, and show no packer.
- Its imports and strings should make sense for the program, not only for a stub.
- It should run the same way as the packed file, inside the VM, on the same input.
- Keep the command that produced it in the session log, so it can be repeated.

Obfuscated native code has its own signs:

- **Opaque predicates.** Conditions that always come out the same way, such as
  `x * (x + 1) % 2 == 0`, guard branches that never run. Prove one constant with a few values,
  then ignore the dead branch.
- **Junk code.** Instructions whose results are never used, placed to slow reading. Follow the
  values that reach a call or a comparison.
- **Indirect jumps.** Jumps through computed addresses hide the control flow from the
  decompiler. Record the table they read from, and resolve it by hand or at run time.

## Signal → next step

| Signal | Next step |
| --- | --- |
| `UPX`, by section names or the `UPX!` marker | `upx -d -o decompiled/<name> original/<name>`, then triage the copy |
| UPX, but `upx -d` reports the file is not packed | The headers were altered. Note it; unpack dynamically only in a VM |
| Another packer name, or `unknown` from entropy | Static: find the unpacking stub's end. Dynamic, in a VM: dump memory after it runs |
| `PyInstaller` | A bundled Python program. Extraction tools for it arrive in a later version |
| `ptrace(PTRACE_TRACEME)` | The program refuses a second tracer. Read what it does on failure |
| A `TracerPid` string with `/proc/self/status` | It reads its own tracer. Read the comparison |
| `IsDebuggerPresent` alone | Usually the C runtime, not a deliberate check; triage ignores it for that reason |
| Two time reads close together | A timing check. Record the threshold |
| `obfuscated-js` | `python scripts/recover_js.py`; webcrack undoes string arrays and most wrappers |
| A dispatcher `switch` inside a loop | Flattened flow. Follow the state variable from case to case |
| One function called before every string use | A string decoder. Reimplement it and decode the strings in Python |
| A function that compares its own source text with a stored copy | Self-defending JavaScript: formatting the code trips it, so analyze rather than run |
| A `debugger` statement inside a timer | A trap for open developer tools. Read around it; do not run it |
| A check for VM files, registry keys or MAC prefixes | Record each indicator. Change the VM to hide them only if the user agrees and needs a dynamic result |

Where to look for each kind of check:

| Platform | Debugger checks | Environment checks |
| --- | --- | --- |
| Windows | `IsDebuggerPresent`, the `BeingDebugged` byte of the PEB, `NtGlobalFlag`, `NtQueryInformationProcess` with `ProcessDebugPort`, scans for `0xCC` breakpoints, `GetThreadContext` reading hardware breakpoints, TLS callbacks that run before `main` | Registry keys of guest tools, process names such as `vmtoolsd.exe`, the CPUID hypervisor bit |
| Linux | `ptrace(PTRACE_TRACEME)`, `TracerPid` in `/proc/self/status`, the parent's name in `/proc/<ppid>/cmdline`, `LD_PRELOAD` in the environment | `/sys/class/dmi/id/product_name`, `/proc/cpuinfo` flags, container files such as `/.dockerenv` |
| macOS | `sysctl` with `KERN_PROC` and the `P_TRACED` flag, `ptrace(PT_DENY_ATTACH)` | `sysctl hw.model`, IOKit device names |
| JavaScript | `debugger` statements on a timer, timing around them | Checks of `navigator` properties, the page's domain, or a function's own source text |

MAC address prefixes also give a VM away: `08:00:27` is VirtualBox, `00:0C:29` and `00:50:56`
are VMware, and `52:54:00` is QEMU.

## Common traps

- **Unpacking the original.** Tools that unpack in place destroy the evidence. Always write to a
  copy in `decompiled/`.
- **Calling a guess a fact.** A high-entropy section can be compressed resources, not code.
  Triage reports its evidence: check it before recording `confirmed` anything.
- **Patching a check to get past it.** Fine as a step in your own analysis, but the finding is
  the check: what it tests and what it does. A patched copy proves nothing about the original.
- **Benign behavior under analysis.** A sample that behaves well under a debugger or in a VM may
  behave differently elsewhere. Say so in the report's gaps.
- **Dynamic unpacking of an unknown sample.** Running it is running malware until shown
  otherwise. It needs the user's confirmed VM, a snapshot and no network.
- **Stopping at the first check.** Programs often stack several. Benchmark 8 has two, and a
  third could be hidden in a timing loop.

## Worked example

Benchmark 8 is a small ELF for arm64 that prints a code only when nothing is tracing it. These
are the real outputs, shortened.

Triage raised two signals and routed here:

```
antidebug: ELF 64-bit little-endian shared object or PIE, arm64
  signal: anti-debug (imports ptrace)
  signal: anti-debug (contains the string TracerPid)
  read next: references/native.md, references/anti-analysis.md
```

`run_ghidra.py` showed `fopen`, `strncmp` and `ptrace` all called from `main`, and the decompiled
`main` held both checks:

```c
  __stream = fopen("/proc/self/status","r");
  ...
      iVar2 = strncmp(acStack_c8,"TracerPid:",10);
    } while (iVar2 != 0);
    iVar2 = __isoc23_strtol(auStack_be,0,10);
    fclose(__stream);
    if (iVar2 == 0) goto LAB_00100c2c;
  }
  puts("Nothing to see here.");
  ...
LAB_00100c2c:
    lVar4 = ptrace(PTRACE_TRACEME,0,0,0);
    if (lVar4 != -1) {
      __printf_chk(2,"The launch code is ");
      ...
        putc((byte)(&MESSAGE)[lVar4] ^ 0x2a,*(FILE **)puVar1);
```

Two findings followed, one per check: the program reads `TracerPid` from `/proc/self/status` and
prints a decoy when it is not 0, and it calls `ptrace(PTRACE_TRACEME)` and prints the decoy when
that fails. Each was a behavior claim, which needs the decompiled logic plus one independent
signal; triage's import and string signals were that signal. Reading `MESSAGE` with `--bytes` and
XORing it with `0x2a` gave the text the program prints when undisturbed, and running it in the VM
printed exactly that: `The launch code is ORCHID-42`.
