# Test VM

A disposable Ubuntu 26.04 arm64 VM for running kit scripts and benchmark targets on an Apple
Silicon Mac. It is defined in [re-kit-linux.yaml](re-kit-linux.yaml) and managed with Lima through
[vm.sh](vm.sh). Tested with Lima 2.2.1.

## First-time setup

```sh
brew install lima
tools/vm/vm.sh up                 # about 20 seconds once the image is cached
tools/vm/vm.sh snapshot clean     # stops the VM and saves the baseline
tools/vm/vm.sh up
tools/vm/vm.sh install-tools      # about 10 minutes, with the lid open
tools/vm/vm.sh snapshot tools     # the baseline for daily work
```

The install uses about 3 GB of disk, and about 5 GB at its peak while building.

## Daily use

```sh
tools/vm/vm.sh up                                   # the network is blocked after every boot
limactl copy ./target re-kit-linux:/tmp/target      # the only way files move in or out
tools/vm/vm.sh shell                                # or: vm.sh shell <command>
tools/vm/vm.sh check-tools                          # prove each tool works, offline
tools/vm/vm.sh restore tools                        # throw away everything since the snapshot
tools/vm/vm.sh down
```

To add another tool, open the network only for as long as you need it, then save a new baseline:

```sh
tools/vm/vm.sh online
tools/vm/vm.sh shell sudo apt-get install -y <package>
tools/vm/vm.sh offline
tools/vm/vm.sh snapshot tools
```

## Installed tools

[install-tools.sh](install-tools.sh) pins these versions and checks the SHA-256 of each download.
`check-tools` runs the same tests with the network blocked.

| Tool | Version | Source | What the test proves |
| --- | --- | --- | --- |
| Ghidra | 12.2 | GitHub release, arm64 natives built in the VM | Decompiles a real function |
| rizin | 0.9.1 | GitHub source release, built in the VM | Analyzes a binary and finds a function |
| jadx | 1.5.6 | GitHub release | Decompiles a jar and recovers a string |
| Frida | 17.25.0, tools 14.11.0 | PyPI | Hooks a function, reads its argument and result |
| apktool | 3.0.3 | GitHub release | Version only, because there is no sample APK yet |
| JDK 25, Node 22, npm, gcc | Ubuntu packages | Ubuntu | Used by the tests above, or version only |

Two tools cannot be installed the usual way on arm64 Linux. Ghidra releases have no arm64 Linux
decompiler, so the script runs `support/gradle/gradlew buildNatives`; without this Ghidra starts but
cannot decompile. rizin has no arm64 Linux package or prebuilt binary, so it is built from source.

## What the isolation covers

| Path | Offline (default) | Online |
| --- | --- | --- |
| Guest reads Mac files | No, nothing is mounted | No |
| Mac reaches guest ports | No, forwarding is off | No |
| Guest reaches services on the Mac's localhost | Blocked | **Reachable** |
| Guest reaches the local network | Blocked | **Reachable** |
| Guest reaches the internet | Blocked | **Reachable** |

The firewall has no connection tracking, so a connection opened while online stops working as soon
as you go offline.

## Limits

- **For your own scripts and benchmark targets, not real malware.** The firewall runs inside the
  guest, the default user has passwordless `sudo`, and anything running as root can remove it.
- **Treat online mode as exposure.** It reaches services on your Mac and your local network.
- **Keep the lid open during long jobs.** Sleep freezes the VM. `install-tools` stops idle sleep, but
  closing the lid still freezes it.
- **Ubuntu's daily updater is off.** `install-tools` disables it, because it takes the apt lock at
  random and would change a baseline meant to stay fixed. Update by hand if you need to.
- **The VM is below Ghidra's stated minimum of 4 GB RAM.** 2 GiB is enough for the small test
  binary. Large targets may need more, and this Mac has only 8 GB.
- **arm64 only.** Build Linux benchmark targets from source in the VM. x86-64 ELF files can be
  analyzed statically here, but they will not run.
- **Snapshots hold the disk only, not memory, and the VM stops while one is taken.** Lima's own
  `snapshot` command is not implemented for this VM type, so `vm.sh` uses `limactl clone`.
- **Snapshots cost almost nothing at first.** On APFS a clone shares blocks with the VM until they
  diverge, so `du` reports the full size for each one even though little extra disk is used.
  Snapshots show up in `limactl list` as stopped instances, and `limactl delete` removes them.
- **The disk is capped at 8 GiB.** It grows into your Mac's free space as the guest fills up. The
  tools leave about 3.6 GB free inside the guest.
- **Guest `/tmp` is a 975 MB RAM disk.** Use `/var/tmp` for anything large.

## Windows

There is no local Windows VM. The `windows-latest` CI job runs the test suite on a fresh Windows
machine for every pull request and every push to `main`, which gives the same clean-slate result
without using local disk. It runs the tests only, not the Ghidra or jadx tools themselves.
