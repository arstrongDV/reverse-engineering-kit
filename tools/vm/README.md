# Test VM

A disposable Ubuntu 26.04 arm64 VM for running kit scripts and benchmark targets on an Apple
Silicon Mac. It is defined in [re-kit-linux.yaml](re-kit-linux.yaml) and managed with Lima through
[vm.sh](vm.sh). Tested with Lima 2.2.1.

## First-time setup

```sh
brew install lima
tools/vm/vm.sh up                 # about 20 seconds once the image is cached
tools/vm/vm.sh snapshot clean     # stops the VM and saves the baseline
```

## Daily use

```sh
tools/vm/vm.sh up                                   # the network is blocked after every boot
limactl copy ./target re-kit-linux:/tmp/target      # the only way files move in or out
tools/vm/vm.sh shell                                # or: vm.sh shell <command>
tools/vm/vm.sh restore clean                        # throw away everything since the snapshot
tools/vm/vm.sh down
```

To install tools, open the network only for as long as you need it, then save a new baseline:

```sh
tools/vm/vm.sh online
tools/vm/vm.sh shell sudo apt-get install -y <package>
tools/vm/vm.sh offline
tools/vm/vm.sh snapshot tools
```

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
- **arm64 only.** Build Linux benchmark targets from source in the VM. x86-64 ELF files can be
  analyzed statically here, but they will not run.
- **Snapshots hold the disk only, not memory, and the VM stops while one is taken.** Lima's own
  `snapshot` command is not implemented for this VM type, so `vm.sh` uses `limactl clone`.
- **Snapshots cost almost nothing at first.** On APFS a clone shares blocks with the VM until they
  diverge, so `du` reports the full size for each one even though little extra disk is used.
  Snapshots show up in `limactl list` as stopped instances, and `limactl delete` removes them.
- **The disk is capped at 8 GiB.** It grows into your Mac's free space as the guest fills up.

## Windows

There is no local Windows VM. The `windows-latest` CI job runs the test suite on a fresh Windows
machine for every pull request and every push to `main`, which gives the same clean-slate result
without using local disk. It runs the tests only, not the Ghidra or jadx tools themselves.
