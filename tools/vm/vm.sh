#!/usr/bin/env bash
# Manage the disposable Linux test VM. Details and isolation limits: tools/vm/README.md.
set -euo pipefail

VM=re-kit-linux
SNAPSHOT_PREFIX="$VM-snap-"
HERE="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE="$HERE/$VM.yaml"
BENCHMARKS="$HERE/../../benchmarks"
GUEST_BENCHMARKS=/var/tmp/benchmarks

usage() {
  cat <<EOF
usage: vm.sh <command>

  up                 create the VM on first use, otherwise start it
  down               stop the VM
  shell [command]    open a shell in the VM, or run one command
  online             allow network access, for installing tools
  offline            block network access again (the state after every boot)
  install-tools      install the analysis tools, then block the network again
  check-tools        prove each installed tool works, with the network still blocked
  build-benchmarks   build the benchmark targets in the VM and copy them to benchmarks/*/build
  status             show the VM state and network mode
  snapshot <name>    stop the VM and save a copy-on-write snapshot, replacing one of that name
  restore <name>     replace the VM with a snapshot and start it
  snapshots          list snapshots
EOF
}

exists() { limactl list --quiet | grep -qx "$1"; }

running() { [[ "$(limactl list --format '{{.Status}}' "$VM" 2>/dev/null)" == Running ]]; }

stop_vm() { if running; then limactl stop "$VM"; fi; }

guest() { limactl shell --workdir / "$VM" "$@"; }

require_name() {
  if [[ -z "${1:-}" ]]; then
    usage >&2
    exit 64
  fi
}

case "${1:-}" in
  up)
    if exists "$VM"; then
      limactl start --tty=false "$VM"
    else
      limactl start --tty=false --name="$VM" "$TEMPLATE"
    fi
    guest sudo systemctl start nftables
    ;;
  down)
    stop_vm
    ;;
  shell)
    shift
    guest "$@"
    ;;
  online)
    guest sudo systemctl stop nftables
    ;;
  offline)
    guest sudo systemctl start nftables
    ;;
  install-tools)
    # A failed install must not leave the VM online.
    trap 'guest sudo systemctl start nftables' EXIT
    guest sudo systemctl stop nftables
    limactl copy "$HERE/install-tools.sh" "$VM:/tmp/install-tools.sh"
    # Sleep freezes the VM. This stops idle sleep, but closing the lid still freezes it.
    caffeinate -i limactl shell --workdir / "$VM" bash /tmp/install-tools.sh
    ;;
  check-tools)
    limactl copy "$HERE/install-tools.sh" "$VM:/tmp/install-tools.sh"
    apk="$BENCHMARKS/05-android-hidden-api/build/fieldnotes.apk"
    if [[ -f "$apk" ]]; then
      limactl copy "$apk" "$VM:/tmp/sample.apk"
    fi
    guest bash /tmp/install-tools.sh --check-only
    ;;
  build-benchmarks)
    # A failed build must not leave the VM online.
    trap 'guest sudo systemctl start nftables' EXIT
    guest rm -rf "$GUEST_BENCHMARKS"
    limactl copy --recursive "$BENCHMARKS" "$VM:$GUEST_BENCHMARKS"
    limactl copy "$HERE/build-benchmarks.sh" "$VM:/tmp/build-benchmarks.sh"
    guest sudo systemctl stop nftables
    caffeinate -i limactl shell --workdir / "$VM" bash /tmp/build-benchmarks.sh "$GUEST_BENCHMARKS"
    guest sudo systemctl start nftables
    # shellcheck disable=SC2016
    guest bash -c 'cd "$1" && tar -cf /tmp/benchmark-builds.tar ./*/build' _ "$GUEST_BENCHMARKS"
    host_copy="$(mktemp)"
    limactl copy "$VM:/tmp/benchmark-builds.tar" "$host_copy"
    tar -C "$BENCHMARKS" -xf "$host_copy"
    rm -f "$host_copy"
    ;;
  status)
    limactl list "$VM"
    if running; then
      if guest systemctl is-active --quiet nftables; then
        echo 'network: blocked'
      else
        echo 'network: OPEN'
      fi
    fi
    ;;
  snapshot)
    require_name "${2:-}"
    stop_vm
    if exists "$SNAPSHOT_PREFIX$2"; then
      limactl delete "$SNAPSHOT_PREFIX$2"
    fi
    limactl clone --tty=false "$VM" "$SNAPSHOT_PREFIX$2"
    ;;
  restore)
    require_name "${2:-}"
    if ! exists "$SNAPSHOT_PREFIX$2"; then
      echo "vm.sh: no snapshot named $2" >&2
      exit 1
    fi
    stop_vm
    limactl delete "$VM"
    limactl clone --tty=false "$SNAPSHOT_PREFIX$2" "$VM"
    limactl start --tty=false "$VM"
    ;;
  snapshots)
    limactl list --quiet | sed -n "s/^$SNAPSHOT_PREFIX//p"
    ;;
  -h | --help)
    usage
    ;;
  *)
    usage >&2
    exit 64
    ;;
esac
