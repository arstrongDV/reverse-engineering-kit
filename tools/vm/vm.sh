#!/usr/bin/env bash
# Manage the disposable Linux test VM. Details and isolation limits: tools/vm/README.md.
set -euo pipefail

VM=re-kit-linux
SNAPSHOT_PREFIX="$VM-snap-"
TEMPLATE="$(cd "$(dirname "$0")" && pwd)/$VM.yaml"

usage() {
  cat <<EOF
usage: vm.sh <command>

  up                 create the VM on first use, otherwise start it
  down               stop the VM
  shell [command]    open a shell in the VM, or run one command
  online             allow network access, for installing tools
  offline            block network access again (the state after every boot)
  status             show the VM state and network mode
  snapshot <name>    stop the VM and save a copy-on-write snapshot
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
