#!/usr/bin/env bash
# Manage the disposable Linux test VM. Details and isolation limits: tools/vm/README.md.
set -euo pipefail

VM=re-kit-linux
SNAPSHOT_PREFIX="$VM-snap-"
HERE="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE="$HERE/$VM.yaml"
BENCHMARKS="$HERE/../../benchmarks"
GUEST_BENCHMARKS=/var/tmp/benchmarks
DIST="$HERE/../../dist"
AGENT_SNAPSHOT=agent
# Claude Code and Ghidra together need more than the 2 GiB the other snapshots run with.
AGENT_MEMORY=3
TOKEN_FILE="${RE_KIT_TOKEN_FILE:-$HOME/.config/re-kit/claude-token}"
RUN_TIMEOUT="${RE_KIT_RUN_TIMEOUT:-3600}"
RUN_MAX_TURNS="${RE_KIT_RUN_MAX_TURNS:-300}"
RUN_MODEL="${RE_KIT_RUN_MODEL:-}"

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
  check-mcp          install GhidraMCP and r2mcp, then test both offline on benchmark 1
  install-agent      install Claude Code for benchmark runs, then block the network again
  run-benchmark <n>  run Claude Code with the blind skill on benchmark n; output in dist/runs/
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

restore_snapshot() {
  if ! exists "$SNAPSHOT_PREFIX$1"; then
    echo "vm.sh: no snapshot named $1" >&2
    exit 1
  fi
  stop_vm
  limactl delete "$VM"
  limactl clone --tty=false "$SNAPSHOT_PREFIX$1" "$VM"
  if [[ -n "${2:-}" ]]; then
    limactl edit --tty=false --memory "$2" "$VM"
  fi
  limactl start --tty=false "$VM"
}

run_benchmark() {
  if [[ ! -f "$TOKEN_FILE" ]]; then
    echo "vm.sh: no token in $TOKEN_FILE; see tools/vm/README.md" >&2
    exit 1
  fi
  if [[ "$(stat -f %Lp "$TOKEN_FILE")" != 600 ]]; then
    echo "vm.sh: $TOKEN_FILE must be readable by you alone: chmod 600 it" >&2
    exit 1
  fi
  stage="$(mktemp -d)"
  trap 'rm -rf "$stage"' EXIT
  local name address out
  name="$(python3 "$HERE/../bench_task.py" "$1" "$stage")"
  python3 "$HERE/../build_zip.py" --blind >/dev/null
  address="$(python3 -c 'import socket; print(socket.gethostbyname("api.anthropic.com"))')"
  restore_snapshot "$AGENT_SNAPSHOT" "$AGENT_MEMORY"
  guest sh -c 'rm -rf /var/tmp/run && mkdir -m 755 /var/tmp/run'
  limactl copy "$HERE/run-agent.sh" "$VM:/var/tmp/run/run-agent.sh"
  limactl copy "$DIST/reverse-engineering-kit-blind.zip" "$VM:/var/tmp/run/skill.zip"
  limactl copy --recursive "$stage/task" "$VM:/var/tmp/run/task"
  limactl copy "$stage/prompt.txt" "$VM:/var/tmp/run/prompt.txt"
  echo "$address" | guest sh -c 'cat >/var/tmp/run/api-address'
  # Through stdin, so the token never appears in a command line.
  guest sh -c 'umask 077 && cat >/var/tmp/run/token' <"$TOKEN_FILE"
  caffeinate -i limactl shell --workdir / "$VM" \
    sudo bash /var/tmp/run/run-agent.sh "$RUN_TIMEOUT" "$RUN_MAX_TURNS" "$RUN_MODEL"
  out="$DIST/runs/$(date +%Y%m%d-%H%M%S)-$name"
  mkdir -p "$out"
  limactl copy "$VM:/var/tmp/run/out.tar" "$out/out.tar"
  tar -C "$out" -xf "$out/out.tar"
  rm -f "$out/out.tar"
  stop_vm
  if grep -q '"authentication_failed"' "$out/transcript.jsonl"; then
    rm -rf "$out"
    echo "vm.sh: Claude Code rejected the token in $TOKEN_FILE; save it again (tools/vm/README.md)" >&2
    exit 1
  fi
  echo "$out"
}

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
  check-mcp)
    crackme="$BENCHMARKS/01-crackme-xor/build/crackme"
    if [[ ! -f "$crackme" ]]; then
      echo "vm.sh: $crackme is missing; run build-benchmarks first" >&2
      exit 1
    fi
    # A failed install must not leave the VM online.
    trap 'guest sudo systemctl start nftables' EXIT
    limactl copy "$HERE/check-mcp.sh" "$VM:/tmp/check-mcp.sh"
    limactl copy "$HERE/mcp_check.py" "$VM:/tmp/mcp_check.py"
    limactl copy "$crackme" "$VM:/tmp/crackme"
    guest sudo systemctl stop nftables
    caffeinate -i limactl shell --workdir / "$VM" bash /tmp/check-mcp.sh --install
    guest sudo systemctl start nftables
    guest bash /tmp/check-mcp.sh --check
    ;;
  install-agent)
    # A failed install must not leave the VM online.
    trap 'guest sudo systemctl start nftables' EXIT
    limactl copy "$HERE/install-agent.sh" "$VM:/tmp/install-agent.sh"
    guest sudo systemctl stop nftables
    caffeinate -i limactl shell --workdir / "$VM" bash /tmp/install-agent.sh
    ;;
  run-benchmark)
    require_name "${2:-}"
    run_benchmark "$2"
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
    restore_snapshot "$2"
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
