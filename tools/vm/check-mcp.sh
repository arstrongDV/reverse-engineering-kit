#!/usr/bin/env bash
# Install GhidraMCP and r2mcp the way references/mcp-setup.md describes, then drive both over
# MCP on benchmark 1. Run through `vm.sh check-mcp`: --install needs the network, --check does
# not. Everything lands in /var/tmp/mcp, radare2 and r2mcp included; `vm.sh restore tools` undoes it.
set -euo pipefail

W=/var/tmp/mcp
UV_VERSION=0.13.7
GHIDRA_MCP_ZIP=https://github.com/LaurieWired/GhidraMCP/releases/download/2.0/GhidraMCP-release-2-0.zip
GHIDRA_MCP_SHA256=ebf904fd6782e429e95a60a24fe0724b20c0acb2dedb304135a5281f6b5f2e72
RADARE2=https://github.com/radareorg/radare2/releases/download/6.2.4
RADARE2_SHA256=bbf48ee7bd5d8282f65a297dcabd34c9961a500e62d6b036679caab187b32ef1
RADARE2_DEV_SHA256=09e4e50be48e3dc79b541a37f3bf1ee6ef21e33c5005b9cf232fa41952d74ade
R2MCP_TAR=https://github.com/radareorg/radare2-mcp/archive/refs/tags/1.9.0.tar.gz
R2MCP_SHA256=c8fa0684d9d83bd39fdbe1e199f8c272cf1c161315ec96a1203b09e034e22eff

step() { echo "==> $*"; }

fetch() {
  curl -fsSL --retry 3 -o "$W/downloads/$(basename "$1")" "$1"
  echo "$2  $W/downloads/$(basename "$1")" | sha256sum --check --quiet
  echo "$W/downloads/$(basename "$1")"
}

quietly() {
  local log="$W/build.log"
  if ! "$@" >"$log" 2>&1; then
    tail -n 40 "$log" >&2
    echo "failed: $*" >&2
    return 1
  fi
}

install() {
  rm -rf "$W" && mkdir -p "$W/downloads" "$W/work"

  step 'GhidraMCP 2.0, headless, on Python 3.13'
  zip="$(fetch "$GHIDRA_MCP_ZIP" "$GHIDRA_MCP_SHA256")"
  unzip -q "$zip" -d "$W"
  unzip -q "$W"/GhidraMCP-release-2-0/ghidra_*_GhidraMCP.zip -d "$W/extension"
  # Ubuntu 26.04 ships Python 3.14, which GhidraMCP's headless mode does not support yet.
  python3 -m venv "$W/uv"
  quietly "$W/uv/bin/pip" install "uv==$UV_VERSION"
  quietly "$W/uv/bin/uv" python install 3.13
  python313="$("$W/uv/bin/uv" python find 3.13)"
  "$python313" -m venv "$W/ghidra-mcp"
  quietly "$W/ghidra-mcp/bin/pip" install "$W/GhidraMCP-release-2-0/ghidra_mcp-2.0.0-py3-none-any.whl[headless]"

  step 'radare2 6.2.4 and r2mcp 1.9.0'
  r2="$(fetch "$RADARE2/radare2_6.2.4_arm64.deb" "$RADARE2_SHA256")"
  r2dev="$(fetch "$RADARE2/radare2-dev_6.2.4_arm64.deb" "$RADARE2_DEV_SHA256")"
  quietly sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$r2" "$r2dev"
  tarball="$(fetch "$R2MCP_TAR" "$R2MCP_SHA256")"
  tar -xzf "$tarball" -C "$W"
  (cd "$W/radare2-mcp-1.9.0" && quietly ./configure --prefix=/usr/local && quietly make)
  (cd "$W/radare2-mcp-1.9.0" && quietly sudo make install)
}

check() {
  cp /tmp/crackme "$W/work/crackme"
  "$W/ghidra-mcp/bin/pip" list 2>/dev/null | grep -i -E '^(ghidra-mcp|pyghidra|jpype1|mcp) '
  r2 -v | head -n 1
  echo "r2mcp $(r2mcp -v)"
  # mcp_check.py uses the MCP client library that GhidraMCP installed.
  "$W/ghidra-mcp/bin/python" /tmp/mcp_check.py "$W"
}

case "${1:-}" in
  --install) install ;;
  --check) check ;;
  *) echo "usage: check-mcp.sh --install | --check" >&2; exit 64 ;;
esac
