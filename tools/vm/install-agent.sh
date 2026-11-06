#!/usr/bin/env bash
# Install Claude Code for benchmark runs, and the user it runs as. Run through
# `vm.sh install-agent`, which opens the network for this script only.
set -euo pipefail

CLAUDE_CODE_VERSION=2.1.296
PREFIX=/opt/claude-code

echo "==> Claude Code $CLAUDE_CODE_VERSION"
sudo npm install --global --prefix "$PREFIX" --no-audit --no-fund --loglevel=error \
  "@anthropic-ai/claude-code@$CLAUDE_CODE_VERSION"
sudo ln -sf "$PREFIX/bin/claude" /usr/local/bin/claude
test "$(claude --version)" = "$CLAUDE_CODE_VERSION (Claude Code)"

echo '==> the user bench'
# No sudo, so the agent cannot change the firewall, the tools or anything outside its home.
if ! id bench >/dev/null 2>&1; then
  sudo useradd --create-home --shell /bin/bash bench
fi
if sudo -l -U bench | grep -q 'may run'; then
  echo 'bench must not have sudo' >&2
  exit 1
fi
echo "installed: $(claude --version)"
