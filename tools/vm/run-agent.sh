#!/usr/bin/env bash
# Run Claude Code on one staged benchmark as the user bench, with only Anthropic's API reachable.
# Run as root through `vm.sh run-benchmark`, which first copies into /var/tmp/run: skill.zip,
# task/, prompt.txt, token and api-address. Everything the run produced ends up in out.tar there.
set -euo pipefail

RUN=/var/tmp/run
HOME_DIR=/home/bench
TIMEOUT="$1"
MAX_TURNS="$2"
MODEL="${3:-}"
# Anthropic's published inbound ranges for the API: platform.claude.com/docs/en/api/ip-addresses
API_V4='160.79.104.0/23, 153.61.224.0/22'
API_V6='2607:6bc0::/48'

step() { echo "==> $*"; }

# Reloading the saved ruleset drops the API rules again, however this script ends.
trap 'systemctl restart nftables' EXIT

step 'checking the VM holds no answers'
if [[ -e /var/tmp/benchmarks ]]; then
  echo 'the benchmark sources are in this VM; restore the agent snapshot first' >&2
  exit 1
fi

step 'setting up the task for bench'
rm -rf "$HOME_DIR/task" "$HOME_DIR/.claude" "$HOME_DIR/re-work"
install -d -o bench -g bench -m 700 "$HOME_DIR/.claude" "$HOME_DIR/.claude/skills"
sudo -u bench unzip -q "$RUN/skill.zip" -d "$HOME_DIR/.claude/skills"
cp -R "$RUN/task" "$HOME_DIR/task"
chown -R bench:bench "$HOME_DIR/task"
install -o bench -g bench -m 600 "$RUN/token" "$HOME_DIR/.token"
rm -f "$RUN/token"

step 'opening the API, and only the API'
address="$(cat "$RUN/api-address")"
# The Mac resolved the name, since this VM has no DNS. Refuse an address outside the ranges.
python3 -c 'import ipaddress, sys
address = ipaddress.ip_address(sys.argv[1])
sys.exit(not any(address in ipaddress.ip_network(net.strip()) for net in sys.argv[2].split(",")))
' "$address" "$API_V4"
echo "$address api.anthropic.com" >>/etc/hosts
nft insert rule inet re_kit_offline output ip daddr "{ $API_V4 }" tcp dport 443 accept
nft insert rule inet re_kit_offline output ip6 daddr "{ $API_V6 }" tcp dport 443 accept
if ! sudo -u bench curl -sS -o /dev/null --max-time 15 https://api.anthropic.com/; then
  echo 'the API is not reachable' >&2
  exit 1
fi
if sudo -u bench curl -sS -o /dev/null --max-time 5 --resolve "github.com:443:140.82.112.3" \
  https://github.com/ 2>/dev/null; then
  echo 'GitHub is reachable, so the answers are too' >&2
  exit 1
fi

step "running Claude Code for up to $TIMEOUT seconds"
model_args=()
if [[ -n "$MODEL" ]]; then
  model_args=(--model "$MODEL")
fi
# WebSearch runs on Anthropic's side, so the firewall cannot stop it: turn both web tools off.
set +e
# The redirects run as root on purpose, so bench cannot touch the transcript it produces.
# shellcheck disable=SC2016,SC2024
sudo -u bench -H bash -c '
  set -euo pipefail
  token="$(cat ~/.token)"
  rm -f ~/.token
  case "$token" in
    sk-ant-api*) export ANTHROPIC_API_KEY="$token" ;;
    *) export CLAUDE_CODE_OAUTH_TOKEN="$token" ;;
  esac
  export PATH=/opt/re-kit/venv/bin:/usr/local/bin:/usr/bin:/bin
  export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 DISABLE_AUTOUPDATER=1
  cd ~/task
  exec timeout --kill-after=30 "$1" claude -p --output-format stream-json --verbose \
    --max-turns "$2" --permission-mode bypassPermissions \
    --disallowedTools WebSearch,WebFetch "${@:4}" <"$3"
' _ "$TIMEOUT" "$MAX_TURNS" "$RUN/prompt.txt" "${model_args[@]}" \
  >"$RUN/transcript.jsonl" 2>"$RUN/stderr.txt"
status=$?
set -e
echo "$status" >"$RUN/exit-code"
systemctl restart nftables

step "packing the output (Claude Code exited $status)"
# Whatever the agent wrote in its home, wherever it put the work directory, minus caches.
tar -C "$RUN" -cf "$RUN/out.tar" transcript.jsonl stderr.txt exit-code prompt.txt
tar -C /home -rf "$RUN/out.tar" --exclude=bench/.claude --exclude=bench/.cache \
  --exclude=bench/.claude.json --exclude=bench/.npm --exclude=bench/.local \
  --exclude=bench/.config bench
du -h "$RUN/out.tar" | cut -f1
