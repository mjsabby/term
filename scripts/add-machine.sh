#!/usr/bin/env bash
# Append a new [[machines]] block to hub.toml with a fresh PSK and print
# the matching agent.toml snippet (and an install-agent.sh command) on
# stdout for the operator to copy.
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 --id ID --label LABEL [options]

Required:
  --id    ID                machine id ([A-Za-z0-9_-]{1,32})
  --label LABEL             human-readable label

Optional:
  --hub-config PATH         default: /etc/term-hub/hub.toml
  --hub HOST:PORT           hint embedded in the printed snippet
                            (default: <domain>:<agent_bind_port> from hub.toml)
  --psk PSK                 use this PSK instead of generating one (44 b64 chars)
  --reload                  systemctl restart term-hub.service after appending
  --print-only              don't touch hub.toml; just print everything
  -h, --help
EOF
}

ID=""
LABEL=""
HUB_CONFIG="/etc/term-hub/hub.toml"
HUB=""
PSK=""
RELOAD=false
PRINT_ONLY=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --id)          ID="$2";           shift 2 ;;
    --label)       LABEL="$2";        shift 2 ;;
    --hub-config)  HUB_CONFIG="$2";   shift 2 ;;
    --hub)         HUB="$2";          shift 2 ;;
    --psk)         PSK="$2";          shift 2 ;;
    --reload)      RELOAD=true;       shift   ;;
    --print-only)  PRINT_ONLY=true;   shift   ;;
    -h|--help)     usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

die()  { echo "add-machine: error: $*" >&2; exit 1; }
note() { echo "add-machine: $*" >&2; }   # to stderr so stdout stays clean for piping

[[ -n "$ID"    ]] || die "--id is required"
[[ -n "$LABEL" ]] || die "--label is required"
[[ "$ID" =~ ^[A-Za-z0-9_-]{1,32}$ ]] || die "id must match [A-Za-z0-9_-]{1,32}"

if ! $PRINT_ONLY; then
  [[ "$(id -u)" -eq 0 ]] || die "must run as root (try: sudo $0 ...)"
  [[ -f "$HUB_CONFIG" ]] || die "$HUB_CONFIG not found (--hub-config to override)"
fi

# --- read existing config to detect duplicate id + guess hub
DOMAIN=""
AGENT_PORT="7700"
if [[ -f "$HUB_CONFIG" ]]; then
  if grep -qE "^[[:space:]]*id[[:space:]]*=[[:space:]]*\"$ID\"" "$HUB_CONFIG"; then
    die "machine id '$ID' already exists in $HUB_CONFIG"
  fi
  DOMAIN="$(awk -F'"' '/^[[:space:]]*domain[[:space:]]*=/ {print $2; exit}' "$HUB_CONFIG" || true)"
  AB="$(awk -F'"' '/^[[:space:]]*agent_bind[[:space:]]*=/ {print $2; exit}' "$HUB_CONFIG" || true)"
  if [[ "$AB" =~ :([0-9]+)$ ]]; then AGENT_PORT="${BASH_REMATCH[1]}"; fi
fi
[[ -z "$HUB" && -n "$DOMAIN" ]] && HUB="$DOMAIN:$AGENT_PORT"

# --- generate PSK
if [[ -z "$PSK" ]]; then
  PSK="$(head -c 32 /dev/urandom | base64)"
fi

# --- append to hub.toml
BLOCK=$(cat <<EOF

[[machines]]
id    = "$ID"
label = "$LABEL"
psk   = "$PSK"
EOF
)

if ! $PRINT_ONLY; then
  note "appending [[machines]] '$ID' to $HUB_CONFIG"
  printf '%s\n' "$BLOCK" >> "$HUB_CONFIG"
  if $RELOAD; then
    note "restarting term-hub.service"
    systemctl restart term-hub.service
  else
    note "remember: sudo systemctl restart term-hub.service"
  fi
fi

# --- stdout: actionable instructions for the operator
cat <<EOF
# machine '$ID' added.
# On the agent host, run:

sudo scripts/install-agent.sh \\
    --hub "${HUB:-HUB_HOST:7700}" \\
    --machine-id "$ID" \\
    --psk "$PSK"

# Or, if you prefer agent.toml directly (/etc/term-agent/agent.toml):

hub         = "${HUB:-HUB_HOST:7700}"
machine_id  = "$ID"
psk         = "$PSK"
tls         = "on"
shell       = "/bin/bash"
tmux        = "/usr/bin/tmux"
EOF
