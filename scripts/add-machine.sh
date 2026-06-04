#!/usr/bin/env bash
# Issue a per-machine mTLS cert via `hub-admin issue-cert` and print
# both the agent.toml snippet and the install-agent.sh command for the
# operator to copy. As of Phase 4.6 hub.toml carries only id + label
# per machine — no secret material — so this script no longer mutates
# hub.toml; it just appends the [[machines]] block on request and
# always issues the cert. Revoke later with:
#   sudo hub-admin revoke-cert --id ID
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
  --days N                  leaf cert validity (default 365)
  --out-dir DIR             where to drop <id>.crt + <id>.key
                            (default: \$PWD)
  --reload                  systemctl restart term-hub.service after appending
  --print-only              don't touch hub.toml; just issue + print
  -h, --help
EOF
}

ID=""
LABEL=""
HUB_CONFIG="/etc/term-hub/hub.toml"
HUB=""
DAYS=365
OUT_DIR="$PWD"
RELOAD=false
PRINT_ONLY=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --id)          ID="$2";           shift 2 ;;
    --label)       LABEL="$2";        shift 2 ;;
    --hub-config)  HUB_CONFIG="$2";   shift 2 ;;
    --hub)         HUB="$2";          shift 2 ;;
    --days)        DAYS="$2";         shift 2 ;;
    --out-dir)     OUT_DIR="$2";      shift 2 ;;
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

# --- mint the cert
mkdir -p "$OUT_DIR"
note "issuing cert via hub-admin issue-cert --id $ID --days $DAYS --out-dir $OUT_DIR"
if ! command -v hub-admin >/dev/null 2>&1; then
  die "hub-admin not in PATH; install it first or use the full path"
fi
hub-admin issue-cert --id "$ID" --label "$LABEL" --days "$DAYS" --out-dir "$OUT_DIR" 1>&2

CERT_PATH="$OUT_DIR/$ID.crt"
KEY_PATH="$OUT_DIR/$ID.key"
[[ -f "$CERT_PATH" && -f "$KEY_PATH" ]] || die "hub-admin issue-cert didn't produce $CERT_PATH + $KEY_PATH"

# --- append to hub.toml (id + label only — no secret material)
BLOCK=$(cat <<EOF

[[machines]]
id    = "$ID"
label = "$LABEL"
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
# Copy the cert + key to the agent host (e.g. via scp), then on the agent host run:

sudo scripts/install-agent.sh \\
    --hub "${HUB:-HUB_HOST:7700}" \\
    --cert "$ID.crt" \\
    --key "$ID.key"

# Or, if you prefer agent.toml directly (/etc/term-agent/agent.toml):

hub        = "${HUB:-HUB_HOST:7700}"
cert_path  = "/etc/term-agent/agent.crt"
key_path   = "/etc/term-agent/agent.key"
tls        = "on"
shell      = "/bin/bash"
EOF
