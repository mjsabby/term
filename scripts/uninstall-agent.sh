#!/usr/bin/env bash
# Uninstall term-agent from this host. Idempotent: missing pieces are
# logged and skipped, not treated as errors. Preserves /etc/term-agent
# by default so a re-install can reuse the existing cert + key —
# pass --purge-config to nuke it.
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 [options]

Optional:
  --bin-dir DIR            where term-agent lives  (default: /usr/local/bin)
  --config-dir DIR         agent config + cert dir (default: /etc/term-agent)
  --purge-config           also remove --config-dir (cert + key + agent.toml)
  --keep-binary            don't remove the term-agent binary
  -h, --help
EOF
}

BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/term-agent"
PURGE_CONFIG=false
KEEP_BINARY=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-dir)      BIN_DIR="$2";       shift 2 ;;
    --config-dir)   CONFIG_DIR="$2";    shift 2 ;;
    --purge-config) PURGE_CONFIG=true;  shift   ;;
    --keep-binary)  KEEP_BINARY=true;   shift   ;;
    -h|--help)      usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

note() { echo "uninstall-agent: $*"; }
die()  { echo "uninstall-agent: error: $*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "must run as root (try: sudo $0 ...)"

# --- systemd unit
if systemctl list-unit-files --no-legend --type=service 2>/dev/null \
    | awk '{print $1}' | grep -qx 'term-agent.service'; then
  note "stopping term-agent.service"
  systemctl stop term-agent.service 2>/dev/null || true
  note "disabling term-agent.service"
  systemctl disable term-agent.service 2>/dev/null || true
fi
for f in /etc/systemd/system/term-agent.service \
         /etc/systemd/system/term-agent.service.d/user.conf; do
  if [[ -e "$f" ]]; then
    note "removing $f"
    rm -f "$f"
  fi
done
rmdir /etc/systemd/system/term-agent.service.d 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true
# Forget any lingering "failed" state from the just-removed unit.
systemctl reset-failed term-agent.service 2>/dev/null || true

# --- binary
if ! $KEEP_BINARY; then
  if [[ -e "$BIN_DIR/term-agent" ]]; then
    note "removing $BIN_DIR/term-agent"
    rm -f "$BIN_DIR/term-agent"
  fi
fi

# --- config dir (cert + key + agent.toml)
if $PURGE_CONFIG; then
  if [[ -d "$CONFIG_DIR" ]]; then
    note "purging $CONFIG_DIR (cert + key + agent.toml)"
    rm -rf "$CONFIG_DIR"
  fi
else
  note "preserving $CONFIG_DIR (use --purge-config to wipe cert+key+agent.toml)"
fi

note "done."
