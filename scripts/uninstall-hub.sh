#!/usr/bin/env bash
# Uninstall term-hub from this host. Idempotent.
#
# Data preservation defaults:
#   --config-dir (/etc/term-hub)         : PRESERVED unless --purge-config
#   --data-dir   (/var/lib/term-hub)     : PRESERVED unless --purge-data
#   service user (term-hub)              : PRESERVED unless --remove-user
#
# --purge-data is destructive: it removes the agent CA, the
# issued-certs allowlist, registered passkey credentials, and the
# ACME cache. Use only when you really want a fresh install.
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 [options]

Optional:
  --bin-dir DIR            where term-hub + hub-admin live (default: /usr/local/bin)
  --config-dir DIR         hub config dir   (default: /etc/term-hub)
  --data-dir DIR           hub state dir    (default: /var/lib/term-hub)
  --user USER              service user     (default: term-hub)

  --purge-config           also remove --config-dir (hub.toml)
  --purge-data             also remove --data-dir (CA, credentials,
                           issued-certs, ACME cache) — DESTRUCTIVE
  --remove-user            also delete the --user account
  --keep-binary            don't remove the term-hub / hub-admin binaries
  -h, --help
EOF
}

BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/term-hub"
DATA_DIR="/var/lib/term-hub"
SERVICE_USER="term-hub"
PURGE_CONFIG=false
PURGE_DATA=false
REMOVE_USER=false
KEEP_BINARY=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-dir)       BIN_DIR="$2";       shift 2 ;;
    --config-dir)    CONFIG_DIR="$2";    shift 2 ;;
    --data-dir)      DATA_DIR="$2";      shift 2 ;;
    --user)          SERVICE_USER="$2";  shift 2 ;;
    --purge-config)  PURGE_CONFIG=true;  shift   ;;
    --purge-data)    PURGE_DATA=true;    shift   ;;
    --remove-user)   REMOVE_USER=true;   shift   ;;
    --keep-binary)   KEEP_BINARY=true;   shift   ;;
    -h|--help)       usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

note() { echo "uninstall-hub: $*"; }
die()  { echo "uninstall-hub: error: $*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "must run as root (try: sudo $0 ...)"

# --- systemd unit
if systemctl list-unit-files --no-legend --type=service 2>/dev/null \
    | awk '{print $1}' | grep -qx 'term-hub.service'; then
  note "stopping term-hub.service"
  systemctl stop term-hub.service 2>/dev/null || true
  note "disabling term-hub.service"
  systemctl disable term-hub.service 2>/dev/null || true
fi
for f in /etc/systemd/system/term-hub.service \
         /etc/systemd/system/term-hub.service.d/user.conf \
         /etc/systemd/system/term-hub.service.d/static.conf; do
  if [[ -e "$f" ]]; then
    note "removing $f"
    rm -f "$f"
  fi
done
rmdir /etc/systemd/system/term-hub.service.d 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true
systemctl reset-failed term-hub.service 2>/dev/null || true

# --- binaries
if ! $KEEP_BINARY; then
  for b in term-hub hub-admin; do
    if [[ -e "$BIN_DIR/$b" ]]; then
      note "removing $BIN_DIR/$b"
      rm -f "$BIN_DIR/$b"
    fi
  done
fi

# --- config dir (hub.toml)
if $PURGE_CONFIG; then
  if [[ -d "$CONFIG_DIR" ]]; then
    note "purging $CONFIG_DIR (hub.toml)"
    rm -rf "$CONFIG_DIR"
  fi
else
  note "preserving $CONFIG_DIR (use --purge-config to wipe hub.toml)"
fi

# --- data dir (CA + credentials + issued-certs + ACME cache)
if $PURGE_DATA; then
  if [[ -d "$DATA_DIR" ]]; then
    note "purging $DATA_DIR (CA, credentials, issued-certs, ACME cache) — DESTRUCTIVE"
    rm -rf "$DATA_DIR"
  fi
else
  note "preserving $DATA_DIR (use --purge-data to wipe CA + credentials + issued-certs)"
fi

# --- service user
if $REMOVE_USER; then
  if id "$SERVICE_USER" >/dev/null 2>&1; then
    note "removing user $SERVICE_USER"
    userdel "$SERVICE_USER" 2>/dev/null || \
      note "userdel $SERVICE_USER failed (still has files? check $DATA_DIR / $CONFIG_DIR)"
  fi
else
  if id "$SERVICE_USER" >/dev/null 2>&1; then
    note "preserving user $SERVICE_USER (use --remove-user to delete it)"
  fi
fi

note "done."
