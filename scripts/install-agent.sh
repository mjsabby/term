#!/usr/bin/env bash
# Install term-agent on this host. Idempotent; refuses to overwrite an
# existing agent.toml unless --force.
#
# As of Phase 4.6 the agent authenticates by client cert (issued via
# `hub-admin issue-cert` on the hub host) rather than by PSK; the
# machine_id is bound by the cert's SAN URN, so there's no
# --machine-id flag anymore.
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 --hub HOST:PORT --cert PATH --key PATH [options]

Required:
  --hub HOST:PORT          hub's agent_bind, e.g. term.xyz.com:7700
  --cert PATH              PEM cert from \`hub-admin issue-cert --id <id>\`
                           (file named <id>.crt; SAN URN encodes the machine_id)
  --key PATH               matching PEM key (file named <id>.key)

Optional:
  --hub-ca PATH            PEM CA(s) for the hub's server cert; needed only
                           when the hub uses tls=files with a private CA
  --tls on|off             default: on (must match hub)
  --server-name HOST       cert verify target (default: host part of --hub)
  --shell PATH             default: /bin/bash

  --user UNIX_USER         run agent as this user; sets a systemd drop-in
                           (default: keep User= from the unit, i.e. root)

  --build-dir DIR          where target/release lives (default: ./target/release)
  --unit-src FILE          systemd unit source        (default: ./systemd/term-agent.service)

  --bin-dir DIR            install binary here      (default: /usr/local/bin)
  --config-dir DIR         agent config dir         (default: /etc/term-agent)

  --no-enable              don't enable/start the unit
  --force                  overwrite an existing agent.toml
  --clean                  uninstall any previous agent first (preserves
                           cert+key+agent.toml unless --purge-config too)
  --purge-config           passed through to --clean: wipe --config-dir
  -h, --help
EOF
}

HUB=""
CERT_SRC=""
KEY_SRC=""
HUB_CA_SRC=""
TLS="on"
SERVER_NAME=""
SHELL_BIN="/bin/bash"
RUN_USER=""

BUILD_DIR="./target/release"
UNIT_SRC="./systemd/term-agent.service"

BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/term-agent"

NO_ENABLE=false
FORCE=false
CLEAN=false
PURGE_CONFIG=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hub)           HUB="$2";          shift 2 ;;
    --cert)          CERT_SRC="$2";     shift 2 ;;
    --key)           KEY_SRC="$2";      shift 2 ;;
    --hub-ca)        HUB_CA_SRC="$2";   shift 2 ;;
    --tls)           TLS="$2";          shift 2 ;;
    --server-name)   SERVER_NAME="$2";  shift 2 ;;
    --shell)         SHELL_BIN="$2";    shift 2 ;;
    --user)          RUN_USER="$2";     shift 2 ;;
    --build-dir)     BUILD_DIR="$2";    shift 2 ;;
    --unit-src)      UNIT_SRC="$2";     shift 2 ;;
    --bin-dir)       BIN_DIR="$2";      shift 2 ;;
    --config-dir)    CONFIG_DIR="$2";   shift 2 ;;
    --no-enable)     NO_ENABLE=true;    shift   ;;
    --force)         FORCE=true;        shift   ;;
    --clean)         CLEAN=true;        shift   ;;
    --purge-config)  PURGE_CONFIG=true; shift   ;;
    -h|--help)       usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

die()  { echo "install-agent: error: $*" >&2; exit 1; }
note() { echo "install-agent: $*"; }

[[ -n "$HUB"      ]] || die "--hub is required"
[[ -n "$CERT_SRC" ]] || die "--cert is required"
[[ -n "$KEY_SRC"  ]] || die "--key is required"
[[ "$TLS" == "on" || "$TLS" == "off" ]] || die "--tls must be on or off"
[[ -f "$CERT_SRC" ]] || die "cert file not readable: $CERT_SRC"
[[ -f "$KEY_SRC"  ]] || die "key file not readable: $KEY_SRC"
[[ -z "$HUB_CA_SRC" || -f "$HUB_CA_SRC" ]] || die "hub-ca file not readable: $HUB_CA_SRC"

[[ "$(id -u)" -eq 0 ]] || die "must run as root (try: sudo $0 ...)"
[[ -x "$BUILD_DIR/term-agent" ]] || die "missing $BUILD_DIR/term-agent (run: cargo build --release)"
[[ -f "$UNIT_SRC"             ]] || die "missing $UNIT_SRC (systemd unit)"

if [[ -n "$RUN_USER" ]] && ! id "$RUN_USER" >/dev/null 2>&1; then
  die "user $RUN_USER does not exist; create it first"
fi

# --- optional clean-install: tear down any previous install first
if $CLEAN; then
  uninstall_script="$(dirname "$0")/uninstall-agent.sh"
  if [[ ! -x "$uninstall_script" ]]; then
    die "--clean requested but $uninstall_script not found / not executable"
  fi
  note "--clean: invoking $uninstall_script first"
  uninstall_args=( --bin-dir "$BIN_DIR" --config-dir "$CONFIG_DIR" --keep-binary )
  $PURGE_CONFIG && uninstall_args+=( --purge-config )
  "$uninstall_script" "${uninstall_args[@]}"
fi

# --- binary
note "installing binary -> $BIN_DIR/term-agent"
install -m 755 "$BUILD_DIR/term-agent" "$BIN_DIR/"

# --- config dir
mkdir -p "$CONFIG_DIR"
chmod 0750 "$CONFIG_DIR"
if [[ -n "$RUN_USER" ]]; then
  chown -R "$RUN_USER:$RUN_USER" "$CONFIG_DIR"
fi

# --- cert + key (always overwrite — issued certs rotate)
CERT_DST="$CONFIG_DIR/agent.crt"
KEY_DST="$CONFIG_DIR/agent.key"
HUB_CA_DST=""
note "installing cert -> $CERT_DST"
install -m 0644 "$CERT_SRC" "$CERT_DST"
note "installing key  -> $KEY_DST (0600)"
install -m 0600 "$KEY_SRC" "$KEY_DST"
if [[ -n "$HUB_CA_SRC" ]]; then
  HUB_CA_DST="$CONFIG_DIR/hub-server-ca.pem"
  note "installing hub server CA -> $HUB_CA_DST"
  install -m 0644 "$HUB_CA_SRC" "$HUB_CA_DST"
fi
if [[ -n "$RUN_USER" ]]; then
  chown "$RUN_USER:$RUN_USER" "$CERT_DST" "$KEY_DST"
  [[ -n "$HUB_CA_DST" ]] && chown "$RUN_USER:$RUN_USER" "$HUB_CA_DST"
fi

# --- agent.toml
CONFIG_PATH="$CONFIG_DIR/agent.toml"
if [[ -e "$CONFIG_PATH" ]] && ! $FORCE; then
  note "$CONFIG_PATH exists; not overwriting (use --force to replace)"
else
  note "writing $CONFIG_PATH"
  server_name_line=""
  [[ -n "$SERVER_NAME" ]] && server_name_line="server_name = \"$SERVER_NAME\""
  hub_ca_line=""
  [[ -n "$HUB_CA_DST"  ]] && hub_ca_line="hub_ca_path = \"$HUB_CA_DST\""
  cat > "$CONFIG_PATH" <<EOF
## generated by scripts/install-agent.sh on $(date -Is)
hub         = "$HUB"
cert_path   = "$CERT_DST"
key_path    = "$KEY_DST"
tls         = "$TLS"
$hub_ca_line
$server_name_line
shell       = "$SHELL_BIN"
EOF
  sed -i '/^$/N;/^\n$/D' "$CONFIG_PATH"
  if [[ -n "$RUN_USER" ]]; then
    chown "$RUN_USER:$RUN_USER" "$CONFIG_PATH"
  fi
  chmod 0600 "$CONFIG_PATH"
fi

# --- systemd unit + optional user drop-in
note "installing systemd unit"
install -m 644 "$UNIT_SRC" /etc/systemd/system/term-agent.service

DROP_IN_DIR=/etc/systemd/system/term-agent.service.d
if [[ -n "$RUN_USER" ]]; then
  mkdir -p "$DROP_IN_DIR"
  cat > "$DROP_IN_DIR/user.conf" <<EOF
[Service]
User=$RUN_USER
Group=$RUN_USER
EOF
  note "agent will run as $RUN_USER (via drop-in $DROP_IN_DIR/user.conf)"
else
  rm -f "$DROP_IN_DIR/user.conf"
fi

systemctl daemon-reload
if ! $NO_ENABLE; then
  note "enabling + (re)starting term-agent.service"
  systemctl enable term-agent.service
  systemctl restart term-agent.service
  sleep 1
  systemctl --no-pager --full status term-agent.service | head -15 || true
fi

note "done."
cat <<EOF

next:
  - tail logs:  sudo journalctl -fu term-agent.service
  - on the hub, you should see:
      agent registered machine=<id from cert SAN> peer=...
EOF
