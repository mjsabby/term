#!/usr/bin/env bash
# Install term-hub + hub-admin on this host. Idempotent; refuses to
# overwrite an existing hub.toml unless --force.
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 --domain DOMAIN --email EMAIL [options]

Required:
  --domain DOMAIN          public DNS name (e.g. term.xyz.com)
  --email  EMAIL           ACME contact email

Optional:
  --rp-id RP_ID            WebAuthn RP id (default: DOMAIN)
  --rp-name NAME           authenticator display name (default: term)
  --prod                   use Let's Encrypt production (default: staging)
  --tls MODE               "acme" | "off"           (default: acme)
  --bind ADDR              browser bind             (default unset)
  --agent-bind ADDR        agent listener bind      (default: [::]:7700)
  --data-dir DIR           hub state                (default: /var/lib/term-hub)

  --build-dir DIR          where target/release lives (default: ./target/release)
  --static-src DIR         where hub/static lives     (default: ./hub/static)
  --unit-src FILE          systemd unit source        (default: ./systemd/term-hub.service)

  --bin-dir DIR            install binaries here    (default: /usr/local/bin)
  --static-dir DIR         install static assets    (default: /usr/local/share/term-hub-static)
  --config-dir DIR         hub config dir           (default: /etc/term-hub)
  --user USER              service user             (default: term-hub)

  --no-enable              don't enable/start the unit
  --force                  overwrite an existing hub.toml
  -h, --help               this help

After install:
  - edit any /etc/term-hub/hub.toml field if needed
  - add machines:  sudo scripts/add-machine.sh --id alpha --label alpha.lan
  - tail logs:     sudo journalctl -fu term-hub.service
EOF
}

# --- defaults
DOMAIN=""
EMAIL=""
RP_ID=""
RP_NAME="term"
PROD=false
TLS="acme"
BIND=""
AGENT_BIND="[::]:7700"
DATA_DIR="/var/lib/term-hub"

BUILD_DIR="./target/release"
STATIC_SRC="./hub/static"
UNIT_SRC="./systemd/term-hub.service"

BIN_DIR="/usr/local/bin"
STATIC_DIR="/usr/local/share/term-hub-static"
CONFIG_DIR="/etc/term-hub"
SERVICE_USER="term-hub"

NO_ENABLE=false
FORCE=false

# --- arg parse
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)      DOMAIN="$2";        shift 2 ;;
    --email)       EMAIL="$2";         shift 2 ;;
    --rp-id)       RP_ID="$2";         shift 2 ;;
    --rp-name)     RP_NAME="$2";       shift 2 ;;
    --prod)        PROD=true;          shift   ;;
    --tls)         TLS="$2";           shift 2 ;;
    --bind)        BIND="$2";          shift 2 ;;
    --agent-bind)  AGENT_BIND="$2";    shift 2 ;;
    --data-dir)    DATA_DIR="$2";      shift 2 ;;
    --build-dir)   BUILD_DIR="$2";     shift 2 ;;
    --static-src)  STATIC_SRC="$2";    shift 2 ;;
    --unit-src)    UNIT_SRC="$2";      shift 2 ;;
    --bin-dir)     BIN_DIR="$2";       shift 2 ;;
    --static-dir)  STATIC_DIR="$2";    shift 2 ;;
    --config-dir)  CONFIG_DIR="$2";    shift 2 ;;
    --user)        SERVICE_USER="$2";  shift 2 ;;
    --no-enable)   NO_ENABLE=true;     shift   ;;
    --force)       FORCE=true;         shift   ;;
    -h|--help)     usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

die()  { echo "install-hub: error: $*" >&2; exit 1; }
note() { echo "install-hub: $*"; }

# --- validation
[[ -n "$DOMAIN" ]] || die "--domain is required"
[[ -n "$EMAIL"  ]] || die "--email is required"
[[ -z "$RP_ID"  ]] && RP_ID="$DOMAIN"
[[ "$TLS" == "acme" || "$TLS" == "off" ]] || die "--tls must be acme or off"
[[ "$DOMAIN" == *"$RP_ID" || "$DOMAIN" == "$RP_ID" ]] \
  || die "rp_id ($RP_ID) must be a suffix of domain ($DOMAIN)"

[[ "$(id -u)" -eq 0 ]] || die "must run as root (try: sudo $0 ...)"
[[ -x "$BUILD_DIR/term-hub"  ]] || die "missing $BUILD_DIR/term-hub  (run: cargo build --release)"
[[ -x "$BUILD_DIR/hub-admin" ]] || die "missing $BUILD_DIR/hub-admin (run: cargo build --release)"
[[ -d "$STATIC_SRC"          ]] || die "missing $STATIC_SRC (frontend assets)"
[[ -f "$UNIT_SRC"            ]] || die "missing $UNIT_SRC (systemd unit)"

# --- service user
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  note "creating user $SERVICE_USER"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# --- binaries
note "installing binaries -> $BIN_DIR"
install -m 755 "$BUILD_DIR/term-hub"  "$BIN_DIR/"
install -m 755 "$BUILD_DIR/hub-admin" "$BIN_DIR/"

# --- static assets
note "installing static assets -> $STATIC_DIR"
rm -rf "$STATIC_DIR"
mkdir -p "$STATIC_DIR"
cp -r "$STATIC_SRC/." "$STATIC_DIR/"

# --- config dir
note "ensuring config dir -> $CONFIG_DIR"
mkdir -p "$CONFIG_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR"
chmod 0750 "$CONFIG_DIR"

# --- hub.toml
CONFIG_PATH="$CONFIG_DIR/hub.toml"
if [[ -e "$CONFIG_PATH" ]] && ! $FORCE; then
  note "$CONFIG_PATH exists; not overwriting (use --force to replace)"
else
  note "writing $CONFIG_PATH"
  acme_email_line=""
  bind_line=""
  if [[ "$TLS" == "acme" ]]; then
    acme_email_line="acme_email      = \"$EMAIL\""
  fi
  if [[ -n "$BIND" ]]; then
    bind_line="bind            = \"$BIND\""
  fi
  cat > "$CONFIG_PATH" <<EOF
## generated by scripts/install-hub.sh on $(date -Is)
domain          = "$DOMAIN"
rp_id           = "$RP_ID"
rp_name         = "$RP_NAME"

tls             = "$TLS"
$acme_email_line
acme_production = $PROD

data_dir        = "$DATA_DIR"
$bind_line
agent_bind      = "$AGENT_BIND"

## add machines with: sudo scripts/add-machine.sh --id ID --label LABEL
EOF
  # strip the empty optional lines and tidy
  sed -i '/^$/N;/^\n$/D' "$CONFIG_PATH"
  chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_PATH"
  chmod 0640 "$CONFIG_PATH"
fi

# --- state dir
mkdir -p "$DATA_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
chmod 0750 "$DATA_DIR"

# --- systemd unit + static-dir drop-in
note "installing systemd unit"
install -m 644 "$UNIT_SRC" /etc/systemd/system/term-hub.service
mkdir -p /etc/systemd/system/term-hub.service.d
cat > /etc/systemd/system/term-hub.service.d/static.conf <<EOF
[Service]
Environment=TERM_HUB_STATIC_DIR=$STATIC_DIR
EOF

systemctl daemon-reload
if ! $NO_ENABLE; then
  note "enabling + starting term-hub.service"
  systemctl enable --now term-hub.service
  sleep 1
  systemctl --no-pager --full status term-hub.service | head -20 || true
fi

note "done."
cat <<EOF

next:
  - tail logs:  sudo journalctl -fu term-hub.service
  - add a machine: sudo scripts/add-machine.sh --id alpha --label alpha.lan
  - then on each agent host, run:
      sudo scripts/install-agent.sh --hub $DOMAIN:7700 --machine-id alpha --psk <PSK>
EOF
