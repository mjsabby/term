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

  --tls MODE               "acme" | "files" | "off"   (default: acme)
  --prod                   use Let's Encrypt production (default: staging)
  --cert PATH              tls=files: PEM cert chain
                           (default: /etc/ssl/certupdater/<domain>.fullchain.pem)
  --key PATH               tls=files: PEM private key
                           (default: /etc/ssl/certupdater/<domain>.key.pem)
  --reload-secs N          tls=files: re-read cadence in seconds
                           (default: 3600 = 1 hour)

  --bind ADDR              browser bind             (default unset)
  --agent-bind ADDR        agent listener bind      (default: [::]:7700)
  --public-origin ORIGIN   override WebAuthn origin (default: https://DOMAIN)
                           For tls=off local dev:   "http://localhost:8080"
  --data-dir DIR           hub state                (default: /var/lib/term-hub)

  --no-auth-bind ADDR      enable the second no-auth listener on this address
                           (e.g. [::]:8080). Plain HTTP only — intended to be
                           fronted by an external perimeter (Microsoft Dev
                           Tunnel, SSO reverse proxy, ...).
  --no-auth-origin ORIGIN  REQUIRED with --no-auth-bind. Public URL of the
                           perimeter, e.g. https://abc-8080.devtunnels.ms.
                           Used for the WS Origin: check on that listener.

  --build-dir DIR          where target/release lives (default: ./target/release)
  --unit-src FILE          systemd unit source        (default: ./systemd/term-hub.service)

  --bin-dir DIR            install binaries here    (default: /usr/local/bin)
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
CERT_PATH=""
KEY_PATH=""
RELOAD_SECS=""
BIND=""
AGENT_BIND="[::]:7700"
PUBLIC_ORIGIN=""
NO_AUTH_BIND=""
NO_AUTH_ORIGIN=""
DATA_DIR="/var/lib/term-hub"

BUILD_DIR="./target/release"
UNIT_SRC="./systemd/term-hub.service"

BIN_DIR="/usr/local/bin"
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
    --cert)        CERT_PATH="$2";     shift 2 ;;
    --key)         KEY_PATH="$2";      shift 2 ;;
    --reload-secs) RELOAD_SECS="$2";   shift 2 ;;
    --bind)        BIND="$2";          shift 2 ;;
    --agent-bind)  AGENT_BIND="$2";    shift 2 ;;
    --public-origin) PUBLIC_ORIGIN="$2"; shift 2 ;;
    --no-auth-bind)   NO_AUTH_BIND="$2";   shift 2 ;;
    --no-auth-origin) NO_AUTH_ORIGIN="$2"; shift 2 ;;
    --data-dir)    DATA_DIR="$2";      shift 2 ;;
    --build-dir)   BUILD_DIR="$2";     shift 2 ;;
    --unit-src)    UNIT_SRC="$2";      shift 2 ;;
    --bin-dir)     BIN_DIR="$2";       shift 2 ;;
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
[[ -z "$RP_ID"  ]] && RP_ID="$DOMAIN"
[[ "$TLS" == "acme" || "$TLS" == "files" || "$TLS" == "off" ]] || die "--tls must be acme, files, or off"
[[ "$TLS" == "acme" && -z "$EMAIL" ]] && die "--email is required when --tls acme"
if [[ "$TLS" == "files" ]]; then
  [[ -z "$CERT_PATH" ]] && CERT_PATH="/etc/ssl/certupdater/${DOMAIN}.fullchain.pem"
  [[ -z "$KEY_PATH"  ]] && KEY_PATH="/etc/ssl/certupdater/${DOMAIN}.key.pem"
  [[ -f "$CERT_PATH" ]] || die "cert not readable: $CERT_PATH"
  [[ -f "$KEY_PATH"  ]] || die "key not readable: $KEY_PATH"
fi
if [[ -n "$RELOAD_SECS" && ! "$RELOAD_SECS" =~ ^[0-9]+$ ]]; then
  die "--reload-secs must be a positive integer"
fi
if [[ -n "$NO_AUTH_BIND" && -z "$NO_AUTH_ORIGIN" ]]; then
  die "--no-auth-bind requires --no-auth-origin (the perimeter URL for WS Origin: check)"
fi
if [[ -z "$NO_AUTH_BIND" && -n "$NO_AUTH_ORIGIN" ]]; then
  die "--no-auth-origin requires --no-auth-bind"
fi
[[ "$DOMAIN" == *"$RP_ID" || "$DOMAIN" == "$RP_ID" ]] \
  || die "rp_id ($RP_ID) must be a suffix of domain ($DOMAIN)"

[[ "$(id -u)" -eq 0 ]] || die "must run as root (try: sudo $0 ...)"
[[ -x "$BUILD_DIR/term-hub"  ]] || die "missing $BUILD_DIR/term-hub  (run: cargo build --release)"
[[ -x "$BUILD_DIR/hub-admin" ]] || die "missing $BUILD_DIR/hub-admin (run: cargo build --release)"
[[ -f "$UNIT_SRC"            ]] || die "missing $UNIT_SRC (systemd unit)"

# --- service user
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  note "creating user $SERVICE_USER"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# --- binaries (term-hub is self-contained: the SPA is embedded)
note "installing binaries -> $BIN_DIR"
install -m 755 "$BUILD_DIR/term-hub"  "$BIN_DIR/"
install -m 755 "$BUILD_DIR/hub-admin" "$BIN_DIR/"

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
  public_origin_line=""
  cert_line=""
  key_line=""
  reload_line=""
  if [[ "$TLS" == "acme" ]]; then
    acme_email_line="acme_email      = \"$EMAIL\""
  fi
  if [[ "$TLS" == "files" ]]; then
    cert_line="cert_path       = \"$CERT_PATH\""
    key_line="key_path        = \"$KEY_PATH\""
    [[ -n "$RELOAD_SECS" ]] && reload_line="tls_reload_interval_secs = $RELOAD_SECS"
  fi
  if [[ -n "$BIND" ]]; then
    bind_line="bind            = \"$BIND\""
  fi
  if [[ -n "$PUBLIC_ORIGIN" ]]; then
    public_origin_line="public_origin   = \"$PUBLIC_ORIGIN\""
  fi
  no_auth_block=""
  if [[ -n "$NO_AUTH_BIND" ]]; then
    no_auth_block=$(cat <<EONA

[no_auth]
bind          = "$NO_AUTH_BIND"
public_origin = "$NO_AUTH_ORIGIN"
EONA
)
  fi
  cat > "$CONFIG_PATH" <<EOF
## generated by scripts/install-hub.sh on $(date -Is)
domain          = "$DOMAIN"
rp_id           = "$RP_ID"
rp_name         = "$RP_NAME"

tls             = "$TLS"
$acme_email_line
acme_production = $PROD
$cert_line
$key_line
$reload_line

data_dir        = "$DATA_DIR"
$bind_line
agent_bind      = "$AGENT_BIND"
$public_origin_line
$no_auth_block

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

# --- systemd unit + drop-in (service user)
note "installing systemd unit"
install -m 644 "$UNIT_SRC" /etc/systemd/system/term-hub.service
mkdir -p /etc/systemd/system/term-hub.service.d
# Always override User=/Group= via drop-in so the unit file stays generic
# and the chosen --user is what actually runs.
cat > /etc/systemd/system/term-hub.service.d/user.conf <<EOF
[Service]
User=$SERVICE_USER
Group=$SERVICE_USER
EOF
# Old installs may have a stale TERM_HUB_STATIC_DIR drop-in from when
# static assets were served off disk; clean it up.
rm -f /etc/systemd/system/term-hub.service.d/static.conf

systemctl daemon-reload
if ! $NO_ENABLE; then
  note "enabling + (re)starting term-hub.service"
  systemctl enable term-hub.service
  systemctl restart term-hub.service
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
