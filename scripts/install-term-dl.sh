#!/usr/bin/env bash
# Install term-dl on this host. Tiny — just copies the binary into a
# directory on the operator's PATH so they can run `term-dl <path>`
# from any shell that's attached to a term-agent session.
#
# Run after `scripts/install-agent.sh` (which already ships term-dl
# alongside term-agent) only if you want term-dl on additional hosts
# without a full agent install (e.g. a developer workstation that
# logs into the agent host).
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --build-dir DIR   where target/release lives  (default: ./target/release)
  --bin-dir DIR    install binary here          (default: /usr/local/bin)
  --force          overwrite an existing binary
  -h, --help
EOF
}

BUILD_DIR="./target/release"
BIN_DIR="/usr/local/bin"
FORCE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir) BUILD_DIR="$2"; shift 2 ;;
    --bin-dir)   BIN_DIR="$2";   shift 2 ;;
    --force)     FORCE=true;     shift   ;;
    -h|--help)   usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

die()  { echo "install-term-dl: error: $*" >&2; exit 1; }
note() { echo "install-term-dl: $*"; }

[[ -x "$BUILD_DIR/term-dl" ]] || die "missing $BUILD_DIR/term-dl (run: cargo build --release)"

# We need write access to BIN_DIR. /usr/local/bin almost always
# requires root; /home/$USER/.local/bin etc. don't. Try the install
# unprivileged first; suggest sudo on failure.
TARGET="$BIN_DIR/term-dl"
if [[ -e "$TARGET" && "$FORCE" != "true" ]]; then
  die "$TARGET exists; pass --force to overwrite"
fi

if ! install -m 755 "$BUILD_DIR/term-dl" "$TARGET" 2>/dev/null; then
  if [[ "$EUID" -ne 0 ]]; then
    note "non-root install failed; re-running via sudo"
    sudo install -m 755 "$BUILD_DIR/term-dl" "$TARGET"
  else
    die "install -m 755 $BUILD_DIR/term-dl $TARGET failed"
  fi
fi

note "installed $TARGET"
note "from a shell attached to a term-agent session, run:  term-dl <path>"
note "(requires TERM_DL_TOKEN in the env, which the agent sets automatically)"
