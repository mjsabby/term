#!/usr/bin/env bash
# Build all three binaries in release mode and report where they landed.
set -euo pipefail

cd "$(dirname "$0")/.."

PROFILE="release"
JOBS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --debug)  PROFILE="dev";  shift ;;
    --jobs|-j) JOBS="-j$2";   shift 2 ;;
    -h|--help)
      cat <<EOF
Usage: $0 [--debug] [-j N]
Builds term-hub, term-agent, hub-admin in release (default) or debug.
EOF
      exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if ! command -v cargo >/dev/null 2>&1; then
  echo "build: cargo not found" >&2
  exit 1
fi

if [[ "$PROFILE" == "release" ]]; then
  # shellcheck disable=SC2086
  cargo build --workspace --release $JOBS
  DIR="target/release"
else
  # shellcheck disable=SC2086
  cargo build --workspace $JOBS
  DIR="target/debug"
fi

echo
echo "built:"
for b in term-hub term-agent hub-admin; do
  if [[ -x "$DIR/$b" ]]; then
    printf '  %-12s %s (%s)\n' "$b" "$DIR/$b" "$(du -h "$DIR/$b" | cut -f1)"
  else
    echo "  MISSING: $DIR/$b" >&2
  fi
done
