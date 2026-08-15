#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

expected_python_mm(){
  local candidate
  for candidate in python3 python python3.14 python3.13 python3.12 python3.11 python3.10; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)' >/dev/null 2>&1; then
      "$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'
      return 0
    fi
  done
  return 1
}
EXPECTED_MM="$(expected_python_mm)"
HOME="$TMP/home" WEBSQLMAPPER_INSTALL_ROOT="$TMP/install" WEBSQLMAPPER_BIN_DIR="$TMP/bin" WEBSQLMAPPER_SKIP_PATH=1 WEBSQLMAPPER_OFFLINE_TEST=1 \
  bash "$ROOT/scripts/install-linux.sh"
ACTUAL_MM="$("$TMP/install/venv/bin/python" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
[ "$ACTUAL_MM" = "$EXPECTED_MM" ] || { echo "Expected installer Python $EXPECTED_MM, got $ACTUAL_MM" >&2; exit 1; }
PATH="$TMP/bin:$PATH" "$TMP/bin/websqlmapper" --version
PATH="$TMP/bin:$PATH" "$TMP/bin/websqlmapper" --color never doctor
