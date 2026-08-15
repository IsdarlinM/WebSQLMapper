#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
EXPECTED_MM="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
mkdir -p "$TMP/home"
HOME="$TMP/home" WEBSQLMAPPER_INSTALL_ROOT="$TMP/install" WEBSQLMAPPER_BIN_DIR="$TMP/bin" WEBSQLMAPPER_SKIP_PATH=1 \
  bash "$ROOT/scripts/install-linux.sh"
ACTUAL_MM="$("$TMP/install/venv/bin/python" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
[ "$ACTUAL_MM" = "$EXPECTED_MM" ] || { echo "Expected installer Python $EXPECTED_MM, got $ACTUAL_MM" >&2; exit 1; }
PATH="$TMP/bin:$PATH" "$TMP/bin/websqlmapper" --version
PATH="$TMP/bin:$PATH" "$TMP/bin/websqlmapper" --color never doctor
"$TMP/install/venv/bin/python" -c 'import requests, websqlmapper; print("online installer imports: OK")'
