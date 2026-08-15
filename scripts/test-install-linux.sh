#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
HOME="$TMP/home" WEBSQLMAPPER_INSTALL_ROOT="$TMP/install" WEBSQLMAPPER_BIN_DIR="$TMP/bin" WEBSQLMAPPER_SKIP_PATH=1 WEBSQLMAPPER_OFFLINE_TEST=1 \
  bash "$ROOT/scripts/install-linux.sh"
PATH="$TMP/bin:$PATH" "$TMP/bin/websqlmapper" --version
PATH="$TMP/bin:$PATH" "$TMP/bin/websqlmapper" --color never doctor
