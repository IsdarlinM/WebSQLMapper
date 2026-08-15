#!/usr/bin/env bash
set -Eeuo pipefail
INSTALL_ROOT="${WEBSQLMAPPER_INSTALL_ROOT:-$HOME/.websqlmapper}"
BIN_DIR="${WEBSQLMAPPER_BIN_DIR:-$HOME/.local/bin}"
rm -rf "$INSTALL_ROOT"
rm -f "$BIN_DIR/websqlmapper"
printf '[WebSQLMapper] Runtime removed. User templates/config under ~/.config/websqlmapper are preserved.\n'
