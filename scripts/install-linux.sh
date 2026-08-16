#!/usr/bin/env bash
set -Eeuo pipefail
PRODUCT="WebSQLMapper"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
INSTALL_ROOT="${WEBSQLMAPPER_INSTALL_ROOT:-$HOME/.websqlmapper}"
SRC_DIR="$INSTALL_ROOT/src"; VENV_DIR="$INSTALL_ROOT/venv"; BIN_DIR="${WEBSQLMAPPER_BIN_DIR:-$HOME/.local/bin}"; WRAPPER="$BIN_DIR/websqlmapper"
log(){ printf '[%s] %s\n' "$PRODUCT" "$*"; }; fail(){ printf '[%s] ERROR: %s\n' "$PRODUCT" "$*" >&2; exit 1; }; have(){ command -v "$1" >/dev/null 2>&1; }
as_root(){ if [ "$(id -u)" -eq 0 ]; then "$@"; elif have sudo; then sudo "$@"; else fail "Root privileges are required to install system packages: $*"; fi; }
python_ok(){ "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)' >/dev/null 2>&1; }
python_mm(){ "$1" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'; }
find_python(){ local c; for c in python3 python python3.14 python3.13 python3.12 python3.11 python3.10; do if have "$c" && python_ok "$c"; then printf '%s' "$c"; return 0; fi; done; return 1; }
install_system_dependencies(){
  log "Installing required system dependencies (Python >=3.10, venv/pip support, Git)."
  if have pkg && printf '%s' "${PREFIX:-}" | grep -qi 'com.termux'; then pkg update -y && pkg install -y python git
  elif have apt-get; then as_root apt-get update; as_root apt-get install -y python3 python3-venv python3-pip git ca-certificates
  elif have dnf; then as_root dnf install -y python3 python3-pip git ca-certificates
  elif have pacman; then as_root pacman -Sy --needed --noconfirm python python-pip git ca-certificates
  elif have apk; then as_root apk add --no-cache python3 py3-pip py3-virtualenv git ca-certificates
  elif have brew; then brew install python git
  else fail "No supported package manager found. Install Python >=3.10 and Git, then rerun this installer."; fi
}
PYTHON="$(find_python || true)"; if [ -z "$PYTHON" ] || ! have git; then install_system_dependencies; PYTHON="$(find_python || true)"; fi
[ -n "$PYTHON" ] || fail "Python >=3.10 is unavailable after dependency installation."
if ! "$PYTHON" -m venv --help >/dev/null 2>&1; then if have apt-get; then as_root apt-get install -y python3-venv; fi; fi
SELECTED_MM="$(python_mm "$PYTHON")"; log "Using existing compatible interpreter: $($PYTHON --version 2>&1)"
mkdir -p "$INSTALL_ROOT" "$BIN_DIR"; TMP_SRC="$INSTALL_ROOT/src.new.$$"; rm -rf "$TMP_SRC"; mkdir -p "$TMP_SRC"
(cd "$SOURCE_ROOT" && tar --exclude='./.venv' --exclude='./.pytest_cache' --exclude='*/__pycache__' --exclude='*.pyc' -cf - .) | tar -xf - -C "$TMP_SRC"
rm -rf "$SRC_DIR"; mv "$TMP_SRC" "$SRC_DIR"; rm -rf "$VENV_DIR"; "$PYTHON" -m venv "$VENV_DIR" || fail "Failed to create virtual environment at $VENV_DIR"
VENV_MM="$(python_mm "$VENV_DIR/bin/python")"; [ "$SELECTED_MM" = "$VENV_MM" ] || fail "Virtual environment Python $VENV_MM does not match selected Python $SELECTED_MM"
install_source_fallback(){
  log "Using source-path runtime fallback with Python $SELECTED_MM."
  if ! "$VENV_DIR/bin/python" -c 'import requests; p=tuple(int(x) for x in requests.__version__.split(".")[:2]); raise SystemExit(0 if p >= (2,32) else 1)' >/dev/null 2>&1; then
    if "$PYTHON" -c 'import requests; p=tuple(int(x) for x in requests.__version__.split(".")[:2]); raise SystemExit(0 if p >= (2,32) else 1)' >/dev/null 2>&1; then rm -rf "$VENV_DIR"; "$PYTHON" -m venv --system-site-packages "$VENV_DIR" || fail "Failed to create fallback virtual environment."
    else "$VENV_DIR/bin/python" -m pip install 'requests>=2.32,<3' || fail "Could not install requests and no compatible system copy exists."; fi
  fi
  SITE_DIR="$("$VENV_DIR/bin/python" -c 'import site; print(site.getsitepackages()[0])')"; printf '%s\n' "$SRC_DIR" > "$SITE_DIR/websqlmapper-source.pth"
  "$VENV_DIR/bin/python" -c 'import requests,websqlmapper' || fail "Source-path fallback verification failed."
}
if [ "${WEBSQLMAPPER_OFFLINE_TEST:-0}" = "1" ]; then install_source_fallback
else
  "$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel || log "WARNING: packaging-tool upgrade failed; continuing."
  if ! "$VENV_DIR/bin/python" -m pip install -e "$SRC_DIR[socks]"; then log "WARNING: optional SOCKS install failed; trying core package."; "$VENV_DIR/bin/python" -m pip install -e "$SRC_DIR" || install_source_fallback; fi
fi
cat > "$WRAPPER" <<EOF
#!/usr/bin/env sh
exec "$VENV_DIR/bin/python" -m websqlmapper "\$@"
EOF
chmod +x "$WRAPPER"
append_env(){ local rc="$1"; [ -e "$rc" ] || touch "$rc"; if ! grep -Fq '# WebSQLMapper environment' "$rc"; then { printf '\n# WebSQLMapper environment\n'; printf 'export WEBSQLMAPPER_HOME=%q\n' "$INSTALL_ROOT"; printf 'export PATH=%q:"$PATH"\n' "$BIN_DIR"; } >> "$rc"; fi; }
if [ "${WEBSQLMAPPER_SKIP_PATH:-0}" != "1" ]; then append_env "$HOME/.profile"; case "${SHELL:-}" in */bash) append_env "$HOME/.bashrc";; */zsh) append_env "$HOME/.zshrc";; esac; fi
export WEBSQLMAPPER_HOME="$INSTALL_ROOT"; export PATH="$BIN_DIR:$PATH"; "$WRAPPER" --version >/dev/null || fail "Installed command failed its version check."
ACTUAL_MM="$(python_mm "$VENV_DIR/bin/python")"; [ "$ACTUAL_MM" = "$SELECTED_MM" ] || fail "Post-install interpreter changed unexpectedly."
log "Installation verified with Python $ACTUAL_MM."; log "Command: websqlmapper"; log "Home: $INSTALL_ROOT"; log "PATH entry: $BIN_DIR"; log "Open a new shell or run: export PATH=\"$BIN_DIR:\$PATH\""
