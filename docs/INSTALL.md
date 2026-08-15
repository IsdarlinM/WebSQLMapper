# WebSQLMapper installation and runtime notes

This document describes the v0.3.0 installers and their failure behavior.

## Runtime requirements

WebSQLMapper requires:

- Python 3.11 or newer;
- `requests` 2.32 or newer and lower than 3.0;
- Git for the `websqlmapper update` command.

PySocks is optional and is needed only when a SOCKS proxy URL is selected. No Node.js, Java, Go, Rust, PHP, Ruby, or other programming language is required at runtime. The browser UI is static HTML/CSS/JavaScript served by the Python process.

## Linux installer

Run:

```bash
bash scripts/install-linux.sh
```

The script:

1. looks for Python 3.11+;
2. installs Python, pip/venv support and Git if they are missing and a supported package manager is available;
3. copies the project into `~/.websqlmapper/src`;
4. creates `~/.websqlmapper/venv`;
5. installs packaging tools and `websqlmapper[socks]`, falling back to core HTTP/HTTPS dependencies if optional SOCKS installation fails;
6. creates `~/.local/bin/websqlmapper`;
7. appends a `WebSQLMapper environment` block to the applicable user shell files;
8. exports `WEBSQLMAPPER_HOME` and prepends the command directory to `PATH` for the current installer process;
9. verifies `websqlmapper --version` before reporting success.

Supported package-manager discovery currently covers Termux `pkg`, `apt`, `dnf`, `pacman`, Alpine `apk`, and Homebrew.

`WEBSQLMAPPER_INSTALL_ROOT`, `WEBSQLMAPPER_BIN_DIR`, and `WEBSQLMAPPER_SKIP_PATH` are intended for controlled installation/testing environments.

## Windows CMD installer

Run from Command Prompt:

```bat
scripts\install.cmd
```

The script does not use PowerShell. It:

1. looks for Python 3.11+ through the Python launcher or `python`;
2. if Python is missing, attempts `winget install Python.Python.3.13`;
3. if Git is missing and winget is available, attempts `winget install Git.Git`;
4. copies the project to `%LOCALAPPDATA%\WebSQLMapper\src`;
5. creates an isolated venv;
6. installs dependencies, attempting optional SOCKS support first;
7. creates `%LOCALAPPDATA%\WebSQLMapper\bin\websqlmapper.cmd`;
8. persists `WEBSQLMAPPER_HOME` and appends the command directory to `HKCU\Environment\Path`;
9. verifies the command before success is printed.

Open a new Command Prompt after installation to inherit the updated user environment.

## Installer tests

Linux smoke:

```bash
bash scripts/test-install-linux.sh
```

Windows native smoke is executed by `.github/workflows/installers.yml` on `windows-latest`.

Windows-container smoke on a compatible Windows Docker host:

```bat
scripts\test-windows-docker.cmd
```

The Docker smoke checks that Docker reports Windows-container mode, then builds and runs `docker\Dockerfile.windows`.

## Uninstall

Linux:

```bash
bash scripts/uninstall-linux.sh
```

Windows:

```bat
scripts\uninstall.cmd
```

The uninstallers remove the runtime/wrapper and environment integration while preserving user configuration/templates.
