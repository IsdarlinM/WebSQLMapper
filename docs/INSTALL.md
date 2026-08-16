# WebSQLMapper v0.4.0 installation

WebSQLMapper requires **Python 3.10 or newer** and has no upper Python version bound. The installers prefer an already installed compatible interpreter and install dependencies into a virtual environment created by that same Python `major.minor`.

## Linux / Unix / Termux

```bash
bash scripts/install-linux.sh
```

The installer searches for a compatible `python3`, `python`, and versioned Python 3.10+ command. If Python or Git is missing it can bootstrap system packages with Termux `pkg`, `apt`, `dnf`, `pacman`, `apk`, or Homebrew.

It then:

1. records the selected Python major/minor;
2. copies the project under `$WEBSQLMAPPER_INSTALL_ROOT` or `~/.websqlmapper`;
3. creates a venv with the selected interpreter;
4. verifies the venv major/minor is identical;
5. installs packaging tools and `websqlmapper[socks]` where available;
6. falls back to core installation when optional SOCKS support cannot be resolved;
7. has a source-path fallback for restricted/offline environments when a compatible Requests installation is already available;
8. writes a `websqlmapper` wrapper;
9. appends `WEBSQLMAPPER_HOME` and the command directory to supported shell startup files;
10. runs a post-install version check.

Environment overrides useful for testing/automation:

```text
WEBSQLMAPPER_INSTALL_ROOT
WEBSQLMAPPER_BIN_DIR
WEBSQLMAPPER_SKIP_PATH=1
WEBSQLMAPPER_OFFLINE_TEST=1
```

The offline mode never changes the selected Python version.

## Windows CMD

```bat
scripts\install.cmd
```

The installer is pure CMD. It checks real `sys.version_info` rather than trusting executable names. Candidate order includes `python`, `python3`, the Windows `py` launcher, version-specific launcher targets, and standard local Python install paths.

If no compatible Python exists, `winget` first attempts Python 3.13 and then Python 3.10 as a fallback. Git is also bootstrapped through `winget` when possible because the update command uses Git.

The Windows installer:

1. selects Python >=3.10;
2. records its major/minor;
3. copies the source into `%LOCALAPPDATA%\WebSQLMapper` by default;
4. creates `%INSTALL_ROOT%\venv` using that exact interpreter;
5. verifies the venv version matches the selected version;
6. installs dependencies using `%VENV_DIR%\Scripts\python.exe -m pip`;
7. creates `%INSTALL_ROOT%\bin\websqlmapper.cmd`;
8. persists `WEBSQLMAPPER_HOME`;
9. appends the command directory to the **user** PATH;
10. executes `websqlmapper --version` as a final verification.

If Python is missing and `winget` is unavailable, the installer stops with an explicit error rather than using an unsupported runtime.

## Dependencies

Core runtime:

```text
Python >=3.10
requests >=2.32,<3
```

Optional SOCKS proxy support:

```text
PySocks >=1.7.1,<2
```

The application itself does not require Node.js, Java, Go, Rust, or another runtime language.

## Uninstall

Linux:

```bash
bash scripts/uninstall-linux.sh
```

Windows:

```bat
scripts\uninstall.cmd
```

## Installer verification

Linux smoke:

```bash
bash scripts/test-install-linux.sh
```

Network/package-index smoke:

```bash
bash scripts/test-install-linux-online.sh
```

Windows definitions:

```text
docker/Dockerfile.windows
scripts/test-windows-docker.cmd
.github/workflows/installers.yml
```

A Windows container requires a Windows Docker host capable of Windows containers; it cannot run on a Linux-only Docker daemon.
