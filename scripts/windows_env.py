from __future__ import annotations

import argparse
import os
import sys
from typing import Iterable

try:
    import winreg  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - only unavailable outside Windows
    winreg = None  # type: ignore[assignment]


def _normalized(entry: str) -> str:
    value = os.path.expandvars(entry.strip().strip('"')).replace("/", "\\")
    while len(value) > 3 and value.endswith("\\"):
        value = value[:-1]
    return value.casefold()


def merge_path(current: str, entry: str) -> str:
    """Append *entry* once while preserving the user's existing PATH text."""
    existing = [part.strip() for part in current.split(";") if part.strip()]
    wanted = _normalized(entry)
    if wanted and all(_normalized(part) != wanted for part in existing):
        existing.append(entry)
    return ";".join(existing)


def configure_user_environment(home: str, bin_dir: str) -> None:
    if winreg is None:
        raise RuntimeError("Windows registry support is unavailable on this platform")
    access = winreg.KEY_READ | winreg.KEY_SET_VALUE
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, "Environment", 0, access) as key:
        try:
            current_path, current_type = winreg.QueryValueEx(key, "Path")
        except FileNotFoundError:
            current_path, current_type = "", winreg.REG_EXPAND_SZ
        if current_type not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
            current_type = winreg.REG_EXPAND_SZ
        winreg.SetValueEx(key, "Path", 0, current_type, merge_path(str(current_path), bin_dir))
        winreg.SetValueEx(key, "WEBSQLMAPPER_HOME", 0, winreg.REG_SZ, home)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Configure WebSQLMapper user environment on Windows")
    parser.add_argument("--home", required=True)
    parser.add_argument("--bin", dest="bin_dir", required=True)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    try:
        configure_user_environment(os.path.abspath(args.home), os.path.abspath(args.bin_dir))
    except (OSError, RuntimeError) as exc:
        print(f"WebSQLMapper environment setup failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
