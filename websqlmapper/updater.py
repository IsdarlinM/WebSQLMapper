from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _run(command: list[str], cwd: Path) -> str:
    try:
        result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"cannot execute {' '.join(command)}: {exc}") from exc
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "command failed").strip()
        raise RuntimeError(f"{' '.join(command)} failed: {message}")
    return result.stdout.strip()


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def update_installation(*, force: bool = False, branch: str = "main") -> list[str]:
    root = project_root()
    if not (root / ".git").exists():
        raise RuntimeError("this installation is not a Git checkout; reinstall from the repository to enable update")
    status = _run(["git", "status", "--porcelain"], root)
    if status and not force:
        raise RuntimeError("local installation has uncommitted changes; use --force only if you intend to discard them")
    if status and force:
        _run(["git", "reset", "--hard", "HEAD"], root)
    _run(["git", "fetch", "origin", branch], root)
    _run(["git", "merge", "--ff-only", f"origin/{branch}"], root)
    _run([sys.executable, "-m", "pip", "install", "-e", str(root)], root)
    return ["repository updated with fast-forward", "package reinstalled in the active environment"]
