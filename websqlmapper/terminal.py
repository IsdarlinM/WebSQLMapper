from __future__ import annotations

import os
import sys
from dataclasses import dataclass


VERSION = "0.4.2"


@dataclass(frozen=True)
class Palette:
    reset: str = "\033[0m"
    bold: str = "\033[1m"
    dim: str = "\033[2m"
    green: str = "\033[38;5;78m"
    cyan: str = "\033[38;5;81m"
    yellow: str = "\033[38;5;220m"
    red: str = "\033[38;5;203m"
    gray: str = "\033[38;5;245m"


P = Palette()


def color_enabled(mode: str = "auto", stream=None) -> bool:
    if mode == "never" or os.getenv("NO_COLOR") is not None:
        return False
    if mode == "always":
        return True
    stream = stream or sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


def paint(text: str, *codes: str, enabled: bool = True) -> str:
    if not enabled:
        return text
    return "".join(codes) + text + P.reset


def banner(*, enabled: bool = True) -> str:
    title = paint("Web SQL Injector", P.bold, P.cyan, enabled=enabled)
    sig = paint(f"imr :: v{VERSION}", P.green, enabled=enabled)
    rule = paint("─" * 50, P.gray, enabled=enabled)
    return f"{rule}\n  {title}\n  {sig}\n{rule}"


def severity_color(score: int) -> str:
    if score >= 90:
        return P.red
    if score >= 75:
        return P.yellow
    if score >= 55:
        return P.cyan
    return P.gray
