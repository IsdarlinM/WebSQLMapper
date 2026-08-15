from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from .models import RequestConfig


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def template_dir() -> Path:
    if os.name == "nt":
        base = Path(os.getenv("APPDATA") or Path.home() / "AppData" / "Roaming")
        return base / "WebSQLMapper" / "templates"
    base = Path(os.getenv("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "websqlmapper" / "templates"


def _path(name: str) -> Path:
    if not _NAME.fullmatch(name):
        raise ValueError("template name may contain only letters, digits, dot, underscore, and hyphen")
    return template_dir() / f"{name}.json"


def save_template(name: str, config: RequestConfig) -> Path:
    path = _path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = config.clone_dict()
    # Do not persist authentication secrets by default.
    data["auth_password"] = None
    data["bearer_token"] = None
    data["cookies"] = {}
    for key in list(data.get("headers", {})):
        if key.lower() in {"authorization", "cookie", "x-api-key", "api-key"}:
            data["headers"][key] = "<redacted>"
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def load_template(name: str) -> RequestConfig:
    path = _path(name)
    try:
        data: Any = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"template not found: {name}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load template {name}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"template {name} is invalid")
    allowed = set(RequestConfig.__dataclass_fields__)
    return RequestConfig(**{key: value for key, value in data.items() if key in allowed})


def list_templates() -> list[str]:
    root = template_dir()
    if not root.exists():
        return []
    return sorted(path.stem for path in root.glob("*.json") if path.is_file())


def delete_template(name: str) -> None:
    path = _path(name)
    try:
        path.unlink()
    except FileNotFoundError as exc:
        raise ValueError(f"template not found: {name}") from exc
