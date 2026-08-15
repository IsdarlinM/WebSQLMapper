from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class RequestConfig:
    url: str
    method: str = "GET"
    parameter: str = "id"
    data: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body_mode: str = "auto"
    timeout: float = 8.0


@dataclass(slots=True)
class ResponseSnapshot:
    status: int
    body: str
    elapsed: float
    final_url: str
    headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None

    @property
    def length(self) -> int:
        return len(self.body.encode("utf-8", errors="replace"))


@dataclass(slots=True)
class Finding:
    category: str
    title: str
    confidence: str
    payload: str
    evidence: dict[str, Any]
    dbms_hint: str | None = None


@dataclass(slots=True)
class ScanReport:
    target: str
    method: str
    parameter: str
    baseline: dict[str, Any]
    findings: list[Finding]
    tested_payloads: int
    errors: list[str] = field(default_factory=list)

    @property
    def likely_vulnerable(self) -> bool:
        return any(f.confidence in {"high", "medium"} for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["likely_vulnerable"] = self.likely_vulnerable
        return result
