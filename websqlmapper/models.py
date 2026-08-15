from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class RequestConfig:
    url: str
    method: str = "GET"
    parameter: str = "id"
    location: str = "auto"
    data: Any = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body_mode: str = "auto"
    raw_body: str | None = None
    timeout: float = 8.0
    proxy: str | None = None
    verify_tls: bool = True
    ca_bundle: str | None = None
    follow_redirects: bool = False
    auth_type: str | None = None
    auth_username: str | None = None
    auth_password: str | None = None
    bearer_token: str | None = None
    rate: float = 0.0
    delay_ms: int = 0
    jitter_ms: int = 0
    retries: int = 1

    def clone_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ResponseSnapshot:
    status: int
    body: str
    elapsed: float
    final_url: str
    headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    request_method: str = ""
    request_url: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str | None = None
    attempt: int = 1

    @property
    def length(self) -> int:
        return len(self.body.encode("utf-8", errors="replace"))


@dataclass(slots=True)
class Finding:
    category: str
    title: str
    confidence: str
    score: int
    payload: str
    evidence: dict[str, Any]
    dbms_hint: str | None = None


@dataclass(slots=True)
class RequestEvidence:
    index: int
    phase: str
    label: str
    status: int
    length: int
    elapsed_ms: float
    error: str | None
    method: str
    url: str
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str | None = None
    response_excerpt: str = ""


@dataclass(slots=True)
class ScanReport:
    target: str
    method: str
    parameter: str
    baseline: dict[str, Any]
    findings: list[Finding]
    tested_payloads: int
    confidence_score: int = 0
    verdict: str = "no-strong-indicator"
    detected_context: str | None = None
    dbms_profile: dict[str, float] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    reproducibility: int = 0
    injection_location: str = "auto"
    requests_sent: int = 0
    request_budget: int | None = None
    timeline: list[RequestEvidence] = field(default_factory=list)
    profile: str = "normal"
    stopped_early: bool = False
    context_profile: dict[str, object] = field(default_factory=dict)

    @property
    def likely_vulnerable(self) -> bool:
        return self.confidence_score >= 55

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["likely_vulnerable"] = self.likely_vulnerable
        return result
