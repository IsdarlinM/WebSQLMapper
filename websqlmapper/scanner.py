from __future__ import annotations

from difflib import SequenceMatcher
from statistics import median
from typing import Iterable

from .models import Finding, RequestConfig, ResponseSnapshot, ScanReport
from .payloads import BOOLEAN_PROBES, ERROR_SIGNATURES, SYNTAX_PROBES, TIME_PROBES
from .safety import require_authorization, validate_http_url
from .transport import HTTPClient


def _similarity(left: str, right: str) -> float:
    if left == right:
        return 1.0
    return SequenceMatcher(None, left[:200_000], right[:200_000], autojunk=True).ratio()


def _db_error_hints(text: str) -> list[str]:
    lowered = text.lower()
    return [dbms for dbms, patterns in ERROR_SIGNATURES.items() if any(p in lowered for p in patterns)]


def _snapshot_summary(snapshot: ResponseSnapshot) -> dict[str, object]:
    return {
        "status": snapshot.status,
        "length": snapshot.length,
        "elapsed_ms": round(snapshot.elapsed * 1000, 2),
        "error": snapshot.error,
    }


class SQLiScanner:
    def __init__(self, client: HTTPClient | None = None) -> None:
        self.client = client or HTTPClient()

    def scan(
        self,
        config: RequestConfig,
        *,
        original_value: str = "1",
        authorized: bool = False,
        time_probes: bool = False,
        dbms: Iterable[str] | None = None,
    ) -> ScanReport:
        require_authorization(authorized)
        validate_http_url(config.url)
        errors: list[str] = []
        findings: list[Finding] = []
        tested = 0

        baselines = [self.client.request(config, original_value) for _ in range(2)]
        baseline = baselines[-1]
        if any(item.status == 0 for item in baselines):
            errors.extend(item.error or "request failed" for item in baselines if item.status == 0)

        baseline_len = median(item.length for item in baselines)
        baseline_time = median(item.elapsed for item in baselines)

        for payload in SYNTAX_PROBES:
            tested += 1
            response = self.client.request(config, original_value + payload)
            hints = _db_error_hints(response.body)
            new_hints = [hint for hint in hints if hint not in _db_error_hints(baseline.body)]
            status_changed = response.status != baseline.status and response.status >= 500
            sim = _similarity(baseline.body, response.body)
            if new_hints or status_changed:
                findings.append(
                    Finding(
                        category="error-based-indicator",
                        title="Database error behavior changed after SQL syntax probe",
                        confidence="medium" if new_hints else "low",
                        payload=payload,
                        dbms_hint=new_hints[0] if new_hints else None,
                        evidence={
                            "baseline": _snapshot_summary(baseline),
                            "probe": _snapshot_summary(response),
                            "similarity": round(sim, 4),
                            "db_error_hints": new_hints,
                        },
                    )
                )

        for pair in BOOLEAN_PROBES:
            tested += 2
            true_response = self.client.request(config, original_value + pair.true_payload)
            false_response = self.client.request(config, original_value + pair.false_payload)
            true_to_base = _similarity(true_response.body, baseline.body)
            false_to_base = _similarity(false_response.body, baseline.body)
            true_false = _similarity(true_response.body, false_response.body)
            len_gap = abs(true_response.length - false_response.length)
            status_gap = true_response.status != false_response.status
            convincing = (true_to_base - false_to_base >= 0.16 and true_false <= 0.84) or status_gap
            moderate = (true_to_base - false_to_base >= 0.08 and true_false <= 0.92) or len_gap >= max(32, baseline_len * 0.15)
            if convincing or moderate:
                findings.append(
                    Finding(
                        category="boolean-based-indicator",
                        title=f"True/false SQL conditions produced distinguishable responses ({pair.name})",
                        confidence="high" if convincing else "medium",
                        payload=f"TRUE: {pair.true_payload} | FALSE: {pair.false_payload}",
                        evidence={
                            "context": pair.context,
                            "baseline": _snapshot_summary(baseline),
                            "true": _snapshot_summary(true_response),
                            "false": _snapshot_summary(false_response),
                            "true_to_baseline_similarity": round(true_to_base, 4),
                            "false_to_baseline_similarity": round(false_to_base, 4),
                            "true_false_similarity": round(true_false, 4),
                        },
                    )
                )

        if time_probes:
            selected = list(dbms or TIME_PROBES.keys())
            for name in selected:
                payload = TIME_PROBES.get(name)
                if not payload:
                    continue
                tested += 1
                response = self.client.request(config, original_value + payload)
                delay = response.elapsed - baseline_time
                if delay >= 1.25:
                    findings.append(
                        Finding(
                            category="time-based-indicator",
                            title=f"Response delay consistent with a {name} time probe",
                            confidence="medium",
                            payload=payload,
                            dbms_hint=name,
                            evidence={
                                "baseline_elapsed_ms": round(baseline_time * 1000, 2),
                                "probe_elapsed_ms": round(response.elapsed * 1000, 2),
                                "delta_ms": round(delay * 1000, 2),
                            },
                        )
                    )

        return ScanReport(
            target=config.url,
            method=config.method.upper(),
            parameter=config.parameter,
            baseline={
                "status": baseline.status,
                "median_length": int(baseline_len),
                "median_elapsed_ms": round(baseline_time * 1000, 2),
            },
            findings=findings,
            tested_payloads=tested,
            errors=errors,
        )
