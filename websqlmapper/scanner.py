from __future__ import annotations

import re
from collections import Counter, defaultdict
from statistics import median
from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .analyzer import (
    BaselineProfile,
    cluster_similarity,
    confidence_from_score,
    cross_similarity,
    profile_baseline,
    similarity,
    unified_response_diff,
)
from .control import ScanCancelled, ScanControl
from .models import Finding, RequestConfig, RequestEvidence, ResponseSnapshot, ScanReport
from .payloads import BOOLEAN_PROBES, ERROR_SIGNATURES, SYNTAX_PROBES, TIME_PROBES
from .safety import require_authorization, validate_http_url
from .transport import HTTPClient, redact_text_secrets


_NUMBER = re.compile(r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$")
_SECRET_NAME = re.compile(r"(?i)(?:pass|secret|token|key|auth|session|cookie)")

_PROFILE_DEFAULTS = {
    "safe": {"baseline": 3, "rounds": 2, "max_requests": 80, "timing": False},
    "normal": {"baseline": 5, "rounds": 3, "max_requests": 160, "timing": False},
    "thorough": {"baseline": 7, "rounds": 4, "max_requests": 300, "timing": True},
}


class _BudgetReached(RuntimeError):
    pass


def _db_error_hints(text: str) -> list[str]:
    lowered = text.lower()
    return [dbms for dbms, patterns in ERROR_SIGNATURES.items() if any(p in lowered for p in patterns)]


def _snapshot_summary(snapshot: ResponseSnapshot) -> dict[str, object]:
    return {
        "status": snapshot.status,
        "length": snapshot.length,
        "elapsed_ms": round(snapshot.elapsed * 1000, 2),
        "error": snapshot.error,
        "attempt": snapshot.attempt,
    }


def _contexts(original_value: str, requested: str) -> list[str]:
    if requested not in {"auto", "numeric", "string"}:
        raise ValueError("context must be one of: auto, numeric, string")
    if requested != "auto":
        return [requested]
    return ["numeric", "string"] if _NUMBER.fullmatch(original_value.strip()) else ["string", "numeric"]


def _context_profile(config: RequestConfig, original_value: str, detected: str | None = None) -> dict[str, object]:
    name = config.parameter.lower()
    hints: dict[str, int] = {"numeric": 0, "quoted-string": 0, "order-by": 0, "limit-offset": 0, "unknown": 5}
    if _NUMBER.fullmatch(original_value.strip()):
        hints["numeric"] += 70
    else:
        hints["quoted-string"] += 65
    if any(token in name for token in ("sort", "order", "orderby", "order_by")):
        hints["order-by"] += 75
    if any(token in name for token in ("limit", "offset", "page", "size")):
        hints["limit-offset"] += 70
    if detected == "numeric":
        hints["numeric"] = max(hints["numeric"], 95)
    elif detected == "string":
        hints["quoted-string"] = max(hints["quoted-string"], 95)
    ordered = sorted(hints.items(), key=lambda item: item[1], reverse=True)
    return {"primary": ordered[0][0], "scores": dict(ordered)}


def _modal_status(items: list[ResponseSnapshot]) -> int:
    if not items:
        return 0
    return Counter(item.status for item in items).most_common(1)[0][0]


def _repeatable_status(items: list[ResponseSnapshot]) -> bool:
    return bool(items) and len({item.status for item in items}) == 1


def _boolean_score(
    baseline: BaselineProfile,
    true_items: list[ResponseSnapshot],
    false_items: list[ResponseSnapshot],
) -> tuple[int, dict[str, object]]:
    if not true_items or not false_items or any(item.status == 0 for item in true_items + false_items):
        return 0, {"network_reliable": False, "rounds": min(len(true_items), len(false_items))}

    true_cluster = cluster_similarity(true_items)
    false_cluster = cluster_similarity(false_items)
    cross = cross_similarity(true_items, false_items)
    within = min(true_cluster, false_cluster)
    cluster_gap = max(0.0, within - cross)

    true_base = median(similarity(item.body, baseline.representative.body) for item in true_items)
    false_base = median(similarity(item.body, baseline.representative.body) for item in false_items)
    baseline_affinity = max(true_base, false_base)

    true_status = _modal_status(true_items)
    false_status = _modal_status(false_items)
    status_separation = true_status != false_status and _repeatable_status(true_items) and _repeatable_status(false_items)

    length_deltas = [abs(a.length - b.length) for a, b in zip(true_items, false_items)]
    median_length_gap = float(median(length_deltas)) if length_deltas else 0.0
    meaningful_length_gap = median_length_gap >= max(24.0, baseline.median_length * 0.08)

    content_separation = (
        cluster_gap >= baseline.differential_margin
        and within >= max(0.82, baseline.median_similarity - 0.12)
        and baseline_affinity >= max(0.70, baseline.median_similarity - 0.20)
    )

    round_confirmations = 0
    for true_item, false_item in zip(true_items, false_items):
        pair_sim = similarity(true_item.body, false_item.body)
        if true_item.status != false_item.status:
            round_confirmations += 1
            continue
        pair_gap = abs(
            similarity(true_item.body, baseline.representative.body)
            - similarity(false_item.body, baseline.representative.body)
        )
        pair_len = abs(true_item.length - false_item.length)
        if pair_gap >= baseline.differential_margin or pair_len >= max(24.0, baseline.median_length * 0.08):
            round_confirmations += 1
        elif pair_sim <= max(0.60, baseline.min_similarity - baseline.differential_margin):
            round_confirmations += 1

    if not (content_separation or status_separation or (meaningful_length_gap and round_confirmations >= 2)):
        score = min(34, round(100 * cluster_gap))
    else:
        score = 44
        score += min(24, round_confirmations * 8)
        score += min(16, round(cluster_gap * 100))
        score += 8 if baseline.stable else 0
        score += 8 if status_separation else 0
        score += 5 if meaningful_length_gap else 0
        score = min(100, score)

    evidence: dict[str, object] = {
        "network_reliable": True,
        "rounds": len(true_items),
        "round_confirmations": round_confirmations,
        "reproducibility": round(100 * round_confirmations / max(1, len(true_items))),
        "true_cluster_similarity": round(true_cluster, 4),
        "false_cluster_similarity": round(false_cluster, 4),
        "cross_cluster_similarity": round(cross, 4),
        "cluster_gap": round(cluster_gap, 4),
        "required_gap": round(baseline.differential_margin, 4),
        "true_to_baseline_similarity": round(float(true_base), 4),
        "false_to_baseline_similarity": round(float(false_base), 4),
        "median_length_gap": round(median_length_gap, 2),
        "true_status": true_status,
        "false_status": false_status,
        "status_separation": status_separation,
        "content_separation": content_separation,
    }
    return score, evidence


def _verdict(score: int) -> str:
    if score >= 90:
        return "confirmed"
    if score >= 75:
        return "high-confidence"
    if score >= 55:
        return "probable"
    if score >= 35:
        return "possible"
    return "no-strong-indicator"


def _dbms_profile(findings: list[Finding]) -> dict[str, float]:
    weights: dict[str, float] = defaultdict(float)
    for finding in findings:
        if finding.dbms_hint:
            multiplier = 1.2 if finding.category == "error-based-indicator" else 1.0
            weights[finding.dbms_hint] += max(1.0, finding.score * multiplier)
        for hint in finding.evidence.get("db_error_hints", []):
            if isinstance(hint, str):
                weights[hint] += max(1.0, finding.score * 0.35)
    total = sum(weights.values())
    if not total:
        return {}
    return {
        name: round(weight * 100.0 / total, 1)
        for name, weight in sorted(weights.items(), key=lambda item: item[1], reverse=True)
    }


def _redact_url(url: str) -> str:
    try:
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        safe = [(key, "<redacted>" if _SECRET_NAME.search(key) else value) for key, value in pairs]
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(safe, doseq=True), parts.fragment))
    except ValueError:
        return url


class SQLiScanner:
    def __init__(self, client: HTTPClient | None = None) -> None:
        self.client = client or HTTPClient()

    def scan(
        self,
        config: RequestConfig,
        *,
        original_value: str = "1",
        authorized: bool = False,
        time_probes: bool | None = None,
        dbms: Iterable[str] | None = None,
        context: str = "auto",
        baseline_samples: int | None = None,
        confirmation_rounds: int | None = None,
        profile: str = "normal",
        max_requests: int | None = None,
        control: ScanControl | None = None,
    ) -> ScanReport:
        require_authorization(authorized)
        validate_http_url(config.url)
        self.client.validate_config(config, original_value)
        if profile not in _PROFILE_DEFAULTS:
            raise ValueError("profile must be one of: safe, normal, thorough")
        defaults = _PROFILE_DEFAULTS[profile]
        baseline_samples = int(defaults["baseline"] if baseline_samples is None else baseline_samples)
        confirmation_rounds = int(defaults["rounds"] if confirmation_rounds is None else confirmation_rounds)
        request_budget = int(defaults["max_requests"] if max_requests is None else max_requests)
        time_probes = bool(defaults["timing"] if time_probes is None else time_probes)
        if profile == "safe":
            time_probes = False
        if baseline_samples < 3 or baseline_samples > 9:
            raise ValueError("baseline_samples must be between 3 and 9")
        if confirmation_rounds < 2 or confirmation_rounds > 5:
            raise ValueError("confirmation_rounds must be between 2 and 5")
        if request_budget < 10 or request_budget > 2000:
            raise ValueError("max_requests must be between 10 and 2000")

        control = control or ScanControl()
        errors: list[str] = []
        findings: list[Finding] = []
        timeline: list[RequestEvidence] = []
        tested = 0
        requests_sent = 0
        stopped_early = False

        def request(value: str, phase: str, label: str) -> ResponseSnapshot:
            nonlocal requests_sent
            control.checkpoint()
            if requests_sent >= request_budget:
                raise _BudgetReached("request budget reached")
            control.emit("request-start", phase=phase, label=label, index=requests_sent + 1, budget=request_budget)
            response = self.client.request(config, value)
            requests_sent += 1
            timeline.append(
                RequestEvidence(
                    index=requests_sent,
                    phase=phase,
                    label=label,
                    status=response.status,
                    length=response.length,
                    elapsed_ms=round(response.elapsed * 1000, 2),
                    error=response.error,
                    method=response.request_method or config.method.upper(),
                    url=_redact_url(response.request_url or config.url),
                    request_headers=response.request_headers,
                    request_body=response.request_body[:20_000] if response.request_body else None,
                    response_excerpt=redact_text_secrets(response.body[:4_000]),
                )
            )
            control.emit(
                "request-complete",
                phase=phase,
                label=label,
                index=requests_sent,
                budget=request_budget,
                status=response.status,
                length=response.length,
                elapsed_ms=round(response.elapsed * 1000, 2),
            )
            if response.error and response.error not in errors:
                errors.append(response.error)
            return response

        baseline: BaselineProfile | None = None
        try:
            control.emit("phase", name="baseline", status="running")
            baselines = [request(original_value, "baseline", f"baseline-{i + 1}") for i in range(baseline_samples)]
            usable_baselines = [item for item in baselines if item.status != 0]
            if len(usable_baselines) < max(2, baseline_samples // 2):
                errors.append("baseline unavailable: too many network/configuration failures")
                stopped_early = True
            else:
                baseline = profile_baseline(usable_baselines)
                control.emit("phase", name="baseline", status="complete", stability=baseline.stability_score)

            if baseline is not None:
                baseline_error_hints = set(_db_error_hints(baseline.representative.body))
                control.emit("phase", name="syntax", status="running")
                for index, payload in enumerate(SYNTAX_PROBES, 1):
                    tested += 1
                    response = request(original_value + payload, "syntax", f"syntax-{index}")
                    if response.status == 0:
                        continue
                    hints = _db_error_hints(response.body)
                    new_hints = [hint for hint in hints if hint not in baseline_error_hints]
                    status_changed = response.status != baseline.representative.status and response.status >= 500
                    if new_hints or status_changed:
                        score = min(88, 58 + (15 if new_hints else 0) + (7 if baseline.stable else 0))
                        findings.append(
                            Finding(
                                category="error-based-indicator",
                                title="Database error behavior changed after SQL syntax probe",
                                confidence=confidence_from_score(score),
                                score=score,
                                payload=payload,
                                dbms_hint=new_hints[0] if new_hints else None,
                                evidence={
                                    "baseline": _snapshot_summary(baseline.representative),
                                    "probe": _snapshot_summary(response),
                                    "similarity": round(similarity(baseline.representative.body, response.body), 4),
                                    "db_error_hints": new_hints,
                                    "baseline_stability": baseline.stability_score,
                                    "response_diff": unified_response_diff(baseline.representative.body, response.body),
                                },
                            )
                        )
                control.emit("phase", name="syntax", status="complete")

                selected_contexts = _contexts(original_value, context)
                control.emit("phase", name="boolean", status="running")
                for pair in (probe for probe in BOOLEAN_PROBES if probe.context in selected_contexts):
                    true_items: list[ResponseSnapshot] = []
                    false_items: list[ResponseSnapshot] = []
                    for round_index in range(confirmation_rounds):
                        if round_index % 2 == 0:
                            true_items.append(request(original_value + pair.true_payload, "boolean", f"{pair.name}-true-{round_index + 1}"))
                            false_items.append(request(original_value + pair.false_payload, "boolean", f"{pair.name}-false-{round_index + 1}"))
                        else:
                            false_items.append(request(original_value + pair.false_payload, "boolean", f"{pair.name}-false-{round_index + 1}"))
                            true_items.append(request(original_value + pair.true_payload, "boolean", f"{pair.name}-true-{round_index + 1}"))
                        tested += 2

                    score, evidence = _boolean_score(baseline, true_items, false_items)
                    if score >= 35:
                        evidence["context"] = pair.context
                        evidence["baseline_stability"] = baseline.stability_score
                        evidence["true_samples"] = [_snapshot_summary(item) for item in true_items]
                        evidence["false_samples"] = [_snapshot_summary(item) for item in false_items]
                        if true_items and false_items:
                            evidence["response_diff"] = unified_response_diff(true_items[0].body, false_items[0].body)
                        findings.append(
                            Finding(
                                category="boolean-based-indicator",
                                title=f"Repeatable true/false SQL response separation ({pair.name})",
                                confidence=confidence_from_score(score),
                                score=score,
                                payload=f"TRUE: {pair.true_payload} | FALSE: {pair.false_payload}",
                                evidence=evidence,
                            )
                        )
                control.emit("phase", name="boolean", status="complete")

                if time_probes:
                    current_profile = _dbms_profile(findings)
                    if dbms:
                        selected_dbms = list(dbms)
                    elif current_profile and next(iter(current_profile.values())) >= 65:
                        selected_dbms = [next(iter(current_profile.keys()))]
                    else:
                        selected_dbms = list(TIME_PROBES.keys())
                    selected_dbms = [name for name in selected_dbms if name in TIME_PROBES]
                    control.emit("phase", name="timing", status="running", dbms=selected_dbms)
                    for name in selected_dbms:
                        payload = TIME_PROBES[name]
                        controls: list[ResponseSnapshot] = []
                        probes: list[ResponseSnapshot] = []
                        for round_index in range(3):
                            if round_index % 2 == 0:
                                controls.append(request(original_value, "timing", f"{name}-control-{round_index + 1}"))
                                probes.append(request(original_value + payload, "timing", f"{name}-probe-{round_index + 1}"))
                            else:
                                probes.append(request(original_value + payload, "timing", f"{name}-probe-{round_index + 1}"))
                                controls.append(request(original_value, "timing", f"{name}-control-{round_index + 1}"))
                            tested += 2
                        if any(item.status == 0 for item in controls + probes):
                            continue
                        deltas = [probe.elapsed - control.elapsed for probe, control in zip(probes, controls)]
                        threshold = max(1.25, baseline.elapsed_mad * 8.0 + 0.25)
                        confirmations = sum(delta >= threshold for delta in deltas)
                        median_delta = float(median(deltas))
                        if confirmations >= 2 and median_delta >= threshold:
                            score = min(92, 55 + confirmations * 9 + (8 if baseline.stable else 0))
                            findings.append(
                                Finding(
                                    category="time-based-indicator",
                                    title=f"Repeated response delay consistent with a {name} timing probe",
                                    confidence=confidence_from_score(score),
                                    score=score,
                                    payload=payload,
                                    dbms_hint=name,
                                    evidence={
                                        "rounds": 3,
                                        "confirmations": confirmations,
                                        "reproducibility": round(100 * confirmations / 3),
                                        "threshold_ms": round(threshold * 1000, 2),
                                        "median_delta_ms": round(median_delta * 1000, 2),
                                        "deltas_ms": [round(delta * 1000, 2) for delta in deltas],
                                        "control_ms": [round(item.elapsed * 1000, 2) for item in controls],
                                        "probe_ms": [round(item.elapsed * 1000, 2) for item in probes],
                                        "baseline_mad_ms": round(baseline.elapsed_mad * 1000, 2),
                                    },
                                )
                            )
                    control.emit("phase", name="timing", status="complete")
        except (_BudgetReached, ScanCancelled) as exc:
            stopped_early = True
            if str(exc) and str(exc) not in errors:
                errors.append(str(exc))
            control.emit("stopped", reason=str(exc))

        findings.sort(key=lambda finding: finding.score, reverse=True)
        confidence_score = findings[0].score if findings else 0
        detected_context = next(
            (
                str(finding.evidence["context"])
                for finding in findings
                if finding.category == "boolean-based-indicator" and "context" in finding.evidence
            ),
            None,
        )
        reproducibility = max(
            (int(finding.evidence.get("reproducibility", 0)) for finding in findings),
            default=0,
        )
        baseline_dict = baseline.to_dict() if baseline else {
            "sample_count": requests_sent,
            "stability_score": 0,
            "stable": False,
            "status": 0,
        }
        report = ScanReport(
            target=_redact_url(config.url),
            method=config.method.upper(),
            parameter=config.parameter,
            baseline=baseline_dict,
            findings=findings,
            tested_payloads=tested,
            confidence_score=confidence_score,
            verdict=_verdict(confidence_score),
            detected_context=detected_context,
            dbms_profile=_dbms_profile(findings),
            errors=errors,
            reproducibility=reproducibility,
            injection_location=config.location,
            requests_sent=requests_sent,
            request_budget=request_budget,
            timeline=timeline,
            profile=profile,
            stopped_early=stopped_early,
            context_profile=_context_profile(config, original_value, detected_context),
        )
        control.emit("complete", verdict=report.verdict, confidence=report.confidence_score, requests=requests_sent)
        return report
