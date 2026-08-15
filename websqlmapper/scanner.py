from __future__ import annotations

import re
from collections import Counter, defaultdict
from statistics import median
from typing import Iterable

from .analyzer import (
    BaselineProfile,
    cluster_similarity,
    confidence_from_score,
    cross_similarity,
    profile_baseline,
    similarity,
)
from .models import Finding, RequestConfig, ResponseSnapshot, ScanReport
from .payloads import BOOLEAN_PROBES, ERROR_SIGNATURES, SYNTAX_PROBES, TIME_PROBES, ProbePair
from .safety import require_authorization, validate_http_url
from .transport import HTTPClient


_NUMBER = re.compile(r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$")


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


def _contexts(original_value: str, requested: str) -> list[str]:
    if requested not in {"auto", "numeric", "string"}:
        raise ValueError("context must be one of: auto, numeric, string")
    if requested != "auto":
        return [requested]
    # Try the most plausible context first, then retain the alternative so quoted
    # numeric values and numeric-looking strings are not silently missed.
    return ["numeric", "string"] if _NUMBER.fullmatch(original_value.strip()) else ["string", "numeric"]


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
    status_separation = (
        true_status != false_status
        and _repeatable_status(true_items)
        and _repeatable_status(false_items)
    )

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
        "rounds": len(true_items),
        "round_confirmations": round_confirmations,
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
        context: str = "auto",
        baseline_samples: int = 5,
        confirmation_rounds: int = 3,
    ) -> ScanReport:
        require_authorization(authorized)
        validate_http_url(config.url)
        if baseline_samples < 3 or baseline_samples > 9:
            raise ValueError("baseline_samples must be between 3 and 9")
        if confirmation_rounds < 2 or confirmation_rounds > 5:
            raise ValueError("confirmation_rounds must be between 2 and 5")

        errors: list[str] = []
        findings: list[Finding] = []
        tested = 0

        baselines = [self.client.request(config, original_value) for _ in range(baseline_samples)]
        if any(item.status == 0 for item in baselines):
            errors.extend(item.error or "request failed" for item in baselines if item.status == 0)
        baseline = profile_baseline(baselines)
        baseline_error_hints = set(_db_error_hints(baseline.representative.body))

        for payload in SYNTAX_PROBES:
            tested += 1
            response = self.client.request(config, original_value + payload)
            hints = _db_error_hints(response.body)
            new_hints = [hint for hint in hints if hint not in baseline_error_hints]
            status_changed = response.status != baseline.representative.status and response.status >= 500
            if new_hints or status_changed:
                score = 58 + (15 if new_hints else 0) + (7 if baseline.stable else 0)
                score = min(88, score)
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
                        },
                    )
                )

        selected_contexts = _contexts(original_value, context)
        for pair in (probe for probe in BOOLEAN_PROBES if probe.context in selected_contexts):
            true_items: list[ResponseSnapshot] = []
            false_items: list[ResponseSnapshot] = []
            # Alternate request order each round to reduce sensitivity to monotonic
            # drift in the application or network.
            for round_index in range(confirmation_rounds):
                if round_index % 2 == 0:
                    true_items.append(self.client.request(config, original_value + pair.true_payload))
                    false_items.append(self.client.request(config, original_value + pair.false_payload))
                else:
                    false_items.append(self.client.request(config, original_value + pair.false_payload))
                    true_items.append(self.client.request(config, original_value + pair.true_payload))
                tested += 2

            score, evidence = _boolean_score(baseline, true_items, false_items)
            if score >= 35:
                evidence["context"] = pair.context
                evidence["baseline_stability"] = baseline.stability_score
                evidence["true_samples"] = [_snapshot_summary(item) for item in true_items]
                evidence["false_samples"] = [_snapshot_summary(item) for item in false_items]
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

        if time_probes:
            selected = list(dbms or TIME_PROBES.keys())
            for name in selected:
                payload = TIME_PROBES.get(name)
                if not payload:
                    continue
                controls: list[ResponseSnapshot] = []
                probes: list[ResponseSnapshot] = []
                for round_index in range(3):
                    if round_index % 2 == 0:
                        controls.append(self.client.request(config, original_value))
                        probes.append(self.client.request(config, original_value + payload))
                    else:
                        probes.append(self.client.request(config, original_value + payload))
                        controls.append(self.client.request(config, original_value))
                    tested += 2

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
                                "threshold_ms": round(threshold * 1000, 2),
                                "median_delta_ms": round(median_delta * 1000, 2),
                                "deltas_ms": [round(delta * 1000, 2) for delta in deltas],
                                "control_ms": [round(item.elapsed * 1000, 2) for item in controls],
                                "probe_ms": [round(item.elapsed * 1000, 2) for item in probes],
                                "baseline_mad_ms": round(baseline.elapsed_mad * 1000, 2),
                            },
                        )
                    )

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
        return ScanReport(
            target=config.url,
            method=config.method.upper(),
            parameter=config.parameter,
            baseline=baseline.to_dict(),
            findings=findings,
            tested_payloads=tested,
            confidence_score=confidence_score,
            verdict=_verdict(confidence_score),
            detected_context=detected_context,
            dbms_profile=_dbms_profile(findings),
            errors=errors,
        )
