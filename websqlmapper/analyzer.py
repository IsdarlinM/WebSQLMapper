from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from itertools import combinations
from statistics import median
from typing import Iterable

from .models import ResponseSnapshot


# Common response values that change independently of the tested parameter.  The
# normalizer is deliberately conservative: it masks well-known volatile shapes,
# not arbitrary numbers or application data.
_DYNAMIC_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"),
        "<UUID>",
    ),
    (
        re.compile(r"\b\d{4}-\d{2}-\d{2}[T ][0-2]\d:[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"),
        "<DATETIME>",
    ),
    (re.compile(r"\b(?:1[5-9]|2[0-2])\d{8,11}\b"), "<EPOCH>"),
    (re.compile(r"\b[0-9a-fA-F]{24,128}\b"), "<HEX>"),
    (
        re.compile(
            r"(?i)(\b(?:csrf|xsrf|nonce|request[_-]?id|trace[_-]?id|correlation[_-]?id)\b\s*[=:]\s*)"
            r"(?:['\"])?[A-Za-z0-9._~+\-/=]{8,}(?:['\"])?"
        ),
        r"\1<VOLATILE>",
    ),
)
_WHITESPACE = re.compile(r"\s+")


def normalize_body(text: str) -> str:
    """Mask common volatile response values and collapse insignificant whitespace."""
    normalized = text[:200_000]
    for pattern, replacement in _DYNAMIC_PATTERNS:
        normalized = pattern.sub(replacement, normalized)
    return _WHITESPACE.sub(" ", normalized).strip()


def similarity(left: str, right: str) -> float:
    """Return a symmetric SequenceMatcher similarity over normalized content."""
    left_n = normalize_body(left)
    right_n = normalize_body(right)
    if left_n == right_n:
        return 1.0
    # SequenceMatcher's heuristic can be asymmetric for long strings.  Averaging
    # both directions and disabling autojunk makes the detector more predictable.
    forward = SequenceMatcher(None, left_n, right_n, autojunk=False).ratio()
    backward = SequenceMatcher(None, right_n, left_n, autojunk=False).ratio()
    return (forward + backward) / 2.0


def _median_or(values: Iterable[float], fallback: float) -> float:
    items = list(values)
    return float(median(items)) if items else fallback


def median_absolute_deviation(values: Iterable[float]) -> float:
    items = list(values)
    if not items:
        return 0.0
    center = float(median(items))
    return float(median(abs(value - center) for value in items))


def cluster_similarity(snapshots: list[ResponseSnapshot]) -> float:
    if len(snapshots) < 2:
        return 1.0
    return _median_or((similarity(a.body, b.body) for a, b in combinations(snapshots, 2)), 1.0)


def cross_similarity(left: list[ResponseSnapshot], right: list[ResponseSnapshot]) -> float:
    if not left or not right:
        return 1.0
    return _median_or((similarity(a.body, b.body) for a in left for b in right), 1.0)


@dataclass(frozen=True, slots=True)
class BaselineProfile:
    sample_count: int
    median_length: float
    length_mad: float
    median_elapsed: float
    elapsed_mad: float
    median_similarity: float
    min_similarity: float
    stability_score: int
    stable: bool
    differential_margin: float
    representative: ResponseSnapshot

    def to_dict(self) -> dict[str, object]:
        return {
            "sample_count": self.sample_count,
            "median_length": round(self.median_length, 2),
            "length_mad": round(self.length_mad, 2),
            "median_elapsed_ms": round(self.median_elapsed * 1000, 2),
            "elapsed_mad_ms": round(self.elapsed_mad * 1000, 2),
            "median_similarity": round(self.median_similarity, 4),
            "min_similarity": round(self.min_similarity, 4),
            "stability_score": self.stability_score,
            "stable": self.stable,
            "differential_margin": round(self.differential_margin, 4),
            "status": self.representative.status,
        }


def profile_baseline(snapshots: list[ResponseSnapshot]) -> BaselineProfile:
    if not snapshots:
        raise ValueError("at least one baseline response is required")

    lengths = [float(snapshot.length) for snapshot in snapshots]
    elapsed = [snapshot.elapsed for snapshot in snapshots]
    pair_sims = [similarity(a.body, b.body) for a, b in combinations(snapshots, 2)]
    median_sim = _median_or(pair_sims, 1.0)
    min_sim = min(pair_sims, default=1.0)

    median_len = float(median(lengths))
    len_mad = median_absolute_deviation(lengths)
    elapsed_med = float(median(elapsed))
    elapsed_mad = median_absolute_deviation(elapsed)

    # Content stability dominates. Length and latency variability only reduce the
    # score slightly because legitimate applications often have network jitter.
    length_noise = min(1.0, len_mad / max(1.0, median_len * 0.05))
    timing_noise = min(1.0, elapsed_mad / max(0.005, elapsed_med * 0.25)) if elapsed_med else 0.0
    score = round(100 * median_sim - 8 * length_noise - 5 * timing_noise)
    stability_score = max(0, min(100, score))
    stable = median_sim >= 0.94 and min_sim >= 0.88

    # Require the true/false clusters to be separated by more than ordinary
    # baseline variation. This replaces fixed global similarity thresholds.
    ordinary_variation = max(0.0, 1.0 - min_sim)
    differential_margin = min(0.35, max(0.045, ordinary_variation + 0.035))

    target_len = median_len
    representative = min(snapshots, key=lambda item: abs(item.length - target_len))
    return BaselineProfile(
        sample_count=len(snapshots),
        median_length=median_len,
        length_mad=len_mad,
        median_elapsed=elapsed_med,
        elapsed_mad=elapsed_mad,
        median_similarity=median_sim,
        min_similarity=min_sim,
        stability_score=stability_score,
        stable=stable,
        differential_margin=differential_margin,
        representative=representative,
    )


def confidence_from_score(score: int) -> str:
    if score >= 90:
        return "confirmed"
    if score >= 75:
        return "high"
    if score >= 55:
        return "medium"
    if score >= 35:
        return "low"
    return "noise"
