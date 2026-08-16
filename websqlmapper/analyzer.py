from __future__ import annotations

import json
import re
import textwrap
from dataclasses import dataclass
from difflib import SequenceMatcher, unified_diff
from functools import lru_cache
from html.parser import HTMLParser
from itertools import combinations
from statistics import median
from typing import Any, Iterable

from .models import ResponseSnapshot

_DYNAMIC_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"), "<UUID>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ][0-2]\d:[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"), "<DATETIME>"),
    (re.compile(r"\b(?:1[5-9]|2[0-2])\d{8,11}\b"), "<EPOCH>"),
    (re.compile(r"\b[0-9a-fA-F]{24,128}\b"), "<HEX>"),
    (re.compile(r"(?i)(\b(?:csrf|xsrf|nonce|request[_-]?id|trace[_-]?id|correlation[_-]?id)\b\s*[=:]\s*)(?:['\"])?[A-Za-z0-9._~+\-/=]{8,}(?:['\"])?"), r"\1<VOLATILE>"),
)
_WHITESPACE = re.compile(r"\s+")
_DYNAMIC_JSON_KEYS = re.compile(r"(?i)(?:timestamp|time|nonce|csrf|xsrf|request[_-]?id|trace[_-]?id|correlation[_-]?id|uuid)")


class _HTMLSemanticParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript"}:
            self._skip += 1
            return
        if not self._skip:
            self.parts.append(f"<{tag}>")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"} and self._skip:
            self._skip -= 1
            return
        if not self._skip:
            self.parts.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        if not self._skip and data.strip():
            self.parts.append(data)


@lru_cache(maxsize=192)
def normalize_body(text: str) -> str:
    normalized = text[:200_000]
    for pattern, replacement in _DYNAMIC_PATTERNS:
        normalized = pattern.sub(replacement, normalized)
    return _WHITESPACE.sub(" ", normalized).strip()


def _sanitize_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: ("<VOLATILE>" if _DYNAMIC_JSON_KEYS.search(str(key)) else _sanitize_json(item))
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, list):
        return [_sanitize_json(item) for item in value]
    if isinstance(value, str):
        return normalize_body(value)
    return value


@lru_cache(maxsize=192)
def semantic_body(body: str, content_type: str = "") -> str:
    limited = body[:200_000]
    lowered = content_type.lower()
    if "json" in lowered or limited.lstrip().startswith(("{", "[")):
        try:
            parsed = json.loads(limited)
        except (json.JSONDecodeError, ValueError):
            pass
        else:
            return json.dumps(_sanitize_json(parsed), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if "html" in lowered or "<html" in limited[:2000].lower() or "<!doctype html" in limited[:2000].lower():
        parser = _HTMLSemanticParser()
        try:
            parser.feed(limited)
            return normalize_body(" ".join(parser.parts))
        except Exception:
            return normalize_body(limited)
    return normalize_body(limited)


def similarity(left: str, right: str) -> float:
    left_n = normalize_body(left)
    right_n = normalize_body(right)
    return _similarity_normalized(left_n, right_n)


def snapshot_similarity(left: ResponseSnapshot, right: ResponseSnapshot) -> float:
    left_n = semantic_body(left.body, left.content_type)
    right_n = semantic_body(right.body, right.content_type)
    return _similarity_normalized(left_n, right_n)


def _similarity_normalized(left_n: str, right_n: str) -> float:
    if left_n == right_n:
        return 1.0
    if not left_n and not right_n:
        return 1.0
    max_len = max(len(left_n), len(right_n), 1)
    if abs(len(left_n) - len(right_n)) / max_len > 0.75:
        return min(len(left_n), len(right_n)) / max_len
    forward = SequenceMatcher(None, left_n, right_n, autojunk=False).ratio()
    backward = SequenceMatcher(None, right_n, left_n, autojunk=False).ratio()
    return (forward + backward) / 2.0


def unified_response_diff(left: str, right: str, *, max_lines: int = 80) -> str:
    left_n = normalize_body(left)[:20_000]
    right_n = normalize_body(right)[:20_000]
    if left_n == right_n:
        return ""

    def lines(value: str) -> list[str]:
        raw = value.splitlines() or [value]
        if len(raw) == 1 and len(raw[0]) > 240:
            return textwrap.wrap(raw[0], width=160, replace_whitespace=False, drop_whitespace=False)
        return raw

    diff = list(unified_diff(lines(left_n), lines(right_n), fromfile="left", tofile="right", lineterm=""))
    if len(diff) > max_lines:
        diff = diff[:max_lines] + ["... <diff truncated>"]
    return "\n".join(diff)


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
    return _median_or((snapshot_similarity(a, b) for a, b in combinations(snapshots, 2)), 1.0)


def cross_similarity(left: list[ResponseSnapshot], right: list[ResponseSnapshot]) -> float:
    if not left or not right:
        return 1.0
    return _median_or((snapshot_similarity(a, b) for a in left for b in right), 1.0)


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
    pair_sims = [snapshot_similarity(a, b) for a, b in combinations(snapshots, 2)]
    median_sim = _median_or(pair_sims, 1.0)
    min_sim = min(pair_sims, default=1.0)
    median_len = float(median(lengths))
    len_mad = median_absolute_deviation(lengths)
    elapsed_med = float(median(elapsed))
    elapsed_mad = median_absolute_deviation(elapsed)
    length_noise = min(1.0, len_mad / max(1.0, median_len * 0.05))
    timing_noise = min(1.0, elapsed_mad / max(0.005, elapsed_med * 0.25)) if elapsed_med else 0.0
    score = round(100 * median_sim - 8 * length_noise - 5 * timing_noise)
    stability_score = max(0, min(100, score))
    stable = median_sim >= 0.94 and min_sim >= 0.88
    ordinary_variation = max(0.0, 1.0 - min_sim)
    differential_margin = min(0.35, max(0.045, ordinary_variation + 0.035))
    representative = min(snapshots, key=lambda item: abs(item.length - median_len))
    return BaselineProfile(
        sample_count=len(snapshots), median_length=median_len, length_mad=len_mad,
        median_elapsed=elapsed_med, elapsed_mad=elapsed_mad, median_similarity=median_sim,
        min_similarity=min_sim, stability_score=stability_score, stable=stable,
        differential_margin=differential_margin, representative=representative,
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
