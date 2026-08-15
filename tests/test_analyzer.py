from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from websqlmapper.analyzer import normalize_body, profile_baseline, similarity  # noqa: E402
from websqlmapper.models import ResponseSnapshot  # noqa: E402


class AnalyzerTests(unittest.TestCase):
    def _snapshot(self, body: str, elapsed: float = 0.1) -> ResponseSnapshot:
        return ResponseSnapshot(status=200, body=body, elapsed=elapsed, final_url="http://127.0.0.1/")

    def test_normalizer_masks_common_volatile_values(self) -> None:
        left = "generated=2026-08-15T10:00:01+00:00 request_id=550e8400-e29b-41d4-a716-446655440000"
        right = "generated=2026-08-15T10:00:59+00:00 request_id=123e4567-e89b-42d3-a456-426614174000"
        self.assertEqual(normalize_body(left), normalize_body(right))
        self.assertEqual(similarity(left, right), 1.0)

    def test_baseline_profile_uses_endpoint_specific_margin(self) -> None:
        snapshots = [
            self._snapshot(f"OK generated=2026-08-15T10:00:0{i}+00:00", 0.10 + i * 0.001)
            for i in range(5)
        ]
        profile = profile_baseline(snapshots)
        self.assertTrue(profile.stable)
        self.assertGreaterEqual(profile.stability_score, 90)
        self.assertGreaterEqual(profile.differential_margin, 0.045)


if __name__ == "__main__":
    unittest.main()
