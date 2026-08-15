# Changelog

## 0.2.0 - 2026-08-15

### Added

- Adaptive 3-9 sample endpoint baseline profiler.
- Conservative volatile-response normalization.
- Symmetric normalized-body similarity analysis.
- Endpoint-specific differential margins.
- Repeated alternating TRUE/FALSE confirmation rounds.
- Numeric confidence scoring and scan verdicts.
- Automatic/explicit SQL context selection.
- Weighted DBMS profile from correlated evidence.
- Repeated timing probe/control pairs using baseline latency MAD.
- Web UI controls for baseline samples, confirmation rounds, and SQL context.
- Safe volatile-response regression endpoint in the local lab.
- Analyzer unit tests and false-positive integration coverage.

### Changed

- Boolean SQLi findings now require repeatable cluster separation instead of fixed global similarity thresholds.
- Timing indicators now require repeated probe/control confirmation instead of a single delayed response.
- Scanner output includes baseline stability, confidence score, verdict, detected context, and DBMS profile.

## 0.1.0

- Initial authorized SQLi detector, private-lab SQLite mapper, CLI, web UI, and local training server.
