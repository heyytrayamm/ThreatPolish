# Testing and evaluation

## Running

```bash
cd backend
python -m pytest -q              # full suite
python scripts/evaluate.py       # benchmark, writes docs/research/
```

The suite uses SQLite and an in-process ASGI client; no external services are
required. Tests are isolated per test via a fresh database and dependency
overrides.

## Suite structure

| File | Covers |
| --- | --- |
| `test_foundation.py` | Health, auth, tokens, RBAC, audit, event contract validation |
| `test_correlation.py` | Feature extraction, corpus weighting, thresholds, anchors, contradictions, campaign construction |
| `test_deception.py` | Decoy profiles, HTTP decoy responses, Cowrie adaptation, password hashing |
| `test_adaptive.py` | Investigation lifecycle, eligibility limits, before/after recording, no evidence creation |
| `test_websec.py` | Scope authorization, SSRF refusal, redirect handling, finding persistence |
| `test_crypto.py` | Provider abstraction, fixture provider, signal scoring, caching |
| `test_responses.py` | Policy matrix, approval requirement, expiry, rollback, state machine |
| `test_pipeline.py` | Ingestion idempotency, quarantine, attribution, modules sharing one contract |
| `test_end_to_end.py` | Login → ingest → correlate → campaign → response → audit over HTTP |
| `test_security.py` | Auth bypass attempts, injection strings, oversized payloads, token tampering |

## Measured behaviour

Latest full run: **62 passed**. Static checks: the frontend builds with
`tsc --noEmit` and `vite build`.

Benchmark, 63 sessions / 1953 pairs, two seeds, algorithm `corr-1.1.0`:

| Metric | Seed 7 | Seed 2026 |
| --- | --- | --- |
| Precision (proposed) | 1.000 | 1.000 |
| Recall (proposed) | 0.781 | 0.562 |
| Precision (rule baseline) | 0.066 | 0.067 |
| False positives (proposed / rule) | 0 / 424 | 0 / 420 |
| Campaign-level exact recovery | 8 of 12 | 4 of 12 |

Resources: 6.1 s total, 16.4 MB peak for a full run including all ablations.
Full tables, per-subset breakdowns, the deliberately hard subset and the
adaptive experiment are in `docs/research/evaluation-results.md`.

## Interpretation

- Precision of 1.000 with recall 0.56–0.78 is a conservative operating point:
  the method prefers missed links over false accusations, which is appropriate
  for attribution support.
- The rule baseline achieves high recall with roughly 27% false positives,
  showing that a threshold-only approach is not usable at this scale.
- Ablating the toolchain family costs precision, confirming that tool
  signatures carry specific evidence.
- Ablating threat intelligence *raises* recall in these seeds. The synthetic
  scenarios provide sparse intelligence, so removing the family redistributes
  weight to behavioural evidence. This is reported rather than hidden; it is
  evidence that the intelligence family is under-informative in this benchmark,
  not that intelligence is useless in production.
- Adaptive observation raises recall (0.78→0.94 and 0.56→0.88) but adds false
  positives, because simulated observation can create similarity that real
  observation would not. The production path records real decoy traffic and
  cannot add evidence, and every investigation stores before/after values.

## Not verified

- Docker Compose was not executed: Docker is not installed on the build host.
  The files are provided and statically reviewed only.
- PostgreSQL was not executed for the same reason; the schema is portable but
  the deployed path is untested here.
- Cowrie was not run end-to-end; the adapter is tested against representative
  JSON log lines.
- The adaptive simulation is not a substitute for field measurement.
- No load test beyond the 63-session benchmark.
