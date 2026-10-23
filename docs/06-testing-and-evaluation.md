# Testing and evaluation

## Running

```bash
cd backend
python -m pytest -q              # full suite
python scripts/evaluate.py       # benchmark, writes docs/research/
```

The suite runs on SQLite with an in-process ASGI client and needs no external
services. Set `TP_TEST_DB_URL` to a PostgreSQL URL to run the same suite against
PostgreSQL; the fixture resets the schema before each test so isolation matches
the SQLite path. CI runs both engines on every push and pull request.

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

Latest full run: **66 passed on SQLite** and **66 passed on PostgreSQL 16**.
Static checks: the frontend builds with `tsc -b` and `vite build`; the backend
passes Ruff and compiles with `compileall`.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request:

| Job | Checks |
| --- | --- |
| Backend tests (SQLite) | Ruff `F,E9`; full pytest suite |
| Backend tests (PostgreSQL) | Full pytest suite against a PostgreSQL 16 service |
| Dashboard build | `npm ci`; TypeScript build and Vite bundle |
| Container image | Multi-stage Docker build |

Benchmark, 63 sessions / 1953 pairs, two seeds, algorithm `corr-1.1.0`:

| Metric | Seed 7 | Seed 2026 |
| --- | --- | --- |
| Precision (proposed) | 1.000 | 1.000 |
| Recall (proposed) | 0.781 | 0.562 |
| Precision (rule baseline) | 0.066 | 0.067 |
| False positives (proposed / rule) | 0 / 424 | 0 / 420 |
| Campaign-level exact recovery | 8 of 12 | 4 of 12 |

Resources: about 6.3 s total, 16.4 MB peak for a full run including all
ablations.
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

## Container deployment verification

The Compose stack was built and run on this host against PostgreSQL 16:

- image build succeeded; the API runs as uid 10001, not root;
- readiness reported the database healthy at schema version 2;
- login, ingestion, correlation and every read endpoint returned success;
- 12 smoke events produced 4 sessions, 6 edges and 1 campaign;
- response approval/rollback and the investigation plan/activate/evaluate
  lifecycle completed against PostgreSQL;
- restarting the API preserved data; a `pg_dump` restored into a scratch
  database with matching row counts;
- stopping PostgreSQL made readiness return 503, and it recovered to 200 after
  the database restarted;
- the optional Cowrie profile started, wrote its JSON log to a shared volume,
  and `cowrie-tail` ingested 5 events, then reported 0 on re-run (idempotent);
- the HTTP decoy ran inside the container and emitted a telemetry event.

Two PostgreSQL-only defects were found and fixed in this pass:
`WHERE (:param IS NULL OR ...)` patterns could not be typed by the driver in
campaign listing and duplicate-investigation lookup. Both now build predicates
conditionally.

## Not verified

- Cowrie was exercised with connection attempts, not a full interactive shell
  session.
- The adaptive simulation is not a substitute for field measurement.
- No load test beyond the 63-session benchmark and the volume run.
- Web assessment was tested against loopback targets, not a real external host.
