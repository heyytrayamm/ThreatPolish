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

The browser test is the only one that needs a built dashboard and Playwright:

```bash
cd frontend && npm run build
cd ../backend && pip install -r requirements-browser.txt
python -m playwright install chromium
python -m pytest tests/test_browser.py -q
```

It starts the API on a free port, which also serves `frontend/dist`, and skips
when the bundle is missing, stale or Playwright is absent.

## Suite structure

| File | Covers |
| --- | --- |
| `test_foundation.py` | Health, auth, tokens, RBAC, audit, event contract validation, migration re-keying |
| `test_correlation.py` | Feature extraction, corpus weighting, thresholds, anchors, contradictions, campaign construction |
| `test_deception.py` | Decoy profiles, HTTP decoy responses, Cowrie adaptation, password hashing |
| `test_adaptive.py` | Investigation lifecycle, eligibility limits, before/after recording, no evidence creation, concurrent planning against the one-open-investigation constraint |
| `test_websec.py` | Scope authorization, SSRF refusal, redirect targets, response bounds, finding persistence |
| `test_crypto.py` | Provider abstraction, fixture provider, signal scoring, caching |
| `test_responses.py` | Policy matrix, approval requirement, expiry, rollback, state machine |
| `test_pipeline.py` | Ingestion idempotency, quarantine, attribution, modules sharing one contract |
| `test_end_to_end.py` | Login → ingest → correlate → campaign → response → audit over HTTP |
| `test_security.py` | Auth bypass attempts, injection strings, oversized payloads, token tampering |
| `test_advanced.py` | Non-finite and unencodable payloads, hostile feature shapes, request-body bounds, login spraying, session revocation on password change, per-device sign-out, foreign-session refusal, an administrator signing one device out of another account, session history states, concurrent duplicate ingestion, redirect scope bypass, decoy request framing |
| `test_signin_alerts.py` | Network-change and distance alerts: same-network silence, window and revoked-session suppression, distant and nearby geolocation, unlocatable fallback |
| `test_browser.py` | Chrome-driven dashboard flow against a live API: every view renders without console errors, the duplicate-resolution note shows on the Deception page, the Account page changes the password, the replacement token survives a reload and an earlier token is refused; a second run plans and activates an investigation through the Campaigns and Deception pages; a third signs a device out from the session table, opens the admin session panel, signs another account's device out from it, creates and revokes a sensor token on the same page and checks the Overview attention card |

## Measured behaviour

Latest full run: **121 passed on SQLite and 121 passed on PostgreSQL 16** in CI
(run `40077471087`, commit `bdd593f`), including the three browser cases. The
PostgreSQL job starts a service database and the fixture resets its schema per
test, so isolation matches the SQLite path.
Static checks: the frontend builds with `tsc -b` and `vite build`; the backend
passes Ruff and compiles with `compileall`.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request:

| Job | Checks |
| --- | --- |
| Backend tests (SQLite) | Ruff `F,E9`; full pytest suite |
| Backend tests (PostgreSQL) | Full pytest suite against a PostgreSQL 16 service |
| Dashboard build | `npm ci`; TypeScript build and Vite bundle |
| Dashboard end-to-end | Builds the bundle, installs Playwright, drives the password, session, token and investigation flows in Chromium against a live API |
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
- readiness reported the database healthy at the current schema version;
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

### Hardening pass

- Adaptive activation now lives on the investigation row, so an API activation
  is visible to the separate decoy process. Expired activations become
  `expired` and release their subject instead of blocking it forever.
- Redirect destinations are re-authorized and re-checked for private addresses;
  URLs with embedded credentials are refused. Target responses are read with a
  1 MB cap so a hostile page cannot exhaust memory.
- Pair identifiers use a separator that cannot occur in a session ID. Migration
  5 re-keys legacy edges from their endpoint columns; a v3 PostgreSQL database
  was copied and upgraded to v5 with data intact as an explicit upgrade test.
- Campaign detail loads exactly its member sessions instead of every session in
  a 14-day window, so older campaign members remain visible.
- The event contract rejects `NaN`/`Infinity` and lone surrogates, so neither a
  hostile sensor nor a misbehaving provider can store a value that later breaks
  strict JSON clients. Market-provider non-finite numbers are treated as
  missing observations.
- Ingestion reads the body with a hard bound (batch size × per-event limit), so
  validation cannot be bypassed by sending a huge request first.
- Login attempts are limited by client address as well as by account; rotating
  the email address no longer resets the attempt budget.
- Active web-assessment probes only run when the final redirect target's scope
  authorizes them, not merely the entry host's.
- The decoy refuses requests with ambiguous framing (Transfer-Encoding or
  duplicate Content-Length) and closes the connection for unread bodies; an
  active investigation's profile, not the default one, decides the credential
  capture path.
- `since`/`until` event filters are parsed and validated instead of being
  compared as unvalidated strings.

## Not verified

- Cowrie was exercised with connection attempts, not a full interactive shell
  session.
- The adaptive simulation is not a substitute for field measurement.
- The upgrade test covered schema v3 → v5 on a copy of the deployment database,
  not a rolling multi-version production cluster.
- No load test beyond the 63-session benchmark and the volume run.
- Web assessment was tested against loopback targets, not a real external host.
