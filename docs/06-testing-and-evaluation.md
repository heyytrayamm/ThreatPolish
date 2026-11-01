# Testing and evaluation

## Running

```bash
cd backend
python -m pytest -q              # full suite
python scripts/evaluate.py       # benchmark, writes docs/research/
python scripts/deepscan.py       # authorization, input, SSRF and outbound scans

# Needs a PostgreSQL database; starts its own four-worker API.
python scripts/benchmark_write_contention.py --db-url postgresql+psycopg://... \
  --workers 4 --writers 6 --repeat 2
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

`scripts/deepscan.py` asks the same questions of every route rather than of the
routes a test happened to cover: it derives each route's permissions from its
dependency closure, calls it as every role and anonymously, then sends hostile
parameters, malformed bodies, tampered tokens and SSRF targets. A fourth scan
points every outbound call — market-data refresh, geolocation lookup and an
assessment whose target redirects — at a local probe that redirects or answers
with 33 MiB. A fifth compares the served routes, their permissions and the
configuration the code reads against the API reference, the suite and
`.env.example`, so a feature cannot leave the documented scope unnoticed. A sixth
times every read endpoint on the evaluation corpus with its statements counted,
and fails on a response over 512 KiB, more than 40 statements in a request, or
one statement repeated per row. It exits non-zero on a 5xx, on an authorization
decision that disagrees with the role matrix, on a target it should have refused,
on a redirect the platform followed, or on a scope or budget mismatch. Results
and the environment they were measured in are in
[`research/deepscan-results.md`](research/deepscan-results.md).

## Suite structure

| File | Covers |
| --- | --- |
| `test_foundation.py` | Health, auth, tokens, RBAC, audit, event contract validation, migration re-keying |
| `test_correlation.py` | Feature extraction, corpus weighting, containment scoring, thresholds, anchors, contradictions, campaign construction, campaign membership after demotion or expiry, preserved expiry evidence, identity across membership growth, archiving a reviewed campaign, merging campaigns with one or conflicting analyst decisions |
| `test_deception.py` | Decoy profiles, HTTP decoy responses, Cowrie adaptation, password hashing, and availability under clients that misbehave: a declared body that never arrives is answered `408` after the read timeout instead of pinning a thread, and ten connections reset mid-response raise nothing out of the handler |
| `test_adaptive.py` | Investigation lifecycle, eligibility limits, before/after recording, no evidence creation, concurrent planning against the one-open-investigation constraint |
| `test_websec.py` | Scope authorization, SSRF refusal, redirect targets, response bounds, finding persistence |
| `test_crypto.py` | Provider abstraction, fixture provider, signal scoring, caching |
| `test_responses.py` | Policy matrix, approval requirement, expiry, rollback, state machine |
| `test_pipeline.py` | Ingestion idempotency, quarantine, attribution, modules sharing one contract |
| `test_end_to_end.py` | Login → ingest → correlate → campaign → response → audit over HTTP |
| `test_determinism.py` | The seeded benchmark describes the same dataset on every run: dataset generation never reads the wall clock, the same seed reproduces identical telemetry, different seeds do not, and the anchor is a fixed instant |
| `test_retention.py` | Role-scoped retention status and admin-only manual run, backlog-versus-overdue grace, expired and retired counts, a combined purge clearing both horizons, scheduled-run history plus audit, total-run reporting when the 14-row view is truncated, CSV export beyond that view, UTC date-range and trigger filtering with matching totals and per-trigger counts, analyst read-only access, explicit viewer denial and Prometheus metrics |
| `test_demo.py` | Development seed populates telemetry, correlation, retention history and a demo login idempotently, and refuses to run in production |
| `test_security.py` | Auth bypass attempts, injection strings, oversized payloads, token tampering |
| `test_advanced.py` | Non-finite and unencodable payloads, hostile feature shapes, request-body bounds, login spraying, session revocation on password change, per-device sign-out, foreign-session refusal, an administrator signing one device out of another account, session history states, concurrent duplicate ingestion, redirect scope bypass, decoy request framing |
| `test_signin_alerts.py` | Network-change and distance alerts: same-network silence, window and revoked-session suppression, distant and nearby geolocation, unlocatable fallback |
| `test_killchain.py` | Tactic classification (reconnaissance before access, discovery after it, each command family, unclassified commands as execution), breadth and risk-weighted coverage, later-tactic tie-breaking, empty campaigns, and campaign-detail integration |
| `test_properties.py` | Invariants rather than scenarios: score symmetry and determinism, bounded outputs, monotone confidence, unique relationship keys for every accepted identifier, rejection of control characters in session and target ids, isolation of legacy corrupt ids, corpus-relative family weights against the uniform-weight ablation, and the narrowest authorization governing a host |
| `test_efficiency.py` | Development scope and read-path cost, measured on the evaluation corpus: every route is documented, exercised and guarded by a permission that some role holds, every configuration value appears in `.env.example`, and every read endpoint stays inside its statement and byte budgets. The graph view is pinned to a bounded page, must report truncation instead of silently returning part of the window, must not serialise stored node properties, and must cost the same number of statements whatever the page size |
| `test_browser.py` | Chrome-driven dashboard flow against a live API: every view renders without console errors, the duplicate-resolution note shows on the Deception page, the Account page changes the password, the replacement token survives a reload and an earlier token is refused; a second run plans and activates an investigation through the Campaigns and Deception pages; a third signs a device out from the session table, opens the admin session panel, signs another account's device out from it, creates and revokes a sensor token on the same page, sets the Events module, severity, window and search, copies the Events link and steps back and forward through its filter states, reloads into them, filters the retention run history by UTC date and trigger, keeps that window in the URL across a reload, copies the filtered retention link and reads it back from the clipboard, checks the Clipboard API fallback, moves between retention filter states and views with the browser's back and forward buttons, exports it as CSV and checks the Overview attention card; a fourth signs in as an analyst, confirms the read-only Retention view has history and export but no run control or Administration entry, checks that malformed and inverted shared filter links are explained and cleaned up, and follows the analyst-facing overdue alert to that page, as an administrator does from the Overview alert; a fifth and sixth cover the themes — a host that reports a light colour scheme starts on the daylight variant and a switch made in the top bar survives a reload, and with nothing stored yet the applied theme follows a host change made while the page is open until a switch is made, after which the host no longer moves it; and a further pair cover the signed-out entry — the landing page says what the platform does before it asks for a credential, its legal pages open without an account and lead back to it, and its hero signs in — and account creation from Administration, which is then signed into with the password that was typed into the form |

## Measured behaviour

The full suite is **212 tests on SQLite**, finishing in 105–125 s on this host
across runs, including the ten browser cases with the bundle built (202 pass and
those ten skip when it is missing). The same 212 pass against PostgreSQL 16.15 in
214–313 s; the fixture drops and recreates the schema per test, so isolation
matches the SQLite path and the extra time is the per-test schema reset. CI runs
both engines on every push.
Static checks: the frontend builds with `tsc -b` and `vite build`; the backend
passes Ruff and compiles with `compileall`.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request:

| Job | Checks |
| --- | --- |
| Backend tests (SQLite) | Ruff `F,E9`; full pytest suite |
| Backend tests (PostgreSQL) | Full pytest suite against a PostgreSQL 16 service |
| API deep scan | `scripts/deepscan.py`: 57 routes as every role and anonymously, 652 hostile requests, 23 SSRF payloads and every outbound call pointed at a hostile local probe; reports uploaded as an artifact |
| Dependency audit | `pip-audit` over the installed backend environment; `npm audit --audit-level=high` over the dashboard lockfile |
| Dashboard build | `npm ci`; TypeScript build and Vite bundle |
| Dashboard end-to-end | Builds the bundle, installs Playwright, drives the password, session, token, investigation, retention filter/export and theme flows in Chromium against a live API |
| Container image | Multi-stage Docker build |
| Demo Compose overlay | Starts the demo overlay against PostgreSQL, waits for the one-shot seed, and asserts it exits cleanly after creating telemetry and a demo login; reruns the seed and checks the row counts are unchanged |

Runtime limits are measured too. `backend/scripts/benchmark_correlation.py`
fills a scratch database with the synthetic dataset and times `correlate` at
increasing sizes; results are in
[`research/correlation-runtime.md`](research/correlation-runtime.md). At 788
sessions (310,078 pairs) a run takes about 28 s, and the 8,000-edge cap retains
every linked pair. At 982 sessions the same cap starts discarding links (1,953),
so the session cap is 800 — the largest measured window that keeps all links —
rather than the largest that fits a time budget.

The evaluation dataset is anchored to a fixed instant rather than the wall clock,
so a seed reproduces the same telemetry and the same counts on every run; two
consecutive full evaluations produced identical JSON apart from timestamps and
resource timings (`test_determinism.py`).

Benchmark, 63 sessions / 1953 pairs, two seeds, algorithm `corr-1.3.0`:

| Metric | Seed 7 | Seed 2026 |
| --- | --- | --- |
| Precision (proposed) | 1.000 | 1.000 |
| Recall (proposed) | 0.906 | 0.812 |
| Recall (Jaccard-only sequence comparison, previous model) | 0.812 | 0.562 |
| Recall (uniform family weights) | 0.875 | 0.812 |
| Precision (rule baseline) | 0.066 | 0.067 |
| False positives (proposed / rule) | 0 / 424 | 0 / 420 |
| Campaign-level exact recovery | 10 of 12 | 8 of 12 |
| Time to detection, median (groups reached) | 541 s (10 of 12) | 614 s (10 of 12) |

Resources: 19 MB peak, 31 ms per scored pair, CPU time equal to wall time, for
a full run including all ablations. Wall time on this host was about a minute
for the same workload that took about 6 s when the benchmark was first run, so
treat the seconds as host-dependent and the memory and per-pair cost as the
stable figures.

Time to detection is the elapsed campaign time until two members of one true
group had both emitted the events that link them. Correlation is batch, so this
measures when the evidence became sufficient, not when a run happened; a group
that never links has no time to detection.
Full tables, per-subset breakdowns, the deliberately hard subset and the
adaptive experiment are in `docs/research/evaluation-results.md`.

## Interpretation

- Precision of 1.000 with recall 0.81–0.91 is a conservative operating point:
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
- Comparing action sequences by overlap as well as Jaccard is the largest
  change in this revision: a session that recorded fewer commands should not
  count as evidence of different behaviour, and Jaccard treats the missing
  n-grams as disagreement. The Jaccard-only ablation scores 0.812 and 0.562,
  against 0.906 and 0.812 with overlap, at identical precision — so the gain is
  attributable to the comparison and not to a threshold. It also raises campaign
  recovery from 9 to 10 of 12 and from 4 to 8 of 12.
- Corpus-relative family weighting still contributes (0.875 → 0.906 on seed 7)
  and is measured against the uniform-weight ablation. Both changes were
  observed on the benchmark they were introduced for; there is no held-out set,
  so the gains are preliminary.
- The earlier adaptive numbers came from a simulation that gave every session
  in an activity category the same synthetic request path, which manufactured
  similarity that observation cannot produce. With observation that only
  replays behaviour the actor already showed, additional decoy time gains one
  link on seed 7, two on seed 2026 and two in the volume run, loses none and adds
  no false positives. That is consistent with the hypothesis but far too small a
  sample to call a demonstrated benefit; the production path records real decoy
  traffic and cannot add evidence, and every investigation stores before/after
  values.

## Deep scan

`scripts/deepscan.py` was run against the whole API surface on this host:

| Scan | Coverage | Findings |
| --- | --- | --- |
| Authorization matrix | 57 routes, 285 requests as admin, analyst, viewer, sensor and anonymous | 0 roles refused a permission they hold, 0 roles granted one they lack, 0 anonymous requests to guarded routes allowed, 0 5xx |
| Hostile inputs | 60 OpenAPI operations, 652 requests | 0 5xx; 413 above the 32.77 MB ingest bound; tampered and `alg: none` tokens 401; non-JSON parsed as nothing |
| SSRF payloads | 23 payloads across 9 loopback, link-local, private and IPv6 scopes | 0 targets reached |
| Outbound calls | 7 cases across market-data refresh, geolocation and an assessment redirect, against a local probe that redirects or announces a 33 MiB body | 0 redirects followed, 0 oversized bodies buffered, valid payloads still accepted |

Write latency was then measured against a real API with four worker processes on
PostgreSQL 16, six concurrent clients and a 6.4 s correlation run over 165
sessions and 13,530 pairs. Across two runs on a reset schema, idle p50 10.5–12.5 ms
and p95 13.4–18.7 ms became p50 10.7–16.3 ms and p95 23.8–25.1 ms during the scan;
the worst request moved from 43–134 ms to 555–699 ms. No write failed and the
accepted-event count reconciled exactly with the stored count. The median is
inside run-to-run noise; the tail is not. Per-scan detail, the two startup races
that measurement exposed, and what the scan does not cover are in
[`research/deepscan-results.md`](research/deepscan-results.md) and
[`research/write-contention.md`](research/write-contention.md).

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
- No load test beyond the 63-session benchmark, the volume run and the
  four-worker write measurement; sustained saturation, failover and multiple API
  hosts are not measured.
- Web assessment was tested against loopback targets, not a real external host.
