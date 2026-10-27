# Deep scan results

Measured 2026-10-27 on the development host: Python 3.12.3, SQLite 3.45.1,
PostgreSQL 16.15 (`postgres:16-alpine` in a container), Playwright 1.64.1 with
Chromium. Every number below came from a command in this document; nothing is
estimated.

The scan complements the test suite rather than replacing it: the suite asserts
specific behaviours, the scan asks the same questions of *every* route, including
routes added later, and fails on any 5xx, any authorization decision that
disagrees with the role matrix, or any outbound redirect it followed. It runs as
a CI job and the reports are uploaded as an artifact.

## Reproducing

```bash
cd backend
python scripts/deepscan.py                    # all four scans
python scripts/deepscan.py --only authz       # one scan
python scripts/deepscan.py --json             # full report, including per-payload rows

python -m pytest -q                                                    # SQLite
TP_TEST_DB_URL=postgresql+psycopg://... python -m pytest -q            # PostgreSQL 16
python -m pytest -q tests/test_browser.py                              # built bundle + Chromium

# Needs PostgreSQL; starts its own four-worker API against a reset schema.
python scripts/benchmark_write_contention.py \
  --db-url postgresql+psycopg://... --workers 4 --writers 6 --repeat 2
```

`deepscan.py` creates a temporary SQLite database, bootstraps an administrator,
creates a viewer, an analyst and a sensor, and drives the application through
`TestClient`. It only calls the application's own HTTP surface and its own local
probe server; no third-party host is contacted, and no state outside the temporary
database is touched. Reports are written to `backend/deepscan-reports/`.

## Authorization matrix

Permissions are read from each route's FastAPI dependency closure, then the route
is called as every role and anonymously. A role that lacks a permission must be
refused (401/403); a role that holds it must not be; any 5xx fails the run.

| Measurement | Result |
| --- | --- |
| API routes exercised (health and login excluded) | 57 |
| Requests | 285 |
| Routes where a role holding the permission was refused | 0 |
| Routes where a role without the permission was allowed | 0 |
| Anonymous requests to a guarded route that were not refused | 0 |
| 5xx responses | 0 |

Empty JSON bodies are sent on write routes, so a 422 from validation cannot be
mistaken for an authorization decision: FastAPI resolves the security dependency
before the body, and the scan asserts the 401/403 arrives first.

## Adversarial input scan

Every operation in the OpenAPI document (60 operations) is called with hostile
query strings and path parameters, hostile JSON bodies, raw malformed bodies,
tampered bearer tokens, wrong content types and oversized bodies.

| Measurement | Result |
| --- | --- |
| Operations from `/openapi.json` | 60 |
| Requests | 652 |
| 5xx responses | 0 |
| Status distribution | 200:128, 202:8, 401:22, 404:158, 405:7, 413:1, 422:328 |

Behaviours confirmed by the run:

- a 33 MiB ingest body is refused with **413** before a parser sees it (the bound
  is 500 events × 64 KiB = 32.77 MB); bodies under that bound that are not valid
  JSON are refused with 422;
- `NaN`, `Infinity`, a lone surrogate, `__proto__` keys and 5,000-character
  strings never reach a stored event or a response body;
- `alg: none` tokens, tokens with a rewritten payload, tokens with an empty
  signature and 10,000-character strings are all refused with 401, never 5xx;
- wrong content types (`text/plain`, form-encoded, XML) are refused rather than
  parsed as JSON.

## SSRF payloads

Nine authorization scopes are created for loopback, link-local, private and IPv6
targets, then 23 payloads are assessed with loopback access disabled.

| Measurement | Result |
| --- | --- |
| Scopes recorded | 9 of 9 |
| Payloads | 23 |
| Targets reached (HTTP 200) | 0 |

Private and loopback targets are refused with `403 forbidden` — decimal,
octal, integer, IPv4-mapped IPv6, zone-id and redirect-style spellings included.
Non-HTTP schemes, credentials in the URL, unparseable hosts and port 0 are
refused with `422 validation_failed`.

## Outbound calls

The platform makes three kinds of outbound call: market-data refresh,
geolocation lookup and an assessment of an authorized target. The scan runs a
local probe that answers valid JSON, redirects, or announces a 33 MiB body, and
then asserts what the platform did with each.

| Call | Case | Result |
| --- | --- | --- |
| Market-data refresh | Valid payload | 200, `BTC` observed |
| Market-data refresh | Redirect to a loopback path | 502 `upstream_failure`, redirect target never requested |
| Market-data refresh | 33 MiB body | 502 `upstream_failure`, 256 KiB written by the probe, refused at the 1 MiB bound |
| Geolocation | Valid payload | Located |
| Geolocation | Redirect | Not located, redirect target never requested |
| Geolocation | 33 MiB body | Not located, refused at the bound |
| Web assessment | Target redirects to an authorized `10.0.0.1` | Partial scan, `target resolves to a non-public address` |

Two calls, the market-data provider and geolocation lookup, previously used
`httpx.get(...).json()`: a provider, proxy or DNS hijack could have made the
process buffer an unbounded body. Both now go through
`app/core/outbound.py`, which streams, stops at 1 MiB, refuses a non-200
(including every redirect) and parses only what it read. The assessment path
already had its own per-hop authorization and bound in `websec/scanner.py`.

## Suite across engines

| Engine | Tests | Wall time |
| --- | --- | --- |
| SQLite 3.45.1 | 193 passed | 83.22 s |
| PostgreSQL 16.15 | 193 passed | 172.34 s |

The conftest fixture drops and recreates the `public` schema before each test on
PostgreSQL, so the two runs have the same isolation. Timing differs because each
test also pays for a schema reset and a fresh connection pool.

## Browser end-to-end

`tests/test_browser.py` starts the API on a free port, serves the built React
bundle and drives Chromium: **6 passed in 24.83 s**. It is skipped when the
bundle is missing, stale relative to its sources, or Playwright is absent, so the
default suite stays dependency-free.

One case renders a synthetic graph with two campaigns whose labels share the
prefix `cross-IP campaign candidate`; it asserts that the two labels are
distinguishable, do not overlap each other and stay inside the SVG frame.

## Write latency during a correlation run

A real API with **four worker processes** ran against PostgreSQL 16. The labelled
evaluation dataset (165 sessions, 1,284 events) was ingested through the public
endpoint, then six clients posted unrelated events continuously while one client
triggered a correlation run over 13,530 pairs. The same clients also ran for
three seconds with no correlation, as the baseline. Each run started from a reset
schema; the two runs are independent.

| Metric | Idle (run 1) | Busy (run 1) | Idle (run 2) | Busy (run 2) |
| --- | ---: | ---: | ---: | ---: |
| Requests | 730 | 1,651 | 724 | 1,420 |
| Accepted events | 730 | 1,651 | 724 | 1,420 |
| p50 | 10.47 ms | 11.08 ms | 12.52 ms | 10.74 ms |
| p95 | 13.40 ms | 23.78 ms | 18.70 ms | 24.45 ms |
| Worst request | 120.36 ms | 698.64 ms | 43.14 ms | 554.71 ms |
| Errors | 0 | 0 | 0 | 0 |
| Correlation wall | — | 6.42 s | — | 6.64 s |

The median is inside this host's run-to-run noise and actually measured lower in
one busy run. The tail is consistent: p95 roughly doubles, and the worst request
is 5–13× slower while the scan holds its transaction. No write failed, and in
both runs the stored event count equalled the seed plus every accepted write
(3,631 after run 1's sequence), so the reader and the writers neither lost nor
duplicated an event.

Write traffic is timestamped two days in the past so that it falls outside the
24-hour correlation window: the run still scores exactly the seeded corpus, while
the rows and indexes being written are the same ones the scan reads.

An earlier single-process SQLite measurement (160 sessions, 12,720 pairs, 20
unrelated audit writes, p50 1.45 ms idle and while correlating) is not comparable:
SQLite serialises writers, so it could not show contention between processes.
That is why the multi-worker measurement exists.

## Defects found and fixed

### The seeded benchmark was not reproducible

While re-running the evaluation for this scan, the same seed produced different
counts on different runs:

| Run | Seed 7 ambiguous pairs | Seed 2026 ambiguous pairs |
| --- | --- | --- |
| Committed report | 214 | 208 |
| First re-run | 213 | 205 |
| Second and third re-run | 214, 211 | 208 |

The cause was in `app/evaluation/scenarios.py`: the generator anchored its base
timestamp on `datetime.now()`, so the hour-of-day features shifted between runs
and pairs sitting near a threshold changed decision.

The fix anchors the evaluation dataset to a fixed instant
(`runner.BENCHMARK_START`) while leaving the demo seeder and the runtime
benchmark on the wall clock, where "recent" is the point. `generate_dataset`
takes an optional `now`, and `tests/test_determinism.py` fails if dataset
generation consults the clock at all. Two consecutive full evaluations now
produce byte-identical JSON apart from `generated_at` and resource timings.

### A four-worker API could not start on a fresh database

The first contention run failed before it measured anything: with four workers
starting together, the server exited during startup.

- `ensure_bootstrap_admin()` counted users and then inserted. Two workers both saw
  an empty table; the loser hit the unique constraint and its lifespan aborted.
- `seed_default_profiles()` did the same for the four shipped decoy profiles.
- `init_db()` applied and recorded migrations with no lock, so concurrent workers
  could run the same DDL twice.

The first two now treat the unique-constraint loser as the expected outcome of a
concurrent start (`test_foundation.py` reproduces it by forcing both workers to
see an empty table). PostgreSQL migrations take a transaction-scoped advisory
lock. After the fix, four workers start reliably against a reset schema, which is
what the measurement above ran on.

### Unbounded provider responses

The market-data adapter and the geolocation lookup buffered whatever the remote
sent before parsing it. Both now use the bounded helper described above, and
`tests/test_outbound.py` fails if a declared 8 MiB body is read rather than
refused.

## What this scan does not cover

- Only the application's own HTTP surface and its outbound calls: no dependency
  version audit (`pip-audit` / `npm audit` run separately in CI) and no
  third-party service behaviour.
- No sustained saturation, failover across API hosts, or multi-host database
  contention; the write measurement is one host, four workers and six clients.
- No timing side channels, no password-cracking cost measurement, and no test of
  the container image's runtime hardening (recorded in
  [`../06-testing-and-evaluation.md`](../06-testing-and-evaluation.md)).
- The scans run as an administrator who creates the authorization scopes they
  need; they do not model an attacker without credentials beyond the anonymous
  rows of the authorization matrix.
