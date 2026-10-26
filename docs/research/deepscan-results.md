# Deep scan results

Measured 2026-10-27 on the development host: Python 3.12.3, SQLite 3.45.1,
PostgreSQL 16.15 (`postgres:16-alpine` in a container), Playwright 1.64.1 with
Chromium. Every number below came from a command in this document; nothing is
estimated.

The scan complements the test suite rather than replacing it: the suite asserts
specific behaviours, the scan asks the same questions of *every* route, including
routes added later, and fails on any 5xx or any authorization decision that
disagrees with the role matrix.

## Reproducing

```bash
cd backend
python scripts/deepscan.py                    # all three scans
python scripts/deepscan.py --only authz       # one scan
python scripts/deepscan.py --json             # full report, including per-payload rows

python -m pytest -q                                                    # SQLite
TP_TEST_DB_URL=postgresql+psycopg://... python -m pytest -q            # PostgreSQL 16
python -m pytest -q tests/test_browser.py                              # built bundle + Chromium
```

`deepscan.py` creates a temporary SQLite database, bootstraps an administrator,
creates a viewer, an analyst and a sensor, and drives the application through
`TestClient`. It only calls the application's own HTTP surface — no third-party
host is contacted, and no state outside the temporary database is touched.
The one exception is `POST /api/v1/crypto/refresh`, which the input scan calls
with hostile bodies; the endpoint itself may reach the market-data provider on a
successful refresh, so the scan's `status_distribution` counts that call as a 200
without asserting anything about the provider.

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

## Suite across engines

| Engine | Tests | Wall time |
| --- | --- | --- |
| SQLite 3.45.1 | 186 passed | 91.51 s |
| PostgreSQL 16.15 | 186 passed | 233.59 s |

The conftest fixture drops and recreates the `public` schema before each test on
PostgreSQL, so the two runs have the same isolation. Timing differs because each
test also pays for a schema reset and a fresh connection pool.

## Browser end-to-end

`tests/test_browser.py` starts the API on a free port, serves the built React
bundle and drives Chromium: **5 passed in 23.73 s**. It is skipped when the
bundle is missing, stale relative to its sources, or Playwright is absent, so the
default suite stays dependency-free.

## Write latency during a correlation run

160 sessions were ingested, then correlation was run on a background thread while
20 unrelated audit writes were timed inside the same window. The baseline is the
same 20 writes with no correlation running.

| Condition | Writes | p50 | max | Errors |
| --- | --- | --- | --- | --- |
| Correlation running (12,720 pairs, 13.38 s) | 20 | 1.45 ms | 2.02 ms | 0 |
| Idle | 20 | 1.49 ms | 2.69 ms | 0 |

Writes issued while pairs were being scored were not slower than idle writes on
this host, so the correlation transaction does not hold a lock that blocks
unrelated writes for the duration of a run. This is a single-process SQLite
measurement; it says nothing about many API workers sharing one PostgreSQL
instance, which is not measured here.

## Defect found and fixed: the benchmark was not reproducible

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
generation consults the clock at all.

After the fix, two consecutive full evaluations produced byte-identical JSON
apart from `generated_at` and the resource timings, and the seed 7 ambiguity
count is stable at 213. The regenerated report in
[`evaluation-results.md`](evaluation-results.md) carries those numbers.

## What this scan does not cover

- Only the application's own HTTP surface: no third-party hosts, no dependency
  version audit (`pip-audit` / `npm audit` run separately in CI).
- No multi-worker or multi-process contention test, and no PostgreSQL write
  contention measurement.
- The SSRF scan exercises the assessment endpoint, not every outbound call the
  platform can make (market-data provider, decoy redirects).
- No timing side channels, no password-cracking cost measurement, and no test of
  the container image's runtime hardening (that is recorded in
  [`../06-testing-and-evaluation.md`](../06-testing-and-evaluation.md)).
- The scans run as an administrator who creates the authorization scopes they
  need; they do not model an attacker without credentials beyond the anonymous
  rows of the authorization matrix.
