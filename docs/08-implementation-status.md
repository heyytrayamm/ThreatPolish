# Implementation status

Legend: **Done** — implemented and exercised by tests or measurements.
**Partial** — implemented, with a stated limitation. **Not done** — absent, and
why.

## Foundation

| Item | Status | Evidence |
| --- | --- | --- |
| API skeleton, versioned contract, OpenAPI | Done | `app/main.py`, `/openapi.json` |
| Configuration from environment | Done | `app/core/config.py`, `.env.example` |
| Database models for all modules | Done | `app/db/` |
| Event contract and validation | Done | `app/schemas/event.py`, `test_foundation.py` |
| Ingestion with hashing, dedup, quarantine | Done | `app/telemetry/ingest.py`, `test_pipeline.py` |
| Auth, RBAC, audit trail | Done | `app/auth/`, `test_foundation.py`, `test_security.py`; password change and the admin session revocation both act on the account session version, the session history is derived from the audit trail with client, address and validity, one device can be signed out through a revocation list keyed by token id, an administrator can sign one device out of another account while its other sessions continue, and a second live session from another network raises `auth.signin.anomaly` (`test_signin_alerts.py`). Session and target identifiers reject control characters, so a sensor cannot craft a session id that collides with the relationship-key separator (`test_properties.py`) |
| Dashboard shell and navigation | Done | `frontend/` builds cleanly; the Deception page lists decoy sessions with their addresses and event counts; the account page rotates the password, keeps the replacement token, lists recent sign-ins and signs out one device, the Overview page raises recent sign-in alerts, administration opens any account's session history, signs one device out of it and manages sensor tokens, the Events filters and open view are URL-backed with filter history, both the Events page and Retention card copy the current link with a Clipboard API fallback, the Retention page gives analysts a read-only history with shareable, validated URL filters and CSV export, browser back and forward restore views and filter states, and `test_browser.py` drives the password, plan/activate, session-management, retention and token flows in Chrome |
| Test harness | Done | 193 tests passing on SQLite in 83.2 s, isolated per test, six of them driving Chrome against a live API; the same 193 pass against PostgreSQL 16 in 172.3 s |
| Deep scan of every route | Done | `backend/scripts/deepscan.py` derives permissions from each route's dependency closure and calls it as every role and anonymously, then sends hostile parameters, malformed bodies, tampered tokens and 23 SSRF payloads; it also points every outbound call at a local probe that redirects or announces a 33 MiB body. Measured 57 routes / 285 authorization checks with no disagreement, 652 hostile requests with no 5xx, no SSRF target reached, and no redirect followed (`docs/research/deepscan-results.md`). CI runs it and keeps the reports |
| Reproducible benchmark | Done | `backend/scripts/evaluate.py`; reports precision, recall, false-positive and false-negative rates, campaign recovery, time to detection, wall and CPU time, memory and milliseconds per pair. The dataset is anchored to a fixed instant, so a seed reproduces the same telemetry and counts (`test_determinism.py`) |
| Audit, novelty review, architecture, threat model | Done | `docs/00`–`docs/03` |
| License | Done | Proprietary notice, all rights reserved by the project team |

## Deception

| Item | Status | Evidence |
| --- | --- | --- |
| Decoy profiles (SSH, HTTP, DB, telnet) | Done | `app/deception/profiles.py` |
| HTTP decoy service | Done | `http_decoy.py`, exercised over HTTP |
| Cowrie log adapter | Done | ran against a real Cowrie container; offset persisted outside the read-only log volume |
| Password capture as hashes | Done | `test_deception.py` |
| Uncertainty-directed investigation | Partial | persisted activation shared with the decoy process and real before/after records. The benchmark simulation now replays only behaviour the actor already showed; under it additional observation gains one link on seed 7, two on seed 2026 and two at volume, loses none and adds no false positives, so the effect points the right way but is too small to call demonstrated and field measurement is still required |
| Automatic decoy rotation from attacker tooling | Not done | the investigation mutates profile choice and records it, but there is no live adaptive server reconfiguration |

## Correlation and risk

| Item | Status | Evidence |
| --- | --- | --- |
| Session feature extraction | Done | `features.py` |
| Corpus-relative token weighting | Done | `scoring.py`, unit tested |
| Six-family evidence scoring | Done | weights sum to 1.0, tested |
| Specificity anchors and contradiction penalty | Done | `test_correlation.py` |
| Corpus-relative family weighting | Done | `_effective_weights` scales each family by the share of its tokens that survive the ubiquity filter, recorded per edge; measured against the `ablation_uniform_weights` run, which reproduces the previous model |
| Overlap-based sequence comparison | Done | action sequences score by containment as well as Jaccard, so a session that recorded fewer commands is not read as disagreement; `sequence_similarity` is recorded per edge and the `ablation_jaccard_only` run reproduces the previous comparison (seed 7 recall 0.812 vs 0.906, seed 2026 0.562 vs 0.812, precision unchanged at 1.000) |
| Campaign membership follows edge state | Done | edges that become hypotheses or expire lose their campaign and campaign views count only active links (`campaign_id=None` on expiry, `status = 'active'` in `get_campaign`); expiry keeps the original evidence and records why and when it was retired (`test_correlation.py`) |
| Edge persistence with full evidence | Done | `graph_edges`, `test_correlation.py` |
| Campaign construction | Done | `engine.py`; new member sets inherit an existing campaign when at least half of its membership survives, so growth and shrinkage keep one identifier and record the added and removed sessions in `membership_history` |
| Campaign lifecycle and archived reviews | Done | a reviewed campaign, or one an investigation or response refers to, is archived rather than deleted when its links disappear; a merge moves feedback and response references to the surviving campaign, carries a single analyst decision forward and turns conflicting decisions into `uncertain`; default listing excludes archived rows and `include_archived=true` shows them (`test_correlation.py`) |
| Risk, severity, journey escalation | Done | `app/risk/scoring.py` |
| Interactive graph and campaign views | Done | `frontend/src/components/EvidenceGraph.tsx` |
| Campaign evidence matrix | Done | Campaign detail plots the stored pairwise confidence grid with family-contribution bars; empty cells are a store-threshold finding (`pages/Campaigns.tsx`, `test_correlation.py`) |
| Evidence acquisition plan and observation efficiency | Done | Campaign detail ranks unavailable families by affected pairs and weight at stake, names families never recorded, and reports observations per link and per session (`repository.py`, `test_correlation.py`); both are rendered on the Campaigns page |
| Tactic coverage | Done | `killchain.py` maps normalized categories and authentication activity to eleven ATT&CK-style tactics with coarse consequence weights; campaign detail reports breadth, risk-weighted coverage and the furthest observed tactic (`test_killchain.py`) |
| Analyst feedback loop | Done | `/feedback`, stored and listed; feedback follows a merged campaign instead of pointing at the absorbed row, and a review on an archived campaign remains readable |
| Learned/calibrated confidence | Not done | would require labelled production data; explicitly out of scope |
| Streaming/incremental correlation | Not done | correlation is batch over a window |

## Assessment and intelligence

| Item | Status | Evidence |
| --- | --- | --- |
| Explicit scope with authorization and expiry | Done | `websec/scope.py`; when scopes overlap, the narrowest live one governs, so a broad grant cannot relax the limits set for a specific host (`test_properties.py`) |
| SSRF guards (scheme, DNS, private ranges) | Done | `test_websec.py` |
| Non-destructive checks | Done | headers, TLS, exposed paths, cookies |
| Findings flow into the shared event contract | Done | same ingestion path |
| Asset quotes and signals | Partial | CoinGecko adapter plus fixture provider; no catalog provider available, external calls unverified live |
| Asset exposure tied to campaigns | Done | `/crypto/assets`, campaign assets |

## Response

| Item | Status | Evidence |
| --- | --- | --- |
| Policy matrix with impact levels | Done | `response/policy.py` |
| Approval requirement for high impact | Done | `test_responses.py` |
| Expiry and rollback | Done | state machine, 409 on invalid transition |
| Emergency disable | Done | admin endpoint |
| Execution adapters (firewall, EDR) | Not done | actions are recorded and state-managed; no external device integration, by design for a lab system |

## Operations

| Item | Status | Evidence |
| --- | --- | --- |
| Dockerfile and Compose stack | Done | built and run on this host; API healthy as non-root; restart, backup/restore and database-outage behaviour verified |
| PostgreSQL production path | Done | migrations, all module flows and recovery verified against PostgreSQL 16 |
| Multi-worker API startup and write contention | Done | a real API with four worker processes starts against a fresh PostgreSQL schema without a startup failure: the bootstrap administrator and decoy-profile seeds tolerate losing the insert race, and migrations take a transaction-scoped advisory lock; ingestion from six clients during a 6.4 s correlation run had no errors, the accepted events reconciled exactly, p95 18.7 → 24.5 ms and the worst request 43 → 555 ms (`docs/research/write-contention.md`) |
| Backup, restore, retention, runbooks | Done | `docs/07-operations.md`, including a step-by-step session-compromise runbook that runs from a sign-in alert to a revoked device. Event retention and graph retention are separate: `purge-graph` deletes retired edges past `TP_GRAPH_RETENTION_DAYS`, the observation records of sessions that old with no live similarity or campaign edge, and nodes nothing references, while keeping hypotheses, active evidence and archived reviews (`test_correlation.py`). A Compose `retention` service runs both horizons on start and on `TP_RETENTION_INTERVAL_SECONDS`; `GET /retention` reports backlog and graph size, Administration shows it with a backlog trend, a run table with trigger, duration and removed counts, a total run count when the view is truncated, UTC date-range and trigger filtering with quick ranges, shareable URLs and filter history, a Copy link action with a Clipboard API fallback, validation and cleanup of malformed or inverted shared filters, CSV export of up to 1,000 matching runs, a confirmed manual run and a read-only analyst view; the Overview raises the overdue alert to analysts as well once the backlog is older than `TP_RETENTION_GRACE_DAYS`; each run writes history plus a `retention.run` audit entry; and `GET /metrics` exports the backlog for monitoring (`test_retention.py`, `test_browser.py`) |
| Health and readiness probes | Done | `/api/v1/health`, `/api/v1/health/ready` |
| Schema migrations and upgrade path | Done | v3 PostgreSQL database upgraded to v5 on a restorable copy; v5 upgraded to v7 on SQLite and PostgreSQL 16, including a copy seeded with duplicate open investigations; v7 → v8 (per-session revocation) verified on both engines; v8 → v9 (campaign lifecycle) adds nullable columns and is covered by a migration test starting from a v8-shaped table; v9 → v10 adds the retention indexes with `IF NOT EXISTS`, so it is safe on a database that already has them; v10 → v11 adds the retention run history table behind an existence check; the graph retention, status and history SQL was run against PostgreSQL 16.2 |
| CI pipeline | Done | `.github/workflows/ci.yml` runs backend lint and tests on SQLite and PostgreSQL 16, an explicit PostgreSQL run of the retention tests, dependency audits, the dashboard build, a container image build and a live demo Compose overlay that asserts the seed exits cleanly with telemetry and a demo login, then reruns it without changing the row counts |
| Dependency scanning | Done | a CI job runs `pip-audit` over the installed backend environment and `npm audit --audit-level=high` over the dashboard lockfile; `make audit` reproduces both locally |

## Deliberate non-goals

- Exploitation, fuzzing or credential attacks against third parties.
- Actor identification or attribution to a person, organisation or state.
- Offensive countermeasures against attackers.
- Storing captured plaintext credentials.
