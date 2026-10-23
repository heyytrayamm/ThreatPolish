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
| Auth, RBAC, audit trail | Done | `app/auth/`, `test_foundation.py`, `test_security.py` |
| Dashboard shell and navigation | Done | `frontend/` builds cleanly |
| Test harness | Done | 97 tests on SQLite, isolated per test; the same suite runs against PostgreSQL 16 in CI, plus container smoke checks |
| Reproducible benchmark | Done | `backend/scripts/evaluate.py` |
| Audit, novelty review, architecture, threat model | Done | `docs/00`–`docs/03` |
| License | Done | Proprietary notice, all rights reserved by the project team |

## Deception

| Item | Status | Evidence |
| --- | --- | --- |
| Decoy profiles (SSH, HTTP, DB, telnet) | Done | `app/deception/profiles.py` |
| HTTP decoy service | Done | `http_decoy.py`, exercised over HTTP |
| Cowrie log adapter | Done | ran against a real Cowrie container; offset persisted outside the read-only log volume |
| Password capture as hashes | Done | `test_deception.py` |
| Uncertainty-directed investigation | Partial | persisted activation shared with the decoy process and real before/after records; the *benefit* is measured with a simulated observation in the benchmark, field measurement pending |
| Automatic decoy rotation from attacker tooling | Not done | the investigation mutates profile choice and records it, but there is no live adaptive server reconfiguration |

## Correlation and risk

| Item | Status | Evidence |
| --- | --- | --- |
| Session feature extraction | Done | `features.py` |
| Corpus-relative token weighting | Done | `scoring.py`, unit tested |
| Six-family evidence scoring | Done | weights sum to 1.0, tested |
| Specificity anchors and contradiction penalty | Done | `test_correlation.py` |
| Edge persistence with full evidence | Done | `graph_edges`, `test_correlation.py` |
| Campaign construction | Done | `engine.py` |
| Risk, severity, journey escalation | Done | `app/risk/scoring.py` |
| Interactive graph and campaign views | Done | `frontend/src/components/EvidenceGraph.tsx` |
| Analyst feedback loop | Done | `/feedback`, stored and listed |
| Learned/calibrated confidence | Not done | would require labelled production data; explicitly out of scope |
| Streaming/incremental correlation | Not done | correlation is batch over a window |

## Assessment and intelligence

| Item | Status | Evidence |
| --- | --- | --- |
| Explicit scope with authorization and expiry | Done | `websec/scope.py` |
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
| Backup, restore, retention, runbooks | Done | `docs/07-operations.md` |
| Health and readiness probes | Done | `/api/v1/health`, `/api/v1/health/ready` |
| Schema migrations and upgrade path | Done | v3 PostgreSQL database upgraded to v5 on a restorable copy |
| CI pipeline | Done | `.github/workflows/ci.yml` runs backend lint and tests on SQLite and PostgreSQL 16, the dashboard build and a container image build |
| Dependency scanning | Not done | commands documented, not automated |

## Deliberate non-goals

- Exploitation, fuzzing or credential attacks against third parties.
- Actor identification or attribution to a person, organisation or state.
- Offensive countermeasures against attackers.
- Storing captured plaintext credentials.
