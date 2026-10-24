# Requirements traceability

Every stage of the master specification, the evidence that it is satisfied, and
the gaps that remain. Statuses: **Done** — implemented and exercised by a test
or a measurement quoted here. **Partial** — implemented with a stated
limitation. **Open** — not implemented.

## Stage map

| Stage | Requirement | Evidence | Status |
| --- | --- | --- | --- |
| 0 | Repository audit, feature inventory, baseline results | `docs/00-repository-audit.md`, `docs/08-implementation-status.md`, `docs/06-testing-and-evaluation.md` | Done |
| 1 | Locked product, architecture, contracts, traceability | `docs/PRODUCT_SPEC.md`, `docs/02-architecture.md`, `docs/04-event-contract.md`, `docs/05-api.md`, this file | Done |
| 2 | Prior work, comparison, falsifiable hypothesis, evaluation plan | `docs/01-novelty-review.md` (reviewed directions, gap, hypothesis, non-claims); benchmark protocol and baselines in `docs/research/evaluation-results.md` | Done |
| 3 | Shared foundation: config, migrations, schema, logging, auth, errors, health, audit, tests | `app/core/`, `app/db/`, `app/api/deps.py`, `test_foundation.py`, `test_security.py`, `test_advanced.py` | Done |
| 4 | Real telemetry pipeline with two independent sources | Generic `POST /ingest/events`, Cowrie JSON tailer (`app/deception/cowrie_adapter.py`), HTTP decoy, assessment and market modules share one contract; `test_pipeline.py`, `test_deception.py` | Done |
| 5 | First end-to-end workflow: controlled session → storage → detection → dashboard alert | `test_end_to_end.py` (login → ingest → correlate → campaign → response → audit), `test_browser.py` (Chrome against a live API) | Done |
| 6 | Cross-IP evidence graph, baselines, campaign formation, investigation UI | `app/correlation/`, `test_correlation.py`, `test_properties.py`, Campaigns and Overview views; campaign identity follows membership, and reviewed campaigns are archived or merged rather than deleted | Done |
| 7 | Uncertainty-aware adaptive deception, passive vs adaptive comparison | `app/deception/adaptive.py`, `test_adaptive.py`; comparison measured and reported — the benefit is **not** demonstrated (see Research claim) | Partial |
| 8 | Risk and explanation engine with separate severity, confidence and risk | `app/risk/scoring.py`, campaign explanations, `test_correlation.py`, dashboard campaign detail | Done |
| 9 | Remaining modules: web security, crypto, honeypot expansion, infrastructure | `app/websec/`, `app/cryptointel/`, `app/deception/`, `deploy/`, `test_websec.py`, `test_crypto.py`; crypto provider calls are unverified live | Partial |
| 10 | Unified dashboard with the eleven required views | `frontend/src/pages/`, view-by-view map below, `test_browser.py` renders every view without console errors | Done |
| 11 | Controlled response: policy, permissions, expiry, rollback, emergency disable | `app/response/`, `test_responses.py`, `test_advanced.py`, Responses view | Done |
| 12 | Research evaluation: baselines, ablations, scenarios, metrics | `backend/scripts/evaluate.py`, `docs/research/evaluation-results.md`; precision, recall, FPR/FNR, campaign recovery, time to detection, latency, CPU and memory all measured | Done |
| 13 | Security, reliability and regression testing | 145 tests, two engines, browser flow, container build, dependency audit; container, outage, backup/restore and upgrade checks in `docs/06-testing-and-evaluation.md` | Done |
| 14 | Deployment and release package | `Dockerfile`, `docker-compose.yml`, `.env.example`, `docs/07-operations.md`, `docs/02-architecture.md`, `docs/03-threat-model.md`, API docs at `/docs` | Done, verified on one host |

## Required dashboard views

| View | Implementation | Evidence |
| --- | --- | --- |
| System overview and health | `pages/Overview.tsx`: event volume, severity split, source health, latest correlation run, campaign candidates | `test_browser.py` renders it; API `summary`, `sources`, `correlation/latest` |
| Event stream | `pages/Events.tsx` with module, severity, source and time filters plus paging | `test_browser.py` renders it |
| Incident investigation | Campaign detail plus `pages/Deception.tsx` investigation lifecycle | `test_browser.py` plans and activates an investigation |
| Cross-IP relationship graph | `components/EvidenceGraph.tsx` inside Campaigns | `test_browser.py` renders the view; graph API tested in `test_correlation.py` |
| Campaign timeline | Campaign detail `explanation.timeline` | `test_correlation.py` |
| Honeypot sessions | `pages/Deception.tsx` decoy-session table backed by `GET /honeypot/sessions` (source IPs, event count, severity, target) | `test_foundation.py`, `test_deception.py`, `test_browser.py` |
| Web security findings | `pages/Findings.tsx` | `test_websec.py`, `test_browser.py` |
| Digital-asset risk intelligence | `pages/Crypto.tsx` with provenance, freshness and disclaimer | `test_crypto.py` |
| Explainable scoring | Campaign explanation, risk factors, evidence components, contradictions, missing evidence | `test_correlation.py` asserts the fields are persisted and returned |
| Response recommendations and audit history | `pages/Responses.tsx` plus audit table on Administration | `test_responses.py`, `test_advanced.py` |
| User access and configuration | `pages/Administration.tsx` (accounts, sessions, agent tokens, source health) and `pages/Account.tsx` | `test_browser.py` covers sessions and tokens |

## Measured research result

Algorithm `corr-1.3.0`; regenerated by `backend/scripts/evaluate.py`.

| Metric | Seed 7 | Seed 2026 | Volume (seed 99) |
| --- | --- | --- | --- |
| Precision / recall, proposed | 1.000 / 0.906 | 1.000 / 0.812 | 1.000 / 0.918 |
| Precision / recall, rule baseline | 0.066 / 0.938 | 0.067 / 0.938 | 0.017 / 0.984 |
| False positives, proposed / rule | 0 / 424 | 0 / 420 | 0 / 0.00% FPR (rule: 56.97%) |
| Campaign-level exact recovery | 10 of 12 | 8 of 12 | 37 of 42 |
| Time to detection, median (groups reached) | 541 s (10 of 12) | 614 s (10 of 12) | 584 s (40 of 42) |
| Wall / CPU per run | 60 s / 60 s | 59 s / 59 s | 132 s |
| Peak memory | 18.9 MB | 18.8 MB | 129.2 MB |
| Cost per pair | 30.9 ms | 30.0 ms | 9.7 ms |

The adaptive clause is measured separately: with a simulation that replays only
behaviour the actor already showed, additional observation gains one link on
seed 7, two on seed 2026 and two at volume, and loses none, with no new false
positives. That is consistent with the claim but too small a sample to call it
demonstrated, and the documents say so.

## Open gaps and decisions

| Gap | Reason | Where it is recorded |
| --- | --- | --- |
| Benchmark is synthetic, no public dataset | No redistributable labelled corpus was available; the generator is deterministic and documented so the result can be reproduced and challenged | `docs/research/evaluation-results.md` limitations |
| Adaptive benefit not demonstrated | The corrected simulation adds only observed behaviour, and that moves almost no decisions; field measurement would be needed | `docs/01-novelty-review.md`, `docs/08-implementation-status.md` |
| Market-data provider calls unverified live | The public API is reachable only from an unrestricted network; the fixture provider covers offline use | `docs/08-implementation-status.md` |
| Cowrie exercised with connection attempts, not a full shell | Time-boxed environment constraint; the adapter and offset handling were run against a real container | `docs/06-testing-and-evaluation.md` |
| Single-node deployment; batch correlation capped at 800 sessions | The cap is set from measured runtime rather than a graph database or worker fleet, which would add operating cost without a measured requirement | `docs/02-architecture.md`, `docs/research/correlation-runtime.md` |
| Time to detection excludes scheduling latency | Correlation is batch; the metric measures when evidence became sufficient, not when a run happened | `docs/research/evaluation-results.md` |
| Seven responsibility areas are staffed by one maintainer in this repository | The structure is reflected in module boundaries and documentation, not in commit identity | this file |

## Document map

| Spec deliverable | Repository document |
| --- | --- |
| `docs/REPOSITORY_AUDIT.md` | `docs/00-repository-audit.md` |
| `docs/FEATURE_INVENTORY.md` | `docs/08-implementation-status.md` |
| `docs/BASELINE_TEST_RESULTS.md` | `docs/06-testing-and-evaluation.md` |
| `docs/PRODUCT_SPEC.md` | `docs/PRODUCT_SPEC.md` |
| `docs/ARCHITECTURE.md` | `docs/02-architecture.md` |
| `docs/REQUIREMENTS_TRACEABILITY.md` | this file |
| `research/RELATED_WORK.md`, `COMPARISON_MATRIX.md`, `RESEARCH_HYPOTHESIS.md` | `docs/01-novelty-review.md` |
| `research/EVALUATION_PLAN.md` | `docs/06-testing-and-evaluation.md` |
| Research output | `docs/research/evaluation-results.md`, `.json` |

Documents are kept true by the rule in `docs/README.md`: a change to behaviour,
configuration, an endpoint or a measured number changes the matching document in
the same commit.
