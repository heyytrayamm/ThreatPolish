# ThreatPolish product specification

This is the authoritative scope for the repository, condensed from the master
brief. Where this document and an older document disagree, this one governs the
intent and `docs/REQUIREMENTS_TRACEABILITY.md` records what is actually built.

## Product

ThreatPolish is one deployable cybersecurity intelligence platform. It collects
security events from several authorized sources, decides whether activity
arriving from different addresses and different sources may belong to one
coordinated campaign, explains every relationship with its evidence and its
gaps, asks for more observation through isolated decoys when the answer is
genuinely uncertain, and supports policy-gated defensive response.

It is **not** an SSH honeypot, a scanner, a chat interface, a log dashboard, a
bundle of unrelated modules, or a system that identifies a person from an IP
address.

## The one differentiator

**Evidence-linked cross-IP campaign intelligence.** Events from different
addresses and sources are normalized, feature-extracted, compared over named
evidence families, and kept in an evidence graph whose edges carry confidence,
missing evidence, contradictions, an algorithm version and a human-readable
explanation. Campaign candidates are formed only where the evidence supports
grouping, and an analyst can reject a link. A controlled, isolated decoy
investigation may be requested for an uncertain relationship and its effect is
measured against passive collection.

The research claim is a hypothesis, not a premise: evidence-weighted,
uncertainty-aware correlation is compared against IP-only grouping and a
rule-based baseline, with ablations, and the measured result — including the
clauses that fail — is published in `docs/research/evaluation-results.md`.

## Required modules

| Module | Responsibility | Primary code |
| --- | --- | --- |
| Infrastructure and network | Deployment, boundaries, TLS, isolation, health | `Dockerfile`, `docker-compose.yml`, `app/core/config.py` |
| Telemetry and data engineering | Ingestion, validation, normalization, persistence, deduplication, retention, source health | `app/telemetry/`, `app/schemas/event.py`, `app/db/` |
| Web application security | Scope-limited assessment, findings, evidence, remediation | `app/websec/` |
| Crypto and digital-asset risk | Approved market data, documented indicators, provenance and freshness | `app/cryptointel/` |
| Honeypot and deception | Isolated SSH/HTTP decoys, session telemetry, adaptive observation | `app/deception/`, `deploy/cowrie/` |
| Detection and analytics | Features, cross-IP correlation, evidence graph, campaigns, confidence, risk, feedback | `app/correlation/`, `app/risk/`, `app/evaluation/` |
| Unified frontend and API | Auth, dashboard views, investigation, reports, response controls, status | `app/api/`, `frontend/` |

The modules are separate engineering responsibilities inside one modular
monolith, one database, one event contract and one dashboard.

## Fixed architecture

```text
authorized sources -> source adapters -> validation and normalization
      -> shared event pipeline -> event storage + feature extraction
      -> cross-IP correlation -> evidence graph -> campaign candidates
      -> explainable risk engine -> analyst dashboard (feedback)
                                 -> policy engine -> approved response
```

Adaptive deception attaches through a restricted interface: it may request
observation from an approved, isolated decoy profile and may not execute
attacker input or reach production systems.

Architecture rules: inspect before replacing; prefer the existing stack; a
modular monolith until measurements justify distribution; relational storage
with migrations; the evidence graph in SQL until a graph database earns its
operating cost; asynchronous work only where needed; versioned schemas and
APIs; every module observable and independently testable; secrets out of source;
decoys never reach sensitive infrastructure.

## Non-negotiable standards

No fake functionality, no fabricated logs or results, no hardcoded credentials,
no unauthorized testing, no arbitrary execution of attacker input, no
unnecessary rewrites, no unversioned contract changes, no untested migrations,
no identity attribution from addresses, no unsupported novelty claim, no
unverified deployment claim, no swallowed errors, and no stage marked complete
before its acceptance criteria pass. Use the simplest reliable implementation;
do not add ML, graph infrastructure or extra services to look advanced.

## Definition of done

The platform is releasable when every required module works and is integrated;
events flow from real sources through normalization, storage and detection;
cross-IP relationships are evidence-backed and uncertainty-aware; campaigns are
distinguishable from isolated alerts; deception is isolated, safe and
experimentally evaluated; findings explain their evidence and limits; the
dashboard shows backend data; response follows authorization and policy; tests
cover security, integration, reliability and performance; deployment and
recovery instructions are verified; and the research claim is supported by
prior-work analysis and reproducible measurement.

Stage-by-stage status, the tests that evidence each requirement and the open
gaps are in `docs/REQUIREMENTS_TRACEABILITY.md`.
