# Changelog

All notable changes to this project are recorded here. Dates use ISO 8601.

## 1.0.0 — 2026-10-23

Initial release.

### Added

- Versioned telemetry contract with validation, normalization, hashing,
  deduplication, quarantine and retention.
- HTTP decoy, Cowrie JSON adapter and database-backed decoy profiles.
- Cross-IP correlation over six evidence families with corpus-relative
  weighting, specificity anchors, contradictions and per-edge explanations.
- Campaign candidates, graph view, risk separation and analyst feedback.
- Uncertainty-directed investigation with bounded activation and recorded
  before/after evidence.
- Scope-limited web assessment with SSRF guards and non-destructive checks.
- Digital-asset risk with a provider adapter, provenance and freshness.
- Policy-gated response engine with approval, expiry, rollback and audit.
- React/TypeScript analyst dashboard with a strict Content-Security-Policy.
- Docker/Compose deployment, CLI, schema migrations, backup and recovery
  runbooks.
- Seeded evaluation harness with baselines, ablations, adaptive experiment and
  a volume run.

### Fixed

- PostgreSQL rejected optional `NULL` parameters in campaign listing and
  duplicate-investigation lookup; predicates are now built conditionally.
- Cowrie's Compose profile now uses a shared writable log volume, the image's
  actual fake filesystem paths and an offset outside the read-only log mount.
- Correlation preserves evidence in windows smaller than ten sessions instead of
  treating every shared token as ubiquitous.
- Malformed assessment ports return a validation error rather than a server
  error.
- Production refuses example signing secrets; the API runs one worker so
  startup migrations cannot race.

### Security

- Bearer tokens are kept in tab-scoped storage.
- The dashboard CSP is sent by the API and scoped to dashboard responses.
- Agent tokens are stored as hashes and can be revoked.
- Build context excludes secrets, local data and build artefacts.
