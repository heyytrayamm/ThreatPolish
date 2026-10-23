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
- CI pipeline covering lint, the full suite on SQLite and PostgreSQL 16, the
  dashboard build and a container image build.
- Seeded evaluation harness with baselines, ablations, adaptive experiment and
  a volume run.
- Dashboard screenshots and a documentation index for review.

### Fixed

- Adaptive activation is persisted on the investigation row and loaded by the
  decoy process; expired activations are marked `expired` and release their
  subject instead of blocking it indefinitely.
- Campaign detail now loads exactly its member sessions, so members older than
  the graph window remain visible.
- Assessment redirects are re-authorized and re-checked for private addresses;
  credential-bearing redirects are refused and response bodies are capped.
- Session-pair identifiers use a separator that cannot occur in a session ID;
  migration 5 re-keys legacy edges from their endpoint columns.
- The dashboard now uses the project logo for navigation, sign-in and favicon.
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
- A sparse event-volume window rendered as one full-width block; bars now cap
  their width and label counts when few buckets exist.
- The container dashboard build used `npm install`; it now uses `npm ci` so the
  lockfile is authoritative.
- Events containing `NaN`/`Infinity` or lone surrogates are quarantined instead
  of being stored; such values would otherwise make later responses invalid for
  strict JSON clients. Non-finite market-data values are treated as missing.
- Ingestion applies a total request-body bound before parsing, returning 413
  rather than buffering an arbitrarily large batch.
- Login attempts are rate limited per client address in addition to per
  account, closing the rotate-the-email bypass for password spraying.
- Active web-assessment probes now require the scope of the final redirect
  target to authorize them.
- The HTTP decoy rejects Transfer-Encoding and duplicate Content-Length
  requests, closes connections with unread bodies, and uses the active
  investigation profile for credential capture.
- Event `since`/`until` filters are validated as timestamps instead of being
  compared as raw strings.

### Security

- Bearer tokens are kept in tab-scoped storage.
- The dashboard CSP is sent by the API and scoped to dashboard responses.
- Agent tokens are stored as hashes and can be revoked.
- Untrusted numeric and Unicode input is bounded at the event and provider
  boundaries before it reaches storage or a JSON response.
- Login endpoints enforce both account-level and address-level attempt budgets.
- Web-assessment probes are constrained by the authorization scope of every
  host they touch, including redirect destinations.
- Build context excludes secrets, local data and build artefacts.
- The Vite/esbuild development toolchain was updated to clear the published
  advisories; `npm audit` reports no vulnerabilities.
