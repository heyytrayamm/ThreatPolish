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
- Account page for password rotation and recent session history, and an
  administrator action that revokes every session of an account without
  changing its password.
- `GET /auth/sessions` reports an account's sign-ins, password changes and
  revocations with client, address and whether each sign-in is still usable,
  derived from the audit trail rather than per-request logging. Administrators
  can open any account's history from the Administration page or
  `GET /auth/users/{id}/sessions`.
- Per-session sign-out: each token carries an identifier, `DELETE /auth/sessions/{jti}`
  revokes just that device, and revoked identifiers are kept only until the token
  would have expired.
- The Overview page raises recent sign-in anomalies as an attention item, for the
  signed-in account and, for administrators, as a count from the audit trail.
- Sign-in anomaly alerts: a second live session from a different network inside
  `TP_SIGNIN_ALERT_WINDOW_MINUTES` is recorded as `auth.signin.anomaly` and shown
  on the account and admin session views. An optional geolocation endpoint adds
  measured distance and the `TP_SIGNIN_ALERT_DISTANCE_KM` threshold; without one
  the alert reports the network change rather than inventing a location.
- The dashboard end-to-end job now also plans and activates an investigation
  through the Campaigns and Deception pages.
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
- Changing a password now revokes every token issued before the change, and
  tokens that carry no session version are refused. The caller receives a
  replacement token so the session making the change is not logged out.
- Duplicate investigation planning is decided by partial unique indexes on the
  open rows, so two concurrent requests for the same campaign or edge can no
  longer both create an investigation and activate two decoys. Existing
  duplicates are marked `superseded` by migration 7, and the Deception page
  names the investigation that replaced each closed duplicate.

### Security

- Bearer tokens are kept in tab-scoped storage.
- The dashboard CSP is sent by the API and scoped to dashboard responses.
- Agent tokens are stored as hashes and can be revoked.
- Bearer tokens are bound to an account session version that is checked on
  every request; rotating a password invalidates tokens already issued, and an
  administrator can revoke an account's sessions when theft is suspected.
- Untrusted numeric and Unicode input is bounded at the event and provider
  boundaries before it reaches storage or a JSON response.
- Login endpoints enforce both account-level and address-level attempt budgets.
- Web-assessment probes are constrained by the authorization scope of every
  host they touch, including redirect destinations.
- Build context excludes secrets, local data and build artefacts.
- The Vite/esbuild development toolchain was updated to clear the published
  advisories; `npm audit` reports no vulnerabilities.
