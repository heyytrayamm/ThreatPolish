# Changelog

All notable changes to this project are recorded here. Dates use ISO 8601.

## 1.0.3 — 2026-10-25

### Added

- Evidence graph retention is separate from event retention. Correlation
  retires stale links, but a deployment that stops correlating kept every edge
  forever; `python -m app.cli purge-graph` now deletes retired edges past
  `TP_GRAPH_RETENTION_DAYS` (default 30), the observation records of sessions
  that old with no live similarity or campaign edge, and nodes nothing
  references. Hypotheses, active evidence, campaign membership and archived
  reviews are kept, so an analyst's decision outlives the evidence behind it
  (`test_correlation.py`).
- `python -m app.cli retention` enforces both horizons in one run. The Compose
  stack gains a `retention` service that waits for the API to be healthy, runs
  at start and then every `TP_RETENTION_INTERVAL_SECONDS` (default 24 hours).
- `GET /retention` (admin) reports expired events, retired edges, stale
  observations, orphan nodes and the current graph size, with `overdue` set
  when any horizon has pending work.
- Migration 10 adds the indexes retention needs; `IF NOT EXISTS` makes it safe
  on a database that already has them.

## 1.0.2 — 2026-10-24

### Changed

- Campaign identity is now independent of membership. A new component inherits
  an existing campaign when at least half of its member set survives, so adding
  or losing a session no longer produces a new identifier and orphans the
  analyst's review; added and removed sessions are recorded in
  `membership_history`. When two campaigns merge, feedback and response
  references move to the survivor, a single review decision is carried forward
  and conflicting decisions become `uncertain` (`test_correlation.py`).
- Scored pairs are streamed through a bounded heap instead of retained as a
  dictionary of full results. At 800 sessions the previous code held more than
  1.6 GB before writing an edge; peak memory no longer grows with the square of
  the window. The run reports how many candidate pairs and how many links the
  per-run edge cap removed, so the cap can be judged on what it drops.
- The session cap rises from 400 to 800 and the per-run edge cap from 2,000 to
  8,000, from measurements in `docs/research/correlation-runtime.md`: 788
  sessions score 310,078 pairs in about 28 s, and the 2,000-edge cap was
  dropping 2,211 links at that size.

### Added

- `GET /campaigns?include_archived=true` lists archived campaigns. Campaign
  detail returns `status_updated_at`, `superseded_by`, `archived_at`,
  `archived` and the full stored `evidence`, including membership and review
  history.
- A CI job audits dependencies with `pip-audit` over the installed backend
  environment and `npm audit --audit-level=high` over the dashboard lockfile;
  `make audit` runs the same checks locally.
- `backend/scripts/benchmark_correlation.py` measures end-to-end correlation at
  increasing session counts and writes `docs/research/correlation-runtime.md`.
- Migration 9 adds the campaign lifecycle columns.

### Fixed

- A reviewed campaign was deleted, along with the feedback that pointed at it,
  when its links expired or fell below the persistence cut. Reviewed campaigns,
  and those an investigation or response refers to, are archived instead;
  untouched automatic candidates are still removed. Expiry of an edge whose
  sessions were scored in the run is now decided from the stored endpoints, so
  the engine does not need to retain every pair key.
- The synthetic scenario generator produced invalid IP octets above 244
  sessions (`203.0.113.256`), breaking volume benchmarks above that size;
  addresses now come from the benchmark range 198.18.0.0/15.

## 1.0.1 — 2026-10-24

### Changed

- Sequence comparison scores containment as well as Jaccard (`corr-1.3.0`), so a
  session that recorded fewer commands is no longer read as evidence of
  different behaviour. It is measured against a new `ablation_jaccard_only` run
  that reproduces the previous comparison: seed 7 recall 0.812 → 0.906 and seed
  2026 0.562 → 0.812 at unchanged precision, with campaign recovery rising from
  9 to 10 of 12 and from 4 to 8 of 12. The comparison used is recorded as
  `sequence_similarity` on every edge.
- Benchmark tables, campaign recovery, time to detection and cost figures were
  regenerated for `corr-1.3.0` in the README, the traceability map and
  `docs/research/`.

### Fixed

- Campaign views presented hypotheses and expired relationships as campaign
  evidence: an edge that stopped being supported kept its campaign identifier,
  and the campaign detail query did not filter by edge state. Membership is now
  cleared when an edge becomes a hypothesis or expires, and the campaign view
  counts only active links.
- Expiring a pair replaced its stored evidence with a two-key stub, discarding
  the reasons the model had proposed the link. Expiry now keeps the original
  evidence and records when and why the relationship was retired.

### Added

- Tests for containment scoring of truncated sessions, for campaign membership
  after an edge is demoted or expired, and for expiry preserving evidence.

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
  would have expired. Administrators can do the same for any account with
  `DELETE /auth/users/{id}/sessions/{jti}`, from the session panel on the
  Administration page, without ending that account's other sessions.
- Administration page manages sensor credentials: it lists agent tokens with
  their prefix, role, last use and state, creates one (plaintext shown once)
  and revokes it, so no shell access is needed to rotate a sensor.
- The operations guide carries a session-compromise runbook that walks from a
  sign-in alert through confirming the device, revoking that one session,
  containing the account or tokens when the scope is unclear, preserving
  evidence and closing out.
- The Overview page raises recent sign-in anomalies as an attention item, for the
  signed-in account and, for administrators, as a count from the audit trail.
- Sign-in anomaly alerts: a second live session from a different network inside
  `TP_SIGNIN_ALERT_WINDOW_MINUTES` is recorded as `auth.signin.anomaly` and shown
  on the account and admin session views. An optional geolocation endpoint adds
  measured distance and the `TP_SIGNIN_ALERT_DISTANCE_KM` threshold; without one
  the alert reports the network change rather than inventing a location.
- The dashboard end-to-end job now also plans and activates an investigation
  through the Campaigns and Deception pages, signs another account's device out
  from the administration session panel, and creates and revokes a sensor token.
- Evidence families are weighted by the corpus, not only tokens (`corr-1.2.0`):
  a family whose tokens are almost all ubiquitous in the analysed window
  contributes less, and the effective weights are recorded on every edge. A
  uniform-weight ablation reproduces the previous model so the effect is
  measured rather than asserted.
- `docs/PRODUCT_SPEC.md` records the authoritative product scope, and
  `docs/REQUIREMENTS_TRACEABILITY.md` maps every stage, module, dashboard view
  and required metric to its implementation, test and measured result, with the
  open gaps stated.
- The evaluation reports time to detection — the elapsed campaign time until two
  members of a true group link — alongside wall and CPU time, peak memory and
  milliseconds per scored pair, so the metrics the specification asks for are
  measured rather than described.
- The Deception page lists decoy sessions from `GET /honeypot/sessions` with
  their addresses, event counts, severity and target, so captured interactions
  are reviewable as sessions rather than as a stream of events.
- `tests/test_properties.py` checks invariants instead of scenarios: symmetric
  and deterministic scoring, bounded outputs, monotone confidence, unique
  relationship keys for every accepted identifier, rejection of control
  characters in identifiers, isolation of legacy corrupt identifiers,
  corpus-relative family weights, and the narrowest authorization governing a
  host.
- Docker/Compose deployment, CLI, schema migrations, backup and recovery
  runbooks.
- CI pipeline covering lint, the full suite on SQLite and PostgreSQL 16, the
  dashboard build and a container image build.
- Seeded evaluation harness with baselines, ablations, adaptive experiment and
  a volume run.
- Dashboard screenshots and a documentation index for review.

### Changed

- The adaptive experiment no longer gives every session in an activity category
  the same synthetic request path. That constant manufactured similarity which
  observation cannot produce, and it inflated the reported benefit. The
  simulation now replays one command the actor already executed, and the report
  counts links gained and lost in both directions. With the corrected
  simulation additional observation moves almost no decisions, so the adaptive
  clause of the hypothesis is stated as unsupported rather than supported.
- Benchmark numbers were regenerated for `corr-1.2.0`: seed 7 recall 0.781 →
  0.812 with precision 1.000, campaign recovery 8 → 9 of 12, and volume recall
  0.836 → 0.853. The same report now includes the cost metrics above.
- Coverage in `docs/06-testing-and-evaluation.md` no longer quotes a single CI
  run as if it were the current count; it names the suite size and states that CI
  runs the same suite on both engines.

### Fixed

- Assessment scopes that overlap were resolved in row order, so a broad
  authorization could re-enable active probes that a scope for the specific host
  forbade. The narrowest live scope now governs, and the choice cannot depend on
  insertion order.
- A sensor could submit a session identifier containing the relationship-key
  separator, which let two different session pairs share one key and overwrite
  each other's evidence. Session and target identifiers now reject control
  characters at ingestion, and identifiers stored before that check degrade to
  one-event sessions instead of being merged.
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
- Session identifiers are validated at the contract boundary so a crafted id
  cannot corrupt the relationship graph, and overlapping assessment scopes are
  resolved by specificity rather than by row order.
- Web-assessment probes are constrained by the authorization scope of every
  host they touch, including redirect destinations.
- Build context excludes secrets, local data and build artefacts.
- The Vite/esbuild development toolchain was updated to clear the published
  advisories; `npm audit` reports no vulnerabilities.
