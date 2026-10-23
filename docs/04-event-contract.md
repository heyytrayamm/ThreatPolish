# Telemetry event contract

All modules emit the same record. `app/schemas/event.py` is authoritative; this
document explains the intent and the per-module feature conventions.

## Envelope

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `schema_version` | `"1.0"` | yes | Rejected if different |
| `event_id` | string (uuid) | no | Generated server-side when absent |
| `occurred_at` | ISO-8601 datetime | yes | Converted to UTC; future timestamps beyond a small tolerance are rejected |
| `source_module` | enum | yes | `honeypot`, `websec`, `cryptointel`, `app`, `correlation`, `manual` |
| `event_type` | string 3–120 chars | yes | Module-defined verb, e.g. `ssh_auth_attempt` |
| `source_ip` | IPv4/IPv6 string | no | Validated; absent for internal analytical events |
| `session_id` | string ≤120 | no | Sensor-scoped session key |
| `target_id` | string ≤200 | no | Asset or host identifier |
| `severity` | enum | no, default `info` | `info`, `low`, `medium`, `high`, `critical` |
| `provenance` | object | yes | See below |
| `features` | object | no | Module-specific, bounded |
| `evidence_refs` | list[str] ≤50 | no | Pointers to raw artefacts (log line ids, file paths) |
| `raw` | object | no | Original payload, truncated |

`provenance`: `collector`, `source`, `reliability` (0–1), `synthetic` (bool),
`external_refs` (≤20), `indicators` (≤50 strings).

`raw` and `features` are size-bounded; oversized values are truncated rather
than rejected, and the truncation is visible in the stored record.

## Validation and outcome

Each record is one of:

- `accepted` — stored.
- `duplicate` — `event_hash` already present; the existing id is returned.
- `rejected` — schema violation with field-level reason; nothing is stored.

Batch ingestion returns a per-item result and an aggregate report.

## Feature conventions per module

**Honeypot (`ssh_auth_attempt`, `command_input`, `http_request`)**
`features.username`, `features.password_sha256`, `features.command`,
`features.client`, `features.path`, `features.method`, `features.user_agent`,
`features.technique`, `features.malware_family`, `features.decoy_profile`.

**HTTP sensor** `features.method`, `features.path`, `features.user_agent`,
`features.technique`, `features.body_bytes`.

**Web assessment** `features.finding`, `features.url`, `features.missing_headers`,
`features.tls_days_remaining`, `features.scope_id`.

**Digital assets** `features.symbol`, `features.change_24h`,
`features.volume_ratio`, `features.signal`.

## Correlation features

`app/correlation/features.py` derives a session feature document from its
events. The families and their weights (sum 1.0):

| Family | Weight | Signals |
| --- | --- | --- |
| behaviour | 0.30 | Normalised command tokens, technique set |
| targeting | 0.20 | Paths, targets, assets |
| timing | 0.15 | Inter-arrival profile, active hours |
| identity | 0.15 | Usernames, credential hashes, client signatures |
| intelligence | 0.12 | Verified indicators, malware family |
| toolchain | 0.08 | Client strings, payload hashes, TLS/JA3-like markers |

Tokens are weighted by document frequency over the analysed window; tokens
appearing in more than 60% of sessions are dropped as uninformative. A family
whose evidence is absent is marked unavailable and its weight is redistributed
proportionally, so missing data lowers confidence rather than manufacturing
agreement.

## Versioning

`schema_version` is strict within a major API version. Adding an optional field
is backward-compatible; renaming or changing semantics requires `"1.1"` and a
parallel ingest path. Correlation output records its own
`algorithm_version`, so stored edges remain interpretable after upgrades.

## Privacy and sensitivity

- Passwords captured by the decoy are stored as a truncated SHA-256 prefix
  (16 hex characters) and a length, with the plaintext discarded. This supports
  correlation without retaining credentials.
- No plaintext payload bodies beyond the configured cap are persisted.
- Timestamps are UTC; analyst timezone handling is a presentation concern.
- Event retention defaults to 90 days (`TP_RETENTION_DAYS`); each event stores
  its own `retention_until`. `python -m app.cli purge` deletes expired events.
- The database should be treated as sensitive: it contains attacker IPs and
  commands that may include third-party personal data.
