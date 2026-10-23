# Threat model

Method: asset and trust-boundary enumeration, adversary capability assumptions,
then a control per identified threat. Residual risk is stated; nothing here
claims the system is unattackable.

## Assets

1. Analyst accounts and the bearer tokens issued to them.
2. Sensor shared secret and database credentials.
3. Collected telemetry, which contains attacker IPs, usernames, commands.
4. Integrity of correlation output — an attacker who can forge evidence can
   misdirect attribution.
5. The host running the API and database.
6. Availability of monitoring during an incident.

## Trust boundaries

| Boundary | Crossing |
| --- | --- |
| Internet → decoy listeners | Untrusted input, fully attacker-controlled |
| Decoy → ingestion API | Log content derived from attacker input |
| Internet → dashboard | Untrusted input, authenticated user |
| Dashboard → API | Bearer token, JSON body |
| API → database | Trusted network, least-privilege role |
| API → authorised web targets | Operator-supplied URL |
| Operator → response execution | Approved action |

## Adversaries

- **Opportunistic scanner / botnet**: automated credential attempts, path
  probing. Assumed present continuously.
- **Targeted intruder**: adapts to what they see, may detect the decoy, may try
  to poison logs or use the decoy as a pivot.
- **Malicious insider with analyst access**: can read telemetry and trigger
  responses; must be constrained and audited.
- **Network attacker**: can spoof source IPs, intercept unencrypted traffic.

## Threats and controls

| # | Threat | Control | Residual risk |
| --- | --- | --- | --- |
| T1 | Unauthenticated access to telemetry or response endpoints | Bearer token + role check on every route; RBAC matrix tested | Stolen token valid until expiry (default 60 min); no revocation list |
| T2 | Weak operator passwords | Minimum length enforced, PBKDF2-HMAC-SHA256 with per-user salt and high iteration count; login audit records failures; attempts are limited per account and per client address so rotating the email does not reset the budget | Password strength policy is minimal by design for a lab tool; address-level limits need care behind a shared NAT |
| T3 | Forged sensor submissions | Per-sensor agent tokens (`X-Agent-Token`); only a hash of each token is stored, tokens are revocable, and a revoked token stops ingesting immediately | Anyone holding a live agent token can inject events; rotate it |
| T4 | Log/evidence poisoning via decoy | Stored as observation with source and sensor id; correlation treats single-source tokens as low evidence; injection strings stored verbatim, never evaluated | A patient attacker can still create plausible false trails |
| T5 | Dashboard XSS | React escaping, no `dangerouslySetInnerHTML`, CSP without `unsafe-inline`, no third-party script origins | Compromised build pipeline could ship modified JS |
| T6 | Token theft from browser | `sessionStorage` (not `localStorage`), cleared on logout, short expiry | Any XSS or local malware on the analyst machine can read it |
| T7 | SSRF via web assessment | Scheme allowlist, DNS resolution of every candidate, rejection of loopback/private/link-local/multicast/reserved, every redirect destination re-authorized and re-checked, credential-bearing redirects refused, active probes require the final host's scope to authorize them, 1 MB response cap | DNS rebinding between resolve and connect is mitigated but not eliminated; a proxy in front of the target changes the picture |
| T8 | Unauthorised scanning | Explicit scope entries with authorization reference and expiry; 403 before any network call; every attempt audited | An analyst with scope-management rights can authorise a target |
| T9 | Decoy used as a pivot | Decoy process has no shell execution path, no outbound connections, no credentials to the API beyond the ingestion secret; runs as non-root in a container with dropped capabilities | Kernel-level container escape is outside this boundary |
| T10 | Denial of service | Total ingestion body bound before validation, event field length caps, non-finite value rejection, correlation session cap, ingestion rate limiting per source, ambiguous decoy framing refused, bounded decoy body read, database statement timeouts recommended | A volumetric flood still saturates the link; use upstream scrubbing |
| T11 | Correlation false positive leading to a wrong block | Response actions require approval for high-impact types; targets never observed by the platform are refused; confidence and evidence are shown; rollback is available; blocks are time-limited | Analyst could approve a bad action |
| T12 | Irreversible response action | Expiry on every action, explicit rollback, state machine rejects invalid transitions, audit trail | Some real-world actions (e.g. notified ISP) cannot be truly undone |
| T13 | Database compromise | Database not published to the host in Compose, password from environment, least-privilege application role recommended, encrypted volume recommended | No encryption at rest configured by default |
| T14 | Supply-chain compromise | Pinned versions, no postinstall scripts in the frontend, minimal dependency set, `pip-audit`/`npm audit` in the checklist | No automated CI gate in this repository yet |
| T15 | Insider misuse of response engine | Approval is a separate admin-only permission (`responses:approve`), every action is audited, applies expire and can be rolled back | The same administrator can request and approve; separation depends on staffing |
| T16 | Sensitive data in telemetry | Password inputs are recorded as hashes only, never plaintext; payloads capped and truncated; retention configurable | Command lines can contain secrets typed by attackers; treat the database as sensitive |
| T17 | Misidentification of a real actor | Output language is "campaign", never "actor identity"; confidence is explicitly not a probability; limitations shown in the UI and evaluation report | Analysts may over-trust a high score |
| T18 | Clock skew corrupting timing evidence | Timestamps stored in UTC ISO-8601; timing family tolerates skew and is down-weighted when sparse | Large skew weakens timing evidence |

## Deployment guidance derived from the model

- Terminate TLS in front of the API and dashboard; never expose port 8000
  directly to the internet.
- Put the API on a management network; only decoy ports face the internet.
- Rotate agent tokens (revoke and reissue via `/auth/tokens`) and the database
  password on a schedule; changing `TP_JWT_SECRET` invalidates all sessions.
- Keep `TP_WEB_SEC_ALLOW_LOOPBACK=false` in production.
- Restrict `TP_ALLOWED_ORIGINS` to the dashboard origin.
- Alert on repeated `authentication_failed` audit entries and on response
  actions approved outside working hours.
- Back up the database before any schema upgrade.
