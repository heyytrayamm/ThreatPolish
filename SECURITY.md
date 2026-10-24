# Security policy

## Supported versions

Security fixes are applied to the current `1.x` line on `main`. Older commits are
not maintained.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository
("Security" → "Report a vulnerability"). Do not open a public issue for a
suspected vulnerability, and do not include live credentials, customer data or
third-party personal data in a report.

Please include:

- the affected version or commit,
- the endpoint, module or file involved,
- reproduction steps against a local instance,
- the impact you believe is possible,
- any suggested mitigation.

Reports are acknowledged on a best-effort basis. This is a self-hosted project
without a paid support contract, so no response-time SLA is offered.

## Scope

In scope:

- authentication, authorization and session handling,
- injection, SSRF and path handling in the API, decoy and assessment modules,
- evidence integrity and response-policy bypasses,
- container and deployment configuration in this repository,
- denial of service that bypasses the documented limits.

Out of scope:

- testing against systems you do not own or have written authorization to assess,
- findings that require a compromised host, browser extension or physical access,
- vulnerabilities in third-party dependencies that are already publicly
  disclosed and fixed upstream (report those upstream),
- the intentional behaviour of decoys, including collecting attacker-supplied
  credentials as truncated hashes.

## Operational expectations

- Replace every placeholder in `.env`; production refuses example signing
  secrets.
- Terminate TLS in front of the API and never publish the API or database
  directly to the internet.
- Deploy decoys on isolated segments with no route to production systems.
- Keep `TP_WEB_SEC_ALLOW_LOOPBACK=false` in production and only create scopes
  with an explicit, recorded authorization.
- Keep dependency locks current. CI audits the backend environment with
  `pip-audit` and the dashboard lockfile with `npm audit --audit-level=high` on
  every push; a finding fails the job instead of being silently accepted.
- Rotate `TP_JWT_SECRET`, agent tokens and the database password on a schedule.
- Treat the database and backups as sensitive: they contain attacker-supplied
  commands and addresses.
