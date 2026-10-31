import { Card } from "../ui";

export default function PrivacyPolicy() {
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Privacy Policy</h1>
          <p className="muted">
            Data processing, telemetry storage, retention schedules, and defensive operational boundaries.
          </p>
        </div>
      </header>

      <div className="stack">
        <Card title="1. Operational Scope and Self-Hosted Architecture">
          <p>
            ThreatPolish is an on-premises, self-hosted defensive correlation platform. All event ingestion,
            session correlation, and audit logging take place within the host infrastructure managed directly
            by the deploying organization. No telemetry, customer credentials, session metadata, or analytical
            hypotheses are transmitted to external cloud services or third-party tracking networks.
          </p>
        </Card>

        <Card title="2. Telemetry and Event Ingestion">
          <p>
            The platform collects and processes defensive telemetry emitted by authorized sensors, honeypots,
            and decoys. Collected data points include:
          </p>
          <ul className="legal-list">
            <li><strong>Network metadata:</strong> Source and destination IP addresses, ports, transport protocols, and timestamps.</li>
            <li><strong>Session behavior:</strong> Command sequences, SSH client banners, HTTP headers, request paths, and query parameters.</li>
            <li><strong>Assessment records:</strong> Target responses, SSL certificate parameters, and port availability states.</li>
            <li><strong>Honeypot interactions:</strong> Decoy-captured passwords and authentication attempts are stored exclusively as truncated one-way hashes, never as recoverable plaintext.</li>
          </ul>
        </Card>

        <Card title="3. Data Retention and Automated Purging">
          <p>
            Telemetry retention is bounded by strict, enforceable time windows configured by the system administrator:
          </p>
          <ul className="legal-list">
            <li><strong>Raw Telemetry:</strong> Stored events expire after the active retention period (default: 90 days) and are permanently purged during scheduled maintenance runs.</li>
            <li><strong>Correlation Graph:</strong> Inferred session links and hypothesis records expire automatically after graph retention limits (default: 30 days).</li>
            <li><strong>Grace Periods:</strong> A deterministic grace window (default: 2 days) isolates soft-deleted records before permanent cryptographic erasure.</li>
          </ul>
        </Card>

        <Card title="4. Access Control and Authentication">
          <p>
            Operator authentication uses cryptographically signed JSON Web Tokens (HS256) with unique token identifiers (JTI).
            Token revocation is tracked at rest, allowing immediate invalidation of individual client sessions or complete
            account sign-out. Passwords are salted and hashed using Argon2 or PBKDF2 with high iteration counts.
          </p>
        </Card>

        <Card title="5. Operator Rights and Administrative Controls">
          <p>
            Authorized administrators retain complete custody and control over all stored data. Operators can review audit
            trails, inspect quarantined payloads, trigger manual retention purges, and revoke agent tokens directly through
            the administration interface.
          </p>
        </Card>
      </div>
    </div>
  );
}

