import { Card } from "../ui";

export default function TermsAndConditions() {
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Terms and Conditions</h1>
          <p className="muted">
            Authorized usage constraints, defensive operational mandates, and verification requirements.
          </p>
        </div>
      </header>

      <div className="stack">
        <Card title="1. Authorized Defensive Deployment Only">
          <p>
            ThreatPolish includes active deception components, decoy listeners, and web assessment capabilities.
            Use of this platform is strictly permitted only on networks, endpoints, and address allocations where the
            operating organization has documented, explicit, and verified authorization.
          </p>
          <p>
            Deploying decoys or executing assessment probes against third-party networks, unauthorized public infrastructure,
            or external domains without written consent is strictly prohibited and constitutes a breach of authorized usage.
          </p>
        </Card>

        <Card title="2. Attribution and Probabilistic Hypotheses">
          <p>
            Correlation engines output evidence-weighted relationship hypotheses, similarity scores, and contradiction
            penalties based on observed telemetry. These indicators measure behavioral overlap across sessions and do not
            constitute definitive legal attribution of individual threat actors.
          </p>
          <p>
            Operators must evaluate evidence tables, specificity anchors, and contradiction metrics before drawing operational
            or forensic conclusions.
          </p>
        </Card>

        <Card title="3. Containment Policy and Human-in-the-Loop Safeguards">
          <p>
            Automated or operator-initiated containment responses (such as IP blocking or decoy profile shifts) are policy-gated.
            Containment actions require explicit human operator or administrator authorization, enforce automatic expiration
            timers, and maintain audited rollback capabilities. The system does not execute destructive payloads.
          </p>
        </Card>

        <Card title="4. Auditability and Immutable Logging">
          <p>
            All administrative actions, session revocations, token generations, response approvals, and retention policy
            overrides are committed to an immutable audit trail with actor IDs, action codes, object references, and request
            origin details. Tampering with or bypassing audit facilities invalidates operational compliance.
          </p>
        </Card>

        <Card title="5. Warranty and Limitation of Operational Liability">
          <p>
            ThreatPolish is provided on an "as is" and "as available" basis without warranties of any kind, whether express
            or implied. Operating organizations assume full responsibility for network segmentation, decoy isolation,
            firewall posture, and regulatory compliance within their jurisdiction.
          </p>
        </Card>
      </div>
    </div>
  );
}

