import {
  IconActivity,
  IconKey,
  IconNetwork,
  IconServer,
  IconShield,
  IconTerminal,
  TerminalWindow,
} from "../ui";

export default function Landing({
  onLaunchConsole,
  onOpenPrivacy,
  onOpenTerms,
}: {
  onLaunchConsole: () => void;
  onOpenPrivacy: () => void;
  onOpenTerms: () => void;
}) {
  const terminalSample: { text: string; type?: "cmd" | "output" | "accent" | "warn" | "error" }[] = [
    { text: "threatpolish listen --port 8022 --mode adaptive", type: "cmd" },
    { text: "[+] Deception engine initialized. Active honeypot listeners on :8022 (HTTP), :2222 (SSH)", type: "accent" },
    { text: "[*] Ingesting telemetry from edge sensor cluster...", type: "output" },
    { text: "[!] 03:41:12 Inbound connection from 198.51.100.42 -> probe /api/v1/debug", type: "warn" },
    { text: "[+] Fingerprint captured: JA3=771,4865-4866, client_banner='Go-http-client/1.1'", type: "output" },
    { text: "[+] Credential payload captured -> stored as one-way truncated hash (sha256:7e8b91...)", type: "accent" },
    { text: "[*] Invoking similarity correlation engine (algorithm: corr-1.3.0)...", type: "output" },
    { text: "[+] Session linked: sess_8f29 <-> sess_3a11 (confidence: 0.942, anchor: command_cadence)", type: "accent" },
    { text: "[+] Campaign candidate formed: cmp_5a9676 (2 members, 2 IPs, severity: HIGH)", type: "warn" },
    { text: "[*] Policy check passed. Containment rule staged with 60m expiry. Analyst approval required.", type: "output" },
  ];

  return (
    <div className="landing-shell">
      {/* Top Navigation */}
      <header className="landing-nav">
        <div className="landing-brand">
          <img src="/logo-mark.png" alt="ThreatPolish Logo" width={34} height={34} />
          <strong>ThreatPolish</strong>
        </div>
        <div className="landing-nav-links">
          <button type="button" className="link small" onClick={onOpenPrivacy}>
            Privacy
          </button>
          <button type="button" className="link small" onClick={onOpenTerms}>
            Terms
          </button>
          <button type="button" className="primary small" onClick={onLaunchConsole}>
            Sign In to Console
          </button>
        </div>
      </header>

      {/* Hero Section */}
      <section className="landing-hero">
        <div className="hero-tag">
          <IconShield size={14} />
          Defensive Cybersecurity Platform
        </div>
        <h1>Understand the Threat. Follow the Evidence.</h1>
        <p>
          An evidence-driven cybersecurity platform for threat observation, session correlation,
          campaign analysis and adaptive deception.
        </p>

        <div className="hero-actions">
          <button type="button" className="primary" onClick={onLaunchConsole}>
            Launch Analyst Workspace
          </button>
          <a href="#architecture" className="btn secondary">
            Explore Architecture
          </a>
        </div>

        {/* Realistic Terminal Demonstration */}
        <div className="hero-terminal-wrap">
          <TerminalWindow
            title="threatpolish-engine@production-node: telemetry-stream"
            lines={terminalSample}
          />
        </div>
      </section>

      {/* Feature Highlights Section */}
      <section className="landing-section">
        <div className="section-head">
          <span className="eyebrow">Defensive Capabilities</span>
          <h2>Engineered for Security Analysts and Researchers</h2>
          <p>
            Traditional attribution relies on fragile lookup tables. ThreatPolish uses behavioral
            evidence weighting to reveal campaigns across rotating infrastructure.
          </p>
        </div>

        <div className="feature-grid">
          <div className="feature-card">
            <div className="feature-icon-wrap">
              <IconNetwork size={22} />
            </div>
            <h3>Cross-IP Behavioral Correlation</h3>
            <p>
              Identifies connected threat sessions even after IP rotation. Analyzes six evidence
              families: targeting, toolchains, command sequences, cadence, timing, and threat intelligence.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon-wrap">
              <IconServer size={22} />
            </div>
            <h3>Adaptive Deception Honeypots</h3>
            <p>
              When evidence is genuinely uncertain, the platform activates bounded decoy profiles to
              solicit decisive telemetry without hallucinating or manufacturing evidence.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon-wrap">
              <IconActivity size={22} />
            </div>
            <h3>Auditable Confidence Graphs</h3>
            <p>
              Every relationship link stores the complete mathematical component table that produced
              it. Severity and confidence are strictly separated for objective decision-making.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon-wrap">
              <IconKey size={22} />
            </div>
            <h3>Zero-Knowledge Decoy Storage</h3>
            <p>
              Decoy-captured passwords and authentication payloads are committed exclusively as
              one-way cryptographic hashes, ensuring analyst safety and zero credential exposure.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon-wrap">
              <IconShield size={22} />
            </div>
            <h3>Policy-Gated Containment</h3>
            <p>
              Inference and action remain distinct privileges. Containment actions require verified
              confidence thresholds, administrator sign-off, automatic expiration timers, and rollback.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon-wrap">
              <IconTerminal size={22} />
            </div>
            <h3>Self-Hosted & Independent</h3>
            <p>
              Full operational sovereignty. Ingests telemetry locally, runs on PostgreSQL or SQLite,
              and maintains zero external cloud dependencies or telemetry tracking.
            </p>
          </div>
        </div>
      </section>

      {/* Architecture Pipeline Section */}
      <section className="landing-section" id="architecture">
        <div className="section-head">
          <span className="eyebrow">Platform Architecture</span>
          <h2>How ThreatPolish Works</h2>
          <p>A rigorous, multi-stage processing pipeline from raw packet to audited defensive decision.</p>
        </div>

        <div className="arch-pipeline">
          <div className="pipeline-step">
            <div className="step-num">01 / OBSERVE</div>
            <div className="step-title">Decoys & Sensors</div>
            <div className="step-desc">Sensors emit standardized versioned events over a secure contract.</div>
          </div>
          <div className="pipeline-step">
            <div className="step-num">02 / NORMALIZE</div>
            <div className="step-title">Sanitization</div>
            <div className="step-desc">Validate, clean, deduplicate, and quarantine malformed records.</div>
          </div>
          <div className="pipeline-step">
            <div className="step-num">03 / CORRELATE</div>
            <div className="step-title">Evidence Scoring</div>
            <div className="step-desc">Score six evidence families, subtract contradictions, link clusters.</div>
          </div>
          <div className="pipeline-step">
            <div className="step-num">04 / INVESTIGATE</div>
            <div className="step-title">Adaptive Observation</div>
            <div className="step-desc">Ambiguous pairs request bounded observation for conclusive scoring.</div>
          </div>
          <div className="pipeline-step">
            <div className="step-num">05 / DECIDE</div>
            <div className="step-title">Campaign Analysis</div>
            <div className="step-desc">Analysts inspect components, missing evidence, and topology.</div>
          </div>
          <div className="pipeline-step">
            <div className="step-num">06 / ACT</div>
            <div className="step-title">Audited Response</div>
            <div className="step-desc">Policy-gated containment with administrator approval and auto-expiry.</div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="landing-footer">
        <div>
          <strong>ThreatPolish</strong> - See the Evidence. Understand the Threat.
        </div>
        <div className="row">
          <button type="button" className="link small" onClick={onOpenPrivacy}>
            Privacy Policy
          </button>
          <span>-</span>
          <button type="button" className="link small" onClick={onOpenTerms}>
            Terms and Conditions
          </button>
          <span>-</span>
          <button type="button" className="link small" onClick={onLaunchConsole}>
            Sign In
          </button>
        </div>
      </footer>
    </div>
  );
}

