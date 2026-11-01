import { FormEvent, useState } from "react";
import {
  ErrorBox,
  IconActivity,
  IconAlertTriangle,
  IconEye,
  IconEyeOff,
  IconKey,
  IconNetwork,
  IconServer,
  IconShield,
  IconTerminal,
  TerminalWindow,
} from "../ui";

export interface LandingProps {
  email: string;
  setEmail: (val: string) => void;
  password: string;
  setPassword: (val: string) => void;
  passwordVisible: boolean;
  setPasswordVisible: (val: boolean) => void;
  busy: boolean;
  error: string | null;
  onSignIn: (e: FormEvent) => void;
  onOpenPrivacy: () => void;
  onOpenTerms: () => void;
}

export default function Landing({
  email,
  setEmail,
  password,
  setPassword,
  passwordVisible,
  setPasswordVisible,
  busy,
  error,
  onSignIn,
  onOpenPrivacy,
  onOpenTerms,
}: LandingProps) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [activePreviewTab, setActivePreviewTab] = useState<
    "overview" | "events" | "campaigns" | "deception" | "admin"
  >("overview");
  const [copiedSnippet, setCopiedSnippet] = useState(false);

  function scrollToSection(id: string) {
    setMobileMenuOpen(false);
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: "smooth" });
    }
  }

  function handleLoginClick() {
    scrollToSection("signin");
    const input = document.getElementById("login-email");
    if (input) {
      setTimeout(() => input.focus(), 400);
    }
  }

  function copyCode(code: string) {
    navigator.clipboard.writeText(code).then(() => {
      setCopiedSnippet(true);
      setTimeout(() => setCopiedSnippet(false), 2000);
    });
  }

  const liveTerminalLines: {
    text: string;
    type?: "cmd" | "output" | "accent" | "warn" | "error";
  }[] = [
    { text: "threatpolish listen --port 8022 --mode adaptive", type: "cmd" },
    {
      text: "[+] Honeypot engine initialized. Listeners active on :8022 (HTTP), :2222 (SSH)",
      type: "accent",
    },
    {
      text: "[*] Ingesting edge telemetry stream (collector: sensor-cluster-01)...",
      type: "output",
    },
    {
      text: "[!] 03:41:12 Inbound probe from 198.51.100.42 -> GET /api/v1/debug HTTP/1.1",
      type: "warn",
    },
    {
      text: "[+] Fingerprint captured: JA3=771,4865-4866, client_banner='Go-http-client/1.1'",
      type: "output",
    },
    {
      text: "[+] Auth payload captured -> stored as one-way SHA-256 hash (7e8b91c0e3...)",
      type: "accent",
    },
    {
      text: "[*] Evaluating multi-family behavioral correlation (corr-1.3.0)...",
      type: "output",
    },
    {
      text: "[+] Session linked: sess_8f29 <-> sess_3a11 (confidence: 0.942, anchor: command_cadence)",
      type: "accent",
    },
    {
      text: "[+] Campaign formed: cmp_5a9676 (2 sessions, 2 IPs, severity: HIGH)",
      type: "warn",
    },
    {
      text: "[*] Policy check passed. Expiring 60m egress containment staged for analyst approval.",
      type: "output",
    },
  ];

  const quickstartCommands = `# Clone the repository
git clone https://github.com/heyytrayamm/ThreatPolish.git
cd ThreatPolish

# Install Python backend dependencies
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\\Scripts\\activate
pip install -r backend/requirements.txt

# Configure environment & start API
export TP_JWT_SECRET="generate-a-secure-secret-key-at-least-32-chars"
export TP_DB_URL="sqlite:///./threatpolish.db"
cd backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000`;

  return (
    <div className="landing-page-white">
      {/* =========================================================
          STICKY HEADER
          ========================================================= */}
      <header className="landing-sticky-header">
        <div className="landing-header-inner">
          <div className="landing-brand-group">
            <a href="#hero" className="landing-brand-link" onClick={() => scrollToSection("hero")}>
              <img
                src="/logo-mark.png"
                alt="ThreatPolish Logo"
                className="landing-brand-img"
                width={32}
                height={32}
              />
              <span className="landing-brand-name">ThreatPolish</span>
            </a>
          </div>

          <nav className={`landing-nav-menu ${mobileMenuOpen ? "is-open" : ""}`} aria-label="Landing Navigation">
            <button type="button" className="landing-nav-link" onClick={() => scrollToSection("overview")}>
              Overview
            </button>
            <button type="button" className="landing-nav-link" onClick={() => scrollToSection("how-it-works")}>
              How It Works
            </button>
            <button type="button" className="landing-nav-link" onClick={() => scrollToSection("features")}>
              Features
            </button>
            <button type="button" className="landing-nav-link" onClick={() => scrollToSection("architecture")}>
              Architecture
            </button>
            <button type="button" className="landing-nav-link" onClick={() => scrollToSection("docs")}>
              Documentation
            </button>
            <a
              href="https://github.com/heyytrayamm/ThreatPolish"
              target="_blank"
              rel="noopener noreferrer"
              className="landing-nav-link external"
            >
              GitHub
              <svg width={12} height={12} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14 21 3" />
              </svg>
            </a>
            <button type="button" className="landing-nav-link signin-link" onClick={handleLoginClick}>
              Login
            </button>
            <button type="button" className="btn-landing-primary small" onClick={handleLoginClick}>
              Get Started
            </button>
          </nav>

          <button
            type="button"
            className="landing-mobile-toggle"
            aria-label="Toggle navigation menu"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          >
            <svg width={22} height={22} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
              {mobileMenuOpen ? (
                <path d="M18 6 6 18M6 6l12 12" />
              ) : (
                <path d="M3 12h18M3 6h18M3 18h18" />
              )}
            </svg>
          </button>
        </div>
      </header>

      {/* =========================================================
          SECTION 1: HERO - INTRODUCE THREATPOLISH
          ========================================================= */}
      <section className="landing-hero-section" id="hero">
        <div className="landing-hero-bg-grid" aria-hidden="true" />
        <div className="landing-container">
          <div className="landing-hero-content">
            <h1 className="landing-hero-title">
              Attract. Detect. Investigate. Understand.
            </h1>

            <p className="landing-hero-lead">
              ThreatPolish is a custom honeypot and defensive intelligence platform that captures
              adversary activity, analyzes attacker behavior, correlates events across rotating
              infrastructure, and helps security teams investigate threats with auditable confidence.
            </p>

            <div className="landing-hero-actions">
              <button type="button" className="btn-landing-primary" onClick={handleLoginClick}>
                Get Started
                <svg width={16} height={16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                  <path d="M5 12h14M12 5l7 7-7 7" />
                </svg>
              </button>
              <button
                type="button"
                className="btn-landing-secondary"
                onClick={() => scrollToSection("overview")}
              >
                Explore the Platform
              </button>
              <a
                href="https://github.com/heyytrayamm/ThreatPolish"
                target="_blank"
                rel="noopener noreferrer"
                className="btn-landing-outline"
              >
                View on GitHub
              </a>
            </div>

            {/* Quick Metrics Bar */}
            <div className="hero-metrics-strip">
              <div className="hero-metric-item">
                <span className="hero-metric-val">100%</span>
                <span className="hero-metric-lbl">Auditable Evidence</span>
              </div>
              <div className="hero-metric-divider" />
              <div className="hero-metric-item">
                <span className="hero-metric-val">6</span>
                <span className="hero-metric-lbl">Correlation Families</span>
              </div>
              <div className="hero-metric-divider" />
              <div className="hero-metric-item">
                <span className="hero-metric-val">Zero</span>
                <span className="hero-metric-lbl">Cloud Dependencies</span>
              </div>
              <div className="hero-metric-divider" />
              <div className="hero-metric-item">
                <span className="hero-metric-val">SHA-256</span>
                <span className="hero-metric-lbl">Zero-Knowledge Hashes</span>
              </div>
            </div>

            {/* Interactive Terminal Demonstration Preview */}
            <div className="landing-hero-preview">
              <div className="preview-header-bar">
                <div className="preview-window-dots">
                  <span className="preview-dot red" />
                  <span className="preview-dot yellow" />
                  <span className="preview-dot green" />
                </div>
                <div className="preview-window-label">
                  threatpolish-telemetry@production-node: live-deception-stream
                </div>
                <div className="preview-window-badge">PORT 8022 / 2222 ACTIVE</div>
              </div>
              <TerminalWindow
                title="threatpolish-telemetry@production-node: live-deception-stream"
                lines={liveTerminalLines}
              />
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================
          SECTION 2: PLATFORM OVERVIEW - WHAT IS THREATPOLISH?
          ========================================================= */}
      <section className="landing-section-white" id="overview">
        <div className="landing-container">
          <div className="landing-section-head">
            <span className="landing-section-eyebrow">Platform Overview</span>
            <h2 className="landing-section-title">What Is ThreatPolish?</h2>
            <p className="landing-section-desc">
              Traditional perimeter detection relies on signatures and noisy alert feeds.
              ThreatPolish deploys controlled deception environments that give defensive teams
              unambiguous, high-fidelity threat intelligence.
            </p>
          </div>

          <div className="overview-grid">
            <div className="overview-card">
              <div className="overview-icon-box">
                <IconShield size={24} />
              </div>
              <h3>What Is a Honeypot?</h3>
              <p>
                A honeypot is a controlled, isolated decoy system configured to mimic genuine organizational
                services. Because legitimate users have no business connecting to a decoy, any inbound traffic
                is inherently suspicious.
              </p>
            </div>

            <div className="overview-card">
              <div className="overview-icon-box">
                <IconActivity size={24} />
              </div>
              <h3>Why Organizations Use Honeypots</h3>
              <p>
                Traditional intrusion detection systems generate thousands of ambiguous alerts. Decoys deliver
                near-zero false positives, detecting adversarial reconnaissance and lateral movement before
                production systems are touched.
              </p>
            </div>

            <div className="overview-card">
              <div className="overview-icon-box">
                <IconNetwork size={24} />
              </div>
              <h3>What ThreatPolish Does</h3>
              <p>
                ThreatPolish combines adaptive deception decoys with multi-family behavioral correlation. It captures
                probes, fingerprints client tools (JA3, headers), safely stores credentials as one-way hashes,
                and clusters related sessions.
              </p>
            </div>

            <div className="overview-card">
              <div className="overview-icon-box">
                <IconServer size={24} />
              </div>
              <h3>How It Helps Security Analysts</h3>
              <p>
                Rather than guessing attribution based on rotating IP addresses, ThreatPolish constructs auditable
                mathematical evidence graphs. Analysts verify the exact behavioral components behind each correlation
                link before acting.
              </p>
            </div>
          </div>

          {/* Interactive Visual Architecture Diagram */}
          <div className="overview-diagram-wrap">
            <h4 className="diagram-title">Safe Telemetry &amp; Deception Flow</h4>
            <div className="diagram-flow">
              <div className="diagram-node attacker-node">
                <div className="node-icon">
                  <IconAlertTriangle size={20} />
                </div>
                <div className="node-info">
                  <strong>Adversary / Scanner</strong>
                  <span>Probing :8022 &amp; :2222</span>
                </div>
              </div>

              <div className="diagram-arrow">
                <svg width={24} height={24} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                  <path d="M5 12h14M12 5l7 7-7 7" />
                </svg>
              </div>

              <div className="diagram-node decoy-node">
                <div className="node-icon">
                  <IconServer size={20} />
                </div>
                <div className="node-info">
                  <strong>ThreatPolish Decoy</strong>
                  <span>Isolated Mock Service</span>
                </div>
              </div>

              <div className="diagram-arrow">
                <svg width={24} height={24} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                  <path d="M5 12h14M12 5l7 7-7 7" />
                </svg>
              </div>

              <div className="diagram-node engine-node">
                <div className="node-icon">
                  <IconActivity size={20} />
                </div>
                <div className="node-info">
                  <strong>Evidence Engine</strong>
                  <span>Sanitize &amp; Correlate</span>
                </div>
              </div>

              <div className="diagram-arrow">
                <svg width={24} height={24} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                  <path d="M5 12h14M12 5l7 7-7 7" />
                </svg>
              </div>

              <div className="diagram-node analyst-node">
                <div className="node-icon">
                  <IconShield size={20} />
                </div>
                <div className="node-info">
                  <strong>Analyst Workspace</strong>
                  <span>Audited Containment</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================
          SECTION 3: HOW THREATPOLISH WORKS (7-STEP PIPELINE)
          ========================================================= */}
      <section className="landing-section-alt" id="how-it-works">
        <div className="landing-container">
          <div className="landing-section-head">
            <span className="landing-section-eyebrow">Operational Lifecycle</span>
            <h2 className="landing-section-title">How ThreatPolish Works</h2>
            <p className="landing-section-desc">
              A rigorous 7-stage processing pipeline that converts raw network interactions
              into auditable threat intelligence and defensive containment.
            </p>
          </div>

          <div className="lifecycle-pipeline">
            <div className="pipeline-card">
              <div className="pipeline-step-header">
                <span className="pipeline-step-number">01</span>
                <span className="pipeline-step-badge">DEPLOY</span>
              </div>
              <h3 className="pipeline-card-title">Deploy Decoys</h3>
              <p className="pipeline-card-desc">
                Configure and expose controlled honeypot endpoints (HTTP APIs, administration portals, SSH shells)
                that imitate authentic production targets.
              </p>
              <div className="pipeline-card-tag">HTTP :8022 | SSH :2222</div>
            </div>

            <div className="pipeline-card">
              <div className="pipeline-step-header">
                <span className="pipeline-step-number">02</span>
                <span className="pipeline-step-badge">CAPTURE</span>
              </div>
              <h3 className="pipeline-card-title">Capture Activity</h3>
              <p className="pipeline-card-desc">
                Record incoming TCP handshakes, TLS parameters, JA3 fingerprints, HTTP payloads, and interactive
                terminal commands in real time.
              </p>
              <div className="pipeline-card-tag">Zero-knowledge hashes</div>
            </div>

            <div className="pipeline-card">
              <div className="pipeline-step-header">
                <span className="pipeline-step-number">03</span>
                <span className="pipeline-step-badge">INGEST</span>
              </div>
              <h3 className="pipeline-card-title">Ingest Telemetry</h3>
              <p className="pipeline-card-desc">
                Validate and normalize supported events into a versioned JSON schema (v1.0) with cryptographic
                provenance and quarantine guards.
              </p>
              <div className="pipeline-card-tag">Schema v1.0 strict</div>
            </div>

            <div className="pipeline-card">
              <div className="pipeline-step-header">
                <span className="pipeline-step-number">04</span>
                <span className="pipeline-step-badge">DETECT</span>
              </div>
              <h3 className="pipeline-card-title">Detect Suspicious Behaviour</h3>
              <p className="pipeline-card-desc">
                Apply detection rules, analyze threat indicators, and flag anomalous sign-ins such as impossible
                travel using great-circle distance checks.
              </p>
              <div className="pipeline-card-tag">Geo-distance anomaly</div>
            </div>

            <div className="pipeline-card">
              <div className="pipeline-step-header">
                <span className="pipeline-step-number">05</span>
                <span className="pipeline-step-badge">CORRELATE</span>
              </div>
              <h3 className="pipeline-card-title">Correlate Events</h3>
              <p className="pipeline-card-desc">
                Connect related activity into campaigns across 6 behavioral evidence families, linking sessions
                even after adversaries rotate source IPs.
              </p>
              <div className="pipeline-card-tag">6 Evidence families</div>
            </div>

            <div className="pipeline-card">
              <div className="pipeline-step-header">
                <span className="pipeline-step-number">06</span>
                <span className="pipeline-step-badge">INVESTIGATE</span>
              </div>
              <h3 className="pipeline-card-title">Investigate Threats</h3>
              <p className="pipeline-card-desc">
                Let analysts explore events, sessions, evidence links, and campaign topologies with auditable
                confidence graphs and observation profiles.
              </p>
              <div className="pipeline-card-tag">Auditable graph</div>
            </div>

            <div className="pipeline-card pipeline-card-highlight">
              <div className="pipeline-step-header">
                <span className="pipeline-step-number">07</span>
                <span className="pipeline-step-badge highlight">DECIDE &amp; ACT</span>
              </div>
              <h3 className="pipeline-card-title">Generate Intelligence</h3>
              <p className="pipeline-card-desc">
                Export forensic reports, track campaign progression, and execute policy-gated containment actions
                with automatic expiration timers.
              </p>
              <div className="pipeline-card-tag">Policy-gated containment</div>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================
          SECTION 4: INSIDE A THREATPOLISH INVESTIGATION
          ========================================================= */}
      <section className="landing-section-white" id="investigation">
        <div className="landing-container">
          <div className="landing-section-head">
            <span className="landing-section-eyebrow">Forensic Walkthrough</span>
            <h2 className="landing-section-title">Inside a ThreatPolish Investigation</h2>
            <p className="landing-section-desc">
              Follow an active adversary probe from initial connection to verified defensive containment.
            </p>
          </div>

          <div className="investigation-walkthrough">
            <div className="investigation-timeline">
              <div className="timeline-item">
                <div className="timeline-marker">1</div>
                <div className="timeline-body">
                  <span className="timeline-time">03:41:12 UTC</span>
                  <h4>Connection Arrives at Decoy</h4>
                  <p>
                    An adversary at <code>198.51.100.42</code> initiates an HTTP GET request to decoy port <code>:8022</code> targeting
                    an administrative debug endpoint <code>/api/v1/debug</code>.
                  </p>
                </div>
              </div>

              <div className="timeline-item">
                <div className="timeline-marker">2</div>
                <div className="timeline-body">
                  <span className="timeline-time">03:41:13 UTC</span>
                  <h4>Telemetry Capture &amp; Normalization</h4>
                  <p>
                    The decoy records TLS parameters (JA3 fingerprint <code>771,4865-4866</code>), HTTP headers, and stores
                    the authentication attempt as a one-way SHA-256 hash.
                  </p>
                </div>
              </div>

              <div className="timeline-item">
                <div className="timeline-marker">3</div>
                <div className="timeline-body">
                  <span className="timeline-time">03:41:14 UTC</span>
                  <h4>Heuristic Event Detection</h4>
                  <p>
                    The ingestion service normalizes the record under schema <code>v1.0</code>, assigning it session ID <code>sess_8f29</code> and
                    flagging it as reconnaissance with medium severity.
                  </p>
                </div>
              </div>

              <div className="timeline-item">
                <div className="timeline-marker">4</div>
                <div className="timeline-body">
                  <span className="timeline-time">03:41:18 UTC</span>
                  <h4>Cross-IP Behavioral Correlation</h4>
                  <p>
                    The correlation engine matches the command cadence, request interval, and user-agent with an earlier session
                    <code>sess_3a11</code> originating from a completely different IP <code>203.0.113.88</code>.
                  </p>
                </div>
              </div>

              <div className="timeline-item">
                <div className="timeline-marker">5</div>
                <div className="timeline-body">
                  <span className="timeline-time">03:41:19 UTC</span>
                  <h4>Campaign Formation</h4>
                  <p>
                    With behavioral confidence calculated at <code>0.942</code>, the engine forms campaign <code>cmp_5a9676</code> linking both
                    infrastructure nodes and alerting the on-duty analyst.
                  </p>
                </div>
              </div>

              <div className="timeline-item">
                <div className="timeline-marker">6</div>
                <div className="timeline-body">
                  <span className="timeline-time">03:41:25 UTC</span>
                  <h4>Audited Containment &amp; Expiration</h4>
                  <p>
                    The security analyst inspects the evidence component table, confirms targeting similarity, and stages a policy-gated
                    60-minute egress block with automatic rollback.
                  </p>
                </div>
              </div>
            </div>

            {/* Illustrative Investigation Card */}
            <div className="investigation-mock-card">
              <div className="mock-card-header">
                <span className="mock-status-pill">ILLUSTRATIVE WORKFLOW DEMONSTRATION</span>
                <span className="mock-id">cmp_5a9676</span>
              </div>
              <div className="mock-card-body">
                <div className="mock-row">
                  <span className="mock-lbl">Campaign Status:</span>
                  <span className="mock-val status-high">HIGH SEVERITY (Active)</span>
                </div>
                <div className="mock-row">
                  <span className="mock-lbl">Link Confidence:</span>
                  <span className="mock-val mono">0.942 (cadence + toolchain)</span>
                </div>
                <div className="mock-row">
                  <span className="mock-lbl">Correlated IPs:</span>
                  <span className="mock-val mono">198.51.100.42, 203.0.113.88</span>
                </div>
                <div className="mock-row">
                  <span className="mock-lbl">Decoy Targets:</span>
                  <span className="mock-val mono">decoy-http-1 (:8022)</span>
                </div>
                <div className="mock-row">
                  <span className="mock-lbl">Evidence Families:</span>
                  <span className="mock-val">Cadence (0.88), Toolchain (0.95), Timing (0.82)</span>
                </div>
                <div className="mock-row">
                  <span className="mock-lbl">Containment Rule:</span>
                  <span className="mock-val mono">egress_block_60m (Analyst Approved)</span>
                </div>
              </div>
              <div className="mock-card-foot">
                <span className="mock-note">Evidence strictly separated: Severity = High, Confidence = 0.942</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================
          SECTION 5: CORE FEATURES
          ========================================================= */}
      <section className="landing-section-alt" id="features">
        <div className="landing-container">
          <div className="landing-section-head">
            <span className="landing-section-eyebrow">Defensive Capabilities</span>
            <h2 className="landing-section-title">Engineered for Rigorous Threat Analysis</h2>
            <p className="landing-section-desc">
              Every capability in ThreatPolish is grounded in deterministic evidence, analyst control,
              and operational sovereignty.
            </p>
          </div>

          <div className="features-grid">
            <div className="feature-item">
              <div className="feature-icon-wrap">
                <IconServer size={22} />
              </div>
              <h3>Decoy Management</h3>
              <p>
                Configure lightweight, isolated honeypot listeners for HTTP and SSH. Emulate authentic application
                surfaces with bounded response profiles that prevent lateral escape.
              </p>
            </div>

            <div className="feature-item">
              <div className="feature-icon-wrap">
                <IconActivity size={22} />
              </div>
              <h3>Normalized Ingestion</h3>
              <p>
                Strict JSON schema enforcement (v1.0) with quarantine buffers for malformed payloads. Edge sensor
                tokens authenticate distributed collectors without write escalation.
              </p>
            </div>

            <div className="feature-item">
              <div className="feature-icon-wrap">
                <IconNetwork size={22} />
              </div>
              <h3>Cross-IP Behavioral Correlation</h3>
              <p>
                Connect adversary sessions even after proxy or VPN hopping. Evaluates 6 evidence families:
                targeting, toolchains, command sequences, cadence, timing, and threat intelligence.
              </p>
            </div>

            <div className="feature-item">
              <div className="feature-icon-wrap">
                <IconShield size={22} />
              </div>
              <h3>Campaign Intelligence</h3>
              <p>
                Cluster discrete sessions into trackable adversary campaigns. Maintain persistent campaign
                lifecycles, member inventories, and auditable status histories.
              </p>
            </div>

            <div className="feature-item">
              <div className="feature-icon-wrap">
                <IconTerminal size={22} />
              </div>
              <h3>Auditable Evidence Graph</h3>
              <p>
                Every relationship link stores the complete mathematical component table that produced it.
                Severity and confidence are strictly separated for objective decision-making.
              </p>
            </div>

            <div className="feature-item">
              <div className="feature-icon-wrap">
                <IconKey size={22} />
              </div>
              <h3>Investigation Workflows</h3>
              <p>
                Stage adaptive observation profiles when evidence is ambiguous. Solicit decisive telemetry
                without hallucinating or manufacturing evidence.
              </p>
            </div>

            <div className="feature-item">
              <div className="feature-icon-wrap">
                <IconAlertTriangle size={22} />
              </div>
              <h3>Policy-Gated Containment</h3>
              <p>
                Inference and action remain distinct privileges. Containment actions require verified
                confidence thresholds, administrator approval, auto-expiry timers, and rollback.
              </p>
            </div>

            <div className="feature-item">
              <div className="feature-icon-wrap">
                <IconEye size={22} />
              </div>
              <h3>Role-Based Access Control</h3>
              <p>
                Four distinct permission tiers: Administrator (full authority), Security Analyst (investigation),
                Viewer (read-only audit), and Sensor Agent (write-only ingest tokens).
              </p>
            </div>

            <div className="feature-item">
              <div className="feature-icon-wrap">
                <IconActivity size={22} />
              </div>
              <h3>Audit Logging &amp; Session Tracking</h3>
              <p>
                Track authentication events with great-circle distance checks for impossible travel anomalies.
                Revoke individual active sessions without disrupting user credentials.
              </p>
            </div>

            <div className="feature-item">
              <div className="feature-icon-wrap">
                <IconServer size={22} />
              </div>
              <h3>Automated Data Retention</h3>
              <p>
                Enforce privacy hygiene with configurable retention horizons for raw events and graph edges.
                Scheduled pruning sweeps keep database footprint lean with CSV audit exports.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================
          SECTION 6: EVIDENCE GRAPH SHOWCASE
          ========================================================= */}
      <section className="landing-section-white" id="evidence-graph">
        <div className="landing-container">
          <div className="landing-section-head">
            <span className="landing-section-eyebrow">Evidence Attribution</span>
            <h2 className="landing-section-title">The ThreatPolish Evidence Graph</h2>
            <p className="landing-section-desc">
              Attribution without speculation. Every relationship links raw evidence to mathematical confidence,
              separating threat severity from observational certainty.
            </p>
          </div>

          <div className="graph-showcase-wrap">
            <div className="graph-visual-box">
              <div className="graph-node-diagram">
                <div className="graph-node-center">
                  <div className="graph-node-badge">CAMPAIGN CLUSTER</div>
                  <strong>cmp_5a9676</strong>
                  <span>Confidence: 0.942</span>
                </div>

                <div className="graph-leaf leaf-top-left">
                  <span className="leaf-label">Source IP</span>
                  <code>198.51.100.42</code>
                </div>

                <div className="graph-leaf leaf-top-right">
                  <span className="leaf-label">Source IP</span>
                  <code>203.0.113.88</code>
                </div>

                <div className="graph-leaf leaf-bottom-left">
                  <span className="leaf-label">Decoy Target</span>
                  <code>decoy-http-1 (:8022)</code>
                </div>

                <div className="graph-leaf leaf-bottom-right">
                  <span className="leaf-label">Indicator</span>
                  <code>ja3:771,4865-4866</code>
                </div>
              </div>
            </div>

            <div className="graph-evidence-table-box">
              <h4>Auditable Mathematical Component Breakdown</h4>
              <p className="graph-table-desc">
                Each correlation link stores individual weights. No black-box AI scores or opaque heuristics.
              </p>

              <div className="evidence-table">
                <div className="evidence-row header">
                  <span>Evidence Family</span>
                  <span>Observed Anchor</span>
                  <span>Component Weight</span>
                </div>
                <div className="evidence-row">
                  <span>Command Cadence</span>
                  <span className="mono">0.42s probe interval</span>
                  <span className="mono weight-high">0.880</span>
                </div>
                <div className="evidence-row">
                  <span>Toolchain Signature</span>
                  <span className="mono">JA3 + Go-client banner</span>
                  <span className="mono weight-high">0.950</span>
                </div>
                <div className="evidence-row">
                  <span>Target Affinity</span>
                  <span className="mono">/api/v1/debug probe</span>
                  <span className="mono weight-med">0.840</span>
                </div>
                <div className="evidence-row">
                  <span>Timing Proximity</span>
                  <span className="mono">Within 72h window</span>
                  <span className="mono weight-med">0.820</span>
                </div>
                <div className="evidence-row summary">
                  <span>Calculated Net Confidence</span>
                  <span className="mono">Multi-family aggregate</span>
                  <span className="mono weight-total">0.942 (HIGH)</span>
                </div>
              </div>

              <div className="graph-axiom">
                <strong>Core Analytical Axiom:</strong> Severity measures impact; Confidence measures certainty.
                ThreatPolish never conflates the two.
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================
          SECTION 7: DASHBOARD PREVIEW
          ========================================================= */}
      <section className="landing-section-alt" id="dashboard-preview">
        <div className="landing-container">
          <div className="landing-section-head">
            <span className="landing-section-eyebrow">Analyst Console</span>
            <h2 className="landing-section-title">Explore the Workspace</h2>
            <p className="landing-section-desc">
              A high-density, low-latency console crafted for fast threat triage, deep forensic inspection,
              and administrative control.
            </p>
          </div>

          <div className="preview-tab-container">
            <div className="preview-tab-buttons" role="tablist">
              <button
                type="button"
                role="tab"
                aria-selected={activePreviewTab === "overview"}
                className={`preview-tab-btn ${activePreviewTab === "overview" ? "active" : ""}`}
                onClick={() => setActivePreviewTab("overview")}
              >
                Overview
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={activePreviewTab === "events"}
                className={`preview-tab-btn ${activePreviewTab === "events" ? "active" : ""}`}
                onClick={() => setActivePreviewTab("events")}
              >
                Events Ledger
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={activePreviewTab === "campaigns"}
                className={`preview-tab-btn ${activePreviewTab === "campaigns" ? "active" : ""}`}
                onClick={() => setActivePreviewTab("campaigns")}
              >
                Campaigns
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={activePreviewTab === "deception"}
                className={`preview-tab-btn ${activePreviewTab === "deception" ? "active" : ""}`}
                onClick={() => setActivePreviewTab("deception")}
              >
                Deception Decoys
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={activePreviewTab === "admin"}
                className={`preview-tab-btn ${activePreviewTab === "admin" ? "active" : ""}`}
                onClick={() => setActivePreviewTab("admin")}
              >
                Administration
              </button>
            </div>

            <div className="preview-tab-content">
              {activePreviewTab === "overview" && (
                <div className="mock-view-card">
                  <div className="mock-view-head">
                    <h3>Overview Dashboard</h3>
                    <span className="mock-view-pill">Live Operational State</span>
                  </div>
                  <div className="mock-kpi-grid">
                    <div className="kpi-box">
                      <span className="kpi-label">Active Campaigns</span>
                      <span className="kpi-value">14</span>
                      <span className="kpi-sub">3 High Severity</span>
                    </div>
                    <div className="kpi-box">
                      <span className="kpi-label">Ingested Events (24h)</span>
                      <span className="kpi-value">1,284</span>
                      <span className="kpi-sub">0 Rejected Payloads</span>
                    </div>
                    <div className="kpi-box">
                      <span className="kpi-label">Decoy Sessions</span>
                      <span className="kpi-value">48</span>
                      <span className="kpi-sub">HTTP &amp; SSH Honeypots</span>
                    </div>
                    <div className="kpi-box">
                      <span className="kpi-label">Retention Hygiene</span>
                      <span className="kpi-value">Healthy</span>
                      <span className="kpi-sub">Next sweep in 18h</span>
                    </div>
                  </div>
                  <div className="mock-banner alert-banner">
                    <strong>Sign-in Attention:</strong> 1 anomalous sign-in detected with impossible travel (5,570 km within 4 minutes).
                  </div>
                </div>
              )}

              {activePreviewTab === "events" && (
                <div className="mock-view-card">
                  <div className="mock-view-head">
                    <h3>Normalized Events Ledger</h3>
                    <span className="mock-view-pill">Schema v1.0 Standard</span>
                  </div>
                  <div className="mock-table-strip">
                    <div className="mock-tbl-row header">
                      <span>Time (UTC)</span>
                      <span>Source IP</span>
                      <span>Module</span>
                      <span>Event Type</span>
                      <span>Severity</span>
                    </div>
                    <div className="mock-tbl-row">
                      <span className="mono">03:41:12</span>
                      <span className="mono">198.51.100.42</span>
                      <span>honeypot</span>
                      <span className="mono">honeypot.http.request</span>
                      <span className="badge sev-medium">medium</span>
                    </div>
                    <div className="mock-tbl-row">
                      <span className="mono">03:39:55</span>
                      <span className="mono">203.0.113.88</span>
                      <span>honeypot</span>
                      <span className="mono">honeypot.http.request</span>
                      <span className="badge sev-medium">medium</span>
                    </div>
                    <div className="mock-tbl-row">
                      <span className="mono">03:38:10</span>
                      <span className="mono">192.0.2.14</span>
                      <span>honeypot</span>
                      <span className="mono">honeypot.ssh.login</span>
                      <span className="badge sev-low">low</span>
                    </div>
                  </div>
                </div>
              )}

              {activePreviewTab === "campaigns" && (
                <div className="mock-view-card">
                  <div className="mock-view-head">
                    <h3>Active Threat Campaigns</h3>
                    <span className="mock-view-pill">Behavioral Correlation Engine</span>
                  </div>
                  <div className="mock-campaign-box">
                    <div className="camp-top">
                      <strong>cmp_5a9676 - Multi-IP Web Probe Campaign</strong>
                      <span className="badge sev-high">high severity</span>
                    </div>
                    <p className="camp-desc">
                      Correlated across 2 source IPs with 0.942 link confidence via command cadence and toolchain matching.
                    </p>
                    <div className="camp-meta">
                      <span>2 sessions</span>
                      <span>-</span>
                      <span>2 unique IPs</span>
                      <span>-</span>
                      <span>Anchor: JA3 fingerprint + 0.42s interval</span>
                    </div>
                  </div>
                </div>
              )}

              {activePreviewTab === "deception" && (
                <div className="mock-view-card">
                  <div className="mock-view-head">
                    <h3>Adaptive Deception Honeypots</h3>
                    <span className="mock-view-pill">Listener Services</span>
                  </div>
                  <div className="mock-kpi-grid">
                    <div className="kpi-box">
                      <span className="kpi-label">HTTP Decoy (:8022)</span>
                      <span className="kpi-value text-ok">ACTIVE</span>
                      <span className="kpi-sub">Profile: admin-console</span>
                    </div>
                    <div className="kpi-box">
                      <span className="kpi-label">SSH Decoy (:2222)</span>
                      <span className="kpi-value text-ok">ACTIVE</span>
                      <span className="kpi-sub">Profile: linux-shell</span>
                    </div>
                    <div className="kpi-box">
                      <span className="kpi-label">Credential Storage</span>
                      <span className="kpi-value">Zero-Knowledge</span>
                      <span className="kpi-sub">Truncated SHA-256</span>
                    </div>
                    <div className="kpi-box">
                      <span className="kpi-label">Active Investigations</span>
                      <span className="kpi-value">2 Planned</span>
                      <span className="kpi-sub">Bounded Observation</span>
                    </div>
                  </div>
                </div>
              )}

              {activePreviewTab === "admin" && (
                <div className="mock-view-card">
                  <div className="mock-view-head">
                    <h3>System Administration &amp; Governance</h3>
                    <span className="mock-view-pill">RBAC &amp; Retention Controls</span>
                  </div>
                  <div className="mock-admin-grid">
                    <div className="admin-sub-card">
                      <h4>Role-Based Access</h4>
                      <p>Provision analysts, viewers, and mint sensor tokens for automated edge ingestion.</p>
                      <span className="mono tag">Admin | Analyst | Viewer | Sensor</span>
                    </div>
                    <div className="admin-sub-card">
                      <h4>Automated Retention</h4>
                      <p>Configurable 90-day event retention and 30-day graph horizons with CSV exports.</p>
                      <span className="mono tag">Scheduled &amp; Manual Pruning</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================
          SECTION 8: BUILT FOR SECURITY TEAMS
          ========================================================= */}
      <section className="landing-section-white" id="teams">
        <div className="landing-container">
          <div className="landing-section-head">
            <span className="landing-section-eyebrow">Security Operations</span>
            <h2 className="landing-section-title">Built for Every Operational Role</h2>
            <p className="landing-section-desc">
              Granular access control enforcing the principle of least privilege across your security team.
            </p>
          </div>

          <div className="teams-grid">
            <div className="team-role-card">
              <div className="role-header">
                <span className="role-badge admin">ADMINISTRATOR</span>
                <span className="role-clearance">Full Authority</span>
              </div>
              <h3>System Administrator</h3>
              <p>
                Provision analyst accounts, issue sensor tokens, approve containment actions, execute manual
                retention sweeps, and review system audit trails.
              </p>
              <ul className="role-caps">
                <li>User &amp; Sensor Token Management</li>
                <li>Containment Policy Approvals</li>
                <li>Data Retention &amp; Pruning Triggers</li>
                <li>Session Revocation &amp; Audits</li>
              </ul>
            </div>

            <div className="team-role-card">
              <div className="role-header">
                <span className="role-badge analyst">SECURITY ANALYST</span>
                <span className="role-clearance">Investigation &amp; Triage</span>
              </div>
              <h3>Security Analyst</h3>
              <p>
                Explore the Evidence Graph, investigate campaigns, evaluate correlation components, stage observation
                profiles, and review retention statistics.
              </p>
              <ul className="role-caps">
                <li>Campaign &amp; Session Analysis</li>
                <li>Evidence Component Verification</li>
                <li>Telemetry Search &amp; Filtering</li>
                <li>Stage Adaptive Observation</li>
              </ul>
            </div>

            <div className="team-role-card">
              <div className="role-header">
                <span className="role-badge viewer">READ-ONLY VIEWER</span>
                <span className="role-clearance">Monitoring Clearance</span>
              </div>
              <h3>Read-Only Viewer</h3>
              <p>
                Maintain situational awareness across active campaigns, view the events ledger, and inspect
                forensic reports without data mutation rights.
              </p>
              <ul className="role-caps">
                <li>Campaign Status Monitoring</li>
                <li>Read-Only Events Ledger</li>
                <li>Forensic Report Inspection</li>
                <li>Audit Visibility</li>
              </ul>
            </div>

            <div className="team-role-card">
              <div className="role-header">
                <span className="role-badge sensor">SENSOR AGENT</span>
                <span className="role-clearance">Write-Only Ingestion</span>
              </div>
              <h3>Automated Sensor</h3>
              <p>
                Low-privilege machine token dedicated strictly to pushing telemetry packets from remote edge
                honeypots into the central normalization pipeline.
              </p>
              <ul className="role-caps">
                <li>Versioned Ingest API (v1.0)</li>
                <li>Token Authentication (X-Agent-Token)</li>
                <li>Zero Database Read Access</li>
                <li>Instant Token Revocation</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================
          SECTION 9: ARCHITECTURE & TECHNOLOGY
          ========================================================= */}
      <section className="landing-section-alt" id="architecture">
        <div className="landing-container">
          <div className="landing-section-head">
            <span className="landing-section-eyebrow">System Engineering</span>
            <h2 className="landing-section-title">Modern, Sovereign Architecture</h2>
            <p className="landing-section-desc">
              Hardened technologies engineered for deterministic execution, self-hosting, and zero telemetry leaks.
            </p>
          </div>

          <div className="tech-stack-grid">
            <div className="tech-item">
              <div className="tech-badge">BACKEND</div>
              <h3>FastAPI &amp; Python 3.11+</h3>
              <p>
                High-performance asynchronous REST API with strict Pydantic v2 validation and structured logging.
              </p>
            </div>

            <div className="tech-item">
              <div className="tech-badge">FRONTEND</div>
              <h3>React 18 &amp; TypeScript</h3>
              <p>
                Single-page application bundled with Vite, local typography, and strict Content Security Policy.
              </p>
            </div>

            <div className="tech-item">
              <div className="tech-badge">STORAGE</div>
              <h3>SQLite &amp; PostgreSQL</h3>
              <p>
                Dual database support via SQLAlchemy ORM: lightweight SQLite for development and PostgreSQL for scale.
              </p>
            </div>

            <div className="tech-item">
              <div className="tech-badge">CORRELATION</div>
              <h3>Deterministic Engine</h3>
              <p>
                Algorithmic multi-family scoring that computes auditable confidence without machine learning hallucinations.
              </p>
            </div>

            <div className="tech-item">
              <div className="tech-badge">SECURITY</div>
              <h3>Zero-Knowledge Storage</h3>
              <p>
                Captured decoy credentials committed exclusively as one-way SHA-256 hashes for safe analyst review.
              </p>
            </div>

            <div className="tech-item">
              <div className="tech-badge">HYGIENE</div>
              <h3>Automated Retention</h3>
              <p>
                Configurable lifecycle retention windows (30/90 days) with scheduled pruning and CSV audit exports.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================
          SECTION 10: GETTING STARTED / DOCUMENTATION
          ========================================================= */}
      <section className="landing-section-white" id="docs">
        <div className="landing-container">
          <div className="landing-section-head">
            <span className="landing-section-eyebrow">Deployment Guide</span>
            <h2 className="landing-section-title">Get Up and Running in Minutes</h2>
            <p className="landing-section-desc">
              Self-host ThreatPolish on your infrastructure with a simple 5-step deployment flow.
            </p>
          </div>

          <div className="getting-started-wrapper">
            <div className="steps-list">
              <div className="step-card">
                <span className="step-num">Step 1</span>
                <h4>Clone &amp; Install Dependencies</h4>
                <p>Clone the repository and install the backend Python requirements and frontend packages.</p>
              </div>

              <div className="step-card">
                <span className="step-num">Step 2</span>
                <h4>Configure Environment</h4>
                <p>Define your JWT secret, database connection string, and bootstrap administrator credentials.</p>
              </div>

              <div className="step-card">
                <span className="step-num">Step 3</span>
                <h4>Initialize Database</h4>
                <p>Run database migrations to initialize tables for events, campaigns, evidence links, and users.</p>
              </div>

              <div className="step-card">
                <span className="step-num">Step 4</span>
                <h4>Deploy Decoy Listeners</h4>
                <p>Start lightweight honeypot listeners on your desired target ports (e.g. HTTP :8022, SSH :2222).</p>
              </div>

              <div className="step-card">
                <span className="step-num">Step 5</span>
                <h4>Launch Console &amp; Monitor</h4>
                <p>Sign in to the analyst console with your administrator credentials and observe live telemetry.</p>
              </div>
            </div>

            <div className="terminal-code-box">
              <div className="code-box-header">
                <span className="code-box-title">Quickstart Setup Commands</span>
                <button
                  type="button"
                  className="btn-copy-code"
                  onClick={() => copyCode(quickstartCommands)}
                >
                  {copiedSnippet ? "Copied!" : "Copy"}
                </button>
              </div>
              <pre className="code-pre">
                <code>{quickstartCommands}</code>
              </pre>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================
          SECTION 11: FINAL CTA & ANALYST PORTAL (SIGN IN)
          ========================================================= */}
      <section className="landing-section-cta" id="signin">
        <div className="landing-container">
          <div className="cta-grid">
            <div className="cta-info-col">
              <div className="landing-eyebrow light">
                <IconShield size={14} />
                <span>Analyst Workspace Access</span>
              </div>

              <h2 className="cta-headline">
                Don't just detect suspicious activity. Understand it.
              </h2>

              <p className="cta-sub">
                Take control of your organization's threat intelligence with custom honeypot telemetry,
                multi-family session correlation, and auditable evidence attribution.
              </p>

              <div className="cta-highlights">
                <div className="cta-highlight-item">
                  <svg width={18} height={18} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                    <path d="M20 6 9 17l-5-5" />
                  </svg>
                  <span>Zero-knowledge credential hashing</span>
                </div>
                <div className="cta-highlight-item">
                  <svg width={18} height={18} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                    <path d="M20 6 9 17l-5-5" />
                  </svg>
                  <span>Deterministic correlation with mathematical confidence</span>
                </div>
                <div className="cta-highlight-item">
                  <svg width={18} height={18} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                    <path d="M20 6 9 17l-5-5" />
                  </svg>
                  <span>100% self-hosted with complete data sovereignty</span>
                </div>
              </div>

              <div className="cta-external-links">
                <a
                  href="https://github.com/heyytrayamm/ThreatPolish"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn-landing-outline light"
                >
                  GitHub Repository
                </a>
                <button
                  type="button"
                  className="btn-landing-secondary light"
                  onClick={() => scrollToSection("docs")}
                >
                  View Documentation
                </button>
              </div>
            </div>

            {/* Embedded Analyst Portal Sign-In Card */}
            <div className="cta-form-col">
              <form onSubmit={onSignIn} className="landing-login-card" aria-label="sign in">
                <div className="login-card-head">
                  <img
                    src="/logo-mark.png"
                    alt="ThreatPolish"
                    className="login-card-logo"
                    width={40}
                    height={40}
                  />
                  <div>
                    <h3 className="login-card-title">Analyst Portal</h3>
                    <p className="login-card-sub">Secure Console Sign In</p>
                  </div>
                </div>

                <ErrorBox message={error} />

                <div className="tp-field">
                  <label htmlFor="login-email" className="tp-field-label">
                    Email
                  </label>
                  <input
                    id="login-email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    autoComplete="username"
                    placeholder="analyst@threatpolish.local"
                    required
                  />
                </div>

                <div className="tp-field">
                  <label htmlFor="login-password" className="tp-field-label">
                    Password
                  </label>
                  <div className="tp-password-input-wrap">
                    <input
                      id="login-password"
                      type={passwordVisible ? "text" : "password"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      autoComplete="current-password"
                      placeholder="Enter password"
                      required
                    />
                    <button
                      type="button"
                      className="tp-password-toggle"
                      onClick={() => setPasswordVisible(!passwordVisible)}
                      aria-label={passwordVisible ? "Hide password" : "Show password"}
                      tabIndex={-1}
                    >
                      {passwordVisible ? <IconEyeOff size={16} /> : <IconEye size={16} />}
                    </button>
                  </div>
                </div>

                <button type="submit" className="primary btn-login-submit" disabled={busy}>
                  {busy ? "Signing in..." : "Sign in"}
                </button>

                <div className="login-card-notes">
                  <span>Sessions expire automatically upon token revocation.</span>
                  <span className="mono text-muted">HS256 session - zero-knowledge credentials</span>
                </div>
              </form>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================
          SECTION 12: FOOTER
          ========================================================= */}
      <footer className="landing-main-footer">
        <div className="landing-container">
          <div className="footer-top-grid">
            <div className="footer-brand-col">
              <div className="footer-brand-header">
                <img src="/logo-mark.png" alt="ThreatPolish" width={30} height={30} />
                <strong>ThreatPolish</strong>
              </div>
              <p className="footer-tagline">
                See the Evidence. Understand the Threat.
              </p>
            </div>

            <div className="footer-links-col">
              <h4>Platform</h4>
              <button type="button" className="footer-link-btn" onClick={() => scrollToSection("overview")}>
                Overview
              </button>
              <button type="button" className="footer-link-btn" onClick={() => scrollToSection("how-it-works")}>
                How It Works
              </button>
              <button type="button" className="footer-link-btn" onClick={() => scrollToSection("features")}>
                Features
              </button>
              <button type="button" className="footer-link-btn" onClick={() => scrollToSection("evidence-graph")}>
                Evidence Graph
              </button>
            </div>

            <div className="footer-links-col">
              <h4>Resources</h4>
              <button type="button" className="footer-link-btn" onClick={() => scrollToSection("architecture")}>
                Architecture
              </button>
              <button type="button" className="footer-link-btn" onClick={() => scrollToSection("docs")}>
                Documentation
              </button>
              <a
                href="https://github.com/heyytrayamm/ThreatPolish"
                target="_blank"
                rel="noopener noreferrer"
                className="footer-link-anchor"
              >
                GitHub Repository
              </a>
              <button type="button" className="footer-link-btn" onClick={handleLoginClick}>
                Analyst Portal
              </button>
            </div>

            <div className="footer-links-col">
              <h4>Legal &amp; Governance</h4>
              <button type="button" className="footer-link-btn" onClick={onOpenPrivacy}>
                Privacy Policy
              </button>
              <button type="button" className="footer-link-btn" onClick={onOpenTerms}>
                Terms and Conditions
              </button>
              <span className="footer-license-note">Licensed under MIT &amp; OFL-1.1</span>
            </div>
          </div>

          <div className="footer-bottom-bar">
            <span>&copy; 2026 ThreatPolish Defensive Systems. All rights reserved.</span>
            <div className="footer-bottom-actions">
              <button type="button" className="footer-bottom-link" onClick={onOpenPrivacy}>
                Privacy
              </button>
              <span className="footer-sep" aria-hidden="true">&middot;</span>
              <button type="button" className="footer-bottom-link" onClick={onOpenTerms}>
                Terms
              </button>
              <span className="footer-sep" aria-hidden="true">&middot;</span>
              <button type="button" className="footer-bottom-link" onClick={handleLoginClick}>
                Portal
              </button>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
