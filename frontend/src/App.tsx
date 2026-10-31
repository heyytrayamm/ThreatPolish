import { FormEvent, useEffect, useState } from "react";
import { api, getToken, setToken, User } from "./api";
import { applyTheme, readTheme, rememberTheme, watchHostTheme, type Theme } from "./theme";
import { ErrorBox, IconEye, IconEyeOff, IconShield, Loading, TerminalWindow } from "./ui";
import Overview from "./pages/Overview";
import Events from "./pages/Events";
import Campaigns from "./pages/Campaigns";
import Deception from "./pages/Deception";
import Findings from "./pages/Findings";
import Crypto from "./pages/Crypto";
import Responses from "./pages/Responses";
import Retention from "./pages/Retention";
import Administration from "./pages/Administration";
import Account from "./pages/Account";
import PrivacyPolicy from "./pages/PrivacyPolicy";
import TermsAndConditions from "./pages/TermsAndConditions";

type View =
  | "overview"
  | "events"
  | "campaigns"
  | "deception"
  | "findings"
  | "crypto"
  | "responses"
  | "retention"
  | "admin"
  | "account"
  | "privacy"
  | "terms";

function viewFromUrl(): View {
  const requested = new URLSearchParams(window.location.search).get("view");
  return requested && VIEWS.has(requested as View) ? (requested as View) : "overview";
}

function rememberView(view: View, mode: "push" | "replace" = "push"): void {
  const url = new URL(window.location.href);
  if (view === "overview") url.searchParams.delete("view");
  else url.searchParams.set("view", view);
  const next = `${url.pathname}${url.search}${url.hash}`;
  const current = `${window.location.pathname}${window.location.search}${window.location.hash}`;
  if (next === current) return;
  if (mode === "replace") window.history.replaceState(null, "", url);
  else window.history.pushState(null, "", url);
}

function utcClock(): string {
  return `${new Date().toISOString().slice(11, 19)} UTC`;
}

const NAV: { key: View; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "events", label: "Events" },
  { key: "campaigns", label: "Campaigns" },
  { key: "deception", label: "Deception" },
  { key: "findings", label: "Web findings" },
  { key: "crypto", label: "Asset risk" },
  { key: "responses", label: "Responses" },
  { key: "retention", label: "Retention" },
  { key: "admin", label: "Administration" },
  { key: "account", label: "Account" },
];

const VIEWS = new Set<View>([...NAV.map((item) => item.key), "privacy", "terms"]);

function canView(view: View, role: string): boolean {
  if (view === "admin") return role === "admin";
  if (view === "retention") return role === "admin" || role === "analyst";
  return true;
}

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [checking, setChecking] = useState(Boolean(getToken()));
  const [view, setView] = useState<View>(viewFromUrl);
  const [error, setError] = useState<string | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [passwordVisible, setPasswordVisible] = useState(false);
  const [busy, setBusy] = useState(false);
  const [clock, setClock] = useState(utcClock);
  const [theme, setTheme] = useState<Theme>(readTheme);

  useEffect(() => {
    const timer = window.setInterval(() => setClock(utcClock()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  useEffect(() => watchHostTheme(setTheme), []);

  useEffect(() => {
    if (!getToken()) return;
    api
      .me()
      .then((me) => setUser({ id: me.id, name: me.name, email: me.email, role: me.role }))
      .catch(() => setToken(null))
      .finally(() => setChecking(false));
  }, []);

  useEffect(() => {
    function handlePopState() {
      setView(viewFromUrl());
    }
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  useEffect(() => {
    if (user && !canView(view, user.role)) {
      setView("overview");
      rememberView("overview", "replace");
    }
  }, [user, view]);

  async function signIn(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await api.login(email, password);
      setToken(result.access_token);
      setUser(result.user);
      setPassword("");
    } catch (failure) {
      setError((failure as Error).message);
    } finally {
      setBusy(false);
    }
  }

  function selectView(next: View) {
    setView(next);
    rememberView(next);
  }

  function selectTheme(next: Theme) {
    rememberTheme(next);
    setTheme(next);
  }

  if (checking) {
    return (
      <div className="login-view">
        <Loading label="Restoring session" />
      </div>
    );
  }

  if (!user) {
    if (view === "privacy" || view === "terms") {
      return (
        <main className="login-view">
          <div className="public-shell">
            <header className="public-nav">
              <button
                type="button"
                className="secondary small"
                onClick={() => selectView("overview")}
              >
                Back to Sign in
              </button>
            </header>
            {view === "privacy" ? <PrivacyPolicy /> : <TermsAndConditions />}
          </div>
          <footer className="login-foot">
            <div className="login-foot-links">
              <button type="button" className="link" onClick={() => selectView("privacy")}>Privacy Policy</button>
              <span>-</span>
              <button type="button" className="link" onClick={() => selectView("terms")}>Terms and Conditions</button>
            </div>
          </footer>
        </main>
      );
    }

    return (
      <main className="login-view">
        <div className="login-container">
          {/* Technical Platform Intro with Interactive Terminal Simulator */}
          <section className="login-intro-section">
            <div className="hero-tag">
              <IconShield size={14} />
              Defensive Cybersecurity Platform
            </div>
            <h1>Understand the Threat. Follow the Evidence.</h1>
            <p>
              An evidence-driven cybersecurity platform for threat observation, session correlation,
              campaign analysis and adaptive deception.
            </p>

            <div className="hero-terminal-wrap">
              <TerminalWindow
                title="threatpolish@sensor-node-01: live-telemetry"
                lines={[
                  { text: "threatpolish listen --port 8022 --mode adaptive", type: "cmd" },
                  { text: "[+] Deception engine ready on :8022 (HTTP) & :2222 (SSH)", type: "accent" },
                  { text: "[!] Sensor alert: incoming probe from 198.51.100.42", type: "warn" },
                  { text: "[+] Fingerprint: JA3=771,4865-4866, client='Go-http-client/1.1'", type: "output" },
                  { text: "[*] Evaluating session correlation graph (corr-1.3.0)...", type: "output" },
                  { text: "[+] Campaign candidate formed: cmp_5a9676 (conf: 0.942)", type: "accent" },
                ]}
              />
            </div>

            <div className="login-pillars">
              <div className="pillar-item">
                <strong>Cross-IP Correlation</strong>
                <span>Links sessions via multi-family behavioral specificity.</span>
              </div>
              <div className="pillar-item">
                <strong>Adaptive Deception</strong>
                <span>Engages ambiguous sources with isolated decoy profiles.</span>
              </div>
              <div className="pillar-item">
                <strong>Audited Containment</strong>
                <span>Policy-gated, expiring mitigations with rollback.</span>
              </div>
            </div>
          </section>

          {/* Clean Cybersecurity Login Card */}
          <section className="login-form-section">
            <form onSubmit={signIn} className="login-box" aria-label="sign in">
              <div className="login-box-head">
                <img className="brand-mark" src="/logo-mark.png" alt="ThreatPolish" width={44} height={44} />
                <h1>ThreatPolish</h1>
                <p>Analyst Access Portal</p>
              </div>

              <ErrorBox message={error} />

              <div className="tp-field">
                <label htmlFor="login-email" className="tp-field-label">Email</label>
                <input
                  id="login-email"
                  type="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  autoComplete="username"
                  placeholder="analyst@threatpolish.local"
                  required
                />
              </div>

              <div className="tp-field">
                <label htmlFor="login-password" className="tp-field-label">Password</label>
                <div className="tp-password-input-wrap">
                  <input
                    id="login-password"
                    type={passwordVisible ? "text" : "password"}
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
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

              <button type="submit" className="primary" disabled={busy}>
                {busy ? "Signing in..." : "Sign in"}
              </button>

              <div className="login-box-footer">
                <span>Sessions expire automatically upon token revocation.</span>
                <span className="mono text-muted">HS256 session - zero-knowledge credentials</span>
              </div>
            </form>
          </section>
        </div>

        <footer className="login-foot">
          <span>Authorized defensive use only - Evidence retained with every decision</span>
          <div className="login-foot-links">
            <button type="button" className="link" onClick={() => selectView("privacy")}>Privacy Policy</button>
            <span>-</span>
            <button type="button" className="link" onClick={() => selectView("terms")}>Terms and Conditions</button>
          </div>
        </footer>
      </main>
    );
  }

  const activeView: View = canView(view, user.role) ? view : "overview";
  const viewTitle =
    NAV.find((item) => item.key === activeView)?.label ??
    (activeView === "privacy" ? "Privacy Policy" : activeView === "terms" ? "Terms and Conditions" : "Workspace");

  return (
    <div className="app">
      <a className="skip-link" href="#main">Skip to content</a>
      <aside className="sidebar">
        <div className="brand">
          <img className="brand-mark" src="/logo-mark.png" alt="ThreatPolish" width={36} height={36} />
          <div>
            <strong>ThreatPolish</strong>
            <span className="brand-sub">Security Workspace</span>
          </div>
        </div>
        <div className="side-status">
          <span className="status-dot" />
          Evidence Engine Active
        </div>
        <nav>
          <span className="nav-label">Navigation</span>
          {NAV.filter((item) => canView(item.key, user.role)).map((item, index) => (
            <button
              key={item.key}
              type="button"
              className={activeView === item.key ? "nav-item active" : "nav-item"}
              aria-label={item.label}
              aria-current={activeView === item.key ? "page" : undefined}
              onClick={() => selectView(item.key)}
            >
              <span className="nav-index" aria-hidden="true">
                {String(index + 1).padStart(2, "0")}
              </span>
              <span className="nav-text">{item.label}</span>
              {activeView === item.key && <span className="nav-beacon" aria-hidden="true" />}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="sidebar-user">
            <span className="muted small">{user.name}</span>
            <span className="role-chip">{user.role}</span>
          </div>
          <div className="sidebar-actions">
            <button
              type="button"
              className="link small"
              onClick={() => {
                setToken(null);
                setUser(null);
              }}
            >
              Sign out
            </button>
            <span className="muted small">-</span>
            <button type="button" className="link small" onClick={() => selectView("privacy")}>
              Privacy
            </button>
            <span className="muted small">-</span>
            <button type="button" className="link small" onClick={() => selectView("terms")}>
              Terms
            </button>
          </div>
        </div>
      </aside>
      <main className="content" id="main">
        <div className="hud-ribbon">
          <span className="ribbon-path">
            ThreatPolish <span className="ribbon-sep">/</span>{" "}
            <b>{viewTitle}</b>
          </span>
          <span className="ribbon-meta">{user.role} clearance</span>
          <button
            type="button"
            className="secondary theme-toggle small"
            aria-label="Daylight theme"
            aria-pressed={theme === "daylight"}
            onClick={() => selectTheme(theme === "daylight" ? "console" : "daylight")}
          >
            {theme === "daylight" ? "Console Theme" : "Daylight Theme"}
          </button>
          <span className="ribbon-clock">{clock}</span>
        </div>
        {activeView === "overview" && (
          <Overview user={user} onOpenRetention={() => selectView("retention")} />
        )}
        {activeView === "events" && <Events />}
        {activeView === "campaigns" && <Campaigns user={user} />}
        {activeView === "deception" && <Deception user={user} />}
        {activeView === "findings" && <Findings user={user} />}
        {activeView === "crypto" && <Crypto user={user} />}
        {activeView === "responses" && <Responses user={user} />}
        {activeView === "retention" && <Retention />}
        {activeView === "admin" && <Administration />}
        {activeView === "account" && <Account user={user} />}
        {activeView === "privacy" && <PrivacyPolicy />}
        {activeView === "terms" && <TermsAndConditions />}
      </main>
    </div>
  );
}
