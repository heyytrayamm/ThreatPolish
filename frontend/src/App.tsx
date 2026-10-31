import { FormEvent, useEffect, useState } from "react";
import { api, getToken, setToken, User } from "./api";
import { applyTheme, readTheme, rememberTheme, watchHostTheme, type Theme } from "./theme";
import { ErrorBox, Loading } from "./ui";
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
  // A new entry makes the browser's back and forward buttons follow the
  // sidebar; re-clicking the current view should not add a duplicate.
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
  const [busy, setBusy] = useState(false);
  // The console ribbon runs a live clock so the workspace reads as a station
  // rather than a report.
  const [clock, setClock] = useState(utcClock);
  const [theme, setTheme] = useState<Theme>(readTheme);

  useEffect(() => {
    const timer = window.setInterval(() => setClock(utcClock()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  // With no stored switch the workspace tracks the host, including a change
  // made while the page is open.
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

  // A hand-edited or stale link must not mount a view the signed-in role
  // cannot use. Replace the entry so Back does not bounce into the same link.
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

  if (checking) return <div className="center"><Loading label="Restoring session" /></div>;

  if (!user) {
    if (view === "privacy" || view === "terms") {
      return (
        <main className="login">
          <div className="hud-scan" aria-hidden="true" />
          <div className="public-shell">
            <header className="public-nav">
              <button
                type="button"
                className="secondary"
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
              <span>·</span>
              <button type="button" className="link" onClick={() => selectView("terms")}>Terms and Conditions</button>
            </div>
          </footer>
        </main>
      );
    }

    return (
      <main className="login">
        <div className="hud-scan" aria-hidden="true" />
        <div className="login-aurora" aria-hidden="true" />
        <section className="login-shell">
          <div className="login-intro">
            <span className="eyebrow">Analyst workspace</span>
            <h1>See the campaign behind the noise.</h1>
            <p>
              ThreatPolish correlates decoy and assessment telemetry across
              addresses, shows the evidence behind every link, and asks for more
              observation only when the answer is genuinely uncertain.
            </p>
            <ul className="login-points">
              <li>Cross-IP correlation with auditable evidence and contradictions</li>
              <li>Adaptive decoys that observe without inventing evidence</li>
              <li>Response actions with approval, expiry and rollback</li>
            </ul>
            <div className="login-orbit" aria-hidden="true">
              <span />
              <span />
              <span />
            </div>
          </div>
          <form onSubmit={signIn} className="login-card" aria-label="sign in">
            <div className="login-card-head">
              <img className="brand-mark brand-logo" src="/logo-mark.png" alt="" width={44} height={44} />
              <div>
                <strong>ThreatPolish</strong>
                <span className="muted small">Analyst access</span>
              </div>
            </div>
            <ErrorBox message={error} />
            <label>
              Email
              <input
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                autoComplete="username"
                required
              />
            </label>
            <label>
              Password
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="current-password"
                required
              />
            </label>
            <button type="submit" disabled={busy}>
              {busy ? "Signing in\u2026" : "Sign in"}
            </button>
            <p className="muted small">
              Sessions expire automatically. Contact an administrator if you do not have an account.
            </p>
            <div className="login-card-meta">
              <span>HS256 session</span>
              <span>every decision retained</span>
            </div>
          </form>
        </section>
        <footer className="login-foot">
          <span>Authorized defensive use only · Evidence retained with every decision</span>
          <div className="login-foot-links">
            <button type="button" className="link" onClick={() => selectView("privacy")}>Privacy Policy</button>
            <span>·</span>
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
      <div className="hud-scan" aria-hidden="true" />
      <a className="skip-link" href="#main">Skip to content</a>
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-sigil">
            <img className="brand-mark brand-logo" src="/logo-mark.png" alt="" width={42} height={42} />
          </span>
          <div>
            <strong>ThreatPolish</strong>
            <span className="brand-sub">Security workspace</span>
          </div>
        </div>
        <div className="side-status">
          <span className="status-dot" />
          Evidence engine
          <span className="signal-bars" aria-hidden="true">
            <i />
            <i />
            <i />
            <i />
          </span>
        </div>
        <nav>
          <span className="nav-label">Workspace</span>
          {NAV.filter((item) => canView(item.key, user.role)).map((item, index) => (
            <button
              key={item.key}
              type="button"
              className={activeView === item.key ? "nav-item active" : "nav-item"}
              // The rail index is drawn from markup rather than generated
              // content so it never joins the button's accessible name.
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
              className="link"
              onClick={() => {
                setToken(null);
                setUser(null);
              }}
            >
              Sign out
            </button>
            <span className="muted small">·</span>
            <button type="button" className="link small" onClick={() => selectView("privacy")}>
              Privacy
            </button>
            <span className="muted small">·</span>
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
            className="secondary theme-toggle"
            // A fixed label keeps the control's name stable whatever the
            // pressed state says.
            aria-label="Daylight theme"
            aria-pressed={theme === "daylight"}
            onClick={() => selectTheme(theme === "daylight" ? "console" : "daylight")}
          >
            Daylight
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
