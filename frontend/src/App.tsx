import { FormEvent, useEffect, useState } from "react";
import { api, getToken, setToken, User } from "./api";
import { applyTheme, readTheme, rememberTheme, watchHostTheme, type Theme } from "./theme";
import { Loading } from "./ui";
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
import Landing from "./pages/Landing";

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
  const [topbarMenuOpen, setTopbarMenuOpen] = useState(false);

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
    setTopbarMenuOpen(false);
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
        <main className="public-shell-view">
          <div className="public-shell">
            <header className="public-nav">
              <div className="public-nav-brand">
                <img src="/logo-mark.png" alt="ThreatPolish" width={32} height={32} />
                <strong>ThreatPolish</strong>
              </div>
              <button
                type="button"
                className="secondary small"
                onClick={() => selectView("overview")}
              >
                Back to Platform
              </button>
            </header>
            <div className="public-content-wrap">
              {view === "privacy" ? <PrivacyPolicy /> : <TermsAndConditions />}
            </div>
            <footer className="public-foot">
              <div className="public-foot-links">
                <button type="button" className="link small" onClick={() => selectView("privacy")}>
                  Privacy Policy
                </button>
                <span>-</span>
                <button type="button" className="link small" onClick={() => selectView("terms")}>
                  Terms and Conditions
                </button>
                <span>-</span>
                <button type="button" className="link small" onClick={() => selectView("overview")}>
                  Console Sign In
                </button>
              </div>
            </footer>
          </div>
        </main>
      );
    }

    return (
      <Landing
        email={email}
        setEmail={setEmail}
        password={password}
        setPassword={setPassword}
        passwordVisible={passwordVisible}
        setPasswordVisible={setPasswordVisible}
        busy={busy}
        error={error}
        onSignIn={signIn}
        onOpenPrivacy={() => selectView("privacy")}
        onOpenTerms={() => selectView("terms")}
      />
    );
  }

  const activeView: View = canView(view, user.role) ? view : "overview";
  const viewTitle =
    NAV.find((item) => item.key === activeView)?.label ??
    (activeView === "privacy" ? "Privacy Policy" : activeView === "terms" ? "Terms and Conditions" : "Workspace");

  return (
    <div className="app">
      <a className="skip-link" href="#main">
        Skip to content
      </a>

      {/* Horizontal Top Navigation Bar with .sidebar class for Playwright compatibility */}
      <header className="app-topbar sidebar" role="banner">
        <div className="topbar-left">
          <div className="topbar-brand">
            <img className="brand-mark" src="/logo-mark.png" alt="ThreatPolish" width={32} height={32} />
            <div className="topbar-brand-text">
              <strong>ThreatPolish</strong>
              <span className="brand-sub">Workspace</span>
            </div>
          </div>
          <div className="side-status topbar-status" aria-hidden="true">
            <span className="status-dot" />
            <span className="topbar-status-text">Evidence Engine Active</span>
          </div>
        </div>

        <nav
          className={`topbar-nav ${topbarMenuOpen ? "topbar-nav-open" : ""}`}
          aria-label="Main Navigation"
        >
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

        <div className="topbar-right">
          <button
            type="button"
            className="secondary theme-toggle small"
            aria-label="Daylight theme"
            aria-pressed={theme === "daylight"}
            onClick={() => selectTheme(theme === "daylight" ? "console" : "daylight")}
          >
            {theme === "daylight" ? "Console Theme" : "Daylight Theme"}
          </button>

          <div className="topbar-user">
            <span className="user-name">{user.name}</span>
            <span className="role-chip">{user.role}</span>
          </div>

          <button
            type="button"
            className="link small topbar-signout"
            onClick={() => {
              setToken(null);
              setUser(null);
            }}
          >
            Sign out
          </button>

          <button
            type="button"
            className="topbar-mobile-btn"
            aria-label="Toggle navigation menu"
            onClick={() => setTopbarMenuOpen(!topbarMenuOpen)}
          >
            <svg width={20} height={20} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
              {topbarMenuOpen ? (
                <path d="M18 6 6 18M6 6l12 12" />
              ) : (
                <path d="M3 12h18M3 6h18M3 18h18" />
              )}
            </svg>
          </button>
        </div>
      </header>

      <main className="content" id="main">
        <div className="hud-ribbon">
          <span className="ribbon-path">
            ThreatPolish <span className="ribbon-sep">/</span> <b>{viewTitle}</b>
          </span>
          <span className="ribbon-meta">{user.role} clearance</span>
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
