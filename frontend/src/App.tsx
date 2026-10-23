import { FormEvent, useEffect, useState } from "react";
import { api, getToken, setToken, User } from "./api";
import { ErrorBox, Loading } from "./ui";
import Overview from "./pages/Overview";
import Events from "./pages/Events";
import Campaigns from "./pages/Campaigns";
import Deception from "./pages/Deception";
import Findings from "./pages/Findings";
import Crypto from "./pages/Crypto";
import Responses from "./pages/Responses";
import Administration from "./pages/Administration";
import Account from "./pages/Account";

type View =
  | "overview"
  | "events"
  | "campaigns"
  | "deception"
  | "findings"
  | "crypto"
  | "responses"
  | "admin"
  | "account";

const NAV: { key: View; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "events", label: "Events" },
  { key: "campaigns", label: "Campaigns" },
  { key: "deception", label: "Deception" },
  { key: "findings", label: "Web findings" },
  { key: "crypto", label: "Asset risk" },
  { key: "responses", label: "Responses" },
  { key: "admin", label: "Administration" },
  { key: "account", label: "Account" },
];

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [checking, setChecking] = useState(Boolean(getToken()));
  const [view, setView] = useState<View>("overview");
  const [error, setError] = useState<string | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!getToken()) return;
    api
      .me()
      .then((me) => setUser({ id: me.id, name: me.name, email: me.email, role: me.role }))
      .catch(() => setToken(null))
      .finally(() => setChecking(false));
  }, []);

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

  if (checking) return <div className="center"><Loading label="Restoring session" /></div>;

  if (!user) {
    return (
      <main className="login">
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
              {busy ? "Signing in…" : "Sign in"}
            </button>
            <p className="muted small">
              Sessions expire automatically. Contact an administrator if you do not have an account.
            </p>
          </form>
        </section>
        <footer className="login-foot">Authorized defensive use only · Evidence retained with every decision</footer>
      </main>
    );
  }

  return (
    <div className="app">
      <a className="skip-link" href="#main">Skip to content</a>
      <aside className="sidebar">
        <div className="brand">
          <img className="brand-mark brand-logo" src="/logo-mark.png" alt="" width={40} height={40} />
          <div>
            <strong>ThreatPolish</strong>
            <span className="brand-sub">Security workspace</span>
          </div>
        </div>
        <div className="side-status">
          <span className="status-dot" />
          Evidence engine
        </div>
        <nav>
          <span className="nav-label">Workspace</span>
          {NAV.filter((item) => item.key !== "admin" || user.role === "admin").map((item) => (
            <button
              key={item.key}
              type="button"
              className={view === item.key ? "nav-item active" : "nav-item"}
              aria-current={view === item.key ? "page" : undefined}
              onClick={() => setView(item.key)}
            >
              {item.label}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="sidebar-user">
            <span className="muted small">{user.name}</span>
            <span className="role-chip">{user.role}</span>
          </div>
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
        </div>
      </aside>
      <main className="content" id="main">
        {view === "overview" && <Overview user={user} />}
        {view === "events" && <Events />}
        {view === "campaigns" && <Campaigns user={user} />}
        {view === "deception" && <Deception user={user} />}
        {view === "findings" && <Findings user={user} />}
        {view === "crypto" && <Crypto user={user} />}
        {view === "responses" && <Responses user={user} />}
        {view === "admin" && <Administration />}
        {view === "account" && <Account user={user} />}
      </main>
    </div>
  );
}
