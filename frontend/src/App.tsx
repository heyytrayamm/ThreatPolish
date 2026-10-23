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

type View = "overview" | "events" | "campaigns" | "deception" | "findings" | "crypto" | "responses" | "admin";

const NAV: { key: View; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "events", label: "Events" },
  { key: "campaigns", label: "Campaigns" },
  { key: "deception", label: "Deception" },
  { key: "findings", label: "Web findings" },
  { key: "crypto", label: "Asset risk" },
  { key: "responses", label: "Responses" },
  { key: "admin", label: "Administration" },
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
        <form onSubmit={signIn} className="login-card">
          <h1>ThreatPolish</h1>
          <p className="muted">Evidence-guided campaign correlation</p>
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
      </main>
    );
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">TP</span>
          <div>
            <strong>ThreatPolish</strong>
            <span className="muted small">{user.role}</span>
          </div>
        </div>
        <nav>
          {NAV.filter((item) => item.key !== "admin" || user.role === "admin").map((item) => (
            <button
              key={item.key}
              className={view === item.key ? "nav-item active" : "nav-item"}
              onClick={() => setView(item.key)}
            >
              {item.label}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="muted small">{user.name}</div>
          <button
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
      <main className="content">
        {view === "overview" && <Overview user={user} />}
        {view === "events" && <Events />}
        {view === "campaigns" && <Campaigns user={user} />}
        {view === "deception" && <Deception user={user} />}
        {view === "findings" && <Findings user={user} />}
        {view === "crypto" && <Crypto user={user} />}
        {view === "responses" && <Responses user={user} />}
        {view === "admin" && <Administration />}
      </main>
    </div>
  );
}
