import { FormEvent, useState } from "react";
import { api, setToken, User } from "../api";
import { SessionTable } from "../components/SessionTable";
import { Card, ErrorBox, Field, Loading, useAsync } from "../ui";

export default function Account({ user }: { user: User }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  const sessions = useAsync(() => api.sessions(), [tick]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setNotice(null);
    if (next.length < 10) {
      setError("New password must be at least 10 characters.");
      return;
    }
    if (next !== confirm) {
      setError("The two new password entries do not match.");
      return;
    }
    setBusy(true);
    try {
      const result = await api.changePassword(current, next);
      // The API revokes every token issued before the change, including the one
      // this request carried, and returns a replacement for the current tab.
      setToken(result.access_token);
      setCurrent("");
      setNext("");
      setConfirm("");
      setNotice("Password changed. Every other session was signed out.");
      setTick((value) => value + 1);
    } catch (failure) {
      setError((failure as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Account</h1>
          <p className="muted">Your identity, credential and recent session activity.</p>
        </div>
      </header>

      {notice && <div className="notice">{notice}</div>}
      <ErrorBox message={error ?? sessions.error} />

      <div className="grid two">
        <Card title="Identity">
          <div className="stack">
            <div className="kv"><span>Name</span><strong>{user.name}</strong></div>
            <div className="kv"><span>Email</span><strong>{user.email}</strong></div>
            <div className="kv"><span>Role</span><strong>{user.role}</strong></div>
            <p className="muted small">
              Sessions expire automatically. Changing the password signs out every other session;
              an administrator can also revoke all sessions when a token is suspected stolen.
            </p>
          </div>
        </Card>

        <Card title="Change password">
          <form onSubmit={submit} className="stack">
            <Field label="Current password">
              <input
                type="password"
                value={current}
                onChange={(event) => setCurrent(event.target.value)}
                autoComplete="current-password"
                required
              />
            </Field>
            <Field label="New password">
              <input
                type="password"
                value={next}
                onChange={(event) => setNext(event.target.value)}
                autoComplete="new-password"
                minLength={10}
                required
              />
            </Field>
            <Field label="Confirm new password">
              <input
                type="password"
                value={confirm}
                onChange={(event) => setConfirm(event.target.value)}
                autoComplete="new-password"
                minLength={10}
                required
              />
            </Field>
            <button type="submit" disabled={busy}>
              {busy ? "Saving…" : "Change password"}
            </button>
          </form>
        </Card>
      </div>

      <Card title="Recent sessions">
        {sessions.loading && <Loading />}
        {sessions.data && <SessionTable history={sessions.data} />}
      </Card>
    </div>
  );
}
