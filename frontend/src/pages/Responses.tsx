import { useState } from "react";
import { api, User } from "../api";
import { Badge, Card, Empty, ErrorBox, Field, formatTime, Loading, can, useAsync } from "../ui";

export default function Responses({ user }: { user: User }) {
  const [tick, setTick] = useState(0);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({
    action: "alert",
    target: "",
    confidence: "0.9",
    severity: "high",
    risk_level: "high",
    risk_score: "75",
    ttl_minutes: "30",
  });

  const responses = useAsync(() => api.responses(), [tick]);
  const policy = useAsync(() => api.policies(), [tick]);

  function update(key: keyof typeof form, value: string) {
    setForm((previous) => ({ ...previous, [key]: value }));
  }

  async function submit() {
    setBusy(true);
    setNotice(null);
    try {
      const record = await api.createResponse({
        action: form.action,
        target: form.target,
        confidence: Number(form.confidence),
        severity: form.severity,
        risk_level: form.risk_level,
        risk_score: Number(form.risk_score),
        ttl_minutes: Number(form.ttl_minutes),
        reason: "Requested from dashboard",
      });
      setNotice(`Response ${record.id} is ${record.status}.`);
      setTick((value) => value + 1);
    } catch (error) {
      setNotice((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function act(kind: "approve" | "rollback", id: string) {
    setBusy(true);
    setNotice(null);
    try {
      if (kind === "approve") await api.approveResponse(id);
      else await api.rollbackResponse(id);
      setNotice(`Response ${id} ${kind === "approve" ? "approved" : "rolled back"}.`);
      setTick((value) => value + 1);
    } catch (error) {
      setNotice((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function disableAll() {
    setBusy(true);
    try {
      const result = await api.disableResponses();
      setNotice(`Emergency disable complete: ${result.rolled_back} rule(s) rolled back.`);
      setTick((value) => value + 1);
    } catch (error) {
      setNotice((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Responses</h1>
          <p className="muted">Policy-controlled containment. Nothing is enforced on weak evidence.</p>
        </div>
        {user.role === "admin" && (
          <button className="danger" onClick={disableAll} disabled={busy}>
            Emergency disable all
          </button>
        )}
      </header>

      <ErrorBox message={responses.error ?? policy.error} />
      {notice && <div className="notice">{notice}</div>}

      <div className="grid two">
        <Card title="Policy">
          {policy.loading && <Loading />}
          {policy.data && (
            <div className="stack">
              <div className="kv"><span>Version</span><strong>{policy.data.version}</strong></div>
              <div className="kv"><span>Enforcement adapter</span><strong>{policy.data.adapter.name}</strong></div>
              <div className="kv"><span>Enforced</span><strong>{policy.data.adapter.enforced ? "yes" : "no (records intent only)"}</strong></div>
              <div className="kv"><span>Rules</span><strong>{policy.data.rules.length}</strong></div>
              <p className="muted small">
                Applying a rate limit needs risk ≥ 60, confidence ≥ 0.85, an observed source address and
                administrator approval. Every rule expires and can be rolled back.
              </p>
            </div>
          )}
        </Card>

        <Card title="Request a response">
          <div className="grid two compact-grid">
            <Field label="Action">
              <select value={form.action} onChange={(event) => update("action", event.target.value)}>
                <option value="alert">alert</option>
                <option value="request_evidence">request evidence</option>
                <option value="recommend_rate_limit">recommend rate limit</option>
                <option value="apply_rate_limit">apply rate limit</option>
                <option value="escalate">escalate</option>
              </select>
            </Field>
            <Field label="Target">
              <input value={form.target} onChange={(event) => update("target", event.target.value)} placeholder="203.0.113.10" />
            </Field>
            <Field label="Confidence (0–1)">
              <input value={form.confidence} onChange={(event) => update("confidence", event.target.value)} />
            </Field>
            <Field label="Severity">
              <select value={form.severity} onChange={(event) => update("severity", event.target.value)}>
                <option value="info">info</option><option value="low">low</option>
                <option value="medium">medium</option><option value="high">high</option>
                <option value="critical">critical</option>
              </select>
            </Field>
            <Field label="Risk level">
              <select value={form.risk_level} onChange={(event) => update("risk_level", event.target.value)}>
                <option value="info">info</option><option value="low">low</option>
                <option value="medium">medium</option><option value="high">high</option>
                <option value="critical">critical</option>
              </select>
            </Field>
            <Field label="Risk score">
              <input value={form.risk_score} onChange={(event) => update("risk_score", event.target.value)} />
            </Field>
          </div>
          <button onClick={submit} disabled={busy || !can(user.role, "analyse")}>
            Submit request
          </button>
        </Card>
      </div>

      <Card title="Response history">
        {responses.loading && <Loading />}
        {responses.data && responses.data.items.length === 0 && <Empty>No responses recorded.</Empty>}
        {responses.data && responses.data.items.length > 0 && (
          <table>
            <thead>
              <tr><th>Created</th><th>Action</th><th>Target</th><th>Status</th><th>Policy</th><th>Expires</th><th /></tr>
            </thead>
            <tbody>
              {responses.data.items.map((record) => (
                <tr key={record.id}>
                  <td>{formatTime(record.created_at)}</td>
                  <td>{record.action}</td>
                  <td className="mono">{record.target}</td>
                  <td><Badge value={record.status} kind="status" /></td>
                  <td className="mono small">{record.policy_id}</td>
                  <td>{formatTime(record.expires_at)}</td>
                  <td>
                    {user.role === "admin" && record.status === "pending_approval" && (
                      <button className="secondary" onClick={() => act("approve", record.id)} disabled={busy}>
                        Approve
                      </button>
                    )}
                    {user.role === "admin" && record.status === "applied" && (
                      <button className="secondary" onClick={() => act("rollback", record.id)} disabled={busy}>
                        Roll back
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
