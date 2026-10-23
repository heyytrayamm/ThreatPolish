import { useState } from "react";
import { api, User } from "../api";
import { Badge, Card, Empty, ErrorBox, Field, formatTime, Loading, can, shortId, useAsync } from "../ui";

export default function Deception({ user }: { user: User }) {
  const [tick, setTick] = useState(0);
  const [activationIp, setActivationIp] = useState("");
  const [notice, setNotice] = useState<string | null>(null);

  const profiles = useAsync(() => api.profiles(), [tick]);
  const investigations = useAsync(() => api.investigations(), [tick]);
  const events = useAsync(
    () => api.events({ module: "honeypot", limit: 20, since: new Date(Date.now() - 6 * 3600 * 1000).toISOString() }),
    [tick],
  );

  async function activate(id: string) {
    if (!activationIp.trim()) {
      setNotice("Enter the source IP to observe before activating.");
      return;
    }
    try {
      const result = await api.activateInvestigation(id, activationIp.trim());
      setNotice(`Profile ${result.profile as string} active for ${result.source_ip as string} until ${formatTime(result.expires_at as string)}.`);
      setTick((value) => value + 1);
    } catch (error) {
      setNotice((error as Error).message);
    }
  }

  async function evaluate(id: string) {
    try {
      const result = await api.evaluateInvestigation(id);
      setNotice(
        `Outcome: ${result.outcome as string} (${Number(result.confidence_before).toFixed(2)} → ` +
          `${Number(result.confidence_after).toFixed(2)}, ${result.new_events_observed as number} new events).`,
      );
      setTick((value) => value + 1);
    } catch (error) {
      setNotice((error as Error).message);
    }
  }

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Deception</h1>
          <p className="muted">Decoy profiles, captured interaction traffic and adaptive investigations.</p>
        </div>
      </header>

      <ErrorBox message={profiles.error ?? investigations.error ?? events.error} />
      {notice && <div className="notice">{notice}</div>}

      <div className="grid two">
        <Card title="Approved decoy profiles">
          {profiles.loading && <Loading />}
          {profiles.data && profiles.data.items.length === 0 && <Empty>No profiles seeded.</Empty>}
          <div className="list">
            {profiles.data?.items.map((profile) => (
              <div key={profile.id} className="list-item static">
                <div className="row space">
                  <strong>{profile.name}</strong>
                  <Badge value={profile.enabled ? "active" : "disabled"} kind="status" />
                </div>
                <div className="muted small">{profile.kind} · {profile.description}</div>
              </div>
            ))}
          </div>
          <p className="muted small">
            Profiles are declarative data only: no code execution and no outbound network access.
          </p>
        </Card>

        <Card title="Investigations">
          {investigations.loading && <Loading />}
          {investigations.data && investigations.data.items.length === 0 && (
            <Empty>No investigations planned. Open a campaign to plan one.</Empty>
          )}
          <div className="list">
            {investigations.data?.items.map((investigation) => (
              <div key={investigation.id} className="list-item static">
                <div className="row space">
                  <strong className="mono">{shortId(investigation.id, 16)}</strong>
                  <Badge value={investigation.status} kind="status" />
                </div>
                <div className="muted small">
                  profile {investigation.chosen_profile ?? "—"} · missing {investigation.missing_evidence.join(", ") || "none"}
                  {investigation.outcome ? ` · outcome ${investigation.outcome}` : ""}
                </div>
                {can(user.role, "analyse") && (
                  <div className="row wrap">
                    <input
                      placeholder="source IP"
                      value={activationIp}
                      onChange={(event) => setActivationIp(event.target.value)}
                      className="compact"
                    />
                    <button className="secondary" onClick={() => activate(investigation.id)}>Activate</button>
                    <button className="secondary" onClick={() => evaluate(investigation.id)}>Evaluate</button>
                  </div>
                )}
              </div>
            ))}
          </div>
          <Field label="Observation target IP">
            <input value={activationIp} onChange={(event) => setActivationIp(event.target.value)} placeholder="203.0.113.10" />
          </Field>
          <p className="muted small">
            Activation expires automatically. The decoy records real interactions only; adaptive observation
            cannot create evidence.
          </p>
        </Card>
      </div>

      <Card title="Recent honeypot interactions">
        {events.loading && <Loading />}
        {events.data && events.data.items.length === 0 && <Empty>No decoy traffic in the last six hours.</Empty>}
        {events.data && events.data.items.length > 0 && (
          <table>
            <thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Session</th><th>Severity</th></tr></thead>
            <tbody>
              {events.data.items.map((event) => (
                <tr key={event.id}>
                  <td>{formatTime(event.occurred_at)}</td>
                  <td className="mono">{event.event_type}</td>
                  <td className="mono">{event.source_ip ?? "—"}</td>
                  <td className="mono">{shortId(event.session_id ?? "—", 20)}</td>
                  <td><Badge value={event.severity} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
