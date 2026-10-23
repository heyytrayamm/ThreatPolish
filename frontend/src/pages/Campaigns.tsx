import { useState } from "react";
import { api, Campaign, CampaignDetail, GraphView, User } from "../api";
import EvidenceGraph from "../components/EvidenceGraph";
import { Badge, Card, Empty, ErrorBox, formatTime, JsonBlock, Loading, can, shortId, useAsync } from "../ui";

export default function Campaigns({ user }: { user: User }) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const [notice, setNotice] = useState<string | null>(null);

  const list = useAsync(() => api.campaigns(), [tick]);
  const graph = useAsync(() => api.graph(72), [tick]);
  const detail = useAsync<CampaignDetail | null>(
    () => (selectedId ? api.campaign(selectedId) : Promise.resolve(null)),
    [selectedId, tick],
  );

  async function sendFeedback(label: string) {
    if (!selectedId) return;
    try {
      await api.feedback(selectedId, label);
      setNotice(`Feedback recorded: ${label}.`);
      setTick((value) => value + 1);
    } catch (error) {
      setNotice((error as Error).message);
    }
  }

  async function planInvestigation() {
    if (!selectedId) return;
    try {
      const plan = await api.planInvestigation({ campaign_id: selectedId });
      setNotice(
        `Investigation ${plan.id as string} planned with profile ${String(plan.profile ?? "none")}. ` +
          `Observable evidence: ${(plan.observable_evidence as string[] | undefined)?.join(", ") || "none"}.`,
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
          <h1>Campaigns</h1>
          <p className="muted">
            Relationship hypotheses derived from evidence. Confidence is not an attribution.
          </p>
        </div>
      </header>

      <ErrorBox message={list.error ?? detail.error ?? graph.error} />
      {notice && <div className="notice">{notice}</div>}

      <div className="grid sidebar-list">
        <Card title={`Candidates (${list.data?.items.length ?? 0})`}>
          {list.loading && <Loading />}
          {list.data && list.data.items.length === 0 && <Empty>No campaign candidates.</Empty>}
          <div className="list">
            {list.data?.items.map((campaign: Campaign) => (
              <button
                key={campaign.id}
                className={selectedId === campaign.id ? "list-item active" : "list-item"}
                onClick={() => setSelectedId(campaign.id)}
              >
                <div className="row space">
                  <strong>{campaign.name}</strong>
                  <Badge value={campaign.status} kind="status" />
                </div>
                <div className="muted small">
                  {campaign.member_count} sessions · {campaign.ip_count} IPs · confidence{" "}
                  {campaign.confidence.toFixed(2)}
                </div>
              </button>
            ))}
          </div>
        </Card>

        <Card title="Evidence graph (72h)">
          {graph.loading && <Loading />}
          {graph.data && <EvidenceGraph graph={graph.data as GraphView} />}
          {graph.data && <p className="muted small">{graph.data.note}</p>}
        </Card>
      </div>

      {detail.data && (
        <>
          <Card
            title={detail.data.campaign.name}
            actions={
              <div className="row">
                {can(user.role, "analyse") && (
                  <>
                    <button className="secondary" onClick={() => sendFeedback("supported")}>Supported</button>
                    <button className="secondary" onClick={() => sendFeedback("rejected")}>Rejected</button>
                    <button className="secondary" onClick={() => sendFeedback("uncertain")}>Uncertain</button>
                    <button onClick={planInvestigation}>Plan investigation</button>
                  </>
                )}
              </div>
            }
          >
            <div className="metrics">
              <div className="metric">
                <span className="muted small">Severity</span>
                <Badge value={detail.data.explanation.severity} />
              </div>
              <div className="metric">
                <span className="muted small">Confidence</span>
                <strong>{detail.data.explanation.confidence.toFixed(2)}</strong>
              </div>
              <div className="metric">
                <span className="muted small">Risk</span>
                <strong>{detail.data.explanation.risk.risk_score.toFixed(0)}</strong>
                <Badge value={detail.data.explanation.risk.risk_level} />
              </div>
              <div className="metric">
                <span className="muted small">Sessions / IPs</span>
                <strong>{detail.data.sessions.length} / {detail.data.ips.length}</strong>
              </div>
            </div>
            <p>{detail.data.explanation.what_happened}</p>
            <p className="muted">{detail.data.explanation.why_flagged}</p>
            <div className="risk-note">
              <strong>Recommended:</strong> {detail.data.explanation.risk.recommended_action}
              <p className="muted small">{detail.data.explanation.risk.caveat}</p>
            </div>
          </Card>

          <div className="grid two">
            <Card title="Sessions">
              <table>
                <thead>
                  <tr><th>Session</th><th>IPs</th><th>Events</th><th>Severity</th><th>First seen</th></tr>
                </thead>
                <tbody>
                  {detail.data.sessions.map((session) => (
                    <tr key={session.id}>
                      <td className="mono">{shortId(session.id, 22)}</td>
                      <td className="mono">{session.source_ips.join(", ")}</td>
                      <td>{session.event_count}</td>
                      <td><Badge value={session.severity_max} /></td>
                      <td>{formatTime(session.first_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>

            <Card title="Timeline">
              <ul className="timeline">
                {detail.data.explanation.timeline.map((item, index) => (
                  <li key={`${item.session}-${index}`}>
                    <span className="muted small">{formatTime(item.at)}</span>
                    <span>{item.event}</span>
                    <span className="mono small">{shortId(item.session, 18)}</span>
                  </li>
                ))}
              </ul>
            </Card>
          </div>

          <Card title="Relationship evidence">
            {detail.data.edges.map((edge) => (
              <details key={edge.id} className="evidence" open={detail.data!.edges.length === 1}>
                <summary>
                  <span className="mono">{shortId(edge.id, 18)}</span>
                  <Badge value={edge.status} kind="status" />
                  <span>confidence {edge.confidence.toFixed(2)}</span>
                </summary>
                <p>{edge.evidence.explanation}</p>
                <div className="row small muted">
                  <span>Anchors: {edge.evidence.anchors?.join(", ") || "none"}</span>
                  <span>Missing: {edge.evidence.missing_evidence?.join(", ") || "none"}</span>
                </div>
                <table>
                  <thead><tr><th>Component</th><th>Family</th><th>Score</th><th>Detail</th></tr></thead>
                  <tbody>
                    {edge.evidence.components?.map((component) => (
                      <tr key={component.name} className={component.available ? "" : "muted"}>
                        <td>{component.name}</td>
                        <td>{component.family}</td>
                        <td>{component.available ? component.score.toFixed(2) : "n/a"}</td>
                        <td>{component.detail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {edge.contradictions.length > 0 && (
                  <>
                    <h3>Contradictions</h3>
                    <JsonBlock value={edge.contradictions} />
                  </>
                )}
              </details>
            ))}
          </Card>
        </>
      )}
    </div>
  );
}
