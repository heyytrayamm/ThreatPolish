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
          <span className="eyebrow">Relationship hypotheses</span>
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
                <span className="list-meter" aria-hidden="true">
                  <span
                    style={{
                      width: `${Math.round(Math.max(0, Math.min(1, campaign.confidence)) * 100)}%`,
                    }}
                  />
                </span>
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

      {detail.data && detail.data.campaign.id === selectedId && (
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

          <EvidenceMatrix detail={detail.data} />

          <KillChain coverage={detail.data.kill_chain} />

          <EvidencePlan plan={detail.data.evidence_plan} />

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

const MATRIX_SESSIONS = 12;
const FAMILY_ORDER = ["behavior", "targeting", "timing", "identity", "intel", "toolchain"];

// Matrix headers only have room for a few characters. Keep the trailing
// components of the identifier, which vary, and let the tooltip carry the rest.
function sessionLabel(id: string): string {
  const parts = id.split("-");
  return parts.length > 1 ? parts.slice(-2).join("-") : id.slice(-6);
}

function EvidenceMatrix({ detail }: { detail: CampaignDetail }) {
  // A full campaign can contain hundreds of sessions. The matrix is a reading
  // aid, so it shows the earliest members and states how many were omitted;
  // the complete pair evidence remains in the edge list below.
  const sessions = detail.sessions.slice(0, MATRIX_SESSIONS);
  const byPair = new Map<string, CampaignDetail["edges"][number]>();
  for (const edge of detail.edges) {
    const left = edge.source.replace(/^session:/, "");
    const right = edge.target.replace(/^session:/, "");
    byPair.set(`${left}|${right}`, edge);
    byPair.set(`${right}|${left}`, edge);
  }
  // The API returns only edges that currently support the campaign, so every
  // cell here is asserted evidence; hypotheses live in the graph view instead.
  const linked = detail.edges.filter((edge) => edge.status === "active");
  const meanConfidence = linked.length
    ? linked.reduce((total, edge) => total + edge.confidence, 0) / linked.length
    : 0;
  const familyTotals = new Map<string, { total: number; count: number }>();
  for (const edge of linked) {
    for (const component of edge.evidence.components ?? []) {
      if (!component.available) continue;
      const current = familyTotals.get(component.family) ?? { total: 0, count: 0 };
      current.total += component.score;
      current.count += 1;
      familyTotals.set(component.family, current);
    }
  }
  const families = FAMILY_ORDER.map((name) => {
    const current = familyTotals.get(name);
    return { name, score: current ? current.total / current.count : 0 };
  });

  return (
    <Card title="Evidence matrix">
      <p className="muted small">
        Pairwise confidence for the first {sessions.length} of {detail.sessions.length}{" "}
        sessions. Bright cells are linked relationships; hollow cells are unconfirmed
        hypotheses. Every cell is backed by the component table below.
      </p>
      <div className="matrix-summary">
        <span><strong>{linked.length}</strong> linked pairs</span>
        <span><strong>{meanConfidence.toFixed(2)}</strong> mean link confidence</span>
        <span><strong>{detail.observation.observations}</strong> observations</span>
        <span>
          <strong>{detail.observation.observations_per_link ?? "–"}</strong> observations / link
        </span>
      </div>
      <div className="matrix-scroll">
        <table className="evidence-matrix" aria-label="Pairwise session evidence matrix">
          <thead>
            <tr>
              <th scope="col">session</th>
              {sessions.map((session) => (
                <th scope="col" key={session.id} title={session.id}>
                  {sessionLabel(session.id)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sessions.map((row) => (
              <tr key={row.id}>
                <th scope="row" title={row.id}>{sessionLabel(row.id)}</th>
                {sessions.map((column) => {
                  if (row.id === column.id) {
                    return <td key={column.id} className="matrix-self">·</td>;
                  }
                  const edge = byPair.get(`${row.id}|${column.id}`);
                  if (!edge) return <td key={column.id} className="matrix-none" />;
                  const strength = Math.max(0.08, Math.min(0.86, edge.confidence * 0.8));
                  return (
                    <td
                      key={column.id}
                      className="matrix-cell active"
                      style={{ background: `rgba(95, 245, 224, ${strength})` }}
                      title={`${row.id} × ${column.id} · ${edge.status} · confidence ${edge.confidence.toFixed(3)} · score ${edge.score.toFixed(3)}`}
                    >
                      {edge.confidence.toFixed(2)}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="family-profile">
        <div>
          <h3>Family contribution · linked edges</h3>
          {linked.length === 0 && <p className="muted small">No linked edge yet.</p>}
          {linked.length > 0 && (
            <ul className="family-bars">
              {families.map((family) => (
                <li key={family.name}>
                  <span>{family.name}</span>
                  <span className="family-track">
                    <span style={{ width: `${Math.round(family.score * 100)}%` }} />
                  </span>
                  <strong>{family.score.toFixed(2)}</strong>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="matrix-legend">
          <h3>Reading the grid</h3>
          <p><span className="legend-swatch linked" /> linked · confidence ≥ 0.70 with an anchor</p>
          <p><span className="legend-swatch none" /> no stored edge · below the evidence floor</p>
          <p className="muted small">
            Confidence is an evidence index, not a probability of shared identity.
            Empty cells are a finding, not missing UI: the pair did not clear the store threshold.
          </p>
          <p className="muted small">{detail.observation.note}</p>
        </div>
      </div>
    </Card>
  );
}

function KillChain({ coverage }: { coverage: CampaignDetail["kill_chain"] }) {
  const breadth = Math.round(coverage.coverage * 100);
  const weighted = Math.round(coverage.risk_weighted_coverage * 100);
  return (
    <Card title="Kill-chain coverage">
      <p className="muted small">
        Tactics evidenced by this campaign's recorded activity. Breadth counts how
        many tactics appeared; risk-weighted coverage counts how much consequence
        they carry. Neither is a prediction of intent.
      </p>
      <div className="killchain-summary">
        <span><strong>{weighted}%</strong> risk-weighted coverage</span>
        <span><strong>{coverage.observed.length}/{coverage.tactics.length}</strong> tactics observed</span>
        <span><strong>{coverage.furthest?.label ?? "none"}</strong> furthest tactic</span>
        <span><strong>{coverage.asset_criticality}</strong> asset criticality</span>
      </div>
      <div className="killchain-meter" aria-label={`${weighted}% risk-weighted coverage`}>
        <span style={{ width: `${weighted}%` }} />
      </div>
      <ol className="killchain-rail">
        {coverage.tactics.map((tactic) => (
          <li
            key={tactic.key}
            className={tactic.observed ? "observed" : "unobserved"}
            title={tactic.observed ? tactic.evidence.join(" · ") : "not observed in this campaign"}
          >
            <span className="killchain-weight">{tactic.weight}</span>
            <span className="killchain-label">{tactic.label}</span>
            <span className="killchain-meta">
              {tactic.observed ? `${tactic.session_count} session${tactic.session_count === 1 ? "" : "s"}` : "not observed"}
            </span>
          </li>
        ))}
      </ol>
      <div className="killchain-foot">
        <span className="muted small">{breadth}% breadth · weights 1–5 by consequence</span>
        <span className="muted small">{coverage.note}</span>
      </div>
    </Card>
  );
}

function EvidencePlan({ plan }: { plan: CampaignDetail["evidence_plan"] }) {
  const peak = Math.max(...plan.items.map((item) => item.weight_at_stake), 0.001);
  return (
    <Card title="Evidence acquisition plan">
      <p className="muted small">
        What the campaign could not see, ranked by how many linked pairs the gap
        weakens. Each row is a collection task an analyst can act on today.
      </p>
      {plan.items.length === 0 && (
        <p className="muted small">
          Every recorded evidence family is present on this campaign. The remaining
          uncertainty is measurement noise, not a missing source.
        </p>
      )}
      {plan.items.length > 0 && (
        <div className="plan-list">
          {plan.items.map((item) => (
            <article key={item.family} className="plan-item">
              <header>
                <strong>{item.family}</strong>
                <span className="mono small">
                  missing on {item.missing_on_edges} pair{item.missing_on_edges === 1 ? "" : "s"}
                </span>
              </header>
              <span className="plan-track">
                <span style={{ width: `${Math.round((item.weight_at_stake / peak) * 100)}%` }} />
              </span>
              <p className="muted small">
                weight at stake (summed over pairs) {item.weight_at_stake.toFixed(2)} · {item.guidance}
              </p>
              {item.components.length > 0 && (
                <p className="mono small muted">missing: {item.components.join(", ")}</p>
              )}
            </article>
          ))}
        </div>
      )}
      {plan.absent_families.length > 0 && (
        <div className="plan-absent">
          <span className="muted small">Never observed on this campaign:</span>
          {plan.absent_families.map((family) => (
            <span key={family} className="chip mono">{family}</span>
          ))}
        </div>
      )}
      <p className="muted small">{plan.note}</p>
    </Card>
  );
}
