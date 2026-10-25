import { useState } from "react";
import { api, RetentionRun } from "../api";
import { Card, ErrorBox, Field, Loading, formatTime, useAsync } from "../ui";

function backlog(run: RetentionRun): number {
  return run.events_expired + run.retired_edges + run.stale_observations;
}

function removed(run: RetentionRun): number {
  return (
    run.events_removed +
    run.edges_removed +
    run.observations_removed +
    run.nodes_removed
  );
}

export function RetentionPanel({
  canRun = false,
  onChange,
}: {
  canRun?: boolean;
  onChange?: () => void;
}) {
  const [tick, setTick] = useState(0);
  const [notice, setNotice] = useState<string | null>(null);
  const [retentionBusy, setRetentionBusy] = useState(false);
  const [exportBusy, setExportBusy] = useState(false);
  const [historyFrom, setHistoryFrom] = useState("");
  const [historyTo, setHistoryTo] = useState("");
  const [range, setRange] = useState({ since: "", until: "" });

  const retention = useAsync(
    () =>
      api.retention({
        since: range.since || undefined,
        until: range.until || undefined,
      }),
    [tick, range.since, range.until],
  );
  const filterActive = Boolean(range.since || range.until);
  const filterInvalid = Boolean(historyFrom && historyTo && historyFrom > historyTo);
  const draftsMatchRange =
    (historyFrom === range.since || historyFrom === range.since.slice(0, 10)) &&
    (historyTo === range.until || historyTo === range.until.slice(0, 10));
  // The API returns the newest run first; a chart reads left to right.
  const retentionHistory = [...(retention.data?.history ?? [])].reverse();
  const maxBacklog = Math.max(1, ...retentionHistory.map(backlog));

  function applyRange() {
    if (filterInvalid) return;
    setRange({ since: historyFrom, until: historyTo });
  }

  function applyPreset(hours: number) {
    const until = new Date();
    const since = new Date(until.getTime() - hours * 3_600_000);
    setHistoryFrom(since.toISOString().slice(0, 10));
    setHistoryTo(until.toISOString().slice(0, 10));
    setRange({ since: since.toISOString(), until: until.toISOString() });
  }

  function clearRange() {
    setHistoryFrom("");
    setHistoryTo("");
    setRange({ since: "", until: "" });
  }

  async function runRetentionNow() {
    if (
      !window.confirm(
        "Run retention now? Expired events and graph evidence past the configured horizons will be deleted.",
      )
    ) {
      return;
    }
    setRetentionBusy(true);
    setNotice(null);
    try {
      const result = await api.runRetention();
      const graphChanges =
        result.graph.edges + result.graph.observations + result.graph.nodes;
      setNotice(
        `Retention run ${result.run_id} removed ${result.events.events} events and ` +
          `${graphChanges} graph records.`,
      );
      setTick((value) => value + 1);
      onChange?.();
    } catch (error) {
      setNotice((error as Error).message);
    } finally {
      setRetentionBusy(false);
    }
  }

  async function exportRetention() {
    if (!retention.data) return;
    setExportBusy(true);
    setNotice(null);
    try {
      const limit = Math.max(1, Math.min(retention.data.history_total, 1000));
      const csv = await api.retentionHistoryCsv({
        limit,
        since: range.since || undefined,
        until: range.until || undefined,
      });
      const url = URL.createObjectURL(csv);
      const link = document.createElement("a");
      link.href = url;
      link.download = `threatpolish-retention-${new Date().toISOString().slice(0, 10)}.csv`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setNotice("Retention history exported as CSV.");
    } catch (error) {
      setNotice((error as Error).message);
    } finally {
      setExportBusy(false);
    }
  }

  return (
    <Card
      title="Retention"
      actions={
        <div className="row">
          <button
            type="button"
            className="secondary small"
            disabled={exportBusy || retentionHistory.length === 0}
            onClick={exportRetention}
          >
            {exportBusy ? "Exporting…" : "Export CSV"}
          </button>
          {canRun && (
            <button
              type="button"
              className="secondary small"
              disabled={retentionBusy}
              onClick={runRetentionNow}
            >
              {retentionBusy ? "Running…" : "Run retention now"}
            </button>
          )}
          <button type="button" className="link" onClick={() => setTick((value) => value + 1)}>
            Refresh
          </button>
        </div>
      }
    >
      <ErrorBox message={retention.error} />
      {notice && <div className="notice">{notice}</div>}
      {retention.loading && <Loading />}
      {retention.data && (
        <>
          <p className="small">
            <span className={retention.data.overdue ? "bad" : "ok"}>
              {retention.data.overdue ? "overdue" : "current"}
            </span>{" "}
            {retention.data.overdue
              ? `Backlog has waited longer than the ${retention.data.grace_days}-day grace window. Check the retention schedule.`
              : "Within the grace window; the scheduled run will clear the backlog."}
          </p>
          <table>
            <tbody>
              <tr>
                <th>Events</th>
                <td>
                  {retention.data.events.total} stored · {retention.data.events.expired} past the{" "}
                  {retention.data.events.retention_days}-day horizon
                </td>
              </tr>
              <tr>
                <th>Oldest event</th>
                <td>{formatTime(retention.data.events.oldest_occurred_at)}</td>
              </tr>
              <tr>
                <th>Graph</th>
                <td>
                  {retention.data.graph.nodes} nodes · {retention.data.graph.edges} edges
                </td>
              </tr>
              <tr>
                <th>Pending graph work</th>
                <td>
                  {retention.data.graph.retired_edges} retired edges ·{" "}
                  {retention.data.graph.stale_observations} stale observations ·{" "}
                  {retention.data.graph.orphan_nodes} orphan nodes
                </td>
              </tr>
              <tr>
                <th>Graph horizon</th>
                <td>{retention.data.graph.retention_days} days</td>
              </tr>
            </tbody>
          </table>
          <div className="filters">
            <Field label="Runs from (UTC)">
              <input
                type="date"
                value={historyFrom}
                max={historyTo || undefined}
                onChange={(event) => setHistoryFrom(event.target.value)}
              />
            </Field>
            <Field label="Runs to (UTC)">
              <input
                type="date"
                value={historyTo}
                min={historyFrom || undefined}
                onChange={(event) => setHistoryTo(event.target.value)}
              />
            </Field>
            <button
              type="button"
              className="secondary"
              disabled={filterInvalid || (!historyFrom && !historyTo) || draftsMatchRange}
              onClick={applyRange}
            >
              Apply
            </button>
            {filterActive && (
              <button type="button" className="link" onClick={clearRange}>
                Clear
              </button>
            )}
            <span className="muted small">Quick range:</span>
            <button type="button" className="secondary" onClick={() => applyPreset(24)}>
              24 hours
            </button>
            <button type="button" className="secondary" onClick={() => applyPreset(24 * 7)}>
              7 days
            </button>
            <button type="button" className="secondary" onClick={() => applyPreset(24 * 30)}>
              30 days
            </button>
          </div>
          <p className="muted small">
            {filterInvalid
              ? "The start date must not be after the end date."
              : "Run history filters use UTC dates; the backlog above always covers the whole deployment."}
          </p>
          {retentionHistory.length > 0 && (
            <>
              <h3>Backlog before each run</h3>
              <svg
                className="bars"
                viewBox="0 0 620 120"
                role="img"
                aria-label="Retention backlog before each run"
              >
                <line x1={10} y1={100} x2={610} y2={100} className="bar-axis" />
                {retentionHistory.map((run, index) => {
                  const slot = 600 / retentionHistory.length;
                  const width = Math.max(2, Math.min(44, slot - 4));
                  const height = (backlog(run) / maxBacklog) * 90;
                  const x = 10 + index * slot + (slot - width) / 2;
                  return (
                    <g key={run.id}>
                      <rect
                        x={x}
                        y={100 - height}
                        width={width}
                        height={height}
                        rx={2}
                        className="bar"
                      />
                      <title>
                        {`${formatTime(run.ran_at)} — ${backlog(run)} items (${run.trigger})`}
                      </title>
                    </g>
                  );
                })}
              </svg>
              <p className="muted small">
                Expired events plus retired edges and stale observations seen before the last{" "}
                {retentionHistory.length} runs. Graph size now: {retention.data.graph.nodes} nodes,{" "}
                {retention.data.graph.edges} edges.
              </p>
              <h3>Recent runs</h3>
              <p className="muted small">
                {retention.data.history_total > retentionHistory.length
                  ? `Showing the last ${retentionHistory.length} of ${retention.data.history_total} ${
                      filterActive ? "matching" : "recorded"
                    } runs. Export includes up to 1,000 ${
                      filterActive ? "matching" : "recorded"
                    } runs.`
                  : `${retention.data.history_total} ${
                      filterActive ? "matching" : "recorded"
                    } run${retention.data.history_total === 1 ? "" : "s"}.`}
              </p>
              <table>
                <thead>
                  <tr>
                    <th>Ran</th><th>Trigger</th><th>Backlog</th><th>Removed</th>
                    <th>Duration</th><th>State</th>
                  </tr>
                </thead>
                <tbody>
                  {retention.data.history.map((run) => (
                    <tr key={run.id}>
                      <td>{formatTime(run.ran_at)}</td>
                      <td>{run.trigger}</td>
                      <td>{backlog(run)}</td>
                      <td>{removed(run)}</td>
                      <td>{run.duration_ms} ms</td>
                      <td>
                        <span className={run.overdue ? "bad" : "ok"}>
                          {run.overdue ? "overdue" : "current"}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
          {retentionHistory.length === 0 && (
            <p className="muted small">
              {filterActive
                ? "No retention runs match this date range."
                : "No retention run has been recorded yet. The scheduled service writes one on each run."}
            </p>
          )}
        </>
      )}
    </Card>
  );
}
