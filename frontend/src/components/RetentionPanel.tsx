import { useEffect, useState } from "react";
import { api, RetentionRun } from "../api";
import { Card, ErrorBox, Field, Loading, formatTime, useAsync } from "../ui";

function backlog(run: RetentionRun): number {
  return run.events_expired + run.retired_edges + run.stale_observations;
}

type RetentionTrigger = "" | "manual" | "scheduled";

type RetentionRange = { since: string; until: string; trigger: RetentionTrigger };

// Matches what the filter inputs send: a UTC day or a full ISO timestamp.
const ISO_BOUNDARY =
  /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:?\d{2}))?$/;

function isIsoBoundary(value: string): boolean {
  if (!value) return true;
  if (!ISO_BOUNDARY.test(value)) return false;
  const day = value.slice(0, 10);
  if (Number(day.slice(0, 4)) < 1) return false;
  const parsedDay = new Date(`${day}T00:00:00Z`);
  return (
    !Number.isNaN(parsedDay.getTime()) &&
    parsedDay.toISOString().slice(0, 10) === day &&
    !Number.isNaN(new Date(value).getTime())
  );
}

// The API treats a bare date in ``history_until`` as the end of that UTC day.
function boundaryTime(value: string, endOfDay: boolean): number {
  if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    const clock = endOfDay ? "23:59:59.999" : "00:00:00.000";
    return new Date(`${value}T${clock}Z`).getTime();
  }
  return new Date(value).getTime();
}

function readRangeFromUrl(): { range: RetentionRange; problem: string | null } {
  const params = new URLSearchParams(window.location.search);
  const raw = {
    since: params.get("history_since")?.trim() ?? "",
    until: params.get("history_until")?.trim() ?? "",
    trigger: params.get("history_trigger")?.trim() ?? "",
  };
  const triggerValid =
    raw.trigger === "" || raw.trigger === "manual" || raw.trigger === "scheduled";
  const sinceValid = isIsoBoundary(raw.since);
  const untilValid = isIsoBoundary(raw.until);
  const invalid: string[] = [];
  if (!sinceValid) invalid.push(`start date "${raw.since}"`);
  if (!untilValid) invalid.push(`end date "${raw.until}"`);
  if (!triggerValid) invalid.push(`trigger "${raw.trigger}"`);

  if (invalid.length > 0) {
    return {
      range: { since: "", until: "", trigger: "" },
      problem:
        `The shared link has an invalid ${invalid.join(" and ")}. ` +
        "Dates must be YYYY-MM-DD or an ISO timestamp, and the trigger must be " +
        "manual or scheduled. Showing all recorded runs.",
    };
  }

  const range: RetentionRange = {
    since: raw.since,
    until: raw.until,
    trigger: raw.trigger as RetentionTrigger,
  };
  if (
    range.since &&
    range.until &&
    boundaryTime(range.since, false) > boundaryTime(range.until, true)
  ) {
    return {
      range: { since: "", until: "", trigger: range.trigger },
      problem:
        "The shared link's start date is after its end date. Ignoring the " +
        "date range.",
    };
  }
  return { range, problem: null };
}

function rememberRange(range: RetentionRange): void {
  const url = new URL(window.location.href);
  const params = url.searchParams;
  for (const [key, value] of [
    ["history_since", range.since],
    ["history_until", range.until],
    ["history_trigger", range.trigger],
  ] as const) {
    if (value) params.set(key, value);
    else params.delete(key);
  }
  window.history.replaceState(null, "", url);
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
  // Filters live in the URL so a shared link opens the same window, and a
  // reload keeps the view an analyst was looking at.
  const [initial] = useState(readRangeFromUrl);
  const [historyFrom, setHistoryFrom] = useState(initial.range.since.slice(0, 10));
  const [historyTo, setHistoryTo] = useState(initial.range.until.slice(0, 10));
  const [trigger, setTrigger] = useState<RetentionTrigger>(initial.range.trigger);
  const [range, setRange] = useState<RetentionRange>(initial.range);
  const [urlProblem, setUrlProblem] = useState<string | null>(initial.problem);

  // Drop invalid values from the address bar once they have been explained,
  // so a reload does not repeat the error or send them to the API again.
  useEffect(() => {
    if (initial.problem) rememberRange(initial.range);
  }, [initial]);

  const retention = useAsync(
    () =>
      api.retention({
        since: range.since || undefined,
        until: range.until || undefined,
        trigger: range.trigger || undefined,
      }),
    [tick, range.since, range.until, range.trigger],
  );
  const filterActive = Boolean(range.since || range.until || range.trigger);
  const filterInvalid = Boolean(historyFrom && historyTo && historyFrom > historyTo);
  const hasDrafts = Boolean(historyFrom || historyTo || trigger);
  const draftsMatchRange =
    (historyFrom === range.since || historyFrom === range.since.slice(0, 10)) &&
    (historyTo === range.until || historyTo === range.until.slice(0, 10)) &&
    trigger === range.trigger;
  // The API returns the newest run first; a chart reads left to right.
  const retentionHistory = [...(retention.data?.history ?? [])].reverse();
  const maxBacklog = Math.max(1, ...retentionHistory.map(backlog));
  const historyCounts = retention.data?.history_counts ?? { manual: 0, scheduled: 0 };

  function applyRange() {
    if (filterInvalid) return;
    const next = { since: historyFrom, until: historyTo, trigger };
    setRange(next);
    setUrlProblem(null);
    rememberRange(next);
  }

  function applyPreset(hours: number) {
    const until = new Date();
    const since = new Date(until.getTime() - hours * 3_600_000);
    setHistoryFrom(since.toISOString().slice(0, 10));
    setHistoryTo(until.toISOString().slice(0, 10));
    const next = {
      since: since.toISOString(),
      until: until.toISOString(),
      trigger,
    };
    setRange(next);
    setUrlProblem(null);
    rememberRange(next);
  }

  function clearRange() {
    setHistoryFrom("");
    setHistoryTo("");
    setTrigger("");
    const next: RetentionRange = { since: "", until: "", trigger: "" };
    setRange(next);
    setUrlProblem(null);
    rememberRange(next);
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
        trigger: range.trigger || undefined,
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
          {urlProblem && (
            <div className="error small" role="alert">
              {urlProblem}
            </div>
          )}
          <div className="filters">
            <Field label="Trigger">
              <select
                value={trigger}
                onChange={(event) =>
                  setTrigger(event.target.value as RetentionTrigger)
                }
              >
                <option value="">Any</option>
                <option value="manual">manual</option>
                <option value="scheduled">scheduled</option>
              </select>
            </Field>
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
              disabled={filterInvalid || !hasDrafts || draftsMatchRange}
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
              : "Run history filters use a trigger and UTC dates; the backlog above always covers the whole deployment."}
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
              <p className="muted small">
                {filterActive ? "Runs in the selected window" : "Recorded runs"}:{" "}
                <strong>{historyCounts.manual}</strong> manual ·{" "}
                <strong>{historyCounts.scheduled}</strong> scheduled
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
            <p className="muted small">                {filterActive
                  ? "No retention runs match these filters."
                  : "No retention run has been recorded yet. The scheduled service writes one on each run."}
            </p>
          )}
        </>
      )}
    </Card>
  );
}
