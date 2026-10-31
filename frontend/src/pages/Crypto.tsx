import { useState } from "react";
import { api, User } from "../api";
import { Badge, Card, Empty, ErrorBox, Loading, can, formatTime, useAsync } from "../ui";

const DEFAULT_SYMBOLS = ["BTC", "ETH", "SOL", "USDT"];

export default function Crypto({ user }: { user: User }) {
  const [tick, setTick] = useState(0);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const assets = useAsync(() => api.cryptoAssets(), [tick]);

  async function refresh() {
    setBusy(true);
    setNotice(null);
    try {
      const result = await api.cryptoRefresh(DEFAULT_SYMBOLS);
      const refreshed = (result.refreshed as { symbol: string }[] | undefined) ?? [];
      setNotice(
        refreshed.length
          ? `Refreshed ${refreshed.map((item) => item.symbol).join(", ")} from ${result.provider as string}.`
          : `No refresh needed: ${(result.skipped as { symbol: string }[] | undefined)?.map((item) => item.symbol).join(", ") ?? "provider cooldown"}.`,
      );
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
          <h1>Digital-asset risk</h1>
          <p className="muted">Observed market facts are separated from inferred risk. No wallet secrets are stored.</p>
        </div>
        <button onClick={refresh} disabled={busy || !can(user.role, "analyse")}>
          {busy ? "Refreshing…" : "Refresh assets"}
        </button>
      </header>

      <ErrorBox message={assets.error} />
      {notice && <div className="notice">{notice}</div>}

      <Card title={`Assets (provider: ${assets.data?.provider ?? "-"})`}>
        {assets.loading && <Loading />}
        {assets.data && assets.data.items.length === 0 && (
          <Empty>No market observations yet. Refresh assets to fetch provider data.</Empty>
        )}
        {assets.data && assets.data.items.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Asset</th><th>Price</th><th>24h</th><th>Risk</th><th>Severity</th>
                <th>Confidence</th><th>Signals</th><th>Observed</th>
              </tr>
            </thead>
            <tbody>
              {assets.data.items.map((asset) => (
                <tr key={asset.symbol}>
                  <td><strong>{asset.symbol}</strong></td>
                  <td>{asset.observed.price_usd == null ? "-" : `$${asset.observed.price_usd.toLocaleString()}`}</td>
                  <td className={asset.observed.change_24h_pct != null && asset.observed.change_24h_pct < 0 ? "bad" : "ok"}>
                    {asset.observed.change_24h_pct == null ? "-" : `${asset.observed.change_24h_pct.toFixed(2)}%`}
                  </td>
                  <td>{asset.inferred?.score ?? "-"}</td>
                  <td>{asset.inferred ? <Badge value={asset.inferred.severity} /> : "-"}</td>
                  <td>{asset.inferred ? asset.inferred.confidence.toFixed(2) : "-"}</td>
                  <td className="small">
                    {asset.inferred?.reasons.map((reason) => reason.code).join(", ") || "none"}
                  </td>
                  <td className="small">
                    {formatTime(asset.observed.fetched_at)}
                    <div className="muted">{asset.stale ? "stale" : `${Math.round(asset.freshness_seconds / 60)}m ago`}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="muted small">
          Risk is derived from a small set of market observables with named reasons. It is not a price
          prediction, investment advice, or a claim about any wallet.
        </p>
      </Card>
    </div>
  );
}
