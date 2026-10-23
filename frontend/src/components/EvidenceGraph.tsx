import { useMemo, useState } from "react";
import { GraphView } from "../api";
import { Empty } from "../ui";

const COLORS: Record<string, string> = {
  session: "#4f8cff",
  ip: "#8b98a9",
  campaign: "#f0a23a",
  asset: "#59c3a8",
  indicator: "#d267d2",
};

export default function EvidenceGraph({
  graph,
  onSelect,
}: {
  graph: GraphView;
  onSelect?: (nodeId: string) => void;
}) {
  const [hovered, setHovered] = useState<string | null>(null);

  const layout = useMemo(() => {
    const nodes = graph.nodes.filter((node) => node.kind !== "asset" && node.kind !== "indicator");
    const positions = new Map<string, { x: number; y: number }>();
    const groups: Record<string, typeof nodes> = {};
    for (const node of nodes) {
      (groups[node.kind] ??= []).push(node);
    }
    const kinds = Object.keys(groups);
    const width = 760;
    const height = 420;
    const centerX = width / 2;
    const centerY = height / 2;
    kinds.forEach((kind, kindIndex) => {
      const radius = 70 + kindIndex * 55;
      const members = groups[kind];
      members.forEach((node, index) => {
        const angle = (2 * Math.PI * index) / Math.max(1, members.length) + kindIndex * 0.6;
        positions.set(node.id, {
          x: centerX + radius * Math.cos(angle),
          y: centerY + radius * Math.sin(angle),
        });
      });
    });
    return { positions, width, height };
  }, [graph]);

  if (graph.nodes.length === 0) {
    return <Empty>No graph nodes in this window. Run correlation after ingesting events.</Empty>;
  }

  const visible = new Set(layout.positions.keys());
  const edges = graph.edges.filter((edge) => visible.has(edge.source) && visible.has(edge.target));

  return (
    <div className="graph-wrap">
      <div className="legend">
        {Object.entries(COLORS).map(([kind, color]) => (
          <span key={kind} className="legend-item">
            <span className="dot" style={{ background: color }} /> {kind}
          </span>
        ))}
        <span className="legend-item"><span className="line" /> linked</span>
        <span className="legend-item"><span className="line dashed" /> hypothesis</span>
      </div>
      <svg viewBox={`0 0 ${layout.width} ${layout.height}`} className="graph" role="img" aria-label="Evidence relationship graph">
        {edges.map((edge) => {
          const from = layout.positions.get(edge.source)!;
          const to = layout.positions.get(edge.target)!;
          return (
            <line
              key={edge.id}
              x1={from.x}
              y1={from.y}
              x2={to.x}
              y2={to.y}
              className={edge.status === "hypothesis" ? "edge hypothesis" : "edge"}
              strokeWidth={edge.kind === "session_similarity" ? Math.max(1, edge.confidence * 4) : 1}
            >
              <title>{`${edge.kind} · confidence ${edge.confidence.toFixed(2)}${edge.explanation ? ` · ${edge.explanation}` : ""}`}</title>
            </line>
          );
        })}
        {[...layout.positions.entries()].map(([id, position]) => {
          const node = graph.nodes.find((item) => item.id === id)!;
          const radius = node.kind === "campaign" ? 11 : node.kind === "session" ? 7 : 5;
          return (
            <g
              key={id}
              transform={`translate(${position.x},${position.y})`}
              onMouseEnter={() => setHovered(id)}
              onMouseLeave={() => setHovered(null)}
              onClick={() => onSelect?.(id)}
              className="node"
            >
              <circle r={radius} fill={COLORS[node.kind] ?? "#999"} />
              {(hovered === id || node.kind === "campaign") && (
                <text y={-radius - 5} textAnchor="middle" className="node-label">
                  {node.label.length > 28 ? `${node.label.slice(0, 27)}…` : node.label}
                </text>
              )}
              <title>{`${node.kind}: ${node.label}`}</title>
            </g>
          );
        })}
      </svg>
      {hovered && <p className="muted small">Selected: {hovered}</p>}
    </div>
  );
}
