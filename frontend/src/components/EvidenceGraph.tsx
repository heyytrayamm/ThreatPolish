import { useMemo, useState } from "react";
import { GraphView } from "../api";
import { Empty } from "../ui";

// Node and legend colours are CSS classes, not inline values: the graph has to
// be readable in both themes, and the palette belongs with the rest of the
// design tokens in styles.css.
const KINDS = ["session", "ip", "campaign", "asset", "indicator"];

// .node-label is 10px monospace; its advance is stable enough to reserve a box
// before the SVG has been laid out, which is what makes collision avoidance
// possible in a pure render pass.
const GLYPH_WIDTH = 6.05;
const LABEL_HEIGHT = 11;

interface Box {
  x1: number;
  y1: number;
  x2: number;
  y2: number;
}

interface Placed {
  x: number;
  y: number;
  anchor: "middle" | "start" | "end";
  box: Box;
}

/**
 * Keep the tail of a long label: campaign candidates share a prefix and differ
 * by the identifier at the end, so truncating from the right made every label
 * identical.
 */
function shorten(label: string, limit: number): string {
  if (label.length <= limit) return label;
  const tail = 6;
  const head = label.slice(0, limit - tail - 1);
  const boundary = head.lastIndexOf(" ");
  const prefix = boundary > 6 ? head.slice(0, boundary) : head;
  return `${prefix.trimEnd()}…${label.slice(-tail)}`;
}

function overlaps(a: Box, b: Box): boolean {
  return !(a.x2 < b.x1 || b.x2 < a.x1 || a.y2 < b.y1 || b.y2 < a.y1);
}

/**
 * Try positions in order and keep the first that stays inside the frame and
 * clear of the labels already placed.
 */
function place(
  text: string,
  x: number,
  y: number,
  radius: number,
  width: number,
  height: number,
  taken: Box[],
): Placed | null {
  const span = text.length * GLYPH_WIDTH;
  const candidates: { x: number; y: number; anchor: Placed["anchor"] }[] = [
    { x, y: y - radius - 7, anchor: "middle" },
    { x, y: y + radius + 14, anchor: "middle" },
    { x: x - radius - 6, y: y + 4, anchor: "end" },
    { x: x + radius + 6, y: y + 4, anchor: "start" },
    { x, y: y - radius - 20, anchor: "middle" },
    { x, y: y + radius + 27, anchor: "middle" },
  ];
  for (const candidate of candidates) {
    const left =
      candidate.anchor === "middle"
        ? candidate.x - span / 2
        : candidate.anchor === "end"
          ? candidate.x - span
          : candidate.x;
    const box: Box = {
      x1: left - 2,
      y1: candidate.y - LABEL_HEIGHT + 1,
      x2: left + span + 2,
      y2: candidate.y + 2,
    };
    if (box.x1 < 4 || box.x2 > width - 4 || box.y1 < 4 || box.y2 > height - 2) continue;
    if (taken.some((existing) => overlaps(box, existing))) continue;
    return { ...candidate, box };
  }
  return null;
}

function labelText(byId: Map<string, GraphView["nodes"][number]>, id: string): string {
  return byId.get(id)?.label ?? id;
}

function radiusFor(kind: string | undefined): number {
  return kind === "campaign" ? 11 : kind === "session" ? 7 : 5;
}

export default function EvidenceGraph({
  graph,
  onSelect,
}: {
  graph: GraphView;
  onSelect?: (nodeId: string) => void;
}) {
  const [hovered, setHovered] = useState<string | null>(null);

  // Node lookup is a Map: the render pass resolves every id several times, and
  // a linear scan per lookup is quadratic once a window holds hundreds of
  // nodes.
  const byId = useMemo(
    () => new Map(graph.nodes.map((node) => [node.id, node] as const)),
    [graph],
  );

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

  // Campaign labels are always visible, so they are placed first and in a
  // stable order; a hovered node gets a label only if one more free slot exists.
  const labels = useMemo(() => {
    const taken: Box[] = [];
    const items: { id: string; text: string; x: number; y: number; anchor: Placed["anchor"] }[] = [];
    const campaigns = [...layout.positions.entries()]
      .filter(([id]) => byId.get(id)?.kind === "campaign")
      .sort(([leftId, left], [rightId, right]) => left.x - right.x || left.y - right.y || leftId.localeCompare(rightId));
    for (const [id, position] of campaigns) {
      const text = shorten(labelText(byId, id), 26);
      const spot = place(text, position.x, position.y, radiusFor("campaign"), layout.width, layout.height, taken);
      if (!spot) continue;
      taken.push(spot.box);
      items.push({ id, text, x: spot.x, y: spot.y, anchor: spot.anchor });
    }
    return { items, taken };
  }, [graph, layout, byId]);

  if (graph.nodes.length === 0) {
    return <Empty>No graph nodes in this window. Run correlation after ingesting events.</Empty>;
  }

  const visible = new Set(layout.positions.keys());
  const edges = graph.edges.filter((edge) => visible.has(edge.source) && visible.has(edge.target));

  const hoveredNode = hovered ? byId.get(hovered) : undefined;
  const hoveredPosition = hovered ? layout.positions.get(hovered) : undefined;
  let hoverLabel: (Placed & { text: string }) | null = null;
  if (hoveredNode && hoveredPosition && hoveredNode.kind !== "campaign") {
    const text = shorten(hoveredNode.label, 34);
    const spot = place(
      text,
      hoveredPosition.x,
      hoveredPosition.y,
      radiusFor(hoveredNode.kind),
      layout.width,
      layout.height,
      labels.taken,
    );
    if (spot) hoverLabel = { ...spot, text };
  }

  return (
    <div className="graph-wrap">
      <div className="legend">
        {KINDS.map((kind) => (
          <span key={kind} className="legend-item">
            <span className={`dot kind-${kind}`} /> {kind}
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
          const node = byId.get(id)!;
          return (
            <g
              key={id}
              transform={`translate(${position.x},${position.y})`}
              onMouseEnter={() => setHovered(id)}
              onMouseLeave={() => setHovered(null)}
              onClick={() => onSelect?.(id)}
              className="node"
            >
              <circle r={radiusFor(node.kind)} className={`node-dot kind-${node.kind}`} />
              <title>{`${node.kind}: ${node.label}`}</title>
            </g>
          );
        })}
        {labels.items.map((item) => (
          <text
            key={`label-${item.id}`}
            x={item.x}
            y={item.y}
            textAnchor={item.anchor}
            className="node-label"
          >
            {item.text}
          </text>
        ))}
        {hoverLabel && (
          <text x={hoverLabel.x} y={hoverLabel.y} textAnchor={hoverLabel.anchor} className="node-label hover">
            {hoverLabel.text}
          </text>
        )}
      </svg>
      {hovered && <p className="muted small">Selected: {hovered}</p>}
    </div>
  );
}
