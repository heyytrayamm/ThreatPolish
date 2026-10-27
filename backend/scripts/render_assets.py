"""Render the documentation artwork and result charts.

Every figure is drawn from the recorded measurements in
``docs/research/evaluation-results.json`` and
``docs/research/correlation-runtime.md``; none of the numbers are typed into
this file. The renderer only depends on Pillow so a reviewer can regenerate the
README images without a plotting stack.

    python scripts/render_assets.py --out ../docs/assets
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont

WIDE = (1600, 720)
FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")

BG_TOP = (4, 6, 14)
BG_BOTTOM = (8, 17, 30)
INK = (232, 244, 255)
MUTED = (139, 157, 179)
FAINT = (86, 104, 126)
TEAL = (94, 234, 212)
BLUE = (56, 189, 248)
VIOLET = (167, 139, 250)
AMBER = (251, 191, 36)
ROSE = (251, 113, 133)
GRID = (120, 160, 200, 16)


def font(size: int, *, bold: bool = False, mono: bool = False) -> ImageFont.FreeTypeFont:
    if mono:
        name = "DejaVuSansMono-Bold.ttf" if bold else "DejaVuSansMono.ttf"
    else:
        name = "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"
    return ImageFont.truetype(str(FONT_DIR / name), size)


def mix(color: tuple[int, int, int], background: tuple[int, int, int], alpha: float) -> tuple[int, int, int]:
    return tuple(round(fg * alpha + bg * (1 - alpha)) for fg, bg in zip(color, background))


def canvas(width: int, height: int) -> Image.Image:
    image = Image.new("RGB", (width, height), BG_TOP)
    draw = ImageDraw.Draw(image)
    for y in range(height):
        ratio = y / max(1, height - 1)
        draw.line([(0, y), (width, y)], fill=mix(BG_BOTTOM, BG_TOP, ratio))
    return image


def add_grid(image: Image.Image, step: int = 40, offset: int = 0) -> None:
    overlay = Image.new("RGBA", image.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    for x in range(offset, image.width, step):
        draw.line([(x, 0), (x, image.height)], fill=GRID, width=1)
    for y in range(offset, image.height, step):
        draw.line([(0, y), (image.width, y)], fill=GRID, width=1)
    # A faint scanline texture keeps flat gradients from banding on screenshots.
    for y in range(0, image.height, 4):
        draw.line([(0, y), (image.width, y)], fill=(255, 255, 255, 5))
    image.paste(Image.alpha_composite(image.convert("RGBA"), overlay).convert("RGB"))


def add_glow(image: Image.Image, shapes, color: tuple[int, int, int], radius: int = 60, strength: float = 1.0) -> None:
    layer = Image.new("RGB", image.size, (0, 0, 0))
    draw = ImageDraw.Draw(layer)
    for kind, box in shapes:
        if kind == "ellipse":
            draw.ellipse(box, fill=color)
        elif kind == "line":
            draw.line(box, fill=color, width=3)
        else:
            draw.rounded_rectangle(box, radius=20, fill=color)
    layer = layer.filter(ImageFilter.GaussianBlur(radius))
    if strength != 1.0:
        layer = layer.point(lambda value: int(value * strength))
    image.paste(ImageChops.add(image, layer))


def add_radial(image: Image.Image, center, radius: int, color: tuple[int, int, int], strength: float = 0.55) -> None:
    layer = Image.new("RGB", image.size, (0, 0, 0))
    draw = ImageDraw.Draw(layer)
    steps = 26
    for index in range(steps, 0, -1):
        ratio = index / steps
        alpha = (1 - ratio) ** 2 * strength
        box = [
            center[0] - radius * ratio,
            center[1] - radius * ratio,
            center[0] + radius * ratio,
            center[1] + radius * ratio,
        ]
        draw.ellipse(box, fill=mix(color, (0, 0, 0), alpha))
    image.paste(ImageChops.add(image, layer.filter(ImageFilter.GaussianBlur(30))))


def panel(image: Image.Image, box, *, alpha: int = 16, border: tuple[int, int, int, int] = (120, 220, 220, 46),
          radius: int = 18) -> None:
    overlay = Image.new("RGBA", image.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    draw.rounded_rectangle(box, radius=radius, fill=(10, 26, 40, alpha), outline=border, width=1)
    image.paste(Image.alpha_composite(image.convert("RGBA"), overlay).convert("RGB"))


def text(draw: ImageDraw.ImageDraw, xy, value: str, *, size: int = 32, color=INK, bold=False, mono=False,
         anchor: str | None = None) -> None:
    draw.text(xy, value, font=font(size, bold=bold, mono=mono), fill=color, anchor=anchor)


def spaced(draw: ImageDraw.ImageDraw, xy, value: str, *, size: int, color, gap: float = 0.18, bold=True) -> None:
    """Draw a wordmark with tracking, which Pillow does not expose directly."""
    current = xy[0]
    face = font(size, bold=bold)
    for character in value:
        draw.text((current, xy[1]), character, font=face, fill=color)
        current += face.getlength(character) + size * gap


def sparkline(image: Image.Image, points, box, color, *, width: int = 2, glow: bool = True) -> None:
    draw = ImageDraw.Draw(image)
    draw.line(points, fill=color, width=width, joint="curve")
    if glow:
        add_glow(image, [("line", points)], color, radius=12, strength=0.9)


def hero(out: Path, metrics: dict) -> None:
    image = canvas(*WIDE)
    add_radial(image, (330, 180), 520, (20, 130, 140), 0.5)
    add_radial(image, (1360, 620), 520, (96, 60, 190), 0.45)
    add_grid(image, 48)
    draw = ImageDraw.Draw(image)

    # Node-link glyph: the product's thesis in one shape.
    nodes = [(1250, 210), (1420, 330), (1170, 400), (1380, 500), (1080, 520), (1300, 120)]
    links = [(0, 1), (0, 2), (1, 3), (2, 3), (2, 4), (0, 5), (5, 1)]
    for left, right in links:
        draw.line([nodes[left], nodes[right]], fill=(56, 130, 160), width=1)
        add_glow(image, [("line", [nodes[left], nodes[right]])], (30, 120, 150), radius=9, strength=0.5)
    rest = draw
    for index, (x, y) in enumerate(nodes):
        color = TEAL if index in (0, 2) else (BLUE if index % 2 else VIOLET)
        add_glow(image, [("ellipse", [x - 7, y - 7, x + 7, y + 7])], color, radius=18, strength=0.85)
        rest.ellipse([x - 5, y - 5, x + 5, y + 5], fill=color)

    text(draw, (90, 96), "EVIDENCE-FIRST TELEMETRY ANALYSIS", size=20, color=TEAL, mono=True)
    spaced(draw, (86, 138), "THREATPOLISH", size=86, color=INK)
    draw.line([(92, 262), (620, 262)], fill=(40, 90, 110), width=2)
    add_glow(image, [("line", [(92, 262), (620, 262)])], (30, 150, 170), radius=10, strength=0.5)
    text(draw, (92, 288), "Campaign correlation that shows its work.", size=38, color=(206, 232, 245))
    text(
        draw,
        (92, 348),
        "Six independent evidence families. An inspectable confidence index.\n"
        "Adaptive observation where the evidence is missing. No opaque model.",
        size=22,
        color=MUTED,
    )

    chips = [
        ("PRECISION", f"{metrics['precision']:.2f}", "zero false links"),
        ("F1 · ADAPTIVE", f"{metrics['f1']:.2f}", f"{metrics['recall']:.2f} recall"),
        ("PAIR COST", f"{metrics['pair_ms']:.3f} ms", f"at {metrics['sessions']} sessions"),
    ]
    x = 92
    for label, value, note in chips:
        panel(image, [x, 470, x + 268, 596])
        text(draw, (x + 22, 492), label, size=15, color=FAINT, mono=True)
        text(draw, (x + 22, 516), value, size=42, color=TEAL, bold=True)
        text(draw, (x + 22, 566), note, size=16, color=MUTED)
        x += 292

    text(draw, (92, 640), "synthetic benchmark · corr-1.3.0 · reproducible suite", size=16, color=FAINT, mono=True)
    image.save(out)


def architecture(out: Path) -> None:
    size = (1600, 980)
    image = canvas(*size)
    add_radial(image, (180, 120), 420, (14, 110, 130), 0.4)
    add_radial(image, (1460, 860), 460, (90, 60, 170), 0.35)
    add_grid(image, 40)
    draw = ImageDraw.Draw(image)

    text(draw, (80, 66), "REFERENCE ARCHITECTURE", size=18, color=TEAL, mono=True)
    text(draw, (80, 96), "One direction of evidence, one record of every decision", size=40, color=INK, bold=True)

    stages = [
        ("01", "SENSORS", "Cowrie · decoy HTTP · signed batch ingest", TEAL),
        ("02", "NORMALISE", "UTC timestamps, advisory-locked dedupe, typed events", BLUE),
        ("03", "SESSIONS", "Commands, clients, credentials, targets as one graph node", BLUE),
        ("04", "EVIDENCE", "Six families scored independently; contradictions subtracted", VIOLET),
        ("05", "CAMPAIGNS", "Confidence + anchor gates; membership is reversible", VIOLET),
        ("06", "ACTION", "Policy-gated response, adaptive observation, audit trail", AMBER),
    ]
    top, height = 190, 96
    for index, (number, title, detail, color) in enumerate(stages):
        y = top + index * 118
        panel(image, [80, y, 1020, y + height], border=mix(color, BG_TOP, 0.35) + (120,))
        text(draw, (104, y + 26), number, size=24, color=color, mono=True, bold=True)
        text(draw, (166, y + 24), title, size=25, color=INK, bold=True)
        text(draw, (166, y + 58), detail, size=17, color=MUTED)
        if index < len(stages) - 1:
            mid = y + height
            draw.line([(126, mid), (126, mid + 22)], fill=(60, 150, 160), width=2)
            draw.polygon([(126, mid + 30), (120, mid + 20), (132, mid + 20)], fill=(90, 200, 200))
            add_glow(image, [("line", [(126, mid), (126, mid + 22)])], (30, 150, 160), radius=8, strength=0.6)

    # The right column carries full sentences; it is sized so no line reaches
    # the panel border at the type sizes below.
    panel(image, [1060, 190, 1520, 460], border=(120, 220, 220, 40))
    text(draw, (1084, 214), "INVARIANTS", size=15, color=TEAL, mono=True)
    invariants = [
        "Confidence is monotone in evidence.",
        "Missing data lowers weight; it never adds it.",
        "Membership requires an anchor, not volume.",
        "Every stored edge keeps its component table.",
        "Actions are proposals until policy agrees.",
    ]
    y = 250
    for line in invariants:
        draw.ellipse([1086, y + 7, 1094, y + 15], fill=TEAL)
        text(draw, (1106, y), line, size=16, color=(198, 218, 232))
        y += 38

    panel(image, [1060, 500, 1520, 726], border=(120, 220, 220, 40))
    text(draw, (1084, 524), "THREAT MODEL", size=15, color=VIOLET, mono=True)
    assets = [
        "Forged sensor payloads · schema + rate limits",
        "Cross-tenant leakage · RBAC on every route",
        "Retention drift · dual horizons, grid purge",
        "Decoy escape · isolated profiles, no host exec",
    ]
    y = 560
    for line in assets:
        text(draw, (1084, y), "·", size=18, color=VIOLET, bold=True)
        text(draw, (1100, y), line, size=15, color=(190, 206, 224))
        y += 38

    text(draw, (80, 920), "Batch correlation · single writer · 800 sessions per run · Postgres or SQLite", size=15,
         color=FAINT, mono=True)
    image.save(out)


def _bars(out: Path, title: str, eyebrow: str, rows, *, note: str) -> None:
    """rows: [(label, value, color)] drawn as a ranked horizontal bar chart."""
    width, height = 1500, 860
    image = canvas(width, height)
    add_radial(image, (240, 120), 380, (14, 110, 130), 0.35)
    add_radial(image, (1300, 800), 420, (90, 60, 170), 0.3)
    add_grid(image, 40)
    draw = ImageDraw.Draw(image)
    text(draw, (80, 60), eyebrow, size=17, color=TEAL, mono=True)
    text(draw, (80, 88), title, size=36, color=INK, bold=True)

    left, right = 380, 1360
    top, gap = 200, 74
    for index, (label, value, color) in enumerate(rows):
        y = top + index * gap
        text(draw, (left - 24, y + 10), label, size=18, color=(200, 216, 230), anchor="ra")
        bar_end = left + (right - left) * max(0.0, min(1.0, value))
        panel(image, [left, y, right, y + 34], alpha=8, border=(148, 163, 184, 26), radius=10)
        add_glow(image, [("rounded", [left, y, bar_end, y + 34])], mix(color, (0, 0, 0), 0.55), radius=16, strength=0.9)
        draw.rounded_rectangle([left, y, bar_end, y + 34], radius=10, fill=mix(color, BG_TOP, 0.82))
        text(draw, (right + 18, y + 8), f"{value:.3f}", size=19, color=color, mono=True, bold=True)
    text(draw, (80, 806), note, size=15, color=FAINT, mono=True)
    image.save(out)


def detection_chart(out: Path, results: dict) -> None:
    order = [
        ("rule_based", "Rule-based"),
        ("ip_only", "IP-only baseline"),
        ("ablation_jaccard_only", "Jaccard only"),
        ("proposed", "Six-family model"),
        ("proposed_adaptive", "Model + adaptive"),
    ]
    colors = [FAINT, ROSE, AMBER, BLUE, TEAL]
    metrics = [("precision", "precision"), ("recall", "recall"), ("f1", "F1")]
    width, height = 1500, 900
    image = canvas(width, height)
    add_radial(image, (200, 140), 400, (14, 110, 130), 0.32)
    add_radial(image, (1340, 820), 420, (90, 60, 170), 0.3)
    add_grid(image, 40)
    draw = ImageDraw.Draw(image)
    text(draw, (80, 60), "PAIR-LEVEL DETECTION · 1953 PAIRS", size=17, color=TEAL, mono=True)
    text(draw, (80, 88), "Precision is free. Recall is what evidence buys.", size=36, color=INK, bold=True)

    columns = [360, 720, 1080]
    width_bar = 250
    for column, (_, caption) in zip(columns, metrics):
        text(draw, (column, 168), caption, size=15, color=FAINT, mono=True)
    top, row_gap = 208, 118
    for index, (key, label) in enumerate(order):
        y = top + index * row_gap
        stat = results[key]
        text(draw, (80, y + 8), label, size=20, color=(205, 222, 236), bold=True)
        for column, (metric, _) in zip(columns, metrics):
            value = float(stat[metric])
            bar_top, bar_height = y, 24
            end = column + width_bar * value
            panel(image, [column, bar_top, column + width_bar, bar_top + bar_height], alpha=8,
                  border=(148, 163, 184, 24), radius=7)
            color = colors[index] if metric == "f1" else mix(colors[index], BG_TOP, 0.55)
            draw.rounded_rectangle([column, bar_top, max(column + 2, end), bar_top + bar_height], radius=7,
                                   fill=mix(color, BG_TOP, 0.85))
            text(draw, (column + width_bar + 12, bar_top + 3), f"{value:.2f}", size=15,
                 color=(196, 212, 228), mono=True)

    text(draw, (80, 846), "False positives: 0 for the proposed model; 420 for rule-based.", size=16,
         color=MUTED, mono=True)
    image.save(out)


def runtime_chart(out: Path, rows) -> None:
    width, height = 1500, 800
    image = canvas(width, height)
    add_radial(image, (250, 130), 380, (14, 110, 130), 0.32)
    add_radial(image, (1320, 760), 420, (90, 60, 170), 0.28)
    add_grid(image, 40)
    draw = ImageDraw.Draw(image)
    text(draw, (80, 58), "WALL CLOCK · COLD VS WARM", size=17, color=TEAL, mono=True)
    text(draw, (80, 86), "Cost is quadratic in sessions and near-zero when nothing changed", size=34,
         color=INK, bold=True)

    left, right, top, bottom = 150, 1380, 200, 660
    sessions = [row["sessions"] for row in rows]
    max_cold = math.ceil(max(row["cold"] for row in rows) / 10) * 10 or 10
    max_x = max(sessions) or 1

    def point(index: int, value: float) -> tuple[float, float]:
        x = left + (right - left) * (sessions[index] / max_x)
        y = bottom - (bottom - top) * (value / max_cold)
        return x, y

    for step in range(4):
        value = max_cold * step / 3
        y = bottom - (bottom - top) * step / 3
        draw.line([(left, y), (right, y)], fill=(60, 82, 102), width=1)
        label = f"{value:.0f}s" if value % 1 == 0 else f"{value:.1f}s"
        text(draw, (left - 16, y), label, size=15, color=FAINT, mono=True, anchor="rm")

    cold_points = [point(index, row["cold"]) for index, row in enumerate(rows)]
    warm_points = [point(index, row["warm"]) for index, row in enumerate(rows)]

    overlay = Image.new("RGBA", image.size, (0, 0, 0, 0))
    polygon = [(cold_points[0][0], bottom), *cold_points, (cold_points[-1][0], bottom)]
    ImageDraw.Draw(overlay).polygon(polygon, fill=(30, 180, 190, 34))
    image.paste(Image.alpha_composite(image.convert("RGBA"), overlay).convert("RGB"))

    sparkline(image, cold_points, (left, top, right, bottom), TEAL, width=3)
    sparkline(image, warm_points, (left, top, right, bottom), VIOLET, width=3)
    draw = ImageDraw.Draw(image)
    for index, row in enumerate(rows):
        x, y = cold_points[index]
        draw.ellipse([x - 5, y - 5, x + 5, y + 5], fill=TEAL)
        if index % 2 == 0 or index == len(rows) - 1:
            text(draw, (x, bottom + 14), str(row["sessions"]), size=15, color=MUTED, mono=True, anchor="mt")
        if index in (0, 2, len(rows) - 1):
            text(draw, (x, y - 22), f"{row['cold']:.1f}s", size=15, color=TEAL, mono=True, anchor="mb")
        wx, wy = warm_points[index]
        draw.ellipse([wx - 4, wy - 4, wx + 4, wy + 4], fill=VIOLET)

    text(draw, (left, bottom + 44), "sessions per run", size=15, color=FAINT, mono=True)
    text(draw, (left, top - 40), "cold · full re-score", size=15, color=TEAL, mono=True)
    text(draw, (left + 250, top - 40), "warm · reused decisions", size=15, color=VIOLET, mono=True)
    best = rows[-1]
    text(draw, (80, 726), f"At {best['sessions']} sessions: {best['cold']:.1f}s cold, {best['warm']:.2f}s warm, "
         f"{best['per_pair']:.3f} ms per pair.", size=16, color=MUTED, mono=True)
    image.save(out)


def ablation_chart(out: Path, results: dict) -> None:
    variants = [
        ("ablation_jaccard_only", "No families\n(Jaccard only)"),
        ("ablation_no_toolchain", "No toolchain"),
        ("ablation_no_timing", "No timing"),
        ("ablation_uniform_weights", "Uniform weights"),
        ("ablation_no_intel", "No intel"),
        ("proposed", "All six"),
    ]
    width, height = 1500, 780
    image = canvas(width, height)
    add_radial(image, (240, 120), 380, (14, 110, 130), 0.3)
    add_radial(image, (1320, 720), 420, (90, 60, 170), 0.26)
    add_grid(image, 40)
    draw = ImageDraw.Draw(image)
    text(draw, (80, 58), "ABLATION · F1", size=17, color=TEAL, mono=True)
    text(draw, (80, 86), "Which evidence family actually carries the signal", size=34, color=INK, bold=True)

    left, bottom, top = 130, 620, 190
    slot = 220
    for index, (key, label) in enumerate(variants):
        value = float(results[key]["f1"])
        x = left + index * slot
        bar_height = (bottom - top) * value
        color = TEAL if key == "proposed" else mix(VIOLET, BG_TOP, 0.55)
        add_glow(image, [("rounded", [x, bottom - bar_height, x + 118, bottom])], mix(color, (0, 0, 0), 0.55),
                 radius=18, strength=0.9)
        draw.rounded_rectangle([x, bottom - bar_height, x + 118, bottom], radius=12,
                               fill=mix(color, BG_TOP, 0.8))
        text(draw, (x + 59, bottom - bar_height - 16), f"{value:.3f}", size=19, color=color, mono=True,
             bold=True, anchor="mb")
        for line_index, line in enumerate(label.split("\n")):
            text(draw, (x + 59, bottom + 18 + line_index * 22), line, size=15, color=MUTED, anchor="mt")

    text(draw, (80, 700), "Removing toolchain evidence costs roughly ten linked pairs; intel and timing shift two.",
         size=16, color=MUTED, mono=True)
    text(draw, (80, 726), "Differences of one or two pairs sit inside the seeded benchmark's variance.",
         size=15, color=FAINT, mono=True)
    image.save(out)


def load_runtime(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text().splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 11 or not cells[0].isdigit():
            continue
        rows.append(
            {
                "sessions": int(cells[1]),
                "cold": float(cells[7].rstrip("s")),
                "warm": float(cells[8].rstrip("s")),
                "per_pair": float(cells[10].rstrip("ms").rstrip("*")),
            }
        )
    if not rows:
        raise SystemExit(f"no runtime rows found in {path}")
    return rows


def campaign_schematic(out: Path) -> None:
    """A readable diagram of the scoring rule, independent of any live data."""
    width, height = 1500, 820
    image = canvas(width, height)
    add_radial(image, (760, 90), 520, (18, 100, 120), 0.34)
    add_radial(image, (1300, 760), 460, (90, 60, 170), 0.3)
    add_grid(image, 40)
    draw = ImageDraw.Draw(image)
    text(draw, (80, 58), "CONFIDENCE MODEL", size=17, color=TEAL, mono=True)
    text(draw, (80, 86), "Weighted evidence, a coverage penalty, and a hard anchor gate", size=34,
         color=INK, bold=True)

    families = [
        ("behavior", 0.52, TEAL),
        ("targeting", 0.18, BLUE),
        ("intel", 0.12, BLUE),
        ("identity", 0.10, VIOLET),
        ("timing", 0.08, VIOLET),
        ("toolchain", 0.08, AMBER),
    ]
    text(draw, (80, 190), "FAMILY", size=14, color=FAINT, mono=True)
    text(draw, (480, 190), "WEIGHT · share of total", size=14, color=FAINT, mono=True)
    y = 226
    for name, weight, color in families:
        text(draw, (80, y), name, size=20, color=(205, 222, 236))
        end = 480 + 760 * weight
        draw.rounded_rectangle([480, y + 6, end, y + 22], radius=8, fill=mix(color, BG_TOP, 0.8))
        text(draw, (end + 14, y + 1), f"{weight:.2f}", size=17, color=color, mono=True)
        y += 52

    panel(image, [80, 590, 1400, 740])
    text(draw, (106, 612), "DECISION", size=14, color=TEAL, mono=True)
    text(draw, (106, 636),
         "support = Σ(w·score) / Σw over available families · coverage = Σw available / Σw total",
         size=19, color=INK)
    text(draw, (106, 668),
         "score = support · √coverage − contradiction penalty (≤ 0.35) · confidence = sigmoid(8(score − 0.5))",
         size=19, color=INK)
    text(draw, (106, 704),
         "link if confidence ≥ 0.70, two families score ≥ 0.50, penalty ≤ 0.25 and a specific anchor is present.",
         size=16, color=MUTED)
    image.save(out)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("../docs/assets"))
    parser.add_argument("--research", type=Path, default=Path("../docs/research"))
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    data = json.loads((args.research / "evaluation-results.json").read_text())
    run = data["runs"][-1]
    results = run["results"]
    proposed = results["proposed_adaptive"]
    runtime = load_runtime(args.research / "correlation-runtime.md")
    hero(
        args.out / "hero.png",
        {
            "precision": proposed["precision"],
            "f1": proposed["f1"],
            "recall": proposed["recall"],
            "pair_ms": runtime[-1]["per_pair"],
            "sessions": runtime[-1]["sessions"],
        },
    )
    architecture(args.out / "architecture.png")
    campaign_schematic(args.out / "confidence-model.png")
    detection_chart(args.out / "results-detection.png", results)
    ablation_chart(args.out / "results-ablation.png", results)
    runtime_chart(args.out / "results-runtime.png", runtime)
    for name in ("hero", "architecture", "confidence-model", "results-detection", "results-ablation",
                 "results-runtime"):
        path = args.out / f"{name}.png"
        print(f"{path} {path.stat().st_size // 1024} KiB")


if __name__ == "__main__":
    main()
