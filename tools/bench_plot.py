#!/usr/bin/env python3
"""bench_plot.py — render the store benchmark CSV into dependency-free SVGs.

Reads bench.csv (produced by store_bench.com) and emits two line charts:
  - bench-latency.svg : x = N (log scale), y = warm resolve latency (ns),
                        one series per resolve path (alias, revmap).
  - bench-size.svg    : x = N (log scale), y = bytes per alias.

Python 3 stdlib ONLY (no matplotlib / gnuplot).  Output is deterministic and
renders in any browser: axes, ticks, gridlines, polylines, labels, legend.

Usage:
  python3 tools/bench_plot.py bench.csv OUT_LATENCY.svg OUT_SIZE.svg

Interpretation (honest framing — do NOT relabel to claim a falling curve):
  - latency: O(prefix length), not O(alias count) => a near-flat, sub-linear
    line on the log-x axis.  NOT "literally flat".
  - size: bytes/alias is ~constant (~480-550 B) across the three decades —
    the store carries no per-alias index bloat.  It does NOT fall as N grows.
"""

import csv
import math
import sys

# ---- geometry ---------------------------------------------------------------
W, H, PAD_L, PAD_R, PAD_T, PAD_B = 720, 400, 70, 24, 30, 44
PLOT_W = W - PAD_L - PAD_R
PLOT_H = H - PAD_T - PAD_B

GRID_COLOR = "#d8dee5"
AXIS_COLOR = "#33415c"
TEXT_COLOR = "#33415c"
FG = {
    "alias": "#2563eb",
    "revmap": "#dc2626",
    "size": "#059669",
}

# ---- helpers ----------------------------------------------------------------
def esc(t):
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def nice_bounds(lo, hi, ntick):
    """Return (min, max, step) for a linear axis with ~ntick gridlines."""
    span = hi - lo
    if span <= 0:
        span = 1.0
    raw = span / max(1, ntick - 1)
    mag = 10.0 ** math.floor(math.log10(raw))
    for m in (1.0, 2.0, 5.0, 10.0):
        s = m * mag
        if s >= raw:
            break
    lo = math.floor(lo / s) * s
    hi = math.ceil(hi / s) * s
    return lo, hi, s


def draw_axes(svg, x_ticks, y_min, y_max, y_step, y_label):
    """Gridlines + numeric tick labels for a log-x / linear-y chart."""
    for gx, _ in x_ticks:
        px = PAD_L + math.log10(gx) / math.log10(10) * PLOT_W
        svg.append(
            f'<line x1="{px:.1f}" y1="{PAD_T}" x2="{px:.1f}" '
            f'y2="{PAD_T + PLOT_H}" stroke="{GRID_COLOR}" stroke-width="1"/>'
        )
    for gx, label in x_ticks:
        px = PAD_L + math.log10(gx) / math.log10(10) * PLOT_W
        svg.append(
            f'<line x1="{px:.1f}" y1="{PAD_T + PLOT_H}" x2="{px:.1f}" '
            f'y2="{PAD_T + PLOT_H + 4}" stroke="{AXIS_COLOR}" stroke-width="1"/>'
        )
        svg.append(
            f'<text x="{px:.1f}" y="{PAD_T + PLOT_H + 16}" '
            f'font-size="11" fill="{TEXT_COLOR}" text-anchor="middle">'
            f'{esc(label)}</text>'
        )
    # y gridlines + ticks
    v = y_min
    while v <= y_max + 1e-9:
        py = PAD_T + PLOT_H - (v - y_min) / (y_max - y_min) * PLOT_H
        svg.append(
            f'<line x1="{PAD_L}" y1="{py:.1f}" x2="{PAD_L + PLOT_W}" '
            f'y2="{py:.1f}" stroke="{GRID_COLOR}" stroke-width="1"/>'
        )
        svg.append(
            f'<line x1="{PAD_L - 4}" y1="{py:.1f}" x2="{PAD_L}" '
            f'y2="{py:.1f}" stroke="{AXIS_COLOR}" stroke-width="1"/>'
        )
        svg.append(
            f'<text x="{PAD_L - 8}" y="{py + 4:.1f}" font-size="11" '
            f'fill="{TEXT_COLOR}" text-anchor="end">{v:g}</text>'
        )
        v += y_step
    # axis frame
    svg.append(
        f'<line x1="{PAD_L}" y1="{PAD_T}" x2="{PAD_L}" y2="{PAD_T + PLOT_H}" '
        f'stroke="{AXIS_COLOR}" stroke-width="1.2"/>'
    )
    svg.append(
        f'<line x1="{PAD_L}" y1="{PAD_T + PLOT_H}" x2="{PAD_L + PLOT_W}" '
        f'y2="{PAD_T + PLOT_H}" stroke="{AXIS_COLOR}" stroke-width="1.2"/>'
    )
    # y axis label (vertical)
    svg.append(
        f'<text x="14" y="{PAD_T + PLOT_H / 2:.1f}" font-size="12" '
        f'fill="{TEXT_COLOR}" text-anchor="middle" '
        f'transform="rotate(-90 14 {PAD_T + PLOT_H / 2:.1f})">'
        f'{esc(y_label)}</text>'
    )


def polyline_for(xs, ys, y_min, y_max, color):
    pts = []
    for x, y in zip(xs, ys):
        px = PAD_L + math.log10(x) / math.log10(10) * PLOT_W
        py = PAD_T + PLOT_H - (y - y_min) / (y_max - y_min) * PLOT_H
        pts.append(f"{px:.1f},{py:.1f}")
    return (f'<polyline points="{" ".join(pts)}" fill="none" '
            f'stroke="{color}" stroke-width="2.2"/>')


def legend(svg, items, x, y):
    cx = x
    for color, label in items:
        svg.append(f'<line x1="{cx}" y1="{y}" x2="{cx + 18}" y2="{y}" '
                   f'stroke="{color}" stroke-width="2.5"/>')
        svg.append(f'<text x="{cx + 24}" y="{y + 4}" font-size="11" '
                   f'fill="{TEXT_COLOR}">{esc(label)}</text>')
        cx += 24 + 18 + 8 + len(label) * 6.2


# ---- reading -----------------------------------------------------------------
def read_csv(path):
    rows = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            rows.append(r)
    return rows


def num(row, col):
    return float(row[col])


# ---- charts -------------------------------------------------------------------
def chart_latency(rows):
    xs = [num(r, "N") for r in rows]
    alias = [num(r, "alias_warm_ns") for r in rows]
    revmap = [num(r, "revmap_warm_ns") for r in rows]
    allv = alias + revmap
    lo, hi, step = nice_bounds(0, max(allv), 6)
    if lo < 0:
        lo = 0.0
    x_ticks = [(t, f"{t:g}") for t in (1e3, 1e4, 1e5, 1e6) if t <= xs[-1]]

    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
           f'viewBox="0 0 {W} {H}">']
    svg.append(f'<text x="{PAD_L}" y="18" font-size="14" font-weight="bold" '
               f'fill="{TEXT_COLOR}">Resolve latency vs alias count '
               f'(warm, random batch)</text>')
    draw_axes(svg, x_ticks, lo, hi, step, "latency (ns)")
    svg.append(polyline_for(xs, alias, lo, hi, FG["alias"]))
    svg.append(polyline_for(xs, revmap, lo, hi, FG["revmap"]))
    legend(svg, [("alias", "alias warm"), ("revmap", "revmap warm")],
           PAD_L, PAD_T + PLOT_H + 30)
    svg.append(f'<text x="{PAD_L}" y="{PAD_T + PLOT_H + 44}" '
               f'font-size="10" fill="#6b7280">'
               f'sub-linear: cost scales with prefix length, not alias count</text>')
    svg.append("</svg>")
    return "\n".join(svg)


def chart_size(rows):
    xs = [num(r, "N") for r in rows]
    ys = [num(r, "bytes_per_alias") for r in rows]
    lo, hi, step = nice_bounds(min(ys) * 0.95, max(ys) * 1.05, 5)
    x_ticks = [(t, f"{t:g}") for t in (1e3, 1e4, 1e5, 1e6) if t <= xs[-1]]

    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
           f'viewBox="0 0 {W} {H}">']
    svg.append(f'<text x="{PAD_L}" y="18" font-size="14" font-weight="bold" '
               f'fill="{TEXT_COLOR}">Store size vs alias count '
               f'(bytes per alias, on disk)</text>')
    draw_axes(svg, x_ticks, lo, hi, step, "bytes / alias")
    svg.append(polyline_for(xs, ys, lo, hi, FG["size"]))
    legend(svg, [("size", "bytes / alias")], PAD_L, PAD_T + PLOT_H + 30)
    svg.append(f'<text x="{PAD_L}" y="{PAD_T + PLOT_H + 44}" '
               f'font-size="10" fill="#6b7280">'
               f'~constant bytes/alias across three decades: no per-alias '
               f'index bloat</text>')
    svg.append("</svg>")
    return "\n".join(svg)


def main():
    if len(sys.argv) != 4:
        print("usage: bench_plot.py BENCH_CSV OUT_LATENCY.svg OUT_SIZE.svg",
              file=sys.stderr)
        return 2
    rows = read_csv(sys.argv[1])
    if not rows:
        print(f"bench_plot.py: no rows in {sys.argv[1]}", file=sys.stderr)
        return 1
    with open(sys.argv[2], "w") as f:
        f.write(chart_latency(rows))
    with open(sys.argv[3], "w") as f:
        f.write(chart_size(rows))
    print(f"wrote {sys.argv[2]}")
    print(f"wrote {sys.argv[3]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
