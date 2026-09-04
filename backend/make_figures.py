"""
Generate the report figures.

Five images: three diagrams and two charts. The charts read from the
evaluation harness output so they cannot drift from the reported numbers.
"""

import json
import pathlib

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

OUT = pathlib.Path(__file__).parent / "figures"
OUT.mkdir(exist_ok=True)

INK = "#0C2230"
INK2 = "#16384A"
GOLD = "#A9802A"
GREEN = "#2C7A58"
RED = "#B4434F"
LINE = "#D7E0DD"
PAPER = "#F7F9F8"
MUTED = "#5F6F77"

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "savefig.dpi": 200,
    "savefig.bbox": "tight",
    "savefig.facecolor": "white",
})


def box(ax, x, y, w, h, title, subtitle="", fill="white", edge=LINE,
        title_colour=INK, lw=1.4):
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h, boxstyle="round,pad=0.012,rounding_size=0.03",
        facecolor=fill, edgecolor=edge, linewidth=lw, zorder=2,
    ))
    # Offsets are a fraction of box height, not absolute: the axes are a
    # 0-10 square rendered at varying aspect, so fixed offsets collide.
    ty = y + h / 2 + (h * 0.18 if subtitle else 0)
    ax.text(x + w / 2, ty, title, ha="center", va="center",
            fontsize=9.5, fontweight="bold", color=title_colour, zorder=3)
    if subtitle:
        ax.text(x + w / 2, y + h / 2 - h * 0.22, subtitle, ha="center",
                va="center", fontsize=7.6, color=MUTED, zorder=3)


def arrow(ax, x1, y1, x2, y2, colour=INK2, style="-|>", lw=1.3, ls="-"):
    ax.add_patch(FancyArrowPatch(
        (x1, y1), (x2, y2), arrowstyle=style, mutation_scale=11,
        color=colour, linewidth=lw, linestyle=ls, zorder=1,
        shrinkA=1, shrinkB=1,
    ))


def blank_axes(figsize):
    fig, ax = plt.subplots(figsize=figsize)
    ax.set_xlim(0, 10); ax.set_ylim(0, 10)
    ax.axis("off")
    return fig, ax


# ---------------------------------------------------- Figure 3.1: pipeline

def figure_pipeline():
    fig, ax = blank_axes((9.2, 4.2))

    stages = [
        ("Authenticate", "who is asking", "#EAF0EE"),
        ("Verify key", "may they ask", "#F4EBD2"),
        ("Resolve context", "which fields", "#EAF0EE"),
        ("Project", "build response", "#E2EFE9"),
        ("Audit", "record outcome", "#EAF0EE"),
    ]
    w, h, gap = 1.62, 2.1, 0.28
    x0 = 0.35
    for i, (title, sub, fill) in enumerate(stages):
        x = x0 + i * (w + gap)
        box(ax, x, 5.0, w, h, title, sub, fill=fill,
            edge=GOLD if i == 1 else LINE, lw=1.8 if i == 1 else 1.3)
        if i < len(stages) - 1:
            arrow(ax, x + w, 6.05, x + w + gap, 6.05)

    ax.text(0.35, 8.6, "Relying party  \u2192  signed Context-Key",
            fontsize=9, color=INK, fontweight="bold")
    arrow(ax, 2.9, 8.4, 1.9, 7.25, colour=GOLD, lw=1.5)

    ax.text(9.68, 6.05, "response", fontsize=8.5, color=GREEN,
            ha="left", va="center", fontweight="bold", rotation=0)

    # Refusal path
    ax.add_patch(FancyBboxPatch(
        (2.4, 2.1), 3.4, 1.3, boxstyle="round,pad=0.012,rounding_size=0.03",
        facecolor="#FBEDEE", edgecolor=RED, linewidth=1.3, zorder=2))
    ax.text(4.1, 2.75, "401  refused, with reason", ha="center", va="center",
            fontsize=8.8, color=RED, fontweight="bold", zorder=3)
    arrow(ax, 2.3, 4.95, 3.2, 3.45, colour=RED, ls=(0, (4, 2)), lw=1.2)
    arrow(ax, 5.8, 2.75, 8.35, 4.95, colour=RED, ls=(0, (4, 2)), lw=1.2)
    ax.text(7.4, 3.55, "refusals are logged too", fontsize=7.6,
            color=MUTED, ha="center", style="italic")

    fig.savefig(OUT / "fig_3_1_pipeline.png")
    plt.close(fig)


# --------------------------------------------------------- Figure 3.2: ERD

def figure_erd():
    fig, ax = blank_axes((9.2, 6.0))

    box(ax, 0.3, 7.3, 2.5, 1.35, "RelyingParty", "signing_secret", fill="#F4EBD2", edge=GOLD)
    box(ax, 3.75, 7.3, 2.5, 1.35, "Grant", "is_active", fill="#F4EBD2", edge=GOLD)
    box(ax, 7.2, 7.3, 2.5, 1.35, "Context", "purpose, is_active", fill="#EAF0EE")

    box(ax, 7.2, 5.05, 2.5, 1.35, "ContextAttribute", "join", fill="#EAF0EE")
    box(ax, 7.2, 2.8, 2.5, 1.35, "Attribute", "derivation rule", fill="#E2EFE9", edge=GREEN)

    box(ax, 0.3, 2.8, 2.5, 1.35, "Citizen", "password, TOTP", fill="#EAF0EE")
    box(ax, 3.75, 2.8, 2.5, 1.35, "CitizenAttribute", "value", fill="#EAF0EE")

    box(ax, 0.3, 0.5, 2.5, 1.35, "AuditEntry", "hash chain", fill="#E2EFE9", edge=GREEN)
    box(ax, 3.75, 0.5, 2.5, 1.35, "UsedKey", "replay guard", fill="#EAF0EE")
    box(ax, 7.2, 0.5, 2.5, 1.35, "UsedTotpCode", "replay guard", fill="#EAF0EE")

    arrow(ax, 2.8, 7.97, 3.75, 7.97, style="-")
    arrow(ax, 6.25, 7.97, 7.2, 7.97, style="-")
    arrow(ax, 8.45, 7.3, 8.45, 6.4, style="-")
    arrow(ax, 8.45, 5.05, 8.45, 3.95, style="-")
    arrow(ax, 2.8, 3.37, 3.75, 3.37, style="-")
    arrow(ax, 6.25, 3.37, 7.2, 3.37, style="-")
    arrow(ax, 1.55, 2.8, 1.55, 1.65, style="-")
    arrow(ax, 1.55, 3.37, 1.55, 3.37, style="-")

    ax.text(3.27, 8.05, "1..*", fontsize=7, color=MUTED, ha="center")
    ax.text(6.72, 8.05, "*..1", fontsize=7, color=MUTED, ha="center")
    ax.text(3.27, 3.55, "1..*", fontsize=7, color=MUTED, ha="center")
    ax.text(6.72, 3.55, "*..1", fontsize=7, color=MUTED, ha="center")

    ax.text(5.0, 9.25, "Which fields a context may see is a row in "
                       "ContextAttribute, not a line of code",
            ha="center", fontsize=8.4, color=INK2, style="italic")

    fig.savefig(OUT / "fig_3_2_erd.png")
    plt.close(fig)


# --------------------------------------------- Figure 3.3: five-layer check

def figure_layers():
    fig, ax = blank_axes((9.2, 5.0))

    layers = [
        ("1  Structural", "Is this a well-formed token?",
         "CTXKEY_MISSING · CTXKEY_MALFORMED"),
        ("2  Identity", "Is the party registered and active?",
         "RP_UNKNOWN · RP_INACTIVE"),
        ("3  Cryptographic", "Does the signature verify?",
         "CTXKEY_BAD_SIGNATURE"),
        ("4  Temporal", "Is the key still in its window?",
         "CTXKEY_EXPIRED · CTXKEY_REPLAYED"),
        ("5  Authorisation", "Context live, and a grant held?",
         "CONTEXT_INACTIVE · CONTEXT_NOT_GRANTED"),
    ]
    h, gap = 1.34, 0.24
    y = 8.9
    for i, (name, question, codes) in enumerate(layers):
        highlight = i == 4
        ax.add_patch(FancyBboxPatch(
            (0.3, y - h), 6.2, h,
            boxstyle="round,pad=0.012,rounding_size=0.03",
            facecolor="#F4EBD2" if highlight else "white",
            edgecolor=GOLD if highlight else LINE,
            linewidth=1.9 if highlight else 1.3, zorder=2))
        ax.text(0.62, y - 0.45, name, fontsize=9.4, fontweight="bold",
                color=INK, zorder=3)
        ax.text(0.62, y - 0.95, question, fontsize=8.2, color=MUTED, zorder=3)
        ax.text(6.75, y - 0.7, codes, fontsize=7.3, color=RED,
                va="center", family="monospace", zorder=3)
        if i < len(layers) - 1:
            arrow(ax, 3.4, y - h, 3.4, y - h - gap, colour=GREEN)
        y -= (h + gap)

    arrow(ax, 3.4, y, 3.4, y - 0.42, colour=GREEN)
    ax.text(3.4, y - 0.75, "pass all five  \u2192  disclose", ha="center",
            fontsize=9.2, color=GREEN, fontweight="bold")
    ax.text(3.4, 9.62, "A valid signature is not sufficient: layer 5 is a "
                      "separate authorisation fact",
            ha="center", fontsize=8.4, color=INK2, style="italic")

    fig.savefig(OUT / "fig_3_3_layers.png")
    plt.close(fig)


# --------------------------------------------- Figures 5.1 and 5.2: charts

def load_results():
    path = pathlib.Path(__file__).parent / "results" / "results.json"
    return json.loads(path.read_text())


def figure_minimisation(results):
    rows = results["minimisation"]["rows"]
    labels = [r["context"].replace("_", " ").title() for r in rows]
    values = [r["percent_withheld"] for r in rows]
    labels.append("Full record")
    values.append(0.0)

    fig, ax = plt.subplots(figsize=(8.4, 4.0))
    colours = [GREEN] * (len(values) - 1) + [RED]
    bars = ax.bar(labels, values, color=colours, width=0.62,
                  edgecolor="white", linewidth=0.8)
    for bar, value in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, value + 1.6,
                f"{value:.1f}%", ha="center", fontsize=8.6,
                fontweight="bold", color=INK)

    mean = results["minimisation"]["mean_percent_withheld"]
    ax.axhline(mean, color=GOLD, linestyle="--", linewidth=1.3, zorder=0)
    ax.text(len(values) - 0.4, mean + 2.2, f"mean {mean}%",
            color=GOLD, fontsize=8.4, fontweight="bold", ha="right")

    ax.set_ylabel("% of the 8-field record withheld", fontsize=9)
    ax.set_ylim(0, 100)
    ax.tick_params(axis="x", labelsize=8.4, rotation=18)
    ax.tick_params(axis="y", labelsize=8.4)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    ax.spines["left"].set_color(LINE); ax.spines["bottom"].set_color(LINE)
    ax.grid(axis="y", color=LINE, linewidth=0.7, alpha=0.7)
    ax.set_axisbelow(True)
    fig.savefig(OUT / "fig_5_1_minimisation.png")
    plt.close(fig)


def figure_latency(results):
    ctx = results["latency"]["contextual"]
    base = results["latency"]["unprotected_baseline"]
    metrics = ["p50", "p95", "p99"]
    ctx_vals = [ctx[f"{m}_ms"] for m in metrics]
    base_vals = [base[f"{m}_ms"] for m in metrics]

    fig, ax = plt.subplots(figsize=(7.2, 3.9))
    x = range(len(metrics))
    width = 0.35
    b1 = ax.bar([i - width / 2 for i in x], ctx_vals, width,
                label="Contextual (verified)", color=INK2,
                edgecolor="white", linewidth=0.8)
    b2 = ax.bar([i + width / 2 for i in x], base_vals, width,
                label="Unprotected baseline", color="#9FB4B1",
                edgecolor="white", linewidth=0.8)
    for bars in (b1, b2):
        for bar in bars:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.18,
                    f"{bar.get_height():.2f}", ha="center", fontsize=8.2,
                    color=INK)

    ax.set_xticks(list(x)); ax.set_xticklabels(metrics, fontsize=9)
    ax.set_ylabel("milliseconds", fontsize=9)
    ax.set_ylim(0, max(ctx_vals) * 1.28)
    ax.tick_params(axis="y", labelsize=8.4)
    ax.legend(fontsize=8.4, frameon=False, loc="upper left")
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    ax.spines["left"].set_color(LINE); ax.spines["bottom"].set_color(LINE)
    ax.grid(axis="y", color=LINE, linewidth=0.7, alpha=0.7)
    ax.set_axisbelow(True)

    overhead = results["latency"]["overhead_p50_ms"]
    percent = results["latency"]["overhead_percent"]
    ax.text(0.98, 0.92, f"overhead at p50: +{overhead} ms  ({percent}%)",
            transform=ax.transAxes, ha="right", fontsize=8.6,
            color=GOLD, fontweight="bold")
    fig.savefig(OUT / "fig_5_2_latency.png")
    plt.close(fig)


if __name__ == "__main__":
    figure_pipeline()
    figure_erd()
    figure_layers()
    results = load_results()
    figure_minimisation(results)
    figure_latency(results)
    for path in sorted(OUT.glob("*.png")):
        print(f"  {path.name}  {path.stat().st_size // 1024} KB")
