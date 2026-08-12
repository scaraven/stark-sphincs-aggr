import numpy as np
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

# ============================================================
# Data — 10 runs each, parsed from multisig benchmark JSONs
# ============================================================

labels = [
    "Schnorr-BTC",
    "SPHINCS$^+$-BTC",
    "SPHINCS$^+$-Poseidon",
    "SPHINCS$^+$-Poseidon\n(Mini)",
]

short = [
    "Schnorr\nBTC",
    "SPHINCS$^+$\nBTC",
    "SPHINCS$^+$\nPoseidon",
    "SPHINCS$^+$\nPoseidon\n(Mini)",
]

# Deterministic — identical across all runs
cairo_cycles = np.array([96_399, 4_844_217, 139_118, 61_220])

# 10 prover runs per scheme (seconds)
prover_time_runs = np.array([
    [76.2, 76.8, 77.5, 77.3, 77.4, 76.4, 78.4, 78.3, 76.1, 78.0],
    [124.3, 126.4, 125.5, 125.5, 128.7, 129.9, 124.4, 123.6, 134.9, 127.1],
    [130.5, 129.5, 130.7, 136.1, 130.5, 129.2, 130.1, 129.5, 130.7, 134.4],
    [90.2, 91.9, 93.0, 90.9, 93.8, 93.2, 94.3, 95.9, 95.7, 93.0],
])

# 10 execution runs per scheme (seconds)
exec_time_runs = np.array([
    [1.87, 2.12, 2.10, 2.08, 2.12, 2.12, 2.16, 2.12, 3.07, 2.14],
    [9.37, 9.45, 9.60, 9.50, 9.34, 9.57, 9.56, 9.43, 9.49, 9.55],
    [2.18, 2.32, 2.30, 2.36, 2.73, 2.35, 2.38, 2.31, 2.34, 2.39],
    [1.39, 1.54, 1.54, 1.53, 1.52, 1.54, 1.55, 1.60, 1.89, 1.59],
])

# Constant across runs
proof_size_kb = np.array([5596.63, 4428.48, 5562.71, 5577.29])

n = len(labels)
x = np.arange(n)

# ============================================================
# Style
# ============================================================

BG       = "#FAFAF8"
PANEL_BG = "#FFFFFF"
GRID     = "#E8E4DE"
SPINE    = "#BBBBBB"
TEXT     = "#1A1A1A"
PALETTE  = ["#2166AC", "#B2182B", "#4DAC26", "#E08214"]

BASE_RC = {
    "font.family":      "serif",
    "font.serif":       ["Georgia", "DejaVu Serif"],
    "font.size":        11,
    "axes.labelsize":   11,
    "axes.titlesize":   12,
    "axes.titleweight": "bold",
    "xtick.labelsize":  9.5,
    "ytick.labelsize":  10,
    "legend.fontsize":  10,
    "figure.dpi":       180,
    "text.color":       TEXT,
    "axes.labelcolor":  TEXT,
    "xtick.color":      TEXT,
    "ytick.color":      TEXT,
}
plt.rcParams.update(BASE_RC)

legend_labels = [
    "Schnorr-BTC",
    "SPHINCS$^+$-BTC",
    "SPHINCS$^+$-Poseidon",
    "SPHINCS$^+$-Poseidon (Mini)",
]

# ============================================================
# Shared helpers
# ============================================================

def style_ax(ax):
    ax.set_facecolor(PANEL_BG)
    ax.grid(axis="y", linestyle="--", linewidth=0.6, color=GRID, zorder=0)
    for spine in ax.spines.values():
        spine.set_edgecolor(SPINE)
        spine.set_linewidth(0.8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)


def add_legend(fig):
    handles = [
        plt.Rectangle((0, 0), 1, 1, facecolor=PALETTE[i],
                       edgecolor="white", linewidth=0.8)
        for i in range(n)
    ]
    fig.legend(
        handles, legend_labels,
        loc="lower center", ncol=4,
        frameon=True, framealpha=0.95,
        edgecolor=SPINE, facecolor=BG,
        fontsize=10,
        bbox_to_anchor=(0.5, 0.005),
        handlelength=1.4, handleheight=1.0,
    )


def bar_chart(ax, values, title, ylabel, fmt=None, log=False):
    style_ax(ax)
    bars = ax.bar(x, values, color=PALETTE, width=0.55, zorder=3,
                  edgecolor="white", linewidth=0.8)
    ax.set_title(title, pad=10)
    ax.set_ylabel(ylabel, labelpad=8)
    ax.set_xticks(x)
    ax.set_xticklabels(short, fontsize=9)

    if log:
        ax.set_yscale("log")
        ax.yaxis.set_major_formatter(
            FuncFormatter(lambda v, _: f"$10^{{{int(np.log10(v))}}}$" if v > 0 else "0")
        )
        ax.set_ylim(top=ax.get_ylim()[1] * 8)
    elif fmt:
        ax.yaxis.set_major_formatter(FuncFormatter(fmt))

    for bar, val in zip(bars, values):
        if log:
            label = f"{val:,.0f}"
            y_pos = bar.get_height() * 1.5
        elif fmt:
            label = fmt(val, None)
            y_pos = bar.get_height() * 1.03
        else:
            label = f"{val:.1f}"
            y_pos = bar.get_height() * 1.03

        ax.text(
            bar.get_x() + bar.get_width() / 2,
            y_pos, label,
            ha="center", va="bottom", fontsize=8.5, color=TEXT,
            fontfamily="serif",
        )


def box_chart(ax, runs_array, title, ylabel, fmt_fn=None):
    """Box plot with jittered data points overlaid."""
    style_ax(ax)

    rng = np.random.default_rng(42)
    positions = np.arange(n)

    bp = ax.boxplot(
        [runs_array[i] for i in range(n)],
        positions=positions,
        widths=0.55,          # wider boxes
        patch_artist=True,
        notch=False,
        vert=True,
        zorder=3,
        medianprops=dict(color="white", linewidth=2.5),
        whiskerprops=dict(linewidth=1.5),
        capprops=dict(linewidth=1.5),
        flierprops=dict(marker="", linestyle="none"),  # hide default fliers
    )

    for patch, col in zip(bp["boxes"], PALETTE):
        patch.set_facecolor(col)
        patch.set_alpha(0.75)
        patch.set_edgecolor(col)

    for whisker, col in zip(bp["whiskers"], np.repeat(PALETTE, 2)):
        whisker.set_color(col)
        whisker.set_alpha(0.9)

    for cap, col in zip(bp["caps"], np.repeat(PALETTE, 2)):
        cap.set_color(col)
        cap.set_alpha(0.9)

    # Jittered individual data points
    for i, col in enumerate(PALETTE):
        jitter = rng.uniform(-0.12, 0.12, size=len(runs_array[i]))
        ax.scatter(
            positions[i] + jitter, runs_array[i],
            color=col, s=28, zorder=5,
            edgecolors="white", linewidths=0.6, alpha=0.9,
        )

    # Median annotation above the 75th-percentile whisker cap
    for i, col in enumerate(PALETTE):
        med = np.median(runs_array[i])
        top = np.percentile(runs_array[i], 75)
        label = fmt_fn(med) if fmt_fn else f"{med:.2f}"
        ax.text(
            positions[i], top,
            label,
            ha="center", va="bottom", fontsize=8.5,
            color=col, fontfamily="serif", fontweight="bold",
        )

    ax.set_title(title, pad=10)
    ax.set_ylabel(ylabel, labelpad=8)
    ax.set_xticks(positions)
    ax.set_xticklabels(short, fontsize=9.5)

    if fmt_fn:
        ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: fmt_fn(v)))

    # Give y-axis a little breathing room above the highest point
    ymin, ymax = ax.get_ylim()
    ax.set_ylim(ymin - (ymax - ymin) * 0.05, ymax + (ymax - ymin) * 0.12)


def save_fig(fig, stem):
    fig.savefig(f"./{stem}.pdf", bbox_inches="tight", facecolor=BG)
    fig.savefig(f"./{stem}.png", bbox_inches="tight", facecolor=BG, dpi=200)
    plt.close(fig)
    print(f"  Saved {stem}.pdf / .png")


# ============================================================
# Figure 1 — Deterministic metrics (Cairo cycles + Proof size)
# ============================================================

fig1, (ax_cycles, ax_proof) = plt.subplots(1, 2, figsize=(13, 6), facecolor=BG)
fig1.subplots_adjust(wspace=0.35, bottom=0.18)

bar_chart(ax_cycles, cairo_cycles,
          "(a) Cairo Execution Cycles", "Cycles (log scale)", log=True)

bar_chart(ax_proof, proof_size_kb,
          "(b) Proof Size", "Size (KB)",
          fmt=lambda v, _: f"{v:,.0f} KB")

add_legend(fig1)
fig1.suptitle(
    "Cairo Prover Benchmark — Deterministic Metrics",
    fontsize=13, fontweight="bold", color=TEXT, y=1.01,
)
save_fig(fig1, "cairo_benchmark_static")


# ============================================================
# Figure 2 — Prover time box plots
# ============================================================

fig2, ax_prover = plt.subplots(figsize=(11, 7), facecolor=BG)
fig2.subplots_adjust(bottom=0.22)

box_chart(ax_prover, prover_time_runs,
          "Prover Time — 10 Runs per Scheme",
          "Time (seconds)",
          fmt_fn=lambda v: f"{v:.1f}s")

add_legend(fig2)
fig2.suptitle(
    "Cairo Prover Benchmark — Prover Time (Single Signature, n=10)",
    fontsize=13, fontweight="bold", color=TEXT, y=1.01,
)
save_fig(fig2, "cairo_benchmark_prover_time")


# ============================================================
# Figure 3 — Execution time box plots
# ============================================================

fig3, ax_exec = plt.subplots(figsize=(11, 7), facecolor=BG)
fig3.subplots_adjust(bottom=0.22)

box_chart(ax_exec, exec_time_runs,
          "Cairo Execution Time — 10 Runs per Scheme",
          "Time (seconds)",
          fmt_fn=lambda v: f"{v:.2f}s")

add_legend(fig3)
fig3.suptitle(
    "Cairo Prover Benchmark — Execution Time (Single Signature, n=10)",
    fontsize=13, fontweight="bold", color=TEXT, y=1.01,
)
save_fig(fig3, "cairo_benchmark_exec_time")

print("Done.")
