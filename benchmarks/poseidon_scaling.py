import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

# ============================================================
# Data — sphincs-poseidon-c multisig benchmarks
# ============================================================

SIG_SIZE_KB = 4412 / 1024  # 4.308 KB per signature

data = [
    # (N, exec_s, prove_s, proof_kb)
    (1,    1.36,   94.9,  5577.3),
    (2,    1.18,   41.7,  5622.0),
    (7,    1.98,  226.7,  5893.0),
    (10,   1.36,  124.7,  5860.0),
    (15,   1.80,  199.1,  6044.0),
    (20,   2.33,  199.9,  6049.0),
    (50,   5.93,   59.2,  5700.0),
    (100, 10.26,   70.1,  5918.0),
    (200, 20.59,   92.0,  6007.0),
    (400, 37.54,  137.6,  6261.0),
    (800, 73.30,  224.8,  6490.0),
    (1600,145.06, 396.1,  6600.0),
    (2000,192.24, 644.9,  6849.0),
]

N         = np.array([d[0] for d in data])
exec_s    = np.array([d[1] for d in data])
prove_s   = np.array([d[2] for d in data])
proof_kb  = np.array([d[3] for d in data])

kb_per_sig       = proof_kb / N
total_sigs_kb    = N * SIG_SIZE_KB
compression      = total_sigs_kb / proof_kb   # >1 means proof < raw sigs

# ============================================================
# Style (matches gen-graph.py)
# ============================================================

BG       = "#FAFAF8"
PANEL_BG = "#FFFFFF"
GRID     = "#E8E4DE"
SPINE    = "#BBBBBB"
TEXT     = "#1A1A1A"
C_PROOF  = "#2166AC"
C_KBSIG  = "#B2182B"
C_PROVE  = "#4DAC26"
C_EXEC   = "#E08214"
C_HLINE  = "#888888"

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


def style_ax(ax):
    ax.set_facecolor(PANEL_BG)
    ax.grid(axis="both", linestyle="--", linewidth=0.6, color=GRID, zorder=0)
    for spine in ax.spines.values():
        spine.set_edgecolor(SPINE)
        spine.set_linewidth(0.8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)


def save_fig(fig, stem):
    fig.savefig(f"./{stem}.pdf", bbox_inches="tight", facecolor=BG)
    fig.savefig(f"./{stem}.png", bbox_inches="tight", facecolor=BG, dpi=200)
    plt.close(fig)
    print(f"  Saved {stem}.pdf / .png")


# ============================================================
# Figure 1 — Proof size scaling + KB/sig
# ============================================================

fig1, ax1 = plt.subplots(figsize=(11, 6), facecolor=BG)
fig1.subplots_adjust(right=0.82)
style_ax(ax1)

ax1.scatter(N, proof_kb, color=C_PROOF, s=55, zorder=5, label="Proof size (KB)")
ax1.plot(N, proof_kb, color=C_PROOF, linewidth=1.8, zorder=4)

ax2 = ax1.twinx()
ax2.spines["top"].set_visible(False)
ax2.spines["right"].set_edgecolor(SPINE)
ax2.spines["right"].set_linewidth(0.8)

ax2.scatter(N, kb_per_sig, color=C_KBSIG, s=55, marker="s", zorder=5, label="KB per signature")
ax2.plot(N, kb_per_sig, color=C_KBSIG, linewidth=1.8, linestyle="--", zorder=4)

# Compression break-even: proof_kb == total_sigs_kb  =>  kb_per_sig == SIG_SIZE_KB
ax2.axhline(SIG_SIZE_KB, color=C_HLINE, linewidth=1.4, linestyle=":", zorder=3,
            label=f"Break-even ({SIG_SIZE_KB:.2f} KB/sig)")
ax2.text(N[-1] * 1.01, SIG_SIZE_KB, "break-even", va="center", fontsize=9,
         color=C_HLINE, fontstyle="italic")

ax1.set_xlabel("Number of signatures (N)")
ax1.set_ylabel("Proof size (KB)", color=C_PROOF)
ax1.tick_params(axis="y", labelcolor=C_PROOF)

ax2.set_ylabel("KB per signature", color=C_KBSIG)
ax2.tick_params(axis="y", labelcolor=C_KBSIG)

ax2.set_yscale("log")
ax2.yaxis.set_major_formatter(ticker.FuncFormatter(lambda v, _: f"{v:,.1f}"))

handles1, labels1 = ax1.get_legend_handles_labels()
handles2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(handles1 + handles2, labels1 + labels2,
           loc="upper right", frameon=True, framealpha=0.95,
           edgecolor=SPINE, facecolor=BG)

fig1.suptitle(
    "SPHINCS$^+$-Poseidon: Proof Size Scaling vs. Number of Signatures",
    fontsize=13, fontweight="bold", color=TEXT, y=1.01,
)
save_fig(fig1, "poseidon_proof_size_scaling")


# ============================================================
# Figure 2 — Prover time + execution time
# ============================================================

fig2, ax3 = plt.subplots(figsize=(11, 6), facecolor=BG)
fig2.subplots_adjust(right=0.82)
style_ax(ax3)

ax3.scatter(N, prove_s, color=C_PROVE, s=55, zorder=5, label="Prover time (s)")
ax3.plot(N, prove_s, color=C_PROVE, linewidth=1.8, zorder=4)

ax4 = ax3.twinx()
ax4.spines["top"].set_visible(False)
ax4.spines["right"].set_edgecolor(SPINE)
ax4.spines["right"].set_linewidth(0.8)

ax4.scatter(N, exec_s, color=C_EXEC, s=55, marker="s", zorder=5, label="Execution time (s)")
ax4.plot(N, exec_s, color=C_EXEC, linewidth=1.8, linestyle="--", zorder=4)

ax3.set_xlabel("Number of signatures (N)")
ax3.set_ylabel("Prover time (s)", color=C_PROVE)
ax3.tick_params(axis="y", labelcolor=C_PROVE)

ax4.set_ylabel("Execution time (s)", color=C_EXEC)
ax4.tick_params(axis="y", labelcolor=C_EXEC)

handles3, labels3 = ax3.get_legend_handles_labels()
handles4, labels4 = ax4.get_legend_handles_labels()
ax3.legend(handles3 + handles4, labels3 + labels4,
           loc="upper left", frameon=True, framealpha=0.95,
           edgecolor=SPINE, facecolor=BG)

fig2.suptitle(
    "SPHINCS$^+$-Poseidon: Prover & Execution Time vs. Number of Signatures",
    fontsize=13, fontweight="bold", color=TEXT, y=1.01,
)
save_fig(fig2, "poseidon_prover_time_scaling")

print("Done.")
