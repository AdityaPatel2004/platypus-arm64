#!/usr/bin/env python3
"""plots_talk.py: presentation versions of the two cost charts, showing only
designs B (masks loaded) and C (aligned), from the same 4 Nov 2026 M4 data.
usage: python3 tools/plots_talk.py   (reads results/m4_2026-11-04/summary.csv,
       writes results/figs_talk/)
"""
import csv, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN = f"{ROOT}/results/m4_2026-11-04"; OUT = f"{ROOT}/results/figs_talk"
os.makedirs(OUT, exist_ok=True)
SURF, INK, INK2, GRID = "#ffffff", "#0b0b0b", "#52514e", "#e4e3df"
SER = {"B": "#eb6834", "C": "#1baf7a"}
NAME = {"B": "Approach 1 · load masks", "C": "Approach 2 · aligned"}
CFG = {"B": "mask", "C": "aligned"}
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 12,
                     "axes.edgecolor": INK2, "axes.labelcolor": INK2,
                     "xtick.color": INK2, "ytick.color": INK2,
                     "figure.facecolor": SURF, "axes.facecolor": SURF,
                     "axes.spines.top": False, "axes.spines.right": False})
summ = {}
with open(f"{RUN}/summary.csv") as f:
    for r in csv.DictReader(f):
        summ[(r["benchmark"], r["config"])] = (float(r["overhead_pct"]), float(r["ci95_lo"]), float(r["ci95_hi"]))

def save(fig, name):
    fig.savefig(f"{OUT}/{name}", dpi=220, bbox_inches="tight", facecolor=SURF); print("wrote", f"{OUT}/{name}")

# worst-case loop: predictable vs unpredictable targets
fig, ax = plt.subplots(figsize=(6.4, 3.9))
ops = {"B": 2, "C": 1}
for k, bench in enumerate(["clamp_enc", "clamp_enc_rand"]):
    for j, o in enumerate("BC"):
        ov, lo, hi = summ[(bench, o)]
        x = k * 3 + j
        ax.bar(x, ov, width=0.72, color=SER[o], label=NAME[o] if k == 0 else None)
        ax.errorbar(x, ov, yerr=[[ov - lo], [hi - ov]], color=INK, capsize=4, lw=1.1)
        ax.text(x, max(hi, 0) + 0.25, f"{ov:+.1f}%", ha="center", fontsize=12, color=INK)
        if k == 1:
            ax.text(x, -0.75, f"{ops[o]} op{'s' if ops[o] > 1 else ''}", ha="center", fontsize=10.5, color=INK2)
ax.axhline(0, color=INK2, lw=0.9)
ax.set_xticks([0.5, 3.5]); ax.set_xticklabels(["predictable targets", "unpredictable targets"])
ax.tick_params(axis="x", pad=18)
ax.set_ylim(-1.0, 8.5)
ax.set_ylabel("extra time vs no defence (%)")
ax.legend(frameon=False, fontsize=11, loc="upper left")
ax.grid(axis="y", color=GRID, lw=0.8); ax.set_axisbelow(True)
save(fig, "cost_worstcase_BC.png")

# real programs
work = [("redis", "redis"), ("speedtest1", "SQLite speedtest1 (disk)"),
        ("sqlite_disk", "SQLite bench (disk)"), ("sqlite_mem", "SQLite bench (memory)")]
fig, ax = plt.subplots(figsize=(6.8, 3.9))
lo_aa, hi_aa = summ[("sqlite_aa2", "aa")][1], summ[("sqlite_aa2", "aa")][2]
ax.axvspan(lo_aa, hi_aa, color="#eeede9", zorder=0)
ax.text((lo_aa + hi_aa) / 2, -0.55, "noise", fontsize=10, color=INK2, ha="center", va="bottom")
for i, (b, lab) in enumerate(work):
    for j, o in enumerate("BC"):
        ov, lo, hi = summ[(b, CFG[o])]
        yy = i + (0.15 if j == 0 else -0.15)
        ax.errorbar(ov, yy, xerr=[[ov - lo], [hi - ov]], fmt="o", ms=8, color=SER[o],
                    ecolor=SER[o], capsize=3, lw=1.8, label=NAME[o] if i == 0 else None)
ax.axvline(0, color=INK2, lw=0.9)
ax.set_yticks(range(len(work))); ax.set_yticklabels([l for _, l in work])
ax.set_xlabel("slowdown vs unhardened (%)   ← faster | slower →")
ax.set_ylim(-0.6, len(work) - 0.3)
ax.legend(frameon=False, fontsize=11, loc="upper center", bbox_to_anchor=(0.4, -0.2), ncol=2)
ax.grid(axis="x", color=GRID, lw=0.8); ax.set_axisbelow(True)
save(fig, "cost_real_BC.png")
