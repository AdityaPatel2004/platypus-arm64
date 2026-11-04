#!/usr/bin/env python3
"""plots_v2.py — report figures from the 4 Nov 2026 M4 run.

  fig2_reach.png       cross-library reachability before/after (sqlite3, redis)
  fig3_rq2_encoding.png  clamp-encoding cost, predictable vs unpredictable targets
  fig4_overhead.png    real-workload overhead per encoding, 95% CI, A/A band
  fig5_bti_pads.png    Ubuntu 24.04 libraries: BTI pads present, marker absent
usage: python3 tools/plots_v2.py   (reads results/, writes results/figs/)
"""
import csv, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = f"{ROOT}/results"; RUN = f"{R}/m4_2026-11-04"; OUT = f"{R}/figs"
os.makedirs(OUT, exist_ok=True)
SURF, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
SER = {"A": "#2a78d6", "B": "#eb6834", "C": "#1baf7a", "D": "#eda100"}
NAME = {"A": "A  registers", "B": "B  masks loaded (mask)",
        "C": "C  aligned jail (aligned)", "D": "D  pc-relative (pcrel)"}
CFG2OPT = {"mask": "B", "aligned": "C", "pcrel": "D"}
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10,
                     "axes.edgecolor": INK2, "axes.labelcolor": INK2,
                     "xtick.color": INK2, "ytick.color": INK2,
                     "figure.facecolor": SURF, "axes.facecolor": SURF,
                     "axes.spines.top": False, "axes.spines.right": False})

summ = {}
with open(f"{RUN}/summary.csv") as f:
    for r in csv.DictReader(f):
        summ[(r["benchmark"], r["config"])] = (float(r["overhead_pct"]),
                                              float(r["ci95_lo"]), float(r["ci95_hi"]))

def save(fig, name):
    fig.savefig(f"{OUT}/{name}", dpi=200, bbox_inches="tight", facecolor=SURF)
    print("wrote", f"{OUT}/{name}")

# --- fig2: reachability ------------------------------------------------------
after = {}
with open(f"{R}/reach_after_bin.csv") as f:
    for r in csv.DictReader(f):
        after[r["binary"]] = (int(r["reachable_after"]), int(r["dangerous_after"]))
before = {}
with open(f"{R}/reach_before_ourbuilds.csv") as f:
    for r in csv.DictReader(f):
        before[r["program"]] = (int(r["reachable_before"]), int(r["dangerous_count"]))
fig, ax = plt.subplots(figsize=(7.2, 3.4))
progs = [("sqlite3", "sqlite3_base", "sqlite3_mask"), ("redis-server", "redis-server_base", "redis-server_mask")]
y = 0; ticks = []
for label, b, a in progs:
    rb, db = before[b]; ra, da = after[a]
    for i, (v, col, txt) in enumerate([(rb, "#8a8984", f"before  {rb:,}"), (ra, SER["B"], f"after  {ra}")]):
        ax.barh(y - i * 0.38, v, height=0.34, color=col)
        ax.text(v * 1.15, y - i * 0.38, txt, va="center", color=INK, fontsize=9)
    red = 100 * (1 - ra / rb)
    ticks.append((y - 0.19, f"{label}\n({red:.1f}% removed; dangerous {db}→{da})"))
    y -= 1.2
ax.set_xscale("log"); ax.set_xlim(1, 4e4)
ax.set_yticks([t for t, _ in ticks]); ax.set_yticklabels([l for _, l in ticks])
ax.set_xlabel("cross-library functions an indirect call can reach (log scale)")
ax.set_title("Reachability, measured from the binaries (same for B, C and D)",
             loc="left", color=INK, fontsize=11)
ax.grid(axis="x", color=GRID, lw=0.8); ax.set_axisbelow(True)
save(fig, "fig2_reach.png")

# --- fig3: RQ2 encodings -----------------------------------------------------
fig, ax = plt.subplots(figsize=(7.2, 3.6))
ops = {"A": 2, "B": 2, "C": 1, "D": 3}
for k, (bench, lab) in enumerate([("clamp_enc", "predictable targets\n(branch predictor right)"),
                                  ("clamp_enc_rand", "unpredictable targets\n(clamp on the critical path)")]):
    for j, o in enumerate("ABCD"):
        ov, lo, hi = summ[(bench, o)]
        x = k * 5 + j
        ax.bar(x, ov, width=0.7, color=SER[o], label=NAME[o].split("  ")[0] + f"  {NAME[o].split('  ')[1]}" if k == 0 else None)
        ax.errorbar(x, ov, yerr=[[ov - lo], [hi - ov]], color=INK, capsize=3, lw=1)
        ax.text(x, max(hi, 0) + 0.35, f"{ov:+.1f}%", ha="center", fontsize=8.5, color=INK)
        if k == 1:
            ax.text(x, -1.1, f"{ops[o]} op{'s' if ops[o] > 1 else ''}", ha="center", fontsize=8, color=INK2)
ax.axhline(0, color=INK2, lw=0.8)
ax.set_xticks([1.5, 6.5]); ax.set_xticklabels(["predictable targets", "unpredictable targets"])
ax.set_ylim(-1.6, 12.5)
ax.set_ylabel("overhead per indirect call loop (%)")
ax.set_title("RQ2: cost tracks the clamp's dependent instructions (M4, 95% CI)",
             loc="left", color=INK, fontsize=11)
ax.legend(frameon=False, fontsize=8.5, loc="upper left")
ax.grid(axis="y", color=GRID, lw=0.8); ax.set_axisbelow(True)
save(fig, "fig3_rq2_encoding.png")

# --- fig4: real workloads ----------------------------------------------------
work = [("redis", "redis (13 command types)"), ("speedtest1", "SQLite speedtest1 (on disk)"),
        ("sqlite_disk", "sqlite_bench (on disk)"), ("sqlite_mem", "sqlite_bench (in memory)")]
fig, ax = plt.subplots(figsize=(7.2, 3.8))
lo_aa, hi_aa = summ[("sqlite_aa2", "aa")][1], summ[("sqlite_aa2", "aa")][2]
ax.axvspan(lo_aa, hi_aa, color="#eeede9", zorder=0)
ax.text((lo_aa + hi_aa) / 2, -0.62, "A/A noise\nfloor", fontsize=7.5, color=INK2, ha="center", va="top")
for i, (b, lab) in enumerate(work):
    for j, cfg in enumerate(["mask", "aligned", "pcrel"]):
        o = CFG2OPT[cfg]; ov, lo, hi = summ[(b, cfg)]
        yy = i + (j - 1) * 0.22
        ax.errorbar(ov, yy, xerr=[[ov - lo], [hi - ov]], fmt="o", ms=6, color=SER[o],
                    ecolor=SER[o], capsize=2.5, lw=1.4, label=NAME[o] if i == 0 else None)
ax.axvline(0, color=INK2, lw=0.8)
ax.set_yticks(range(len(work))); ax.set_yticklabels([l for _, l in work])
ax.set_xlabel("runtime overhead vs unhardened (%), median with 95% bootstrap CI")
ax.set_title("Real workloads: B costs at most ~2%; C and D sit at or below zero",
             loc="left", color=INK, fontsize=11)
ax.set_ylim(-0.9, len(work) - 0.5)
ax.legend(frameon=False, fontsize=8.5, loc="upper center", bbox_to_anchor=(0.45, -0.22), ncol=3)
ax.grid(axis="x", color=GRID, lw=0.8); ax.set_axisbelow(True)
save(fig, "fig4_overhead.png")

# --- fig5: BTI pads present but marker absent --------------------------------
rows = []
with open(f"{R}/bti_pads_ubuntu2404_toolchain_libs.csv") as f:
    for r in csv.DictReader(f):
        if int(r["bti_pads"]) > 0 or r["library"] in ("libc.so.6", "libm.so.6"):
            rows.append((r["library"], int(r["bti_pads"]), r["bti_marker"]))
rows.sort(key=lambda t: t[1])
fig, ax = plt.subplots(figsize=(7.2, 3.6))
GCCRT = ("libstdc++", "libasan", "libubsan", "libatomic", "libgcc_s", "libgomp", "libitm")
for i, (n, p, m) in enumerate(rows):
    ax.barh(i, max(p, 0.8), color="#2a78d6" if n.startswith(GCCRT) else "#8a8984", height=0.6,
            label=None)
    ax.text(max(p, 0.8) * 1.12, i, f"{p:,} pads · marker: {m}", va="center", fontsize=8.5, color=INK)
ax.set_xscale("log"); ax.set_xlim(0.7, 6e4)
ax.set_yticks(range(len(rows))); ax.set_yticklabels([r[0] for r in rows], fontsize=9)
ax.set_xlabel("bti landing-pad instructions in the library (log scale)")
ax.set_title("Ubuntu 24.04 arm64: landing pads compiled in, BTI marker never set",
             loc="left", color=INK, fontsize=11)
from matplotlib.patches import Patch
ax.legend(handles=[Patch(color="#2a78d6", label="GCC runtime libraries"),
                   Patch(color="#8a8984", label="glibc (not built with branch protection)")],
          frameon=False, fontsize=8.5, loc="lower right")
ax.grid(axis="x", color=GRID, lw=0.8); ax.set_axisbelow(True)
save(fig, "fig5_bti_pads.png")
