#!/usr/bin/env python3
# (21 Oct figures; superseded by tools/plots_v2.py)
"""plots.py — generate the report figures from results/*.csv. Writes PNGs to
results/figs/. Each figure is self-contained and skipped if its data is missing.
"""
import csv, os, statistics as st, random
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
random.seed(7)

def _load(csvf):
    d = {}
    with open(os.path.join(RES, csvf)) as f:
        for r in csv.DictReader(f):
            c = r.get("config") or r.get("cfg"); d.setdefault(c, []).append(float(r["seconds"]))
    return d
def _ovh(b, j): return 100.0*(st.median(j)-st.median(b))/st.median(b)
def _ci(b, j, B=4000):
    xs=sorted(_ovh([random.choice(b) for _ in b],[random.choice(j) for _ in j]) for _ in range(B))
    return _ovh(b,j), xs[int(0.025*B)], xs[int(0.975*B)]

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES  = os.path.join(HERE, "results")
FIG  = os.path.join(RES, "figs")
os.makedirs(FIG, exist_ok=True)

def have(f): return os.path.exists(os.path.join(RES, f))

# --- Fig 1: distribution-wide BTI/PAC coverage -----------------------------
if have("bti_scan.csv"):
    by = {}
    with open(os.path.join(RES, "bti_scan.csv")) as f:
        for r in csv.DictReader(f):
            d = r["dir"]; by.setdefault(d, [0,0,0])
            by[d][0]+=1; by[d][1]+=int(r["has_bti"]); by[d][2]+=int(r["has_pac"])
    dirs = list(by) + ["TOTAL"]
    tot=[sum(c) for c in zip(*by.values())]; by["TOTAL"]=tot
    bti=[100*by[d][1]/by[d][0] for d in dirs]
    pac=[100*by[d][2]/by[d][0] for d in dirs]
    x=range(len(dirs)); w=0.38
    fig,ax=plt.subplots(figsize=(8,4))
    ax.bar([i-w/2 for i in x], bti, w, label="BTI", color="#c0392b")
    ax.bar([i+w/2 for i in x], pac, w, label="PAC", color="#2980b9")
    ax.set_xticks(list(x)); ax.set_xticklabels([os.path.basename(d) or d for d in dirs], rotation=20, ha="right")
    ax.set_ylabel("% of ELF files"); ax.set_ylim(0, max(10,max(pac)+2))
    ax.set_title("Ubuntu 24.04 arm64: BTI/PAC coverage (the foundation is nearly unused)")
    for i,v in enumerate(bti): ax.text(i-w/2, v+0.1, f"{v:.1f}", ha="center", fontsize=7)
    ax.legend(); fig.tight_layout(); fig.savefig(os.path.join(FIG,"fig1_bti_coverage.png"), dpi=130)
    print("fig1_bti_coverage.png")

# --- Fig 2: reachability before vs after ------------------------------------
if have("reach_before.csv"):
    progs=[]; before=[]
    relabel={"redis-check-rdb":"redis-server"}
    with open(os.path.join(RES,"reach_before.csv")) as f:
        for r in csv.DictReader(f):
            progs.append(relabel.get(r["program"], r["program"]))
            before.append(int(r["reachable_before"]))
    fig,(a1,a2)=plt.subplots(1,2,figsize=(11,4))
    a1.bar(progs, before, color="#34495e"); a1.set_ylabel("reachable cross-DSO functions")
    a1.set_title("Attack surface of distro binaries BEFORE (Arm64, Deliverable 1)")
    a1.tick_params(axis="x",rotation=20)
    for i,v in enumerate(before): a1.text(i,v+100,str(v),ha="center",fontsize=7)
    # OUR-OWN-BUILD sqlite3 before/after (apples-to-apples: same binary family)
    B_ALL,A_ALL,B_D,A_D = 3816,23,32,1
    a2.bar([0,1],[B_ALL,B_D],0.35,label="before",color="#34495e")
    a2.bar([0.4,1.4],[A_ALL,A_D],0.35,label="after (jail)",color="#27ae60")
    a2.set_xticks([0.2,1.2]); a2.set_xticklabels(["all reachable","dangerous"])
    a2.set_yscale("symlog")
    a2.set_title("our sqlite3 build: before→after  "
                 f"({100*(B_ALL-A_ALL)/B_ALL:.1f}% / {100*(B_D-A_D)/B_D:.1f}%)")
    a2.legend()
    for xi,v in zip([0,1,0.4,1.4],[B_ALL,B_D,A_ALL,A_D]): a2.text(xi,v*1.1+0.3,str(v),ha="center",fontsize=8)
    fig.tight_layout(); fig.savefig(os.path.join(FIG,"fig2_reachability.png"),dpi=130)
    print("fig2_reachability.png")

# --- Fig 3: runtime overhead with 95% CI and the noise floor ----------------
rows=[]
for name,csvf in [("Indirect-call\nmicrobench\n(worst case)","bench_micro.csv"),
                  ("SQLite\nworkload","bench_sqlite.csv"),
                  ("liboqs\nML-KEM-768","bench_oqs.csv")]:
    if not have(csvf): continue
    d=_load(csvf)
    if "base" in d and "jail" in d:
        m,lo,hi=_ci(d["base"],d["jail"]); rows.append((name,m,lo,hi))
# noise floor from the A/A control
floor=None
if have("bench_sqlite_aa.csv"):
    d=_load("bench_sqlite_aa.csv"); _,flo,fhi=_ci(d["base"],d["jail"]); floor=(flo,fhi)
if rows:
    fig,ax=plt.subplots(figsize=(7.5,4.2))
    names=[r[0] for r in rows]; ov=[r[1] for r in rows]
    lo=[r[1]-r[2] for r in rows]; hi=[r[3]-r[1] for r in rows]
    if floor:
        ax.axhspan(floor[0],floor[1],color="#bbbbbb",alpha=0.35,
                   label=f"A/A noise floor [{floor[0]:+.1f}%,{floor[1]:+.1f}%]")
    bars=ax.bar(names, ov, 0.5, yerr=[lo,hi], capsize=6, color="#8e44ad")
    ax.set_ylabel("runtime overhead vs unhardened (%)")
    ax.set_title("Jail overhead on Apple M4 (median, 95% bootstrap CI; interleaved; BTI on in both)")
    ax.axhline(0,color="k",lw=0.6)
    for i,(_,m,l,h) in enumerate(rows):
        sig = "" if (l<=0<=h) else "  (significant)"
        tag = f"{m:+.1f}%" + ("  n.s." if (l<=0<=h) else "*")
        ax.text(i, h+0.3, tag, ha="center", fontsize=9)
    ax.legend(fontsize=8, loc="upper right")
    fig.tight_layout(); fig.savefig(os.path.join(FIG,"fig3_overhead.png"),dpi=130)
    print("fig3_overhead.png")
print("figures in", FIG)
