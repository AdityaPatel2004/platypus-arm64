#!/usr/bin/env python3
"""bench.py — interleaved, pinned, multi-config benchmark runner.

Each config is a shell command that prints "<seconds> <checksum>" as its first
line (self-timed: the program times only its own work). Configs run
round-robin (base, B, D, base, B, D, ...) so slow drift hits all of them
equally; every rep's checksum must equal the base's or the run stops.

  bench.py NAME REPS CORE base='cmd' mask='cmd' pcrel='cmd' [aa='cmd' ...]

Writes results/bench_NAME.csv (config,rep,seconds) and results/bench_NAME.meta,
then prints per-config median/IQR and, for every non-base config, the overhead
vs base: median difference, 95% bootstrap CI, two-sided permutation p.
"""
import csv, os, platform, random, statistics as st, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(cmd, core):
    full = f"taskset -c {core} {cmd}" if core != "-" else cmd
    p = subprocess.run(full, shell=True, capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"FAILED (exit {p.returncode}): {full}\n{p.stderr[-2000:]}")
    first = p.stdout.strip().splitlines()[0].split()
    return float(first[0]), (first[1] if len(first) > 1 else "")

def overhead(b, j):
    return 100.0 * (st.median(j) - st.median(b)) / st.median(b)

def boot_ci(b, j, B=10000, rng=random.Random(12345)):
    xs = sorted(overhead([rng.choice(b) for _ in b], [rng.choice(j) for _ in j])
                for _ in range(B))
    return xs[int(0.025 * B)], xs[int(0.975 * B)]

def perm_p(b, j, B=10000, rng=random.Random(54321)):
    obs = abs(st.median(j) - st.median(b)); pool = list(b) + list(j); nb = len(b); c = 0
    for _ in range(B):
        rng.shuffle(pool)
        if abs(st.median(pool[nb:]) - st.median(pool[:nb])) >= obs - 1e-15: c += 1
    return c / B

def summarize(path):
    d = {}
    with open(path) as f:
        for r in csv.DictReader(f):
            d.setdefault(r["config"], []).append(float(r["seconds"]))
    print(f"\n{'config':8} {'n':>3} {'median_s':>10} {'IQR_s':>9}")
    for c, xs in d.items():
        q = st.quantiles(xs, n=4)
        print(f"{c:8} {len(xs):>3} {st.median(xs):>10.5f} {q[2]-q[0]:>9.5f}")
    out = []
    for c, xs in d.items():
        if c == "base": continue
        ov = overhead(d["base"], xs); lo, hi = boot_ci(d["base"], xs); p = perm_p(d["base"], xs)
        v = "not distinguishable from zero" if lo <= 0 <= hi else "distinguishable from zero"
        print(f"  {c:8} vs base: {ov:+.2f}%  95% CI [{lo:+.2f}%, {hi:+.2f}%]  perm p={p:.3f}  -> {v}")
        out.append((c, ov, lo, hi, p))
    return out

def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "--summary":
        summarize(sys.argv[2]); return
    name, reps, core = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    cfgs = [a.split("=", 1) for a in sys.argv[4:]]
    assert cfgs[0][0] == "base", "first config must be base"
    os.makedirs(f"{ROOT}/results", exist_ok=True)
    csvp, metap = f"{ROOT}/results/bench_{name}.csv", f"{ROOT}/results/bench_{name}.meta"
    with open(metap, "w") as m:
        m.write(f"date: {time.strftime('%Y-%m-%dT%H:%M:%S%z')}\nname: {name}\nreps: {reps}\ncore: {core}\n")
        m.write(f"host: {platform.node()} {platform.machine()} {platform.release()}\n")
        for c, cmd in cfgs: m.write(f"config {c}: {cmd}\n")
    for c, cmd in cfgs:                                   # warm-up + checksum gate
        run(cmd, core)
    ref = run(cfgs[0][1], core)[1]
    with open(csvp, "w", newline="") as f:
        w = csv.writer(f); w.writerow(["config", "rep", "seconds"])
        for r in range(1, reps + 1):
            for c, cmd in cfgs:
                s, chk = run(cmd, core)
                if chk != ref:
                    sys.exit(f"CHECKSUM MISMATCH in {c} rep {r}: {chk} != {ref}")
                w.writerow([c, r, f"{s:.6f}"]); f.flush()
    print(f"raw -> {csvp}  meta -> {metap}  (checksum {ref} matched in every run)")
    summarize(csvp)

if __name__ == "__main__":
    main()
