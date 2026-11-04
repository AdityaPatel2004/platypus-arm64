#!/usr/bin/env python3
"""stats.py — per-config summary plus a 95% bootstrap CI and a permutation
p-value for the overhead, so we don't over-read small differences.
"""
import csv, sys, statistics as st, random
random.seed(12345)

def load(path):
    d = {}
    with open(path) as f:
        for row in csv.DictReader(f):
            c = row.get("config") or row.get("cfg")
            d.setdefault(c, []).append(float(row["seconds"]))
    return d

def overhead(b, j):               # % difference of medians
    return 100.0 * (st.median(j) - st.median(b)) / st.median(b)

def boot_ci(b, j, B=10000):
    xs = []
    for _ in range(B):
        bb = [random.choice(b) for _ in b]
        jj = [random.choice(j) for _ in j]
        xs.append(overhead(bb, jj))
    xs.sort()
    return xs[int(0.025*B)], xs[int(0.975*B)]

def perm_p(b, j, B=10000):
    obs = abs(st.median(j) - st.median(b))
    pool = b + j; nb = len(b); cnt = 0
    for _ in range(B):
        random.shuffle(pool)
        d = abs(st.median(pool[nb:]) - st.median(pool[:nb]))
        if d >= obs - 1e-15: cnt += 1
    return cnt / B

def main():
    d = load(sys.argv[1])
    print(f"\n{'config':6} {'n':>3} {'median_s':>10} {'IQR_s':>9} {'mean_s':>10} {'sd_s':>9}")
    for c in ("base", "jail"):
        if c not in d: continue
        xs = sorted(d[c]); q = st.quantiles(xs, n=4) if len(xs) >= 4 else [xs[0], xs[-1], xs[-1]]
        print(f"{c:6} {len(xs):>3} {st.median(xs):>10.5f} {q[2]-q[0]:>9.5f} "
              f"{st.mean(xs):>10.5f} {st.pstdev(xs):>9.5f}")
    if "base" in d and "jail" in d:
        b, j = d["base"], d["jail"]
        ov = overhead(b, j); lo, hi = boot_ci(b, j); p = perm_p(list(b), list(j))
        verdict = ("not distinguishable from zero" if lo <= 0 <= hi else
                   "distinguishable from zero")
        print(f"\noverhead (median): {ov:+.2f}%   95% CI [{lo:+.2f}%, {hi:+.2f}%]   "
              f"perm p={p:.3f}  -> {verdict}")

if __name__ == "__main__":
    main()
