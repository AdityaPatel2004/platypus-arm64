# Restricting Cross-Library Control Flow on AArch64

An AArch64 port of PLaTypus's cross-module control-flow confinement ("execution
jails"), evaluated on an Apple M4 Pro running Arm64 Linux. Before every
**indirect** call, an out-of-tree LLVM 20 pass clamps the target into the
caller's own module, so a hijacked function pointer cannot reach
`system()`/`execve()` in another library. It relies on Arm **BTI** to stop jumps
into the middle of the clamp.

- **`REPORT.md`**: the write-up and every number (4 Nov 2026 revision)
- **`AUDIT_RESPONSE.md`**: what the 4 Nov audit found and what was done about each item
- `docs/design_note_mask_encoding.md`: the four clamp encodings (RQ2)
- `PROGRESS_LOG.md`: build history · `REVIEW.md`: the earlier 21 Oct review (historical)

## Headline (M4, 4 Nov 2026)

- A hijack that reaches the real `system()` under BTI alone is **blocked** in
  every hardened build, and so is a write-then-hijack attack that bypassed the
  21 Oct build.
- Cross-library reach: sqlite3 **3,816 → 26** (99.3%), redis-server
  **3,816 → 7** (99.8%), measured from the binaries.
- SQLite is byte-identical in 4 storage modes; speedtest1 and redis checks match.
- Cost: real workloads ≤ ~2% (Option B on SQLite), C/D indistinguishable from
  zero. Worst-case clamp microbenchmark +3.6% (C) to +11% (D).
- Ubuntu 24.04: 0.1% of files carry the BTI marker. GCC's runtime libraries
  contain thousands of landing pads but lose the marker at link time.

## Layout

```
pass/JailPass.cpp     the pass: JAIL=mask (B) | pcrel (D) | aligned (C) | check | audit
runtime/jail_rt.c     start-up routine (read-only masks, fail-closed, C/D window check)
runtime/crt_bti.S     BTI-marked _start (24.04's glibc crt files lack the marker)
bin/a64cc             compiler driver (native, or A64_CROSS=1 from x86-64)
tools/                reach.py, reach_after_bin.py, asm_audit.py, btiscan.sh, bti_pads_scan.sh, plots_v2.py
tests/                bti_probe, toy_indirect, hijack_poc, mask_attack_poc, check_correctness.sh
bench/                bench.py (interleaved, CI), build_all.sh, build_redis.sh, run_all_benches.sh, ...
targets/dl/           pinned source archives (SQLite 3.54.1, redis 7.2.5) + prebuilt amalgamation
results/m4_2026-11-04/   raw data of the 4 Nov run      results/figs/  figures
results/oct21_superseded/  the 21 Oct benchmark CSVs (withdrawn; kept for the record)
run_all.sh            one command to rebuild and re-check everything natively
platypus-arm64.bundle git history (clone with: git clone platypus-arm64.bundle)
```

## Reproduce in the Lima VM (Ubuntu 24.04 arm64, on the M4)

Run these in the macOS Terminal. Each line is explained after the block.

```bash
limactl start e0256                       # start the VM made in Week 1
limactl shell e0256                       # open a shell inside it
cp -r "/Users/adityapatel/Downloads/System Security/Sem project/platypus-arm64" ~/pa
cd ~/pa && bash bin/provision.sh          # once: LLVM 20, cmake, pyelftools, ...
bash run_all.sh                           # build + security demos + correctness + audits (~15 min)
BENCH=1 bash run_all.sh                   # ... and all benchmarks (~30 min more)
python3 tools/plots_v2.py                 # figures
```

- `limactl shell` puts you *inside* Linux. The Mac's home folder is visible
  there read-only, which is why the project is copied to `~/pa` first.
- `run_all.sh` builds the pass, four configurations of every program, runs
  the attack demos, the correctness checks, the machine-code audit and the
  reachability counts, and writes everything to `results/native_<date>/`.
- Copy results back to the Mac with `cp -r ~/pa/results/native_* "/Users/adityapatel/..."`
  from inside the VM only if your Lima mount is writable; otherwise use
  `limactl copy e0256:~/pa/results ./results_lima` from the Mac Terminal.

## Usage

```bash
JAIL=pcrel bin/a64cc -O2 prog.c -o prog          # Option D (recommended default)
JAIL=aligned JAIL_K=22 bin/a64cc -O2 prog.c -o p # Option C (cheapest clamp; window 2^22)
JAIL=mask bin/a64cc -O2 prog.c -o prog           # Option B (PLaTypus-style masks)
JAIL=audit bin/a64cc -O2 prog.c -o prog          # count out-of-jail calls, no enforcement
JAIL_VERBOSE=1 ./prog                            # print the window + soundness check
```
Licence: MIT (same as the upstream PLaTypus reference).
