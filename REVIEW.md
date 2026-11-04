# Review of the platypus-arm64 work — 21 Oct 2026

Reviewed like a second student checking a teammate's project before the write-up. Every code file was read; the raw CSVs were re-analysed; the pass, toy test and microbenchmark were rebuilt independently from the folder's own source with LLVM 20 (run under QEMU emulation, for correctness only — no timing from that run is used).

**Verdict: the core system is real and works, but the project is not yet "only documentation left".** Seven claims in `REPORT.md` need correcting or re-measuring, two proposal promises are only partly met, and there are a handful of code bugs. Nothing looks invented: every number traced back to a raw file.

---

## 1. What checks out (verified)

| Item | How it was checked | Result |
|---|---|---|
| Pass builds and works | Rebuilt `pass/JailPass.cpp` from source with LLVM 20; compiled `toy_indirect.c` and `indirect_micro.c` hardened | Builds cleanly; toy prints `r=21` / `r=40` in both builds; pass reports 1 clamped call each |
| Clamp is really in the hot path | Disassembled the hardened microbenchmark | `ldr` (or-mask), `ldr` (and-mask), `orr`, `and`, `blr` sit inside the loop — the microbenchmark measures what it claims |
| Overhead medians in `REPORT.md` | Recomputed from `results/bench_*.csv` | All match: SQLite +2.71%, micro +0.32%, liboqs +0.96%, ablation +2.24% / +3.38% |
| BTI scan numbers | Re-counted `results/bti_scan.csv` | 2,095 ELF files, 2 with BTI, 80 with PAC — matches; the flagged files (systemd, gcc runtime libs, libnfnetlink, libnetfilter_conntrack) look like genuine detections |
| "Before" reachability numbers | Read `results/reach_before.csv` | Match the report table |
| SQLite version 3.54.1 | Web search | Real release ([Phoronix](https://phoronix.com/news/SQLite-3.54-Released), [warp2search](https://www.warp2search.net/story/sqlite-3541-released-fixes-32bit-heapbuffer-overflow/)) |
| Deliverables 1, 2, 3, 5 exist | Against the proposal's table | Tool + dataset (5 programs), probe + scan, pass + start-up routine, liboqs stretch — all present |

---

## 2. Must fix before writing up (claims that are wrong or unsupported)

1. **The sqlite3 before/after comparison uses two different programs.** "Before" (6,022) was measured on the distro's `/usr/bin/sqlite3`, which loads `libsqlite3.so` — so its own ~hundreds of SQLite API exports are counted as "other library" functions. "After" (23) comes from *our* statically-built amalgamation. Fix: run `reach.py` on our own **unhardened** sqlite3 build as the "before"; the 99.6% will change. Demo 5 in `run_demos.sh` has the same mix-up.
2. **"After" is not measured from the hardened binary.** It is just the list of fake-PLT stubs the pass wrote out, and it silently assumes the clamp window contains only the module's own code. The window is the smallest power-of-two block covering the module, so it is larger than the module: in the rebuild, a ~198 KiB module got a 256–512 KiB window. Add a check (e.g. in `jail_rt.c` verbose mode, walk `dl_iterate_phdr` and report any other module's executable segment inside the window) and report the result. For a PIE executable this is probably empty, because libraries are mapped far away — but it is untested, and it matters for any hardened shared library.
3. **Scope vs the proposal.** The proposal fixes the evaluation at five programs (nginx, redis, curl, sqlite3, openssl). Only sqlite3 was hardened (plus liboqs, the stretch). `REPORT.md` does not say this up front; it is only in the progress log as "deferred". Either harden at least one server (redis is the easiest build) or state the reduced scope plainly in the report's first table.
4. **Research question 2 is only half answered.** The proposal says the port "must choose between a reserved register, a memory load, or aligned jail placement … and the trade-offs will be measured". Only the memory load (Option B) was built and measured, and the promised design note on the mask-encoding decision is missing. At minimum, write the design note and give the reasoned (unmeasured) trade-offs; ideally measure one alternative.
5. **The Arm PLT question is missing.** The proposal's contribution section says placing PLT stubs outside the jail "must be re-derived" for Arm. The report never addresses it. A lead from the earlier cloud session: with lld, AArch64 PIE PLT entries carry no `bti c` landing pad (only PLT0 does), so BTI already stops indirect calls from landing on them. Verify this on the M4 (`objdump -d -j .plt` on a hardened binary; also try `-fuse-ld=bfd`) and write it up — it is the Arm answer to PLaTypus §3.3.3.
6. **Statistics are over-read.**
   - Microbenchmark +0.32%: 95% bootstrap CI −0.15% to +1.38%, permutation p = 0.27 → **not distinguishable from zero**. The report calls it "the pure per-call clamp cost ~0.3%"; it should say the cost is below what 11 runs can resolve.
   - liboqs +0.96%: CI +0.02% to +1.52%, p ≈ 0.05 → borderline; say so.
   - SQLite +2.71%: CI +0.86% to +3.52%, p = 0.001 → real. It is ~10× the paper's 0.28% for SQLite and needs a sentence on why.
   - Ablation: the report says fake-PLT on vs off is "within noise", but no-fake-PLT is *slower* than with-fake-PLT by +1.11% (p = 0.03). Removing stubs cannot plausibly slow it down, so this is almost certainly run-order drift: `run_bench.sh` runs all of one config, then all of the next. Re-run interleaved (A B A B …) and add an A/A run (baseline vs baseline) to show the noise floor.
   - The report says "15 runs" for every benchmark; `bench_micro.csv` and `bench_ablation.csv` have **11**.
7. **Over-claims and stale text in `REPORT.md` / `README.md`:**
   - "This meets/exceeds the paper's Intel figure (>98%)" — one program, a different metric (exported symbol names vs landing-pad instructions), and no callback handling. Say "comparable in magnitude, on a different metric".
   - "Nothing was run on cloud or emulated hardware" — the `starter/` files and the report doc's "early findings" came from a QEMU cloud session. Say the M4 runs are the authoritative ones.
   - Title "Execution Jails for ARM64": the submitted title is "Restricting Cross-Library Control Flow on AArch64", and leading with "Execution Jails" was rejected on 9 Sep (it collides with FreeBSD jails).
   - `reach.py`'s docstring advertises a `--count-landing-pads` option that does not exist.

---

## 3. Code bugs and robustness issues

| # | File | Issue | Effect on current results |
|---|---|---|---|
| 8 | `runtime/jail_rt.c` | `__jail_check` and `__jail_audit` have default (exported) visibility (confirmed with `readelf -s`). With two hardened modules (e.g. an executable plus a hardened `.so`), both modules' calls bind to one copy, which uses that module's masks. Mark them `visibility("hidden")` like the masks. | None yet — only single-module programs were hardened |
| 9 | `runtime/jail_rt.c` | The masks are ordinary writable globals for the program's whole life. PLaTypus keeps them in read-only (RELRO) memory. Either put them on their own page and make it read-only after the constructor runs, or list this as a limitation in the threat model. | Threat-model text must mention it |
| 10 | `pass/JailPass.cpp` | Returns `PreservedAnalyses::all()` when it added fake-PLT stubs but clamped no calls (the module *was* changed). Should be `none()` whenever `nTramp > 0`. | Unlikely to have mattered; still incorrect |
| 11 | `pass/JailPass.cpp` | Header comment still says `-mllvm -jail-mode=`; the mode actually comes from the `JAIL` environment variable at compile time. | Docs only |
| 12 | `pass/JailPass.cpp` | No completeness check: computed `goto` (`indirectbr`) is not handled, hand-written assembly is never instrumented, and nothing verifies that the masked register reaches `blr` without being spilled. Add an "asm audit" script that counts every `blr`/`br` in the final binaries and checks each is preceded by the clamp; report the uninstrumented count. | Needed for an honest completeness claim |
| 13 | `bin/a64cc` | `-Wl,--no-warnings` hides **all** linker warnings, including `-z force-bti` warnings about input objects that lack BTI (relevant for liboqs, which may contain assembly). Remove it and keep the warnings in a log. The driver also always adds `_start`, which would be wrong for `-shared` builds. | Unknown whether any liboqs object lacked BTI |
| 14 | `tools/btiscan.sh` | Greps the whole `readelf -n` output for "BTI"/"PAC", case-insensitive. Match only the `AArch64 feature:` line. | Current numbers look right |
| 15 | `bench/run_bench.sh` | Runs configs in blocks (order bias), discards build errors (`2>/dev/null`), and carries on after a checksum MISMATCH. Interleave runs, stop on mismatch, and save the exact command and flags next to each CSV. | Explains the odd ablation result |
| 16 | reproducibility | No script fetches the SQLite amalgamation, and the SQL "battery" behind the identical-md5 claim is not in the repo. liboqs is cloned unpinned (record the commit hash). The progress log elides the exact `run_bench.sh` arguments with "…". | The correctness claim can't be re-run as is |

---

## 4. Demos (`demos/run_demos.sh`, `DEMO_GUIDE.md`)

- The script says it "rebuilds anything missing", but nothing fetches the SQLite source (`targets/sqlite_src/sqlite-amalgamation-3540100`), so demo 5 fails on a fresh VM.
- Every build line sends errors to `/dev/null`. If a build fails during the talk, the next line runs a stale or missing binary with no visible error. Fail loudly instead.
- Demo 5 repeats the before/after mix-up from item 1.
- Demo 3's `awk` extracts lines from `main` up to the first `blr`. It works for the toy, but check the printed lines are exactly the clamp before presenting.
- `fig2_reachability.png` labels the redis bar "redis-check-rdb". Call it "redis-server" (the same multi-call binary) to avoid a question. Its right panel shows the item-1 mix-up, and the "dangerous" bars are invisible on that scale.
- `fig3_overhead.png`: the micro and liboqs error bars cross zero, which supports item 6. The caption should say so rather than present the bars as costs.
- The hijack proof-of-concept itself was not reviewed here; only the build and measurement steps around it were.

---

## 5. Suggested order of fixes

1. Re-measure: our-own-baseline "before" (1), the window-overlap check (2), interleaved benchmark re-runs with an A/A control (6, 15).
2. Fix code bugs 8, 10, 13 and re-run the affected builds and tests.
3. Verify the PLT landing-pad behaviour on the M4 and write the PLT paragraph (5); write the mask-encoding design note (4).
4. Decide on scope (3): harden redis if time allows, or disclose.
5. Correct the text (7), then fill in the report.
