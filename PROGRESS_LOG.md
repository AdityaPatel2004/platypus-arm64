# Progress Log — Execution Jails for ARM64

Timeline note: the 9-week plan was compressed into a focused build sprint. Entries
use the project's 8-field template. Machine state unless stated: Ubuntu 24.04.5
arm64 in Lima VM on Apple M4 Pro, 4 vCPU / 8 GB, native virtualization, idle.

---

## Session A — Environment + BTI go/no-go (Week 1)
- **DID:** Installed Lima; created `e0256` VM (Ubuntu 24.04.5, 4c/8G/40G, vz).
  Provisioned LLVM 20.1.8 + lld-20 from apt.llvm.org, pyelftools 0.30, eval
  targets. Wrote + ran the BTI probe through the project driver. Confirmed BTI
  enforced. Wrote `bin/a64cc`.
- **BROKE:** `clang-20 -mbranch-protection=standard` produced an executable with
  **no BTI note** — linker ANDs the GNU-property note and glibc's
  `Scrt1.o/crti.o/crtn.o` on 24.04 lack it. `-z force-bti` then made it **SIGILL
  at startup** (`_start` in unmarked `Scrt1.o` entered indirectly, no landing pad).
- **DECIDED:** Replace `Scrt1.o` with a BTI-marked `_start` (`runtime/crt_bti.S`),
  use gcc-13 `crtbeginS.o/crtendS.o` (which ARE BTI-marked on 24.04), omit glibc
  `crti/crtn`, `-z force-bti`. Rejected: building a BTI glibc (week-long). Native
  toolchain, not cross (the starter `a64cc` was cross-style).
- **NEXT:** reachability tool.
- **NUMBERS:** CPU features include `bti paca pacg dit`. gcc crtbegin BTI=yes;
  glibc Scrt1/crti/crtn BTI=no; libc.so.6 BTI=no. Probe: normal call ran (r=42),
  skip-pad call → SIGILL → **GO**.
- **COMMANDS:** `bin/a64cc -O1 tests/bti_probe.c -o probe_driver && ./probe_driver`
- **FILES:** `bin/provision.sh`, `bin/a64cc`, `runtime/crt_bti.S`, `tests/bti_probe.c`

## Session B — Reachability + BTI coverage (Weeks 2–3, the floor)
- **DID:** `tools/reach.py` (pyelftools) + `tools/btiscan.sh`. Ran on 5 targets
  and the whole distro.
- **BROKE:** nothing.
- **DECIDED:** Metric = exported `.dynsym` FUNC/IFUNC in other loaded DSOs
  (reproducible proxy for cross-module landing pads). Dangerous list = 32 funcs.
- **NEXT:** the pass.
- **NUMBERS:** reachable before — nginx 8764, redis 15931, curl 14948, sqlite3
  6022, openssl 8584; **all 32 dangerous reachable**. BTI coverage: **2/2095
  (0.1%)**, PAC 80/2095 (3.8%); /usr/bin 0/702. `results/reach_before.csv`,
  `results/bti_scan.csv`.
- **COMMANDS:** `python3 tools/reach.py /usr/sbin/nginx … --csv results/reach_before.csv`;
  `bash tools/btiscan.sh results/bti_scan.csv /usr/bin /usr/sbin /usr/lib/aarch64-linux-gnu`
- **FILES:** `tools/reach.py`, `tools/btiscan.sh`, `results/*.csv`

## Session C — The pass on a toy (Weeks 4–5)
- **DID:** `pass/JailPass.cpp` (LLVM 20, OptimizerLast) + `runtime/jail_rt.c`
  (`dl_iterate_phdr` constructor, 2^k-aligned block, mask globals). Toy clamped,
  correct, clamp visible before `blr`.
- **BROKE:** (1) `find_package(LLVM 20)` rejected → dropped version, pin LLVM_DIR.
  (2) `-mllvm -jail-mode` rejected (plugin loads after -mllvm parsing) → read mode
  from `JAIL` env instead.
- **DECIDED:** Mask-encoding **Option B** (load masks from module global); modes
  mask/check/audit via env. Masks delivered by a startup constructor, not a
  patched loader (the stated trade).
- **NUMBERS:** toy: 1 indirect call clamped; runs r=21/r=40; clamp = `ldr`(or),
  `ldr`(and), `orr`, `and`, `blr`.
- **FILES:** `pass/JailPass.cpp`, `pass/CMakeLists.txt`, `runtime/jail_rt.c`,
  `tests/toy_indirect.c`

## Session D — Security demo + real program + fake-PLT (Weeks 6–7)
- **DID:** Security PoC both ways. Built real sqlite3 CLI hardened; correctness
  battery identical. Implemented fake-PLT (pass v2).
- **BROKE:** Hardened sqlite **SIGILL at ≥100k rows** — `audit`+`dladdr` showed
  424 out-of-jail calls = SQLite VFS calling libc `pread64/pwrite/stat/access/
  __close/__fstat64` via its syscall table (temp-file spill on index build).
  Also fake-PLT first crash: `internal linkage + hidden visibility` assert → drop
  visibility.
- **DECIDED:** Add fake-PLT trampolines (`musttail`) for address-taken imports;
  redirect the stored pointers. PoC now fetches the real `system` addr via
  `dlsym` (not `&system`, which fake-PLT would legitimately stub).
- **NUMBERS:** sqlite clamps 1937 total; battery md5 identical; audit 745,465
  calls / 0 oob (battery), 424 oob (100k bench). fake-PLT: sqlite 20 trampolines.
  PoC: unhardened runs `id`; hardened killed (no `id`).
- **FILES:** `tests/hijack_poc.c`, updated `pass/JailPass.cpp`, `runtime/jail_rt.c`

## Session E — Evaluation + liboqs stretch (Weeks 8–9)
- **DID:** Overhead (15 reps, core 1) for SQLite, microbench, liboqs; fake-PLT
  ablation; reach-after; built liboqs hardened; 3 figures.
- **BROKE:** nothing.
- **DECIDED:** Second real target = liboqs (achievable static-lib build; ties to
  PQC). nginx/redis from-source hardened builds deferred (heavy; SQLite + liboqs
  + microbench give error-barred coverage).
- **NUMBERS:** overhead — SQLite **+2.71%**, microbench **+0.32%**, liboqs
  **+0.96%**; ablation fp +2.24% / nofp +3.38% (noise). reach-after sqlite
  **6022→23 (99.6%)**, dangerous **32→1**. liboqs fake-PLT 5, 0 dangerous.
  `results/bench_*.csv`, `results/figs/*.png`.
- **COMMANDS:** `REPS=15 CORE=1 bash bench/run_bench.sh sqlite …`;
  `bash bench/build_liboqs.sh`; `python3 tools/plots.py`
- **FILES:** `bench/*`, `tools/plots.py`, `REPORT.md`

## Session F — Independent-review corrections (REVIEW.md)
- **DID:** Worked REVIEW.md end to end. Fixed code bugs #8 (hidden visibility on
  __jail_audit/check — verified HIDDEN), #10 (PreservedAnalyses none when
  trampolines added), #11 (header comment), #13 (a64cc: keep+log linker
  warnings, handle -shared), #14 (btiscan match only the AArch64-feature line).
  Added #2 window-soundness check, #12 register-precise asm_audit.sh,
  #16 fetch_sqlite.sh + sql_battery.sql + check_correctness.sh + pinned liboqs
  commit fd44469. Wrote #4 design note and #5 PLT finding. Re-measured all
  benchmarks interleaved with CI + permutation p + A/A control. Rewrote REPORT,
  README, fig2/fig3, run_demos, DEMO_GUIDE. Disclosed scope (#3) in Limitations.
- **BROKE:** #14 fix revealed the old PAC 3.8% was false positives
  (FDO_PACKAGING_METADATA contains "PAC"); real PAC = 0.1%. Interleaved re-run
  revealed the earlier overheads were run-order artifacts.
- **DECIDED:** Disclose reduced scope (sqlite+liboqs hardened) rather than harden
  redis from source (rabbit hole). Document writable-masks (#9) as a limitation
  rather than add a risky post-ctor mprotect.
- **NEXT:** optional — harden a server (redis), Option C aligned jails.
- **NUMBERS (corrected):** BTI 2/2100 (0.1%), PAC 2/2100 (0.1%). reach (our
  build) 3816→23 (99.4%), dangerous 32→1. overhead interleaved: micro +5.21%
  [3.9,5.7] p<0.001; sqlite -0.14% [−2.1,+4.4] n.s.; liboqs +0.04% n.s.;
  ablation n.s.; A/A floor [−1.4,+1.7]. asm audit 1761/1761 clamped. PLT entries
  have no bti pad (BTI blocks landing). window overlap 0.
- **FILES:** all of tools/, pass/JailPass.cpp, runtime/jail_rt.c, bin/a64cc,
  bench/*, docs/design_note_mask_encoding.md, tests/{sql_battery.sql,
  check_correctness.sh}, REPORT.md, README.md, DEMO_GUIDE.md.

---
### Open / optional
- nginx+wrk or redis-benchmark hardened from source (would add a server workload).
- Option C (aligned jails / NaCl-style immediate masks) vs Option B comparison.
- `check` mode measurement at scale; HWASan-style report of blocked escapes.
- RELRO masks (#9): post-constructor mprotect on a dedicated mask page.
- variadic address-taken imports (fcntl64, mremap) fake-PLT via an asm thunk.
