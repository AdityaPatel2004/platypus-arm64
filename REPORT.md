# Restricting Cross-Library Control Flow on AArch64 — Working Report

**E0-256 System Security · submission #25951 · an AArch64 port of PLaTypus's
cross-module control-flow defence ("execution jails")**
Aditya Patel · Platform: Apple M4 Pro, Arm64 Linux (Ubuntu 24.04.5 LTS in a Lima
VM, native hardware virtualization — not emulation)

> Living lab report; every number traces to a raw file under `results/`. The
> authoritative runs are on the M4 via the Lima VM `e0256`. (An earlier
> exploratory session used QEMU emulation for correctness sanity only; no timing
> from it is used, and the `starter/` files originated there.) Reproduce from
> `bin/provision.sh` + `tools/fetch_sqlite.sh` + the commands in each section.
>
> **This report incorporates an independent review (`REVIEW.md`): the SQLite
> before/after now uses our own build, overhead was re-measured interleaved with
> confidence intervals, and several bugs were fixed. Corrections are flagged ⟲.**

## Headline results

| # | Question | Result (Apple M4, Arm64 Linux) |
|---|----------|-------------------------------|
| RQ3 | Is the BTI foundation present in the wild? | **0.1%** of Ubuntu 24.04 arm64 ELF files carry BTI (2/2100); PAC also **0.1%** ⟲ |
| — | Is BTI enforced when we ship it? | **Yes** — skip-landing-pad indirect jump → SIGILL (GO) |
| — | Does BTI alone stop a cross-library hijack? | **No** — unhardened PoC reaches real `system()` and runs a shell |
| RQ1 | How much cross-library reach does the jail remove? | our sqlite3 build **3,816 → 23** functions (**99.4%**) ⟲; dangerous **32 → 1** |
| RQ2 | What does it cost on Apple Silicon? | real workloads (SQLite, liboqs) **not distinguishable from zero** (≤ ±1.5% noise floor); worst-case microbench **+5.2%** [3.9, 5.7] ⟲. Mask encoding = **Option B**; design note in `docs/` |
| — | Completeness of the clamp | **1761/1761** indirect calls (`blr`) in hardened sqlite are clamped (`tools/asm_audit.sh`) |
| — | Arm PLT ("move the desks out") | AArch64 PIE PLT entries carry **no `bti` landing pad**, so BTI already blocks landing on them — no PLT relocation needed |

Figures: `results/figs/fig1_bti_coverage.png`, `fig2_reachability.png`,
`fig3_overhead.png`.

---

## 0. Environment and the BTI go/no-go gate  ✅ GO

Ubuntu 24.04.5 LTS, kernel 6.8.0-142, glibc 2.39, aarch64, 4 vCPU / 8 GB, Apple
Virtualization.framework via Lima; CPU features include `bti paca pacg dit`
(implementer 0x61). LLVM 20.1.8 + lld-20.

**Finding — 24.04's glibc startup objects are not BTI-marked.** A plain
`clang-20 -mbranch-protection=standard` yields an executable with no BTI note
(linker ANDs the GNU-property note across inputs; `Scrt1.o/crti.o/crtn.o` lack
it). `-z force-bti` then SIGILLs at startup (`_start` entered indirectly, no
landing pad). **Fix (`bin/a64cc`):** supply a BTI-marked `_start`
(`runtime/crt_bti.S`), use gcc-13 `crtbeginS.o/crtendS.o` (BTI-marked on 24.04),
omit glibc `crti/crtn`, force the note. (Linker warnings are kept and logged, not
suppressed — bug #13 fixed.)

**Probe (`tests/bti_probe.c`):** normal call runs; `tgt+4` (skip the `bti c`) →
**SIGILL**; control build without the flag does not trap. **BTI is enforced → GO.**

---

## 1. Deliverable 1 — cross-library reachability  ✅

`tools/reach.py` resolves a program's loaded DSOs (`ldd`), counts exported
`.dynsym` functions in *other* modules (the cross-module landing pads a hijacked
indirect call could reach), and flags a 32-entry dangerous set.

**Distro binaries (ecosystem attack surface):** every target can reach the whole
dangerous set (libc is loaded in all).

| Program | Loaded DSOs | Reachable cross-DSO | Dangerous |
|--------|---:|---:|---:|
| nginx | 7 | 8 764 | 32 |
| redis-server¹ | 17 | 15 931 | 32 |
| curl | 32 | 14 948 | 32 |
| sqlite3 (distro) | 7 | 6 022 | 32 |
| openssl | 4 | 8 584 | 32 |

¹ `/usr/bin/redis-server` realpaths to the multi-call `redis-check-rdb` image.
⟲ The distro `sqlite3` (6,022) loads `libsqlite3.so`, so its own API exports are
counted as "other-module" — valid as an ecosystem number but **not** the baseline
for our defence; §4d uses our own build instead.

---

## 2. Deliverable 2 — distribution-wide BTI/PAC coverage  ✅

`tools/btiscan.sh` reads each ELF's `AArch64 feature:` GNU-property line.
⟲ **Bug #14 fixed:** the earlier scan grepped the whole note and counted
`FDO_PACKAGING_METADATA` (the substring "PAC") as PAC — inflating PAC to 3.8%.
Matching only the feature line gives the true figure.

| Directory | ELF | with BTI | with PAC |
|-----------|---:|---:|---:|
| /usr/bin | 704 | 0 | 0 |
| /usr/sbin | 242 | 0 | 0 |
| /usr/lib/aarch64-linux-gnu | 1 154 | 2 | 2 |
| **Total** | **2 100** | **2 (0.1%)** | **2 (0.1%)** |

libc, libssl, libcrypto, bash, curl, python3, nginx, redis, sqlite3: none.
**RQ3: both BTI and PAC are ~0.1% — the foundation this class of defence needs is
essentially unused in the wild**, so a defence standing on BTI must ship BTI
itself (which `a64cc` does).

---

## 3. Deliverable 3 — the AArch64 hardening pass  ✅

**Design (Option B).** AArch64 `AND`/`ORR` immediates can only encode logical
(replicated) bit patterns, not an arbitrary address mask, so the masks are
**loaded** from two hidden module-local globals (`__jail_ormask/__jail_andmask`),
filled at start-up by `runtime/jail_rt.c`'s `dl_iterate_phdr` constructor, which
derives the smallest 2^k-aligned block covering the module. Full rationale and
the A/B/C trade-offs (RQ2): **`docs/design_note_mask_encoding.md`** (#4).

**Pass (`pass/JailPass.cpp`, LLVM 20, OptimizerLast).** Before every indirect
call/invoke it inserts `(t|ormask)&andmask` (mask mode) or a call to
`__jail_check/__jail_audit`. Fake-PLT (below) handles address-taken imports.
Modes selected via the `JAIL` env var. ⟲ bugs #10 (preserved-analyses),
#11 (comment) fixed; coverage caveats documented in the header.

**Completeness (`tools/asm_audit.sh`, #12).** Register-precise check on the final
machine code: **every `blr` in the hardened sqlite3 (1761/1761) is clamped**; `br`
(278) are PLT/fake-PLT jumps, not call sites. Not covered by the pass: computed
`goto` (`indirectbr`, whose targets are in-module block addresses anyway) and
hand-written assembly (none in these targets); these are stated, not assumed.

**Toy (`tests/toy_indirect.c`).** Clamp visible before the `blr`
(`ldr` ormask, `ldr` andmask, `orr`, `and`, `blr`); program correct.

---

## 4. Deliverable 4 — evaluation

### 4a. Security demonstration — blocked hijack  ✅
`tests/hijack_poc.c`: a 24-byte overflow overwrites a function pointer with
libc's **real** `system` address (fetched via `dlsym`, i.e. a genuine
out-of-module pointer), then the program makes its normal indirect call. BTI on
in both builds.
- **Unhardened:** the shell runs (`uid=501…`) — BTI alone does not stop it.
- **Hardened:** process killed, **no shell** — the clamp bent `system` out of
  reach. (Dies via SIGSEGV here — the clamped address fell in an unmapped part of
  the module's reserved block; a clamp onto mapped non-landing-pad code would
  SIGILL via BTI. Both block the escape.)

### 4b. Correctness on a real program — SQLite  ✅
`tests/check_correctness.sh` builds sqlite3 (amalgamation 3.54.1) both ways and
runs `tests/sql_battery.sql` (20k-row recursive insert, index, join, group-by,
aggregates). **Byte-identical output, md5 `afbbd05eb9ca0102`** (reproducible;
#16). The pass clamps 1,937 IR indirect calls across SQLite.
⟲ Limitation surfaced: 2 **variadic** address-taken imports (`fcntl64`,
`mremap`) cannot be `musttail`-stubbed and are left un-stubbed; if ever called
*indirectly* they would be clamped. SQLite's exercised paths do not (audit below);
noted in §7.

### 4c. Runtime overhead ⟲ (interleaved, 21 reps, pinned core 1, 95% bootstrap CI, permutation p)
The first measurement ran all of one config then the other, which injected
run-order bias (#6/#15). Re-measured **interleaved** (base,jail,base,…), with an
**A/A control** (base vs base) to establish the noise floor:

| Workload | overhead (median) | 95% CI | verdict |
|----------|------------------:|--------|---------|
| **A/A control** (noise floor) | +0.08% | [−1.4%, +1.7%] | n.s. (defines the floor) |
| Indirect-call microbench (worst case) | **+5.21%** | [+3.9%, +5.7%], p<0.001 | **real** |
| SQLite (100k ins + 100k queries) | −0.14% | [−2.1%, +4.4%], p=0.87 | not distinguishable from 0 |
| liboqs ML-KEM-768 | +0.04% | [−0.7%, +0.6%], p=1.0 | not distinguishable from 0 |
| fake-PLT ablation (on vs off) | −0.47% | [−2.5%, +1.4%], p=0.71 | not distinguishable from 0 |

**Reading:** the per-call clamp genuinely costs ~5% in a loop that does nothing
but indirect calls (the worst case), but on real workloads (a database, a PQC
library) the cost is **below this VM's ~1.5% noise floor** — i.e. no measurable
slowdown, consistent with PLaTypus's "<1% on real apps". ⟲ The earlier
"+2.71% / +0.96% / +0.32%" figures were run-order artifacts and are withdrawn.
Raw: `results/bench_*.csv` (+ `.meta` with exact flags).

### 4d. Reachability AFTER hardening ⟲ (our own build, apples-to-apples)
`reach.py --after` on our own sqlite3 (same source, unhardened vs hardened), with
the clamp window verified to contain no other module's code (#2, `JAIL_VERBOSE`
reports 0 overlaps):

| | reachable cross-DSO | dangerous |
|--|--:|--:|
| our sqlite3 **before** | 3 816 | 32 |
| our sqlite3 **after** | **23** | **1** (`mmap64`) |
| reduction | **99.4%** | **96.9%** |

`system`, `execve*`, `popen`, `dlopen`, `mprotect`, `fork`, … all unreachable;
the one survivor (`mmap64`) is a function sqlite legitimately address-takes.

## 5. Deliverable 5 (stretch) — liboqs (post-quantum)  ✅
liboqs (ML-KEM-768) built twice through the pass. Shared secrets agree hardened
and unhardened; overhead **not distinguishable from zero** (§4c). Fake-PLT set =
5 (`aligned_alloc`, `explicit_bzero`, `getentropy`, `memalign`,
`posix_memalign`) — all memory/RNG helpers, **none dangerous**.

## 6. Additional results from the review

- **Arm PLT (#5).** `objdump -d -j .plt` on a hardened binary: PLT0 has `bti c`
  but individual PLT entries (`memcpy@plt`, …) have **no landing pad**, so BTI
  already forbids a hijacked indirect call from landing on a PLT stub. This is the
  AArch64 answer to PLaTypus §3.3.3 ("move the desks out"): the PLT needs no
  relocation on Arm. Our fake-PLT trampolines *do* carry `bti c` then `b …@plt`.
- **Window soundness (#2).** For the hardened PIE executables, the constructor
  reports **0** other-module executable segments inside the clamp window, so the
  "after = fake-PLT set" count is verified, not assumed. (Would need re-checking
  for a hardened shared library sharing address space.)

## 7. Limitations & threat model ⟲
- **Scope (#3).** Only sqlite3 (real app) and liboqs (stretch library) were
  hardened end-to-end; nginx/redis/curl/openssl appear only in the Deliverable-1
  measurement. A from-source hardened server (redis) is future work.
- **Writable masks (#9).** The mask globals stay writable for the process
  lifetime. PLaTypus keeps them in RELRO. We cannot: they are written by a
  constructor (after RELRO is applied), so a read-only placement would need a
  post-constructor `mprotect` on a dedicated page — listed as a limitation.
- **Variadic address-taken imports** (`fcntl64`, `mremap`) are not stubbed
  (musttail cannot forward varargs); un-exercised here but a correctness gap if
  such a function were called indirectly.
- **Metric caveat (#7).** The 99.4% reach reduction is one program on an
  exported-symbol metric (not landing-pad instructions) with fake-PLT, so it is
  *comparable in magnitude to*, not a reproduction of, PLaTypus's >98%.
- **Masks set at start-up**, not before any code runs (the dl_iterate_phdr trade,
  vs the paper's loader): a slightly wider race window, stated as accepted.

---
## Appendix — layout & reproducibility
```
bin/provision.sh  tools/fetch_sqlite.sh  — environment + source
bin/a64cc                                 — BTI-enforcing driver (JAIL=mask|check|audit)
pass/JailPass.cpp  runtime/jail_rt.c  runtime/crt_bti.S
tools/reach.py  tools/btiscan.sh  tools/asm_audit.sh  tools/plots.py
tests/bti_probe.c  toy_indirect.c  hijack_poc.c  sql_battery.sql  check_correctness.sh
bench/* (sqlite/micro/liboqs harnesses, run_bench.sh interleaved, stats.py with CI)
docs/design_note_mask_encoding.md     results/*.csv (+ .meta)   results/figs/*.png
```
