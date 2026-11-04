# Restricting Cross-Library Control Flow on AArch64 — Working Report

**E0-256 System Security · submission #25951 · Aditya Patel**
An AArch64 port of PLaTypus's cross-module control-flow defence ("execution
jails"), evaluated on an Apple M4 Pro running Arm64 Linux.

> **Status: 4 Nov 2026 revision.** This replaces the 21 Oct report. An
> independent audit found that the hardened SQLite crashed on every on-disk
> database, that the masks could be overwritten, and that several numbers were
> over-read. All of that is fixed, re-measured and recorded below. What changed,
> and why, is listed point by point in `AUDIT_RESPONSE.md`. Every number here
> traces to a file under `results/m4_2026-11-04/` or `results/`.

---

## The idea in one page (read first)

A running program is its own code plus shared libraries (libc and others), each
in its own region of memory. Most calls are *direct*: the target is fixed when
the program is built. Some calls are *indirect*: the target address is read
from a variable at run time (callbacks, function tables). If a memory bug lets
an attacker overwrite that variable, the next indirect call goes wherever the
attacker chose. Typically that is `system()` in libc, which runs a shell
command.

Arm's **BTI** (Branch Target Identification) is a hardware check. An indirect
jump may only land on a special "landing pad" instruction, `bti c`, which the
compiler puts at the start of functions. That stops jumps into the *middle* of
code. But any function start in any library is still allowed, so `system()` is
still reachable.

An **execution jail** closes that gap. Think of each module as a fenced yard.
Just before every indirect call, the compiler inserts a few instructions that
**clamp** the target address so it cannot point outside the caller's own yard.
Legitimate calls to other libraries don't use indirect calls. They go through
a fixed table of stubs, the **PLT**: a reception desk that only direct calls
use. So clamping indirect calls costs real programs almost nothing, while a
hijacked pointer can no longer leave the module.

Two details make it work:

- **Fake-PLT stubs.** Sometimes a program *does* store a library function's
  address, for example SQLite's table of system calls (`pread`, `fcntl`, …).
  For each such function the pass builds a two-instruction stub inside the
  module (`bti c; b <function>`) and stores the stub's address instead. The
  pointer now passes the clamp, and the stub still reaches the real function.
- **BTI underneath.** The clamp only helps if an attacker cannot jump *past*
  it. BTI guarantees that, because jumps can only land on landing pads.

PLaTypus (IEEE S&P 2026) built this for Intel only. This project builds it for
Arm64 and asks three questions:

1. **RQ1:** how much cross-library reach does the jail remove on Arm64?
2. **RQ2:** Arm cannot write the clamp the way Intel does, so which encoding
   should it use, and what does each cost?
3. **RQ3:** how much of a real Arm Linux distribution actually turns BTI on?

## Headline results

| Question | Result on the M4 (4 Nov 2026) |
|---|---|
| Is BTI enforced? | **Yes.** A jump that skips the landing pad dies with SIGILL (`tests/bti_probe.c`). |
| Does BTI alone stop a hijack to `system()`? | **No.** The unhardened proof-of-concept runs a shell. |
| Does the jail stop it? | **Yes, in all three encodings.** Hardened builds die before any shell runs. |
| Can an attacker who can write memory switch the jail off? | **Not any more.** The 21 Oct build could be bypassed (shell ran); now the mask write faults. |
| Correctness | SQLite is byte-identical to unhardened in 4 storage modes (in-memory, rollback, WAL, mmap). speedtest1's verification hash and a redis command script also match. |
| RQ1: reach removed | sqlite3 **3,816 → 26** (99.3%); redis-server **3,816 → 7** (99.8%). Measured from the binaries. |
| RQ2: encodings | Worst case (unpredictable targets): C **+3.6%**, A/B **+7.0%**, D **+11.0%**. Cost tracks the number of instructions on the target's dependency chain. With predictable targets all are ≤1.2%. |
| Real-workload cost | redis, speedtest1, sqlite_bench: Option B **+0.9% to +1.8%** on SQLite and ≈0 on redis. C and D are indistinguishable from zero, or below it. |
| Completeness | Every indirect call in hardened SQLite (1,909–1,917) and redis (1,057–1,059) is clamped. The only 2 unclamped branches are in GCC's start-up file. |
| RQ3: BTI in Ubuntu 24.04 | 2 of 2,100 files carry the BTI marker (0.1%; 21 Oct scan). New: GCC's runtime libraries *contain* thousands of landing pads but **no** marker; glibc isn't built for BTI at all. |

Figures: `results/figs/fig2_reach.png`, `fig3_rq2_encoding.png`,
`fig4_overhead.png`, `fig5_bti_pads.png` (plus the 21 Oct
`fig1_bti_coverage.png`).

## Where and how this was measured

- **Hardware:** Apple M4 Pro; CPU features `bti paca pacg dit` (implementer 0x61).
- **Run environment:** an Arm64 Linux VM on the same chip (Ubuntu 22.04
  userland, kernel 6.8, 4 vCPU, Apple virtualization, *not* emulation). Every
  binary runs against **Ubuntu 24.04's glibc 2.39**, the same libc as the Lima
  VM, via its own `PT_INTERP`/`RPATH`. Details: `results/m4_2026-11-04/ENVIRONMENT.txt`.
- **Toolchain:** Ubuntu 24.04's clang 20.1.2, binutils 2.42 and gcc-13 crt
  files (cross packages from `noble-updates`); the pass is built against the
  same LLVM 20.
- **Why not the Lima VM:** this audit session could not type into Terminal,
  so it could not enter Lima. `run_all.sh` reruns everything natively in
  Lima, and that run should be the final confirmation (see README).
- **Benchmarks:** `bench/bench.py`. Configurations run **interleaved**
  (base, B, D, C, base, …) on a pinned core. Each run is checked against the
  unhardened checksum, and overhead is the median difference with a 95%
  bootstrap CI and a permutation p-value. An **A/A run** (unhardened against
  an identical copy) gives the noise floor: ±0.8%.

---

## 1. Environment and the BTI go/no-go ✅

`tests/bti_probe.c` calls a function through a pointer twice: once at its
landing pad (it runs) and once one instruction later (`SIGILL`). **BTI is
enforced → GO** (`results/m4_2026-11-04/security_demo.txt`).

**Finding (kept from 21 Oct, re-confirmed on the 24.04 packages):** Ubuntu
24.04's glibc start-up objects (`Scrt1.o`, `crti.o`, `crtn.o`) carry no BTI
marker. The linker ANDs the marker across every input file, so any program
linked normally loses it. `bin/a64cc` works around this: it uses its own
BTI-marked `_start` (`runtime/crt_bti.S`) and GCC's BTI-marked
`crtbeginS.o`/`crtendS.o`, omits `crti`/`crtn`, and links with `-z force-bti`.

## 2. Deliverable 1 — cross-library reachability ✅

`tools/reach.py` counts the exported functions of every *other* module a
program loads. These are the would-be landing pads a hijacked indirect call
could reach if every library had BTI. It also flags 32 dangerous symbol names
(29 distinct functions; `system`/`__libc_system` and `mmap`/`mmap64`/`__mmap`
are aliases).

| Program | Before | Source |
|---|---:|---|
| nginx (distro) | 8,764 | 21 Oct Lima scan, `results/reach_before.csv` (not re-run) |
| redis-check-rdb / redis-server (distro) | 15,931 | same |
| curl (distro) | 14,948 | same |
| sqlite3 (distro) | 6,022 | same |
| openssl (distro) | 8,584 | same |
| **our sqlite3 build** | **3,816** | `results/reach_before_ourbuilds.csv` (re-measured; equals the 21 Oct value) |
| **our redis-server build** | **3,816** | same (loads the same libc + libm + ld.so) |

Caveat: the distro binaries have no BTI at all (see §6). In reality a hijack
there can land on *any* instruction, not just a function start. These counts
are therefore what BTI would leave reachable *if it were switched on*.

`reach.py --libdir DIR` resolves libraries itself instead of calling `ldd`, so
the tool also works on a non-Arm machine.

## 3. Deliverable 3 — the hardening pass and start-up routine ✅

**Pass:** `pass/JailPass.cpp` (out-of-tree LLVM 20 pass, `-fpass-plugin`,
runs last in the optimisation pipeline). **Start-up routine:**
`runtime/jail_rt.c` (constructor using `dl_iterate_phdr`). **Driver:**
`bin/a64cc` (`JAIL=mask|pcrel|aligned`).

### The encoding problem (RQ2), in plain words

The clamp needs two numbers that describe the module's yard. On Intel,
PLaTypus folds the memory read into the instruction itself
(`or rax,[rip+ormask]`, `and rax,[rip+andmask]`: two instructions). Arm
instructions cannot read memory while computing, and Arm's `and`/`orr`
immediates can only hold "repeating" bit patterns, not an arbitrary address.
So the port must choose how the clamp gets its numbers. Four options were
built or measured:

| Option | How it works (AArch64) | Instructions on the target's path | Stored state | Status |
|---|---|---|---|---|
| **A** reserved registers | masks live permanently in two registers: `orr; and` | 2 | none | microbenchmark only (would change the ABI for every library) |
| **B** load (`JAIL=mask`) | `ldp` both masks from a read-only page, then `orr; and` | 2 (the load issues early) | masks page, **read-only after start-up** | built, all workloads |
| **C** aligned jail (`JAIL=aligned`) | link with 2^k segment alignment so the kernel places the module on a 2^k boundary; `bfxil` inserts the low k bits of the target into the module base | **1** | none | built, all workloads — **new** |
| **D** pc-relative (`JAIL=pcrel`) | base from `adrp __ehdr_start`; `sub; and #(2^k−1); add` | 3 | none | built, all workloads — **new** |

Option C is what the proposal called "aligned jail placement (the approach
Native Client used)". NaCl needed its own loader to place code. Here no
custom loader is needed: Linux ≥ 5.10 (and glibc ≥ 2.35 for shared libraries)
honour a module's segment alignment. The price is ASLR entropy: measured over
300 runs, the module base is always 2^22-aligned under C against 2^16 under D.
That is **6 bits less randomness** at k = 22 (7 bits for redis at k = 23).
There is also file padding: sqlite3 grows 1.7 → 4.3 MB, redis 6.2 → 12.4 MB.

C and D compute the base with a single side-effecting `adrp` at each call
site. An earlier build let the optimiser compute the clamped pointer early,
spill it to the stack and reload it just before the call. A stack-write bug
could then have replaced it. `tools/asm_audit.py` caught this, and the
`adrp` pins the clamp to its call.

### Fake-PLT stubs, now for every signature

The 21 Oct pass built stubs as IR `musttail` functions, which cannot forward
*variadic* functions (`fcntl`, `mremap`, `open`, `ioctl`). It skipped them,
and SQLite stores `fcntl` in its system-call table. **The hardened SQLite
therefore crashed on the first file lock of any on-disk database.** The stubs
are now two lines of module-level assembly (`bti c; b <f>`, COMDAT + hidden).
A plain branch forwards any signature. The ablation confirms the stubs are
essential, not optional: without them SQLite crashes on disk, and even in
memory once a 100k-row index build spills to a temp file. With them it is
correct everywhere (§4b).

### Completeness (`tools/asm_audit.py`, replaces `asm_audit.sh`)

For every `blr`/`br` in the final machine code, the audit finds the
instruction that last wrote the target register and classifies the branch:
clamped, switch jump table, PLT, or unclamped.

| Binary | Clamped call sites | Jump tables | PLT | Unclamped |
|---|---:|---:|---:|---:|
| sqlite3 B / D / C | 1,909 / 1,915 / 1,917 | 22 | 107 | 2 |
| redis-server B / D / C | 1,057 / 1,057 / 1,059 | 13 | 235 | 2 |
| sqlite3 unhardened (sanity) | 0 | 22 | 104 | 1,910 |

The 2 unclamped branches are `register_tm_clones`/`deregister_tm_clones` in
GCC's `crtbeginS.o`. They branch to a GOT entry that is null unless
transactional memory is in use, so they never fire. About 148 of SQLite's
call sites are indirect *tail* calls (`br`), all clamped. The 21 Oct report
had mislabelled them as PLT jumps. Source: `results/asm_audit.txt`.

### The Arm PLT (contribution claim) ✅

In every hardened PIE binary, only the first PLT entry (PLT0) has a landing
pad; the per-function entries have none, so BTI already forbids a hijack from
landing on them. With `-z now`, PLT0's resolver slot is empty, so PLT0 is
inert. On Arm, therefore, the PLT does **not** have to be moved out of the
jail, unlike PLaTypus §3.3.3 on Intel. Caveat: this is GNU ld behaviour for
PIE. For non-PIE executables GNU ld puts `bti c` on *every* PLT entry, and
the result would not hold.

## 4. Deliverable 4 — evaluation

### 4a. Blocked hijack, and a stronger attacker ✅

`results/m4_2026-11-04/security_demo.txt`, all native on the M4:

| Program | Unhardened | 21 Oct design | B | C | D |
|---|---|---|---|---|---|
| `hijack_poc`: overflow overwrites a function pointer with libc's real `system` | shell runs | killed | killed (SIGSEGV) | killed | killed |
| `mask_attack_poc`: first an arbitrary write widens the jail, then the same hijack | — | **shell runs (bypass)** | killed at the mask write | killed | killed |

The second row is why the masks moved to a read-only page. In the standard
CFI threat model (the attacker can write memory), writable masks are a
one-write off-switch. Options C and D store nothing at all.

### 4b. Correctness ✅

`tests/check_correctness.sh` runs the SQL battery against every build in four
storage modes. It then reopens each file, runs `PRAGMA integrity_check`, and
requires byte-identical output: **ALL IDENTICAL** for base/B/C/D. The
unmodified 21 Oct battery gives md5 `afbbd05e…` on every build, identical to
21 Oct. That also confirms the self-built SQLite 3.54.1 amalgamation matches
the release used before. On disk SQLite really does call `fcntl64` (and, in
mmap mode, `mremap`) through pointers: audit mode logged them
(`results/m4_2026-11-04/correctness.txt`).

- speedtest1 (SQLite's standard benchmark, on disk, `--verify`): hash
  `f99b2520…` identical for all builds.
- redis 7.2.5 (all 146 source files, including Lua, hiredis and
  hdr_histogram, through the pass): a fixed command script covering strings,
  lists, hashes, sets, sorted sets, SORT and a Lua `EVAL` gives an identical
  md5 (`d285c4224c65`) on every build, and every redis-benchmark run passed it.
  Redis's own Tcl test suite was **not** run (no Tcl available in this
  session); it is the next correctness step (`make test` in Lima).

### 4c. Runtime overhead (RQ2) ✅

**Encodings in isolation** (`bench/clamp_micro.c`, hand-written clamps, 31/21 reps):

| | A | B | C | D |
|---|---:|---:|---:|---:|
| predictable targets | −0.02% | +1.20% | +0.01% | +0.48% |
| unpredictable targets (clamp on the critical path) | +7.06% | +7.04% | **+3.57%** | +10.96% |
| instructions on the target's dependency chain | 2 | 2 | 1 | 3 |

With unpredictable targets, every branch mispredicts and the CPU must wait
for the clamped address. Each dependent instruction then costs about 3.5% of
this loop, which is why the single-instruction C is cheapest. When the
predictor is right, the clamp is off the critical path, and the pass-generated
code in `indirect_micro.c` costs B +0.03%, D +0.01%, C −0.04% (all CIs within
±0.15%).

**The 21 Oct "+5.2% worst case" does not reproduce.** The 21 Oct pass itself,
rebuilt and run here in the same interleaved run, costs −0.02% [−0.14, +0.07]
(`bench_micro.csv`, config `oct21`). The 5.2% was an artefact of the earlier
measurement, not a clamp cost.

**Real workloads** (`results/m4_2026-11-04/summary.csv`, fig. 4):

| Workload | B (mask) | C (aligned) | D (pcrel) |
|---|---|---|---|
| redis, 13 command types, unix socket (21 reps) | −0.07% [−1.30, +0.76] | +0.48% [−0.61, +1.73] | −0.07% [−0.96, +0.97] |
| SQLite speedtest1, on disk (14 reps) | **+1.35%** [+0.10, +2.04] | +0.27% [−0.94, +1.80] | −0.30% [−1.48, +0.75] |
| sqlite_bench, on disk (14 reps) | **+1.83%** [+1.44, +2.47] | −3.78% [−4.24, −3.19] | −4.70% [−5.28, −4.32] |
| sqlite_bench, in memory (28 reps) | +0.86% [−0.52, +1.37] | −2.69% [−4.24, −1.79] | −3.39% [−4.72, −2.06] |
| A/A noise floor (21 reps) | −0.47% [−0.76, +0.53] | | |
| fake-PLT ablation, B with vs without stubs | −0.11% [−0.67, +0.46] | | |

**Reading it honestly:**

- Option B costs SQLite up to ~2%, and nothing measurable on redis.
- C and D are at zero on redis and speedtest1. On the synthetic
  sqlite_bench they come out 3–5% *faster* than unhardened. Instrumentation
  cannot genuinely speed code up. Re-aligning the unhardened build moves it
  by under 2% (`sqlite_layout`, `sqlite_disk_layout`), so this is an
  unexplained code-placement effect, and no speed-up is claimed.
- The defensible statement: **on the M4, the jail's cost on real workloads is
  below ~2%, and below what single-build measurements resolve for C and D.**
  That is consistent with PLaTypus's <0.5% on Intel.

### 4d. Reachability after hardening (RQ1) ✅

`tools/reach_after_bin.py` measures "after" **from the hardened binary**. A
cross-library function counts as still reachable if some landing pad inside
the module is immediately followed by a direct branch to that function's PLT
entry. The pass's own list is no longer trusted for this.

| | Before | After | Removed | Dangerous before → after |
|---|---:|---:|---:|---|
| sqlite3 | 3,816 | 26 | **99.3%** | 32 → 2 (`mmap64`, `mremap`) |
| redis-server | 3,816 | 7 | **99.8%** | 32 → 0 |
| PLaTypus, sqlite3 on Intel (Table 2) | 6,873 | 43 | 99.37% | — |

The result is identical for B, C and D. The binary-level count is slightly
*higher* than the pass's list: it also catches SQLite's own one-line wrapper
functions that tail-call `free`/`open64`. One caveat applies to every jail,
PLaTypus included. Dangerous functions the module calls *directly* are still
reachable in two steps, by first hijacking into the module's own function
that calls them. For sqlite3 those are `system`, `popen` and `mprotect` (the
shell's `.system`/`.shell` commands, plus the jail runtime's own `mprotect`).
For redis they are `execve`, `fork`, `dlopen`, `dlsym`, `mmap64` and `mprotect`.

The metric differs from the paper's: exported functions here, `endbr64` pads
there. Comparable in magnitude, not a reproduction.

## 5. Deliverable 5 (stretch) — liboqs

Built and measured on 21 Oct (ML-KEM-768; ≈0 overhead; 5 fake-PLT stubs, none
dangerous). **Not re-run in this revision**, and it remains a weak test:
liboqs makes only ~3 indirect calls per KEM operation. The 21 Oct build used
an unpinned checkout (the "pinned fd44469" in the old log was not true of the
script). `bench/build_liboqs.sh` now pins release tag 0.12.0 and logs build
output instead of discarding it; the liboqs numbers need re-running with it.

## 6. Deliverable 2 / RQ3 — BTI in a real distribution

- **21 Oct scan (Lima, Ubuntu 24.04):** 2 of 2,100 ELF files in `/usr/bin`,
  `/usr/sbin` and `/usr/lib/aarch64-linux-gnu` carry the BTI marker (0.1%).
  libc, libssl, bash, curl, python3, nginx, redis and sqlite3 have none. This
  is the installed base of one VM, not the whole Ubuntu archive.
- **New (4 Nov): the marker is lost, not just absent.** I scanned 27 Ubuntu
  24.04 arm64 libraries: glibc 2.39 plus GCC 13's runtime libraries, from the
  official cross packages (`results/bti_pads_ubuntu2404_toolchain_libs.csv`,
  fig. 5). **None** carries the marker. Yet the GCC runtime libraries are full
  of landing pads: libstdc++ 4,207, libasan 1,914, libgcc_s 214. They were
  compiled for BTI, and the marker was dropped at link time by the same
  AND-rule this project hit in Week 1. glibc itself is different: it is *not*
  built with branch protection (libc.so.6: 23 pads in 289,361 instructions,
  all in hand-written assembly; `system()` has none).
- **Not yet measured:** other distributions. Fedora has built every package
  with `-mbranch-protection=standard` by default since Fedora 33
  ([Fedora change page](https://fedoraproject.org/wiki/Changes/Aarch64_PointerAuthentication)).
  "BTI is unused in the wild" therefore holds for Ubuntu 24.04 only.
  `tools/bti_pads_scan.sh` (marker *and* pad count per file) is ready to run
  on Fedora and Ubuntu 26.04 VMs.

## 7. Limitations and threat model

- **What is protected:** indirect calls made *from hardened modules*. libc and
  other unhardened libraries keep their own indirect calls unprotected
  (PLaTypus hardens glibc too).
- **Not supported:** cross-library callbacks (PLaTypus §3.4) and `dlopen`'d
  modules (§3.5). A hardened program that calls a pointer obtained from
  another library (a `dlsym` result, a C++ virtual call into libstdc++) would
  crash. SQLite is built with `SQLITE_OMIT_LOAD_EXTENSION` for this reason.
  Only C programs were hardened.
- **Two-step reuse** through the module's own functions remains (§4d), as in
  PLaTypus.
- **Spills:** the clamp is inserted in LLVM IR, so in principle the register
  allocator may keep a clamped pointer in memory (a stack slot, or a
  callee-saved register that a callee spills) between the clamp and the call,
  where a stack-write attacker could alter it. Before the per-call `adrp`
  fix, the audit found exactly this in C and D builds (stack reloads, and 4–7
  clamped values reused across a call). In the final binaries it finds **0**
  such sites. Only a machine-level (MIR) pass could *guarantee* this, and
  PLaTypus, which also instruments IR, has the same theoretical exposure.
- **PLT result** depends on PIE + GNU ld + `-z now` (§3).
- **Option C** trades ASLR entropy (6–7 bits) and file size for the cheapest
  clamp.
- **Environment:** the measurements ran in a separate VM on the same M4, not
  the Lima VM. `run_all.sh` reproduces them in Lima.
- **The scope is two hardened applications** (sqlite3, redis) plus the liboqs
  stretch. nginx, curl and openssl appear only in Deliverable 1.

## Appendix — files

```
pass/JailPass.cpp            the pass (mask / pcrel / aligned / check / audit; asm fake-PLT)
runtime/jail_rt.c            start-up routine: masks page read-only, fail-closed, C/D window check
runtime/crt_bti.S            BTI-marked _start
bin/a64cc                    driver (native or A64_CROSS=1)
tools/reach.py               D1 before-count (--libdir for foreign binaries)
tools/reach_after_bin.py     after-count measured from the binary
tools/asm_audit.py           clamp completeness from machine code
tools/btiscan.sh             D2 marker scan (21 Oct)    tools/bti_pads_scan.sh  marker + pads
tests/check_correctness.sh   4 storage modes            tests/mask_attack_poc.c  write-then-hijack attack
bench/bench.py               interleaved, CI, permutation p, APPEND resume
bench/build_all.sh, build_redis.sh, run_all_benches.sh, speedtest1_run.sh, redis_run.sh
run_all.sh                   one command: build + demos + correctness + audits (+ BENCH=1)
results/m4_2026-11-04/       every raw CSV, .meta, summary.csv, demo + correctness logs
```
