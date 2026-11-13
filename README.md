# platypus-arm64: restricting cross-library control flow on AArch64

An **AArch64 (Arm64) port of PLaTypus**'s "execution jails"
([IEEE S&P 2026](https://cispa.de/en/research/publications/105071-platypus-restricting-cross-module-transitions-to-mitigate-code-reuse-attacks),
[x86-64 artifact](https://github.com/Platypus2025/Platypus)), built on Arm
**BTI** and evaluated on an Apple M4 Pro running Arm64 Linux.

> **Status: research prototype.** This started as a course project (E0-256
> System Security, IISc Bengaluru, 2026). It hardens two real programs (SQLite
> and redis) on one machine. It is not production-ready, and it is not
> affiliated with or endorsed by the PLaTypus authors. Read the
> [limitations](#limitations) before relying on any number.

## The problem in four lines

1. A memory bug lets an attacker overwrite a **function pointer**, so the next
   indirect call goes wherever the attacker chooses, typically `system()` in libc.
2. Arm **BTI** (like Intel CET/IBT) only lets indirect branches land on a
   landing pad (`bti c`) at a function's start. **Every** function start in
   **every** library is still a legal target, `system()` included.
3. PLaTypus closes this on x86-64: before each indirect call, a short
   **clamp** forces the target into the caller's own module (the "jail").
   Legitimate calls to other libraries are direct calls through the PLT, so
   the clamp doesn't affect them.
4. The paper names BTI as having the same gap, but no Arm implementation existed.
   This repository builds one and measures it.

## What the port had to solve differently from x86-64

| Problem | PLaTypus on x86-64 | This port on AArch64 |
|---|---|---|
| Writing the clamp | `or`/`and` with the masks read straight from memory (2 instructions) | Arm can't read memory inside `orr`/`and`, and its immediates can't hold an arbitrary address. Four encodings were built or measured: **B** masks loaded from a read-only page, **C** aligned jail (`bfxil`, 1 instruction, kernel-placed via `p_align`), **D** pc-relative (`adrp __ehdr_start`), **A** reserved registers (microbenchmark only). See [`docs/design_note_mask_encoding.md`](docs/design_note_mask_encoding.md). |
| Getting the module's address range | modified `ld.so` + new relocation types | no loader changes: a per-module constructor uses `dl_iterate_phdr`, writes the masks, then `mprotect`s them read-only. It fails closed. ([`runtime/jail_rt.c`](runtime/jail_rt.c)) |
| PLT stubs | moved outside every jail (§3.3.3) | not needed for PIE + GNU ld + `-z now`: per-function Arm PLT entries carry no landing pad, so BTI already blocks them (REPORT §3) |
| Getting BTI switched on at all | — | Ubuntu 24.04's glibc start files are unmarked, so any normally linked program loses BTI. [`bin/a64cc`](bin/a64cc) links a BTI-marked `_start` instead. |

## Results

Measured on an Apple M4 Pro (CPU features `bti paca pacg`) in an Arm64 Linux VM
(not emulation). Every number traces to a file under [`results/`](results/).
[`REPORT.md`](REPORT.md) has the full tables, confidence intervals and caveats.

| Question | Result | Evidence |
|---|---|---|
| Is BTI enforced on this machine? | Yes: a call that skips the landing pad gets `SIGILL` | `results/native_2026-11-13/security_demo.txt` |
| Does BTI alone stop a hijack to libc's real `system()`? | **No**: the unhardened demo runs a shell command | same |
| Does the jail stop it? | **Yes**, in encodings B, C and D (the process is killed before any shell runs) | same |
| Can a memory write switch the jail off? | No: the write to the mask page faults (an earlier, writable-mask version *was* bypassable) | same; `tests/mask_attack_poc.c` |
| Cross-library functions reachable through an indirect call | sqlite3 **3,816 → 26** (99.3%), redis-server **3,816 → 7** (99.8%), counted from the hardened binaries | `results/native_2026-11-13/reach_after_bin.csv` |
| Does the hardened code still work? | SQLite output byte-identical in 4 storage modes; speedtest1 verification hash and a redis command script match | `results/native_2026-11-13/correctness.txt` |
| Completeness | all indirect calls clamped (sqlite3 1,909–1,917, redis 1,057–1,059); 2 unclamped branches, both in GCC's `crtbeginS.o` start-up code | `results/asm_audit.txt` |
| Worst-case clamp cost (microbenchmark, every branch mispredicted) | C **+3.6%**, A/B **+7.0%**, D **+11.0%** | `results/m4_2026-11-04/` |
| Cost on real workloads | B: up to about +2% on SQLite, not measurable on redis. C and D: not distinguishable from zero | `results/m4_2026-11-04/summary.csv` |
| How much of Ubuntu 24.04 has BTI on? | 2 of 2,091 ELF files carry the BTI marker. GCC's runtime libraries contain thousands of landing pads but no marker. glibc is not built for BTI. | `results/native_2026-11-13/bti_pads_scan.csv` |

For scale: PLaTypus reports a 99.37% reduction for sqlite3 on Intel. Our
metric is different (exported functions rather than `endbr64` pads), so the
two numbers are comparable in magnitude, not a reproduction.

**Which run produced what.** The benchmarks (4 Nov 2026) ran in an Arm64 VM on
the M4 with Ubuntu 24.04's glibc 2.39 loaded through each binary's own
`PT_INTERP` ([`ENVIRONMENT.txt`](results/m4_2026-11-04/ENVIRONMENT.txt)). On
13 Nov 2026 the functional part (`bash run_all.sh`, everything except the
benchmarks) was re-run in a stock Ubuntu 24.04 arm64 Lima VM on the same M4,
and every outcome matched. The benchmarks have not been repeated on a second
machine.

## Limitations

- **Only executables are hardened.** Hardening a shared library (the case
  PLaTypus covers most) has not been done. libc and other libraries keep their
  own indirect calls unprotected.
- **Not supported:** calls through pointers obtained from another library
  (callbacks, `dlsym` results, C++ virtual calls into libstdc++) and
  `dlopen`'d modules. Such a program crashes when hardened, which is why SQLite
  is built with `SQLITE_OMIT_LOAD_EXTENSION`. Only C programs were tested.
- **Two-step reuse remains**, as in PLaTypus: a dangerous function the module
  calls *directly* (e.g. `system` from SQLite's shell) is reachable by first
  hijacking into the module's own caller of it.
- **IR-level pass:** the clamp is inserted in LLVM IR. The final binaries were
  audited and no clamped pointer is spilled to memory before its call, but only
  a machine-level pass could guarantee that.
- **Encoding C** costs 6–7 bits of ASLR entropy for the hardened module, and
  file padding (sqlite3 1.7 → 4.3 MB).
- **The PLT finding** holds for PIE + GNU ld + `-z now`. It does not hold for
  non-PIE executables, where GNU ld gives every PLT entry a landing pad.
- **The window check only reports.** At start-up, the routine *aborts* if the
  program's code doesn't fit its jail window. It only *reports* (with
  `JAIL_VERBOSE=1`) whether another module's code lies inside the window.
- **The BTI scan covers Ubuntu 24.04 only.** It should not be read as a
  statement about current distributions: Debian has built glibc with BTI
  support since 2.39-5, and Fedora, Debian and newer Ubuntu releases (26.04)
  were not scanned here.
- **Scale:** two applications, one CPU model, one VM setup. Redis's own test
  suite has not been run.

## Run it

**On Arm64 hardware with BTI** (tested only on an Apple M4 Pro, in an
Ubuntu 24.04 arm64 VM under Lima; check `grep -w bti /proc/cpuinfo`):

```bash
git clone https://github.com/AdityaPatel2004/platypus-arm64 && cd platypus-arm64
bash bin/provision.sh      # once: LLVM 20 (apt.llvm.org), cmake, ninja, pyelftools, ...
bash run_all.sh            # build + attack demos + correctness + audits -> results/native_<date>/
BENCH=1 bash run_all.sh    # ... plus every benchmark (about 30 extra minutes)
```

SQLite 3.54.1 and redis 7.2.5 sources are downloaded on first use and checked
against SHA-256 hashes ([`tools/fetch_sqlite.sh`](tools/fetch_sqlite.sh),
[`bench/build_redis.sh`](bench/build_redis.sh)).

**On an x86-64 machine (behaviour only, no timing):**
[`tools/qemu_smoke.sh`](tools/qemu_smoke.sh) cross-compiles everything and
runs the BTI probe, the attack demos and the SQLite correctness test under
`qemu-aarch64 -cpu max`. Emulated timing means nothing, so no performance
claim comes from this path.

**Compiling your own program:**

```bash
JAIL=mask    bin/a64cc -O2 prog.c -o prog            # B: masks on a read-only page
JAIL=aligned JAIL_K=22 bin/a64cc -O2 prog.c -o prog  # C: aligned 2^22 window (cheapest clamp)
JAIL=pcrel   bin/a64cc -O2 prog.c -o prog            # D: pc-relative, nothing stored
JAIL=audit   bin/a64cc -O2 prog.c -o prog            # log calls that would leave the jail
JAIL_VERBOSE=1 ./prog                                # print the window and the start-up checks
```

## Repository layout

```
pass/JailPass.cpp        out-of-tree LLVM 20 pass (-fpass-plugin): the clamp + fake-PLT stubs
runtime/jail_rt.c        per-module start-up routine: finds the module, read-only masks, fail-closed
runtime/crt_bti.S        BTI-marked _start
bin/a64cc                compiler driver (native, or A64_CROSS=1 from x86-64)
tests/                   bti_probe, hijack_poc, mask_attack_poc, toy program, SQL battery, check_correctness.sh
tools/                   reach.py / reach_after_bin.py (reachability), asm_audit.py (completeness),
                         btiscan.sh / bti_pads_scan.sh (distribution scan), plots, qemu_smoke.sh
bench/                   interleaved benchmark harness (bench.py: median, bootstrap CI, permutation p)
results/m4_2026-11-04/   raw data of the benchmark run (CSV + .meta per benchmark)
results/native_2026-11-13/  the functional re-run in a stock Ubuntu 24.04 Lima VM
results/oct21_superseded/   an earlier run whose numbers were withdrawn (kept for the record)
REPORT.md                full write-up
docs/                    mask-encoding design note; docs/history/ = review, audit response, build log
```

## How this was built

The [`docs/history/`](docs/history/) folder keeps the review of an earlier
version, the 14 problems it found (including a crash on on-disk SQLite
databases and writable masks), and how each was fixed. The commit history
starts from that earlier version on purpose.

Project direction and design decisions are by Aditya Patel. The 13 Nov 2026
confirmation run was carried out by the author.

## Credits and citation

This is an independent port. No code was copied from the PLaTypus artifact;
the design follows the paper:

> Apostolos Chatzianagnostou, Marcos Sanchez Bajo, Christian Rossow. *PLaTypus: Restricting
> Cross-Module Transitions to Mitigate Code-Reuse Attacks.* IEEE Symposium on
> Security and Privacy (S&P), 2026.

The aligned-jail encoding (C) follows the address-masking approach of Native
Client on Arm (Sehr et al., USENIX Security 2010). To cite this repository, see
[`CITATION.cff`](CITATION.cff).

Licensed under the [MIT License](LICENSE).
