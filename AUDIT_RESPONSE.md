# Audit response — 4 Nov 2026

The 4 Nov audit (doc "PLaTypus-on-AArch64 — Independent Audit and Next Plan")
listed 14 problems with the 21 Oct state. This file records what was done
about each one. Evidence paths are relative to this folder.

| # | Problem | Severity | Done | Evidence |
|---|---|---|---|---|
| 1 | Hardened SQLite crashed on every on-disk database: variadic `fcntl64`/`mremap` got no fake-PLT stub | High | **Fixed.** Stubs are now `bti c; b <f>` in module-level assembly, which works for any signature. Correctness test covers 4 storage modes. | `pass/JailPass.cpp`; `tests/check_correctness.sh`; `results/m4_2026-11-04/correctness.txt` |
| 2 | Writable masks = one-write bypass | High | **Fixed.** Masks are on their own 64 KiB page, read-only after start-up, starting at 0/0 (fail-closed). Options C and D store nothing. A write-then-hijack demo proves the 21 Oct build is bypassed and the new ones are not. | `runtime/jail_rt.c`; `tests/mask_attack_poc.c`; `results/m4_2026-11-04/security_demo.txt` |
| 3 | Missing limitations: callbacks, dlopen, executable-only | High | **Stated** (REPORT §7). Not implemented. | REPORT §7 |
| 4 | SQLite overhead over-read | High | **Re-measured** interleaved, with A/A and layout controls; reported with CIs and caveats. | `results/m4_2026-11-04/summary.csv`, REPORT §4c |
| 5 | Design note misstated Intel (immediates) | Medium | **Corrected** against the paper's listings. | `docs/design_note_mask_encoding.md` |
| 6 | Design note contradicted the benchmark | Medium | **Rewritten** on the new encoding experiment. The old +5.2% did not reproduce (21 Oct build: −0.02% [−0.14, +0.07]). | same; `bench_micro.csv` (`oct21` config) |
| 7 | `br` mislabelled as PLT jumps | Medium | **New audit** `tools/asm_audit.py`: 148 indirect tail calls clamped, 22 jump tables, 107 PLT, 2 unclamped in crtbeginS. | `results/asm_audit.txt` |
| 8 | "system unreachable" needed a qualifier | Medium | **Measured.** Dangerous functions called directly by the module are reported as two-step reachable. | `tools/reach_after_bin.py`; `results/reach_after_bin.csv` |
| 9 | RQ3 generalised from one distro | Medium | **Partly addressed.** New evidence that 24.04's marker is lost although pads exist; Fedora noted. The Fedora/26.04 scan is still to do (`tools/bti_pads_scan.sh` ready). | `results/bti_pads_ubuntu2404_toolchain_libs.csv`; REPORT §6 |
| 10 | "After" read from the pass's list; counted `sqlite3_free` | Low | **Fixed.** "After" is measured from the binary and counts only stubs that branch to a PLT entry (26 for sqlite3, 7 for redis). | `tools/reach_after_bin.py` |
| 11 | Distro "before" assumes BTI | Low | **Labelled** in REPORT §2. | REPORT §2 |
| 12 | liboqs unpinned, output hidden, missing .meta | Low | **Fixed** in the script (tag 0.12.0, logs kept); liboqs not re-run yet. Every new benchmark has a `.meta`. | `bench/build_liboqs.sh`; `results/m4_2026-11-04/*.meta` |
| 13 | Runtime fail-open silently | Low | **Fixed:** aborts with a message. | `runtime/jail_rt.c` |
| 14 | Alias counting, stale titles, varying window | Low | **Fixed:** 32 names = 29 functions stated; titles corrected; window variation documented (C/D windows are fixed-size). | REPORT §2, §3 |

## Plan items from the audit

| Plan item | Status |
|---|---|
| 1 Fix the variadic crash | done |
| 2 Test SQLite on disk (+ speedtest1) | done |
| 3 Read-only masks, fail closed | done |
| 4 Re-measure SQLite | done |
| 5 Correct the text | done (REPORT, design note, README, log) |
| 6 RQ2 second option (Option D) | done, **plus Option C built and measured, plus Option A microbenchmark** |
| 7 Harden redis from source | done (correctness script + benchmark; official Tcl test suite not run) |
| 8 RQ3 on Fedora / Ubuntu 26.04 + pads vs marker | pads-vs-marker done for 24.04 toolchain libs; other distros **open** |
| 9 "After" measured from the binary | done |
| 10 Git + GitHub | git history is in `platypus-arm64.bundle` (`git clone platypus-arm64.bundle`); **publishing to GitHub is your call** |
| 11 One reproduce script | done: `run_all.sh` (`BENCH=1` for benchmarks) |
| 12 Harden a shared library | **open** |

## Still open (in order of value)

1. Run `BENCH=1 bash run_all.sh` once in the Lima VM, the same environment as
   21 Oct, to confirm these numbers there.
2. Run redis's own test suite against the hardened server (`make test` in
   Lima: install `tcl` first).
3. Fedora and Ubuntu 26.04 arm64 VMs → `tools/bti_pads_scan.sh` → RQ3 across
   distributions.
4. Re-run liboqs with the pinned script.
5. A hardened shared library (e.g. `libsqlite3.so`), the multi-module case.
6. Publish on GitHub (MIT), tagging the revision the report uses.
