# Restricting Cross-Library Control Flow on AArch64

An AArch64 port of PLaTypus's cross-module control-flow confinement ("execution
jails"), built and evaluated on Apple Silicon (Arm64 Linux). Before every
**indirect** call, an out-of-tree LLVM 20 pass clamps the target pointer into the
caller's own module, so a hijacked function pointer cannot reach
`system()`/`execve()` in another library. It stands on Arm **BTI** (which stops
jumps landing mid-clamp).

See **`REPORT.md`** for the full write-up and all numbers, **`REVIEW.md`** for
the independent review it answers, **`PROGRESS_LOG.md`** for the build history,
**`DEMO_GUIDE.md`** / **`CLI_GUIDE.md`** to present it.

## Headline
- BTI *and* PAC coverage of Ubuntu 24.04 arm64: **0.1%** each (2 of 2,100 ELF files).
- A hijack that reaches real `system()` under BTI alone is **blocked** once hardened.
- our sqlite3 build cross-library reach: **3,816 → 23** functions (99.4%);
  dangerous **32 → 1**; every `blr` clamped (1761/1761).
- Overhead: real workloads (SQLite, liboqs) **not distinguishable from zero**
  (≤ ±1.5% noise floor); worst-case indirect-call microbench **+5.2%**.

## Layout
```
bin/provision.sh   one-time VM setup (LLVM 20, tools, eval targets)
bin/a64cc          BTI-enforcing compiler driver; JAIL=mask|check|audit
pass/JailPass.cpp  the hardening pass (clamp + fake-PLT) + CMakeLists.txt
runtime/jail_rt.c  dl_iterate_phdr constructor, mask globals, audit/check rt
runtime/crt_bti.S  BTI-marked _start replacement (24.04 glibc crt lacks BTI)
tools/reach.py     cross-library reachability + dangerous classification
tools/btiscan.sh   distribution-wide BTI/PAC coverage scan
tools/plots.py     report figures
tests/             bti_probe.c, toy_indirect.c, hijack_poc.c
bench/             sqlite/microbench/liboqs harnesses + runners + stats
results/           all CSVs and figures
```

## Reproduce (Apple Silicon Mac)
```bash
brew install lima
limactl create --name=e0256 --cpus=4 --memory=8 --disk=40 template:ubuntu-24.04
limactl start e0256
limactl shell e0256        # then, inside, in a copy of this tree at ~/e0256:
bash bin/provision.sh
# build the pass
cmake -S pass -B pass/build -G Ninja -DLLVM_DIR=$(llvm-config-20 --cmakedir)
cmake --build pass/build && ln -sf build/libJailPass.so pass/libJailPass.so
clang-20 -c runtime/crt_bti.S -o runtime/crt_bti.o
clang-20 -O2 -mbranch-protection=standard -c runtime/jail_rt.c -o runtime/jail_rt.o
# go/no-go, toy, security demo
bin/a64cc -O1 tests/bti_probe.c -o /tmp/probe && /tmp/probe
JAIL=mask bin/a64cc -O2 tests/toy_indirect.c -o /tmp/toy && /tmp/toy 1
```

## Usage
```bash
# harden any C/C++ program (mask = enforce; audit = measure; check = loud enforce)
JAIL=mask bin/a64cc -O2 prog.c -o prog
JAIL=audit JAIL_VERBOSE=1 bin/a64cc -O2 prog.c -o prog   # counts out-of-jail calls
JAIL=mask JAIL_NO_FAKEPLT=1 bin/a64cc ...                # ablation
```
Licence: MIT (same as the upstream PLaTypus reference).
