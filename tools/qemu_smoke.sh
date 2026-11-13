#!/usr/bin/env bash
# qemu_smoke.sh — functional smoke test on an x86-64 machine, no Arm hardware needed.
#
# Cross-compiles the pass, the runtime, the security demos and SQLite with
# A64_CROSS=1, then runs them under qemu-user with BTI emulation (-cpu max).
# It checks BEHAVIOUR only: BTI traps, the hijack is blocked, SQLite output is
# identical. It says NOTHING about performance — timing under emulation is
# meaningless. All numbers in REPORT.md come from native runs on an Apple M4 Pro.
#
# Needs (Ubuntu 24.04 x86-64):
#   sudo apt-get install clang-20 llvm-20-dev lld-20 cmake ninja-build \
#        binutils-aarch64-linux-gnu gcc-13-aarch64-linux-gnu libc6-dev-arm64-cross \
#        qemu-user python3-pyelftools
# usage: bash tools/qemu_smoke.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
export A64_CROSS=1 QEMU_LD_PREFIX=/usr/aarch64-linux-gnu QEMU_CPU=max
O="$ROOT/build/qemu"; mkdir -p "$O"
CC="$ROOT/bin/a64cc"
j() { local m="$1"; shift; if [ "$m" = base ]; then JAIL=none "$CC" "$@"; else JAIL=$m "$CC" "$@"; fi; }

echo "### 1. pass + cross runtime"
cmake -S pass -B pass/build -G Ninja -DLLVM_DIR="$(llvm-config-20 --cmakedir)" >/dev/null
cmake --build pass/build >/dev/null && ln -sf build/libJailPass.so pass/libJailPass.so
mkdir -p runtime/cross
clang-20 --target=aarch64-linux-gnu -c runtime/crt_bti.S -o runtime/cross/crt_bti.o
clang-20 --target=aarch64-linux-gnu -O2 -mbranch-protection=standard -c runtime/jail_rt.c -o runtime/cross/jail_rt.o

echo "### 2. SQLite source"
bash tools/fetch_sqlite.sh
SQ="$ROOT/targets/sqlite_src/sqlite-amalgamation-3540100"
SQF="-O2 -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION -I$SQ"

echo "### 3. build (base / mask=B / pcrel=D / aligned=C)"
"$CC" -O1 tests/bti_probe.c -o "$O/bti_probe"
for m in base mask pcrel aligned; do
  j $m -O2 -U_FORTIFY_SOURCE tests/hijack_poc.c -o "$O/poc_$m"
  [ $m != base ] && j $m -O2 tests/mask_attack_poc.c -o "$O/attack_$m"
  j $m $SQF "$SQ/shell.c" "$SQ/sqlite3.c" -lm -o "$O/sqlite3_$m"
done 2> "$O/build.log"

echo "### 4. security demos (expected: base exit=0, every hardened build exit=139)"
qemu-aarch64 "$O/bti_probe" || true
fail=0
r() { local want="$1"; shift; set +e; qemu-aarch64 "$@" >/dev/null 2>&1; local rc=$?; set -e
      printf "%-40s exit=%-3s expected=%s\n" "$(basename "$1") ${2:-}" "$rc" "$want"
      [ "$rc" = "$want" ] || fail=1; }
r 0 "$O/poc_base" hijack
for m in mask pcrel aligned; do r 139 "$O/poc_$m" hijack; r 139 "$O/attack_$m"; done

echo "### 5. SQLite correctness, 4 storage modes"
RUN=qemu-aarch64 bash tests/check_correctness.sh "$O/sqlite3_base" "$O/sqlite3_mask" "$O/sqlite3_pcrel" "$O/sqlite3_aligned" || fail=1

[ $fail = 0 ] && echo "### SMOKE TEST PASSED (behaviour only; no timing)" || { echo "### SMOKE TEST FAILED"; exit 1; }
