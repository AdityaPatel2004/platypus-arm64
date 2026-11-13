#!/usr/bin/env bash
# run_all.sh — rebuild and re-check everything from source, natively, inside the
# Ubuntu 24.04 arm64 Lima VM on the M4 (see README "Reproduce").
#   bash run_all.sh            build + security demos + correctness + audits
#   BENCH=1 bash run_all.sh    ... plus all benchmarks (~30 min extra) + figures
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"; cd "$ROOT"
B="$ROOT/build/native"; OUT="$ROOT/results/native_$(date +%F)"; mkdir -p "$OUT"
echo "### 1. pass + runtime"
cmake -S pass -B pass/build -G Ninja -DLLVM_DIR="$(llvm-config-20 --cmakedir)" >/dev/null
cmake --build pass/build && ln -sf build/libJailPass.so pass/libJailPass.so
clang-20 -c runtime/crt_bti.S -o runtime/crt_bti.o
clang-20 -O2 -mbranch-protection=standard -c runtime/jail_rt.c -o runtime/jail_rt.o
echo "### 2. sources"
bash tools/fetch_sqlite.sh
echo "### 3. build everything (base / mask=B / pcrel=D / aligned=C)"
bash bench/build_all.sh native > "$OUT/build.log" 2>&1
echo "### 4. security demos"
{ "$B/bti_probe"
  for m in base mask pcrel aligned; do echo "== hijack_poc $m"; "$B/poc_$m" hijack; echo "exit=$?"; done
  for m in mask pcrel aligned; do echo "== attack_$m"; "$B/attack_$m"; echo "exit=$?"; done
} > "$OUT/security_demo.txt" 2>&1 || true
cat "$OUT/security_demo.txt"
echo "### 5. correctness"
bash tests/check_correctness.sh "$B/sqlite3_base" "$B/sqlite3_mask" "$B/sqlite3_pcrel" "$B/sqlite3_aligned" | tee "$OUT/correctness.txt"
for m in base mask pcrel aligned; do echo "speedtest1 $m $(bench/speedtest1_run.sh "$B/speedtest1_$m" 60 /tmp)"; \
  echo "redis $m $(bench/redis_run.sh "$B/redis-server_$m" "$B/redis-benchmark" "$B/redis-cli" 20000)"; done | tee -a "$OUT/correctness.txt"
echo "### 6. machine-code audit + reachability"
for b in sqlite3 redis-server; do for m in base mask pcrel aligned; do python3 tools/asm_audit.py "$B/${b}_$m" --quiet; done; done | tee "$OUT/asm_audit.txt"
rm -f "$OUT/reach_after_bin.csv"
for b in sqlite3 redis-server; do for m in base mask pcrel aligned; do python3 tools/reach_after_bin.py "$B/${b}_$m" --csv "$OUT/reach_after_bin.csv"; done; done
python3 tools/reach.py "$B/sqlite3_base" "$B/redis-server_base" --csv "$OUT/reach_before.csv"
echo "### 7. BTI marker vs landing pads across this distribution"
bash tools/bti_pads_scan.sh "$OUT/bti_pads_scan.csv" /usr/bin /usr/sbin /usr/lib/aarch64-linux-gnu
if [ "${BENCH:-0}" = 1 ]; then
  echo "### 8. benchmarks"; DBDIR=/tmp bash bench/run_all_benches.sh "$B"
fi
echo "### done -> $OUT"
