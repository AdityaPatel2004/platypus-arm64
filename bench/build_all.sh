#!/usr/bin/env bash
# build_all.sh — build every test, demo and benchmark binary in three
# configurations (base = unhardened, mask = Option B, pcrel = Option D) into
# build/<tag>/. Works natively in the Lima VM (Ubuntu 24.04 arm64) and as a
# cross build (A64_CROSS=1) whose binaries are then run on the M4.
#   usage: build_all.sh [tag]        (default tag: native)
#   needs: pass built (pass/libJailPass.so), runtime objects, targets/ fetched
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TAG="${1:-native}"; O="$ROOT/build/$TAG"; mkdir -p "$O"
CC="$ROOT/bin/a64cc"
SQ="$ROOT/targets/sqlite_src/sqlite-amalgamation-3540100"
SQF="-O2 -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION -I$SQ"
log() { echo "### $*"; }
j() { local mode="$1"; shift; if [ "$mode" = base ]; then JAIL=none "$CC" "$@"; else JAIL=$mode "$CC" "$@"; fi; }

log "tests + demos"
"$CC" -O1 "$ROOT/tests/bti_probe.c" -o "$O/bti_probe"
"$CC" -O1 -mbranch-protection=none "$ROOT/tests/bti_probe.c" -o "$O/bti_probe_control" 2>/dev/null || true
for m in base mask pcrel; do
  j $m -O2 "$ROOT/tests/toy_indirect.c"   -o "$O/toy_$m"
  j $m -O2 -U_FORTIFY_SOURCE "$ROOT/tests/hijack_poc.c"     -o "$O/poc_$m"
  [ $m != base ] && j $m -O2 "$ROOT/tests/mask_attack_poc.c" -o "$O/attack_$m"
done

log "microbenchmarks"
for m in base mask pcrel; do j $m -O2 "$ROOT/bench/indirect_micro.c" -o "$O/micro_$m"; done
for v in NONE A B D; do "$CC" -O2 -DVARIANT_$v "$ROOT/bench/clamp_micro.c" -o "$O/cmicro_$v"; done

log "sqlite (CLI, bench, speedtest1)"
for m in base mask pcrel; do
  : > "$O/fakeplt_sqlite_$m.txt"
  JAIL_FAKEPLT_OUT="$O/fakeplt_sqlite_$m.txt" j $m $SQF "$SQ/shell.c" "$SQ/sqlite3.c" -lm -o "$O/sqlite3_$m" &
  j $m $SQF "$ROOT/bench/sqlite_bench.c" "$SQ/sqlite3.c" -lm -o "$O/sqlbench_$m" &
  j $m $SQF -DSQLITE_OMIT_LOAD_EXTENSION "$SQ/speedtest1.c" "$SQ/sqlite3.c" -lm -o "$O/speedtest1_$m" &
  wait
done
JAIL_NO_FAKEPLT=1 j mask $SQF "$ROOT/bench/sqlite_bench.c" "$SQ/sqlite3.c" -lm -o "$O/sqlbench_mask_nofp"
JAIL=audit "$CC" $SQF "$SQ/shell.c" "$SQ/sqlite3.c" -lm -o "$O/sqlite3_audit"

log "redis"
"$ROOT/bench/build_redis.sh" base mask pcrel
for m in base mask pcrel; do cp "$ROOT/targets/redis-$m/src/redis-server" "$O/redis-server_$m"; done
cp "$ROOT/targets/redis-base/src/redis-benchmark" "$ROOT/targets/redis-base/src/redis-cli" "$O/"
ls -la "$O"
