#!/usr/bin/env bash
# run_all_benches.sh BUILD_DIR — every overhead measurement in REPORT.md,
# interleaved and pinned (bench/bench.py). About 30 min on the M4; run it on an
# idle machine. Writes results/bench_*.csv + .meta.
#   env: DBDIR  where on-disk databases go (default: $TMPDIR or /tmp; use a VM-local disk)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; B="$(cd "$1" && pwd)"
DB="${DBDIR:-${TMPDIR:-/tmp}}"; mkdir -p "$DB"
P="python3 $ROOT/bench/bench.py"; R="$ROOT/bench/redis_run.sh"; S="$ROOT/bench/speedtest1_run.sh"
cp "$B/sqlbench_base" "$B/sqlbench_base_copy"          # A/A control binary
set -x
# RQ2 in isolation: the pass-generated clamp in a tight indirect-call loop, and
# the four encodings by hand with predictable / unpredictable targets
$P micro 31 1 base="$B/micro_base 400000000" mask="$B/micro_mask 400000000" pcrel="$B/micro_pcrel 400000000" aligned="$B/micro_aligned 400000000"
$P clamp_enc 31 1 base="$B/cmicro_NONE 400000000" A="$B/cmicro_A 400000000" B="$B/cmicro_B 400000000" C="$B/cmicro_C 400000000" D="$B/cmicro_D 400000000"
$P clamp_enc_rand 21 1 base="$B/cmicroR_NONE 100000000" A="$B/cmicroR_A 100000000" B="$B/cmicroR_B 100000000" C="$B/cmicroR_C 100000000" D="$B/cmicroR_D 100000000"
# noise floor and real workloads
$P sqlite_aa2 21 1 base="$B/sqlbench_base 100000 100000" aa="$B/sqlbench_base_copy 100000 100000"
$P sqlite_mem 28 1 base="$B/sqlbench_base 100000 100000" mask="$B/sqlbench_mask 100000 100000" pcrel="$B/sqlbench_pcrel 100000 100000" aligned="$B/sqlbench_aligned 100000 100000"
$P sqlite_disk 14 1 base="$B/sqlbench_base 60000 60000 $DB/sb.db" mask="$B/sqlbench_mask 60000 60000 $DB/sb.db" pcrel="$B/sqlbench_pcrel 60000 60000 $DB/sb.db" aligned="$B/sqlbench_aligned 60000 60000 $DB/sb.db"
$P speedtest1 14 1 base="$S $B/speedtest1_base 60 $DB" mask="$S $B/speedtest1_mask 60 $DB" pcrel="$S $B/speedtest1_pcrel 60 $DB" aligned="$S $B/speedtest1_aligned 60 $DB"
$P redis 21 - base="$R $B/redis-server_base $B/redis-benchmark $B/redis-cli 40000" mask="$R $B/redis-server_mask $B/redis-benchmark $B/redis-cli 40000" pcrel="$R $B/redis-server_pcrel $B/redis-benchmark $B/redis-cli 40000" aligned="$R $B/redis-server_aligned $B/redis-benchmark $B/redis-cli 40000"
# fake-PLT ablation (60k rows: without stubs SQLite crashes once it spills to a temp file)
$P ablation_fakeplt 31 1 base="$B/sqlbench_mask 60000 60000" nofp="$B/sqlbench_mask_nofp 60000 60000"
set +x
echo "ALL BENCHMARKS DONE"
