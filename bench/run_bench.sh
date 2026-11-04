#!/usr/bin/env bash
# run_bench.sh — build a C benchmark unhardened and hardened, run them
# INTERLEAVED (base,jail,base,jail,…) pinned to one core, and record everything
# needed to reproduce. Interleaving removes the run-order drift that block runs
# introduce. Stops on a checksum mismatch. Build errors are shown, not hidden.
#
#   usage: run_bench.sh NAME SRC... -- [bench args]
#   env:   REPS (default 21) CORE (default 1) CFL (compile flags)
#          AA=1  -> A/A control: both configs are the SAME unhardened binary
#                   (measures the noise floor; overhead should be ~0)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME="$1"; shift
SRCS=(); while [ "${1:-}" != "--" ] && [ $# -gt 0 ]; do SRCS+=("$1"); shift; done
[ "${1:-}" = "--" ] && shift
BARGS=("$@")
REPS="${REPS:-21}"; CORE="${CORE:-1}"; CFL="${CFL:--O2}"
OUT="$ROOT/results/bench_${NAME}.csv"; META="$ROOT/results/bench_${NAME}.meta"
mkdir -p "$ROOT/results"

base="/tmp/${NAME}_base"; jail="/tmp/${NAME}_jail"
echo "build unhardened..."
if ! "$ROOT/bin/a64cc" $CFL "${SRCS[@]}" -lm -o "$base"; then echo "BUILD FAILED (base)"; exit 2; fi
if [ "${AA:-0}" = 1 ]; then
  cp "$base" "$jail"; echo "A/A control: jail := base (noise floor)"
else
  echo "build hardened (JAIL=mask)..."
  if ! JAIL=mask "$ROOT/bin/a64cc" $CFL "${SRCS[@]}" -lm -o "$jail"; then echo "BUILD FAILED (jail)"; exit 2; fi
fi

# correctness gate: checksums (2nd field) must match; STOP if not.
cb=$("$base" "${BARGS[@]}" | awk '{print $2}')
cj=$("$jail" "${BARGS[@]}" | awk '{print $2}')
if [ "$cb" != "$cj" ]; then
  echo "CHECKSUM MISMATCH base=$cb jail=$cj — STOPPING (correctness broken)"; exit 3
fi
echo "checksum MATCH ($cb)"

{ echo "date: $(date -Is)"; echo "name: $NAME"; echo "srcs: ${SRCS[*]}";
  echo "cflags: $CFL"; echo "bench_args: ${BARGS[*]}"; echo "reps: $REPS core: $CORE";
  echo "aa_control: ${AA:-0}"; echo "driver: a64cc (clang-20, -mbranch-protection=standard)";
  echo "base_sha: $(sha256sum "$base"|cut -c1-16)"; echo "jail_sha: $(sha256sum "$jail"|cut -c1-16)";
} > "$META"

taskset -c "$CORE" "$base" "${BARGS[@]}" >/dev/null 2>&1 || true   # warmup
taskset -c "$CORE" "$jail" "${BARGS[@]}" >/dev/null 2>&1 || true
echo "config,rep,seconds" > "$OUT"
for r in $(seq 1 "$REPS"); do                                      # INTERLEAVED
  sb=$(taskset -c "$CORE" "$base" "${BARGS[@]}" | awk '{print $1}'); echo "base,$r,$sb" >> "$OUT"
  sj=$(taskset -c "$CORE" "$jail" "${BARGS[@]}" | awk '{print $1}'); echo "jail,$r,$sj" >> "$OUT"
done
echo "raw -> $OUT    meta -> $META"
python3 "$ROOT/bench/stats.py" "$OUT"
