#!/usr/bin/env bash
# build_liboqs.sh — build liboqs twice (unhardened + jail-hardened static libs),
# ML-KEM-768 only, for the stretch evaluation. Pinned to release tag $OQS_TAG.
# Build output goes to results/build_liboqs_*.log (never discarded).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OQS_TAG="${OQS_TAG:-0.12.0}"
PASS="$ROOT/pass/libJailPass.so"
SRC="$ROOT/targets/liboqs-$OQS_TAG"
mkdir -p "$ROOT/targets" "$ROOT/results"
[ -d "$SRC" ] || git clone --depth 1 --branch "$OQS_TAG" https://github.com/open-quantum-safe/liboqs.git "$SRC"
echo "liboqs $OQS_TAG at commit $(git -C "$SRC" rev-parse HEAD)" | tee "$ROOT/results/liboqs_version.txt"
common=(-DBUILD_SHARED_LIBS=OFF -DOQS_BUILD_ONLY_LIB=ON
        -DOQS_MINIMAL_BUILD=KEM_ml_kem_768 -DOQS_USE_OPENSSL=OFF
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang-20 -G Ninja)
for cfg in base mask pcrel aligned; do
  B="$SRC/build_$cfg"; rm -rf "$B"; : > "$ROOT/results/fakeplt_oqs_$cfg.txt"
  if [ $cfg = base ]; then FL="-O2 -mbranch-protection=standard"; else FL="-O2 -mbranch-protection=standard -fpass-plugin=$PASS"; fi
  echo "### liboqs $cfg"
  JAIL=$cfg JAIL_K="${JAIL_K:-22}" JAIL_FAKEPLT_OUT="$ROOT/results/fakeplt_oqs_$cfg.txt" \
    cmake -S "$SRC" -B "$B" "${common[@]}" -DCMAKE_C_FLAGS="$FL" > "$ROOT/results/build_liboqs_$cfg.log" 2>&1
  JAIL=$cfg JAIL_K="${JAIL_K:-22}" JAIL_FAKEPLT_OUT="$ROOT/results/fakeplt_oqs_$cfg.txt" \
    cmake --build "$B" >> "$ROOT/results/build_liboqs_$cfg.log" 2>&1 \
    || { echo "BUILD FAILED: results/build_liboqs_$cfg.log"; exit 1; }
  ls -la "$B/lib/liboqs.a"
done
