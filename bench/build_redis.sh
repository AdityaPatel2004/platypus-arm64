#!/usr/bin/env bash
# build_redis.sh — build redis 7.2.5 from source three ways through a64cc:
#   base (unhardened), mask (Option B), pcrel (Option D) and aligned (Option C),
#   the last two with JAIL_K=${REDIS_K:-23} (8 MiB window; redis is ~6 MiB)
# Built at -O2 like every other target (redis defaults to -O3 + LTO; LTO would
# move code generation to link time). jemalloc is skipped (MALLOC=libc) so every line of C in the binary goes
# through the pass. Output: targets/redis-<cfg>/src/redis-server
#   usage: build_redis.sh [cfg ...]     (default: base mask pcrel)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VER=7.2.5
TAR="$ROOT/targets/dl/redis-$VER.tar.gz"   # sha256 98a8502a2e902d2a9785ef46a69a5f8d5e24cbf9ea3ae4d845afcfc6778aa783
[ -f "$TAR" ] || { mkdir -p "$ROOT/targets/dl"; curl -fsSL -o "$TAR" "https://codeload.github.com/redis/redis/tar.gz/refs/tags/$VER"; }
echo "98a8502a2e902d2a9785ef46a69a5f8d5e24cbf9ea3ae4d845afcfc6778aa783  $TAR" | sha256sum -c -
cfgs=("$@"); [ ${#cfgs[@]} -eq 0 ] && cfgs=(base mask pcrel aligned)
for cfg in "${cfgs[@]}"; do
  D="$ROOT/targets/redis-$cfg"
  rm -rf "$D"; mkdir -p "$D"; tar xzf "$TAR" -C "$D" --strip-components=1
  case $cfg in base) J=none ;; *) J=$cfg ;; esac
  : > "$ROOT/results/fakeplt_redis_$cfg.txt"
  echo "### redis $cfg (JAIL=$J)"
  ( cd "$D" && JAIL=$J JAIL_K="${REDIS_K:-23}" JAIL_FAKEPLT_OUT="$ROOT/results/fakeplt_redis_$cfg.txt" \
      make -j"$(nproc)" OPTIMIZATION=-O2 MALLOC=libc BUILD_TLS=no USE_SYSTEMD=no uname_M=aarch64 \
           CC="$ROOT/bin/a64cc" LD="$ROOT/bin/a64cc" ${A64_LINKFLAGS:+REDIS_LDFLAGS="$A64_LINKFLAGS"} \
           > "$ROOT/results/build_redis_$cfg.log" 2>&1 ) || { echo "BUILD FAILED: see results/build_redis_$cfg.log"; tail -20 "$ROOT/results/build_redis_$cfg.log"; exit 1; }
  ls -la "$D/src/redis-server"
done
