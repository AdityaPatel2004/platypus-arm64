#!/usr/bin/env bash
# provision.sh — one-time setup of the E0-256 dev box (Restricting Cross-Library Control Flow on AArch64).
# Runs INSIDE the Ubuntu 24.04 arm64 Lima VM (which runs natively on the M4).
# Idempotent-ish: safe to re-run; apt skips already-installed packages.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "### [1/5] base build tools"
sudo apt-get update -y
sudo apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build git wget gnupg lsb-release \
    software-properties-common binutils file ca-certificates pkg-config

echo "### [2/5] LLVM 20 from apt.llvm.org (never from source)"
if ! command -v clang-20 >/dev/null 2>&1; then
    wget -q https://apt.llvm.org/llvm.sh -O /tmp/llvm.sh
    chmod +x /tmp/llvm.sh
    sudo /tmp/llvm.sh 20
    sudo apt-get install -y clang-20 llvm-20-dev lld-20
fi

echo "### [3/5] python tooling for the reachability tool + plots"
sudo apt-get install -y python3 python3-pip python3-pyelftools python3-matplotlib python3-numpy tcl

echo "### [4/5] evaluation targets (for 'before' reachability + benchmarks)"
# Real distro arm64 binaries — their BTI status is itself data (week-3 scan).
sudo apt-get install -y \
    nginx-core redis-server curl sqlite3 openssl \
    libssl-dev zlib1g-dev libsqlite3-dev \
    wrk redis-tools apache2-utils || true

echo "### [5/5] versions"
clang-20 --version | head -1
llvm-config-20 --version
echo "llvm includedir: $(llvm-config-20 --includedir)"
echo "llvm cmakedir:   $(llvm-config-20 --cmakedir)"
python3 -c 'import elftools; print("pyelftools", elftools.__version__)'
echo "### provision done"
