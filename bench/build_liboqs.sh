#!/usr/bin/env bash
# build_liboqs.sh — build liboqs twice (unhardened + jail-hardened static libs),
# ML-KEM-768 only, for the stretch evaluation. Run inside the VM in ~/e0256.
set -euo pipefail
ROOT="$HOME/e0256"
PASS="$ROOT/pass/libJailPass.so"
SRC="$ROOT/targets/liboqs"
cd "$ROOT/targets"
if [ ! -d liboqs ]; then
  git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
fi

common=(-DBUILD_SHARED_LIBS=OFF -DOQS_BUILD_ONLY_LIB=ON
        -DOQS_MINIMAL_BUILD=KEM_ml_kem_768 -DOQS_USE_OPENSSL=OFF
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang-20 -G Ninja)

echo "### unhardened liboqs"
rm -rf "$SRC/build_base"
cmake -S "$SRC" -B "$SRC/build_base" "${common[@]}" \
      -DCMAKE_C_FLAGS="-O2 -mbranch-protection=standard" >/dev/null
cmake --build "$SRC/build_base" >/dev/null 2>&1
echo "    -> $(ls -la $SRC/build_base/lib/liboqs.a | awk '{print $5}') bytes"

echo "### hardened liboqs (JAIL=mask + fake-PLT)"
rm -rf "$SRC/build_jail" ; : > /tmp/fp_oqs.txt
JAIL=mask JAIL_FAKEPLT_OUT=/tmp/fp_oqs.txt \
cmake -S "$SRC" -B "$SRC/build_jail" "${common[@]}" \
      -DCMAKE_C_FLAGS="-O2 -mbranch-protection=standard -fpass-plugin=$PASS" >/dev/null
JAIL=mask JAIL_FAKEPLT_OUT=/tmp/fp_oqs.txt cmake --build "$SRC/build_jail" >/dev/null 2>/tmp/oqs_jail_build.log
echo "    -> $(ls -la $SRC/build_jail/lib/liboqs.a | awk '{print $5}') bytes"
echo "    fake-PLT imports: $(sort -u /tmp/fp_oqs.txt | wc -l)"
echo "### liboqs build done"
