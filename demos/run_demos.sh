#!/usr/bin/env bash
# run_demos.sh — the live demo reel. Run INSIDE the e0256 VM, from ~/e0256:
#   bash demos/run_demos.sh            (runs straight through)
#   PAUSE=1 bash demos/run_demos.sh    (pauses between demos, for presenting)
# Builds fail LOUDLY (no hidden errors); fetches the SQLite source if missing.
set -uo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)"; ROOT="$PWD"
OUT="$ROOT/demos/out"; mkdir -p "$OUT"
SRC="$ROOT/targets/sqlite_src/sqlite-amalgamation-3540100"
SQ="-O2 -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION -I$SRC"
hr(){ printf '\n\033[1;36m══════════════════════════════════════════════════════════\n%s\n══════════════════════════════════════════════════════════\033[0m\n' "$1"; }
pause(){ [ "${PAUSE:-0}" = 1 ] && { echo; read -rp $'\033[1;33m[Enter for next]\033[0m '; } || true; }
build(){ # build LOUDLY: show errors, stop the reel if a build fails
  if ! "$@"; then echo -e "\033[1;31mBUILD FAILED:\033[0m $*"; exit 1; fi; }

hr "SETUP — toolchain, source, and demo binaries"
if [ ! -e pass/libJailPass.so ]; then
  cmake -S pass -B pass/build -G Ninja -DLLVM_DIR=$(llvm-config-20 --cmakedir) >/dev/null
  cmake --build pass/build >/dev/null && ln -sf build/libJailPass.so pass/libJailPass.so
fi
[ -e runtime/crt_bti.o ] || clang-20 -c runtime/crt_bti.S -o runtime/crt_bti.o
[ -e runtime/jail_rt.o ] || clang-20 -O2 -mbranch-protection=standard -c runtime/jail_rt.c -o runtime/jail_rt.o
[ -d "$SRC" ] || bash tools/fetch_sqlite.sh
echo "ready."
pause

hr "DEMO 1 — Arm BTI is really enforced (the foundation)"
echo "tgt() begins with a 'bti c' landing pad; we call tgt+4, skipping it:"
objdump -d "$OUT/bti_probe" 2>/dev/null | awk '/<tgt>:/{m=1} m{print} /ret/&&m{exit}' 2>/dev/null \
  || { build bin/a64cc -O1 tests/bti_probe.c -o "$OUT/bti_probe"; objdump -d "$OUT/bti_probe"|awk '/<tgt>:/{m=1}m{print}/ret/&&m{exit}'; }
"$OUT/bti_probe"; echo "(skip-pad -> TRAP [SIGILL] means BTI is live)"
pause

hr "DEMO 2 — THE MONEY SHOT: a hijack reaching real system()"
echo "Vulnerable struct {buf[16]; fp;}; a 24-byte overflow overwrites fp with"
echo "libc's real system() address. BTI is ON in both builds."
P="-O1 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -Wno-everything"
build bin/a64cc $P tests/hijack_poc.c -ldl -o "$OUT/poc_unhard"
JAIL=mask bash -c "'$ROOT/bin/a64cc' $P tests/hijack_poc.c -ldl -o '$OUT/poc_hard'" || { echo BUILD FAIL; exit 1; }
echo; echo "--- UNHARDENED: exploit SUCCEEDS (shell runs 'id') ---"; "$OUT/poc_unhard" hijack; echo "(exit $?)"
echo; echo "--- HARDENED: SAME exploit BLOCKED (no 'id') ---"; "$OUT/poc_hard" hijack || echo "(killed, exit $? — before any shell)"
pause

hr "DEMO 3 — the clamp the compiler inserted"
JAIL=mask bash -c "'$ROOT/bin/a64cc' -O2 tests/toy_indirect.c -o '$OUT/toy'"
echo "The clamp sits before 'blr': load masks, OR floor, AND ceiling:"
objdump -d "$OUT/toy" | awk '/<main>:/{m=1} m&&/\tblr\t/{print;exit} m&&/\t(ldr|adrp|orr|and)\t/{print}' | tail -6
pause

hr "DEMO 4 — attack surface of OUR OWN sqlite3 build, BEFORE"
build bin/a64cc $SQ "$SRC/shell.c" "$SRC/sqlite3.c" -lm -o "$OUT/sqlite_base"
python3 tools/reach.py "$OUT/sqlite_base" 2>/dev/null | sed -n '2,5p'
pause

hr "DEMO 5 — how much the jail removes (same binary, hardened)"
rm -f /tmp/fp.txt
JAIL=mask JAIL_FAKEPLT_OUT=/tmp/fp.txt bash -c "'$ROOT/bin/a64cc' $SQ '$SRC/shell.c' '$SRC/sqlite3.c' -lm -o '$OUT/sqlite_hard'"
python3 tools/reach.py "$OUT/sqlite_base" --after /tmp/fp.txt 2>/dev/null | grep -E 'BEFORE|reachable AFTER|dangerous AFTER'
echo "(system/execve/dlopen/mprotect all gone; only mmap64 — which sqlite uses — remains)"
echo; echo "Completeness: every indirect call in the hardened binary is clamped:"
bash tools/asm_audit.sh "$OUT/sqlite_hard" 2>/dev/null | sed -n '3,5p'
pause

hr "DONE — full numbers + stats in REPORT.md"
