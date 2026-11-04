#!/usr/bin/env bash
# check_correctness.sh — build sqlite3 (amalgamation) unhardened and hardened,
# run tests/sql_battery.sql through both, and compare md5. Reproducible.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/targets/sqlite_src/sqlite-amalgamation-3540100"
[ -d "$SRC" ] || bash "$ROOT/tools/fetch_sqlite.sh"
CFL="-O2 -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION -I$SRC"
"$ROOT/bin/a64cc" $CFL "$SRC/shell.c" "$SRC/sqlite3.c" -lm -o /tmp/sq_base
JAIL=mask "$ROOT/bin/a64cc" $CFL "$SRC/shell.c" "$SRC/sqlite3.c" -lm -o /tmp/sq_jail
/tmp/sq_base :memory: < "$ROOT/tests/sql_battery.sql" > /tmp/out_base.txt 2>&1
/tmp/sq_jail :memory: < "$ROOT/tests/sql_battery.sql" > /tmp/out_jail.txt 2>&1
mb=$(md5sum < /tmp/out_base.txt | cut -c1-16); mj=$(md5sum < /tmp/out_jail.txt | cut -c1-16)
if [ "$mb" = "$mj" ]; then echo "CORRECT: identical output, md5=$mb"; else
  echo "DIFFERENT:"; diff /tmp/out_base.txt /tmp/out_jail.txt | head; exit 1; fi
