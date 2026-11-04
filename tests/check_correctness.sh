#!/usr/bin/env bash
# check_correctness.sh — run the SQL battery through every sqlite3 build in
# four storage configurations and require byte-identical output to the
# unhardened build in each one:
#   mem    :memory: database (no file I/O, no locking)       — the old test
#   delete on-disk file, rollback journal (fcntl locks, pread/pwrite)
#   wal    on-disk file, WAL journal (shared-memory mmap + locks)
#   mmap   on-disk file, PRAGMA mmap_size=256MiB (mmap/mremap I/O path)
# The on-disk modes are exactly what the 21-Oct version never exercised: the
# hardened build crashed there on SQLite's indirect call to fcntl().
#
# usage: check_correctness.sh BASE_BIN HARD_BIN [HARD_BIN...]
#   env RUN="qemu-aarch64 -L ..." to run under emulation (correctness only)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BAT="$ROOT/tests/sql_battery.sql"
RUN="${RUN:-}"
W="$(mktemp -d)"
base="$1"; shift
fail=0
for mode in mem delete wal mmap; do
  case $mode in
    mem)    pre="";                               db=":memory:" ;;
    delete) pre="PRAGMA journal_mode=DELETE;";    db="$W/db_MODE.sqlite" ;;
    wal)    pre="PRAGMA journal_mode=WAL;";       db="$W/db_MODE.sqlite" ;;
    mmap)   pre="PRAGMA mmap_size=268435456;";    db="$W/db_MODE.sqlite" ;;
  esac
  # strip the battery's own journal_mode line so each mode sets its own
  body="$(grep -v -i '^PRAGMA journal_mode' "$BAT")"
  i=0
  for b in "$base" "$@"; do
    d="${db/MODE/${mode}_$i}"; rm -f "$d" "$d-wal" "$d-shm" "$d-journal"
    # .output-free run; capture stdout+stderr and the exit status
    { echo "$pre"; echo "$body"; } | $RUN "$b" "$d" > "$W/out_${mode}_$i.txt" 2>&1
    rc=$?
    # reopen the file and re-read it: proves what was written is valid
    if [ "$mode" != mem ]; then
      echo "PRAGMA integrity_check; SELECT count(*), sum(v) FROM t;" | $RUN "$b" "$d" >> "$W/out_${mode}_$i.txt" 2>&1 || rc=$?
    fi
    m=$(md5sum < "$W/out_${mode}_$i.txt" | cut -c1-16)
    if [ $i -eq 0 ]; then ref=$m; tag=base; else tag=$(basename "$b"); fi
    if [ $rc -ne 0 ] || [ "$m" != "$ref" ]; then st=FAIL; fail=1; else st=ok; fi
    printf "%-7s %-12s exit=%-3s md5=%s %s\n" "$mode" "$tag" "$rc" "$m" "$st"
    i=$((i+1))
  done
done
[ $fail = 0 ] && echo "ALL IDENTICAL" || { echo "MISMATCH OR CRASH"; exit 1; }
