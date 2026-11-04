#!/usr/bin/env bash
# speedtest1_run.sh BIN SIZE DBDIR — run SQLite's standard speedtest1 on an
# on-disk database with --verify; print "<TOTAL seconds> <verification hash>".
set -euo pipefail
bin="$1"; size="$2"; d="$3"; db="$d/st_$$.db"
rm -f "$db" "$db"-*
out="$("$bin" --size "$size" --verify "$db" 2>&1)"
rm -f "$db" "$db"-*
t=$(echo "$out" | awk '/TOTAL/{gsub(/s/,"",$NF); print $NF}')
h=$(echo "$out" | awk '/Verification Hash/{print $NF}')
echo "$t $h"
