#!/usr/bin/env bash
# redis_run.sh SERVER BENCH CLI N — one measured redis run.
# Starts SERVER pinned to core ${SCORE:-2} on a unix socket (no persistence),
# checks correctness with a fixed command script (strings, lists, hashes,
# sorted sets, SORT, and a Lua EVAL - the Lua interpreter is hardened too),
# then drives it with redis-benchmark pinned to core ${CCORE:-3}.
# Prints "<seconds> <md5-of-script-output>", where seconds = sum over tests of
# N / requests-per-second (time to serve N requests of each kind).
set -euo pipefail
srv="$1"; bench="$2"; cli="$3"; n="$4"
d="$(mktemp -d)"; s="$d/r.sock"
taskset -c "${SCORE:-2}" "$srv" --port 0 --unixsocket "$s" --save '' --appendonly no \
  --daemonize no --logfile "$d/log" >/dev/null 2>&1 &
pid=$!
for _ in $(seq 1 200); do [ -S "$s" ] && break; sleep 0.02; done
chk=$({ printf 'SET k1 v1\nGET k1\nINCRBY ctr 41\nINCR ctr\nRPUSH l a b c d e\nLRANGE l 0 -1\n'
        printf 'HSET h f1 1 f2 2 f3 3\nHGETALL h\nZADD z 3 c 1 a 2 b\nZRANGE z 0 -1 WITHSCORES\n'
        printf 'SADD s x y z\nSCARD s\nSORT l ALPHA DESC\n'
        printf "EVAL \"local t={} for i=1,100 do t[i]=i*i end return t[100]\" 0\n"
        printf 'DBSIZE\nFLUSHALL\n'; } | "$cli" -s "$s" 2>&1 | md5sum | cut -c1-12)
csv=$(taskset -c "${CCORE:-3}" "$bench" -s "$s" -n "$n" -q --csv \
      -t set,get,incr,lpush,rpush,lpop,rpop,sadd,hset,spop,zadd,lrange_100,mset 2>/dev/null)
"$cli" -s "$s" shutdown nosave >/dev/null 2>&1 || true
wait "$pid" 2>/dev/null || true
rm -rf "$d"
secs=$(echo "$csv" | awk -F'"' -v n="$n" 'NR>1 && $4+0>0 {t+=n/$4} END{printf "%.6f", t}')
echo "$secs $chk"
