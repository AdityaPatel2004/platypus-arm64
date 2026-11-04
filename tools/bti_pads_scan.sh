#!/usr/bin/env bash
# bti_pads_scan.sh — for every ELF shared object / executable under the given
# directories, report BOTH
#   bti_marker : the GNU property note the loader looks at (BTI enforced only if set)
#   bti_pads   : how many `bti` landing-pad instructions the code really contains
# A file with many pads but no marker was compiled for BTI and then lost the
# marker at link time (one unmarked input object, e.g. glibc's crti.o, is enough).
#   usage: bti_pads_scan.sh OUT.csv DIR [DIR...]
#   env:   OBJDUMP / READELF (default objdump / readelf; aarch64-linux-gnu-* when cross)
set -u
out="${1:?usage: bti_pads_scan.sh OUT.csv DIR...}"; shift
OD="${OBJDUMP:-objdump}"; RE="${READELF:-readelf}"
echo "library,path,bti_marker,pac_marker,bti_pads,paciasp" > "$out"
find "$@" -type f \( -name '*.so*' -o -perm -u+x \) 2>/dev/null | sort | while read -r f; do
  [ "$(head -c4 "$f" 2>/dev/null | od -An -tx1 | tr -d ' ')" = 7f454c46 ] || continue
  feat="$("$RE" -n "$f" 2>/dev/null | grep 'AArch64 feature:')"
  bm=absent; pm=absent
  echo "$feat" | grep -qw BTI && bm=present
  echo "$feat" | grep -qw PAC && pm=present
  d="$("$OD" -d --no-show-raw-insn "$f" 2>/dev/null)"
  pads=$(printf '%s\n' "$d" | grep -cP '\tbti\b')
  pac=$(printf '%s\n' "$d" | grep -cP '\tpaciasp\b')
  echo "$(basename "$f"),$f,$bm,$pm,$pads,$pac" >> "$out"
done
echo "wrote $out"; awk -F, 'NR>1{n++; if($3=="present")m++; if($5>0)p++} END{printf "files=%d marker=%d with_pads=%d\n",n,m,p}' "$out"
