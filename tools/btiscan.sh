#!/usr/bin/env bash
# btiscan.sh — measure how much of an Arm Linux distribution actually enables
# the BTI (and PAC) hardware CFI foundation this defence stands on.
#
# For every ELF file under the given directories, read its GNU property note
# (readelf -n) and record whether it carries:
#   BTI  = GNU_PROPERTY_AARCH64_FEATURE_1_BTI  (indirect-branch landing pads)
#   PAC  = GNU_PROPERTY_AARCH64_FEATURE_1_PAC  (return-address signing)
# A binary only gets BTI enforced by the CPU if this note is present AND it was
# built with -mbranch-protection; so this note is the ground truth for coverage.
#
# Usage: btiscan.sh OUT.csv DIR [DIR...]
#   e.g. btiscan.sh results/bti_scan.csv /usr/bin /usr/sbin /usr/lib/aarch64-linux-gnu
set -u
out="${1:?usage: btiscan.sh OUT.csv DIR [DIR...]}"; shift
echo "path,dir,is_elf,has_bti,has_pac" > "$out"
tot=0; bti=0; pac=0
for dir in "$@"; do
  while IFS= read -r f; do
    # cheap ELF magic check before spawning readelf
    [ -f "$f" ] || continue
    if [ "$(head -c4 "$f" 2>/dev/null | od -An -tx1 | tr -d ' ')" != "7f454c46" ]; then
      continue
    fi
    # Match ONLY the GNU-property feature line (e.g. "AArch64 feature: BTI, PAC"),
    # not any other occurrence of the letters BTI/PAC elsewhere in the notes.
    feat="$(readelf -n "$f" 2>/dev/null | grep -i 'AArch64 feature:')"
    hb=0; hp=0
    echo "$feat" | grep -qiw 'BTI' && hb=1
    echo "$feat" | grep -qiw 'PAC' && hp=1
    echo "$f,$dir,1,$hb,$hp" >> "$out"
    tot=$((tot+1)); bti=$((bti+hb)); pac=$((pac+hp))
  done < <(find "$dir" -type f 2>/dev/null)
done
echo "--------------------------------------------------"
echo "scanned dirs : $*"
echo "ELF files    : $tot"
if [ "$tot" -gt 0 ]; then
  awk -v t="$tot" -v b="$bti" -v p="$pac" 'BEGIN{
    printf "with BTI     : %d  (%.1f%%)\n", b, 100*b/t
    printf "with PAC     : %d  (%.1f%%)\n", p, 100*p/t
  }'
fi
echo "csv          : $out"
