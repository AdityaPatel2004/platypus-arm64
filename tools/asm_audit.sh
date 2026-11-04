#!/usr/bin/env bash
# asm_audit.sh — completeness check on a HARDENED binary. For every indirect
# CALL `blr xT`, verify a clamp wrote xT shortly before: an `and xT, ...`
# (the ceiling op of the clamp) within K instructions. This is register-precise,
# not position-based, so it is robust to the scheduler spacing the clamp out.
# Any `blr` with no matching `and xT` is reported with its function — a genuine
# uninstrumented indirect call. `br` is listed separately (PLT / fake-PLT jumps).
#   usage: asm_audit.sh BINARY [window=16]
set -euo pipefail
bin="${1:?usage: asm_audit.sh BINARY [window]}"
K="${2:-16}"
objdump -d "$bin" | awk -v K="$K" '
  /^[0-9a-f]+ <.*>:/ { fn=$2; sub(/:$/,"",fn); delete andat }   # reset per function
  NF>=3 {
    n++; mn=$3; sub(/ .*/,"",mn)
    # destination register is the first operand token
    dst=$4; sub(/,.*/,"",dst); gsub(/ /,"",dst)
    if (mn=="and") andat[dst]=n
    else if (mn=="blr") {
      tgt=$4; gsub(/ /,"",tgt)
      blr++
      if ((tgt in andat) && (n - andat[tgt]) <= K) clamped++
      else { printf "  UNCLAMPED blr %s (x=%s) in %s\n",$1,tgt,fn; un++ }
    }
    else if (mn=="br") br++
  }
  END{
    printf "\n%s\n", BIN
    printf "indirect calls (blr)      : %d\n", blr+0
    printf "  clamped (and xT within %d): %d\n", K, clamped+0
    printf "  UNCLAMPED               : %d\n", un+0
    printf "indirect branches (br)    : %d  (PLT x16/x17 + fake-PLT tail jumps)\n", br+0
  }' BIN="$bin"
