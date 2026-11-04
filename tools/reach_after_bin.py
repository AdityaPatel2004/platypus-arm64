#!/usr/bin/env python3
"""reach_after_bin.py — cross-library reachability AFTER hardening, measured
from the hardened binary itself (not from the pass's list of stubs).

Inside the jail, a hijacked indirect call can only land on a BTI landing pad
(`bti c` / `bti jc`) in this module. A landing pad leads OUT of the module in
one hop only if it is immediately followed by a direct branch to a PLT entry,
i.e. it is a fake-PLT stub `bti c ; b <f@plt>`. So:

  reachable_after = { f : some landing pad in the module is `bti c; b f@plt` }

We also report two things the 21-Oct numbers left out:
  * PLT entries that carry their own landing pad (would be reachable directly);
    on a PIE linked by GNU ld only PLT0 does, and with -z now PLT0 is inert.
  * dangerous library functions the module calls DIRECTLY (bl f@plt) from its
    own code — reachable only transitively, by first hijacking into one of
    this module's own functions (the same scope limit as PLaTypus).

usage: reach_after_bin.py HARDENED_BIN [--objdump OBJDUMP] [--csv out.csv]
"""
import argparse, csv, re, subprocess, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from reach import DANGEROUS

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--objdump", default="objdump")
    ap.add_argument("--csv")
    a = ap.parse_args()
    out = subprocess.run([a.objdump, "-d", "--no-show-raw-insn", a.binary],
                         capture_output=True, text=True, check=True).stdout
    rows = []; sec = fn = None
    for ln in out.splitlines():
        m = re.match(r"Disassembly of section (\S+):", ln)
        if m: sec = m.group(1); continue
        m = re.match(r"^([0-9a-f]+) <(.+)>:", ln)
        if m: fn = m.group(2); continue
        m = re.match(r"^\s+([0-9a-f]+):\s+(\S+)\s*(.*)$", ln)
        if m: rows.append((sec, fn, m.group(2), m.group(3)))
    reach, plt_pads, direct = set(), [], set()
    for i, (sec, fn, mn, ops) in enumerate(rows):
        pad = (mn == "bti" and ops.startswith(("c", "jc"))) or (mn == "hint" and ops in ("#0x22", "#0x26", "#34", "#38"))
        if sec == ".plt":
            if pad: plt_pads.append(fn)
            continue
        if pad and i + 1 < len(rows):
            nmn, nops = rows[i + 1][2], rows[i + 1][3]
            m = re.search(r"<(.+)@plt>", nops)
            if nmn == "b" and m:
                reach.add(m.group(1))
        if mn == "bl":
            m = re.search(r"<(.+)@plt>", ops)
            if m and m.group(1) in DANGEROUS:
                direct.add(m.group(1))
    dang = sorted(reach & DANGEROUS)
    print(f"{a.binary}")
    print(f"  cross-library functions reachable in one hop (fake-PLT stubs): {len(reach)}")
    print(f"     {' '.join(sorted(reach))}")
    print(f"  dangerous among them: {len(dang)} {' '.join(dang)}")
    print(f"  PLT entries with a landing pad: {len(plt_pads)} {' '.join(plt_pads)}")
    print(f"  dangerous functions called DIRECTLY by this module (transitive only): "
          f"{' '.join(sorted(direct)) or 'none'}")
    if a.csv:
        new = not os.path.exists(a.csv)
        with open(a.csv, "a", newline="") as f:
            w = csv.writer(f)
            if new:
                w.writerow(["binary", "reachable_after", "dangerous_after",
                            "dangerous_after_list", "plt_pads", "direct_dangerous", "reachable_list"])
            w.writerow([os.path.basename(a.binary), len(reach), len(dang), ";".join(dang),
                        ";".join(plt_pads), ";".join(sorted(direct)), ";".join(sorted(reach))])

if __name__ == "__main__":
    main()
