#!/usr/bin/env python3
"""asm_audit.py — completeness check on a HARDENED AArch64 binary.

For every indirect branch in the final machine code (`blr xN` = indirect call,
`br xN` = indirect tail call / jump table / PLT), find the instruction that last
wrote xN and classify the branch:

  clamped-B   last writer is `and xN, ..`            (Option B: or/and masks)
  clamped-C   last writer is `bfxil xN, xT, #0, #k`   (Option C: aligned jail)
  clamped-D   last writer is `add xN, xW, xB` where xW came from an
              `and .., #imm` shortly before           (Option D: base-relative)
  jumptable   `br` whose target is built from an `adr` table + scaled index
              (switch statement; target is inside the same function)
  plt         inside the .plt section (direct-call plumbing, not a call site)
  UNCLAMPED   anything else — reported with its function name

A clamped target kept in a callee-saved register across another call is still
clamped, but is counted separately: the callee may spill that register to its
stack frame, where a stack-write attacker could alter it before it is restored.

Replaces the 21-Oct shell version, which only matched an `and` with the same
register within 16 instructions, ignored `br` entirely and mislabelled indirect
tail calls as "PLT/fake-PLT jumps".

usage: asm_audit.py BINARY [--objdump aarch64-linux-gnu-objdump] [--quiet]
"""
import argparse, collections, re, subprocess, sys

CALLEE_SAVED = {f"x{i}" for i in range(19, 29)} | {"x29", "x30"}
NOWRITE = {"str", "stp", "stur", "strb", "strh", "sturb", "sturh", "cmp", "cmn",
           "tst", "cbz", "cbnz", "tbz", "tbnz", "b", "ret", "nop", "bti", "hint",
           "paciasp", "autiasp", "prfm", "dmb", "dsb", "isb", "ccmp", "fcmp"}

def reg(r):
    r = r.strip().rstrip(",")
    if re.fullmatch(r"[wx]\d+", r):
        return "x" + r[1:]
    return r

def parse(binary, objdump):
    out = subprocess.run([objdump, "-d", "--no-show-raw-insn", binary],
                         capture_output=True, text=True, check=True).stdout
    sec = fn = None; ins = []
    for ln in out.splitlines():
        m = re.match(r"Disassembly of section (\S+):", ln)
        if m: sec = m.group(1); continue
        m = re.match(r"^([0-9a-f]+) <(.+)>:", ln)
        if m: fn = m.group(2); continue
        m = re.match(r"^\s+([0-9a-f]+):\s+(\S+)\s*(.*)$", ln)
        if m:
            ops = m.group(3).split("//")[0].strip()
            ins.append((sec, fn, int(m.group(1), 16), m.group(2), ops))
    return ins

crossed = [0]

def writer_of(ins, i, r, limit=48):
    """index of the last instruction before i (same function) that writes r"""
    f = ins[i][1]; j = i - 1
    while j >= 0 and ins[j][1] == f and i - j <= limit:
        mn, ops = ins[j][3], ins[j][4]
        if mn in ("bl", "blr"):
            if r not in CALLEE_SAVED:
                return None, "clobbered-by-call"
            crossed[0] += 1                 # value kept live across a call
            j -= 1
            continue
        if mn not in NOWRITE and not mn.startswith("b.") and ops:
            first = ops.split(",")[0]
            if reg(first) == r:
                return j, None
            if mn in ("ldp",) and len(ops.split(",")) > 1 and reg(ops.split(",")[1]) == r:
                return j, None
        j -= 1
    return None, "not-found"

def classify(ins, i):
    sec, f, a, mn, ops = ins[i]
    if sec == ".plt":
        return "plt"
    r = reg(ops.split(",")[0])
    j, why = writer_of(ins, i, r)
    if j is None:
        return "UNCLAMPED"
    wmn, wops = ins[j][3], ins[j][4]
    if wmn == "and":
        return "clamped-B"
    if wmn == "bfxil":
        return "clamped-C"
    if wmn == "add":
        parts = [p.strip() for p in wops.split(",")]
        if any(("sxtw" in p or "uxtw" in p or "lsl" in p) for p in parts[2:]):
            # adr-based switch table: look for an adr feeding the add
            for k in range(j - 1, max(j - 12, -1), -1):
                if ins[k][1] != f: break
                if ins[k][3] == "adr":
                    return "jumptable"
        # switch table, second form: adr xA, . ; ldrsw xO, [...] ; add xT, xA, xO
        for src in parts[1:3]:
            sj, _ = writer_of(ins, j, reg(src), limit=12)
            if sj is not None and ins[sj][3] == "adr":
                return "jumptable"
        # Option D: add xT, xW, xBase with xW = and xW, .., #imm
        for src in parts[1:3]:
            sj, _ = writer_of(ins, j, reg(src), limit=12)
            if sj is not None and ins[sj][3] == "and" and "#" in ins[sj][4]:
                return "clamped-D"
    return "UNCLAMPED"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--objdump", default="objdump")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()
    ins = parse(a.binary, a.objdump)
    cnt = collections.Counter(); bad = []
    for i, (sec, f, addr, mn, ops) in enumerate(ins):
        if mn not in ("blr", "br"):
            continue
        crossed[0] = 0
        c = classify(ins, i)
        cnt[(mn, c)] += 1
        if c.startswith("clamped") and crossed[0]:
            cnt[(mn, "  (of which clamp reused across a call)")] += 1
        if c == "UNCLAMPED":
            bad.append((hex(addr), f, mn, ops))
    calls = sum(v for (m, c), v in cnt.items() if c.startswith("clamped"))
    print(f"{a.binary}")
    for (m, c), v in sorted(cnt.items()):
        print(f"  {m:4} {c:11} {v}")
    print(f"  => clamped indirect call sites: {calls}; unclamped indirect branches: {len(bad)}")
    if not a.quiet:
        for b in bad[:40]:
            print("     UNCLAMPED", *b)
    return 0

if __name__ == "__main__":
    sys.exit(main())
