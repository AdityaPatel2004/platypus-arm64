#!/usr/bin/env python3
"""
reach.py — cross-library control-flow reachability for AArch64 ELF programs.

WHAT THIS MEASURES (plain language)
-----------------------------------
When a program runs, it is loaded together with its shared libraries (libc,
libssl, ...). Each lives in its own block of memory. An *indirect call* reads
its target address from a variable at run time (callbacks, function pointers,
C++ vtables). If an attacker corrupts that variable (a memory bug), the call
jumps wherever the attacker wrote.

Arm BTI only forces that jump to land on the *start of some function*. It does
NOT stop it from landing on a function in a DIFFERENT library — including
dangerous ones like system()/execve() in libc that the program never meant to
call. This tool counts, for a given program, how many functions in *other*
loaded modules an indirect call could land on ("cross-DSO reachable"), and how
many of those are dangerous.

That "before" count is the attack surface. After our hardening pass clamps
indirect calls into their own module, only a tiny set (functions whose address
the module legitimately stores — the "fake-PLT" set) stays reachable; --after
computes that number from the pass's sidecar file.

METRIC DEFINITION (stated so it is reproducible)
------------------------------------------------
reachable_before(P) = sum over every loaded DSO D != P of
                      | exported function symbols of D |
where an "exported function symbol" is a .dynsym entry that is DEFINED
(st_shndx != UNDEF), STT_FUNC or STT_GNU_IFUNC, binding GLOBAL or WEAK, and
not STV_HIDDEN. This is the standard, tool-only proxy for "legitimate
cross-module landing pads": every such symbol is an address another module is
allowed to resolve and call, hence a BTI landing pad reachable after a hijack.
It is conservative: local, non-exported functions with bti landing pads also
exist and are not counted here (an exact count needs disassembly).

Usage:
  reach.py BINARY [BINARY...] [--csv out.csv] [--per-dso per_dso.csv]
  reach.py BINARY --after fakeplt.txt            # (legacy) "after" from the pass's list
  reach.py BINARY --libdir /usr/aarch64-linux-gnu/lib   # no ldd needed
  For the hardened "after" number measured from the binary, use reach_after_bin.py.
Requires: pyelftools (python3-pyelftools), and `ldd` on PATH for lib resolution.
"""
import argparse, csv, os, subprocess, sys, shutil
from collections import OrderedDict

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
except ImportError:
    sys.exit("error: pyelftools not installed (sudo apt-get install python3-pyelftools)")

# Functions an exploit wants to reach. Grouped only for the report; counted flat.
DANGEROUS = {
    # arbitrary command / program execution
    "system", "__libc_system", "popen", "execl", "execlp", "execle",
    "execv", "execvp", "execvpe", "execve", "execveat", "fexecve",
    "posix_spawn", "posix_spawnp",
    # make memory executable again / map memory (ROP/JOP stage setters)
    "mprotect", "mmap", "mmap64", "mremap", "__mmap",
    # dynamic code loading
    "dlopen", "dlsym", "dlmopen",
    # process / privilege
    "fork", "vfork", "clone", "setuid", "setgid", "seteuid", "setegid",
    "setreuid", "setresuid",
    # raw syscall gate
    "syscall",
}

LIBDIRS = []          # set by --libdir: resolve DT_NEEDED ourselves instead of ldd

def resolve_needed(binary):
    """Portable alternative to ldd (works on a foreign-architecture host):
    breadth-first over DT_NEEDED, searching --libdir directories, plus the
    PT_INTERP loader. Same result set as ldd for a normal search path."""
    from elftools.elf.dynamic import DynamicSection
    libs = OrderedDict(); todo = [binary]; seen = set()
    while todo:
        cur = todo.pop(0)
        with open(cur, "rb") as f:
            elf = ELFFile(f)
            for seg in elf.iter_segments():
                if seg["p_type"] == "PT_INTERP":
                    ip = os.path.basename(seg.get_interp_name())
                    for d in LIBDIRS:
                        q = os.path.join(d, ip)
                        if os.path.exists(q): libs.setdefault(ip, os.path.realpath(q))
            dyn = elf.get_section_by_name(".dynamic")
            needed = [t.needed for t in dyn.iter_tags() if t.entry.d_tag == "DT_NEEDED"] \
                     if isinstance(dyn, DynamicSection) else []
        for n in needed:
            if n in seen: continue
            seen.add(n)
            for d in LIBDIRS:
                q = os.path.join(d, n)
                if os.path.exists(q):
                    libs[n] = os.path.realpath(q); todo.append(q); break
            else:
                print(f"  warn: {n} not found in --libdir", file=sys.stderr)
    return libs

def resolve_libs(binary):
    """Return OrderedDict name->abspath of the DSOs this binary actually loads,
    as the real loader resolves them (via ldd, or via --libdir). The binary
    itself is excluded."""
    if LIBDIRS:
        return resolve_needed(binary)
    libs = OrderedDict()
    if not shutil.which("ldd"):
        return libs
    try:
        out = subprocess.run(["ldd", binary], capture_output=True, text=True,
                             timeout=30).stdout
    except Exception as e:
        print(f"  warn: ldd failed on {binary}: {e}", file=sys.stderr)
        return libs
    for line in out.splitlines():
        line = line.strip()
        # formats:  "libfoo.so.1 => /path/libfoo.so.1 (0x...)"
        #           "/lib/ld-linux-aarch64.so.1 (0x...)"
        #           "linux-vdso.so.1 (0x...)"   <- not a real file, skip
        if "=>" in line:
            name, _, rest = line.partition("=>")
            path = rest.strip().split(" (")[0].strip()
            name = name.strip()
        else:
            path = line.split(" (")[0].strip()
            name = os.path.basename(path)
        if not path or "vdso" in name:
            continue
        if os.path.exists(path):
            libs[name] = os.path.realpath(path)
    return libs

def exported_funcs(path):
    """Set of exported (DEFINED, FUNC/IFUNC, GLOBAL/WEAK, not hidden) symbol names."""
    names = set()
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            dyn = elf.get_section_by_name(".dynsym")
            if not isinstance(dyn, SymbolTableSection):
                return names
            for sym in dyn.iter_symbols():
                i = sym["st_info"]
                o = sym["st_other"]
                if i["type"] not in ("STT_FUNC", "STT_GNU_IFUNC"):
                    continue
                if i["bind"] not in ("STB_GLOBAL", "STB_WEAK"):
                    continue
                if sym["st_shndx"] == "SHN_UNDEF":
                    continue
                if o["visibility"] == "STV_HIDDEN":
                    continue
                if sym.name:
                    names.add(sym.name)
    except Exception as e:
        print(f"  warn: cannot read {path}: {e}", file=sys.stderr)
    return names

def analyze(binary):
    binary = os.path.realpath(binary)
    libs = resolve_libs(binary)
    per_dso = []       # (dso_name, path, nfuncs, ndanger, danger_names)
    total = 0
    danger_total = set()
    for name, path in libs.items():
        funcs = exported_funcs(path)
        dangers = funcs & DANGEROUS
        per_dso.append((name, path, len(funcs), sorted(dangers)))
        total += len(funcs)
        danger_total |= {(name, d) for d in dangers}
    return {
        "binary": binary,
        "per_dso": per_dso,
        "reachable_before": total,
        "n_dsos": len(libs),
        "dangerous": sorted(danger_total),
        "dangerous_count": len(danger_total),
    }

def after_count(fakeplt_file):
    """'after' reachable = number of distinct external functions that still have
    a fake-PLT stub (address-taken imports the pass had to preserve)."""
    names = set()
    with open(fakeplt_file) as f:
        for ln in f:
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                names.add(ln)
    return names

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binaries", nargs="+")
    ap.add_argument("--csv", help="summary CSV (one row per binary)")
    ap.add_argument("--per-dso", help="detailed CSV (one row per (binary,dso))")
    ap.add_argument("--libdir", action="append", default=[],
                    help="resolve DT_NEEDED in this directory instead of running ldd "
                         "(repeatable; for analysing foreign-architecture binaries)")
    ap.add_argument("--after", metavar="FAKEPLT",
                    help="treat as hardened: reachable = fake-PLT set in this file")
    args = ap.parse_args()
    LIBDIRS.extend(args.libdir)

    summary_rows = []
    per_dso_rows = []
    for b in args.binaries:
        if not os.path.exists(b):
            w = shutil.which(b)
            if w: b = w
            else:
                print(f"skip (not found): {b}", file=sys.stderr); continue
        r = analyze(b)
        after = ""
        after_danger = ""
        if args.after:
            fp = after_count(args.after)
            after = len(fp)
            after_danger = sorted(fp & DANGEROUS)
        name = os.path.basename(r["binary"])
        print(f"\n=== {name} ===")
        print(f"  loaded DSOs            : {r['n_dsos']}")
        print(f"  reachable cross-DSO fns: {r['reachable_before']}  (BEFORE hardening)")
        print(f"  dangerous reachable    : {r['dangerous_count']}  "
              f"-> {', '.join(f'{d}@{m}' for m,d in r['dangerous'][:12])}"
              + (" ..." if len(r['dangerous'])>12 else ""))
        if args.after:
            print(f"  reachable AFTER (fakePLT): {after}  (surviving imports)")
            print(f"  dangerous AFTER          : {len(after_danger)}"
                  + (f"  -> {', '.join(after_danger)}" if after_danger else "  (none)"))
        for dso, path, n, dl in r["per_dso"]:
            per_dso_rows.append([name, dso, n, len(dl), ";".join(dl)])
        summary_rows.append([name, r["binary"], r["n_dsos"],
                             r["reachable_before"], r["dangerous_count"],
                             ";".join(f"{d}@{m}" for m,d in r["dangerous"]),
                             after])

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["program","path","n_dsos","reachable_before",
                        "dangerous_count","dangerous_list","reachable_after"])
            w.writerows(summary_rows)
        print(f"\nwrote {args.csv}")
    if args.per_dso:
        with open(args.per_dso, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["program","dso","exported_funcs","dangerous_in_dso","dangerous_names"])
            w.writerows(per_dso_rows)
        print(f"wrote {args.per_dso}")

if __name__ == "__main__":
    main()
