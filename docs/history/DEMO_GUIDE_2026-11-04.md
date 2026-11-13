# Demo walkthrough — teaching from the real artifacts

The idea: for each point, **open the actual code**, **show it in assembly**, then
**run it** so the audience sees the result with their own eyes. Nothing staged —
every file below is a real part of the project. All commands run **inside the VM**
(`limactl start e0256` → `limactl shell e0256` → `cd ~/e0256`).

Pre-built binaries live in `demos/out/`, pre-generated assembly in `demos/asm/`,
so nothing has to compile mid-talk (but compiling live is fine — it's ~1 s).

> **4 Nov 2026:** `demos/out/` holds the **21 Oct** binaries. Their hardened
> SQLite crashes on any on-disk database, and their masks are writable. Before
> presenting, run `bash run_all.sh` once and use the fresh binaries in
> `build/native/` (same names with `_mask`/`_pcrel`/`_aligned`, e.g.
> `build/native/poc_pcrel hijack`). Numbers below are updated to REPORT.md.

Order below is the suggested teaching arc. Each step says what to open, what to
run, and the one line it proves.

---

## Step 1 — What BTI actually does (and the exact instruction it checks)

**Open the code:**
```bash
cat tests/bti_probe.c
```
Point at: `f = (int(*)(void))((uintptr_t)tgt + 4);` — we deliberately call **4
bytes past** the start of `tgt`.

**Show it in assembly** — look at `tgt` in the compiled binary:
```bash
objdump -d demos/out/bti_probe | awk '/<tgt>:/{m=1} m{print} /ret/&&m{exit}'
```
You'll see:
```
<tgt>:  bti   c          <- the landing pad (the ONLY legal place to land)
        mov   w0, #42
        ret
```
Point at `bti c`: "BTI says an indirect jump may only land *here*. `tgt+4` is the
`mov` — not a landing pad."

**Run it:**
```bash
demos/out/bti_probe
```
Output: normal call runs; the skip-pad call → **TRAP [SIGILL]**.
**Proves:** BTI is real and enforced on this machine.

---

## Step 2 — The hole BTI leaves: a hijack that reaches `system()`

**Open the code (the vulnerable program):**
```bash
cat tests/hijack_poc.c
```
Point at: the struct `{ char buf[16]; void (*fp)(const char*); }` (buffer right
before a function pointer), and the `memcpy(s.buf, payload, 24)` — a 24-byte copy
into a 16-byte buffer that overflows into `fp`, overwriting it with libc's real
`system` address.

**Run it (unhardened, but BTI is ON):**
```bash
demos/out/poc_unhard hijack
```
Output: `uid=501(adityapatel) ...` — **the shell command `id` ran.**
**Proves:** BTI alone does *not* stop a cross-library hijack. This is the paper's
claim about Arm, demonstrated live on your machine.

---

## Step 3 — Our defense, visible in the assembly

**Show the same program, with and without our pass, side by side.** The cleanest
example is the toy (one indirect call):
```bash
diff demos/asm/toy_base.s demos/asm/toy_jail.s
```
The only added lines (prefixed `>`) are:
```
ldp  x9, x10, [x25]        <- load both masks from the read-only __jail_masks page
orr  x8,  x8, x9           <- force address >= module base
and  x8,  x8, x10          <- force address <= module top
```
"Before every indirect `blr`, our compiler pass inserts these instructions that
bend the target back into this program's own memory." (This is Option B,
`JAIL=mask`. The other two encodings are a good second slide:
`JAIL=pcrel` → `adrp; sub; and #0x3fffff; add`, and `JAIL=aligned` → one
`bfxil`. Rebuild the toy with each and `objdump -d` it.)

> 4 Nov 2026: the `demos/asm/*.s` files are from the 21 Oct pass, which used
> two separate globals `__jail_ormask`/`__jail_andmask`; regenerate them with
> `JAIL=mask bin/a64cc -O2 -S tests/toy_indirect.c -o demos/asm/toy_jail.s`.

(Same thing in the exploit itself: `demos/asm/poc_base.s` vs `poc_jail.s`.)

**Run the defended exploit:**
```bash
demos/out/poc_hard hijack
```
Output: `Segmentation fault (core dumped)` — **no `id`, the shell never ran.**
**Proves:** the identical exploit is blocked. Same attack, same BTI, one pass
makes the difference.

---

## Step 4 — Where the mask numbers come from (optional depth)

**Open the runtime:**
```bash
cat runtime/jail_rt.c
```
Point at `__jail_init` / `find_self`: at start-up it calls `dl_iterate_phdr` to
ask "where am I loaded?", then computes the two masks. **Show the real values:**
```bash
JAIL_VERBOSE=1 demos/out/toy_jail 1
```
Output includes the actual module range and `ormask=… andmask=…` for that run.
**Proves:** the masks are computed from the live process, not hard-coded.

---

## Step 5 — A real edge case we discovered (the research contribution)

This is the part that teaches *why the port is non-trivial*. Our `audit` mode
watches every indirect call and reports any that leave the module:
```bash
JAIL_LOG_OOB=1 demos/out/sqlite_audit 100000 100000 2>&1 | grep 'OOB target' | sort -u
```
Output:
```
OOB target … = pread64   (libc.so.6)
OOB target … = pwrite    (libc.so.6)
OOB target … = stat / access / __close / __fstat64 (libc.so.6)
```
"Real SQLite, at scale, legitimately calls libc through function pointers (its
file layer). A naive jail would break these. That's the problem we solved with
**fake-PLT** — in-module two-instruction stubs `bti c; b <f>` (`cat
pass/JailPass.cpp`, function `installFakePlt`). On disk SQLite also calls
`fcntl64` (and `mremap` in mmap mode) this way — both variadic, which the 21 Oct
version could not stub, so it crashed on every on-disk database. Now 25 stubs
are generated and the hardened SQLite is byte-identical in all 4 storage modes
(`bash tests/check_correctness.sh <base> <hardened>`)."
**Proves:** this is engineering/research, not a mechanical port.

---

## Step 6 — The measurements (fast, run live)

Measure **our own** sqlite3 build both ways (same binary family — apples to
apples). Build + capture the fake-PLT list:
```bash
SRC=targets/sqlite_src/sqlite-amalgamation-3540100
F="-O2 -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION -I$SRC"
bin/a64cc $F $SRC/shell.c $SRC/sqlite3.c -lm -o /tmp/sqlite_base
rm -f /tmp/fp.txt; JAIL=mask JAIL_FAKEPLT_OUT=/tmp/fp.txt bin/a64cc $F $SRC/shell.c $SRC/sqlite3.c -lm -o /tmp/sqlite_hard
```
**Before:**
```bash
python3 tools/reach.py /tmp/sqlite_base
```
→ **3,816** reachable cross-library functions, **32 dangerous** (system, execve, …).
**After** (measured from the hardened binary itself):
```bash
python3 tools/reach_after_bin.py /tmp/sqlite_hard
```
→ **26** reachable, **2** dangerous (`mmap64`, `mremap`). A **99.3%** cut. It also
lists `system`/`popen`, which the sqlite shell calls *directly*: reachable only in
two steps, via the shell's own code (same limit as PLaTypus).
**Completeness** (every indirect call clamped):
```bash
python3 tools/asm_audit.py /tmp/sqlite_hard
```
→ 1,909 call sites clamped (1,761 `blr` + 148 indirect tail calls `br`); the only 2
unclamped branches are in GCC's crtbeginS.o.

**The stronger attacker** (write-then-hijack):
```bash
build/native/attack_mask          # Segmentation fault at the mask write: masks are read-only
```
The 21 Oct build lost this one: the attacker rewrote the masks and the shell ran.

> The distro `/usr/bin/sqlite3` shows a bigger 6,022 "before" because it also
> loads `libsqlite3.so` — that number is the *ecosystem* attack surface
> (Deliverable 1), not the before for this defence. Use our own build for the
> before/after so it is the same binary.

---

## Long-running — show as results, not live

These take too long to run during a talk. Show the saved figure/number and say
"this is a measurement that runs for ~N; here is the result":

| Task | Why not live | Where the result is |
|------|-------------|---------------------|
| Distribution BTI scan | ~6 s (borderline; can run `bash tools/btiscan.sh /tmp/x.csv /usr/bin` for just /usr/bin in ~2 s) | `results/bti_scan.csv`, `results/figs/fig1_bti_coverage.png` → **0.1%** |
| Overhead benchmarks | 15 reps × 2 builds × several s each (minutes), needs a quiet machine | `results/figs/fig3_overhead.png`, `REPORT.md §4c` → +0.32% / +0.96% / +2.71% |
| liboqs dual build | ~2 min compile | pre-built; result in `REPORT.md §5` → +0.96%, correctness OK |

If asked for a live taste of overhead, a 5-run quick version (~20 s):
```bash
for b in demos/out/sb_base demos/out/sb_jail; do echo -n "$b: "; \
  for i in 1 2 3 4 5; do taskset -c 1 $b 80000 80000|awk '{print $1}'; done|sort -n|sed -n 3p; done
```

---

### If a binary is missing (e.g. fresh VM)
Rebuild the whole demo set in one go:
```bash
bash demos/run_demos.sh        # also runs them; Ctrl-C after the builds if you only want the binaries
```
