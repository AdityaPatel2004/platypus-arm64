# Design note — how the clamp gets its numbers on AArch64 (Research Question 2)

*Revised 4 Nov 2026. The 21 Oct version said Intel PLaTypus used immediates and
that the loads were "free" because the microbenchmark CI straddled zero. Both
statements were wrong; see "Corrections" at the end.*

## The problem in plain words

The clamp must force a call target into the module's own address block, so it
needs two facts: where the block starts, and how big it is (2^k bytes). Every
option below is a different answer to "where do those facts live?".

**What Intel PLaTypus does.** It keeps the two masks in GOT slots, filled in
by a modified loader and then made read-only, and uses x86 instructions that
read memory as part of the arithmetic:
`or rax,[rip+ormask_offset]; and rax,[rip+andmask_offset]` (paper, Listing 1
and the instrumentation listing next to Table 4). That is two instructions,
with two memory reads folded in.

**Why that does not transfer.** AArch64 is a load/store architecture:
`orr`/`and` cannot read memory, so the same idea takes 4 instructions
(2 loads + 2 ALU). An address mask can't be an immediate either, because
AArch64 logical immediates only encode a run of ones replicated across the
register.

## The four options (all measured on the M4, 4 Nov 2026)

| Option | AArch64 sequence | On the target's dependency chain | State an attacker could overwrite | Interop with unhardened code |
|---|---|---|---|---|
| A reserved registers | `orr xt,xt,x27; and xt,xt,x28` | 2 | none (registers) | **breaks**: every library must leave x27/x28 alone |
| B load (`JAIL=mask`) | `ldp x9,x10,[__jail_masks]; orr; and` | 2 (the load issues early) | masks page, **read-only after start-up** | yes |
| C aligned jail (`JAIL=aligned`) | `adrp x16,__ehdr_start; mov x9,x16; bfxil x9,xt,#0,#k` | **1** | none | yes |
| D pc-relative (`JAIL=pcrel`) | `adrp x16,__ehdr_start; sub; and #(2^k−1); add` | 3 | none | yes |

**Option C** is the proposal's "aligned jail placement (Native Client)". The
module is linked with `-z max-page-size=2^k`, so every segment has
`p_align = 2^k`. Linux ≥ 5.10 then places the executable on a 2^k boundary
(glibc ≥ 2.35 does the same for shared libraries). Inserting the target's
low k bits into the module base (`bfxil`) lands it inside the block. NaCl
needed its own loader for this; here the stock kernel does it.

**Option D** needs no alignment. `t' = base + ((t − base) mod 2^k)` keeps
the target in `[base, base + 2^k)` wherever ASLR put the module, at the cost
of one subtract and one add.

In C and D the base comes from `adrp` of the linker-defined `__ehdr_start`
(the module's first byte, page-aligned). It is computed from the program
counter, so there is nothing in memory to corrupt, no constructor has to run
first, and no start-up race exists. The `adrp` is emitted once per call site
as side-effecting inline assembly, which keeps the optimiser from computing
the clamp early and spilling it to the stack. An earlier build did exactly
that; `tools/asm_audit.py` caught it.

## Measured cost

Hand-written clamps in a loop of indirect calls (`bench/clamp_micro.c`;
`results/m4_2026-11-04/bench_clamp_enc*.csv`):

| | A | B | C | D |
|---|---:|---:|---:|---:|
| predictable targets (branch predictor right) | −0.02% | +1.20% | +0.01% | +0.48% |
| unpredictable targets (every call mispredicts) | +7.06% | +7.04% | **+3.57%** | +10.96% |

When the predictor is right, the CPU speculates the call target and the clamp
is off the critical path, so it is nearly free. When the predictor is wrong,
the CPU must wait for the clamped address, and each dependent instruction
adds roughly 3.5% to this loop. That ranks C (1) < A = B (2) < D (3). B's
loads cost no more than A's registers because they do not depend on the
target and are issued early.

On real workloads (redis, SQLite speedtest1, sqlite_bench in memory and on
disk), B costs up to about 2% on SQLite and nothing measurable on redis.
C and D are indistinguishable from zero, or measured below it (layout noise).
See REPORT §4c.

## What each option costs besides time

| | A | B | C | D |
|---|---|---|---|---|
| Security of the bounds | registers can't be overwritten | page read-only after start-up (writable before: masks start at 0/0, so early calls crash) | nothing stored | nothing stored |
| ASLR entropy | unchanged | unchanged | **−(k − 16) bits** (measured: bases 2^22- vs 2^16-aligned) | unchanged |
| Binary size | — | +64 KiB masks page | **file padding** (sqlite3 1.7 → 4.3 MB, redis 6.2 → 12.4 MB) | none |
| Window | — | smallest aligned block covering the module (2–8 MiB for sqlite3, varies with ASLR) | aligned 2^k block | `[base, base + 2^k)` |
| Start-up check | — | computes the masks; aborts if module not found | verifies code fits the block; aborts if not | verifies code fits the window; aborts if not |

## Recommendation

- **Default: D (`pcrel`).** No stored state, no ASLR loss, no size cost, and
  no measurable real-workload overhead. Its only weakness is the worst-case
  microbenchmark (+11%).
- **When call-heavy code with unpredictable targets matters: C (`aligned`).**
  Cheapest clamp, paid for with 6–7 bits of ASLR entropy and larger files.
- **B (`mask`)** stays for comparison with PLaTypus: it is the same design as
  Intel's, made safe with a read-only page.
- **A** is not worth an ABI break: B matches its cost.

## Corrections to the 21 Oct note

1. "The Intel clamp uses immediates": false. PLaTypus loads its masks from
   GOT slots. The real Arm difference is load/store (4 instructions vs 2).
2. "The loads are below the noise floor": the corrected microbenchmark at the
   time read +5.2%. The 5.2% itself then failed to reproduce here (+0.12% for
   the 21 Oct build on this machine). Neither was a sound basis for the
   claim; the encoding experiment above is.
3. "Option C needs a custom loader": not on Linux ≥ 5.10. Segment alignment
   is enough. It was built and measured.
4. "The masks are writable, listed as a limitation": with an arbitrary-write
   bug that is a one-write bypass, demonstrated by `tests/mask_attack_poc.c`.
   The masks are now on a read-only page, and C/D store nothing.
