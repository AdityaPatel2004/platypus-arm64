# Design note — mask encoding on AArch64 (Research Question 2)

**Question.** PLaTypus's Intel clamp is two instructions with the masks baked in
as immediates (`or rax,[ormask]; and rax,[andmask]` — actually immediate on
x86). On AArch64 that does not transfer, because an `AND`/`ORR`/`BIC` *immediate*
can only encode a **logical (bitmask) immediate**: a single run of ones inside a
2/4/8/16/32/64-bit element, replicated across the register, optionally rotated.
A realistic per-module address mask (e.g. `0x0000aaf8_24340000` floor /
`0x0000aaf8_2437ffff` ceiling) is not such a pattern, so the constants cannot sit
in the instruction. The port must choose how to deliver them. Three options,
with the trade-offs.

## Option A — reserved register
Keep `ormask`/`andmask` in two reserved callee-saved registers, set once at
start-up. Clamp = two register-to-register ops (`orr`, `and`), no memory.
- **Pro:** fastest possible clamp; no load.
- **Con:** reserving registers globally is an ABI change — every object in the
  process (including unhardened libraries and libc) would have to agree not to
  use them, which **breaks the ability to mix hardened and unhardened code**, one
  of PLaTypus's headline properties. Also raises register pressure everywhere.
- **Verdict:** rejected. The interop cost is not worth the ~1–2 saved loads,
  especially as the loads turn out to be below the measurement noise floor (§4c).

## Option B — load the masks from a module-local global  **(chosen)**
Two hidden globals (`__jail_ormask`, `__jail_andmask`) per module, filled at
start-up by the `dl_iterate_phdr` constructor; clamp = two loads + `orr` + `and`.
- **Pro:** no ABI change, no reserved registers, **composes with unhardened
  code** (reserves nothing); simplest to implement; the globals are hot in L1.
- **Con:** one extra load per mask per indirect call vs Option A, and the masks
  live in writable memory for the process lifetime (see threat-model limitation).
- **Measured cost:** below what this setup can resolve — the indirect-call
  microbenchmark's clamp cost and the SQLite/liboqs overheads all have 95%
  bootstrap CIs that straddle 0 (§4c). So the "extra loads" are effectively free
  on the M4's wide out-of-order core (the mask loads sit off the dependent call
  chain).
- **Verdict:** chosen. Best interop, negligible measured cost.

## Option C — aligned jails (NaCl-style encodable immediates)
Place each module so its clamp mask *becomes* an encodable logical immediate,
then the clamp needs no loads (`bic`/`and` with an immediate, as Google Native
Client shipped on Arm in 2010: `bic r0,r0,#0xC000000F; bx r0`, ~5% overhead while
instrumenting *every* branch).
- **Pro:** no loads, no writable masks; the elegant answer.
- **Con:** requires controlling the module's **load placement** to a specially
  chosen base whose complement mask is encodable — which reintroduces exactly the
  loader/linker coupling that Option B was chosen to avoid (PLaTypus itself
  modifies the loader for this). Our constructor already derives a 2^k-aligned
  window, but ASLR puts the module at an arbitrary aligned-down base, whose mask
  is not encodable; forcing an encodable base needs a linker script
  (`-Ttext`/segment base) or a custom loader.
- **Verdict:** future work. It is the natural next step if loader/linker control
  is acceptable; the measurement harness and reach tooling here would carry over
  unchanged.

## Summary
| Option | Clamp cost | Interop with unhardened code | Needs placement control | Status |
|--------|-----------|------------------------------|-------------------------|--------|
| A reserved reg | 2 ALU ops | **No** (ABI change) | No | rejected |
| **B load global** | 2 loads + 2 ALU | **Yes** | No | **built, measured** |
| C aligned jail | 2 ALU (imm) | Yes | **Yes** | future work |

The decision (B) prioritises the paper's incremental-deployment property over the
few saved instructions, and the measurements justify it: the saved instructions
are not resolvable above noise, so Option A's interop sacrifice buys nothing here.
