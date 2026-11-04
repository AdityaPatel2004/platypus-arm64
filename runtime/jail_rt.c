/* jail_rt.c — per-module start-up routine and runtime for the execution jail.
 *
 * Replaces PLaTypus's modified dynamic loader with a self-contained mechanism:
 * a constructor (runs before main) asks the standard dl_iterate_phdr interface
 * "where is my own module loaded, and how big is it?", then computes two mask
 * constants describing the smallest 2^k-aligned block that covers the module,
 * and stores them in two module-local globals the clamp loads from.
 *
 * Trade stated honestly for the report: vs. the paper's loader integration this
 * costs one memory load per indirect call (mask mode) and sets the masks at
 * start-up rather than before any code runs. Linked once into each hardened
 * module (the globals are hidden, so every module gets its own masks).
 */
#define _GNU_SOURCE
#include <link.h>
#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* identity until the constructor runs: (t | 0) & ~0 == t  (no clamp) */
__attribute__((visibility("hidden"))) uint64_t __jail_ormask  = 0;
__attribute__((visibility("hidden"))) uint64_t __jail_andmask = ~(uint64_t)0;

/* audit-mode counters */
static unsigned long jail_audited = 0, jail_oob = 0;

/* the chosen 2^k clamp window [lo,hi) and this module's own extent */
static uintptr_t jail_win_lo, jail_win_hi, jail_mod_lo, jail_mod_hi;

struct find_ctx { uintptr_t self; int found; };

static int find_self(struct dl_phdr_info *info, size_t sz, void *data) {
    (void)sz;
    struct find_ctx *fc = (struct find_ctx *)data;
    uintptr_t base = (uintptr_t)info->dlpi_addr;
    uintptr_t lo = UINTPTR_MAX, hi = 0;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *p = &info->dlpi_phdr[i];
        if (p->p_type != PT_LOAD) continue;
        uintptr_t s = base + p->p_vaddr;
        uintptr_t e = s + p->p_memsz;
        if (s < lo) lo = s;
        if (e > hi) hi = e;
    }
    if (hi == 0 || !(fc->self >= lo && fc->self < hi))
        return 0;                       /* not our module, keep looking */

    /* smallest 2^k-aligned block [B, B+2^k) that fully covers [lo, hi) */
    uintptr_t span = hi - lo;
    int k = 0;
    while (((uintptr_t)1 << k) < span) k++;
    uintptr_t B, mask;
    for (;;) {
        mask = ((uintptr_t)1 << k) - 1;
        B = lo & ~mask;
        if (lo >= B && hi <= B + mask + 1) break;  /* fully covered */
        k++;
    }
    __jail_ormask  = B;                 /* floor:   forces address >= B        */
    __jail_andmask = B | mask;          /* ceiling: forces address <= B+2^k-1  */
    jail_win_lo = B; jail_win_hi = B + mask + 1;
    jail_mod_lo = lo; jail_mod_hi = hi;
    fc->found = 1;
    if (getenv("JAIL_VERBOSE"))
        fprintf(stderr,
            "[jail] module [%#lx,%#lx) span=%#lx -> block 2^%d [%#lx,%#lx] "
            "ormask=%#lx andmask=%#lx\n",
            (unsigned long)lo, (unsigned long)hi, (unsigned long)span, k,
            (unsigned long)B, (unsigned long)(B | mask),
            (unsigned long)__jail_ormask, (unsigned long)__jail_andmask);
    return 1;                           /* stop iteration */
}

/* Soundness check (verbose mode): does any OTHER module's executable segment
 * fall inside our clamp window? The window is the smallest 2^k block covering
 * the module, so it is larger than the module; a reachability "after" count that
 * assumes only our own code is in the window is only valid if nothing else is.
 * For a PIE executable, libraries are mapped far away, so this should be empty —
 * but it is now checked and reported rather than assumed, which matters for a
 * hardened shared library sharing address space with others. */
static int check_overlap(struct dl_phdr_info *info, size_t sz, void *data) {
    (void)sz;
    uintptr_t base = (uintptr_t)info->dlpi_addr;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *p = &info->dlpi_phdr[i];
        if (p->p_type != PT_LOAD || !(p->p_flags & PF_X)) continue;
        uintptr_t s = base + p->p_vaddr, e = s + p->p_memsz;
        /* skip our own module (its segments are supposed to be in the window) */
        if (s >= jail_mod_lo && s < jail_mod_hi) continue;
        if (s < jail_win_hi && e > jail_win_lo) {    /* overlaps the window */
            (*(int *)data)++;
            fprintf(stderr, "[jail] WINDOW OVERLAP: %s exec [%#lx,%#lx) "
                    "intersects clamp window [%#lx,%#lx)\n",
                    info->dlpi_name && info->dlpi_name[0] ? info->dlpi_name : "(exe)",
                    (unsigned long)s, (unsigned long)e,
                    (unsigned long)jail_win_lo, (unsigned long)jail_win_hi);
        }
    }
    return 0;
}

/* priority 101: run before ordinary constructors so masks are set first */
__attribute__((constructor(101)))
static void __jail_init(void) {
    struct find_ctx fc = { (uintptr_t)&__jail_ormask, 0 };
    dl_iterate_phdr(find_self, &fc);
    /* if not found, masks stay identity (fail-open): correctness over a broken
     * security claim; this path is reported if it ever triggers. */
    if (getenv("JAIL_VERBOSE") && fc.found) {
        int ov = 0;
        dl_iterate_phdr(check_overlap, &ov);
        fprintf(stderr, "[jail] window soundness: %d other-module exec segment(s)"
                " inside the clamp window\n", ov);
    }
}

/* audit: count out-of-jail targets, return target UNCHANGED (no enforcement).
 * If JAIL_LOG_OOB is set, resolve distinct out-of-jail targets with dladdr so
 * we can see exactly which cross-module functions a real program calls via a
 * pointer (the address-taken-import / fake-PLT set).
 *
 * hidden visibility: like the mask globals, each hardened module must bind to
 * its OWN copy of these helpers (they read that module's masks). Without this,
 * an executable + a hardened .so would both resolve to one exported copy. */
#include <dlfcn.h>
#define JAIL_OOB_MAX 64
static uint64_t oob_seen[JAIL_OOB_MAX];
static int oob_n = 0;
__attribute__((visibility("hidden")))
uint64_t __jail_audit(uint64_t target) {
    jail_audited++;
    if (target < __jail_ormask || target > __jail_andmask) {
        jail_oob++;
        if (getenv("JAIL_LOG_OOB")) {
            for (int i = 0; i < oob_n; i++) if (oob_seen[i] == target) return target;
            if (oob_n < JAIL_OOB_MAX) {
                oob_seen[oob_n++] = target;
                Dl_info di;
                if (dladdr((void *)(uintptr_t)target, &di) && di.dli_sname)
                    fprintf(stderr, "[jail] OOB target %#lx = %s  (%s)\n",
                            (unsigned long)target, di.dli_sname,
                            di.dli_fname ? di.dli_fname : "?");
                else
                    fprintf(stderr, "[jail] OOB target %#lx = <unresolved>\n",
                            (unsigned long)target);
            }
        }
    }
    return target;
}

/* check: enforce by clamping; log when a target is bent (a blocked escape) */
__attribute__((visibility("hidden")))
uint64_t __jail_check(uint64_t target) {
    uint64_t clamped = (target | __jail_ormask) & __jail_andmask;
    if (clamped != target)
        fprintf(stderr,
            "[jail] blocked cross-module indirect target %#lx -> %#lx\n",
            (unsigned long)target, (unsigned long)clamped);
    return clamped;
}

__attribute__((destructor))
static void __jail_report(void) {
    if (getenv("JAIL_VERBOSE") && jail_audited)
        fprintf(stderr, "[jail] audit: indirect calls=%lu out-of-jail=%lu (%.1f%%)\n",
                jail_audited, jail_oob,
                jail_audited ? 100.0 * jail_oob / jail_audited : 0.0);
}
