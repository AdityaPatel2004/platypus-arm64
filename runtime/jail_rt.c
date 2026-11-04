/* jail_rt.c — per-module start-up routine and runtime for the execution jail.
 *
 * Replaces PLaTypus's modified dynamic loader with a self-contained mechanism:
 * a constructor (runs before main) asks the standard dl_iterate_phdr interface
 * "where is my own module loaded, and how big is it?".
 *
 *  - mask mode (Option B): computes the smallest 2^k-aligned block covering the
 *    module, writes ormask/andmask, then makes the page holding them READ-ONLY
 *    (mprotect), so a memory-corruption bug cannot rewrite the jail bounds.
 *    PLaTypus gets the same property by keeping its masks in RELRO'd GOT slots.
 *  - pcrel mode (Option D): nothing is stored; the clamp computes the base from
 *    the PC. The constructor only VERIFIES that the module fits in the 2^k
 *    window the code was compiled for, and aborts if it does not.
 *
 * Fail-closed: the masks start as {0, 0}, so an indirect call made before the
 * constructor runs is clamped to address 0 and crashes instead of escaping.
 * If the module cannot be found, the process aborts with a message.
 *
 * Linked once into each hardened module; all symbols are hidden, so every
 * module (executable or shared library) gets its own copy and its own masks.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#define JAIL_PAGE 65536   /* covers 4 KiB, 16 KiB and 64 KiB kernel page sizes */

/* The two masks on a page of their own (64 KiB aligned, exactly 64 KiB long),
 * so mprotect(PROT_READ) affects nothing else. All-zero = fail-closed. */
struct jail_masks { uint64_t ormask, andmask; uint8_t pad[JAIL_PAGE - 16]; };
__attribute__((visibility("hidden"), aligned(JAIL_PAGE), section(".bss.jail_masks")))
struct jail_masks __jail_masks;

/* Option D: k recorded by the pass (absent unless the module was built pcrel) */
extern const uint64_t __jail_pcrel_k __attribute__((weak, visibility("hidden")));
extern const char __ehdr_start[] __attribute__((visibility("hidden")));

static unsigned long jail_audited = 0, jail_oob = 0;
static uintptr_t win_lo, win_hi, mod_lo, mod_hi;

struct find_ctx { uintptr_t self; int found; };

static int find_self(struct dl_phdr_info *info, size_t sz, void *data) {
    (void)sz;
    struct find_ctx *fc = (struct find_ctx *)data;
    uintptr_t base = (uintptr_t)info->dlpi_addr, lo = UINTPTR_MAX, hi = 0;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *p = &info->dlpi_phdr[i];
        if (p->p_type != PT_LOAD) continue;
        uintptr_t s = base + p->p_vaddr, e = s + p->p_memsz;
        if (s < lo) lo = s;
        if (e > hi) hi = e;
    }
    if (hi == 0 || !(fc->self >= lo && fc->self < hi)) return 0;  /* not us */
    mod_lo = lo; mod_hi = hi; fc->found = 1;
    return 1;
}

static int check_overlap(struct dl_phdr_info *info, size_t sz, void *data) {
    (void)sz;
    uintptr_t base = (uintptr_t)info->dlpi_addr;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *p = &info->dlpi_phdr[i];
        if (p->p_type != PT_LOAD || !(p->p_flags & PF_X)) continue;
        uintptr_t s = base + p->p_vaddr, e = s + p->p_memsz;
        if (s >= mod_lo && s < mod_hi) continue;          /* our own segment */
        if (s < win_hi && e > win_lo) {
            (*(int *)data)++;
            fprintf(stderr, "[jail] WINDOW OVERLAP: %s exec [%#lx,%#lx) inside "
                    "[%#lx,%#lx)\n", info->dlpi_name && info->dlpi_name[0] ?
                    info->dlpi_name : "(exe)", (unsigned long)s, (unsigned long)e,
                    (unsigned long)win_lo, (unsigned long)win_hi);
        }
    }
    return 0;
}

__attribute__((noreturn)) static void jail_die(const char *why) {
    fprintf(stderr, "[jail] FATAL: %s\n", why);
    abort();
}

/* priority 101: before ordinary constructors, so the masks are set first */
__attribute__((constructor(101)))
static void __jail_init(void) {
    struct find_ctx fc = { (uintptr_t)&__jail_init, 0 };
    dl_iterate_phdr(find_self, &fc);
    if (!fc.found) jail_die("cannot locate own module via dl_iterate_phdr");
    int verbose = getenv("JAIL_VERBOSE") != NULL;
    uintptr_t span = mod_hi - mod_lo;

    if (&__jail_pcrel_k) {                         /* Option D: verify only */
        uint64_t k = __jail_pcrel_k;
        uintptr_t base = (uintptr_t)__ehdr_start;
        win_lo = base; win_hi = base + ((uintptr_t)1 << k);
        if (base != mod_lo || mod_hi > win_hi) {
            fprintf(stderr, "[jail] module [%#lx,%#lx) span=%#lx does not fit "
                    "pcrel window 2^%lu from %#lx; rebuild with larger JAIL_K\n",
                    (unsigned long)mod_lo, (unsigned long)mod_hi,
                    (unsigned long)span, (unsigned long)k, (unsigned long)base);
            jail_die("pcrel window too small");
        }
        if (verbose)
            fprintf(stderr, "[jail] pcrel module [%#lx,%#lx) span=%#lx window 2^%lu "
                    "[%#lx,%#lx)\n", (unsigned long)mod_lo, (unsigned long)mod_hi,
                    (unsigned long)span, (unsigned long)k,
                    (unsigned long)win_lo, (unsigned long)win_hi);
    }

    /* Option B masks (also used by check/audit): smallest covering 2^k block */
    int k = 0;
    while (((uintptr_t)1 << k) < span) k++;
    uintptr_t B, m;
    for (;;) {
        m = ((uintptr_t)1 << k) - 1;
        B = mod_lo & ~m;
        if (mod_hi <= B + m + 1) break;
        k++;
    }
    __jail_masks.ormask = B;
    __jail_masks.andmask = B | m;
    if (!&__jail_pcrel_k) { win_lo = B; win_hi = B + m + 1; }
    if (mprotect(&__jail_masks, sizeof __jail_masks, PROT_READ) != 0)
        jail_die("mprotect(masks, PROT_READ) failed");
    if (verbose && !&__jail_pcrel_k)
        fprintf(stderr, "[jail] module [%#lx,%#lx) span=%#lx -> block 2^%d "
                "[%#lx,%#lx] ormask=%#lx andmask=%#lx (masks page read-only)\n",
                (unsigned long)mod_lo, (unsigned long)mod_hi, (unsigned long)span,
                k, (unsigned long)B, (unsigned long)(B | m),
                (unsigned long)__jail_masks.ormask,
                (unsigned long)__jail_masks.andmask);
    if (verbose) {
        int ov = 0;
        dl_iterate_phdr(check_overlap, &ov);
        fprintf(stderr, "[jail] window soundness: %d other-module exec segment(s)"
                " inside the clamp window\n", ov);
    }
}

/* audit: count out-of-jail targets, return target UNCHANGED (no enforcement).
 * JAIL_LOG_OOB=1 additionally names each distinct out-of-jail target. */
#define JAIL_OOB_MAX 64
static uint64_t oob_seen[JAIL_OOB_MAX];
static int oob_n = 0;
__attribute__((visibility("hidden")))
uint64_t __jail_audit(uint64_t target) {
    jail_audited++;
    if (target < __jail_masks.ormask || target > __jail_masks.andmask) {
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
    uint64_t c = (target | __jail_masks.ormask) & __jail_masks.andmask;
    if (c != target)
        fprintf(stderr, "[jail] blocked cross-module indirect target %#lx -> %#lx\n",
                (unsigned long)target, (unsigned long)c);
    return c;
}

__attribute__((destructor))
static void __jail_report(void) {
    if (getenv("JAIL_VERBOSE") && jail_audited)
        fprintf(stderr, "[jail] audit: indirect calls=%lu out-of-jail=%lu (%.1f%%)\n",
                jail_audited, jail_oob, 100.0 * jail_oob / jail_audited);
}
