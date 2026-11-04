/* clamp_micro.c — Research Question 2 in isolation: what does each clamp
 * ENCODING cost per indirect call on this core, independent of the pass?
 *
 * The same indirect-call loop as indirect_micro.c, with the clamp written by
 * hand in inline assembly, one variant per build (-DVARIANT=...):
 *
 *   NONE  no clamp                                  (baseline)
 *   A     masks held in two registers: orr + and    (Option A, reserved regs;
 *         here the compiler simply keeps them live across the loop, which is
 *         what reserving x27/x28 process-wide would give — the lower bound)
 *   B     two loads from a mask pair + orr + and    (Option B, what mask mode emits)
 *   C     bfxil (insert low k bits into the 2^k-aligned base)
 *                                                   (Option C, what aligned mode emits)
 *   D     adrp base + sub + and #imm + add          (Option D, what pcrel mode emits)
 *
 * The window here is this executable's own 2^22 block, so every target stays
 * valid and the checksum must match NONE.
 * -DRANDOM picks the table slot with a cheap LCG instead of i&3, so the
 * branch predictor CANNOT predict the target: every mispredict then has to wait
 * for the clamp's result, which is where an extra cycle or two would show.
 *   usage: clamp_micro [iterations]     prints "<seconds> <checksum>"
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static long f0(long x) { return x + 1; }
static long f1(long x) { return x ^ 3; }
static long f2(long x) { return x * 3; }
static long f3(long x) { return x - 2; }
typedef long (*fn)(long);
volatile fn tab[4] = { f0, f1, f2, f3 };

extern const char __ehdr_start[] __attribute__((visibility("hidden")));
/* B: the mask pair, like __jail_masks (filled at start-up, read every call) */
__attribute__((visibility("hidden"))) uint64_t masks[2];

static double now_s(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

int main(int argc, char **argv) {
    long N = (argc > 1) ? atol(argv[1]) : 400000000L;
    uint64_t base = (uint64_t)__ehdr_start, K = 22;
    uint64_t lo = base & ~((1ULL << K) - 1);
    uint64_t hi = base + 0x200000;                       /* module < 2 MiB */
    while ((lo | ((1ULL << K) - 1)) < hi) K++;
    masks[0] = lo; masks[1] = lo | ((1ULL << K) - 1);
    register uint64_t ormask = masks[0], andmask = masks[1];
    uint64_t cbase = lo;                 /* Option C: aligned block base */
    (void)ormask; (void)andmask; (void)cbase;
    long acc = 0;
    uint64_t lcg = 88172645463325252ULL;
    double t0 = now_s();
    for (long i = 0; i < N; i++) {
#ifdef RANDOM
        lcg = lcg * 6364136223846793005ULL + 1442695040888963407ULL;
        uint64_t t = (uint64_t)tab[(lcg >> 33) & 3];
#else
        uint64_t t = (uint64_t)tab[i & 3];
#endif
#if defined(VARIANT_A)
        __asm__ volatile("orr %0, %0, %1\n\tand %0, %0, %2"
                         : "+r"(t) : "r"(ormask), "r"(andmask));
#elif defined(VARIANT_B)
        uint64_t a, b;
        __asm__ volatile("ldr %1, [%3]\n\tldr %2, [%3, #8]\n\t"
                         "orr %0, %0, %1\n\tand %0, %0, %2"
                         : "+r"(t), "=&r"(a), "=&r"(b) : "r"(masks) : "memory");
#elif defined(VARIANT_C)
        uint64_t r = cbase;
        __asm__ volatile("bfxil %0, %1, #0, #22" : "+r"(r) : "r"(t));
        t = r;
#elif defined(VARIANT_D)
        uint64_t b;
        __asm__ volatile("adrp %1, __ehdr_start\n\t"
                         "sub %0, %0, %1\n\tand %0, %0, #0x3fffff\n\tadd %0, %0, %1"
                         : "+r"(t), "=&r"(b));
#endif
        acc += ((fn)t)(acc);
    }
    double t1 = now_s();
    printf("%.6f %ld\n", t1 - t0, acc);
    return 0;
}
