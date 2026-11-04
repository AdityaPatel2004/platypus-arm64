/* indirect_micro.c — worst-case microbenchmark: a loop dominated by indirect
 * calls, to isolate the per-call cost of the clamp (load ormask + load andmask
 * + orr + and). Real programs do real work between indirect calls and see far
 * less; this is the upper bound. Prints "<elapsed_seconds> <checksum>".
 *   usage: indirect_micro [iterations]
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static long f0(long x) { return x + 1; }
static long f1(long x) { return x ^ 3; }
static long f2(long x) { return x * 3; }
static long f3(long x) { return x - 2; }

typedef long (*fn)(long);
/* volatile table: the compiler cannot devirtualise, so every call is a real blr */
volatile fn tab[4] = { f0, f1, f2, f3 };

static double now_s(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

int main(int argc, char **argv) {
    long N = (argc > 1) ? atol(argv[1]) : 500000000L;
    long acc = 0;
    double t0 = now_s();
    for (long i = 0; i < N; i++) {
        fn f = tab[i & 3];
        acc += f(acc);          /* the indirect call under test */
    }
    double t1 = now_s();
    printf("%.6f %ld\n", t1 - t0, acc);
    return 0;
}
