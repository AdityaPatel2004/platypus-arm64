/* toy_indirect.c — smallest program with a *real* indirect call.
 *
 * The call `f(20)` goes through a volatile function-pointer table, so the
 * optimiser cannot prove which function it is and must emit a true indirect
 * branch (`blr`). This is the instruction our pass clamps. Because the target
 * lives in this same module, the clamp must leave it unchanged -> program
 * still prints the right answer. That is the week-5 correctness check, and
 * `objdump -d` must show the clamp sequence immediately before the `blr`.
 */
#include <stdio.h>
#include <stdlib.h>

static int addone(int x) { return x + 1; }
static int dbl   (int x) { return x * 2; }

typedef int (*fn)(int);
volatile fn table[2] = { addone, dbl };   /* volatile: defeats devirtualisation */

int main(int argc, char **argv) {
    int sel = (argc > 1) ? atoi(argv[1]) : 0;
    fn f = table[sel & 1];
    int r = f(20);                          /* <-- the indirect call (blr) */
    printf("sel=%d r=%d\n", sel & 1, r);
    return 0;
}
