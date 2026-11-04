/* bti_probe.c — is BTI actually ENFORCED in this environment? (week-1 go/no-go)
 *
 * tgt()'s first instruction is a `bti c` landing pad (emitted because we build
 * with -mbranch-protection=standard and take tgt's address). We make an
 * indirect call through a function pointer:
 *    normal : fp = tgt      -> lands on the bti pad        -> should RUN
 *    skip   : fp = tgt + 4  -> lands on the 2nd instruction -> should TRAP
 * If the "skip" case traps (SIGILL), BTI is live: GO. If it returns normally,
 * BTI is not being enforced: NO-GO.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>

__attribute__((noinline))
int tgt(void) { return 42; }

static sigjmp_buf jb;
static volatile int trapped = 0;
static void handler(int sig) { trapped = sig; siglongjmp(jb, 1); }

static int call_via(void *addr) {
    int (*fp)(void) = (int (*)(void))addr;
    trapped = 0;
    if (sigsetjmp(jb, 1) == 0) {
        int r = fp();                 /* the indirect call (blr) */
        return r;                     /* no trap */
    }
    return -1;                        /* trapped */
}

int main(void) {
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = handler; sigaction(SIGILL, &sa, NULL); sigaction(SIGSEGV, &sa, NULL);

    void *good = (void *)tgt;
    void *bad  = (void *)((uintptr_t)tgt + 4);

    int rg = call_via(good);
    int tg = trapped;
    int rb = call_via(bad);
    int tb = trapped;

    printf("normal call (fp=tgt)    : %s (r=%d)\n",
           tg ? "TRAP" : "ran", rg);
    printf("skip-pad call (fp=tgt+4): %s%s\n",
           tb ? "TRAP" : "ran (NO trap)",
           tb ? (tb==SIGILL? " [SIGILL]" : " [SIGSEGV]") : "");

    if (!tg && tb) { printf("RESULT: BTI ENFORCED -> GO\n"); return 0; }
    printf("RESULT: BTI NOT enforced -> NO-GO\n");
    return 1;
}
