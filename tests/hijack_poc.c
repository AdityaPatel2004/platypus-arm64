/* hijack_poc.c — the security demonstration.
 *
 * A struct places a fixed-size buffer immediately before a function pointer:
 *
 *      struct S { char buf[16]; void (*fp)(const char *); };
 *
 * `buf` is overflowed (a classic out-of-bounds write) so that the bytes past
 * its end land on `fp`, overwriting it with an attacker-chosen address. The
 * program then performs its normal indirect call `s.fp("id")`.
 *
 * Two builds, BTI ON in both:
 *   UNHARDENED : fp is overwritten with &system. The indirect call lands on
 *                system()'s entry in libc (a different module) -- which BTI
 *                freely allows -- and the shell command `id` runs. This is the
 *                hole that BTI alone leaves open, and the paper's whole motive.
 *   HARDENED   : our pass clamps fp into THIS program's own module just before
 *                the call. &system (in libc) is bent out of reach; the landing
 *                address is no longer a BTI landing pad, so the CPU raises
 *                SIGILL and the process dies BEFORE any shell runs.
 *
 * Run:
 *   ./hijack_poc           -> normal: calls the real callback, prints a line
 *   ./hijack_poc hijack    -> overwrites fp with &system, calls fp("id")
 *
 * Build the PoC WITHOUT _FORTIFY_SOURCE so the deliberate overflow is not
 * turned into an abort by libc's fortified memcpy (that would mask the point).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

struct S {
    char buf[16];
    void (*fp)(const char *);   /* adjacent to buf: overflow target */
};

/* the legitimate callback this indirect pointer is supposed to hold */
static void log_cb(const char *msg) {
    printf("[cb] legitimate callback ran with: %s\n", msg);
}

int main(int argc, char **argv) {
    struct S s;
    s.fp = log_cb;

    int hijack = (argc > 1 && strcmp(argv[1], "hijack") == 0);

    if (hijack) {
        /* Build a 24-byte "attacker input": 16 filler bytes + an 8-byte
         * address that overwrites fp. The chosen address is &system. */
        unsigned char payload[sizeof(s.buf) + sizeof(s.fp)];
        memset(payload, 'A', sizeof(s.buf));
        /* The attacker's chosen address is libc's REAL system() address — the
         * kind of value an exploit computes from a leaked libc base. We fetch
         * it at run time via dlsym rather than &system in source, so it is a
         * genuine out-of-module pointer (and not something the compiler could
         * have routed through a fake-PLT trampoline). */
        void *target = dlsym(RTLD_DEFAULT, "system");
        memcpy(payload + sizeof(s.buf), &target, sizeof(target));

        /* THE VULNERABILITY: copy 24 bytes into a 16-byte buffer. The extra
         * 8 bytes spill into fp. (volatile length defeats compile-time bounds
         * folding so the write really happens at run time.) */
        volatile size_t n = sizeof(payload);
        memcpy(s.buf, payload, n);
        printf("[poc] fp overwritten -> %p (real system=%p)\n",
               (void *)s.fp, dlsym(RTLD_DEFAULT, "system"));
    }

    fflush(stdout);
    /* The indirect call. Unhardened+hijacked: runs `id`. Hardened: SIGILL. */
    s.fp("id");

    printf("[poc] returned normally (no trap, no shell escape blocked)\n");
    return 0;
}
