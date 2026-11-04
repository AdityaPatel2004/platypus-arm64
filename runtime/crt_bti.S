/* Minimal BTI-marked replacement for glibc's Scrt1.o (_start).
   Ubuntu 24.04's arm64 *cross* glibc ships Scrt1.o/crti.o/crtn.o without the
   GNU_PROPERTY_AARCH64_FEATURE_1_BTI note and without a landing pad at _start, so a
   BTI-enforced executable dies before main(). Mirrors sysdeps/aarch64/start.S (glibc>=2.34). */
    .text
    .globl _start
    .type  _start, %function
_start:
    bti   jc                  /* ld.so / kernel enter via BR -> needs a 'j' landing pad */
    mov   x29, #0
    mov   x30, #0
    mov   x5, x0              /* rtld_fini from the dynamic linker */
    ldr   x1, [sp]            /* argc */
    add   x2, sp, #8          /* argv */
    mov   x6, sp              /* stack_end */
    mov   x3, #0              /* init (unused since glibc 2.34) */
    mov   x4, #0              /* fini (unused since glibc 2.34) */
    adrp  x0, :got:main
    ldr   x0, [x0, :got_lo12:main]
    bl    __libc_start_main
    bl    abort
    .size _start, .-_start

    .data
    .globl data_start
data_start:
    .long 0

    /* GNU property note: this object is BTI + PAC compatible */
    .section .note.gnu.property, "a"
    .p2align 3
    .long 4, 16, 5
    .asciz "GNU"
    .long 0xc0000000, 4, 3     /* GNU_PROPERTY_AARCH64_FEATURE_1_AND = BTI|PAC */
    .p2align 3
    .section .note.GNU-stack,"",%progbits
