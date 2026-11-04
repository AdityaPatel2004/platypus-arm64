/* oqs_bench.c — post-quantum KEM workload (ML-KEM-768) for the jail evaluation.
 * Loops keypair/encaps/decaps; checksum is sum of (ss_encaps[0]^ss_decaps[0]),
 * which is 0 when the shared secrets agree (correctness under hardening).
 *   usage: oqs_bench [iterations]
 */
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static double now_s(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

int main(int argc, char **argv) {
    int iters = (argc > 1) ? atoi(argv[1]) : 20000;
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) { fprintf(stderr, "ML-KEM-768 unavailable\n"); return 1; }
    uint8_t *pk  = malloc(kem->length_public_key);
    uint8_t *sk  = malloc(kem->length_secret_key);
    uint8_t *ct  = malloc(kem->length_ciphertext);
    uint8_t *ss1 = malloc(kem->length_shared_secret);
    uint8_t *ss2 = malloc(kem->length_shared_secret);
    unsigned long acc = 0;
    double t0 = now_s();
    for (int i = 0; i < iters; i++) {
        OQS_KEM_keypair(kem, pk, sk);
        OQS_KEM_encaps(kem, ct, ss1, pk);
        OQS_KEM_decaps(kem, ss2, ct, sk);
        acc += (unsigned)(ss1[0] ^ ss2[0]);   /* 0 if shared secrets agree */
    }
    double t1 = now_s();
    printf("%.6f %lu\n", t1 - t0, acc);
    OQS_KEM_free(kem);
    free(pk); free(sk); free(ct); free(ss1); free(ss2);
    return 0;
}
