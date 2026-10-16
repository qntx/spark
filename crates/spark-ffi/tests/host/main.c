/*
 * C host test for qntx_spark.h: verifies the committed header compiles
 * standalone, the ABI version, the allocation contract, one FROST commit,
 * one ECIES roundtrip, and every ffi-sign / ffi-aggregate / ffi-errors
 * vector (generated into vectors.inc by scripts/ffi-host.ts).
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "qntx_spark.h"
#include "vectors.inc"

static int failures = 0;

#define CHECK(cond, msg)                                          \
    do {                                                          \
        if (!(cond)) {                                            \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, msg); \
            failures++;                                           \
        }                                                         \
    } while (0)

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decodes `hex` into `out`; returns the decoded length or -1. */
static long unhex(const char *hex, uint8_t *out, size_t cap) {
    size_t n = 0;
    while (hex[2 * n] && hex[2 * n + 1]) {
        int hi = hexval(hex[2 * n]);
        int lo = hexval(hex[2 * n + 1]);
        if (hi < 0 || lo < 0 || n >= cap) return -1;
        out[n] = (uint8_t)((hi << 4) | lo);
        n++;
    }
    if (hex[2 * n]) return -1;
    return (long)n;
}

/* Calls fn(req) and compares the output against expected hex. */
static void check_io(const char *label, const char *req_hex, const char *res_hex,
                     int32_t (*fn)(const uint8_t *, size_t, uint8_t **, size_t *)) {
    static uint8_t req[1 << 20], want[1 << 20];
    long req_len = unhex(req_hex, req, sizeof(req));
    long want_len = unhex(res_hex, want, sizeof(want));
    CHECK(req_len >= 0 && want_len >= 0, "vector hex decode");
    uint8_t *out = NULL;
    size_t out_len = 0;
    int32_t code = fn(req, (size_t)req_len, &out, &out_len);
    if (code != 0) {
        fprintf(stderr, "FAIL %s: code %d != 0\n", label, code);
        failures++;
        return;
    }
    CHECK(out_len == (size_t)want_len, "output length");
    CHECK(out_len == (size_t)want_len && memcmp(out, want, out_len) == 0, "output bytes");
    qs_free(out, out_len);
}

static void check_errors(const ErrCase *c) {
    static uint8_t a[1 << 20], b[1 << 20], d[1 << 20];
    long a_len = unhex(c->a ? c->a : "", a, sizeof(a));
    long b_len = unhex(c->b ? c->b : "", b, sizeof(b));
    long d_len = unhex(c->d ? c->d : "", d, sizeof(d));
    uint8_t *out = NULL;
    size_t out_len = 0;
    int32_t code = -1;
    if (strcmp(c->function, "frost_commit") == 0) {
        code = qs_frost_commit(a, (size_t)a_len, b, (size_t)b_len, &out, &out_len);
    } else if (strcmp(c->function, "frost_sign") == 0) {
        code = qs_frost_sign(a, (size_t)a_len, &out, &out_len);
    } else if (strcmp(c->function, "frost_aggregate") == 0) {
        code = qs_frost_aggregate(a, (size_t)a_len, &out, &out_len);
    } else if (strcmp(c->function, "ecies_encrypt") == 0) {
        code = qs_ecies_encrypt(a, (size_t)a_len, b, (size_t)b_len, d, (size_t)d_len, &out,
                                &out_len);
    } else if (strcmp(c->function, "ecies_decrypt") == 0) {
        code = qs_ecies_decrypt(a, (size_t)a_len, b, (size_t)b_len, &out, &out_len);
    } else if (strcmp(c->function, "split_secret_with_proofs") == 0) {
        code = qs_split_secret_with_proofs(a, (size_t)a_len, (uint32_t)c->n1,
                                           (uint32_t)c->n2, d, (size_t)d_len, &out,
                                           &out_len);
    } else {
        fprintf(stderr, "FAIL unknown error-case function %s\n", c->function);
        failures++;
        return;
    }
    if (code != c->code) {
        fprintf(stderr, "FAIL %s: code %d != expected %d\n", c->function, code, c->code);
        failures++;
    }
    /* An error return must not leak an output buffer; qs_free(NULL, 0) is a
       no-op, so freeing unconditionally also covers a wrongly-written out. */
    qs_free(out, out_len);
}

int main(void) {
    /* ABI version and allocation contract. */
    CHECK(qs_abi_version() == qs_ABI_VERSION, "qs_abi_version");
    CHECK(qs_alloc(0) == NULL, "qs_alloc(0)");
    uint8_t *buf = qs_alloc(64);
    CHECK(buf != NULL, "qs_alloc(64)");
    memset(buf, 0xAB, 64);
    qs_free(buf, 64);
    qs_free(NULL, 0);

    /* One batched commit: two seeds -> 260 bytes. */
    uint8_t hedge[32], random[64];
    memset(hedge, 0x11, sizeof(hedge));
    memset(random, 0x22, sizeof(random));
    hedge[31] = 0x01;
    uint8_t *out = NULL;
    size_t out_len = 0;
    int32_t code =
        qs_frost_commit(hedge, sizeof(hedge), random, sizeof(random), &out, &out_len);
    CHECK(code == 0, "qs_frost_commit code");
    CHECK(out_len == 2 * 130, "qs_frost_commit output length");
    qs_free(out, out_len);

    /* Deterministic ECIES roundtrip from the shared vector. */
    static uint8_t pk[65], sk[32], pt[256], ct[512], enc_r[32];
    long pk_len = unhex(ECIES_PUBLIC_KEY, pk, sizeof(pk));
    long sk_len = unhex(ECIES_SECRET_KEY, sk, sizeof(sk));
    long pt_len = unhex(ECIES_PLAINTEXT, pt, sizeof(pt));
    long ct_len = unhex(ECIES_CIPHERTEXT, ct, sizeof(ct));
    long enc_r_len = unhex(ECIES_RANDOM, enc_r, sizeof(enc_r));
    CHECK(pk_len > 0 && sk_len == 32 && pt_len > 0 && ct_len > 0 && enc_r_len == 32,
          "ecies vector decode");
    out = NULL;
    out_len = 0;
    code = qs_ecies_encrypt(pk, (size_t)pk_len, pt, (size_t)pt_len, enc_r,
                            (size_t)enc_r_len, &out, &out_len);
    CHECK(code == 0, "qs_ecies_encrypt code");
    CHECK(out_len == (size_t)ct_len && memcmp(out, ct, out_len) == 0,
          "qs_ecies_encrypt bytes");
    qs_free(out, out_len);
    out = NULL;
    out_len = 0;
    code = qs_ecies_decrypt(sk, (size_t)sk_len, ct, (size_t)ct_len, &out, &out_len);
    CHECK(code == 0, "qs_ecies_decrypt code");
    CHECK(out_len == (size_t)pt_len && memcmp(out, pt, out_len) == 0,
          "qs_ecies_decrypt bytes");
    qs_free(out, out_len);

    /* Shared FFI vectors. */
    for (size_t i = 0; i < FFI_SIGN_COUNT; i++) {
        check_io("frost_sign", FFI_SIGN_REQUESTS[i], FFI_SIGN_RESPONSES[i], qs_frost_sign);
    }
    for (size_t i = 0; i < FFI_AGGREGATE_COUNT; i++) {
        check_io("frost_aggregate", FFI_AGGREGATE_REQUESTS[i], FFI_AGGREGATE_RESPONSES[i],
                 qs_frost_aggregate);
    }
    for (size_t i = 0; i < FFI_ERROR_COUNT; i++) {
        check_errors(&FFI_ERRORS[i]);
    }

    if (failures == 0) {
        printf("ffi-host: ok (%zu sign, %zu aggregate, %zu error cases)\n", FFI_SIGN_COUNT,
               FFI_AGGREGATE_COUNT, FFI_ERROR_COUNT);
        return 0;
    }
    fprintf(stderr, "ffi-host: %d failures\n", failures);
    return 1;
}
