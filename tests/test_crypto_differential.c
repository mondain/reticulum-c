/*
 * Differential test: random inputs through the OpenSSL backend and the portable
 * backend (both compiled in with distinct symbol prefixes); every output, and every
 * accept/reject decision, must match.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint64_t opaque[14];
} sha_ctx;

#define DECLARE(P)                                                                        \
    int P##_sha256(const void *, size_t, uint8_t[32]);                                    \
    int P##_sha256_init(sha_ctx *);                                                       \
    int P##_sha256_update(sha_ctx *, const void *, size_t);                               \
    int P##_sha256_final(sha_ctx *, uint8_t[32]);                                         \
    int P##_hmac_sha256(const uint8_t *, size_t, const void *, size_t, uint8_t[32]);      \
    int P##_hkdf_sha256(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, \
                        size_t, uint8_t *, size_t);                                       \
    int P##_aes256_cbc_encrypt(const uint8_t *, const uint8_t *, const uint8_t *, uint8_t *, size_t); \
    int P##_aes256_cbc_decrypt(const uint8_t *, const uint8_t *, const uint8_t *, uint8_t *, size_t); \
    int P##_x25519_public(const uint8_t *, uint8_t *);                                    \
    int P##_x25519_derive(const uint8_t *, const uint8_t *, uint8_t *);                   \
    int P##_ed25519_public(const uint8_t *, uint8_t *);                                   \
    int P##_ed25519_sign(const uint8_t *, const void *, size_t, uint8_t *);               \
    int P##_ed25519_verify(const uint8_t *, const void *, size_t, const uint8_t *);       \
    int P##_hmac_digest(int, const uint8_t *, size_t, const void *, size_t, uint8_t *, size_t, size_t *); \
    int P##_ct_memcmp(const void *, const void *, size_t);
DECLARE(ossl)
DECLARE(port)

static uint64_t rng_state = 0x9e3779b97f4a7c15ull;
static uint64_t rnd(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}
static void fill(uint8_t *p, size_t n) {
    size_t i;
    for (i = 0; i < n; i++)
        p[i] = (uint8_t)(rnd() >> 24);
}

static int failures;
static long compared;
#define SAME(cond, what)                                                                 \
    do {                                                                                 \
        compared++;                                                                      \
        if (!(cond)) {                                                                   \
            fprintf(stderr, "MISMATCH %s (iteration %d)\n", what, iter);                 \
            failures++;                                                                  \
        }                                                                                \
    } while (0)

int main(void) {
    static uint8_t data[2200], a[2200], b[2200];
    int iter;
    for (iter = 0; iter < 3000; iter++) {
        size_t n = (size_t)(rnd() % (iter % 50 == 0 ? 2100 : 200)), kn = (size_t)(rnd() % 140);
        uint8_t key[140], d1[32], d2[32], k32[32], iv[16], p1[32], p2[32], s1[64], s2[64];
        size_t blocks = (size_t)(rnd() % 100) * 16u, on = (size_t)(rnd() % 120);
        fill(data, sizeof(data));
        fill(key, sizeof(key));

        SAME(ossl_sha256(data, n, d1) && port_sha256(data, n, d2) && !memcmp(d1, d2, 32), "sha256");
        {
            sha_ctx c;
            size_t cut = n ? (size_t)(rnd() % (n + 1)) : 0;
            port_sha256_init(&c);
            port_sha256_update(&c, data, cut);
            port_sha256_update(&c, data + cut, n - cut);
            port_sha256_final(&c, d2);
            SAME(!memcmp(d1, d2, 32), "sha256 incremental");
        }
        SAME(ossl_hmac_sha256(key, kn, data, n, d1) && port_hmac_sha256(key, kn, data, n, d2) &&
                 !memcmp(d1, d2, 32),
             "hmac");
        {
            size_t sn = (size_t)(rnd() % 70), in = (size_t)(rnd() % 90), fn = (size_t)(rnd() % 60);
            size_t ol = 1 + (size_t)(rnd() % 255);
            if (rnd() % 4 == 0)
                sn = 0;
            if (rnd() % 4 == 0)
                fn = 0;
            SAME(ossl_hkdf_sha256(key, sn, data, in, a, fn, b, ol) &&
                     port_hkdf_sha256(key, sn, data, in, a, fn, a + 300, ol) &&
                     !memcmp(b, a + 300, ol),
                 "hkdf");
        }
        fill(k32, 32);
        fill(iv, 16);
        SAME(ossl_aes256_cbc_encrypt(k32, iv, data, a, blocks) &&
                 port_aes256_cbc_encrypt(k32, iv, data, b, blocks) && !memcmp(a, b, blocks),
             "aes encrypt");
        SAME(ossl_aes256_cbc_decrypt(k32, iv, data, a, blocks) &&
                 port_aes256_cbc_decrypt(k32, iv, data, b, blocks) && !memcmp(a, b, blocks),
             "aes decrypt");

        /* x25519: random scalar against a random point (including degenerate ones) */
        fill(p1, 32);
        if (rnd() % 8 == 0)
            memset(p1, 0xff, 32);
        if (rnd() % 8 == 0)
            memset(p1, 0, 32);
        {
            int r1 = ossl_x25519_derive(k32, p1, s1), r2 = port_x25519_derive(k32, p1, s2);
            SAME(r1 == r2 && (!r1 || !memcmp(s1, s2, 32)), "x25519 derive");
            SAME(ossl_x25519_public(k32, p1) && port_x25519_public(k32, p2) && !memcmp(p1, p2, 32),
                 "x25519 public");
        }

        {
            uint8_t pub1[32], pub2[32], sg1[64], sg2[64];
            SAME(ossl_ed25519_public(k32, pub1) && port_ed25519_public(k32, pub2) &&
                     !memcmp(pub1, pub2, 32),
                 "ed25519 public");
            SAME(ossl_ed25519_sign(k32, data, on, sg1) && port_ed25519_sign(k32, data, on, sg2) &&
                     !memcmp(sg1, sg2, 64),
                 "ed25519 sign");
            SAME(ossl_ed25519_verify(pub1, data, on, sg1) && port_ed25519_verify(pub1, data, on, sg1),
                 "ed25519 verify valid");
            {
                /* corrupt a random signature, message or key bit: decisions must agree */
                uint8_t sg[64], pk[32], msg[120];
                int r1, r2, which = (int)(rnd() % 4);
                memcpy(sg, sg1, 64);
                memcpy(pk, pub1, 32);
                memcpy(msg, data, on);
                if (which == 0)
                    sg[rnd() % 64] ^= (uint8_t)(1u << (rnd() % 8));
                if (which == 1 && on)
                    msg[rnd() % on] ^= 1;
                if (which == 2)
                    pk[rnd() % 32] ^= (uint8_t)(1u << (rnd() % 8));
                if (which == 3)
                    fill(sg, 64);
                r1 = ossl_ed25519_verify(pk, msg, on, sg);
                r2 = port_ed25519_verify(pk, msg, on, sg);
                SAME(r1 == r2, "ed25519 verify decision");
            }
            {
                /* S + L (malleated, non-canonical S): the backends must agree (reject) */
                static const uint8_t L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                                              0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                                              0,    0,    0,    0,    0,    0,    0,    0,
                                              0,    0,    0,    0,    0,    0,    0,    0x10};
                uint8_t sg[64];
                unsigned carry = 0, i;
                memcpy(sg, sg1, 64);
                for (i = 0; i < 32; i++) {
                    unsigned v = sg[32 + i] + L[i] + carry;
                    sg[32 + i] = (uint8_t)v;
                    carry = v >> 8;
                }
                SAME(ossl_ed25519_verify(pub1, data, on, sg) == port_ed25519_verify(pub1, data, on, sg),
                     "ed25519 non-canonical S");
            }
        }
        {
            /* the RPC handshake digests: MD5, SHA-256, SHA-384, SHA3-256, SHA3-384 */
            int id;
            for (id = 1; id <= 5; id++) {
                uint8_t o1[64], o2[64];
                size_t w1 = 0, w2 = 0;
                SAME(ossl_hmac_digest(id, key, kn, data, n, o1, sizeof(o1), &w1) &&
                         port_hmac_digest(id, key, kn, data, n, o2, sizeof(o2), &w2) && w1 == w2 &&
                         !memcmp(o1, o2, w1),
                     "hmac digest");
            }
        }
        SAME((ossl_ct_memcmp(a, b, n % 40 + 1) == 0) == (port_ct_memcmp(a, b, n % 40 + 1) == 0),
             "ct_memcmp");
    }
    if (failures) {
        fprintf(stderr, "%d mismatches out of %ld comparisons\n", failures, compared);
        return 1;
    }
    printf("differential: %ld comparisons identical\n", compared);
    return 0;
}
