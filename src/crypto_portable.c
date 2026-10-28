/*
 * Portable crypto backend (-DRNC_CRYPTO=portable): no OpenSSL, no platform RNG.
 *
 *  - X25519 and Ed25519 (with its SHA-512): Monocypher 4.0.2, vendored in
 *    src/third_party/monocypher (BSD-2-Clause or CC0).
 *  - SHA-256, HMAC-SHA256, HKDF-SHA256 and AES-256-CBC: written here in plain C99
 *    with no platform dependencies and no dynamic allocation.
 *
 * Timing: SHA-256, HMAC and HKDF have no data-dependent branches or table
 * lookups. AES uses a 256-byte S-box lookup per state byte, i.e. data-dependent
 * memory access: a known cache-timing side channel (the tradeoff for a
 * dependency-free implementation on devices without hardware AES). It is only
 * practically exploitable by a local attacker who can observe the data cache;
 * cacheless MCUs are not affected, and a port to a chip with an AES engine
 * should replace the AES functions below with the hardware. The 256-byte S-box
 * (not 4 KB T-tables) keeps flash use and the cache footprint small, and the
 * GF(2^8) arithmetic is branch-free.
 */
#include "crypto_backend.h"
#include "third_party/monocypher/monocypher-ed25519.h"
#include "third_party/monocypher/monocypher.h"
#include <string.h>

void rnc_cleanse(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--)
        *v++ = 0;
}

int rnc_ct_memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
    uint8_t d = 0;
    size_t i;
    for (i = 0; i < n; i++)
        d |= (uint8_t)(x[i] ^ y[i]);
    return d;
}

/* ------------------------------------------------------------------ SHA-256 */

typedef struct sha256_state {
    uint32_t h[8];
    uint64_t length; /* bytes absorbed */
    uint8_t block[64];
} sha256_state;

typedef char sha256_state_fits[sizeof(sha256_state) <= sizeof(rnc_sha256_ctx) ? 1 : -1];

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_compress(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[64], a, b, c, d, e, f, g, hh, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[4 * i] << 24) | ((uint32_t)block[4 * i + 1] << 16) |
               ((uint32_t)block[4 * i + 2] << 8) | block[4 * i + 3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; hh = h[7];
    for (i = 0; i < 64; i++) {
        t1 = hh + (ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        t2 = (ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    rnc_cleanse(w, sizeof(w));
}

static sha256_state *st(rnc_sha256_ctx *ctx) { return (sha256_state *)(void *)ctx->opaque; }

int rnc_sha256_init(rnc_sha256_ctx *ctx) {
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    sha256_state *s = st(ctx);
    memcpy(s->h, iv, sizeof(iv));
    s->length = 0;
    return 1;
}

int rnc_sha256_update(rnc_sha256_ctx *ctx, const void *data, size_t size) {
    sha256_state *s = st(ctx);
    const uint8_t *p = (const uint8_t *)data;
    size_t used = (size_t)(s->length & 63u);
    if (!size)
        return 1;
    s->length += size;
    if (used) {
        size_t take = 64u - used;
        if (take > size)
            take = size;
        memcpy(s->block + used, p, take);
        p += take;
        size -= take;
        used += take;
        if (used < 64u)
            return 1;
        sha256_compress(s->h, s->block);
    }
    while (size >= 64u) {
        sha256_compress(s->h, p);
        p += 64;
        size -= 64;
    }
    if (size)
        memcpy(s->block, p, size);
    return 1;
}

int rnc_sha256_final(rnc_sha256_ctx *ctx, uint8_t out[32]) {
    sha256_state *s = st(ctx);
    uint64_t bits = s->length * 8u;
    size_t used = (size_t)(s->length & 63u);
    int i;
    s->block[used++] = 0x80;
    if (used > 56u) {
        memset(s->block + used, 0, 64u - used);
        sha256_compress(s->h, s->block);
        used = 0;
    }
    memset(s->block + used, 0, 56u - used);
    for (i = 0; i < 8; i++)
        s->block[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_compress(s->h, s->block);
    for (i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(s->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(s->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(s->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)s->h[i];
    }
    rnc_cleanse(ctx, sizeof(*ctx));
    return 1;
}

int rnc_sha256_copy(rnc_sha256_ctx *dst, const rnc_sha256_ctx *src) {
    memcpy(dst, src, sizeof(*dst));
    return 1;
}

void rnc_sha256_discard(rnc_sha256_ctx *ctx) { rnc_cleanse(ctx, sizeof(*ctx)); }

int rnc_sha256(const void *data, size_t size, uint8_t out[32]) {
    rnc_sha256_ctx c;
    rnc_sha256_init(&c);
    rnc_sha256_update(&c, data, size);
    return rnc_sha256_final(&c, out);
}

/* --------------------------------------------------------------------- HMAC */

int rnc_hmac_sha256(const uint8_t *key, size_t key_size, const void *data, size_t size,
                    uint8_t out[32]) {
    uint8_t k[64], pad[64], inner[32];
    rnc_sha256_ctx c;
    size_t i;
    memset(k, 0, sizeof(k));
    if (key_size > 64u)
        rnc_sha256(key, key_size, k);
    else if (key_size)
        memcpy(k, key, key_size);
    for (i = 0; i < 64u; i++)
        pad[i] = (uint8_t)(k[i] ^ 0x36);
    rnc_sha256_init(&c);
    rnc_sha256_update(&c, pad, 64);
    rnc_sha256_update(&c, data, size);
    rnc_sha256_final(&c, inner);
    for (i = 0; i < 64u; i++)
        pad[i] = (uint8_t)(k[i] ^ 0x5c);
    rnc_sha256_init(&c);
    rnc_sha256_update(&c, pad, 64);
    rnc_sha256_update(&c, inner, 32);
    rnc_sha256_final(&c, out);
    rnc_cleanse(k, sizeof(k));
    rnc_cleanse(pad, sizeof(pad));
    rnc_cleanse(inner, sizeof(inner));
    return 1;
}

#ifndef RNC_PORTABLE_NO_RPC_DIGESTS
#include "crypto_portable_digest.h"
#endif

int rnc_hmac_digest(int digest, const uint8_t *key, size_t key_size, const void *data,
                    size_t size, uint8_t *out, size_t out_capacity, size_t *written) {
    uint8_t mac[48];
    size_t n = 32;
    if (digest == RNC_DIGEST_SHA256) {
        rnc_hmac_sha256(key, key_size, data, size, mac);
    } else {
#ifndef RNC_PORTABLE_NO_RPC_DIGESTS
        /* MD5, SHA-384 and SHA-3 exist only for the host RPC channel handshake */
        if (!xhmac(digest, key, key_size, data, size, mac, &n))
            return 0;
#else
        return 0;
#endif
    }
    if (out_capacity < n)
        n = out_capacity;
    memcpy(out, mac, n);
    *written = n;
    return 1;
}

/* --------------------------------------------------------------------- HKDF */

int rnc_hkdf_sha256(const uint8_t *salt, size_t salt_size, const uint8_t *ikm, size_t ikm_size,
                    const uint8_t *info, size_t info_size, uint8_t *out, size_t out_size) {
    static const uint8_t zeros[32] = {0};
    uint8_t prk[32], t[32], msg[32 + 256 + 1];
    size_t done = 0, tlen = 0;
    uint8_t counter = 1;
    if (out_size > 255u * 32u || info_size > 256u)
        return 0;
    if (!salt_size) {
        salt = zeros;
        salt_size = 32;
    }
    rnc_hmac_sha256(salt, salt_size, ikm, ikm_size, prk);
    while (done < out_size) {
        size_t m = 0, take;
        memcpy(msg, t, tlen);
        m += tlen;
        if (info_size)
            memcpy(msg + m, info, info_size);
        m += info_size;
        msg[m++] = counter++;
        rnc_hmac_sha256(prk, 32, msg, m, t);
        tlen = 32;
        take = out_size - done < 32u ? out_size - done : 32u;
        memcpy(out + done, t, take);
        done += take;
    }
    rnc_cleanse(prk, sizeof(prk));
    rnc_cleanse(t, sizeof(t));
    rnc_cleanse(msg, sizeof(msg));
    return 1;
}

/* ------------------------------------------------------------------ AES-256 */

#include "crypto_portable_aes_tables.h"

static uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ (0x1bu & (0u - (unsigned)(x >> 7)))); }

typedef struct aes_key {
    uint8_t rk[15][16];
} aes_key;

static void aes_expand(aes_key *k, const uint8_t key[32]) {
    uint8_t *w = &k->rk[0][0];
    uint8_t rcon = 1;
    size_t i;
    uint8_t t[4];
    memcpy(w, key, 32);
    for (i = 8; i < 60u; i++) {
        memcpy(t, w + 4 * (i - 1), 4);
        if (i % 8u == 0) {
            uint8_t x = t[0];
            t[0] = (uint8_t)(SBOX[t[1]] ^ rcon);
            t[1] = SBOX[t[2]];
            t[2] = SBOX[t[3]];
            t[3] = SBOX[x];
            rcon = xtime(rcon);
        } else if (i % 8u == 4) {
            t[0] = SBOX[t[0]]; t[1] = SBOX[t[1]]; t[2] = SBOX[t[2]]; t[3] = SBOX[t[3]];
        }
        w[4 * i] = (uint8_t)(w[4 * (i - 8)] ^ t[0]);
        w[4 * i + 1] = (uint8_t)(w[4 * (i - 8) + 1] ^ t[1]);
        w[4 * i + 2] = (uint8_t)(w[4 * (i - 8) + 2] ^ t[2]);
        w[4 * i + 3] = (uint8_t)(w[4 * (i - 8) + 3] ^ t[3]);
    }
    rnc_cleanse(t, sizeof(t));
}

static void add_round_key(uint8_t s[16], const uint8_t rk[16]) {
    int i;
    for (i = 0; i < 16; i++)
        s[i] ^= rk[i];
}

static void sub_shift(uint8_t s[16]) {
    uint8_t t[16];
    int r, c;
    for (c = 0; c < 4; c++)
        for (r = 0; r < 4; r++)
            t[r + 4 * c] = SBOX[s[r + 4 * ((c + r) & 3)]];
    memcpy(s, t, 16);
}

static void inv_shift_sub(uint8_t s[16]) {
    uint8_t t[16];
    int r, c;
    for (c = 0; c < 4; c++)
        for (r = 0; r < 4; r++)
            t[r + 4 * ((c + r) & 3)] = RSBOX[s[r + 4 * c]];
    memcpy(s, t, 16);
}

static void mix_columns(uint8_t s[16]) {
    int c;
    for (c = 0; c < 4; c++) {
        uint8_t *a = s + 4 * c;
        uint8_t t = (uint8_t)(a[0] ^ a[1] ^ a[2] ^ a[3]);
        uint8_t a0 = a[0];
        a[0] ^= (uint8_t)(t ^ xtime((uint8_t)(a[0] ^ a[1])));
        a[1] ^= (uint8_t)(t ^ xtime((uint8_t)(a[1] ^ a[2])));
        a[2] ^= (uint8_t)(t ^ xtime((uint8_t)(a[2] ^ a[3])));
        a[3] ^= (uint8_t)(t ^ xtime((uint8_t)(a[3] ^ a0)));
    }
}

static void inv_mix_columns(uint8_t s[16]) {
    int c;
    for (c = 0; c < 4; c++) {
        uint8_t *a = s + 4 * c;
        uint8_t u = xtime(xtime((uint8_t)(a[0] ^ a[2])));
        uint8_t v = xtime(xtime((uint8_t)(a[1] ^ a[3])));
        a[0] ^= u; a[1] ^= v; a[2] ^= u; a[3] ^= v;
    }
    mix_columns(s);
}

static void aes_encrypt_block(const aes_key *k, uint8_t s[16]) {
    int round;
    add_round_key(s, k->rk[0]);
    for (round = 1; round < 14; round++) {
        sub_shift(s);
        mix_columns(s);
        add_round_key(s, k->rk[round]);
    }
    sub_shift(s);
    add_round_key(s, k->rk[14]);
}

static void aes_decrypt_block(const aes_key *k, uint8_t s[16]) {
    int round;
    add_round_key(s, k->rk[14]);
    for (round = 13; round > 0; round--) {
        inv_shift_sub(s);
        add_round_key(s, k->rk[round]);
        inv_mix_columns(s);
    }
    inv_shift_sub(s);
    add_round_key(s, k->rk[0]);
}

int rnc_aes256_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16], const uint8_t *in,
                           uint8_t *out, size_t size) {
    aes_key k;
    uint8_t chain[16], blk[16];
    size_t i, j;
    if (size % 16u)
        return 0;
    aes_expand(&k, key);
    memcpy(chain, iv, 16);
    for (i = 0; i < size; i += 16u) {
        for (j = 0; j < 16u; j++)
            blk[j] = (uint8_t)(in[i + j] ^ chain[j]);
        aes_encrypt_block(&k, blk);
        memcpy(chain, blk, 16);
        memcpy(out + i, blk, 16);
    }
    rnc_cleanse(&k, sizeof(k));
    rnc_cleanse(chain, sizeof(chain));
    rnc_cleanse(blk, sizeof(blk));
    return 1;
}

int rnc_aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16], const uint8_t *in,
                           uint8_t *out, size_t size) {
    aes_key k;
    uint8_t chain[16], next[16], blk[16];
    size_t i, j;
    if (size % 16u)
        return 0;
    aes_expand(&k, key);
    memcpy(chain, iv, 16);
    for (i = 0; i < size; i += 16u) {
        memcpy(next, in + i, 16); /* keep the ciphertext: in and out may alias */
        memcpy(blk, next, 16);
        aes_decrypt_block(&k, blk);
        for (j = 0; j < 16u; j++)
            out[i + j] = (uint8_t)(blk[j] ^ chain[j]);
        memcpy(chain, next, 16);
    }
    rnc_cleanse(&k, sizeof(k));
    rnc_cleanse(chain, sizeof(chain));
    rnc_cleanse(next, sizeof(next));
    rnc_cleanse(blk, sizeof(blk));
    return 1;
}

/* ------------------------------------------------------------------- curves */

int rnc_x25519_public(const uint8_t private_key[32], uint8_t public_key[32]) {
    crypto_x25519_public_key(public_key, private_key);
    return 1;
}

int rnc_x25519_derive(const uint8_t private_key[32], const uint8_t peer_public[32],
                      uint8_t shared[32]) {
    uint8_t out[32], zero;
    size_t i;
    crypto_x25519(out, private_key, peer_public);
    for (zero = 0, i = 0; i < 32u; i++)
        zero |= out[i];
    if (!zero) {
        rnc_cleanse(out, sizeof(out));
        return 0;
    }
    memcpy(shared, out, 32);
    rnc_cleanse(out, sizeof(out));
    return 1;
}

int rnc_ed25519_public(const uint8_t seed[32], uint8_t public_key[32]) {
    uint8_t secret[64], s[32];
    memcpy(s, seed, 32); /* key_pair wipes its seed argument */
    crypto_ed25519_key_pair(secret, public_key, s);
    rnc_cleanse(secret, sizeof(secret));
    return 1;
}

int rnc_ed25519_sign(const uint8_t seed[32], const void *data, size_t size, uint8_t signature[64]) {
    uint8_t secret[64], pub[32], s[32];
    memcpy(s, seed, 32);
    crypto_ed25519_key_pair(secret, pub, s);
    crypto_ed25519_sign(signature, secret, (const uint8_t *)data, size);
    rnc_cleanse(secret, sizeof(secret));
    return 1;
}

int rnc_ed25519_verify(const uint8_t public_key[32], const void *data, size_t size,
                       const uint8_t signature[64]) {
    return crypto_ed25519_check(signature, public_key, (const uint8_t *)data, size) == 0;
}
