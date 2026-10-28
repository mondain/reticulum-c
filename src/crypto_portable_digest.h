/*
 * MD5, SHA-384, SHA3-256 and SHA3-384 (with HMAC), included into crypto_portable.c.
 *
 * The only consumer is the host RPC channel (src/ipc.c), whose challenge/response
 * must answer whatever digest Python's multiprocessing.connection names. A
 * microcontroller build that has no RPC channel can drop this code (about 3 KB)
 * with -DRNC_PORTABLE_RPC_DIGESTS=OFF (CMake) / -DRNC_PORTABLE_NO_RPC_DIGESTS.
 * MD5 is used here only as an HMAC primitive for that legacy handshake.
 */
#include "crypto_portable_digest_tables.h"

typedef struct xhash {
    int kind;
    size_t block, outlen, used;
    uint64_t total;
    union {
        uint32_t m[4];
        uint64_t s[8];
        uint64_t k[25];
    } st;
    uint8_t buf[144];
} xhash;

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))
#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void md5_compress(uint32_t s[4], const uint8_t b[64]) {
    static const uint8_t R[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                                  5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                                  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                                  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
    uint32_t w[16], a = s[0], bb = s[1], c = s[2], d = s[3];
    int i;
    for (i = 0; i < 16; i++)
        w[i] = (uint32_t)b[4 * i] | ((uint32_t)b[4 * i + 1] << 8) | ((uint32_t)b[4 * i + 2] << 16) |
               ((uint32_t)b[4 * i + 3] << 24);
    for (i = 0; i < 64; i++) {
        uint32_t f, t;
        int g;
        if (i < 16) { f = (bb & c) | (~bb & d); g = i; }
        else if (i < 32) { f = (d & bb) | (~d & c); g = (5 * i + 1) & 15; }
        else if (i < 48) { f = bb ^ c ^ d; g = (3 * i + 5) & 15; }
        else { f = c ^ (bb | ~d); g = (7 * i) & 15; }
        t = d;
        d = c;
        c = bb;
        bb = bb + ROL32(a + f + MD5K[i] + w[g], R[i]);
        a = t;
    }
    s[0] += a; s[1] += bb; s[2] += c; s[3] += d;
}

static void sha512_compress(uint64_t h[8], const uint8_t b[128]) {
    uint64_t w[80], v[8], t1, t2;
    int i;
    for (i = 0; i < 16; i++) {
        int j;
        w[i] = 0;
        for (j = 0; j < 8; j++)
            w[i] = (w[i] << 8) | b[8 * i + j];
    }
    for (i = 16; i < 80; i++) {
        uint64_t s0 = ROR64(w[i - 15], 1) ^ ROR64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = ROR64(w[i - 2], 19) ^ ROR64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    memcpy(v, h, sizeof(v));
    for (i = 0; i < 80; i++) {
        t1 = v[7] + (ROR64(v[4], 14) ^ ROR64(v[4], 18) ^ ROR64(v[4], 41)) + ((v[4] & v[5]) ^ (~v[4] & v[6])) +
             K512[i] + w[i];
        t2 = (ROR64(v[0], 28) ^ ROR64(v[0], 34) ^ ROR64(v[0], 39)) + ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
        v[7] = v[6]; v[6] = v[5]; v[5] = v[4]; v[4] = v[3] + t1;
        v[3] = v[2]; v[2] = v[1]; v[1] = v[0]; v[0] = t1 + t2;
    }
    for (i = 0; i < 8; i++)
        h[i] += v[i];
}

static void keccak_f(uint64_t a[25]) {
    static const uint8_t rot[25] = {0,  1,  62, 28, 27, 36, 44, 6,  55, 20, 3,  10, 43,
                                    25, 39, 41, 45, 15, 21, 8,  18, 2,  61, 56, 14};
    int round;
    for (round = 0; round < 24; round++) {
        uint64_t c[5], d, b[25];
        int x, y;
        for (x = 0; x < 5; x++)
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        for (x = 0; x < 5; x++) {
            d = c[(x + 4) % 5] ^ ROL64(c[(x + 1) % 5], 1);
            for (y = 0; y < 25; y += 5)
                a[y + x] ^= d;
        }
        for (x = 0; x < 5; x++)
            for (y = 0; y < 5; y++) {
                int i = x + 5 * y;
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rot[i] ? ROL64(a[i], rot[i]) : a[i];
            }
        for (y = 0; y < 25; y += 5)
            for (x = 0; x < 5; x++)
                a[y + x] = b[y + x] ^ (~b[y + (x + 1) % 5] & b[y + (x + 2) % 5]);
        a[0] ^= KECCAK_RC[round];
    }
}

static void keccak_absorb_block(uint64_t k[25], const uint8_t *b, size_t rate) {
    size_t i, j;
    for (i = 0; i < rate / 8; i++) {
        uint64_t v = 0;
        for (j = 0; j < 8; j++)
            v |= (uint64_t)b[8 * i + j] << (8 * j);
        k[i] ^= v;
    }
    keccak_f(k);
}

static void xh_compress(xhash *h, const uint8_t *b) {
    switch (h->kind) {
    case RNC_DIGEST_MD5: md5_compress(h->st.m, b); break;
    case RNC_DIGEST_SHA384: sha512_compress(h->st.s, b); break;
    default: keccak_absorb_block(h->st.k, b, h->block); break;
    }
}

static int xh_init(xhash *h, int kind) {
    memset(h, 0, sizeof(*h));
    h->kind = kind;
    switch (kind) {
    case RNC_DIGEST_MD5:
        h->block = 64; h->outlen = 16;
        h->st.m[0] = 0x67452301u; h->st.m[1] = 0xefcdab89u; h->st.m[2] = 0x98badcfeu; h->st.m[3] = 0x10325476u;
        return 1;
    case RNC_DIGEST_SHA384:
        h->block = 128; h->outlen = 48;
        memcpy(h->st.s, IV384, sizeof(IV384));
        return 1;
    case RNC_DIGEST_SHA3_256: h->block = 136; h->outlen = 32; return 1;
    case RNC_DIGEST_SHA3_384: h->block = 104; h->outlen = 48; return 1;
    default: return 0;
    }
}

static void xh_update(xhash *h, const uint8_t *p, size_t n) {
    h->total += n;
    while (n) {
        size_t take = h->block - h->used;
        if (take > n)
            take = n;
        memcpy(h->buf + h->used, p, take);
        h->used += take;
        p += take;
        n -= take;
        if (h->used == h->block) {
            xh_compress(h, h->buf);
            h->used = 0;
        }
    }
}

static void xh_final(xhash *h, uint8_t *out) {
    size_t i, j;
    if (h->kind == RNC_DIGEST_MD5 || h->kind == RNC_DIGEST_SHA384) {
        uint64_t bits = h->total * 8u;
        size_t lenbytes = h->kind == RNC_DIGEST_MD5 ? 8u : 16u;
        h->buf[h->used++] = 0x80;
        if (h->used > h->block - lenbytes) {
            memset(h->buf + h->used, 0, h->block - h->used);
            xh_compress(h, h->buf);
            h->used = 0;
        }
        memset(h->buf + h->used, 0, h->block - h->used);
        for (i = 0; i < 8; i++) {
            if (h->kind == RNC_DIGEST_MD5)
                h->buf[h->block - 8 + i] = (uint8_t)(bits >> (8 * i));
            else
                h->buf[h->block - 1 - i] = (uint8_t)(bits >> (8 * i));
        }
        xh_compress(h, h->buf);
        if (h->kind == RNC_DIGEST_MD5) {
            for (i = 0; i < 16; i++)
                out[i] = (uint8_t)(h->st.m[i / 4] >> (8 * (i % 4)));
        } else {
            for (i = 0; i < 48; i++)
                out[i] = (uint8_t)(h->st.s[i / 8] >> (56 - 8 * (i % 8)));
        }
    } else {
        memset(h->buf + h->used, 0, h->block - h->used);
        h->buf[h->used] ^= 0x06;
        h->buf[h->block - 1] ^= 0x80;
        keccak_absorb_block(h->st.k, h->buf, h->block);
        for (i = 0; i < h->outlen / 8u; i++)
            for (j = 0; j < 8; j++)
                out[8 * i + j] = (uint8_t)(h->st.k[i] >> (8 * j));
    }
}

/* HMAC (RFC 2104) over any of the digests above; out receives outlen bytes. */
static int xhmac(int kind, const uint8_t *key, size_t key_size, const void *data, size_t size,
                 uint8_t out[48], size_t *outlen) {
    xhash h;
    uint8_t k[144], pad[144], inner[48];
    size_t block, i;
    if (!xh_init(&h, kind))
        return 0;
    block = h.block;
    memset(k, 0, sizeof(k));
    if (key_size > block) {
        xh_update(&h, key, key_size);
        xh_final(&h, k);
        xh_init(&h, kind);
    } else if (key_size) {
        memcpy(k, key, key_size);
    }
    for (i = 0; i < block; i++)
        pad[i] = (uint8_t)(k[i] ^ 0x36);
    xh_update(&h, pad, block);
    xh_update(&h, (const uint8_t *)data, size);
    xh_final(&h, inner);
    *outlen = h.outlen;
    xh_init(&h, kind);
    for (i = 0; i < block; i++)
        pad[i] = (uint8_t)(k[i] ^ 0x5c);
    xh_update(&h, pad, block);
    xh_update(&h, inner, *outlen);
    xh_final(&h, out);
    rnc_cleanse(&h, sizeof(h));
    rnc_cleanse(k, sizeof(k));
    rnc_cleanse(pad, sizeof(pad));
    rnc_cleanse(inner, sizeof(inner));
    return 1;
}
