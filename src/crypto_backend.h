#ifndef RNC_CRYPTO_BACKEND_H
#define RNC_CRYPTO_BACKEND_H
/*
 * Internal crypto backend interface (not installed).
 *
 * Every primitive the protocol core needs goes through these functions. Two
 * implementations exist and exactly one is linked, chosen at configure time
 * with -DRNC_CRYPTO=openssl (default, src/crypto_openssl.c) or
 * -DRNC_CRYPTO=portable (src/crypto_portable.c, no OpenSSL, Monocypher for the
 * curve work).
 *
 * Randomness is NOT part of this interface: the core receives it only through
 * the caller-supplied rnc_random_fn callbacks.
 *
 * Unless stated, int-returning functions return 1 on success and 0 on failure.
 * A symbol prefix may be defined (RNC_BACKEND_PREFIX handled in the backends'
 * own files) so the differential test can link both backends side by side.
 */
#include <stddef.h>
#include <stdint.h>

#ifndef RNC_BE
#define RNC_BE(name) rnc_##name
#endif

#define rnc_cleanse RNC_BE(cleanse)
#define rnc_ct_memcmp RNC_BE(ct_memcmp)
#define rnc_sha256_init RNC_BE(sha256_init)
#define rnc_sha256_update RNC_BE(sha256_update)
#define rnc_sha256_final RNC_BE(sha256_final)
#define rnc_sha256_copy RNC_BE(sha256_copy)
#define rnc_sha256_discard RNC_BE(sha256_discard)
#define rnc_sha256 RNC_BE(sha256)
#define rnc_hmac_sha256 RNC_BE(hmac_sha256)
#define rnc_hmac_digest RNC_BE(hmac_digest)
#define rnc_hkdf_sha256 RNC_BE(hkdf_sha256)
#define rnc_aes256_cbc_encrypt RNC_BE(aes256_cbc_encrypt)
#define rnc_aes256_cbc_decrypt RNC_BE(aes256_cbc_decrypt)
#define rnc_x25519_public RNC_BE(x25519_public)
#define rnc_x25519_derive RNC_BE(x25519_derive)
#define rnc_ed25519_public RNC_BE(ed25519_public)
#define rnc_ed25519_sign RNC_BE(ed25519_sign)
#define rnc_ed25519_verify RNC_BE(ed25519_verify)

/* Zero memory in a way the compiler may not elide. */
void rnc_cleanse(void *p, size_t n);
/* Constant-time compare: 0 when equal, non-zero otherwise. */
int rnc_ct_memcmp(const void *a, const void *b, size_t n);

/* Incremental SHA-256. The context is opaque, caller-allocated and may hold a
 * backend resource until _final or _discard. _init may fail (returns 0); after
 * any failure call _discard. _final releases the context. */
typedef struct rnc_sha256_ctx {
    uint64_t opaque[14];
} rnc_sha256_ctx;
int rnc_sha256_init(rnc_sha256_ctx *ctx);
int rnc_sha256_update(rnc_sha256_ctx *ctx, const void *data, size_t size);
int rnc_sha256_final(rnc_sha256_ctx *ctx, uint8_t out[32]);
int rnc_sha256_copy(rnc_sha256_ctx *dst, const rnc_sha256_ctx *src);
void rnc_sha256_discard(rnc_sha256_ctx *ctx);
int rnc_sha256(const void *data, size_t size, uint8_t out[32]);

int rnc_hmac_sha256(const uint8_t *key, size_t key_size, const void *data, size_t size,
                    uint8_t out[32]);

/* HMAC with a named digest, only for the RPC challenge/response which must
 * follow Python's multiprocessing.connection. Digest ids: */
#define RNC_DIGEST_MD5 1
#define RNC_DIGEST_SHA256 2
#define RNC_DIGEST_SHA384 3
#define RNC_DIGEST_SHA3_256 4
#define RNC_DIGEST_SHA3_384 5
/* Writes up to out_capacity bytes, sets *written. Returns 0 when the digest is
 * not supported by the backend (the portable backend supports SHA-256 only). */
int rnc_hmac_digest(int digest, const uint8_t *key, size_t key_size, const void *data,
                    size_t size, uint8_t *out, size_t out_capacity, size_t *written);

/* HKDF-SHA256 (RFC 5869). salt may be NULL with salt_size 0 (all-zero salt),
 * likewise info. out_size <= 255 * 32. */
int rnc_hkdf_sha256(const uint8_t *salt, size_t salt_size, const uint8_t *ikm, size_t ikm_size,
                    const uint8_t *info, size_t info_size, uint8_t *out, size_t out_size);

/* AES-256-CBC without padding: size must be a multiple of 16. in and out may be
 * the same buffer. The core applies and checks PKCS7 itself. */
int rnc_aes256_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16], const uint8_t *in,
                           uint8_t *out, size_t size);
int rnc_aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16], const uint8_t *in,
                           uint8_t *out, size_t size);

/* X25519 (RFC 7748). _public derives the public key from a 32 byte private
 * scalar. _derive returns 0 when the shared secret is all zero (low order
 * point), like OpenSSL. */
int rnc_x25519_public(const uint8_t private_key[32], uint8_t public_key[32]);
int rnc_x25519_derive(const uint8_t private_key[32], const uint8_t peer_public[32],
                      uint8_t shared[32]);

/* Ed25519 (RFC 8032) from a 32 byte seed. */
int rnc_ed25519_public(const uint8_t seed[32], uint8_t public_key[32]);
int rnc_ed25519_sign(const uint8_t seed[32], const void *data, size_t size, uint8_t signature[64]);
/* Returns 1 for a valid signature, 0 otherwise. */
int rnc_ed25519_verify(const uint8_t public_key[32], const void *data, size_t size,
                       const uint8_t signature[64]);

#endif
