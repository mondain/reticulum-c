/* Crypto backend using OpenSSL 3 (the default, -DRNC_CRYPTO=openssl). */
#include "crypto_backend.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string.h>

void rnc_cleanse(void *p, size_t n) { OPENSSL_cleanse(p, n); }

int rnc_ct_memcmp(const void *a, const void *b, size_t n) { return CRYPTO_memcmp(a, b, n); }

/* The opaque context holds an EVP_MD_CTX pointer. */
static EVP_MD_CTX **slot(rnc_sha256_ctx *ctx) { return (EVP_MD_CTX **)(void *)ctx->opaque; }

int rnc_sha256_init(rnc_sha256_ctx *ctx) {
    EVP_MD_CTX **c = slot(ctx);
    *c = EVP_MD_CTX_new();
    return *c && EVP_DigestInit_ex(*c, EVP_sha256(), NULL) == 1;
}

int rnc_sha256_update(rnc_sha256_ctx *ctx, const void *data, size_t size) {
    return size == 0 || EVP_DigestUpdate(*slot(ctx), data, size) == 1;
}

void rnc_sha256_discard(rnc_sha256_ctx *ctx) {
    EVP_MD_CTX **c = slot(ctx);
    EVP_MD_CTX_free(*c);
    *c = NULL;
}

int rnc_sha256_final(rnc_sha256_ctx *ctx, uint8_t out[32]) {
    unsigned int n = 0;
    int ok = EVP_DigestFinal_ex(*slot(ctx), out, &n) == 1 && n == 32;
    rnc_sha256_discard(ctx);
    return ok;
}

int rnc_sha256_copy(rnc_sha256_ctx *dst, const rnc_sha256_ctx *src) {
    EVP_MD_CTX **d = slot(dst);
    EVP_MD_CTX *const *s = (EVP_MD_CTX *const *)(const void *)src->opaque;
    *d = EVP_MD_CTX_new();
    return *d && EVP_MD_CTX_copy_ex(*d, *s) == 1;
}

int rnc_sha256(const void *data, size_t size, uint8_t out[32]) {
    size_t n = 32;
    uint8_t digest[32];
    if (!EVP_Q_digest(NULL, "SHA256", NULL, data, size, digest, &n) || n != 32)
        return 0;
    memcpy(out, digest, 32);
    return 1;
}

int rnc_hmac_digest(int digest, const uint8_t *key, size_t key_size, const void *data,
                    size_t size, uint8_t *out, size_t out_capacity, size_t *written) {
    const char *name;
    size_t n = out_capacity;
    switch (digest) {
    case RNC_DIGEST_MD5: name = "MD5"; break;
    case RNC_DIGEST_SHA256: name = "SHA256"; break;
    case RNC_DIGEST_SHA384: name = "SHA384"; break;
    case RNC_DIGEST_SHA3_256: name = "SHA3-256"; break;
    case RNC_DIGEST_SHA3_384: name = "SHA3-384"; break;
    default: return 0;
    }
    if (!EVP_Q_mac(NULL, "HMAC", NULL, name, NULL, key, key_size, data, size, out, out_capacity, &n))
        return 0;
    *written = n;
    return 1;
}

int rnc_hmac_sha256(const uint8_t *key, size_t key_size, const void *data, size_t size,
                    uint8_t out[32]) {
    size_t n = 0;
    return rnc_hmac_digest(RNC_DIGEST_SHA256, key, key_size, data, size, out, 32, &n) && n == 32;
}

int rnc_hkdf_sha256(const uint8_t *salt, size_t salt_size, const uint8_t *ikm, size_t ikm_size,
                    const uint8_t *info, size_t info_size, uint8_t *out, size_t out_size) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    size_t n = out_size;
    int ok = ctx && EVP_PKEY_derive_init(ctx) == 1 &&
             EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) == 1 &&
             (!salt_size || EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, (int)salt_size) == 1) &&
             EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, (int)ikm_size) == 1 &&
             (!info_size || EVP_PKEY_CTX_add1_hkdf_info(ctx, info, (int)info_size) == 1) &&
             EVP_PKEY_derive(ctx, out, &n) == 1 && n == out_size;
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static int cbc(int encrypt, const uint8_t key[32], const uint8_t iv[16], const uint8_t *in,
               uint8_t *out, size_t size) {
    EVP_CIPHER_CTX *ctx;
    int n = 0, ok;
    if (size % 16u)
        return 0;
    if (!size)
        return 1;
    ctx = EVP_CIPHER_CTX_new();
    ok = ctx && EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, encrypt) == 1 &&
         EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
         EVP_CipherUpdate(ctx, out, &n, in, (int)size) == 1 && (size_t)n == size;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int rnc_aes256_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16], const uint8_t *in,
                           uint8_t *out, size_t size) {
    return cbc(1, key, iv, in, out, size);
}

int rnc_aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16], const uint8_t *in,
                           uint8_t *out, size_t size) {
    return cbc(0, key, iv, in, out, size);
}

static int pub(int type, const uint8_t sk[32], uint8_t out[32]) {
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(type, NULL, sk, 32);
    size_t n = 32;
    int ok = key && EVP_PKEY_get_raw_public_key(key, out, &n) == 1 && n == 32;
    EVP_PKEY_free(key);
    return ok;
}

int rnc_x25519_public(const uint8_t private_key[32], uint8_t public_key[32]) {
    return pub(EVP_PKEY_X25519, private_key, public_key);
}

int rnc_x25519_derive(const uint8_t private_key[32], const uint8_t peer_public[32],
                      uint8_t shared[32]) {
    EVP_PKEY *local = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key, 32);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_public, 32);
    EVP_PKEY_CTX *ctx = local ? EVP_PKEY_CTX_new(local, NULL) : NULL;
    uint8_t out[32];
    size_t n = 32;
    int ok = peer && ctx && EVP_PKEY_derive_init(ctx) == 1 &&
             EVP_PKEY_derive_set_peer(ctx, peer) == 1 && EVP_PKEY_derive(ctx, out, &n) == 1 &&
             n == 32;
    if (ok)
        memcpy(shared, out, 32);
    OPENSSL_cleanse(out, sizeof(out));
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(local);
    return ok;
}

int rnc_ed25519_public(const uint8_t seed[32], uint8_t public_key[32]) {
    return pub(EVP_PKEY_ED25519, seed, public_key);
}

int rnc_ed25519_sign(const uint8_t seed[32], const void *data, size_t size, uint8_t signature[64]) {
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    uint8_t result[64];
    size_t n = 64;
    int ok = key && ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1 &&
             EVP_DigestSign(ctx, result, &n, data, size) == 1 && n == 64;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    if (ok)
        memcpy(signature, result, 64);
    return ok;
}

int rnc_ed25519_verify(const uint8_t public_key[32], const void *data, size_t size,
                       const uint8_t signature[64]) {
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, 32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = key && ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
             EVP_DigestVerify(ctx, signature, 64, data, size) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}
