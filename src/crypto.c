#include <reticulum_c/rnc.h>
#include "internal.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string.h>

rnc_result rnc_hash(const void *data, size_t size, uint8_t output[32]) {
    uint8_t digest[32]; size_t written = sizeof(digest);
    if ((!data && size) || !output) return RNC_INVALID;
    if (!EVP_Q_digest(NULL, "SHA256", NULL, data, size, digest, &written) || written != 32) return RNC_CRYPTO;
    memcpy(output, digest, 32);
    return RNC_OK;
}

static int public_key(int type, const uint8_t private_key[32], uint8_t output[32]) {
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(type, NULL, private_key, 32);
    size_t size = 32;
    int ok = key && EVP_PKEY_get_raw_public_key(key, output, &size) && size == 32;
    EVP_PKEY_free(key);
    return ok;
}

rnc_result rnc_identity_from_public(rnc_identity *identity, const uint8_t key[64]) {
    rnc_identity result = {0}; uint8_t digest[32];
    if (!identity || !key) return RNC_INVALID;
    if (rnc_hash(key, 64, digest) != RNC_OK) return RNC_CRYPTO;
    memcpy(result.public_key, key, 64); memcpy(result.hash, digest, 16);
    *identity = result;
    return RNC_OK;
}

rnc_result rnc_identity_from_private(rnc_identity *identity, const uint8_t key[64]) {
    rnc_identity result = {0}; uint8_t pub[64];
    rnc_result status = RNC_CRYPTO;
    if (!identity || !key) return RNC_INVALID;
    if (!public_key(EVP_PKEY_X25519, key, pub) || !public_key(EVP_PKEY_ED25519, key+32, pub+32)) goto done;
    if (rnc_identity_from_public(&result, pub) != RNC_OK) goto done;
    memcpy(result.private_key, key, 64); result.has_private = 1;
    *identity = result;
    status = RNC_OK;
done:
    rnc_identity_clear(&result);
    return status;
}

rnc_result rnc_identity_generate(rnc_identity *identity, rnc_random_fn random, void *context) {
    uint8_t key[64]; rnc_result status;
    if (!identity || !random) return RNC_INVALID;
    status = random(context, key, sizeof(key));
    if (status == RNC_OK) status = rnc_identity_from_private(identity, key);
    OPENSSL_cleanse(key, sizeof(key));
    return status;
}

void rnc_identity_clear(rnc_identity *identity) {
    if (identity) OPENSSL_cleanse(identity, sizeof(*identity));
}

rnc_result rnc_identity_sign(const rnc_identity *identity, const void *data,
    size_t size, uint8_t signature[64]) {
    EVP_PKEY *key; EVP_MD_CTX *ctx; uint8_t result[64]; size_t written = 64;
    int ok;
    if (!identity || !identity->has_private || (!data && size) || !signature) return RNC_INVALID;
    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, identity->private_key+32, 32);
    ctx = EVP_MD_CTX_new();
    ok = key && ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1 &&
        EVP_DigestSign(ctx, result, &written, data, size) == 1 && written == 64;
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(key);
    if (!ok) return RNC_CRYPTO;
    memcpy(signature, result, 64);
    return RNC_OK;
}

rnc_result rnc_identity_verify(const rnc_identity *identity, const void *data,
    size_t size, const uint8_t signature[64]) {
    EVP_PKEY *key; EVP_MD_CTX *ctx; rnc_result status = RNC_CRYPTO;
    if (!identity || (!data && size) || !signature) return RNC_INVALID;
    key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, identity->public_key+32, 32);
    ctx = EVP_MD_CTX_new();
    if (key && ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1)
        status = EVP_DigestVerify(ctx, signature, 64, data, size) == 1 ? RNC_OK : RNC_AUTH;
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(key);
    return status;
}

int rnc_crypto_derive(const uint8_t private_key[32], const uint8_t peer_key[32],
    const uint8_t salt[16], uint8_t output[64]) {
    EVP_PKEY *local = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key, 32);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_key, 32);
    EVP_PKEY_CTX *exchange = local ? EVP_PKEY_CTX_new(local, NULL) : NULL;
    EVP_PKEY_CTX *hkdf = NULL;
    uint8_t shared[32]; size_t shared_size = 32, derived_size = 64;
    int ok = 0;
    if (!peer || !exchange || EVP_PKEY_derive_init(exchange) != 1 ||
        EVP_PKEY_derive_set_peer(exchange, peer) != 1 ||
        EVP_PKEY_derive(exchange, shared, &shared_size) != 1 || shared_size != 32) goto done;
    hkdf = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    ok = hkdf && EVP_PKEY_derive_init(hkdf) == 1 &&
        EVP_PKEY_CTX_set_hkdf_md(hkdf, EVP_sha256()) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_salt(hkdf, salt, 16) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_key(hkdf, shared, 32) == 1 &&
        EVP_PKEY_derive(hkdf, output, &derived_size) == 1 && derived_size == 64;
done:
    OPENSSL_cleanse(shared, sizeof(shared));
    EVP_PKEY_CTX_free(hkdf); EVP_PKEY_CTX_free(exchange);
    EVP_PKEY_free(peer); EVP_PKEY_free(local);
    return ok;
}

static int mac(const uint8_t key[32], const uint8_t *data, size_t size, uint8_t output[32]) {
    size_t written = 32;
    return EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, key, 32, data, size,
        output, 32, &written) != NULL && written == 32;
}

rnc_result rnc_identity_encrypt(const rnc_identity *identity, const void *data,
    size_t size, rnc_random_fn random, void *context, uint8_t *output,
    size_t capacity, size_t *written) {
    uint8_t token[RNC_MTU], private_key[32], key[64];
    EVP_CIPHER_CTX *ctx = NULL; int count = 0, final = 0;
    size_t needed; rnc_result status = RNC_CRYPTO;
    if (written) *written = 0;
    if (!identity || (!data && size) || !random || !output || !written || size > RNC_SINGLE_MDU) return RNC_INVALID;
    needed = 80u + (size/16u + 1u)*16u;
    if (capacity < needed) return RNC_NO_SPACE;
    status = random(context, private_key, 32);
    if (status != RNC_OK) goto done;
    status = RNC_CRYPTO;
    if (!public_key(EVP_PKEY_X25519, private_key, token) ||
        !rnc_crypto_derive(private_key, identity->public_key, identity->hash, key)) goto done;
    status = random(context, token+32, 16);
    if (status != RNC_OK) goto done;
    status = RNC_CRYPTO;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key+32, token+32) != 1 ||
        EVP_EncryptUpdate(ctx, token+48, &count, data, (int)size) != 1 ||
        EVP_EncryptFinal_ex(ctx, token+48+count, &final) != 1 ||
        (size_t)(count+final) != needed-80u ||
        !mac(key, token+32, needed-64u, token+needed-32u)) goto done;
    memcpy(output, token, needed); *written = needed;
    status = RNC_OK;
done:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(private_key, sizeof(private_key)); OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(token, sizeof(token));
    return status;
}

rnc_result rnc_identity_decrypt(const rnc_identity *identity, const uint8_t *token,
    size_t size, uint8_t *output, size_t capacity, size_t *written) {
    uint8_t key[64], tag[32], plain[384]; EVP_CIPHER_CTX *ctx = NULL;
    int count = 0, final = 0; rnc_result status = RNC_AUTH;
    if (written) *written = 0;
    if (!identity || !identity->has_private || !token || !output || !written) return RNC_INVALID;
    if (size < 96 || size > 464 || (size-80u)%16u) return RNC_AUTH;
    if (!rnc_crypto_derive(identity->private_key, token, identity->hash, key) ||
        !mac(key, token+32, size-64u, tag) || CRYPTO_memcmp(tag, token+size-32u, 32)) goto done;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key+32, token+32) != 1) { status = RNC_CRYPTO; goto done; }
    if (EVP_DecryptUpdate(ctx, plain, &count, token+48, (int)(size-80u)) != 1 ||
        EVP_DecryptFinal_ex(ctx, plain+count, &final) != 1) goto done;
    if ((size_t)(count+final) > RNC_SINGLE_MDU) goto done;
    if (capacity < (size_t)(count+final)) { status = RNC_NO_SPACE; goto done; }
    memcpy(output, plain, (size_t)(count+final)); *written = (size_t)(count+final);
    status = RNC_OK;
done:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key)); OPENSSL_cleanse(tag, sizeof(tag)); OPENSSL_cleanse(plain, sizeof(plain));
    return status;
}

rnc_result rnc_token_seal(const uint8_t key[64], const void *data, size_t size,
    rnc_random_fn random, void *context, uint8_t *output, size_t capacity, size_t *written) {
    uint8_t token[RNC_MAX_MTU]; EVP_CIPHER_CTX *ctx = NULL; int n = 0, final = 0;
    size_t needed; rnc_result result;
    if (written) *written = 0;
    if (!key || (!data && size) || !random || !output || !written || size > RNC_LINK_MAX_MDU) return RNC_INVALID;
    needed = 48u + (size/16u+1u)*16u;
    if (capacity < needed) return RNC_NO_SPACE;
    result = random(context, token, 16);
    if (result != RNC_OK) goto done;
    result = RNC_CRYPTO;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key+32, token) != 1 ||
        EVP_EncryptUpdate(ctx, token+16, &n, data, (int)size) != 1 ||
        EVP_EncryptFinal_ex(ctx, token+16+n, &final) != 1 || (size_t)(n+final) != needed-48u ||
        !mac(key, token, needed-32u, token+needed-32u)) goto done;
    memcpy(output, token, needed); *written = needed; result = RNC_OK;
done:
    EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(token, sizeof(token)); return result;
}

rnc_result rnc_token_open(const uint8_t key[64], const uint8_t *data, size_t size,
    uint8_t *output, size_t capacity, size_t *written) {
    uint8_t tag[32], plain[RNC_LINK_MAX_MDU+1u]; EVP_CIPHER_CTX *ctx = NULL;
    int n = 0, final = 0; rnc_result result = RNC_AUTH;
    if (written) *written = 0;
    if (!key || !data || !output || !written) return RNC_INVALID;
    if (size < 64 || size > RNC_LINK_MAX_MDU+49u || (size-48u)%16u) return RNC_AUTH;
    if (!mac(key, data, size-32u, tag) || CRYPTO_memcmp(tag, data+size-32u, 32)) goto done;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key+32, data) != 1) { result = RNC_CRYPTO; goto done; }
    if (EVP_DecryptUpdate(ctx, plain, &n, data+16, (int)(size-48u)) != 1 ||
        EVP_DecryptFinal_ex(ctx, plain+n, &final) != 1 || (size_t)(n+final) > RNC_LINK_MAX_MDU) goto done;
    if (capacity < (size_t)(n+final)) { result = RNC_NO_SPACE; goto done; }
    memcpy(output, plain, (size_t)(n+final)); *written = (size_t)(n+final); result = RNC_OK;
done:
    EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(plain, sizeof(plain));
    OPENSSL_cleanse(tag, sizeof(tag)); return result;
}

rnc_result rnc_destination_hash(const char *dotted_name, const rnc_identity *identity,
    uint8_t name_hash[10], uint8_t destination[16]) {
    uint8_t digest[32], material[26]; const char *p; size_t length;
    if (!dotted_name || !name_hash || !destination || !*dotted_name) return RNC_INVALID;
    length = strlen(dotted_name);
    if (length > 255 || dotted_name[0] == '.' || dotted_name[length-1u] == '.') return RNC_INVALID;
    for (p = dotted_name; *p; ++p)
        if ((unsigned char)*p < 33 || (unsigned char)*p == 127 || (*p == '.' && p[1] == '.')) return RNC_INVALID;
    if (rnc_hash(dotted_name, length, digest) != RNC_OK) return RNC_CRYPTO;
    memcpy(material, digest, 10);
    if (identity) memcpy(material+10, identity->hash, 16);
    if (rnc_hash(material, identity ? 26 : 10, digest) != RNC_OK) return RNC_CRYPTO;
    memcpy(name_hash, material, 10); memcpy(destination, digest, 16);
    return RNC_OK;
}
