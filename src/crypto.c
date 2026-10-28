#include <reticulum_c/rnc.h>
#include "internal.h"
#include "crypto_backend.h"
#include <string.h>

rnc_result rnc_hash(const void *data, size_t size, uint8_t output[32]) {
    uint8_t digest[32];
    if ((!data && size) || !output) return RNC_INVALID;
    if (!rnc_sha256(data, size, digest)) return RNC_CRYPTO;
    memcpy(output, digest, 32);
    return RNC_OK;
}

rnc_result rnc_truncated_hash(const void *data, size_t size, uint8_t output[16]) {
    uint8_t full[32];
    rnc_result r;
    if (!output) return RNC_INVALID;
    r = rnc_hash(data, size, full);
    if (r == RNC_OK) memcpy(output, full, 16);
    return r;
}
rnc_result rnc_random_hash(rnc_random_fn random, void *context, uint8_t output[16]) {
    uint8_t bytes[16];
    rnc_result r;
    if (!random || !output) return RNC_INVALID;
    r = random(context, bytes, sizeof(bytes));
    if (r == RNC_OK) r = rnc_truncated_hash(bytes, sizeof(bytes), output);
    rnc_cleanse(bytes, sizeof(bytes));
    return r;
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
    if (!rnc_x25519_public(key, pub) || !rnc_ed25519_public(key+32, pub+32)) goto done;
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
    rnc_cleanse(key, sizeof(key));
    return status;
}

void rnc_identity_clear(rnc_identity *identity) {
    if (identity) rnc_cleanse(identity, sizeof(*identity));
}

rnc_result rnc_identity_sign(const rnc_identity *identity, const void *data,
    size_t size, uint8_t signature[64]) {
    uint8_t result[64];
    if (!identity || !identity->has_private || (!data && size) || !signature) return RNC_INVALID;
    if (!rnc_ed25519_sign(identity->private_key+32, data, size, result)) return RNC_CRYPTO;
    memcpy(signature, result, 64);
    return RNC_OK;
}

rnc_result rnc_identity_verify(const rnc_identity *identity, const void *data,
    size_t size, const uint8_t signature[64]) {
    if (!identity || (!data && size) || !signature) return RNC_INVALID;
    return rnc_ed25519_verify(identity->public_key+32, data, size, signature) ? RNC_OK : RNC_AUTH;
}

int rnc_crypto_derive(const uint8_t private_key[32], const uint8_t peer_key[32],
    const uint8_t salt[16], uint8_t output[64]) {
    uint8_t shared[32];
    int ok = rnc_x25519_derive(private_key, peer_key, shared) &&
        rnc_hkdf_sha256(salt, 16, shared, 32, NULL, 0, output, 64);
    rnc_cleanse(shared, sizeof(shared));
    return ok;
}

/* Token body shared by link tokens, group tokens and the single-packet identity
 * token: IV(16) || AES-256-CBC(PKCS7(plain)) || HMAC-SHA256(IV || ciphertext).
 * key is 64 bytes: HMAC key first, AES key second. Everything is built in the
 * caller's output buffer (no heap, no large stack buffers); data may overlap it. */
rnc_result rnc_token_encrypt(const uint8_t key[64], const void *data, size_t size,
    rnc_random_fn random, void *context, uint8_t *output, size_t capacity, size_t *written) {
    uint8_t iv[16];
    size_t padded, needed, pad;
    rnc_result result;
    if (written) *written = 0;
    needed = 48u + (size/16u+1u)*16u;
    if (capacity < needed) return RNC_NO_SPACE;
    padded = needed - 48u;
    pad = padded - size;
    result = random(context, iv, 16);
    if (result != RNC_OK) goto done;
    result = RNC_CRYPTO;
    if (size) memmove(output+16, data, size);
    memset(output+16+size, (int)pad, pad);
    if (!rnc_aes256_cbc_encrypt(key+32, iv, output+16, output+16, padded)) goto wipe;
    memcpy(output, iv, 16);
    if (!rnc_hmac_sha256(key, 32, output, needed-32u, output+needed-32u)) goto wipe;
    if (written) *written = needed;
    result = RNC_OK;
    goto done;
wipe:
    rnc_cleanse(output, needed);
done:
    rnc_cleanse(iv, sizeof(iv));
    return result;
}

/* Verify, decrypt and unpad a token (see rnc_token_encrypt). Any size >= 64 with a
 * 16-byte multiple body is accepted here; callers bound the size. max_plain bounds
 * the recovered plaintext (RNC_AUTH when exceeded). */
rnc_result rnc_token_decrypt(const uint8_t key[64], const uint8_t *data, size_t size,
    size_t max_plain, uint8_t *output, size_t capacity, size_t *written) {
    uint8_t tag[32], last[16];
    const uint8_t *cipher = data+16, *prev;
    size_t csize = size-48u, pad, length, i;
    unsigned bad = 0;
    rnc_result result = RNC_AUTH;
    if (written) *written = 0;
    if (size < 64 || (size-48u)%16u) return RNC_AUTH;
    if (!rnc_hmac_sha256(key, 32, data, size-32u, tag) || rnc_ct_memcmp(tag, data+size-32u, 32)) goto done;
    prev = csize > 16u ? cipher+csize-32u : data;
    if (!rnc_aes256_cbc_decrypt(key+32, prev, cipher+csize-16u, last, 16)) { result = RNC_CRYPTO; goto done; }
    pad = last[15];
    bad |= (pad == 0u) | (pad > 16u);
    for (i = 1; i <= 16u; i++) bad |= (i <= pad) & (last[16u-i] != pad);
    if (bad) goto done;
    length = csize - pad;
    if (length > max_plain) goto done;
    if (capacity < length) { result = RNC_NO_SPACE; goto done; }
    if (csize > 16u &&
        !rnc_aes256_cbc_decrypt(key+32, data, cipher, output, csize-16u)) { result = RNC_CRYPTO; goto done; }
    memcpy(output+csize-16u, last, 16u-pad);
    *written = length;
    result = RNC_OK;
done:
    rnc_cleanse(tag, sizeof(tag)); rnc_cleanse(last, sizeof(last));
    return result;
}

rnc_result rnc_identity_encrypt(const rnc_identity *identity, const void *data,
    size_t size, rnc_random_fn random, void *context, uint8_t *output,
    size_t capacity, size_t *written) {
    uint8_t private_key[32], key[64], eph[32];
    size_t needed, body = 0; rnc_result status = RNC_CRYPTO;
    if (written) *written = 0;
    if (!identity || (!data && size) || !random || !output || !written || size > RNC_SINGLE_MDU) return RNC_INVALID;
    needed = 80u + (size/16u + 1u)*16u;
    if (capacity < needed) return RNC_NO_SPACE;
    status = random(context, private_key, 32);
    if (status != RNC_OK) goto done;
    status = RNC_CRYPTO;
    if (!rnc_x25519_public(private_key, eph) ||
        !rnc_crypto_derive(private_key, identity->public_key, identity->hash, key)) goto done;
    status = rnc_token_encrypt(key, data, size, random, context, output+32, capacity-32u, &body);
    if (status != RNC_OK) goto done;
    memcpy(output, eph, 32); *written = 32u + body;
done:
    rnc_cleanse(private_key, sizeof(private_key)); rnc_cleanse(key, sizeof(key));
    return status;
}

rnc_result rnc_identity_decrypt(const rnc_identity *identity, const uint8_t *token,
    size_t size, uint8_t *output, size_t capacity, size_t *written) {
    uint8_t key[64]; rnc_result status = RNC_AUTH;
    if (written) *written = 0;
    if (!identity || !identity->has_private || !token || !output || !written) return RNC_INVALID;
    if (size < 96 || size > 464 || (size-80u)%16u) return RNC_AUTH;
    if (!rnc_crypto_derive(identity->private_key, token, identity->hash, key)) goto done;
    status = rnc_token_decrypt(key, token+32, size-32u, RNC_SINGLE_MDU, output, capacity, written);
done:
    rnc_cleanse(key, sizeof(key));
    return status;
}

rnc_result rnc_token_seal(const uint8_t key[64], const void *data, size_t size,
    rnc_random_fn random, void *context, uint8_t *output, size_t capacity, size_t *written) {
    if (written) *written = 0;
    if (!key || (!data && size) || !random || !output || !written || size > RNC_LINK_MAX_MDU) return RNC_INVALID;
    return rnc_token_encrypt(key, data, size, random, context, output, capacity, written);
}

rnc_result rnc_token_open(const uint8_t key[64], const uint8_t *data, size_t size,
    uint8_t *output, size_t capacity, size_t *written) {
    if (written) *written = 0;
    if (!key || !data || !output || !written) return RNC_INVALID;
    if (size < 64 || size > RNC_LINK_MAX_MDU+49u || (size-48u)%16u) return RNC_AUTH;
    return rnc_token_decrypt(key, data, size, RNC_LINK_MAX_MDU, output, capacity, written);
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
