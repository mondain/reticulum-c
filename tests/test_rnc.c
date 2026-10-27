#include <reticulum_c/rnc.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

/* Frozen facts from Leviculum 395edd42, vectors.json, generated against
 * RNS 1.3.5 d5e62d4e15c5fe2e170f7bd9e120551671f21a27. See docs/reticulum-c.md.
 * These constants are independent expectations, never produced by rnc_ code. */
static size_t unhex(const char *text, uint8_t *out) {
    size_t n = 0;
    while (*text) { unsigned value; CHECK(sscanf(text, "%2x", &value) == 1); out[n++] = (uint8_t)value; text += 2; }
    return n;
}
static void equals_hex(const uint8_t *data, size_t size, const char *hex) {
    uint8_t expected[1002];
    CHECK(unhex(hex, expected) == size);
    CHECK(!memcmp(data, expected, size));
}
static void make_identity(rnc_identity *identity, unsigned first) {
    uint8_t key[64]; size_t i;
    for (i = 0; i < sizeof(key); ++i) key[i] = (uint8_t)(first + i);
    CHECK(rnc_identity_from_private(identity, key) == RNC_OK);
}
typedef struct fixed_rng { uint64_t counter; uint8_t block[32]; size_t used; } fixed_rng;
static rnc_result fixed_random(void *context, uint8_t *out, size_t size) {
    fixed_rng *rng = context;
    while (size--) {
        if (rng->used == 32) {
            uint8_t seed[21] = "rns-spec-seed"; size_t written = 32, i;
            for (i = 0; i < 8; ++i) seed[20u-i] = (uint8_t)(rng->counter >> (i*8u));
            CHECK(EVP_Q_digest(NULL, "SHA256", NULL, seed, sizeof(seed), rng->block, &written));
            ++rng->counter; rng->used = 0;
        }
        *out++ = rng->block[rng->used++];
    }
    return RNC_OK;
}
static rnc_result failed_random(void *context, uint8_t *out, size_t size) {
    (void)context; (void)out; (void)size; return RNC_CRYPTO;
}
static rnc_result failed_iv(void *context, uint8_t *out, size_t size) {
    unsigned *calls = context;
    if ((*calls)++) return RNC_CRYPTO;
    memset(out, 0x23, size); return RNC_OK;
}
/* Independent OpenSSL construction lets the attacker change CBC bytes while
 * retaining a valid MAC. The positive control proves this reaches unpadding. */
static void authenticate_modified_token(const rnc_identity *identity, uint8_t *token, size_t size) {
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, identity->private_key, 32);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, token, 32);
    EVP_PKEY_CTX *exchange = EVP_PKEY_CTX_new(key, NULL), *hkdf = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    uint8_t shared[32], derived[64]; size_t n = 32, derived_size = 64, mac_size = 32;
    CHECK(key && peer && exchange && hkdf);
    CHECK(EVP_PKEY_derive_init(exchange) == 1 && EVP_PKEY_derive_set_peer(exchange, peer) == 1);
    CHECK(EVP_PKEY_derive(exchange, shared, &n) == 1 && n == 32);
    CHECK(EVP_PKEY_derive_init(hkdf) == 1 && EVP_PKEY_CTX_set_hkdf_md(hkdf, EVP_sha256()) == 1);
    CHECK(EVP_PKEY_CTX_set1_hkdf_salt(hkdf, identity->hash, 16) == 1);
    CHECK(EVP_PKEY_CTX_set1_hkdf_key(hkdf, shared, 32) == 1);
    CHECK(EVP_PKEY_derive(hkdf, derived, &derived_size) == 1 && derived_size == 64);
    CHECK(EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, derived, 32, token+32, size-64,
        token+size-32, 32, &mac_size));
    EVP_PKEY_CTX_free(exchange); EVP_PKEY_CTX_free(hkdf); EVP_PKEY_free(key); EVP_PKEY_free(peer);
}
static void identity_vectors(void) {
    rnc_identity src, dst, pub, unchanged;
    uint8_t hash[32], signature[64], token[500], output[500], name[10], dest[16];
    const char *message = "reticulum-spec-signed-message";
    const char *plain = "reticulum encrypted payload";
    fixed_rng rng = {0, {0}, 32};
    size_t size, i;
    make_identity(&src, 0); make_identity(&dst, 64);
    equals_hex(src.public_key, 64, "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7");
    equals_hex(src.hash, 16, "aca31af0441d81dbec71e82da0b4b5f5");
    CHECK(rnc_hash("reticulum-spec", strlen("reticulum-spec"), hash) == RNC_OK);
    equals_hex(hash, 32, "659fe249468c635cdfe90a12624abec49f0bd36ba66d467b4f7155c79e8addf2");
    CHECK(rnc_identity_sign(&src, message, strlen(message), signature) == RNC_OK);
    equals_hex(signature, 64, "bbfdcde5aa05197f77acd8ac31aceb1e6470fe69b894ce4ea52da018c88c411cb6aa7352e3c30323462a362b767600d163cce4c10ae69769f3f0a78c06a8b10d");
    CHECK(rnc_identity_from_public(&pub, src.public_key) == RNC_OK);
    CHECK(rnc_identity_verify(&pub, message, strlen(message), signature) == RNC_OK);
    signature[0] ^= 1;
    CHECK(rnc_identity_verify(&pub, message, strlen(message), signature) == RNC_AUTH);
    CHECK(rnc_identity_sign(&pub, message, strlen(message), signature) == RNC_INVALID);
    CHECK(rnc_destination_hash("test.vec", &dst, name, dest) == RNC_OK);
    equals_hex(name, 10, "9da53eec82a28ce2f2e9");
    equals_hex(dest, 16, "07d4541d4fdc0abfacc9364fdf979ee1");
    CHECK(rnc_identity_encrypt(&dst, plain, strlen(plain), fixed_random, &rng, token, sizeof(token), &size) == RNC_OK);
    equals_hex(token, size, "efd9ec3449e46df22de114b1f785b359bef07989e7e1bbb62a0e9908cb72ed5353f9c3fa8c40c79941c89cf944dd56950758047257bf483145886d2115b50dc2e84dec35bc18a0b37d31e9350c8cb09a0d6facefdc669d6f1c9bc07f5e46b99a2c00a3ea0059e49adecc7c5df500491b");
    CHECK(rnc_identity_decrypt(&dst, token, size, output, sizeof(output), &i) == RNC_OK);
    CHECK(i == strlen(plain) && !memcmp(output, plain, i));
    for (i = 0; i < size; ++i) {
        size_t written = 99; token[i] ^= 1; memset(output, 0x55, sizeof(output));
        CHECK(rnc_identity_decrypt(&dst, token, size, output, sizeof(output), &written) != RNC_OK);
        CHECK(written == 0 && output[0] == 0x55 && output[499] == 0x55);
        token[i] ^= 1;
    }
    authenticate_modified_token(&dst, token, size);
    CHECK(rnc_identity_decrypt(&dst, token, size, output, sizeof(output), &i) == RNC_OK);
    token[63] ^= 1; authenticate_modified_token(&dst, token, size);
    memset(output, 0x55, sizeof(output));
    CHECK(rnc_identity_decrypt(&dst, token, size, output, sizeof(output), &i) == RNC_AUTH);
    CHECK(i == 0 && output[0] == 0x55 && output[499] == 0x55);
    token[63] ^= 1; authenticate_modified_token(&dst, token, size);
    CHECK(rnc_identity_decrypt(&pub, token, size, output, sizeof(output), &i) == RNC_INVALID);
    CHECK(rnc_identity_decrypt(&dst, token, size, output, 1, &i) == RNC_NO_SPACE && i == 0);
    unchanged = src;
    CHECK(rnc_identity_generate(&src, failed_random, NULL) == RNC_CRYPTO);
    CHECK(!memcmp(&src, &unchanged, sizeof(src)));
    CHECK(rnc_identity_encrypt(&dst, plain, strlen(plain), failed_random, NULL, token, sizeof(token), &size) == RNC_CRYPTO);
    {
        unsigned calls = 0; uint8_t zeros[64] = {0}; rnc_identity low_order;
        memset(token, 0x55, sizeof(token));
        CHECK(rnc_identity_encrypt(&dst, plain, strlen(plain), failed_iv, &calls, token, sizeof(token), &size) == RNC_CRYPTO);
        CHECK(calls == 2 && !size && token[0] == 0x55 && token[499] == 0x55);
        CHECK(rnc_identity_from_public(&low_order, zeros) == RNC_OK);
        CHECK(rnc_identity_encrypt(&low_order, plain, strlen(plain), fixed_random, &rng, token, sizeof(token), &size) == RNC_CRYPTO);
        CHECK(!size && token[0] == 0x55);
        memset(token, 0, 96);
        CHECK(rnc_identity_decrypt(&dst, token, 96, output, sizeof(output), &size) == RNC_AUTH && !size);
    }
    CHECK(rnc_identity_encrypt(&dst, plain, strlen(plain), fixed_random, &rng, token, 1, &size) == RNC_NO_SPACE);
    memset(output, 'x', 384);
    CHECK(rnc_identity_encrypt(&dst, output, 384, fixed_random, &rng, token, sizeof(token), &size) == RNC_INVALID);
    for (i = 0; i <= RNC_SINGLE_MDU; ++i) {
        size_t encoded, decoded;
        memset(output, (int)(i & 255u), i);
        CHECK(rnc_identity_encrypt(&dst, output, i, fixed_random, &rng, token, sizeof(token), &encoded) == RNC_OK);
        CHECK(rnc_identity_decrypt(&dst, token, encoded, output, sizeof(output), &decoded) == RNC_OK && decoded == i);
        if (i) CHECK(output[0] == (i & 255u) && output[i-1u] == (i & 255u));
    }
    rnc_identity_clear(&src); memset(&unchanged, 0, sizeof(unchanged));
    CHECK(!memcmp(&src, &unchanged, sizeof(src)));
    rnc_identity_clear(&dst); rnc_identity_clear(&pub);
}

static void packet_vectors(void) {
    rnc_packet packet, sentinel, second;
    uint8_t raw[501], encoded[500], hash[32], other[32]; size_t size, n, i;
    size = unhex("0800fc0910664040482cd653166c8f225520006869", raw);
    CHECK(rnc_packet_decode(raw, size, &packet) == RNC_OK);
    CHECK(packet.flags == 8 && packet.context == 0 && packet.data_size == 2);
    CHECK(!memcmp(packet.data, "hi", 2));
    CHECK(rnc_packet_encode(&packet, encoded, sizeof(encoded), &n) == RNC_OK && n == size);
    CHECK(!memcmp(raw, encoded, size));
    CHECK(rnc_packet_hash(&packet, hash) == RNC_OK);
    second = packet; second.flags |= 0x50; second.hops = 7;
    memset(second.transport_id, 0xa1, sizeof(second.transport_id));
    CHECK(rnc_packet_hash(&second, other) == RNC_OK && !memcmp(hash, other, 32));
    CHECK(rnc_packet_encode(&second, raw, sizeof(raw), &n) == RNC_OK && n == size+16);
    CHECK(rnc_packet_decode(raw, n, &second) == RNC_OK && second.hops == 7 && second.transport_id[0] == 0xa1);
    second.hops = 127;
    CHECK(rnc_packet_encode(&second, raw, sizeof(raw), &n) == RNC_OK);
    raw[1] = 128;
    CHECK(rnc_packet_decode(raw, n, &second) == RNC_PROTOCOL);
    raw[1] = 0;
    CHECK(rnc_packet_decode(raw, 35, &second) == RNC_PROTOCOL);
    memset(&sentinel, 0x55, sizeof(sentinel));
    for (i = 0; i < 35; ++i) {
        second = sentinel;
        CHECK(rnc_packet_decode(raw, i, &second) == RNC_PROTOCOL);
        CHECK(!memcmp(&second, &sentinel, sizeof(second)));
    }
    raw[0] |= 0x80;
    CHECK(rnc_packet_decode(raw, n, &second) == RNC_UNSUPPORTED);
    CHECK(rnc_packet_decode(raw, 501, &second) == RNC_PROTOCOL);
    memset(encoded, 0x55, sizeof(encoded));
    CHECK(rnc_packet_encode(&packet, encoded, 1, &n) == RNC_NO_SPACE && n == 0 && encoded[0] == 0x55);
    packet.data_size = RNC_MTU-19u;
    CHECK(rnc_packet_encode(&packet, raw, sizeof(raw), &n) == RNC_OK && n == 500);
    packet.data_size++;
    CHECK(rnc_packet_encode(&packet, raw, sizeof(raw), &n) == RNC_INVALID);
    packet.data_size = 0;
    CHECK(rnc_packet_encode(&packet, raw, sizeof(raw), &n) == RNC_INVALID);
    packet.data_size = 1; packet.hops = 128;
    CHECK(rnc_packet_encode(&packet, raw, sizeof(raw), &n) == RNC_INVALID);
}

static void announce_vectors(void) {
    const char *ordinary = "010007d4541d4fdc0abfacc9364fdf979ee10079a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd59da53eec82a28ce2f2e930078528be006553f1000766299dffcc8ecad446372b2b47b7e6afc0f699487099642a81378c49888e43a626529d493fd8b1da2fd17b43161bcb8b2506fee1e65ff92ce8b1b015a595004144";
    const char *ratcheted = "2100bb0868b19b0a9c1f2df1441de5dfcfbc0079a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd585eae8cf1203d961396730078528be006553f10047ef27fd7465d539b8d23394c0d6a0021223ec7107422d60213c0e98d25b6a7f494d501a6f6cab03cea2950c43b53f721c9d68458c875f4644ece57eb2ecec038ecae1f1ccd3c2ad080e418eac4f17d97cfdc353e99556514a70f037c887230d4144";
    rnc_packet packet, created; rnc_announce announce, sentinel;
    uint8_t raw[500], encoded[500]; size_t size, written, i;
    rnc_identity identity; fixed_rng rng = {0, {0}, 32};
    size = unhex(ordinary, raw);
    CHECK(rnc_packet_decode(raw, size, &packet) == RNC_OK);
    CHECK(rnc_announce_verify(&packet, &announce) == RNC_OK);
    CHECK(!announce.identity.has_private && !announce.has_ratchet && announce.app_size == 2);
    CHECK(!memcmp(announce.app_data, "AD", 2));
    equals_hex(announce.destination, 16, "07d4541d4fdc0abfacc9364fdf979ee1");
    memset(&sentinel, 0x55, sizeof(sentinel));
    for (i = 0; i < packet.data_size; ++i) {
        announce = sentinel; packet.data[i] ^= 1;
        CHECK(rnc_announce_verify(&packet, &announce) != RNC_OK);
        CHECK(!memcmp(&announce, &sentinel, sizeof(announce)));
        packet.data[i] ^= 1;
    }
    packet.destination[0] ^= 1;
    CHECK(rnc_announce_verify(&packet, &announce) == RNC_AUTH);
    packet.destination[0] ^= 1;
    packet.context = 11; packet.hops = 8;
    CHECK(rnc_announce_verify(&packet, &announce) == RNC_OK);
    packet.data_size = 147;
    CHECK(rnc_announce_verify(&packet, &announce) == RNC_PROTOCOL);
    make_identity(&identity, 64);
    CHECK(rnc_announce_create(&identity, "test.vec", "AD", 2, 1700000000, fixed_random, &rng, &created) == RNC_OK);
    CHECK(rnc_packet_encode(&created, encoded, sizeof(encoded), &written) == RNC_OK);
    equals_hex(encoded, written, ordinary);
    CHECK(rnc_announce_create(&identity, "test.vec", "AD", 2, UINT64_MAX, fixed_random, &rng, &created) == RNC_INVALID);
    size = unhex(ratcheted, raw);
    CHECK(rnc_packet_decode(raw, size, &packet) == RNC_OK);
    CHECK(rnc_announce_verify(&packet, &announce) == RNC_OK && announce.has_ratchet);
    for (i = 0; i < 32; ++i) {
        packet.data[84u+i] ^= 1;
        CHECK(rnc_announce_verify(&packet, &announce) == RNC_AUTH);
        packet.data[84u+i] ^= 1;
    }
    rnc_identity_clear(&identity);
}

static void framing_vectors(void) {
    const uint8_t data[] = {1, 0x7e, 2, 0x7d, 3};
    uint8_t framed[1002], decoded[500]; size_t n, size, i; rnc_hdlc state = {0};
    CHECK(rnc_hdlc_encode(data, sizeof(data), framed, sizeof(framed), &size) == RNC_OK);
    equals_hex(framed, size, "7e017d5e027d5d037e");
    for (i = 0; i < size; ++i) {
        rnc_result result = rnc_hdlc_feed(&state, framed[i], decoded, sizeof(decoded), &n);
        CHECK(result == (i+1u == size ? RNC_OK : RNC_AGAIN));
    }
    CHECK(n == sizeof(data) && !memcmp(decoded, data, n));
    CHECK(rnc_hdlc_encode(data, sizeof(data), framed, 1, &size) == RNC_NO_SPACE && size == 0);
    for (i = 0; i < 500; ++i) decoded[i] = (uint8_t)(i & 1 ? 0x7d : 0x7e);
    CHECK(rnc_hdlc_encode(decoded, 500, framed, sizeof(framed), &size) == RNC_OK && size == 1002);
    for (i = 0; i < size; ++i) {
        rnc_result result = rnc_hdlc_feed(&state, framed[i], decoded, sizeof(decoded), &n);
        CHECK(result == (i+1u == size ? RNC_OK : RNC_AGAIN));
    }
    CHECK(n == 500);
    CHECK(rnc_hdlc_feed(&state, 0x7e, decoded, 500, &n) == RNC_AGAIN);
    for (i = 0; i < sizeof(state.data); ++i) CHECK(rnc_hdlc_feed(&state, 1, decoded, 500, &n) == RNC_AGAIN);
    CHECK(rnc_hdlc_feed(&state, 1, decoded, 500, &n) == RNC_NO_SPACE);
    CHECK(rnc_hdlc_feed(&state, 0x7e, decoded, 500, &n) == RNC_AGAIN);
    CHECK(rnc_hdlc_feed(&state, 1, decoded, 500, &n) == RNC_AGAIN);
    CHECK(rnc_hdlc_feed(&state, 0x7e, decoded, 500, &n) == RNC_OK && n == 1 && decoded[0] == 1);
    CHECK(rnc_hdlc_feed(&state, 0x7d, decoded, 500, &n) == RNC_AGAIN);
    CHECK(rnc_hdlc_feed(&state, 0x7e, decoded, 500, &n) == RNC_PROTOCOL);
}

/* Identity.truncated_hash and Identity.get_random_hash. */
static void hash_helpers(void) {
    uint8_t full[32], truncated[16], a[16], b[16], seed_bytes[16], expected[16];
    fixed_rng one = {0, {0}, 32}, two = {0, {0}, 32}, three = {0, {0}, 32};
    CHECK(rnc_hash("abc", 3, full) == RNC_OK);
    CHECK(rnc_truncated_hash("abc", 3, truncated) == RNC_OK && !memcmp(truncated, full, 16));
    CHECK(rnc_truncated_hash(NULL, 0, truncated) == RNC_OK);
    CHECK(rnc_truncated_hash(NULL, 1, truncated) == RNC_INVALID && rnc_truncated_hash("x", 1, NULL) == RNC_INVALID);
    /* random hash: the truncated hash of 16 random bytes */
    CHECK(fixed_random(&one, seed_bytes, 16) == RNC_OK);
    CHECK(rnc_truncated_hash(seed_bytes, 16, expected) == RNC_OK);
    CHECK(rnc_random_hash(fixed_random, &two, a) == RNC_OK && !memcmp(a, expected, 16));
    CHECK(rnc_random_hash(fixed_random, &two, b) == RNC_OK && memcmp(a, b, 16));
    CHECK(rnc_random_hash(NULL, &three, a) == RNC_INVALID && rnc_random_hash(fixed_random, &three, NULL) == RNC_INVALID);
}
int main(int argc, char **argv) {
    CHECK(argc == 2);
    if (!strcmp(argv[1], "identity")) identity_vectors();
    else if (!strcmp(argv[1], "packet")) packet_vectors();
    else if (!strcmp(argv[1], "framing")) framing_vectors();
    else if (!strcmp(argv[1], "announce")) announce_vectors();
    else if (!strcmp(argv[1], "hashes")) hash_helpers();
    else CHECK(0);
    puts("Reticulum C test passed");
    return 0;
}
