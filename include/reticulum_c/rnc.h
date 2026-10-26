#ifndef RETICULUM_C_RNC_H
#define RETICULUM_C_RNC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RNC_MTU 500u
#define RNC_ADDRESS_SIZE 16u
#define RNC_NAME_HASH_SIZE 10u
#define RNC_SINGLE_MDU 383u
#define RNC_HDLC_MAX (2u * RNC_MTU + 2u)

typedef enum rnc_result {
    RNC_OK = 0, RNC_AGAIN, RNC_INVALID, RNC_NO_SPACE, RNC_AUTH,
    RNC_CRYPTO, RNC_PROTOCOL, RNC_UNSUPPORTED, RNC_STATE, RNC_TIMEOUT
} rnc_result;

enum rnc_destination_type { RNC_SINGLE = 0, RNC_GROUP = 1, RNC_PLAIN = 2, RNC_LINK = 3 };
enum rnc_packet_type { RNC_DATA = 0, RNC_ANNOUNCE = 1, RNC_LINKREQUEST = 2, RNC_PROOF = 3 };

/* Return RNC_OK after filling every byte with cryptographically secure random
 * data. Tests may supply fixed randomness; production hosts must not do so. */
typedef rnc_result (*rnc_random_fn)(void *context, uint8_t *output, size_t size);

/* Caller-owned sensitive storage. Do not log/copy the private key; clear when
 * finished. Crypto operations allocate inside OpenSSL. No file, socket, clock,
 * thread, or random-device access is performed by this protocol library. */
typedef struct rnc_identity {
    uint8_t private_key[64], public_key[64], hash[16];
    int has_private;
} rnc_identity;

typedef struct rnc_packet {
    uint8_t flags, hops, transport_id[16], destination[16], context;
    size_t data_size;
    uint8_t data[RNC_MTU - 19u];
} rnc_packet;

/* Start each byte stream with `rnc_hdlc state = {0}`. Zero the whole structure
 * to reset it on transport replacement; never carry a partial frame across
 * connections. Do not modify fields directly while a stream is active. */
typedef struct rnc_hdlc {
    size_t size;
    int active, escaped, discard;
    uint8_t data[RNC_MTU];
} rnc_hdlc;

typedef struct rnc_announce {
    rnc_identity identity; /* Public only; no private key is received. */
    uint8_t destination[16], name_hash[10], random_hash[10], ratchet[32];
    int has_ratchet;
    size_t app_size;
    uint8_t app_data[RNC_MTU - 19u - 148u];
} rnc_announce;

/* Outputs are committed only on success; *written is zero on any failure.
 * Input/output objects and buffers must not overlap. NULL data is valid only
 * with size zero. Instances and incremental framing state are thread-confined. */
rnc_result rnc_hash(const void *data, size_t size, uint8_t output[32]);
rnc_result rnc_identity_from_private(rnc_identity *identity, const uint8_t key[64]);
rnc_result rnc_identity_from_public(rnc_identity *identity, const uint8_t key[64]);
rnc_result rnc_identity_generate(rnc_identity *identity, rnc_random_fn random, void *context);
void rnc_identity_clear(rnc_identity *identity);
rnc_result rnc_identity_sign(const rnc_identity *identity, const void *data,
    size_t size, uint8_t signature[64]);
rnc_result rnc_identity_verify(const rnc_identity *identity, const void *data,
    size_t size, const uint8_t signature[64]);
/* SINGLE static-identity encryption. Ratchet encryption and authenticated sender
 * identity are not provided by this API. An encrypted packet can be anonymous. */
rnc_result rnc_identity_encrypt(const rnc_identity *identity, const void *data,
    size_t size, rnc_random_fn random, void *context, uint8_t *output,
    size_t capacity, size_t *written);
rnc_result rnc_identity_decrypt(const rnc_identity *identity, const uint8_t *token,
    size_t size, uint8_t *output, size_t capacity, size_t *written);
rnc_result rnc_destination_hash(const char *dotted_name, const rnc_identity *identity,
    uint8_t name_hash[10], uint8_t destination[16]);

rnc_result rnc_packet_encode(const rnc_packet *packet, uint8_t *output,
    size_t capacity, size_t *written);
rnc_result rnc_packet_decode(const uint8_t *data, size_t size, rnc_packet *packet);
rnc_result rnc_packet_hash(const rnc_packet *packet, uint8_t hash[32]);

rnc_result rnc_hdlc_encode(const uint8_t *data, size_t size, uint8_t *output,
    size_t capacity, size_t *written);
/* Feed one stream byte. RNC_OK yields one complete frame. Overlong/invalid
 * frames are discarded through the next delimiter, then framing resumes. */
rnc_result rnc_hdlc_feed(rnc_hdlc *state, uint8_t byte, uint8_t *output,
    size_t capacity, size_t *written);

/* Create a non-ratcheted announce; caller supplies Unix seconds and randomness.
 * Verification accepts both ordinary and ratcheted signed announce layouts.
 * Verified metadata does not establish freshness, a path, or sender identity. */
rnc_result rnc_announce_create(const rnc_identity *identity, const char *dotted_name,
    const void *app_data, size_t app_size, uint64_t unix_seconds,
    rnc_random_fn random, void *context, rnc_packet *packet);
rnc_result rnc_announce_verify(const rnc_packet *packet, rnc_announce *announce);

#ifdef __cplusplus
}
#endif
#endif
