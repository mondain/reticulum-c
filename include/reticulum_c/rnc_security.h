#ifndef RETICULUM_C_SECURITY_H
#define RETICULUM_C_SECURITY_H
#include <reticulum_c/rnc.h>
#ifdef __cplusplus
extern "C" {
#endif

#define RNC_IFAC_MAX_SIZE 64u
#define RNC_IFAC_FRAME_MAX (RNC_MAX_MTU + RNC_IFAC_MAX_SIZE)
#define RNC_RATCHET_MAX_KEYS 512u
#define RNC_RATCHET_DEFAULT_INTERVAL UINT64_C(1800)
#define RNC_RATCHET_PEER_EXPIRY UINT64_C(2592000)
#define RNC_RATCHET_EXPORT_MAX (48u + 40u * RNC_RATCHET_MAX_KEYS + 64u)
#define RNC_GROUP_MDU 431u

/* Input/output buffers and key storage must not overlap. All data outputs are
 * committed only on success; *written is zero on failure. Caller-supplied Unix
 * seconds govern rotation/expiry; no wall clock or filesystem is accessed. */
/* Sensitive caller-owned configuration. Initialize before use; clear on release.
 * Name/passphrase are exact UTF-8 bytes, with NULL/zero denoting absence. At
 * least one nonempty component is required. Tag size is in bytes, 1..64. */
typedef struct rnc_ifac {
    uint8_t key[64];
    rnc_identity identity;
    size_t size;
} rnc_ifac;
rnc_result rnc_ifac_init(rnc_ifac *ifac, const void *name, size_t name_size,
    const void *passphrase, size_t passphrase_size, size_t tag_size);
void rnc_ifac_clear(rnc_ifac *ifac);
/* Raw packet codec runs inside the IFAC boundary: encode, apply, frame; receive,
 * deframe, verify, decode. Only complete authenticated packets are committed.
 * Output must not overlap input/configuration; *written is zero on failure. */
rnc_result rnc_ifac_apply(const rnc_ifac *ifac, const uint8_t *raw, size_t size,
    uint8_t *output, size_t capacity, size_t *written);
rnc_result rnc_ifac_verify(const rnc_ifac *ifac, const uint8_t *frame, size_t size,
    uint8_t *output, size_t capacity, size_t *written);

typedef struct rnc_ratchet_key {
    uint8_t private_key[32], public_key[32];
    uint64_t created_at;
} rnc_ratchet_key;
/* Keys newest first. Caller supplies stable storage; no allocation or I/O.
 * Private keys age by retention count, matching the reference. Peer public keys
 * expire separately. Do not mutate initialized fields directly. */
typedef struct rnc_ratchets {
    rnc_ratchet_key *keys;
    size_t count, capacity;
    uint64_t interval, last_rotation, last_time;
    uint8_t owner_hash[16];
} rnc_ratchets;
typedef struct rnc_peer_ratchet {
    uint8_t destination[16], public_key[32];
    uint64_t received_at, announced_at;
    int valid;
} rnc_peer_ratchet;
rnc_result rnc_ratchet_generate(rnc_ratchet_key *key, uint64_t unix_seconds,
    rnc_random_fn random, void *context);
void rnc_ratchet_clear(rnc_ratchet_key *key);
rnc_result rnc_ratchet_id(const uint8_t public_key[32], uint8_t id[10]);
rnc_result rnc_ratchets_init(rnc_ratchets *store, const rnc_identity *owner,
    rnc_ratchet_key *storage, size_t capacity, uint64_t interval_seconds);
void rnc_ratchets_clear(rnc_ratchets *store);
/* A due rotation generates before changing state; an unchanged store returns
 * RNC_OK. Time rollback is rejected. First rotation always creates a key. */
rnc_result rnc_ratchets_rotate(rnc_ratchets *store, uint64_t unix_seconds,
    rnc_random_fn random, void *context);
rnc_result rnc_ratchets_public(const rnc_ratchets *store, uint8_t public_key[32]);
/* Records contain private keys and are owner-signed, versioned and endian-stable.
 * Host must provide private storage; format is local, not Python pickle/MessagePack.
 * Import verifies signature, ownership, framing, key bounds and ordering before
 * replacing state. Store storage/capacity are retained. A live store rejects
 * timestamp rollback; reinitialize before restoring an earlier checkpoint. */
rnc_result rnc_ratchets_export(const rnc_ratchets *store, const rnc_identity *owner,
    uint8_t *output, size_t capacity, size_t *written);
rnc_result rnc_ratchets_import(rnc_ratchets *store, const rnc_identity *owner,
    const uint8_t *record, size_t size);
/* The reference's ratchet file (Destination.enable_ratchets): a MessagePack map
 * {"signature": Ed25519 signature by the owner over the packed list, "ratchets":
 * the packed list of the 32 byte private keys, newest first}. The file carries
 * no timestamps: an imported store has every key at time 0 and its next
 * rotation is due at once, as the reference's first announce after a restart.
 * Import verifies the owner's signature and framing before replacing state;
 * RNC_NO_SPACE if the store cannot hold the keys, RNC_AUTH for a wrong owner,
 * a bad signature or a time rollback. unix_seconds is the store's new time. */
rnc_result rnc_ratchets_export_reference(const rnc_ratchets *store,
    const rnc_identity *owner, uint8_t *output, size_t capacity, size_t *written);
rnc_result rnc_ratchets_import_reference(rnc_ratchets *store,
    const rnc_identity *owner, const uint8_t *file, size_t size,
    uint64_t unix_seconds);
/* Encrypted wire tokens use the owner's identity hash as HKDF salt. */
rnc_result rnc_ratchet_encrypt(const rnc_identity *destination,
    const uint8_t ratchet_public[32], const void *data, size_t size,
    rnc_random_fn random, void *context, uint8_t *output, size_t capacity,
    size_t *written);
rnc_result rnc_ratchets_decrypt(const rnc_ratchets *store,
    const rnc_identity *owner, int enforce_ratchets, const uint8_t *token,
    size_t size, uint8_t *output, size_t capacity, size_t *written,
    uint8_t used_ratchet_id[10]);
rnc_result rnc_announce_create_ratchet(const rnc_identity *identity,
    const char *dotted_name, const uint8_t ratchet_public[32],
    const void *app_data, size_t app_size, uint64_t unix_seconds,
    rnc_random_fn random, void *context, rnc_packet *packet);
/* Only signed, ratcheted announces are remembered. Entries bind one destination;
 * clear before rebinding. Older announced timestamps and time rollback fail. */
rnc_result rnc_peer_ratchet_remember(rnc_peer_ratchet *peer,
    const rnc_packet *announce, uint64_t unix_seconds);
rnc_result rnc_peer_ratchet_public(const rnc_peer_ratchet *peer,
    uint64_t unix_seconds, uint8_t public_key[32]);
void rnc_peer_ratchet_clear(rnc_peer_ratchet *peer);

typedef struct rnc_group_key { uint8_t bytes[64]; int valid; } rnc_group_key;
rnc_result rnc_group_generate(rnc_group_key *key, rnc_random_fn random, void *context);
rnc_result rnc_group_import(rnc_group_key *key, const uint8_t bytes[64]);
void rnc_group_clear(rnc_group_key *key);
rnc_result rnc_group_encrypt(const rnc_group_key *key, const void *data,
    size_t size, rnc_random_fn random, void *context, uint8_t *output,
    size_t capacity, size_t *written);
rnc_result rnc_group_decrypt(const rnc_group_key *key, const uint8_t *token,
    size_t size, uint8_t *output, size_t capacity, size_t *written);
rnc_result rnc_plain_destination_hash(const char *dotted_name,
    uint8_t destination[16]);
#ifdef __cplusplus
}
#endif
#endif
