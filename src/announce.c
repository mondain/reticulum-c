#include <reticulum_c/rnc.h>
#include <openssl/crypto.h>
#include <string.h>

rnc_result rnc_announce_create(const rnc_identity *identity, const char *dotted_name,
    const void *app_data, size_t app_size, uint64_t unix_seconds,
    rnc_random_fn random, void *context, rnc_packet *packet) {
    rnc_packet result = {0}; uint8_t name[10], nonce[16], digest[32], signed_data[RNC_MTU];
    size_t i; rnc_result status;
    if (!identity || !identity->has_private || !random || !packet || (!app_data && app_size) ||
        app_size > 464u-148u || unix_seconds > UINT64_C(0xffffffffff)) return RNC_INVALID;
    status = rnc_destination_hash(dotted_name, identity, name, result.destination);
    if (status != RNC_OK) return status;
    status = random(context, nonce, sizeof(nonce));
    if (status != RNC_OK) return status;
    status = rnc_hash(nonce, sizeof(nonce), digest);
    OPENSSL_cleanse(nonce, sizeof(nonce));
    if (status != RNC_OK) return status;
    result.flags = RNC_ANNOUNCE;
    memcpy(result.data, identity->public_key, 64);
    memcpy(result.data+64, name, 10); memcpy(result.data+74, digest, 5);
    for (i = 0; i < 5; ++i) result.data[83u-i] = (uint8_t)(unix_seconds >> (i*8u));
    memcpy(signed_data, result.destination, 16); memcpy(signed_data+16, result.data, 84);
    if (app_size) memcpy(signed_data+100, app_data, app_size);
    status = rnc_identity_sign(identity, signed_data, 100u+app_size, result.data+84);
    if (status != RNC_OK) return status;
    if (app_size) memcpy(result.data+148, app_data, app_size);
    result.data_size = 148u+app_size;
    *packet = result;
    return RNC_OK;
}

rnc_result rnc_announce_verify(const rnc_packet *packet, rnc_announce *announce) {
    rnc_announce result = {0}; uint8_t signed_data[RNC_MTU], material[26], digest[32];
    size_t prefix, signature_offset, header; rnc_result status;
    if (!packet || !announce) return RNC_INVALID;
    if (packet->flags & 0x80u) return RNC_UNSUPPORTED;
    if ((packet->flags & 0x0fu) != RNC_ANNOUNCE ||
        (packet->context != 0 && packet->context != 11)) return RNC_PROTOCOL;
    header = packet->flags & 0x40u ? 35u : 19u;
    result.has_ratchet = (packet->flags & 0x20u) != 0;
    prefix = result.has_ratchet ? 180u : 148u;
    if (packet->data_size < prefix || packet->data_size > RNC_MTU-header) return RNC_PROTOCOL;
    signature_offset = prefix-64u;
    result.app_size = packet->data_size-prefix;
    status = rnc_identity_from_public(&result.identity, packet->data);
    if (status != RNC_OK) return status;
    memcpy(result.destination, packet->destination, 16);
    memcpy(result.name_hash, packet->data+64, 10); memcpy(result.random_hash, packet->data+74, 10);
    if (result.has_ratchet) memcpy(result.ratchet, packet->data+84, 32);
    memcpy(material, result.name_hash, 10); memcpy(material+10, result.identity.hash, 16);
    if (rnc_hash(material, sizeof(material), digest) != RNC_OK) return RNC_CRYPTO;
    if (CRYPTO_memcmp(packet->destination, digest, 16)) return RNC_AUTH;
    memcpy(signed_data, packet->destination, 16);
    memcpy(signed_data+16, packet->data, signature_offset);
    memcpy(signed_data+16+signature_offset, packet->data+prefix, result.app_size);
    status = rnc_identity_verify(&result.identity, signed_data,
        16u+signature_offset+result.app_size, packet->data+signature_offset);
    if (status != RNC_OK) return status;
    memcpy(result.app_data, packet->data+prefix, result.app_size);
    *announce = result;
    return RNC_OK;
}

int rnc_announce_matches_aspect(const rnc_announce *announce, const char *aspect) {
    uint8_t name[RNC_NAME_HASH_SIZE], destination[16];
    if (!announce || !aspect || !*aspect)
        return 0;
    if (rnc_destination_hash(aspect, &announce->identity, name, destination) != RNC_OK)
        return 0;
    return !memcmp(destination, announce->destination, 16);
}
