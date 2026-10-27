#include "internal.h"
#include <float.h>
#include <math.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
_Static_assert(sizeof(double) == 8 && DBL_MANT_DIG == 53,
               "IEEE binary64 required for RTT messages");
_Static_assert(sizeof(float) == 4 && FLT_MANT_DIG == 24, "IEEE binary32 required for RTT messages");

rnc_link *rnc_link_new(rnc_random_fn random, void *context) {
    rnc_link *link;
    if (!random)
        return NULL;
    link = calloc(1, sizeof(*link));
    if (link) {
        link->random = random;
        link->random_context = context;
        link->local_mtu = link->mtu = RNC_MTU;
        link->mdu = RNC_LINK_MDU;
        link->tx_window = link->tx_limit = link->tx_min = link->tx_tier = RNC_CHANNEL_TX_WINDOW;
    }
    return link;
}
static size_t mdu_for_mtu(size_t mtu) { return ((mtu - 68u) / 16u) * 16u - 1u; }
rnc_result rnc_link_configure_mtu(rnc_link *link, size_t mtu) {
    if (!link || mtu < RNC_MTU || mtu > RNC_MAX_MTU)
        return RNC_INVALID;
    if (link->state != RNC_LINK_IDLE)
        return RNC_STATE;
    link->local_mtu = link->mtu = mtu;
    link->mdu = mdu_for_mtu(mtu);
    return RNC_OK;
}
size_t rnc_link_mtu(const rnc_link *link) { return link ? link->mtu : 0; }
size_t rnc_link_mdu(const rnc_link *link) { return link ? link->mdu : 0; }
size_t rnc_link_channel_mdu(const rnc_link *link) { return link ? link->mdu - 6u : 0; }
static void signalling(uint8_t output[3], size_t mtu) {
    output[0] = (uint8_t)(0x20u | ((mtu >> 16) & 0x1fu));
    output[1] = (uint8_t)(mtu >> 8);
    output[2] = (uint8_t)mtu;
}
void rnc_link_free(rnc_link *link) {
    if (link) {
        OPENSSL_cleanse(link, sizeof(*link));
        free(link);
    }
}
rnc_link_event *rnc_emit(rnc_link *link, rnc_link_event_type type) {
    rnc_link_event *event = &link->events[(link->head + link->count) % RNC_LINK_EVENTS];
    memset(event, 0, sizeof(*event));
    event->type = type;
    ++link->count;
    return event;
}
void rnc_emit_packet(rnc_link *link, const rnc_packet *packet) {
    link->outbound = link->now;
    rnc_emit(link, RNC_LINK_SEND)->packet = *packet;
}
rnc_result rnc_link_poll(rnc_link *link, rnc_link_event *event) {
    if (!link || !event)
        return RNC_INVALID;
    if (!link->count)
        return RNC_AGAIN;
    *event = link->events[link->head];
    OPENSSL_cleanse(&link->events[link->head], sizeof(*event));
    link->head = (link->head + 1u) % RNC_LINK_EVENTS;
    --link->count;
    return RNC_OK;
}
int rnc_link_is_active(const rnc_link *link) { return link && link->state == RNC_LINK_RUNNING; }
rnc_result rnc_link_remote_identity(const rnc_link *link, rnc_identity *identity) {
    if (!link || !identity)
        return RNC_INVALID;
    if (!link->remote_set || link->state == RNC_LINK_DEAD)
        return RNC_AGAIN;
    *identity = link->remote;
    return RNC_OK;
}
rnc_result rnc_link_address(const rnc_link *link, uint8_t address[16]) {
    if (!link || !address)
        return RNC_INVALID;
    if (link->state == RNC_LINK_IDLE)
        return RNC_STATE;
    memcpy(address, link->address, 16);
    return RNC_OK;
}
static rnc_result check_packet(const rnc_packet *packet) {
    uint8_t raw[RNC_MAX_MTU];
    size_t written;
    return rnc_packet_encode(packet, raw, sizeof(raw), &written);
}
static rnc_result parameters(const uint8_t *data, size_t size, size_t base, size_t *mtu) {
    if (size == base) {
        *mtu = RNC_MTU;
        return RNC_OK;
    }
    if (size != base + 3u)
        return RNC_PROTOCOL;
    if ((data[base] >> 5) != 1u)
        return RNC_UNSUPPORTED;
    size_t value =
        ((size_t)(data[base] & 0x1fu) << 16) | ((size_t)data[base + 1u] << 8) | data[base + 2u];
    if (value < RNC_MTU)
        return RNC_UNSUPPORTED;
    *mtu = value;
    return RNC_OK;
}
static rnc_result request_hash(const rnc_packet *packet, uint8_t address[16]) {
    rnc_packet keys = *packet;
    uint8_t hash[32];
    rnc_result result;
    keys.data_size = 64;
    result = rnc_packet_hash(&keys, hash);
    if (result == RNC_OK)
        memcpy(address, hash, 16);
    return result;
}
rnc_result rnc_link_seal(rnc_link *link, uint8_t context, const void *data, size_t size,
                         rnc_packet *packet) {
    rnc_packet result = {0};
    rnc_result status;
    result.flags = 12;
    result.context = context;
    memcpy(result.destination, link->address, 16);
    if (size > link->mdu)
        return RNC_INVALID;
    status = rnc_token_seal(link->key, data, size, link->random, link->random_context, result.data,
                            sizeof(result.data), &result.data_size);
    if (status == RNC_OK)
        *packet = result;
    return status;
}
static int service_context(uint8_t context) {
    return context == 0 || (context >= 2 && context <= 4) ||
           ((context >= 6 && context <= 10) && context != 8) || context == 13;
}
rnc_result rnc_link_send_packet_hashed(rnc_link *link, uint8_t context, const void *data,
                                       size_t size, uint64_t now, uint8_t hash[32]) {
    rnc_packet packet;
    rnc_result result;
    uint8_t digest[32];
    if (!link || (!data && size) || !service_context(context) || size > rnc_link_mdu(link) ||
        now < link->now)
        return RNC_INVALID;
    if (!rnc_link_is_active(link))
        return RNC_STATE;
    if (link->count == RNC_LINK_EVENTS)
        return RNC_AGAIN;
    result = rnc_link_seal(link, context, data, size, &packet);
    if (result == RNC_OK && hash)
        result = rnc_packet_hash(&packet, digest);
    if (result == RNC_OK) {
        rnc_emit_packet(link, &packet);
        link->now = now;
        if (hash)
            memcpy(hash, digest, 32);
    }
    return result;
}
rnc_result rnc_link_send_packet(rnc_link *link, uint8_t context, const void *data, size_t size,
                                uint64_t now) {
    return rnc_link_send_packet_hashed(link, context, data, size, now, NULL);
}
rnc_result rnc_link_send_resource_packet(rnc_link *link, uint8_t packet_type, uint8_t context,
                                         const void *data, size_t size, uint64_t now) {
    rnc_packet packet = {0};
    if (!link || !data || !size || size > rnc_link_mtu(link) - 36u || now < link->now ||
        !((packet_type == RNC_DATA && context == 1) ||
          (packet_type == RNC_DATA && context == 8 && size == 32) ||
          (packet_type == RNC_PROOF && context == 5 && size == 64)))
        return RNC_INVALID;
    if (!rnc_link_is_active(link))
        return RNC_STATE;
    if (link->count == RNC_LINK_EVENTS)
        return RNC_AGAIN;
    packet.flags = (uint8_t)(12u | packet_type);
    packet.context = context;
    memcpy(packet.destination, link->address, 16);
    packet.data_size = size;
    memcpy(packet.data, data, size);
    rnc_emit_packet(link, &packet);
    link->now = now;
    return RNC_OK;
}
static int token_mac(const uint8_t key[32], const uint8_t *data, size_t size, uint8_t tag[32]) {
    size_t written = 0;
    return EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, key, 32, data, size, tag, 32, &written) !=
               NULL &&
           written == 32;
}
rnc_result rnc_link_encrypt(rnc_link *link, const void *data, size_t size, uint8_t *output,
                            size_t capacity, size_t *written) {
    uint8_t *token = NULL;
    size_t needed;
    EVP_CIPHER_CTX *cipher = NULL;
    int n = 0, final = 0;
    rnc_result result;
    if (written)
        *written = 0;
    if (!link || (!data && size) || !output || !written || size > RNC_LINK_TOKEN_MAX)
        return RNC_INVALID;
    if (!rnc_link_is_active(link))
        return RNC_STATE;
    needed = 48u + (size / 16u + 1u) * 16u;
    if (capacity < needed)
        return RNC_NO_SPACE;
    token = OPENSSL_malloc(needed);
    if (!token)
        return RNC_NO_SPACE;
    result = link->random(link->random_context, token, 16);
    if (result != RNC_OK)
        goto done;
    result = RNC_CRYPTO;
    cipher = EVP_CIPHER_CTX_new();
    if (!cipher ||
        EVP_EncryptInit_ex(cipher, EVP_aes_256_cbc(), NULL, link->key + 32, token) != 1 ||
        EVP_EncryptUpdate(cipher, token + 16, &n, data, (int)size) != 1 ||
        EVP_EncryptFinal_ex(cipher, token + 16 + n, &final) != 1 ||
        (size_t)(n + final) != needed - 48u ||
        !token_mac(link->key, token, needed - 32u, token + needed - 32u))
        goto done;
    memcpy(output, token, needed);
    *written = needed;
    result = RNC_OK;
done:
    EVP_CIPHER_CTX_free(cipher);
    OPENSSL_clear_free(token, needed);
    return result;
}
rnc_result rnc_link_decrypt(rnc_link *link, const uint8_t *data, size_t size, uint8_t *output,
                            size_t capacity, size_t *written) {
    uint8_t tag[32], *plain = NULL;
    size_t encrypted;
    EVP_CIPHER_CTX *cipher = NULL;
    int n = 0, final = 0;
    rnc_result result = RNC_AUTH;
    if (written)
        *written = 0;
    if (!link || !data || !output || !written)
        return RNC_INVALID;
    if (!rnc_link_is_active(link))
        return RNC_STATE;
    if (size < 64 || size > RNC_LINK_TOKEN_MAX + 64u || (size - 48u) % 16u)
        return RNC_AUTH;
    if (!token_mac(link->key, data, size - 32u, tag) || CRYPTO_memcmp(tag, data + size - 32u, 32))
        goto done;
    encrypted = size - 48u;
    plain = OPENSSL_malloc(encrypted);
    if (!plain) {
        result = RNC_NO_SPACE;
        goto done;
    }
    cipher = EVP_CIPHER_CTX_new();
    if (!cipher || EVP_DecryptInit_ex(cipher, EVP_aes_256_cbc(), NULL, link->key + 32, data) != 1) {
        result = RNC_CRYPTO;
        goto done;
    }
    if (EVP_DecryptUpdate(cipher, plain, &n, data + 16, (int)encrypted) != 1 ||
        EVP_DecryptFinal_ex(cipher, plain + n, &final) != 1)
        goto done;
    if (capacity < (size_t)(n + final)) {
        result = RNC_NO_SPACE;
        goto done;
    }
    memcpy(output, plain, (size_t)(n + final));
    *written = (size_t)(n + final);
    result = RNC_OK;
done:
    EVP_CIPHER_CTX_free(cipher);
    OPENSSL_clear_free(plain, plain ? size - 48u : 0);
    OPENSSL_cleanse(tag, sizeof(tag));
    return result;
}
static void begin(rnc_link *link, int state, int initiator, uint64_t now) {
    link->state = state;
    link->initiator = initiator;
    link->started = link->now = link->activity = link->control = now;
    link->outbound = now;
    link->activated = 0;
    if (!link->est_set)
        link->est_timeout = 30000u;
    link->stale = link->teardown = 0;
    link->rtt_ms = 1;
}
rnc_result rnc_link_open(rnc_link *link, const rnc_announce *peer, uint64_t now) {
    rnc_identity ephemeral = {0};
    rnc_packet packet = {0};
    uint8_t address[16];
    rnc_result result;
    if (!link || !peer)
        return RNC_INVALID;
    if (link->state != RNC_LINK_IDLE)
        return RNC_STATE;
    result = rnc_identity_generate(&ephemeral, link->random, link->random_context);
    if (result != RNC_OK)
        goto done;
    packet.flags = 2;
    packet.data_size = 67;
    memcpy(packet.destination, peer->destination, 16);
    memcpy(packet.data, ephemeral.public_key, 64);
    signalling(packet.data + 64, link->local_mtu);
    result = request_hash(&packet, address);
    if (result != RNC_OK)
        goto done;
    if (rnc_identity_from_public(&link->remote, peer->identity.public_key) != RNC_OK) {
        result = RNC_CRYPTO;
        goto done;
    }
    link->ephemeral = ephemeral;
    memcpy(link->address, address, 16);
    begin(link, RNC_LINK_WAIT_PROOF, 1, now);
    rnc_emit_packet(link, &packet);
done:
    rnc_identity_clear(&ephemeral);
    return result;
}
rnc_result rnc_link_accept(rnc_link *link, const rnc_identity *local, const uint8_t destination[16],
                           const rnc_packet *request, uint64_t now) {
    rnc_identity ephemeral = {0}, peer = {0};
    rnc_packet proof = {0};
    uint8_t private_key[64], address[16], key[64], signed_data[83];
    rnc_result result;
    size_t mtu;
    if (!link || !local || !local->has_private || !destination || !request)
        return RNC_INVALID;
    if (link->state != RNC_LINK_IDLE)
        return RNC_STATE;
    result = check_packet(request);
    if (result != RNC_OK)
        return result;
    if ((request->flags & 15u) != 2 || request->context ||
        memcmp(request->destination, destination, 16))
        return RNC_PROTOCOL;
    result = parameters(request->data, request->data_size, 64, &mtu);
    if (result != RNC_OK)
        return result;
    if (mtu > link->local_mtu)
        mtu = link->local_mtu;
    result = request_hash(request, address);
    if (result != RNC_OK)
        return result;
    result = link->random(link->random_context, private_key, 32);
    if (result != RNC_OK)
        goto done;
    memcpy(private_key + 32, local->private_key + 32, 32);
    result = rnc_identity_from_private(&ephemeral, private_key);
    if (result != RNC_OK)
        goto done;
    result = rnc_identity_from_public(&peer, request->data);
    if (result != RNC_OK)
        goto done;
    result = RNC_CRYPTO;
    if (!rnc_crypto_derive(ephemeral.private_key, peer.public_key, address, key))
        goto done;
    proof.flags = 15;
    proof.context = 255;
    proof.data_size = 99;
    memcpy(proof.destination, address, 16);
    memcpy(proof.data + 64, ephemeral.public_key, 32);
    signalling(proof.data + 96, mtu);
    memcpy(signed_data, address, 16);
    memcpy(signed_data + 16, ephemeral.public_key, 64);
    memcpy(signed_data + 80, proof.data + 96, 3);
    result = rnc_identity_sign(local, signed_data, sizeof(signed_data), proof.data);
    if (result != RNC_OK)
        goto done;
    link->ephemeral = ephemeral;
    link->peer_signer = peer;
    memcpy(link->address, address, 16);
    memcpy(link->key, key, 64);
    link->mtu = mtu;
    link->mdu = mdu_for_mtu(mtu);
    begin(link, RNC_LINK_WAIT_RTT, 0, now);
    rnc_emit_packet(link, &proof);
done:
    OPENSSL_cleanse(private_key, sizeof(private_key));
    OPENSSL_cleanse(key, sizeof(key));
    rnc_identity_clear(&ephemeral);
    return result;
}
static void float_pack(double seconds, uint8_t output[9]) {
    uint64_t bits;
    size_t i;
    memcpy(&bits, &seconds, 8);
    output[0] = 0xcb;
    for (i = 0; i < 8; ++i)
        output[8u - i] = (uint8_t)(bits >> (i * 8u));
}
static int float_unpack(const uint8_t *data, size_t size, double *seconds) {
    size_t i;
    if (size == 9 && data[0] == 0xcb) {
        uint64_t bits = 0;
        for (i = 1; i < 9; ++i)
            bits = (bits << 8) | data[i];
        memcpy(seconds, &bits, 8);
    } else if (size == 5 && data[0] == 0xca) {
        uint32_t bits = 0;
        float value;
        for (i = 1; i < 5; ++i)
            bits = (bits << 8) | data[i];
        memcpy(&value, &bits, 4);
        *seconds = value;
    } else if (size == 1 && data[0] < 128)
        *seconds = data[0];
    else
        return 0;
    return isfinite(*seconds) && *seconds >= 0 && *seconds <= 360;
}
static rnc_result accept_proof(rnc_link *link, const rnc_packet *packet, uint64_t now) {
    uint8_t signed_data[83], peer_public[64], key[64], rtt[9];
    size_t signed_size, mtu;
    rnc_identity peer;
    rnc_packet reply;
    rnc_result result;
    result = parameters(packet->data, packet->data_size, 96, &mtu);
    if (result != RNC_OK)
        return result;
    if (mtu > link->local_mtu)
        return RNC_UNSUPPORTED;
    memcpy(peer_public, packet->data + 64, 32);
    memcpy(peer_public + 32, link->remote.public_key + 32, 32);
    memcpy(signed_data, link->address, 16);
    memcpy(signed_data + 16, peer_public, 64);
    signed_size = 80;
    if (packet->data_size == 99) {
        memcpy(signed_data + 80, packet->data + 96, 3);
        signed_size = 83;
    }
    result = rnc_identity_verify(&link->remote, signed_data, signed_size, packet->data);
    if (result != RNC_OK)
        return result;
    if (!rnc_crypto_derive(link->ephemeral.private_key, peer_public, link->address, key))
        return RNC_CRYPTO;
    result = rnc_identity_from_public(&peer, peer_public);
    if (result != RNC_OK)
        goto done;
    float_pack((double)(now - link->started ? now - link->started : 1u) / 1000.0, rtt);
    memset(&reply, 0, sizeof(reply));
    reply.flags = 12;
    reply.context = 254;
    memcpy(reply.destination, link->address, 16);
    result = rnc_token_seal(key, rtt, sizeof(rtt), link->random, link->random_context, reply.data,
                            sizeof(reply.data), &reply.data_size);
    if (result != RNC_OK)
        goto done;
    memcpy(link->key, key, 64);
    link->peer_signer = peer;
    link->mtu = mtu;
    link->mdu = mdu_for_mtu(mtu);
    link->remote_set = 1;
    link->state = RNC_LINK_RUNNING;
    link->activated = now;
    link->rtt_ms = now - link->started ? now - link->started : 1u;
    rnc_emit_packet(link, &reply);
    rnc_emit(link, RNC_LINK_ACTIVE);
    memcpy(rnc_emit(link, RNC_LINK_IDENTIFIED)->identity_hash, link->remote.hash, 16);
done:
    OPENSSL_cleanse(key, sizeof(key));
    return result;
}
void rnc_link_end(rnc_link *link, rnc_result reason, const rnc_packet *last_packet) {
    OPENSSL_cleanse(link->events, sizeof(link->events));
    link->head = link->count = 0;
    rnc_identity_clear(&link->ephemeral);
    OPENSSL_cleanse(link->key, sizeof(link->key));
    OPENSSL_cleanse(link->tx, sizeof(link->tx));
    OPENSSL_cleanse(link->rx, sizeof(link->rx));
    link->state = RNC_LINK_DEAD;
    link->remote_set = 0;
    if (last_packet)
        rnc_emit_packet(link, last_packet);
    rnc_emit(link, RNC_LINK_CLOSED)->reason = reason;
}
rnc_result rnc_link_input(rnc_link *link, const rnc_packet *packet, uint64_t now) {
    uint8_t plain[RNC_LINK_MAX_MDU];
    size_t size = 0, required = 3;
    rnc_result result;
    if (!link || !packet || now < link->now)
        return RNC_INVALID;
    if (link->state == RNC_LINK_IDLE || link->state == RNC_LINK_DEAD)
        return RNC_STATE;
    result = check_packet(packet);
    if (result != RNC_OK)
        return result;
    if (memcmp(packet->destination, link->address, 16))
        return RNC_PROTOCOL;
    if (packet->data_size + (packet->flags & 0x40u ? 35u : 19u) > link->mtu)
        return RNC_PROTOCOL;
    if ((packet->flags & 15u) == 12 && packet->context == 14)
        required = RNC_CHANNEL_RX_WINDOW + 2u;
    if (RNC_LINK_EVENTS - link->count < required)
        return RNC_AGAIN;
    if (link->state == RNC_LINK_RUNNING &&
        (((packet->flags & 15u) == 12 && (packet->context == 1 || packet->context == 8)) ||
         ((packet->flags & 15u) == 15 && packet->context == 5))) {
        if ((packet->context == 8 && packet->data_size != 32) ||
            (packet->context == 5 && packet->data_size != 64) ||
            (packet->context == 1 && packet->data_size > link->mtu - 36u))
            return RNC_PROTOCOL;
        rnc_link_event *event = rnc_emit(link, RNC_LINK_RESOURCE_PACKET);
        event->packet = *packet;
        event->context = packet->context;
        event->size = packet->data_size;
        link->now = now;
        return RNC_OK; /* Resource engine authenticates only the complete stream. */
    }
    if (link->state == RNC_LINK_WAIT_PROOF) {
        if ((packet->flags & 15u) != 15 || packet->context != 255)
            return RNC_STATE;
        result = accept_proof(link, packet, now);
    } else if ((packet->flags & 15u) == 15 && packet->context == 0 &&
               link->state == RNC_LINK_RUNNING) {
        result = rnc_channel_proof(link, packet);
    } else if ((packet->flags & 15u) == 12) {
        if (packet->context == 250 && link->state == RNC_LINK_RUNNING) {
            if (packet->data_size != 1)
                return RNC_PROTOCOL;
            if ((!link->initiator && packet->data[0] == 0xff) ||
                (link->initiator && packet->data[0] == 0xfe)) {
                if (!link->initiator) {
                    rnc_packet reply = *packet;
                    reply.hops = 0;
                    reply.flags = 12;
                    reply.data[0] = 0xfe;
                    rnc_emit_packet(link, &reply);
                }
                /* Canonical keepalives establish liveness, not peer authentication. */
                link->now = link->activity = now;
                link->stale = 0;
                return RNC_OK;
            }
            return RNC_PROTOCOL;
        }
        result =
            rnc_token_open(link->key, packet->data, packet->data_size, plain, sizeof(plain), &size);
        if (result != RNC_OK)
            return result;
        if (size > link->mdu) {
            OPENSSL_cleanse(plain, sizeof(plain));
            return RNC_PROTOCOL;
        }
        if (packet->context == 254 && !link->initiator && link->state == RNC_LINK_WAIT_RTT) {
            double seconds;
            if (!float_unpack(plain, size, &seconds))
                result = RNC_PROTOCOL;
            else {
                link->rtt_ms = (uint64_t)(seconds * 1000.0);
                if (link->rtt_ms < now - link->started)
                    link->rtt_ms = now - link->started;
                if (!link->rtt_ms)
                    link->rtt_ms = 1;
                link->state = RNC_LINK_RUNNING;
                link->activated = now;
                rnc_emit(link, RNC_LINK_ACTIVE);
                result = RNC_OK;
            }
        } else if (packet->context == 251 && !link->initiator) {
            rnc_identity remote;
            uint8_t signed_data[80];
            if (size != 128)
                result = RNC_PROTOCOL;
            else {
                result = rnc_identity_from_public(&remote, plain);
                memcpy(signed_data, link->address, 16);
                memcpy(signed_data + 16, plain, 64);
                if (result == RNC_OK)
                    result = rnc_identity_verify(&remote, signed_data, 80, plain + 64);
                if (result == RNC_OK && link->remote_set &&
                    memcmp(remote.hash, link->remote.hash, 16))
                    result = RNC_AUTH;
                if (result == RNC_OK && !link->remote_set) {
                    link->remote = remote;
                    link->remote_set = 1;
                    memcpy(rnc_emit(link, RNC_LINK_IDENTIFIED)->identity_hash, remote.hash, 16);
                }
            }
        } else if (packet->context == 252) {
            if (size != 16 || CRYPTO_memcmp(plain, link->address, 16))
                result = RNC_AUTH;
            else {
                link->teardown = link->initiator ? RNC_TEARDOWN_DESTINATION_CLOSED
                                                 : RNC_TEARDOWN_INITIATOR_CLOSED;
                rnc_link_end(link, RNC_OK, NULL);
                result = RNC_OK;
            }
        } else if (packet->context == 14 && link->state == RNC_LINK_RUNNING) {
            result = rnc_channel_receive(link, packet, plain, size);
        } else if (link->state == RNC_LINK_RUNNING && service_context(packet->context)) {
            rnc_link_event *event = rnc_emit(link, RNC_LINK_PACKET);
            event->context = packet->context;
            event->size = size;
            event->packet = *packet;
            memcpy(event->data, plain, size);
            result = RNC_OK;
        } else
            result = RNC_UNSUPPORTED;
    } else
        result = RNC_PROTOCOL;
    OPENSSL_cleanse(plain, sizeof(plain));
    if (result == RNC_OK) {
        link->now = link->activity = now;
        link->stale = 0;
    }
    return result;
}
rnc_result rnc_link_identify(rnc_link *link, const rnc_identity *identity, uint64_t now) {
    uint8_t signed_data[80], plain[128];
    rnc_packet packet;
    rnc_result result;
    if (!link || !identity || !identity->has_private || now < link->now)
        return RNC_INVALID;
    if (link->state != RNC_LINK_RUNNING || !link->initiator)
        return RNC_STATE;
    if (link->count == RNC_LINK_EVENTS)
        return RNC_AGAIN;
    memcpy(signed_data, link->address, 16);
    memcpy(signed_data + 16, identity->public_key, 64);
    memcpy(plain, identity->public_key, 64);
    result = rnc_identity_sign(identity, signed_data, sizeof(signed_data), plain + 64);
    if (result == RNC_OK)
        result = rnc_link_seal(link, 251, plain, sizeof(plain), &packet);
    if (result == RNC_OK) {
        rnc_emit_packet(link, &packet);
        link->now = now;
    }
    OPENSSL_cleanse(plain, sizeof(plain));
    return result;
}
uint64_t rnc_link_keepalive_ms(const rnc_link *link) {
    uint64_t keepalive;
    if (!link || link->state != RNC_LINK_RUNNING)
        return 360000u;
    keepalive = link->rtt_ms > 360000u ? 360000u : link->rtt_ms * 360000u / 1750u;
    return keepalive < 5000u ? 5000u : keepalive > 360000u ? 360000u : keepalive;
}
rnc_result rnc_link_tick(rnc_link *link, uint64_t now) {
    rnc_result result;
    uint64_t keepalive;
    if (!link || now < link->now)
        return RNC_INVALID;
    if (link->state == RNC_LINK_IDLE || link->state == RNC_LINK_DEAD)
        return RNC_OK;
    if (link->state != RNC_LINK_RUNNING && now - link->started >= link->est_timeout) {
        link->teardown = RNC_TEARDOWN_TIMEOUT;
        rnc_link_end(link, RNC_TIMEOUT, NULL);
        link->now = now;
        return RNC_OK;
    }
    if (link->state != RNC_LINK_RUNNING) {
        link->now = now;
        return RNC_OK;
    }
    if (RNC_LINK_EVENTS - link->count < 2)
        return RNC_AGAIN;
    result = rnc_channel_tick(link, now);
    if (result != RNC_OK)
        return result;
    if (link->state != RNC_LINK_RUNNING)
        return RNC_OK;
    keepalive = rnc_link_keepalive_ms(link);
    if (link->stale) {
        if (now - link->stale_since >= link->rtt_ms * 4u + 5000u) {
            rnc_packet packet;
            link->now = now;
            if (rnc_link_seal(link, 252, link->address, 16, &packet) != RNC_OK)
                packet.data_size = 0;
            link->teardown = RNC_TEARDOWN_TIMEOUT;
            rnc_link_end(link, RNC_TIMEOUT, packet.data_size ? &packet : NULL);
            return RNC_OK;
        }
    } else if (now - link->activity >= keepalive || now - link->outbound >= keepalive) {
        if (link->initiator && now - link->control >= keepalive) {
            rnc_packet packet = {0};
            packet.flags = 12;
            packet.context = 250;
            packet.data_size = 1;
            packet.data[0] = 0xff;
            memcpy(packet.destination, link->address, 16);
            link->now = now;
            rnc_emit_packet(link, &packet);
            link->control = now;
        }
        if (now - link->activity >= 2u * keepalive) {
            link->stale = 1;
            link->stale_since = now;
        }
    }
    link->now = now;
    return RNC_OK;
}
rnc_link_status rnc_link_status_of(const rnc_link *link) {
    if (!link)
        return RNC_LINK_STATUS_CLOSED;
    switch (link->state) {
    case RNC_LINK_WAIT_RTT: return RNC_LINK_STATUS_HANDSHAKE;
    case RNC_LINK_RUNNING: return link->stale ? RNC_LINK_STATUS_STALE : RNC_LINK_STATUS_ACTIVE;
    case RNC_LINK_DEAD: return RNC_LINK_STATUS_CLOSED;
    default: return RNC_LINK_STATUS_PENDING;
    }
}
rnc_link_teardown rnc_link_teardown_reason(const rnc_link *link) {
    return link ? (rnc_link_teardown)link->teardown : RNC_TEARDOWN_NONE;
}
rnc_result rnc_link_configure_establishment(rnc_link *link, unsigned hops,
                                            uint64_t first_hop_timeout_ms) {
    if (!link || link->state != RNC_LINK_IDLE || hops > 128u ||
        first_hop_timeout_ms > 600000u)
        return RNC_INVALID;
    link->est_timeout = first_hop_timeout_ms + 6000u * (hops ? hops : 1u);
    link->est_set = 1;
    return RNC_OK;
}
rnc_result rnc_link_rtt(const rnc_link *link, uint64_t *rtt_ms) {
    if (!link || !rtt_ms)
        return RNC_INVALID;
    if (link->state != RNC_LINK_RUNNING)
        return RNC_STATE;
    *rtt_ms = link->rtt_ms;
    return RNC_OK;
}
rnc_result rnc_link_age_ms(const rnc_link *link, uint64_t now, uint64_t *age) {
    if (!link || !age)
        return RNC_INVALID;
    if (link->state != RNC_LINK_RUNNING || now < link->activated)
        return RNC_STATE;
    *age = now - link->activated;
    return RNC_OK;
}
uint64_t rnc_link_no_inbound_ms(const rnc_link *link, uint64_t now) {
    return link && now >= link->activity ? now - link->activity : 0;
}
uint64_t rnc_link_no_outbound_ms(const rnc_link *link, uint64_t now) {
    return link && now >= link->outbound ? now - link->outbound : 0;
}
rnc_result rnc_link_close(rnc_link *link, uint64_t now) {
    rnc_packet packet;
    rnc_result result;
    if (!link || now < link->now)
        return RNC_INVALID;
    if (link->state == RNC_LINK_DEAD)
        return RNC_OK;
    link->teardown = link->initiator ? RNC_TEARDOWN_INITIATOR_CLOSED
                                     : RNC_TEARDOWN_DESTINATION_CLOSED;
    if (link->state == RNC_LINK_RUNNING || link->state == RNC_LINK_WAIT_RTT) {
        result = rnc_link_seal(link, 252, link->address, 16, &packet);
        if (result != RNC_OK)
            return result;
        rnc_link_end(link, RNC_OK, &packet);
    } else
        rnc_link_end(link, RNC_OK, NULL);
    link->now = now;
    return RNC_OK;
}

size_t rnc_link_last_resource_window(const rnc_link *link) {
    return link ? link->last_resource_window : 0;
}
void rnc_link_set_last_resource_window(rnc_link *link, size_t window) {
    if (link)
        link->last_resource_window = window;
}
uint64_t rnc_link_last_resource_eifr(const rnc_link *link) {
    return link ? link->last_resource_eifr : 0;
}
void rnc_link_set_last_resource_eifr(rnc_link *link, uint64_t bits_per_second) {
    if (link)
        link->last_resource_eifr = bits_per_second;
}
