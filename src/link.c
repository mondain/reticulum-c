#include "internal.h"
#include <openssl/crypto.h>
#include <float.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
_Static_assert(sizeof(double) == 8 && DBL_MANT_DIG == 53, "IEEE binary64 required for RTT messages");
_Static_assert(sizeof(float) == 4 && FLT_MANT_DIG == 24, "IEEE binary32 required for RTT messages");

rnc_link *rnc_link_new(rnc_random_fn random, void *context) {
    rnc_link *link;
    if (!random) return NULL;
    link = calloc(1, sizeof(*link));
    if (link) { link->random = random; link->random_context = context; }
    return link;
}
void rnc_link_free(rnc_link *link) {
    if (link) { OPENSSL_cleanse(link, sizeof(*link)); free(link); }
}
rnc_link_event *rnc_emit(rnc_link *link, rnc_link_event_type type) {
    rnc_link_event *event = &link->events[(link->head+link->count) % RNC_LINK_EVENTS];
    memset(event, 0, sizeof(*event)); event->type = type; ++link->count; return event;
}
void rnc_emit_packet(rnc_link *link, const rnc_packet *packet) {
    rnc_emit(link, RNC_LINK_SEND)->packet = *packet;
}
rnc_result rnc_link_poll(rnc_link *link, rnc_link_event *event) {
    if (!link || !event) return RNC_INVALID;
    if (!link->count) return RNC_AGAIN;
    *event = link->events[link->head];
    OPENSSL_cleanse(&link->events[link->head], sizeof(*event));
    link->head = (link->head+1u) % RNC_LINK_EVENTS; --link->count; return RNC_OK;
}
int rnc_link_is_active(const rnc_link *link) { return link && link->state == RNC_LINK_RUNNING; }
rnc_result rnc_link_remote_identity(const rnc_link *link, rnc_identity *identity) {
    if (!link || !identity) return RNC_INVALID;
    if (!link->remote_set || link->state == RNC_LINK_DEAD) return RNC_AGAIN;
    *identity = link->remote; return RNC_OK;
}
rnc_result rnc_link_address(const rnc_link *link, uint8_t address[16]) {
    if (!link || !address) return RNC_INVALID;
    if (link->state == RNC_LINK_IDLE) return RNC_STATE;
    memcpy(address, link->address, 16); return RNC_OK;
}
static rnc_result check_packet(const rnc_packet *packet) {
    uint8_t raw[RNC_MTU]; size_t written;
    return rnc_packet_encode(packet, raw, sizeof(raw), &written);
}
static rnc_result parameters(const uint8_t *data, size_t size, size_t base) {
    uint32_t mtu;
    if (size == base) return RNC_OK;
    if (size != base+3u) return RNC_PROTOCOL;
    if ((data[base] >> 5) != 1) return RNC_UNSUPPORTED;
    mtu = ((uint32_t)(data[base] & 0x1fu) << 16) | ((uint32_t)data[base+1u] << 8) | data[base+2u];
    return mtu >= RNC_MTU ? RNC_OK : RNC_UNSUPPORTED;
}
static rnc_result request_hash(const rnc_packet *packet, uint8_t address[16]) {
    rnc_packet keys = *packet; uint8_t hash[32]; rnc_result result;
    keys.data_size = 64;
    result = rnc_packet_hash(&keys, hash);
    if (result == RNC_OK) memcpy(address, hash, 16);
    return result;
}
rnc_result rnc_link_seal(rnc_link *link, uint8_t context, const void *data,
    size_t size, rnc_packet *packet) {
    rnc_packet result = {0}; rnc_result status;
    result.flags = 12; result.context = context; memcpy(result.destination, link->address, 16);
    status = rnc_token_seal(link->key, data, size, link->random, link->random_context,
        result.data, sizeof(result.data), &result.data_size);
    if (status == RNC_OK) *packet = result;
    return status;
}
static void begin(rnc_link *link, int state, int initiator, uint64_t now) {
    link->state = state; link->initiator = initiator;
    link->started = link->now = link->activity = link->control = now;
    link->rtt_ms = 1;
}
rnc_result rnc_link_open(rnc_link *link, const rnc_announce *peer, uint64_t now) {
    rnc_identity ephemeral = {0}; rnc_packet packet = {0}; uint8_t address[16]; rnc_result result;
    if (!link || !peer) return RNC_INVALID;
    if (link->state != RNC_LINK_IDLE) return RNC_STATE;
    result = rnc_identity_generate(&ephemeral, link->random, link->random_context);
    if (result != RNC_OK) goto done;
    packet.flags = 2; packet.data_size = 67;
    memcpy(packet.destination, peer->destination, 16); memcpy(packet.data, ephemeral.public_key, 64);
    packet.data[64] = 0x20; packet.data[65] = 1; packet.data[66] = 0xf4;
    result = request_hash(&packet, address);
    if (result != RNC_OK) goto done;
    if (rnc_identity_from_public(&link->remote, peer->identity.public_key) != RNC_OK) { result = RNC_CRYPTO; goto done; }
    link->ephemeral = ephemeral; memcpy(link->address, address, 16);
    begin(link, RNC_LINK_WAIT_PROOF, 1, now); rnc_emit_packet(link, &packet);
done:
    rnc_identity_clear(&ephemeral); return result;
}
rnc_result rnc_link_accept(rnc_link *link, const rnc_identity *local,
    const uint8_t destination[16], const rnc_packet *request, uint64_t now) {
    rnc_identity ephemeral = {0}, peer = {0}; rnc_packet proof = {0};
    uint8_t private_key[64], address[16], key[64], signed_data[83]; rnc_result result;
    if (!link || !local || !local->has_private || !destination || !request) return RNC_INVALID;
    if (link->state != RNC_LINK_IDLE) return RNC_STATE;
    result = check_packet(request);
    if (result != RNC_OK) return result;
    if ((request->flags & 15u) != 2 || request->context || memcmp(request->destination, destination, 16)) return RNC_PROTOCOL;
    result = parameters(request->data, request->data_size, 64);
    if (result != RNC_OK) return result;
    result = request_hash(request, address);
    if (result != RNC_OK) return result;
    result = link->random(link->random_context, private_key, 32);
    if (result != RNC_OK) goto done;
    memcpy(private_key+32, local->private_key+32, 32);
    result = rnc_identity_from_private(&ephemeral, private_key);
    if (result != RNC_OK) goto done;
    result = rnc_identity_from_public(&peer, request->data);
    if (result != RNC_OK) goto done;
    result = RNC_CRYPTO;
    if (!rnc_crypto_derive(ephemeral.private_key, peer.public_key, address, key)) goto done;
    proof.flags = 15; proof.context = 255; proof.data_size = 99;
    memcpy(proof.destination, address, 16); memcpy(proof.data+64, ephemeral.public_key, 32);
    proof.data[96] = 0x20; proof.data[97] = 1; proof.data[98] = 0xf4;
    memcpy(signed_data, address, 16); memcpy(signed_data+16, ephemeral.public_key, 64);
    memcpy(signed_data+80, proof.data+96, 3);
    result = rnc_identity_sign(local, signed_data, sizeof(signed_data), proof.data);
    if (result != RNC_OK) goto done;
    link->ephemeral = ephemeral; link->peer_signer = peer;
    memcpy(link->address, address, 16); memcpy(link->key, key, 64);
    begin(link, RNC_LINK_WAIT_RTT, 0, now); rnc_emit_packet(link, &proof);
done:
    OPENSSL_cleanse(private_key, sizeof(private_key)); OPENSSL_cleanse(key, sizeof(key));
    rnc_identity_clear(&ephemeral); return result;
}
static void float_pack(double seconds, uint8_t output[9]) {
    uint64_t bits; size_t i;
    memcpy(&bits, &seconds, 8); output[0] = 0xcb;
    for (i = 0; i < 8; ++i) output[8u-i] = (uint8_t)(bits >> (i*8u));
}
static int float_unpack(const uint8_t *data, size_t size, double *seconds) {
    size_t i;
    if (size == 9 && data[0] == 0xcb) {
        uint64_t bits = 0; for (i = 1; i < 9; ++i) bits = (bits << 8) | data[i];
        memcpy(seconds, &bits, 8);
    } else if (size == 5 && data[0] == 0xca) {
        uint32_t bits = 0; float value;
        for (i = 1; i < 5; ++i) bits = (bits << 8) | data[i];
        memcpy(&value, &bits, 4); *seconds = value;
    } else if (size == 1 && data[0] < 128) *seconds = data[0];
    else return 0;
    return isfinite(*seconds) && *seconds >= 0 && *seconds <= 360;
}
static rnc_result accept_proof(rnc_link *link, const rnc_packet *packet, uint64_t now) {
    uint8_t signed_data[83], peer_public[64], key[64], rtt[9];
    size_t signed_size; rnc_identity peer; rnc_packet reply; rnc_result result;
    result = parameters(packet->data, packet->data_size, 96);
    if (result != RNC_OK) return result;
    memcpy(peer_public, packet->data+64, 32); memcpy(peer_public+32, link->remote.public_key+32, 32);
    memcpy(signed_data, link->address, 16); memcpy(signed_data+16, peer_public, 64);
    signed_size = 80;
    if (packet->data_size == 99) { memcpy(signed_data+80, packet->data+96, 3); signed_size = 83; }
    result = rnc_identity_verify(&link->remote, signed_data, signed_size, packet->data);
    if (result != RNC_OK) return result;
    if (!rnc_crypto_derive(link->ephemeral.private_key, peer_public, link->address, key)) return RNC_CRYPTO;
    result = rnc_identity_from_public(&peer, peer_public);
    if (result != RNC_OK) goto done;
    float_pack((double)(now-link->started ? now-link->started : 1u)/1000.0, rtt);
    memset(&reply, 0, sizeof(reply)); reply.flags = 12; reply.context = 254;
    memcpy(reply.destination, link->address, 16);
    result = rnc_token_seal(key, rtt, sizeof(rtt), link->random, link->random_context,
        reply.data, sizeof(reply.data), &reply.data_size);
    if (result != RNC_OK) goto done;
    memcpy(link->key, key, 64); link->peer_signer = peer;
    link->remote_set = 1; link->state = RNC_LINK_RUNNING;
    link->rtt_ms = now-link->started ? now-link->started : 1u;
    rnc_emit_packet(link, &reply); rnc_emit(link, RNC_LINK_ACTIVE);
    memcpy(rnc_emit(link, RNC_LINK_IDENTIFIED)->identity_hash, link->remote.hash, 16);
done:
    OPENSSL_cleanse(key, sizeof(key)); return result;
}
void rnc_link_end(rnc_link *link, rnc_result reason, const rnc_packet *last_packet) {
    OPENSSL_cleanse(link->events, sizeof(link->events)); link->head = link->count = 0;
    rnc_identity_clear(&link->ephemeral); OPENSSL_cleanse(link->key, sizeof(link->key));
    OPENSSL_cleanse(link->tx, sizeof(link->tx)); OPENSSL_cleanse(link->rx, sizeof(link->rx));
    link->state = RNC_LINK_DEAD; link->remote_set = 0;
    if (last_packet) rnc_emit_packet(link, last_packet);
    rnc_emit(link, RNC_LINK_CLOSED)->reason = reason;
}
rnc_result rnc_link_input(rnc_link *link, const rnc_packet *packet, uint64_t now) {
    uint8_t plain[RNC_LINK_MDU]; size_t size = 0, required = 3;
    rnc_result result;
    if (!link || !packet || now < link->now) return RNC_INVALID;
    if (link->state == RNC_LINK_IDLE || link->state == RNC_LINK_DEAD) return RNC_STATE;
    result = check_packet(packet); if (result != RNC_OK) return result;
    if (memcmp(packet->destination, link->address, 16)) return RNC_PROTOCOL;
    if ((packet->flags & 15u) == 12 && packet->context == 14) required = RNC_CHANNEL_RX_WINDOW+2u;
    if (RNC_LINK_EVENTS-link->count < required) return RNC_AGAIN;
    if (link->state == RNC_LINK_WAIT_PROOF) {
        if ((packet->flags & 15u) != 15 || packet->context != 255) return RNC_STATE;
        result = accept_proof(link, packet, now);
    } else if ((packet->flags & 15u) == 15 && packet->context == 0 && link->state == RNC_LINK_RUNNING) {
        result = rnc_channel_proof(link, packet);
    } else if ((packet->flags & 15u) == 12) {
        if (packet->context == 250 && link->state == RNC_LINK_RUNNING) {
            if (packet->data_size != 1) return RNC_PROTOCOL;
            if ((!link->initiator && packet->data[0] == 0xff) || (link->initiator && packet->data[0] == 0xfe)) {
                if (!link->initiator) {
                    rnc_packet reply = *packet; reply.hops = 0; reply.flags = 12; reply.data[0] = 0xfe;
                    rnc_emit_packet(link, &reply);
                }
                /* Canonical keepalives establish liveness, not peer authentication. */
                link->now = link->activity = now;
                return RNC_OK;
            }
            return RNC_PROTOCOL;
        }
        result = rnc_token_open(link->key, packet->data, packet->data_size, plain, sizeof(plain), &size);
        if (result != RNC_OK) return result;
        if (packet->context == 254 && !link->initiator && link->state == RNC_LINK_WAIT_RTT) {
            double seconds;
            if (!float_unpack(plain, size, &seconds)) result = RNC_PROTOCOL;
            else {
                link->rtt_ms = (uint64_t)(seconds*1000.0);
                if (link->rtt_ms < now-link->started) link->rtt_ms = now-link->started;
                if (!link->rtt_ms) link->rtt_ms = 1;
                link->state = RNC_LINK_RUNNING; rnc_emit(link, RNC_LINK_ACTIVE); result = RNC_OK;
            }
        } else if (packet->context == 251 && !link->initiator) {
            rnc_identity remote; uint8_t signed_data[80];
            if (size != 128) result = RNC_PROTOCOL;
            else {
                result = rnc_identity_from_public(&remote, plain);
                memcpy(signed_data, link->address, 16); memcpy(signed_data+16, plain, 64);
                if (result == RNC_OK) result = rnc_identity_verify(&remote, signed_data, 80, plain+64);
                if (result == RNC_OK && link->remote_set && memcmp(remote.hash, link->remote.hash, 16)) result = RNC_AUTH;
                if (result == RNC_OK && !link->remote_set) {
                    link->remote = remote; link->remote_set = 1;
                    memcpy(rnc_emit(link, RNC_LINK_IDENTIFIED)->identity_hash, remote.hash, 16);
                }
            }
        } else if (packet->context == 252) {
            if (size != 16 || CRYPTO_memcmp(plain, link->address, 16)) result = RNC_AUTH;
            else { rnc_link_end(link, RNC_OK, NULL); result = RNC_OK; }
        } else if (packet->context == 14 && link->state == RNC_LINK_RUNNING) {
            result = rnc_channel_receive(link, packet, plain, size);
        } else result = RNC_UNSUPPORTED;
    } else result = RNC_PROTOCOL;
    OPENSSL_cleanse(plain, sizeof(plain));
    if (result == RNC_OK) link->now = link->activity = now;
    return result;
}
rnc_result rnc_link_identify(rnc_link *link, const rnc_identity *identity, uint64_t now) {
    uint8_t signed_data[80], plain[128]; rnc_packet packet; rnc_result result;
    if (!link || !identity || !identity->has_private || now < link->now) return RNC_INVALID;
    if (link->state != RNC_LINK_RUNNING || !link->initiator) return RNC_STATE;
    if (link->count == RNC_LINK_EVENTS) return RNC_AGAIN;
    memcpy(signed_data, link->address, 16); memcpy(signed_data+16, identity->public_key, 64);
    memcpy(plain, identity->public_key, 64);
    result = rnc_identity_sign(identity, signed_data, sizeof(signed_data), plain+64);
    if (result == RNC_OK) result = rnc_link_seal(link, 251, plain, sizeof(plain), &packet);
    if (result == RNC_OK) { rnc_emit_packet(link, &packet); link->now = now; }
    OPENSSL_cleanse(plain, sizeof(plain)); return result;
}
rnc_result rnc_link_tick(rnc_link *link, uint64_t now) {
    rnc_result result;
    if (!link || now < link->now) return RNC_INVALID;
    if (link->state == RNC_LINK_IDLE || link->state == RNC_LINK_DEAD) return RNC_OK;
    if ((link->state != RNC_LINK_RUNNING && now-link->started >= 30000u) ||
        (link->state == RNC_LINK_RUNNING && now-link->activity >= 180000u)) {
        rnc_link_end(link, RNC_TIMEOUT, NULL); link->now = now; return RNC_OK;
    }
    if (link->state != RNC_LINK_RUNNING) { link->now = now; return RNC_OK; }
    if (RNC_LINK_EVENTS-link->count < 2) return RNC_AGAIN;
    result = rnc_channel_tick(link, now);
    if (result != RNC_OK) return result;
    if (link->state == RNC_LINK_RUNNING && link->initiator && now-link->control >= 30000u) {
        rnc_packet packet = {0}; packet.flags = 12; packet.context = 250; packet.data_size = 1; packet.data[0] = 0xff;
        memcpy(packet.destination, link->address, 16); rnc_emit_packet(link, &packet); link->control = now;
    }
    link->now = now; return RNC_OK;
}
rnc_result rnc_link_close(rnc_link *link, uint64_t now) {
    rnc_packet packet; rnc_result result;
    if (!link || now < link->now) return RNC_INVALID;
    if (link->state == RNC_LINK_DEAD) return RNC_OK;
    if (link->state == RNC_LINK_RUNNING || link->state == RNC_LINK_WAIT_RTT) {
        result = rnc_link_seal(link, 252, link->address, 16, &packet);
        if (result != RNC_OK) return result;
        rnc_link_end(link, RNC_OK, &packet);
    } else rnc_link_end(link, RNC_OK, NULL);
    link->now = now; return RNC_OK;
}
