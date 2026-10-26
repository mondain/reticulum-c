#include "internal.h"
#include <openssl/crypto.h>
#include <string.h>

static uint16_t read16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] << 8 | p[1]); }
static void write16(uint8_t *p, uint16_t value) { p[0] = (uint8_t)(value >> 8); p[1] = (uint8_t)value; }
static uint64_t retry_delay(const rnc_link *link, size_t attempts) {
    uint64_t base = link->rtt_ms*3u;
    if (base < 250) base = 250;
    if (base > 4000) base = 4000;
    base <<= attempts-1u;
    return base > 30000 ? 30000 : base;
}

rnc_result rnc_link_send(rnc_link *link, uint16_t type, const void *data, size_t size, uint64_t now) {
    rnc_tx_message message = {0}; rnc_packet packet; rnc_result result;
    size_t i;
    if (!link || (!data && size) || size > RNC_CHANNEL_MDU || type >= 0xf000 || now < link->now) return RNC_INVALID;
    if (link->state != RNC_LINK_RUNNING) return RNC_STATE;
    if (link->count == RNC_LINK_EVENTS) return RNC_AGAIN;
    for (i = 0; i < RNC_CHANNEL_TX_WINDOW && link->tx[i].used; ++i) { }
    if (i == RNC_CHANNEL_TX_WINDOW) return RNC_AGAIN;
    message.used = 1; message.sequence = link->tx_next; message.size = size+6u; message.attempts = 1;
    write16(message.data, type); write16(message.data+2, message.sequence); write16(message.data+4, (uint16_t)size);
    if (size) memcpy(message.data+6, data, size);
    result = rnc_link_seal(link, 14, message.data, message.size, &packet);
    if (result != RNC_OK) goto done;
    result = rnc_packet_hash(&packet, message.hashes[0]);
    if (result != RNC_OK) goto done;
    message.deadline = now+retry_delay(link, 1);
    link->tx[i] = message; link->tx_next = (uint16_t)(link->tx_next+1u); link->now = now;
    rnc_emit_packet(link, &packet);
done:
    OPENSSL_cleanse(&message, sizeof(message)); return result;
}

rnc_result rnc_channel_proof(rnc_link *link, const rnc_packet *packet) {
    size_t i, attempt;
    if (packet->data_size != 96) return RNC_PROTOCOL;
    for (i = 0; i < RNC_CHANNEL_TX_WINDOW; ++i) {
        rnc_tx_message *message = &link->tx[i];
        if (!message->used) continue;
        for (attempt = 0; attempt < message->attempts; ++attempt) {
            rnc_result result;
            if (CRYPTO_memcmp(message->hashes[attempt], packet->data, 32)) continue;
            result = rnc_identity_verify(&link->peer_signer, packet->data, 32, packet->data+32);
            if (result != RNC_OK) return result;
            rnc_emit(link, RNC_LINK_DELIVERED)->sequence = message->sequence;
            OPENSSL_cleanse(message, sizeof(*message)); return RNC_OK;
        }
    }
    return RNC_AUTH; /* Unknown/old receipt must not refresh authenticated activity. */
}

rnc_result rnc_channel_receive(rnc_link *link, const rnc_packet *packet,
    const uint8_t *plain, size_t size) {
    uint16_t type, sequence, length, distance; size_t i, empty = RNC_CHANNEL_RX_WINDOW;
    rnc_packet proof = {0}; rnc_result result; rnc_rx_message *existing = NULL;
    if (size < 6) return RNC_PROTOCOL;
    type = read16(plain); sequence = read16(plain+2); length = read16(plain+4);
    if (length != size-6u || length > RNC_CHANNEL_MDU) return RNC_PROTOCOL;
    if (type >= 0xf000) return RNC_UNSUPPORTED;
    distance = (uint16_t)(sequence-link->rx_next);
    if (distance >= RNC_CHANNEL_RX_WINDOW && distance < 32768u) return RNC_PROTOCOL;
    for (i = 0; i < RNC_CHANNEL_RX_WINDOW; ++i) {
        if (link->rx[i].used && link->rx[i].sequence == sequence) existing = &link->rx[i];
        if (!link->rx[i].used) empty = i;
    }
    if (existing && (existing->type != type || existing->size != length || memcmp(existing->data, plain+6, length))) return RNC_PROTOCOL;
    if (!existing && distance < RNC_CHANNEL_RX_WINDOW && empty == RNC_CHANNEL_RX_WINDOW) return RNC_AGAIN;
    proof.flags = 15; proof.data_size = 96; memcpy(proof.destination, link->address, 16);
    result = rnc_packet_hash(packet, proof.data);
    if (result != RNC_OK) return result;
    result = rnc_identity_sign(&link->ephemeral, proof.data, 32, proof.data+32);
    if (result != RNC_OK) return result;
    /* Acknowledge only after authentication, bounds, window and storage checks. */
    rnc_emit_packet(link, &proof);
    if (distance >= 32768u || existing) return RNC_OK;
    existing = &link->rx[empty]; existing->used = 1; existing->type = type;
    existing->sequence = sequence; existing->size = length;
    memcpy(existing->data, plain+6, length);
    for (;;) {
        rnc_link_event *event;
        for (i = 0; i < RNC_CHANNEL_RX_WINDOW; ++i)
            if (link->rx[i].used && link->rx[i].sequence == link->rx_next) break;
        if (i == RNC_CHANNEL_RX_WINDOW) break;
        existing = &link->rx[i]; event = rnc_emit(link, RNC_LINK_MESSAGE);
        event->sequence = existing->sequence; event->message_type = existing->type;
        event->size = existing->size; memcpy(event->data, existing->data, existing->size);
        OPENSSL_cleanse(existing, sizeof(*existing)); link->rx_next = (uint16_t)(link->rx_next+1u);
    }
    return RNC_OK;
}

rnc_result rnc_channel_tick(rnc_link *link, uint64_t now) {
    size_t i;
    for (i = 0; i < RNC_CHANNEL_TX_WINDOW; ++i) {
        rnc_tx_message *message = &link->tx[i]; rnc_packet packet;
        uint8_t hash[32]; rnc_result result;
        if (!message->used || now < message->deadline) continue;
        if (message->attempts == RNC_LINK_ATTEMPTS) { rnc_link_end(link, RNC_TIMEOUT, NULL); return RNC_OK; }
        result = rnc_link_seal(link, 14, message->data, message->size, &packet);
        if (result != RNC_OK) return result;
        result = rnc_packet_hash(&packet, hash);
        if (result != RNC_OK) return result;
        memcpy(message->hashes[message->attempts++], hash, 32);
        message->deadline = now+retry_delay(link, message->attempts);
        rnc_emit_packet(link, &packet); break;
    }
    return RNC_OK;
}
