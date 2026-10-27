#ifndef RNC_INTERNAL_H
#define RNC_INTERNAL_H
#include <reticulum_c/rnc_link.h>
#include <reticulum_c/rnc_log.h>
#include <stdio.h>
#define RNC_LINK_IDLE 0
#define RNC_LINK_WAIT_PROOF 1
#define RNC_LINK_WAIT_RTT 2
#define RNC_LINK_RUNNING 3
#define RNC_LINK_DEAD 4
#define RNC_LINK_ATTEMPTS 5u
typedef struct rnc_tx_message {
    int used;
    uint16_t sequence;
    size_t size, attempts;
    uint64_t deadline;
    uint8_t data[RNC_LINK_MAX_MDU], hashes[RNC_LINK_ATTEMPTS][32];
} rnc_tx_message;
typedef struct rnc_rx_message {
    int used;
    uint16_t sequence, type;
    size_t size;
    uint8_t data[RNC_CHANNEL_MAX_MDU];
} rnc_rx_message;
struct rnc_link {
    rnc_random_fn random;
    void *random_context;
    int state, initiator, remote_set;
    rnc_identity ephemeral, peer_signer, remote;
    uint8_t address[16], key[64];
    uint64_t now, started, activity, control, rtt_ms;
    uint64_t outbound, activated, est_timeout, stale_since, data_at;
    size_t est_cost;
    int stale, teardown, est_set;
    size_t last_resource_window;
    uint64_t last_resource_eifr;
    size_t local_mtu, mtu, mdu;
    uint16_t tx_next, rx_next;
    size_t tx_window, tx_limit, tx_min, tx_tier, tx_good;
    int tx_adaptive;
    rnc_tx_message tx[RNC_CHANNEL_TX_MAX];
    rnc_rx_message rx[RNC_CHANNEL_RX_WINDOW];
    size_t head, count;
    rnc_link_event events[RNC_LINK_EVENTS];
};
int rnc_crypto_derive(const uint8_t private_key[32], const uint8_t public_key[32],
    const uint8_t salt[16], uint8_t key[64]);
rnc_result rnc_token_seal(const uint8_t key[64], const void *data, size_t size,
    rnc_random_fn random, void *context, uint8_t *output, size_t capacity, size_t *written);
rnc_result rnc_token_open(const uint8_t key[64], const uint8_t *data, size_t size,
    uint8_t *output, size_t capacity, size_t *written);
/* Caller reserves event space before these internal helpers. */
rnc_link_event *rnc_emit(rnc_link *link, rnc_link_event_type type);
void rnc_emit_packet(rnc_link *link, const rnc_packet *packet);
rnc_result rnc_link_seal(rnc_link *link, uint8_t context, const void *data,
    size_t size, rnc_packet *packet);
void rnc_link_end(rnc_link *link, rnc_result reason, const rnc_packet *last_packet);
rnc_result rnc_channel_receive(rnc_link *link, const rnc_packet *packet,
    const uint8_t *plain, size_t size);
rnc_result rnc_channel_proof(rnc_link *link, const rnc_packet *packet);
rnc_result rnc_channel_tick(rnc_link *link, uint64_t now_ms);
/* Lower-case hex of a hash for log messages (n up to 16 bytes). */
static inline const char *rnc_hex_label(const uint8_t *bytes, size_t n, char out[33]) {
    size_t i;
    for (i = 0; i < n && i < 16; i++)
        (void)snprintf(out + 2 * i, 3, "%02x", bytes[i]);
    return out;
}
#endif
