#ifndef RETICULUM_C_LINK_H
#define RETICULUM_C_LINK_H
#include <reticulum_c/rnc.h>
#ifdef __cplusplus
extern "C" {
#endif

#define RNC_LINK_MDU 431u
#define RNC_LINK_MAX_MDU (((RNC_MAX_MTU - 68u) / 16u) * 16u - 1u)
#define RNC_CHANNEL_MDU (RNC_LINK_MDU - 6u)
#define RNC_CHANNEL_MAX_MDU (RNC_LINK_MAX_MDU - 6u)
#define RNC_LINK_EVENTS 64u
#define RNC_CHANNEL_RX_WINDOW 48u
#define RNC_CHANNEL_TX_WINDOW 2u
#define RNC_CHANNEL_TX_MAX 48u
#define RNC_LINK_TOKEN_MAX (16u * 1024u * 1024u)
#define RNC_RESOURCE_SDU 464u
#define RNC_RESOURCE_MAX_SDU (RNC_MAX_MTU - 36u)

typedef struct rnc_link rnc_link;
typedef enum rnc_link_event_type {
    RNC_LINK_SEND = 1,
    RNC_LINK_ACTIVE,
    RNC_LINK_IDENTIFIED,
    RNC_LINK_MESSAGE,
    RNC_LINK_DELIVERED,
    RNC_LINK_CLOSED,
    RNC_LINK_PACKET,
    RNC_LINK_RESOURCE_PACKET
} rnc_link_event_type;
typedef struct rnc_link_event {
    rnc_link_event_type type;
    rnc_result reason;
    rnc_packet packet; /* SEND: host routes this packet on this link's interface. */
    uint16_t message_type, sequence;
    uint8_t identity_hash[16], context;
    size_t size;
    uint8_t data[RNC_LINK_MAX_MDU];
} rnc_link_event;

/* One transport association per instance; serialize calls and use monotonic
 * milliseconds. RNG/context must outlive the instance. All events own copies.
 * Drain frequently. RNC_AGAIN never commits an operation; drain then retry.
 * Crypto failure requires closing/recreating the instance. No I/O is owned here.
 * MTU defaults to 500; explicitly configure local capacity up to 4096 before
 * opening/accepting. Session negotiation chooses the smaller endpoint capacity.
 * AES-256-CBC is the supported link cipher. Hosts own routing/IFAC/Resources. */
rnc_link *rnc_link_new(rnc_random_fn random, void *context);
void rnc_link_free(rnc_link *link);
/* IDLE-only local MTU limit, 500..RNC_MAX_MTU. Default 500. Packet/Channel
 * limits are getters so applications can use the negotiated payload capacity. */
rnc_result rnc_link_configure_mtu(rnc_link *link, size_t mtu);
size_t rnc_link_mtu(const rnc_link *link);
size_t rnc_link_mdu(const rnc_link *link);
size_t rnc_link_channel_mdu(const rnc_link *link);
/* Initiator: peer must be a previously verified announce. */
rnc_result rnc_link_open(rnc_link *link, const rnc_announce *peer, uint64_t now_ms);
/* Responder: application admits the request before calling accept. */
rnc_result rnc_link_accept(rnc_link *link, const rnc_identity *local, const uint8_t destination[16],
                           const rnc_packet *request, uint64_t now_ms);
rnc_result rnc_link_input(rnc_link *link, const rnc_packet *packet, uint64_t now_ms);
rnc_result rnc_link_identify(rnc_link *link, const rnc_identity *identity, uint64_t now_ms);
rnc_result rnc_link_send(rnc_link *link, uint16_t message_type, const void *data, size_t size,
                         uint64_t now_ms);
/* Configure an empty Channel's send window (1..48). Defaults remain fixed2.
 * Adaptive mode grows on verified receipts, applies RTT-dependent caps and
 * reduces the window on retry. Reconfiguration while messages are pending is
 * rejected with RNC_STATE. These are local policies, not wire negotiation. */
rnc_result rnc_link_configure_channel(rnc_link *link, size_t initial_window, size_t maximum_window,
                                      int adaptive);
size_t rnc_link_channel_window(const rnc_link *link);
size_t rnc_link_channel_pending(const rnc_link *link);
/* Only the standard Buffer system type0xff00 is supported by this method. */
rnc_result rnc_link_send_system(rnc_link *link, uint16_t message_type, const void *data,
                                size_t size, uint64_t now_ms);
/* Normally encrypted Link packets. Application/service contexts supported:
 * 0,2,3,4,6,7,9,10,13. Delivery is not retried by this primitive. Incoming
 * authenticated plaintext is RNC_LINK_PACKET with context/data/size and an
 * original packet copy (for request IDs). Maximum plaintext is rnc_link_mdu(link). */
rnc_result rnc_link_send_packet(rnc_link *link, uint8_t context, const void *data, size_t size,
                                uint64_t now_ms);
/* Like send_packet, also returns the exact encrypted packet hash on success. */
rnc_result rnc_link_send_packet_hashed(rnc_link *link, uint8_t context, const void *data,
                                       size_t size, uint64_t now_ms, uint8_t hash[32]);
/* Resource-only bypass: DATA context1, DATA context8 (32-byte cache request),
 * and PROOF context5 (64-byte resource proof). Parts carry already
 * encrypted whole-stream bytes. RNC_LINK_RESOURCE_PACKET exposes raw bytes in
 * event.packet, NOT event.data. They are unauthenticated until the resource
 * engine checks the complete transfer; they do not refresh link liveness. */
rnc_result rnc_link_send_resource_packet(rnc_link *link, uint8_t packet_type, uint8_t context,
                                         const void *data, size_t size, uint64_t now_ms);
/* Whole-resource token operations. Caller-owned buffers, active Link required,
 * at most RNC_LINK_TOKEN_MAX plaintext bytes; outputs commit only on success.
 * The temporary allocation is bounded and cleansed, and decryption verifies
 * HMAC before producing any plaintext. Ciphertext overhead is 48 + PKCS7 pad. */
rnc_result rnc_link_encrypt(rnc_link *link, const void *data, size_t size, uint8_t *output,
                            size_t capacity, size_t *written);
rnc_result rnc_link_decrypt(rnc_link *link, const uint8_t *data, size_t size, uint8_t *output,
                            size_t capacity, size_t *written);
rnc_result rnc_link_tick(rnc_link *link, uint64_t now_ms);
/* Discards unpolled events/pending data, queues graceful close when active,
 * clears session secrets, and emits CLOSED. Free/new to reconnect. */
rnc_result rnc_link_close(rnc_link *link, uint64_t now_ms);
rnc_result rnc_link_poll(rnc_link *link, rnc_link_event *event);
int rnc_link_is_active(const rnc_link *link);
/* Client learns the destination identity after proof. Server learns an
 * initiator identity only after verified LINKIDENTIFY. Public material only. */
rnc_result rnc_link_remote_identity(const rnc_link *link, rnc_identity *identity);
rnc_result rnc_link_address(const rnc_link *link, uint8_t address[16]);

/* Link lifecycle (manual 16.6). Keepalive = RTT * 360/1.75 s clamped to 5..360 s;
 * a link with no inbound traffic for twice that is STALE and is torn down
 * RTT*4 + 5 s later unless traffic arrives. Establishment timeout defaults to
 * 30 s; configure hops/first-hop time before opening for the reference
 * formula first_hop + 6 s * max(1, hops). */
typedef enum rnc_link_status {
    RNC_LINK_STATUS_PENDING = 0, RNC_LINK_STATUS_HANDSHAKE, RNC_LINK_STATUS_ACTIVE,
    RNC_LINK_STATUS_STALE, RNC_LINK_STATUS_CLOSED
} rnc_link_status;
typedef enum rnc_link_teardown {
    RNC_TEARDOWN_NONE = 0, RNC_TEARDOWN_TIMEOUT, RNC_TEARDOWN_INITIATOR_CLOSED,
    RNC_TEARDOWN_DESTINATION_CLOSED
} rnc_link_teardown;
rnc_link_status rnc_link_status_of(const rnc_link *link);
rnc_link_teardown rnc_link_teardown_reason(const rnc_link *link);
rnc_result rnc_link_configure_establishment(rnc_link *link, unsigned hops,
                                            uint64_t first_hop_timeout_ms);
/* RTT measured during establishment; RNC_STATE until the link is active. */
rnc_result rnc_link_rtt(const rnc_link *link, uint64_t *rtt_ms);
uint64_t rnc_link_keepalive_ms(const rnc_link *link);
rnc_result rnc_link_age_ms(const rnc_link *link, uint64_t now_ms, uint64_t *age_ms);
uint64_t rnc_link_no_inbound_ms(const rnc_link *link, uint64_t now_ms);
uint64_t rnc_link_no_outbound_ms(const rnc_link *link, uint64_t now_ms);

#ifdef __cplusplus
}
#endif
#endif
