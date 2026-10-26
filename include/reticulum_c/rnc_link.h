#ifndef RETICULUM_C_LINK_H
#define RETICULUM_C_LINK_H
#include <reticulum_c/rnc.h>
#ifdef __cplusplus
extern "C" {
#endif

#define RNC_LINK_MDU 431u
#define RNC_CHANNEL_MDU (RNC_LINK_MDU - 6u)
#define RNC_LINK_EVENTS 64u
#define RNC_CHANNEL_RX_WINDOW 48u
#define RNC_CHANNEL_TX_WINDOW 2u

typedef struct rnc_link rnc_link;
typedef enum rnc_link_event_type {
    RNC_LINK_SEND = 1, RNC_LINK_ACTIVE, RNC_LINK_IDENTIFIED,
    RNC_LINK_MESSAGE, RNC_LINK_DELIVERED, RNC_LINK_CLOSED
} rnc_link_event_type;
typedef struct rnc_link_event {
    rnc_link_event_type type;
    rnc_result reason;
    rnc_packet packet; /* SEND: host routes this packet on this link's interface. */
    uint16_t message_type, sequence;
    uint8_t identity_hash[16];
    size_t size;
    uint8_t data[RNC_CHANNEL_MDU];
} rnc_link_event;

/* One transport association per instance; serialize calls and use monotonic
 * milliseconds. RNG/context must outlive the instance. All events own copies.
 * Drain frequently. RNC_AGAIN never commits an operation; drain then retry.
 * Crypto failure requires closing/recreating the instance. No I/O is owned here.
 * This version negotiates MTU 500 and AES-256-CBC. No routing/IFAC/Resources. */
rnc_link *rnc_link_new(rnc_random_fn random, void *context);
void rnc_link_free(rnc_link *link);
/* Initiator: peer must be a previously verified announce. */
rnc_result rnc_link_open(rnc_link *link, const rnc_announce *peer, uint64_t now_ms);
/* Responder: application admits the request before calling accept. */
rnc_result rnc_link_accept(rnc_link *link, const rnc_identity *local,
    const uint8_t destination[16], const rnc_packet *request, uint64_t now_ms);
rnc_result rnc_link_input(rnc_link *link, const rnc_packet *packet, uint64_t now_ms);
rnc_result rnc_link_identify(rnc_link *link, const rnc_identity *identity, uint64_t now_ms);
rnc_result rnc_link_send(rnc_link *link, uint16_t message_type, const void *data,
    size_t size, uint64_t now_ms);
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

#ifdef __cplusplus
}
#endif
#endif
