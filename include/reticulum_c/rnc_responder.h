#ifndef RETICULUM_C_RESPONDER_H
#define RETICULUM_C_RESPONDER_H
#include <reticulum_c/rnc_node.h>
#include <reticulum_c/rnc_service.h>
#ifdef __cplusplus
extern "C" {
#endif
#define RNC_RESPONDER_LINKS 8u
#define RNC_RESPONDER_DESTINATIONS 4u
#define RNC_RESPONDER_HANDLERS 8u

/* Link-terminating destinations for a node: accepts link requests addressed to
 * registered destinations, runs one request/response service per link and calls
 * the registered handler for each admitted request (the RNS
 * Destination.register_request_handler model). Sans-I/O: the host feeds it
 * LOCAL node events and ticks it; its packets leave through rnc_node_send.
 * Thread-confined; borrows the node and RNG. */
typedef struct rnc_responder rnc_responder;

/* `request` is the complete MessagePack value the client sent; write a complete
 * MessagePack value to `response`. Return RNC_OK with *written set to answer,
 * RNC_AGAIN to send no response (the reference's `None`), anything else is
 * logged by the host and answered with no response. identity_hash is NULL
 * unless the client identified itself on the link. */
typedef rnc_result (*rnc_responder_handler)(void *context, const char *path,
                                            const uint8_t *request,
                                            size_t request_size,
                                            const uint8_t *identity_hash,
                                            uint8_t *response, size_t capacity,
                                            size_t *written);

/* max_value bounds each request and response (0 = 1 MiB). */
rnc_responder *rnc_responder_new(rnc_node *node, size_t max_value,
                                 rnc_random_fn random, void *random_context);
void rnc_responder_free(rnc_responder *responder);
/* Copies the identity (private key required). The destination must already be
 * registered on the node with the same identity, so it is announced and path
 * requests for it are answered. */
rnc_result rnc_responder_add_destination(rnc_responder *responder,
                                         const rnc_identity *identity,
                                         const uint8_t destination[16]);
/* Policy ALLOW_LIST takes up to RNC_SERVICE_ALLOWLIST identity hashes. */
rnc_result rnc_responder_register(rnc_responder *responder,
                                  const uint8_t destination[16],
                                  const char *path, rnc_service_policy policy,
                                  const uint8_t (*allowed)[16],
                                  size_t allowed_count,
                                  rnc_responder_handler handler, void *context);
/* RNC_OK: the event was for a responder link and is consumed. RNC_AGAIN: not
 * ours, handle it elsewhere. Other results: the event was ours but could not be
 * processed (for example RNC_NO_SPACE when all link slots are busy). */
rnc_result rnc_responder_input(rnc_responder *responder,
                               const rnc_node_event *event,
                               uint64_t unix_seconds, uint64_t now_ms);
/* Drives links and services, runs handlers and sends their packets. */
rnc_result rnc_responder_tick(rnc_responder *responder, uint64_t unix_seconds,
                              uint64_t now_ms);
size_t rnc_responder_link_count(const rnc_responder *responder);
#ifdef __cplusplus
}
#endif
#endif
