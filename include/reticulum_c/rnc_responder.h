#ifndef RETICULUM_C_RESPONDER_H
#define RETICULUM_C_RESPONDER_H
#include <reticulum_c/rnc_node.h>
#include <reticulum_c/rnc_service.h>
#ifdef __cplusplus
extern "C" {
#endif
#ifndef RNC_RESPONDER_LINKS
#define RNC_RESPONDER_LINKS 8u
#endif
#ifndef RNC_RESPONDER_DESTINATIONS
#define RNC_RESPONDER_DESTINATIONS 4u
#endif
#ifndef RNC_RESPONDER_HANDLERS
#define RNC_RESPONDER_HANDLERS 24u
#endif

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

/* A handler that may answer with a file (the reference's file-object
 * response): raw `data` plus one encoded MessagePack `metadata` value, sent as a
 * Resource. The buffers belong to the responder; fill them and set the sizes.
 * data_capacity is max_value, metadata_capacity RNC_RESPONDER_METADATA_MAX.
 * Set data_size (and metadata_size) to answer with the file; otherwise the
 * handler answers like a plain one through `response`/`written`. */
#define RNC_RESPONDER_METADATA_MAX 256u
typedef struct rnc_responder_file {
  uint8_t *data;
  size_t data_capacity, data_size;
  uint8_t *metadata;
  size_t metadata_capacity, metadata_size;
} rnc_responder_file;
typedef rnc_result (*rnc_responder_file_handler)(
    void *context, const char *path, const uint8_t *request, size_t request_size,
    const uint8_t *identity_hash, uint8_t *response, size_t capacity,
    size_t *written, rnc_responder_file *file);
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
/* As rnc_responder_register, for a handler that can answer with a file. */
rnc_result rnc_responder_register_file(
    rnc_responder *responder, const uint8_t destination[16], const char *path,
    rnc_service_policy policy, const uint8_t (*allowed)[16],
    size_t allowed_count, rnc_responder_file_handler handler, void *context);
/* The identity (public key only) the caller identified itself with, for the
 * request a handler is running for; RNC_STATE outside a handler or when the
 * caller did not identify. */
rnc_result rnc_responder_request_identity(const rnc_responder *responder,
                                          rnc_identity *identity);
/* The id of the link the request a handler is running for arrived on (to tell
 * links apart, as the reference's link_id argument does); RNC_STATE outside a
 * handler. */
rnc_result rnc_responder_request_link_id(const rnc_responder *responder,
                                         uint8_t link_id[16]);
/* A handler may keep the node serviced while it works (a long subprocess, say)
 * by feeding events to rnc_responder_input and calling rnc_responder_tick from
 * inside the handler: link keepalives and other links' packets keep being
 * processed, but no second handler starts and a link that closes meanwhile is
 * released only after the handler returns. */
/* Answering later. Inside a handler, rnc_responder_defer takes a ticket for the
 * request being handled and gives it `lifetime_ms` (instead of 30 seconds) to
 * be answered; the handler then returns RNC_AGAIN (no response now) and goes on
 * with its work elsewhere, without blocking the node. rnc_responder_reply sends
 * the answer, a complete MessagePack value, whenever it is ready. RNC_STATE
 * when the ticket was used, the link has gone or the request expired. */
typedef struct rnc_responder_ticket {
  uint8_t link_id[16], request_id[16];
  int valid;
} rnc_responder_ticket;
rnc_result rnc_responder_defer(rnc_responder *responder,
                               rnc_responder_ticket *ticket,
                               uint64_t lifetime_ms);
rnc_result rnc_responder_reply(rnc_responder *responder,
                               rnc_responder_ticket *ticket, const void *value,
                               size_t value_size, uint64_t now_ms);
/* Destination.set_max_request_size for every link to the destination, present
 * and future (RNC_SERVICE_NO_LIMIT removes the limit). */
rnc_result rnc_responder_set_max_request_size(rnc_responder *responder,
                                              const uint8_t destination[16],
                                              size_t max_size);
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
