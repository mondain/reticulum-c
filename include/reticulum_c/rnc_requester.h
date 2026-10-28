#ifndef RETICULUM_C_REQUESTER_H
#define RETICULUM_C_REQUESTER_H
#include <reticulum_c/rnc_node.h>
#include <reticulum_c/rnc_service.h>
#ifdef __cplusplus
extern "C" {
#endif
#ifndef RNC_REQUESTER_JOBS
#define RNC_REQUESTER_JOBS 4u
#endif

/* One-shot request client: for each job, opens a link to a destination the
 * node has a route to, optionally identifies, sends one request, collects the
 * response and closes the link (what a Link.request() client does). Sans-I/O
 * like rnc_responder: feed it LOCAL node events, tick it, poll results. It
 * borrows the node and RNG and is thread-confined. */
typedef struct rnc_requester rnc_requester;
typedef enum rnc_requester_status {
  RNC_REQUESTER_DONE = 1, /* response received */
  RNC_REQUESTER_FAILED    /* link not established, closed, or timed out */
} rnc_requester_status;
typedef struct rnc_requester_result {
  uint32_t tag;
  rnc_requester_status status;
  uint8_t destination[16];
  size_t size; /* response bytes (DONE only) */
  size_t metadata_size; /* metadata of a file response (see poll_file), else 0 */
} rnc_requester_result;

/* max_value bounds each request and response (0 = 1 MiB). */
rnc_requester *rnc_requester_new(rnc_node *node, size_t max_value,
                                 rnc_random_fn random, void *random_context);
void rnc_requester_free(rnc_requester *requester);
/* encoded_value is one complete MessagePack value (0xc0 for none). identify may
 * be NULL; otherwise it needs its private key. timeout_ms covers link set-up
 * and the response. Returns RNC_STATE when the node has no route to the
 * destination (request a path first) and RNC_AGAIN when all jobs are busy
 * (results not yet polled count as busy). */
rnc_result rnc_requester_start(rnc_requester *requester,
                               const uint8_t destination[16],
                               const rnc_identity *identify, const char *path,
                               const void *encoded_value, size_t value_size,
                               uint32_t tag, uint64_t timeout_ms,
                               uint64_t unix_seconds, uint64_t now_ms);
/* RNC_OK: the event belongs to a requester link and is consumed; RNC_AGAIN:
 * not ours. */
rnc_result rnc_requester_input(rnc_requester *requester,
                               const rnc_node_event *event,
                               uint64_t unix_seconds, uint64_t now_ms);
rnc_result rnc_requester_tick(rnc_requester *requester, uint64_t unix_seconds,
                              uint64_t now_ms);
/* RequestReceipt view of the job started with this tag: SENT while the link
 * opens and the request travels, DELIVERED once a Resource-sized request has
 * arrived, RECEIVING with a 0..1 progress while a Resource-sized response
 * arrives, READY (1.0) or FAILED once finished, until the result is polled.
 * RNC_STATE for an unknown tag. */
rnc_result rnc_requester_progress(const rnc_requester *requester, uint32_t tag,
                                  rnc_request_state *state, double *progress);
/* Next finished job; RNC_AGAIN if none. NO_SPACE (nothing consumed) if the
 * response does not fit capacity; *size says how much is needed. */
rnc_result rnc_requester_poll(rnc_requester *requester,
                              rnc_requester_result *result, void *response,
                              size_t capacity);
/* Like rnc_requester_poll, and copies the metadata of a file response (the
 * reference's RequestReceipt.metadata) into `metadata`. NO_SPACE (nothing
 * consumed) if either buffer is too small; result->size and ->metadata_size say
 * what is needed. */
rnc_result rnc_requester_poll_file(rnc_requester *requester,
                                   rnc_requester_result *result, void *response,
                                   size_t capacity, void *metadata,
                                   size_t metadata_capacity);
#ifdef __cplusplus
}
#endif
#endif
