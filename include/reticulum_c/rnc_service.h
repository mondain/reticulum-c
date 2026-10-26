#ifndef RETICULUM_C_SERVICE_H
#define RETICULUM_C_SERVICE_H
#include <reticulum_c/rnc_resource.h>
#ifdef __cplusplus
extern "C" {
#endif
#define RNC_SERVICE_PENDING 8u
#define RNC_SERVICE_HANDLERS 16u
#define RNC_SERVICE_EVENTS 8u
#define RNC_SERVICE_ALLOWLIST 8u
typedef struct rnc_service rnc_service;
typedef enum rnc_service_policy {
    RNC_SERVICE_ALLOW_NONE = 0,
    RNC_SERVICE_ALLOW_ALL = 1,
    RNC_SERVICE_ALLOW_IDENTIFIED = 2,
    RNC_SERVICE_ALLOW_LIST = 3
} rnc_service_policy;
typedef enum rnc_service_event_type {
    RNC_SERVICE_REQUEST = 1,
    RNC_SERVICE_RESPONSE,
    RNC_SERVICE_TIMEOUT,
    RNC_SERVICE_DENIED,
    RNC_SERVICE_FAILED
} rnc_service_event_type;
typedef struct rnc_service_event {
    rnc_service_event_type type;
    rnc_result reason;
    uint8_t request_id[16], path_hash[16], identity_hash[16];
    int identified;
    double requested_at;
    size_t data_size;
} rnc_service_event;
/* Borrows link/RNG. Encoded values are complete MessagePack objects, copied on
 * acceptance, never interpreted as application commands. One outgoing and one
 * incoming Resource may run concurrently; eight inline requests may be pending.
 * max_value bounds each encoded request/response and each queued event; 0=1MiB.
 * A 64-entry FIFO of completed/denied/expired incoming request IDs suppresses
 * recent replay. This bounded cache does not guarantee indefinite exactly-once
 * side effects; applications still make irreversible requests idempotent.
 * Incoming admitted requests expire locally after 30 seconds. */
rnc_service *rnc_service_new(rnc_link *link, size_t max_value, rnc_random_fn random, void *context);
void rnc_service_free(rnc_service *service);
rnc_result rnc_service_register(rnc_service *service, const char *path, rnc_service_policy policy,
                                const uint8_t (*allowed_identities)[16], size_t allowed_count);
rnc_result rnc_service_unregister(rnc_service *service, const char *path);
/* unix_seconds is a finite nonnegative Unix timestamp; now_ms is monotonic.
 * timeout_ms is nonzero. Returns the canonical RNS request ID on success only.
 * Values too large for one encrypted packet automatically use Resources. */
rnc_result rnc_service_request(rnc_service *service, const char *path, const void *encoded_value,
                               size_t value_size, double unix_seconds, uint64_t now_ms,
                               uint64_t timeout_ms, uint8_t request_id[16]);
/* Only responds once to an admitted, unexpired request. */
rnc_result rnc_service_respond(rnc_service *service, const uint8_t request_id[16],
                               const void *encoded_value, size_t value_size, uint64_t now_ms);
/* Forward link packet/resource/closed events; AGAIN means unhandled, or retry
 * when the bounded application event queue is full. Retain the event then. */
rnc_result rnc_service_input(rnc_service *service, const rnc_link_event *event, uint64_t now_ms);
rnc_result rnc_service_pump(rnc_service *service, uint64_t now_ms);
rnc_result rnc_service_tick(rnc_service *service, uint64_t now_ms);
/* Copies an event and its encoded value. NO_SPACE leaves it queued, reports
 * the required capacity in *written and does not alter event/output bytes. */
rnc_result rnc_service_poll(rnc_service *service, rnc_service_event *event, void *value,
                            size_t capacity, size_t *written);
#ifdef __cplusplus
}
#endif
#endif
