#ifndef RETICULUM_C_RESOURCE_H
#define RETICULUM_C_RESOURCE_H
#include <reticulum_c/rnc_link.h>
#ifdef __cplusplus
extern "C" {
#endif
#define RNC_RESOURCE_SEGMENT_MAX 1048575u
#define RNC_RESOURCE_MAP_BATCH 74u
#define RNC_RESOURCE_DEFAULT_LIMIT (4u * 1024u * 1024u)
typedef struct rnc_resource rnc_resource;
typedef struct rnc_resource_options {
    int compress;
    const uint8_t *metadata; /* One complete encoded MessagePack value; copied. */
    size_t metadata_size;
    const uint8_t *request_id; /* Optional 16 bytes; copied. */
    int is_response;
} rnc_resource_options;
typedef enum rnc_resource_event_type {
    RNC_RESOURCE_PROGRESS = 1,
    RNC_RESOURCE_COMPLETE,
    RNC_RESOURCE_FAILED
} rnc_resource_event_type;
typedef struct rnc_resource_event {
    rnc_resource_event_type type;
    rnc_result reason;
    uint8_t hash[32], original_hash[32], request_id[16];
    int has_request_id, is_response, outgoing;
    size_t transferred, total;
} rnc_resource_event;
/* Borrows an active link and RNG context. max_size bounds uncompressed total
 * (including metadata), allocation, and decompression. 0 selects 4MiB. Every
 * method is thread-confined. Drain link events and resource events frequently. */
rnc_resource *rnc_resource_new(rnc_link *link, size_t max_size, rnc_random_fn random,
                               void *random_context);
void rnc_resource_free(rnc_resource *resource);
/* Copies caller data/options and prepares the first segment. Returns AGAIN
 * while another transfer is active; no partial acceptance. */
rnc_result rnc_resource_send(rnc_resource *resource, const void *data, size_t size,
                             const rnc_resource_options *options, uint64_t now_ms);
/* Explicit application admission: input never auto-accepts an advertisement.
 * Pass decrypted context2 bytes after applying policy. May accept the next
 * segment only when its original hash, size, metadata and request binding agree. */
rnc_result rnc_resource_accept(rnc_resource *resource, const uint8_t *advertisement, size_t size,
                               uint64_t now_ms);
/* Feed relevant RNC_LINK_PACKET/RESOURCE_PACKET events to every candidate
 * resource on the link. Unrelated resource IDs return AGAIN. */
rnc_result rnc_resource_input(rnc_resource *resource, const rnc_link_event *event, uint64_t now_ms);
rnc_result rnc_resource_pump(rnc_resource *resource, uint64_t now_ms);
rnc_result rnc_resource_tick(rnc_resource *resource, uint64_t now_ms);
rnc_result rnc_resource_cancel(rnc_resource *resource, uint64_t now_ms);
rnc_result rnc_resource_poll(rnc_resource *resource, rnc_resource_event *event);
/* Copies completed incoming application data; metadata separately. No data is
 * released before full stream authentication, decompression and hash checks. */
rnc_result rnc_resource_read(const rnc_resource *resource, void *data, size_t capacity,
                             size_t *written);
/* Size of the completed incoming data (excluding metadata); 0 otherwise. */
size_t rnc_resource_data_size(const rnc_resource *resource);
rnc_result rnc_resource_metadata(const rnc_resource *resource, void *data, size_t capacity,
                                 size_t *written);
int rnc_resource_is_complete(const rnc_resource *resource);
/* Receive window in parts (0 if not receiving) and its current ceiling. The
 * window starts at 4 (or where the link's previous incoming resource ended),
 * grows one part per completed request round up to the ceiling, and follows the
 * reference's rate classes: ceiling 10 normally, 75 after 4 fast rounds (above
 * 6.25 kB/s), 4 after 2 very slow rounds (below 250 B/s). A timed-out round
 * shrinks both. */
size_t rnc_resource_window(const rnc_resource *resource);
size_t rnc_resource_window_max(const rnc_resource *resource);
/* Parse a standard advertisement without admitting or allocating a transfer. */
rnc_result rnc_resource_inspect(const uint8_t *data, size_t size, size_t *transfer_size,
                                size_t *data_size, uint8_t hash[32], uint8_t original_hash[32],
                                uint8_t request_id[16], int *has_request_id, int *is_response);
#ifdef __cplusplus
}
#endif
#endif
