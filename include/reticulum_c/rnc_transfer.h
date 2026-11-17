#ifndef RETICULUM_C_TRANSFER_H
#define RETICULUM_C_TRANSFER_H
#include <reticulum_c/rnc_node.h>
#include <reticulum_c/rnc_resource.h>
#ifdef __cplusplus
extern "C" {
#endif
#ifndef RNC_TRANSFER_LINKS
#define RNC_TRANSFER_LINKS 4u
#endif
#ifndef RNC_TRANSFER_JOBS
#define RNC_TRANSFER_JOBS 4u
#endif
#ifndef RNC_TRANSFER_ALLOWED
#define RNC_TRANSFER_ALLOWED 64u
#endif
#define RNC_TRANSFER_NAME_MAX 255u
/* Largest file: the Resource limit (16 MiB) less room for the metadata. */
#define RNC_TRANSFER_MAX_SIZE (16u * 1024u * 1024u - 4096u)
#define RNC_TRANSFER_DEFAULT_LIMIT RNC_TRANSFER_MAX_SIZE
/* Largest file moved through the streaming calls below, which hold one 1 MiB segment of it in memory at a time:
 * 1 TiB, or 2 GiB less one byte on a target whose size_t has 32 bits. */
#define RNC_TRANSFER_STREAM_MAX_SIZE (sizeof(size_t) > 4 ? (UINT64_C(1) << 40) : UINT64_C(0x7fffffff))

/* Streamed files, for sizes that should not be held in memory (the calls without "stream" in their name keep a
 * whole file in memory and stop at RNC_TRANSFER_MAX_SIZE). The Resource protocol moves a large file as
 * segments, each authenticated on its own; the pieces below hand them over as they come.
 *
 * Receiving: open() is called once, when the first segment has arrived and the file's name is known, with the
 * file's total size; it returns a handle for write() and close(). write() gets the data in order, each piece
 * authentic by itself. close() is called exactly once for every successful open(): complete is 1 when the whole
 * file has arrived and 0 when the transfer failed or the link went (a file written to a temporary name should
 * then be removed, and renamed into place on 1). An error from open() or write() fails the transfer.
 * Sending: a source describes the file; read() fills a range and release() is called once when the transfer is
 * over, however it ends. */
typedef struct rnc_transfer_stream {
  rnc_result (*open)(void *context, const uint8_t *identity_hash, const uint8_t *name, size_t name_size,
                     uint64_t size, void **file);
  rnc_result (*write)(void *file, uint64_t offset, const void *data, size_t size);
  void (*close)(void *file, int complete);
} rnc_transfer_stream;
typedef struct rnc_transfer_source {
  uint64_t size;
  rnc_resource_source_fn read;
  void *context;
  void (*release)(void *context); /* may be NULL */
  uint8_t name[RNC_TRANSFER_NAME_MAX]; /* serving a fetch: the name the file is sent under */
  size_t name_size;
} rnc_transfer_source;
typedef int (*rnc_transfer_fetch_stream_fn)(void *context, const uint8_t *path, size_t path_size,
                                            const uint8_t *identity_hash, rnc_transfer_source *source);

/* File transfer as rncp does it. A listener owns one SINGLE destination
 * (conventionally "rncp.receive"), accepts links, and receives files that the
 * sender pushes as a Resource whose metadata is {"name": <file name>}. With a
 * fetch callback it also answers "fetch_file" requests: the response is True,
 * False (not found) or 240 (not allowed), and the file follows as a Resource.
 * A client pushes a file (send) or pulls one (fetch). Sans-I/O like
 * rnc_responder: feed LOCAL node events, tick, poll. Thread-confined; the node
 * and RNG are borrowed. Files are held in memory, bounded by max_size, unless the streaming calls and
 * configuration further down are used. */
typedef struct rnc_transfer_listener rnc_transfer_listener;
typedef struct rnc_transfer_client rnc_transfer_client;

/* A completed incoming file. identity_hash is NULL when the sender did not
 * identify (possible only with allow_all). name is the sender's file name,
 * unsanitised: the callback must reduce it to a safe base name. */
typedef rnc_result (*rnc_transfer_received_fn)(void *context,
                                               const uint8_t *identity_hash,
                                               const uint8_t *name,
                                               size_t name_size,
                                               const uint8_t *data,
                                               size_t size);
typedef enum rnc_transfer_fetch_result {
  RNC_FETCH_FOUND = 0,   /* *data malloc'd by the callback, freed by the library */
  RNC_FETCH_NOT_FOUND,
  RNC_FETCH_NOT_ALLOWED
} rnc_transfer_fetch_result;
typedef int (*rnc_transfer_fetch_fn)(void *context, const uint8_t *path,
                                     size_t path_size,
                                     const uint8_t *identity_hash,
                                     uint8_t **data, size_t *size,
                                     uint8_t name[RNC_TRANSFER_NAME_MAX],
                                     size_t *name_size);
typedef struct rnc_transfer_config {
  int allow_all; /* accept files and fetches from anyone */
  uint8_t allowed[RNC_TRANSFER_ALLOWED][16]; /* identity hashes otherwise */
  size_t allowed_count;
  size_t max_size; /* largest incoming file held in memory; 0 = RNC_TRANSFER_MAX_SIZE */
  /* Streamed files: when stream.write is set, incoming files go through it instead of `received`, up to
   * max_stream_size bytes (0 = RNC_TRANSFER_STREAM_MAX_SIZE); fetch_stream, when set, answers fetches in
   * place of `fetch` (returning the same RNC_FETCH_* codes, and filling `source` for RNC_FETCH_FOUND). */
  rnc_transfer_stream stream;
  uint64_t max_stream_size;
  rnc_transfer_fetch_stream_fn fetch_stream;
  int no_compress; /* send fetched files uncompressed (rncp -C) */
  rnc_transfer_received_fn received;
  rnc_transfer_fetch_fn fetch; /* NULL: fetching disabled */
  void *context;
} rnc_transfer_config;

/* The destination must already be registered on the node with this identity
 * (so it is announced), and the identity needs its private key. */
rnc_transfer_listener *rnc_transfer_listener_new(
    rnc_node *node, const rnc_identity *identity, const uint8_t destination[16],
    const rnc_transfer_config *config, rnc_random_fn random,
    void *random_context);
void rnc_transfer_listener_free(rnc_transfer_listener *listener);
/* RNC_OK: consumed; RNC_AGAIN: not ours; other: ours but not processed. */
rnc_result rnc_transfer_listener_input(rnc_transfer_listener *listener,
                                       const rnc_node_event *event,
                                       uint64_t unix_seconds, uint64_t now_ms);
rnc_result rnc_transfer_listener_tick(rnc_transfer_listener *listener,
                                      uint64_t unix_seconds, uint64_t now_ms);
size_t rnc_transfer_listener_link_count(const rnc_transfer_listener *listener);

typedef enum rnc_transfer_status {
  RNC_TRANSFER_DONE = 1,
  RNC_TRANSFER_FAILED,      /* link, transfer or timeout failure */
  RNC_TRANSFER_NOT_FOUND,   /* fetch: the remote has no such file */
  RNC_TRANSFER_NOT_ALLOWED  /* fetch: the remote refused */
} rnc_transfer_status;
typedef struct rnc_transfer_result {
  uint32_t tag;
  rnc_transfer_status status;
  uint8_t destination[16];
  uint8_t name[RNC_TRANSFER_NAME_MAX]; /* fetch: the file's name */
  size_t name_size;
  size_t size; /* fetch: file bytes */
} rnc_transfer_result;

rnc_transfer_client *rnc_transfer_client_new(rnc_node *node, size_t max_size,
                                             rnc_random_fn random,
                                             void *random_context);
void rnc_transfer_client_free(rnc_transfer_client *client);
/* Whether files this client sends are compressed when the build can (default on; rncp -C turns it off). */
void rnc_transfer_client_set_compression(rnc_transfer_client *client, int enabled);
/* identity (with private key) is sent as the link identification. The node
 * needs a route to the destination (RNC_STATE otherwise); RNC_AGAIN when all
 * jobs are busy (unpolled results count as busy). timeout_ms covers the whole
 * job. */
rnc_result rnc_transfer_send(rnc_transfer_client *client,
                             const uint8_t destination[16],
                             const rnc_identity *identity, const uint8_t *name,
                             size_t name_size, const void *data, size_t size,
                             uint32_t tag, uint64_t timeout_ms,
                             uint64_t unix_seconds, uint64_t now_ms);
/* Send a file read from a source, up to the client's stream limit (default RNC_TRANSFER_STREAM_MAX_SIZE).
 * The source is released when the job ends, or at once if the call fails. */
rnc_result rnc_transfer_send_stream(rnc_transfer_client *client, const uint8_t destination[16],
                                    const rnc_identity *identity, const uint8_t *name, size_t name_size,
                                    const rnc_transfer_source *source, uint32_t tag, uint64_t timeout_ms,
                                    uint64_t unix_seconds, uint64_t now_ms);
/* Fetch a file into a stream. The result carries the name and the size; poll with no buffer. */
rnc_result rnc_transfer_fetch_stream(rnc_transfer_client *client, const uint8_t destination[16],
                                     const rnc_identity *identity, const uint8_t *path, size_t path_size,
                                     const rnc_transfer_stream *stream, void *stream_context, uint32_t tag,
                                     uint64_t timeout_ms, uint64_t unix_seconds, uint64_t now_ms);
/* The largest file the streaming calls of this client move; at most RNC_TRANSFER_STREAM_MAX_SIZE. */
void rnc_transfer_client_set_stream_limit(rnc_transfer_client *client, uint64_t max_size);
rnc_result rnc_transfer_fetch(rnc_transfer_client *client,
                              const uint8_t destination[16],
                              const rnc_identity *identity, const uint8_t *path,
                              size_t path_size, uint32_t tag,
                              uint64_t timeout_ms, uint64_t unix_seconds,
                              uint64_t now_ms);
rnc_result rnc_transfer_client_input(rnc_transfer_client *client,
                                     const rnc_node_event *event,
                                     uint64_t unix_seconds, uint64_t now_ms);
rnc_result rnc_transfer_client_tick(rnc_transfer_client *client,
                                    uint64_t unix_seconds, uint64_t now_ms);
/* 0..1 progress of the job's file transfer; RNC_STATE for an unknown tag. */
rnc_result rnc_transfer_client_progress(const rnc_transfer_client *client,
                                        uint32_t tag, double *progress);
/* Next finished job; RNC_AGAIN if none. RNC_NO_SPACE (nothing consumed) if the
 * file does not fit capacity; result->size says how much is needed. */
rnc_result rnc_transfer_client_poll(rnc_transfer_client *client,
                                    rnc_transfer_result *result, void *data,
                                    size_t capacity);
#ifdef __cplusplus
}
#endif
#endif
