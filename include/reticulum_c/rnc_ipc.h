#ifndef RETICULUM_C_IPC_H
#define RETICULUM_C_IPC_H
#include <reticulum_c/rnc.h>
#ifdef __cplusplus
extern "C" {
#endif
#define RNC_RPC_MESSAGE_MAX 65536u
#define RNC_RPC_EVENTS 8u
#define RNC_RPC_KEY_MAX 128u
#define RNC_RPC_WRITER_DEPTH 16u
typedef struct rnc_rpc rnc_rpc;
typedef enum rnc_rpc_event_type {
  RNC_RPC_SEND = 1,
  RNC_RPC_AUTHENTICATED,
  RNC_RPC_MESSAGE,
  RNC_RPC_CLOSED
} rnc_rpc_event_type;
typedef struct rnc_rpc_event {
  rnc_rpc_event_type type;
  rnc_result reason;
  size_t size;
  uint8_t data[RNC_RPC_MESSAGE_MAX + 12u];
} rnc_rpc_event;
/* Transport owns the socket and private state files. RPC uses POSIX
 * multiprocessing.connection framing and mutual HMAC challenge authentication.
 * Modern SHA256 is generated; accepted digest choices match CPython's SHA2/SHA3
 * family plus legacy MD5. This is NOT a general pickle interpreter: RNS1.5.5
 * application calls/responses are MessagePack. All APIs are thread-confined. */
rnc_rpc *rnc_rpc_new(const void *key, size_t key_size, int server,
                     rnc_random_fn random, void *random_context,
                     size_t max_payload);
void rnc_rpc_free(rnc_rpc *rpc);
rnc_result rnc_rpc_key(const rnc_identity *transport_identity, uint8_t key[32]);
rnc_result rnc_rpc_start(rnc_rpc *rpc, uint64_t now_ms);
/* May consume an input prefix; always advance by *consumed. AGAIN consumes zero
 * when output event pressure prevents processing. Partial frames remain owned
 * by the instance. A protocol/authentication failure closes the instance. */
rnc_result rnc_rpc_input(rnc_rpc *rpc, const uint8_t *data, size_t size,
                         size_t *consumed, uint64_t now_ms);
rnc_result rnc_rpc_send(rnc_rpc *rpc, const void *payload, size_t size,
                        uint64_t now_ms);
rnc_result rnc_rpc_poll(rnc_rpc *rpc, rnc_rpc_event *event);
rnc_result rnc_rpc_tick(rnc_rpc *rpc, uint64_t now_ms);
rnc_result rnc_rpc_close(rnc_rpc *rpc);
int rnc_rpc_is_authenticated(const rnc_rpc *rpc);

typedef enum rnc_rpc_query_type {
  RNC_RPC_INTERFACE_STATS = 1,
  RNC_RPC_PATH_TABLE,
  RNC_RPC_LINK_COUNT,
  RNC_RPC_ACTIVE_LINK_COUNT,
  RNC_RPC_NEXT_HOP,
  RNC_RPC_NEXT_HOP_IF_NAME,
  RNC_RPC_FIRST_HOP_TIMEOUT,
  RNC_RPC_LOWEST_INTERFACE_BITRATE,
  RNC_RPC_MEDIUM_PATH_TIMEOUT,
  RNC_RPC_RATE_TABLE,
  RNC_RPC_BLACKHOLED_IDENTITIES
} rnc_rpc_query_type;
typedef struct rnc_rpc_query {
  rnc_rpc_query_type type;
  uint8_t destination_hash[16];
  int has_destination, has_max_hops;
  uint32_t max_hops;
} rnc_rpc_query;
/* Bounded GET-only MessagePack map parser; rejects mutation methods, duplicate
 * fields, malformed lengths and unsupported objects without executing anything.
 * The output is committed only on success. Host owns query authorization/data.
 */
rnc_result rnc_rpc_decode_query(const void *payload, size_t size,
                                rnc_rpc_query *query);

/* Native response writer. Init, append exactly one complete value, finish,
 * then pass the completed bytes to rnc_rpc_send(). Container cardinalities are
 * checked; errors are sticky. Strings must be valid UTF-8. No pointers retained
 * beyond the caller-owned output buffer. Each append commits a whole value. */
typedef struct rnc_rpc_writer {
  uint8_t *data;
  size_t capacity, size, remaining[RNC_RPC_WRITER_DEPTH];
  unsigned depth;
  rnc_result status;
} rnc_rpc_writer;
void rnc_rpc_writer_init(rnc_rpc_writer *writer, void *output, size_t capacity);
rnc_result rnc_rpc_write_map(rnc_rpc_writer *writer, size_t pairs);
rnc_result rnc_rpc_write_array(rnc_rpc_writer *writer, size_t count);
rnc_result rnc_rpc_write_uint(rnc_rpc_writer *writer, uint64_t value);
rnc_result rnc_rpc_write_int(rnc_rpc_writer *writer, int64_t value);
rnc_result rnc_rpc_write_real(rnc_rpc_writer *writer, double value);
rnc_result rnc_rpc_write_string(rnc_rpc_writer *writer, const char *value);
rnc_result rnc_rpc_write_bin(rnc_rpc_writer *writer, const void *value,
                             size_t size);
rnc_result rnc_rpc_write_bool(rnc_rpc_writer *writer, int value);
rnc_result rnc_rpc_write_nil(rnc_rpc_writer *writer);
rnc_result rnc_rpc_writer_finish(rnc_rpc_writer *writer, size_t *written);
#ifdef __cplusplus
}
#endif
#endif
