#ifndef RETICULUM_C_HOST_H
#define RETICULUM_C_HOST_H
/* Optional POSIX host adapter. This is separate from the sans-I/O core. */
#include <reticulum_c/rnc_node.h>
#include <reticulum_c/rnc_security.h>
#ifdef __cplusplus
extern "C" {
#endif
#define RNC_HOST_SLOTS 24u
#define RNC_HOST_QUEUE_FRAMES 32u
#define RNC_HOST_FRAME_MAX (2u * (RNC_MAX_FRAME + 1u) + 2u)
#define RNC_HOST_AUTO_PEER_TIMEOUT 22000u
typedef enum rnc_host_kind {
  RNC_HOST_TCP_LISTEN = 1,
  RNC_HOST_TCP_CONNECT,
  RNC_HOST_UDP,
  RNC_HOST_AUTO,
  RNC_HOST_SERIAL,
  RNC_HOST_KISS,
  RNC_HOST_RNODE
} rnc_host_kind;
typedef enum rnc_host_framing {
  RNC_HOST_HDLC = 1,
  RNC_HOST_KISS_FRAMING
} rnc_host_framing;
typedef struct rnc_host_framer {
  size_t size;
  int active, escaped, discard;
  uint8_t data[RNC_MAX_FRAME + 1u];
} rnc_host_framer;
/* Pure framing codecs, including KISS command/port byte. Initialize framers to
 * zero per connection. Feed returns AGAIN until one frame is complete. */
rnc_result rnc_host_frame_encode(rnc_host_framing framing, uint8_t command,
                                 const uint8_t *data, size_t size,
                                 uint8_t *output, size_t capacity,
                                 size_t *written);
rnc_result rnc_host_frame_feed(rnc_host_framer *state, rnc_host_framing framing,
                               uint8_t byte, uint8_t *command, uint8_t *output,
                               size_t capacity, size_t *written);
/* AutoInterface discovery uses SHA256(group+canonical IPv6 source text), and
 * ff12:0:<group hash bytes2..13> for temporary link-scope multicast. It is peer
 * discovery, not identity authentication. Network access is protected by IFAC.
 */
rnc_result rnc_host_auto_group(const char *group, uint8_t multicast[16]);
rnc_result rnc_host_auto_token(const char *group, const char *ipv6,
                               uint8_t token[32]);
typedef struct rnc_host_config {
  rnc_host_kind kind;
  const char *name; /* optional human-readable interface name */
  int local; /* shared-instance data interface; reserved for trusted local hosts
              */
  const char *address; /* bind address, TCP remote address, or serial path */
  const char *target;  /* UDP remote address; NULL for receive-only */
  uint16_t port, target_port;
  uint16_t mtu;     /* default500; AUTO default1196; serial/radio maximum500 */
  uint32_t bitrate; /* serialization pacing; default10Mb/s */
  unsigned serial_baud, kiss_port;
  const char
      *device; /* AUTO: interface name carrying a link-local IPv6 address */
  const char *group; /* AUTO: discovery group, default"reticulum" */
  uint16_t discovery_port, data_port; /* AUTO defaults29716/42671 */
  const rnc_ifac *ifac; /* optional sensitive configuration copied on add */
  uint32_t frequency, bandwidth; /* RNODE required Hz */
  unsigned spreading_factor, coding_rate;
  int tx_power, flow_control;
} rnc_host_config;
typedef struct rnc_host_status {
  uint32_t interface_id, parent_id;
  rnc_host_kind kind;
  char name[128];
  uint8_t hash[32];
  uint32_t bitrate;
  int local;
  uint16_t bound_port, mtu;
  int online, last_errno;
  int radio_ready; /* RNode parameters acknowledged; descriptor online alone is
                      insufficient */
  size_t queued_frames;
  uint64_t rx_packets, tx_packets, dropped_packets, reconnects;
  uint64_t rx_bytes, tx_bytes, rx_announces, tx_announces, rx_announce_bytes,
      tx_announce_bytes;
  uint64_t ifac_violations, protocol_violations;
  size_t ifac_size;
  uint8_t ifac_signature[64];
} rnc_host_status;
typedef struct rnc_host rnc_host;
typedef enum rnc_host_event_type {
  RNC_HOST_NODE = 1,
  RNC_HOST_UP,
  RNC_HOST_DOWN
} rnc_host_event_type;
typedef struct rnc_host_event {
  rnc_host_event_type type;
  uint32_t interface_id;
  int error_number;
  rnc_node_event node;
} rnc_host_event;
/* Node is borrowed. Configured IDs must be1..0x7fffffff; dynamic TCP/Auto peers
 * use IDs>=0x80000000. The node's eight-interface bound still applies. DNS is
 * resolved on add; reconnects reuse that address. All I/O after add is
 * nonblocking. Caller drains events and retains LOCAL packets while its
 * application is busy. */
/* Load a raw64-byte private identity, or create exclusively with mode0600.
 * Existing files must be regular, owned by the effective user, exactly64bytes
 * and inaccessible to group/others. Symlinks/FIFOs are rejected. Existing
 * invalid files are never replaced; identity output commits only on success. */
rnc_result rnc_host_identity_load(const char *path, rnc_random_fn random,
                                  void *random_context, rnc_identity *identity);
rnc_host *rnc_host_new(rnc_node *node);
void rnc_host_free(rnc_host *host);
rnc_result rnc_host_add(rnc_host *host, uint32_t interface_id,
                        const rnc_host_config *config);
rnc_result rnc_host_remove(rnc_host *host, uint32_t interface_id);
rnc_result rnc_host_get_status(const rnc_host *host, uint32_t interface_id,
                               rnc_host_status *status);
rnc_result rnc_host_status_at(const rnc_host *host, size_t index,
                              rnc_host_status *status);
/* Poll descriptors, feed decoded/IFAC-verified packets, retain bounded output,
 * and drive node timers. timeout is0..1000ms. Times must not move backwards. */
rnc_result rnc_host_step(rnc_host *host, int timeout_ms, uint64_t unix_seconds,
                         uint64_t now_ms);
rnc_result rnc_host_poll(rnc_host *host, rnc_host_event *event);
#ifdef __cplusplus
}
#endif
#endif
