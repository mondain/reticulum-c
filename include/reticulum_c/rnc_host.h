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
  RNC_HOST_RNODE,
  RNC_HOST_PIPE, /* address = command line; HDLC over the child's stdio */
  RNC_HOST_AX25  /* address = serial path; AX.25 UI frames inside KISS */
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
#define RNC_HOST_CALLSIGN_MAX 32u
/* Backbone-style listener protection: a client IP whose connections each last
 * under threshold_seconds more than grace times is refused until expiry_seconds
 * after its last flap. Zero fields select 20 s, 5 flaps and 12 h. */
typedef struct rnc_fast_flap {
  int enabled;
  unsigned threshold_seconds, grace, expiry_seconds;
} rnc_fast_flap;
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
  /* Serial-style kinds: 0 = 8 data bits, no parity, 1 stop bit. serial_parity
   * is 'N', 'E' or 'O'. */
  unsigned serial_databits, serial_stopbits;
  char serial_parity;
  const char
      *device; /* AUTO: interface name carrying a link-local IPv6 address */
  const char *group; /* AUTO: discovery group, default"reticulum" */
  uint16_t discovery_port, data_port; /* AUTO defaults29716/42671 */
  const rnc_ifac *ifac; /* optional sensitive configuration copied on add */
  uint32_t frequency, bandwidth; /* RNODE required Hz */
  unsigned spreading_factor, coding_rate;
  int tx_power, flow_control;
  /* RNODE: airtime limits in percent (0 = leave the radio default) and an
   * optional station ID beacon: id_callsign (at most RNC_HOST_CALLSIGN_MAX
   * bytes) sent id_interval seconds after the first transmission. */
  double airtime_limit_short, airtime_limit_long;
  const char *id_callsign;
  unsigned id_interval;
  unsigned respawn_delay_ms; /* PIPE: wait before restarting; 0 = 5000 */
  /* AX25: source callsign (3 to 6 characters, upper-cased) and SSID (0-15);
   * TNC settings in milliseconds (persistence is 0-255), 0 = reference
   * defaults of 350, 20, 64 and 20. */
  const char *callsign;
  unsigned ssid, preamble_ms, txtail_ms, persistence, slottime_ms;
  rnc_interface_mode mode;        /* default FULL; inherited by child ifaces */
  uint32_t announce_cap_permille; /* 0 = 20 (2%) */
  /* Per-destination announce rate control; see rnc_interface_policy. */
  uint32_t announce_rate_target, announce_rate_grace, announce_rate_penalty;
  int recursive_path_requests;  /* see rnc_interface_policy */
  rnc_ingress_policy ingress;   /* zero = reference defaults */
  rnc_fast_flap fast_flap;      /* TCP_LISTEN only; off by default */
  /* TCP_CONNECT: retry pacing and limits (0 = reference defaults: 5 s wait,
   * unlimited tries, 5 s connect timeout); kiss_framing uses KISS data frames
   * instead of HDLC. prefer_ipv6 picks an IPv6 address when a name has both. */
  unsigned reconnect_wait_ms, max_reconnect_tries, connect_timeout_ms;
  int kiss_framing, prefer_ipv6;
  /* The reference's `outgoing = No`: the interface receives but nothing is
   * sent on it. Connections a listener accepts inherit it. */
  int no_output;
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
  rnc_interface_mode mode;
  uint32_t announce_cap_permille;
  size_t blocked_ips; /* TCP_LISTEN: IPs currently refused for flapping */
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
