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
  RNC_HOST_AX25, /* address = serial path; AX.25 UI frames inside KISS */
  RNC_HOST_I2P,  /* address/port = SAM bridge of a local I2P router */
  RNC_HOST_RNODE_MULTI, /* address = serial path; several radios on one device */
  RNC_HOST_WEAVE /* address = serial path of a Weave switch; peers are children */
} rnc_host_kind;
#define RNC_HOST_SUBRADIOS 11u
/* One radio of an RNODE_MULTI device. vport is its position in the device's
 * own list (0 and up, in the order the device reports its radios). */
typedef struct rnc_host_subradio {
  const char *name;
  unsigned vport;
  uint32_t frequency, bandwidth;
  int tx_power, flow_control, no_output;
  unsigned spreading_factor, coding_rate;
  double airtime_limit_short, airtime_limit_long; /* percent, 0 = default */
} rnc_host_subradio;
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
/* The address of a network device as text, as the reference's get_address_for_if reads it: its IPv4 address
 * (or its broadcast address when `broadcast`), else, or with `prefer_ipv6`, its first IPv6 address (a
 * link-local one carries "%device"). 0 on success, -1 when the device has none or `out` is too small. */
int rnc_host_device_address(const char *device, int broadcast, int prefer_ipv6, char *out, size_t capacity);
/* The Linux abstract Unix socket address the reference's shared instance uses: "rns/<name><suffix>" with a
 * leading NUL byte ("default" and "" for the data port, "default" and "/rpc" for the RPC port). `out` receives a
 * struct sockaddr_un (capacity at least its size); the return value is the address length to pass to bind and
 * connect, or 0 where abstract sockets do not exist, or for a name that is empty, longer than
 * RNC_HOST_UNIX_NAME_MAX or has a NUL in it. */
#define RNC_HOST_UNIX_NAME_MAX 80u
size_t rnc_host_abstract_address(const char *name, const char *suffix, void *out, size_t capacity);
/* The multicast group with the reference's type and scope nibbles: `permanent` selects ff0x over
 * ff1x, scope is one of the RNC_AUTO_SCOPE_ values (discovery_scope), else RNC_INVALID. */
#define RNC_AUTO_SCOPE_LINK 2u
#define RNC_AUTO_SCOPE_ADMIN 4u
#define RNC_AUTO_SCOPE_SITE 5u
#define RNC_AUTO_SCOPE_ORGANISATION 8u
#define RNC_AUTO_SCOPE_GLOBAL 14u
rnc_result rnc_host_auto_group_ex(const char *group, int permanent, unsigned scope,
                                  uint8_t multicast[16]);
/* Whether AutoInterface uses a network device: `allowed` (comma-separated, empty or NULL = any) and
 * `ignored` are the reference's `devices` and `ignored_devices`; an ignored device is never used. */
int rnc_host_auto_device_allowed(const char *allowed, const char *ignored, const char *name);
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
  /* AUTO: comma-separated device names to use (`devices`, empty = any) and to skip (`ignored_devices`);
   * auto_permanent selects the permanent multicast type (`multicast_address_type`); auto_scope is an
   * RNC_AUTO_SCOPE_ value (`discovery_scope`), 0 = link. */
  const char *auto_devices, *auto_ignored_devices;
  int auto_permanent;
  unsigned auto_scope;
  /* TCP: the link runs over an I2P tunnel, so dead-peer detection uses the I2P timings (reference
   * `i2p_tunneled`). Connections a listener accepts inherit it. */
  int i2p_tunneled;
  /* TCP_CONNECT and I2P: send the tunnel synthesis without the RNS 1.6 map, for a peer running RNS 1.5,
   * which accepts only that form (see rnc_node_set_interface_tunnel). */
  int tunnel_plain;
  /* TCP_LISTEN and TCP_CONNECT: a Linux abstract Unix socket named "rns/<unix_name>" instead of an address
   * and port, which is how the reference's shared instance listens by default (its name is the config's
   * instance_name, "default" if unset). address and port are ignored. rnc_host_add returns RNC_UNSUPPORTED
   * where abstract sockets do not exist, and RNC_INVALID for a name that is empty, over 80 bytes, or the
   * empty string. */
  const char *unix_name;
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
  int no_announces_from_internal, announces_to_internal; /* see rnc_interface_policy */
  int gravity;                  /* see rnc_interface_policy */
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
  /* I2P: address and port (default 7656) reach the router's SAM bridge. The
   * destination's private key is read from i2p_key_path, or generated by the
   * router and written there with owner-only access. Each entry of i2p_peers
   * is a "<52 characters>.b32.i2p" name, a bare 52 character b32 address, or a
   * full base64 destination, and is dialled through the router; with
   * i2p_connectable other nodes may connect in. Peers spawned this way are
   * children of the I2P interface, as with a TCP listener. */
  /* RNODE_MULTI: the device is opened like a serial RNode, detected, and each
   * entry of subradios becomes a child interface once the device has reported
   * its radios. id_callsign/id_interval, mode and the announce settings apply
   * to every child. */
  const rnc_host_subradio *subradios;
  size_t subradio_count;
  const char *i2p_key_path;
  const char *const *i2p_peers;
  size_t i2p_peer_count;
  int i2p_connectable;
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
  /* path requests (the reference's prxc/ptxc and prxb/ptxb) */
  uint64_t rx_path_requests, tx_path_requests, rx_path_request_bytes, tx_path_request_bytes;
  uint64_t ifac_violations, protocol_violations;
  /* bytes received here and discarded (rnc_node_input_class, bad IFAC, undecodable); they are not in rx_bytes */
  uint64_t filtered_bytes;
  /* backpressure on a TCP peer that connected to this host (the reference's Backbone ingress and egress control):
   * reading from it is held back while the host's event queue is deep and it is the busiest producer, and its
   * outgoing queue counts as stalled once nothing drains from it */
  int ingress_gated, tx_stalled;
  uint64_t ingress_throttles;
  size_t ifac_size;
  uint8_t ifac_signature[64];
  rnc_interface_mode mode;
  /* RNode only: signal figures of the last received frame, as the reference's
   * r_stat_rssi / r_stat_snr / r_stat_q (RSSI in dBm, SNR in dB, link quality in
   * percent from the SNR and spreading factor). */
  int has_signal, rssi;
  float snr, quality;
  uint32_t announce_cap_permille;
  int gravity, announces_to_internal; /* the interface's policy, as the management RPC reports it */
  size_t blocked_ips; /* TCP_LISTEN: IPs currently refused for flapping */
  size_t queued_announces; /* announces waiting for the interface's announce bandwidth cap */
  /* the configured per destination announce rate limit (seconds, violations); target 0: none */
  uint32_t announce_rate_target, announce_rate_grace, announce_rate_penalty;
  char i2p_b32[56];   /* I2P: this node's b32 address, without ".b32.i2p" */
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
  /* RNC_HOST_NODE from an RNode with signal figures: those of the frame (the
   * reference's packet.rssi, packet.snr and packet.q) */
  int has_signal, rssi;
  float snr, quality;
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
/* Identity.to_file / pub_to_file: writes the raw 64 byte private key (mode
 * 0600) or, with public_only, the public key (mode 0644). An existing file is
 * kept and RNC_STATE returned unless overwrite is set, and replacement is atomic
 * (written beside it and renamed). RNC_INVALID when the identity has no private
 * key to save. */
rnc_result rnc_host_identity_save(const char *path, const rnc_identity *identity,
                                  int public_only, int overwrite);
rnc_host *rnc_host_new(rnc_node *node);
/* The stamp costs an interface requires (see rnc_node_set_interface_stamp_costs; negative: the node's
 * policy). Unlike the node call, this also covers the connections a listener accepts and re-created
 * interfaces. RNC_STATE for an unknown interface. */
rnc_result rnc_host_set_interface_stamp_costs(rnc_host *host, uint32_t interface_id, double destination_cost,
                                              double pr_cost);
/* Link requests this node sends are stamped when the destination asks (RNS 1.6). A new host installs a stamper that
 * searches the stamped key on `workers` threads (0 = one per core, at most 16) and gives up after `max_trials`
 * key trials in all (0 = 2^26, seconds on a few cores up to a cost of about 25); with `always` it also stamps for
 * destinations that announced no cost, at the policy's lr_cost. RNC_INVALID for more than 16 workers. */
rnc_result rnc_host_set_link_stamping(rnc_host *host, unsigned workers, uint64_t max_trials, int always);
/* The stamper itself (an rnc_link_stamper_fn; `context` is the rnc_host), for tests and custom hosts. */
int rnc_host_link_stamper(void *context, const uint8_t material[48], double cost, uint8_t private_key[32],
                          uint8_t public_key[32]);
void rnc_host_free(rnc_host *host);
rnc_result rnc_host_add(rnc_host *host, uint32_t interface_id,
                        const rnc_host_config *config);
rnc_result rnc_host_remove(rnc_host *host, uint32_t interface_id);
rnc_result rnc_host_get_status(const rnc_host *host, uint32_t interface_id,
                               rnc_host_status *status);
/* Running totals over every interface the host has had, closed ones included, local clients' interfaces left
 * out (the reference's totals). Link traffic is what travels on links: received from a peer, and forwarded on. */
typedef struct rnc_host_totals {
  uint64_t rx_bytes, tx_bytes, filtered_bytes, link_rx_bytes, link_tx_bytes;
  uint64_t rx_packets, tx_packets; /* received and not discarded, and sent */
} rnc_host_totals;
/* The index-th address a listening interface is refusing for flapping; RNC_AGAIN past the last one. */
rnc_result rnc_host_blocked_ip(const rnc_host *host, uint32_t interface_id, size_t index, char *out, size_t size);
rnc_result rnc_host_get_totals(const rnc_host *host, rnc_host_totals *totals);
rnc_result rnc_host_status_at(const rnc_host *host, size_t index,
                              rnc_host_status *status);
/* Poll descriptors, feed decoded/IFAC-verified packets, retain bounded output,
 * and drive node timers. timeout is0..1000ms. Times must not move backwards. */
rnc_result rnc_host_step(rnc_host *host, int timeout_ms, uint64_t unix_seconds,
                         uint64_t now_ms);
rnc_result rnc_host_poll(rnc_host *host, rnc_host_event *event);
/* Transport.await_path: asks the network for a path to the destination (on
 * every interface, again every five seconds once one is online) and runs the
 * host until the node has one, or timeout_ms passes (RNC_TIMEOUT). It steps the
 * host itself with the system clocks, so do not step it concurrently or with
 * other times. callback, if given, receives every host event (the host queue
 * is drained here, so feed events to your listeners from it) and then NULL once
 * per pass, the place to tick them. A callback returning nonzero stops the wait
 * (RNC_AGAIN), for a signal handler's flag. */
typedef int (*rnc_host_await_fn)(void *context, const rnc_host_event *event);
rnc_result rnc_host_await_path(rnc_host *host, const uint8_t destination[16],
                               unsigned timeout_ms, rnc_host_await_fn callback,
                               void *context);
#ifdef __cplusplus
}
#endif
#endif
