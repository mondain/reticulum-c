#ifndef RETICULUM_C_NODE_H
#define RETICULUM_C_NODE_H
#include <reticulum_c/rnc.h>
#include <reticulum_c/rnc_link.h>
#ifdef __cplusplus
extern "C" {
#endif
#ifndef RNC_NODE_INTERFACES
#define RNC_NODE_INTERFACES 8u
#endif
#ifndef RNC_NODE_ROUTES
#define RNC_NODE_ROUTES 128u
#endif
#ifndef RNC_NODE_DESTINATIONS
#define RNC_NODE_DESTINATIONS 16u
#endif
#ifndef RNC_NODE_LINKS
#define RNC_NODE_LINKS 64u
#endif
#ifndef RNC_NODE_EVENTS
#define RNC_NODE_EVENTS 64u
#endif
/* Interface ID zero is reserved for local delivery. Routing policy is bounded:
 * no automatic allocation/eviction after new; expire entries with tick(). */
typedef struct rnc_node rnc_node;
typedef struct rnc_path_request {
  uint8_t destination[16], transport_id[16], tag[16];
  size_t tag_size;
  int has_transport;
  /* the 64 byte form RNS 1.6 sends: dst | transport id | tag | 0xC1 | flags | 14 byte stamp */
  int has_stamp;
  uint8_t stamp[14];
} rnc_path_request;
typedef struct rnc_route {
  uint8_t destination[16], next_hop[16];
  uint32_t interface_id;
  uint8_t hops;
  uint64_t expires_ms, announced_at;
  rnc_announce announce;
} rnc_route;
typedef enum rnc_node_event_type {
  RNC_NODE_SEND = 1,
  RNC_NODE_LOCAL,
  RNC_NODE_ANNOUNCE,
  RNC_NODE_RECEIPT
} rnc_node_event_type;
/* Per-destination delivery proof policy for SINGLE DATA packets. PROVE_ALL
 * makes the node answer every locally delivered packet with an implicit proof;
 * PROVE_APP leaves it to rnc_node_prove(); PROVE_NONE (default) never proves. */
typedef enum rnc_proof_strategy {
  RNC_PROVE_NONE = 0,
  RNC_PROVE_APP,
  RNC_PROVE_ALL
} rnc_proof_strategy;
typedef enum rnc_receipt_status {
  RNC_RECEIPT_SENT = 0,
  RNC_RECEIPT_DELIVERED = 1,
  RNC_RECEIPT_FAILED
} rnc_receipt_status;
#ifndef RNC_NODE_RECEIPTS
#define RNC_NODE_RECEIPTS 32u
#endif
#ifndef RNC_NODE_KNOWN
#define RNC_NODE_KNOWN 256u
#endif
typedef struct rnc_node_event {
  rnc_node_event_type type;
  uint32_t interface_id;
  rnc_packet packet;
  rnc_route route;
  /* RNC_NODE_RECEIPT only: full packet hash, status and round trip time. */
  uint8_t receipt_hash[32];
  rnc_receipt_status receipt_status;
  uint64_t rtt_ms;
  /* Set by the host on events it hands out (RNC_HOST_NODE): the physical layer figures of the interface the
   * packet came in on, when it reports them (an RNode). A link manager passes them on to its link. */
  int has_signal, rssi;
  float snr, quality;
} rnc_node_event;
rnc_result rnc_path_request_create(const uint8_t destination[16],
                                   const uint8_t transport_id[16],
                                   const uint8_t *tag, size_t tag_size,
                                   rnc_packet *packet);
/* A stamped path request: the 64 byte form; the stamp covers destination || tag (see rnc_netstamp.h), the
 * transport id is required and the tag must be 16 bytes. */
rnc_result rnc_path_request_create_stamped(const uint8_t destination[16], const uint8_t transport_id[16],
                                           const uint8_t *tag, size_t tag_size, const uint8_t stamp[14],
                                           rnc_packet *packet);
rnc_result rnc_path_request_decode(const rnc_packet *packet,
                                   rnc_path_request *request);
rnc_node *rnc_node_new(const rnc_identity *identity, int transport,
                       rnc_random_fn random, void *random_context);
void rnc_node_free(rnc_node *node);
rnc_result rnc_node_add_interface(rnc_node *node, uint32_t interface_id,
                                  uint32_t bitrate);
/* Configure physical MTU before opening links; default500. Link requests are
 * clamped to both ingress and egress limits without changing their link ID. */
rnc_result rnc_node_interface_mtu(rnc_node *node, uint32_t interface_id,
                                  size_t mtu);
/* Shared-instance client interfaces are transparent hops. They are bridged to
 * physical interfaces even when this instance does not act as a transit router.
 */
rnc_result rnc_node_local_interface(rnc_node *node, uint32_t interface_id,
                                    int local);
/* Interface modes follow the Reticulum manual (8.16): ACCESS_POINT does not
 * receive rebroadcast announces and keeps paths one day; ROAMING keeps paths
 * six hours and does not carry announces from ROAMING or BOUNDARY segments;
 * BOUNDARY does not carry announces from ROAMING. FULL (default) and GATEWAY
 * propagate identically. announce_cap_permille is the share of the interface
 * bitrate announces may use in thousandths (0 selects the 20 = 2% default). */
typedef enum rnc_interface_mode {
  RNC_MODE_FULL = 0,
  RNC_MODE_GATEWAY,
  RNC_MODE_ACCESS_POINT,
  RNC_MODE_ROAMING,
  RNC_MODE_BOUNDARY,
  RNC_MODE_INTERNAL /* reference MODE_INTERNAL: joins the nodes of one internal network */
} rnc_interface_mode;
/* Ingress/egress control (manual 8.18-8.20), enabled by default. Zero fields
 * select the reference defaults: new_time 7200s, burst_hold 15s, burst_penalty
 * 15s, held_release_interval 5s, max_held 256 (bounded by the node's shared
 * table), announce burst 3 Hz on young / 10 Hz on older interfaces, path
 * request burst 3 / 8 Hz, egress path request limit 5 Hz. Frequencies are
 * in milli-hertz. */
typedef struct rnc_ingress_policy {
  int disabled;        /* turn off ingress and egress control */
  uint32_t new_time_s, burst_hold_s, burst_penalty_s, held_release_interval_s;
  uint32_t max_held;
  uint32_t burst_freq_new_mhz, burst_freq_mhz;
  uint32_t pr_burst_freq_new_mhz, pr_burst_freq_mhz, ec_pr_freq_mhz;
} rnc_ingress_policy;
typedef struct rnc_interface_policy {
  rnc_interface_mode mode;
  uint32_t announce_cap_permille;
  /* Per-destination limit on announces received here before they are
   * rebroadcast. Target is the minimum seconds between announces (0 disables).
   * More than `grace` violations block rebroadcast for target + penalty
   * seconds; paths are still learned. */
  uint32_t announce_rate_target, announce_rate_grace, announce_rate_penalty;
  /* Answer unknown-destination path requests from this interface by searching
   * other interfaces. GATEWAY, ACCESS_POINT and ROAMING always do; BOUNDARY
   * searches boundary and gateway peers; FULL only when this is set. */
  int recursive_path_requests;
  /* Reference announces_from_internal (default on) and announces_to_internal (default off).
   * An interface with no_announces_from_internal set never passes on announces learned on an
   * INTERNAL interface. An interface with announces_to_internal set lets its announces go to
   * INTERNAL interfaces even from a BOUNDARY one. */
  int no_announces_from_internal, announces_to_internal;
  /* Reference `gravity` (default 0): the same announce heard later on an interface of higher
   * gravity, with no more hops, moves the path there. */
  int gravity;
  rnc_ingress_policy ingress;
} rnc_interface_policy;
rnc_result rnc_node_interface_policy(rnc_node *node, uint32_t interface_id,
                                     const rnc_interface_policy *policy);
rnc_result rnc_node_remove_interface(rnc_node *node, uint32_t interface_id);
/* The reference's drop_path, drop_all_via and drop_announce_queues. A dropped path is forgotten at once and
 * learned again from the next announce. drop_path returns RNC_STATE when there was no such path; drop_via
 * returns how many paths used that next hop; drop_announce_queues discards the announces waiting to be sent
 * on any interface (announces held back by the cap and ones waiting out their rebroadcast delay) and
 * returns how many. */
rnc_result rnc_node_drop_path(rnc_node *node, const uint8_t destination[16]);
size_t rnc_node_drop_via(rnc_node *node, const uint8_t next_hop[16]);
size_t rnc_node_drop_announce_queues(rnc_node *node);
/* Copies private material solely for announce generation; clear/free removes
 * it. Keep name <=127 bytes and app data <=316. Outputs commit only on success.
 */
rnc_result rnc_node_add_destination(rnc_node *node,
                                    const rnc_identity *identity,
                                    const char *name, const void *app_data,
                                    size_t size, uint8_t destination[16]);
/* GROUP/PLAIN registration enables local delivery but never announces them.
 * GROUP stores only public identity metadata; its symmetric key stays with the
 * host, which must authenticate/decrypt LOCAL data before application use. */
rnc_result rnc_node_add_destination_ex(rnc_node *node,
                                       const rnc_identity *identity, int type,
                                       const char *name, const void *app_data,
                                       size_t size, uint8_t destination[16]);
/* Caller rotates/persists private ratchets; node copies only the public key.
 * NULL disables ratcheted announces. Applies to normal and path responses. */
rnc_result rnc_node_set_ratchet(rnc_node *node, const uint8_t destination[16],
                                const uint8_t public_key[32]);
rnc_result rnc_node_set_proof_strategy(rnc_node *node,
                                       const uint8_t destination[16],
                                       rnc_proof_strategy strategy);
/* Answer a delivered DATA packet (from a LOCAL event; pass its interface_id)
 * with an implicit (64 byte) or explicit (96 byte) proof signed by the
 * destination identity. The proof is queued as a SEND on that interface. */
rnc_result rnc_node_prove(rnc_node *node, const uint8_t destination[16],
                          const rnc_packet *packet, uint32_t interface_id,
                          int implicit, uint64_t unix_seconds, uint64_t now_ms);
/* Link MTU discovery (the reference's link_mtu_discovery, default on). A link
 * that applications open or accept on this node should be configured with
 * rnc_link_configure_mtu() using the first function below (initiator, the MTU
 * of the interface the route to `destination` leaves by) or the second
 * (responder, the interface the link request arrived on), before
 * rnc_link_open() / rnc_link_accept(). Both return 500 when discovery is off or
 * the interface or route is unknown, so interfaces left at the default 500 byte
 * MTU change nothing. The negotiated MTU is then the smaller of both ends, and
 * transport nodes clamp a link request to their own interfaces. */
rnc_result rnc_node_set_link_mtu_discovery(rnc_node *node, int enabled);
int rnc_node_link_mtu_discovery(const rnc_node *node);
size_t rnc_node_link_mtu_to(rnc_node *node, const uint8_t destination[16],
                            uint64_t now_ms);
size_t rnc_node_link_mtu_on(rnc_node *node, uint32_t interface_id);
/* The reference's use_implicit_proof (default on): PROVE_ALL answers with the
 * 64 byte implicit proof, or with the 96 byte explicit proof (packet hash plus
 * signature) when switched off. The receiver accepts both. */
rnc_result rnc_node_set_implicit_proofs(rnc_node *node, int implicit);
int rnc_node_implicit_proofs(const rnc_node *node);
/* Send a SINGLE DATA packet and track its delivery proof. A route to the
 * destination is required to learn the signer. Exactly one RNC_NODE_RECEIPT
 * event follows: DELIVERED on a valid proof, FAILED after timeout_ms (0 = default). The
 * packet hash (also the receipt key) is returned in hash. */
/* Query a receipt by packet hash after (or before) its event: SENT while
 * pending, then DELIVERED or FAILED with the round trip time (0 while pending).
 * Finished receipts stay until their slot is recycled for a newer one, oldest
 * first; an unknown or recycled hash returns RNC_STATE (the reference's CULLED). */
rnc_result rnc_node_receipt_status(const rnc_node *node, const uint8_t hash[32],
                                   rnc_receipt_status *status,
                                   uint64_t *rtt_ms);
/* The reference's default receipt timeout for a destination with a known
 * route: 6 s per hop plus 6 s and one MTU at the first hop's bitrate.
 * rnc_node_send_tracked uses it when timeout_ms is 0. */
rnc_result rnc_node_receipt_timeout(rnc_node *node, const uint8_t destination[16],
                                    uint64_t now, uint64_t *timeout_ms);
rnc_result rnc_node_send_tracked(rnc_node *node, const rnc_packet *packet,
                                 uint64_t timeout_ms, uint64_t unix_seconds,
                                 uint64_t now_ms, uint8_t hash[32]);
/* Packet(destination, data).send() for a SINGLE destination with a known route: encrypts `data` to the
 * destination as the reference does (to the ratchet it announced if it announced one, else to its identity
 * key), sends the packet and tracks its delivery proof like rnc_node_send_tracked (same receipt event, timeout
 * rule and returned hash). RNC_STATE without a route, RNC_NO_SPACE when the encrypted payload does not fit a
 * packet. Calling it again with the same data is Packet.resend(): the payload is encrypted afresh, so the new
 * packet has a new hash and a new receipt, as the reference's re-pack gives; a transport or the destination
 * would drop an identical packet as a duplicate. */
rnc_result rnc_node_send_single(rnc_node *node, const uint8_t destination[16], const void *data, size_t size,
                                uint64_t timeout_ms, uint64_t unix_seconds, uint64_t now_ms, uint8_t hash[32]);
/* Replaces the app data a SINGLE destination announces (up to 316 bytes), for
 * payloads that change between announces such as interface discovery. */
rnc_result rnc_node_set_destination_data(rnc_node *node,
                                         const uint8_t destination[16],
                                         const void *app_data, size_t size);
rnc_result rnc_node_announce(rnc_node *node, const uint8_t destination[16],
                             uint64_t unix_seconds, uint64_t now_ms);
rnc_result rnc_node_request_path(rnc_node *node, const uint8_t destination[16],
                                 uint64_t now_ms);
/* Transport.request_path with its options. interface_id 0 sends on every
 * interface, otherwise only on that one (RNC_STATE if unknown). tag NULL draws
 * a random 16 byte tag, else tag_size is 1 to 16. With recursive and an
 * interface (the form a transport uses to pass requests on) nothing is sent,
 * and RNC_AGAIN returned, while announces are queued for that interface or its
 * announce bandwidth allowance has not yet recovered. */
rnc_result rnc_node_request_path_ex(rnc_node *node, const uint8_t destination[16],
                                    uint32_t interface_id, const uint8_t *tag,
                                    size_t tag_size, int recursive,
                                    uint64_t now_ms);
/* Transport.hops_to: hops to a destination with a known path, else
 * RNC_PATHFINDER_MAX_HOPS. */
#define RNC_PATHFINDER_MAX_HOPS 128u
unsigned rnc_node_hops_to(rnc_node *node, const uint8_t destination[16],
                          uint64_t now_ms);
/* Destination.accepts_links (default on): link requests addressed to a
 * destination that does not accept them are dropped before the application
 * sees them. rnc_node_accepts_links returns 0 for an unknown destination. */
rnc_result rnc_node_set_accepts_links(rnc_node *node, const uint8_t destination[16],
                                      int accepts);
int rnc_node_accepts_links(rnc_node *node, const uint8_t destination[16]);
rnc_result rnc_node_input(rnc_node *node, uint32_t interface_id,
                          const rnc_packet *packet, uint64_t unix_seconds,
                          uint64_t now_ms);
/* What the last rnc_node_input made of its packet, for traffic statistics as RNS 1.6 keeps them. Only
 * meaningful after a call that returned RNC_OK; a packet refused with an error is discarded traffic too. */
#define RNC_INPUT_FILTERED 1u /* discarded: a duplicate, a rejected or stale announce, not for this node */
#define RNC_INPUT_HEARD 2u    /* with FILTERED: an announce that still counts as heard (stale, or held back) */
#define RNC_INPUT_LINK_RX 4u  /* link traffic received from a peer, for a local link or one forwarded */
#define RNC_INPUT_LINK_TX 8u  /* link traffic forwarded on to a peer */
unsigned rnc_node_input_class(const rnc_node *node);
rnc_result rnc_node_send(rnc_node *node, const rnc_packet *packet,
                         uint64_t unix_seconds, uint64_t now_ms);
rnc_result rnc_node_tick(rnc_node *node, uint64_t unix_seconds,
                         uint64_t now_ms);
rnc_result rnc_node_lookup(const rnc_node *node, const uint8_t destination[16],
                           uint64_t now_ms, rnc_route *route);
/* Tunnels (Transport.synthesize_tunnel / handle_tunnel). An interface that can
 * come back with a different address (a TCP client, I2P) announces a tunnel
 * made of the node's transport identity and a stable interface hash. A peer
 * that sees the same tunnel again on a new interface restores the paths it had
 * learned through it, without waiting for fresh announces. Entries expire after
 * eight hours without use. */
#ifndef RNC_NODE_TUNNELS
#define RNC_NODE_TUNNELS 8u
#endif
#ifndef RNC_NODE_TUNNEL_PATHS
#define RNC_NODE_TUNNEL_PATHS 16u
#endif
#define RNC_TUNNEL_TIMEOUT_MS (UINT64_C(8) * 3600u * 1000u)
typedef struct rnc_tunnel_info {
  uint8_t id[32];
  uint32_t interface_id; /* 0 while the interface is away */
  uint64_t expires_ms;
  size_t paths;
} rnc_tunnel_info;
/* Since RNS 1.6 a synthesis carries a signed map: implementation name and version, whether the node
 * transports, and the stamp costs the interface requires. A node answers such a synthesis once with its own
 * (the "reverse" synthesis), on an interface that was given a tunnel hash; the side that asked records the
 * answer without making a tunnel of it. A second synthesis on one connection is RNC_PROTOCOL. What the peer
 * said is kept until the interface is removed. */
typedef struct rnc_tunnel_peer {
  int has_identity; /* a valid synthesis arrived */
  int has_info;     /* it carried the 1.6 map: the fields below the identity are set */
  int has_tunnel;   /* a tunnel was named on this connection, by us or by the peer */
  uint8_t identity_hash[16], tunnel_id[32];
  char implementation[32], version[16];
  int transport;
  double destination_cost, pr_cost;
} rnc_tunnel_peer;
/* `interface_hash` is the one a reverse synthesis names (NULL: do not answer). `extension` 0 sends the form
 * without the map, 176 bytes: RNS 1.5 accepts only that one. The default is to send the map. */
rnc_result rnc_node_set_interface_tunnel(rnc_node *node, uint32_t interface_id, const uint8_t interface_hash[32],
                                         int extension);
rnc_result rnc_node_interface_tunnel_peer(const rnc_node *node, uint32_t interface_id, rnc_tunnel_peer *peer);
/* 1 when the transport identity that synthesized on this interface is blackholed: a host drops the connection,
 * as the reference does. */
int rnc_node_interface_peer_blackholed(const rnc_node *node, uint32_t interface_id, uint64_t unix_seconds);
/* Queues the synthesis packet on the interface. Needs the node's identity with
 * its private key (RNC_STATE otherwise) and a configured interface. */
rnc_result rnc_node_synthesize_tunnel(rnc_node *node, uint32_t interface_id,
                                      const uint8_t interface_hash[32],
                                      uint64_t now_ms);
/* Owner-signed checkpoint of the tunnel table (like rnc_node_state_export, but
 * a separate record so the route checkpoint format is unchanged). Imported
 * tunnels have no interface until their peer reappears; expired tunnels and
 * paths are skipped. Import is atomic and only into an empty tunnel table. */
#define RNC_NODE_TUNNEL_STATE_MAX \
  (96u + RNC_NODE_TUNNELS * (42u + RNC_NODE_TUNNEL_PATHS * (18u + RNC_MTU)))
rnc_result rnc_node_tunnels_export(const rnc_node *node, const rnc_identity *owner,
                                   uint64_t unix_seconds, uint64_t now_ms,
                                   void *output, size_t capacity, size_t *written);
rnc_result rnc_node_tunnels_import(rnc_node *node, const rnc_identity *owner,
                                   uint64_t unix_seconds, uint64_t now_ms,
                                   const void *input, size_t size);
size_t rnc_node_tunnel_count(const rnc_node *node);
rnc_result rnc_node_tunnel_at(const rnc_node *node, size_t index,
                              rnc_tunnel_info *info);
/* Identity blackholing (Transport.blackhole_identity). Announces from a
 * blackholed identity are dropped after signature verification, their
 * destinations' paths are removed, and path requests for them are not answered.
 * `until` is a unix time (0 = until lifted); entries expire lazily and in
 * rnc_node_tick. The table holds RNC_NODE_BLACKHOLE entries. */
#ifndef RNC_NODE_BLACKHOLE
#define RNC_NODE_BLACKHOLE 256
#endif
#define RNC_BLACKHOLE_REASON 64
typedef struct rnc_blackhole_entry {
  uint8_t identity[16], source[16]; /* source: who listed it (local = node id) */
  uint64_t until;
  char reason[RNC_BLACKHOLE_REASON]; /* empty = none */
} rnc_blackhole_entry;
/* RNC_OK added; RNC_STATE already listed; RNC_AGAIN table full. */
rnc_result rnc_node_blackhole(rnc_node *node, const uint8_t identity[16],
                              uint64_t until, const char *reason,
                              uint64_t unix_seconds);
/* RNC_OK lifted; RNC_STATE not listed. */
rnc_result rnc_node_unblackhole(rnc_node *node, const uint8_t identity[16]);
int rnc_node_is_blackholed(const rnc_node *node, const uint8_t identity[16],
                           uint64_t unix_seconds);
/* Enumerates live entries; RNC_AGAIN past the end. */
rnc_result rnc_node_blackhole_at(const rnc_node *node, size_t index,
                                 uint64_t unix_seconds,
                                 rnc_blackhole_entry *entry);
/* Reference file format: MessagePack map of identity hash to
 * {source, until, reason}. Export writes only locally listed entries; import
 * attributes entries to `source` (NULL = local), skips expired ones and never
 * overrides a local entry. */
rnc_result rnc_node_blackhole_export(const rnc_node *node, void *output,
                                     size_t capacity, size_t *written);
rnc_result rnc_node_blackhole_import(rnc_node *node, const void *input,
                                     size_t size, const uint8_t source[16],
                                     uint64_t unix_seconds);
/* Live update from a subscribed source (BlackholeUpdater): same format, but
 * only identities not already listed are added, whoever listed them. *added
 * (optional) receives the number of new entries. Validation is as for import. */
rnc_result rnc_node_blackhole_merge(rnc_node *node, const void *input,
                                    size_t size, const uint8_t source[16],
                                    uint64_t unix_seconds, size_t *added);
/* Network stamps (RNS 1.6). With `enabled`, an announce whose app data ends in a stamp extension is checked
 * against the cost the ingress interface requires (its own, set below, else destination_cost): a stamp that
 * meets it is removed from the app data kept and delivered, and the destination's announced link request cost
 * is recorded. With enforce_announces, an announce without a sufficient stamp is dropped and counted on its
 * interface; otherwise it is accepted either way, as RNS 1.6.1 does by default. Announces are always passed on
 * unchanged. enforce_link_requests and pr_cost take effect with link and path request stamps. Defaults: enabled,
 * nothing enforced, destination_cost 23.5, pr_cost 15.8. */
typedef struct rnc_stamp_policy {
  int enabled, enforce_announces, enforce_link_requests;
  double destination_cost, pr_cost;
  double lr_cost; /* link request cost of a destination that has none of its own; default 12.5, at most 40 */
} rnc_stamp_policy;
rnc_result rnc_node_stamp_policy(const rnc_node *node, rnc_stamp_policy *policy);
rnc_result rnc_node_set_stamp_policy(rnc_node *node, const rnc_stamp_policy *policy); /* RNC_INVALID for costs outside 0..100 */
/* Per interface costs; a negative value means the policy's. RNC_STATE for an unknown interface. */
rnc_result rnc_node_set_interface_stamp_costs(rnc_node *node, uint32_t interface_id, double destination_cost,
                                              double pr_cost);
/* The link request cost the destination announced with a valid stamp; RNC_STATE when it is unknown or never did. */
rnc_result rnc_node_recall_link_cost(const rnc_node *node, const uint8_t destination[16], double *link_cost);
/* Our own announces. A destination's stamp depends only on public data (see rnc_netstamp.h), so it can be
 * searched elsewhere and loaded here. rnc_node_destination_stamp_material gives that material (destination
 * hash, public key, name hash). rnc_node_set_destination_stamp checks the stamp against `destination_value`
 * of rnc_node_set_stamp_emission (RNC_AUTH if it falls short, RNC_STATE for a destination that is not a local
 * SINGLE one). A destination with a stamp announces with the extension and its link request cost; one without
 * announces unstamped, unless `required`, when rnc_node_announce returns RNC_AGAIN until a stamp is loaded.
 * The extension counts against the 316 byte destination app data limit: when the data and the extension do not
 * fit, the announce goes out without it. Path responses are stamped when a stamp is loaded and never wait. */
rnc_result rnc_node_set_stamp_emission(rnc_node *node, int required, double destination_value);
/* Path requests we send are stamped through a provider the host sets: it is given the stamp material
 * (destination || 16 byte tag) and fills the 14 byte stamp, returning 1, or 0 when it cannot (then the request is
 * cancelled and RNC_TIMEOUT returned, as the reference does when stamping times out). A stamped request is the 64 byte
 * form and always carries this node's id as transport id. Requests with a tag shorter than 16 bytes stay unstamped.
 * NULL removes the provider. The provider runs inside rnc_node_request_path*, on the caller's thread. */
typedef int (*rnc_stamp_provider_fn)(void *context, const uint8_t material[32], uint8_t stamp[14]);
rnc_result rnc_node_set_stamp_provider(rnc_node *node, rnc_stamp_provider_fn provider, void *context);
/* Link requests we send: a host calls rnc_node_stamp_link on each new link before rnc_link_open. The link then asks
 * for a stamped key when the destination announced a link request cost above 0 (see rnc_node_recall_link_cost), or,
 * with `always`, at the policy's lr_cost when it announced none. Unless the host sets its own stamper (for example
 * rnc_netstamp_link_stamper_run with a larger attempt budget), the node searches with its own random source for
 * up to 2^20 trials, as the reference stamps by default. A NULL stamper restores that default. */
rnc_result rnc_node_set_link_stamper(rnc_node *node, rnc_link_stamper_fn stamper, void *context, int always);
rnc_result rnc_node_stamp_link(const rnc_node *node, rnc_link *link, const uint8_t destination[16]);
/* The index'th local SINGLE destination (in the order they were added); RNC_AGAIN past the last. */
rnc_result rnc_node_destination_at(const rnc_node *node, size_t index, uint8_t destination[16]);
rnc_result rnc_node_destination_stamp_material(const rnc_node *node, const uint8_t destination[16], uint8_t out[90]);
rnc_result rnc_node_set_destination_stamp(rnc_node *node, const uint8_t destination[16], const uint8_t stamp[14]);
/* The link request cost a local destination announces and, with enforce_link_requests, requires (the policy's
 * lr_cost until set; 0 means none, at most 40). RNC_STATE for a destination that is not local. */
rnc_result rnc_node_set_destination_link_cost(rnc_node *node, const uint8_t destination[16], double cost);
rnc_result rnc_node_destination_link_cost(const rnc_node *node, const uint8_t destination[16], double *cost);
/* Before accepting a link request for `destination`: RNC_OK when stamps are not enforced for link requests,
 * the destination is not local, its cost is 0, or the request's encryption key meets the cost as a stamped key
 * over destination || signature key; RNC_AUTH when it does not; RNC_PROTOCOL when the request is too short. */
rnc_result rnc_node_check_link_request(const rnc_node *node, const uint8_t destination[16], const rnc_packet *request);
/* Ingress control as it stands on an interface (the reference's held_announces, ic_burst_active and the path
 * request equivalents). The since times are on the node's clock, and 0 when there is no burst. */
typedef struct rnc_node_ingress_state {
  size_t held_announces;
  int burst_active, pr_burst_active;
  uint64_t burst_since_ms, pr_burst_since_ms;
} rnc_node_ingress_state;
rnc_result rnc_node_interface_ingress(const rnc_node *node, uint32_t interface_id, rnc_node_ingress_state *state);
/* Announces discarded on an interface (a missing or insufficient stamp, a blackholed identity, nothing newer
 * than the known path), and path requests discarded for their stamp. */
rnc_result rnc_node_interface_filtered(const rnc_node *node, uint32_t interface_id, uint64_t *announces);
rnc_result rnc_node_interface_filtered_requests(const rnc_node *node, uint32_t interface_id, uint64_t *requests);
/* Known-destination store (Identity.recall). Every valid, fresh announce for
 * a non-local destination is remembered independently of path lifetime, in a
 * table bounded to RNC_NODE_KNOWN entries (least recently heard is evicted).
 * RNC_STATE means unknown. Newer announces replace older ones; replays do not. */
rnc_result rnc_node_recall(const rnc_node *node, const uint8_t destination[16],
                           rnc_announce *announce);
/* Versioned, SHA-256-sealed snapshot for host persistence. Import is atomic,
 * rejects any modification (RNC_AUTH) and entries whose destination does not
 * derive from their identity, and merges into the current table. */
rnc_result rnc_node_known_export(const rnc_node *node, void *output,
                                 size_t capacity, size_t *written);
rnc_result rnc_node_known_import(rnc_node *node, const void *input,
                                 size_t size);
rnc_result rnc_node_poll(rnc_node *node, rnc_node_event *event);
/* Bind a locally owned link before routing its packets (initiator or
 * responder). Transit links are installed by forwarded requests and activated
 * only after a valid destination proof on the expected interface/hop count. */
rnc_result rnc_node_bind_link(rnc_node *node, const uint8_t link_id[16]);
/* Prefer explicit binding from the outbound route or admitted request ingress.
 * Incoming packets never select or change a local link's output interface. */
rnc_result rnc_node_bind_link_on(rnc_node *node, const uint8_t link_id[16],
                                 uint32_t interface_id);
rnc_result rnc_node_unbind_link(rnc_node *node, const uint8_t link_id[16]);
/* Indexed snapshots for host administration. Expired routes are omitted. */
size_t rnc_node_link_count(const rnc_node *node, int active_only);
rnc_result rnc_node_route_at(const rnc_node *node, size_t ordinal,
                             uint64_t now_ms, rnc_route *route);
/* Announce rate table, the entries the reference reports over RPC as `rate_table`:
 * one per destination heard on an interface with an announce rate target. Times are the
 * node's monotonic milliseconds (the caller converts to wall time); at most
 * RNC_RATE_TIMESTAMPS recent announce times are kept, oldest first. RNC_AGAIN past the end. */
#ifndef RNC_RATE_TIMESTAMPS
#define RNC_RATE_TIMESTAMPS 16u
#endif
typedef struct rnc_rate_entry {
  uint8_t destination[16];
  unsigned violations;
  uint64_t last_ms, blocked_until_ms;
  size_t timestamp_count;
  uint64_t timestamps_ms[RNC_RATE_TIMESTAMPS];
} rnc_rate_entry;
rnc_result rnc_node_rate_at(const rnc_node *node, size_t ordinal, rnc_rate_entry *entry);
/* Owner-signed, versioned checkpoint of verified public routes/announces.
 * Export needs the node owner's private identity, import its public identity.
 * Import is atomic and only allowed into an empty learner with configured
 * interfaces. Expired/missing-interface records are skipped; rollback is an
 * error. Import/export allocate bounded temporary storage, perform no I/O. */
rnc_result rnc_node_state_export(const rnc_node *node,
                                 const rnc_identity *owner,
                                 uint64_t unix_seconds, uint64_t now_ms,
                                 void *output, size_t capacity,
                                 size_t *written);
rnc_result rnc_node_state_import(rnc_node *node, const rnc_identity *owner,
                                 uint64_t unix_seconds, uint64_t now_ms,
                                 const void *input, size_t size);
#ifdef __cplusplus
}
#endif
#endif
