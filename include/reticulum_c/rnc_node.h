#ifndef RETICULUM_C_NODE_H
#define RETICULUM_C_NODE_H
#include <reticulum_c/rnc.h>
#ifdef __cplusplus
extern "C" {
#endif
#define RNC_NODE_INTERFACES 8u
#define RNC_NODE_ROUTES 128u
#define RNC_NODE_DESTINATIONS 16u
#define RNC_NODE_LINKS 64u
#define RNC_NODE_EVENTS 64u
/* Interface ID zero is reserved for local delivery. Routing policy is bounded:
 * no automatic allocation/eviction after new; expire entries with tick(). */
typedef struct rnc_node rnc_node;
typedef struct rnc_path_request {
  uint8_t destination[16], transport_id[16], tag[16];
  size_t tag_size;
  int has_transport;
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
#define RNC_NODE_RECEIPTS 32u
#define RNC_NODE_KNOWN 256u
typedef struct rnc_node_event {
  rnc_node_event_type type;
  uint32_t interface_id;
  rnc_packet packet;
  rnc_route route;
  /* RNC_NODE_RECEIPT only: full packet hash, status and round trip time. */
  uint8_t receipt_hash[32];
  rnc_receipt_status receipt_status;
  uint64_t rtt_ms;
} rnc_node_event;
rnc_result rnc_path_request_create(const uint8_t destination[16],
                                   const uint8_t transport_id[16],
                                   const uint8_t *tag, size_t tag_size,
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
  RNC_MODE_BOUNDARY
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
  rnc_ingress_policy ingress;
} rnc_interface_policy;
rnc_result rnc_node_interface_policy(rnc_node *node, uint32_t interface_id,
                                     const rnc_interface_policy *policy);
rnc_result rnc_node_remove_interface(rnc_node *node, uint32_t interface_id);
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
/* Replaces the app data a SINGLE destination announces (up to 316 bytes), for
 * payloads that change between announces such as interface discovery. */
rnc_result rnc_node_set_destination_data(rnc_node *node,
                                         const uint8_t destination[16],
                                         const void *app_data, size_t size);
rnc_result rnc_node_announce(rnc_node *node, const uint8_t destination[16],
                             uint64_t unix_seconds, uint64_t now_ms);
rnc_result rnc_node_request_path(rnc_node *node, const uint8_t destination[16],
                                 uint64_t now_ms);
rnc_result rnc_node_input(rnc_node *node, uint32_t interface_id,
                          const rnc_packet *packet, uint64_t unix_seconds,
                          uint64_t now_ms);
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
#define RNC_NODE_TUNNELS 8u
#define RNC_NODE_TUNNEL_PATHS 16u
#define RNC_TUNNEL_TIMEOUT_MS (UINT64_C(8) * 3600u * 1000u)
typedef struct rnc_tunnel_info {
  uint8_t id[32];
  uint32_t interface_id; /* 0 while the interface is away */
  uint64_t expires_ms;
  size_t paths;
} rnc_tunnel_info;
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
#define RNC_NODE_BLACKHOLE 256
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
