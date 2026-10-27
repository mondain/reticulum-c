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
  RNC_RECEIPT_DELIVERED = 1,
  RNC_RECEIPT_FAILED
} rnc_receipt_status;
#define RNC_NODE_RECEIPTS 32u
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
typedef struct rnc_interface_policy {
  rnc_interface_mode mode;
  uint32_t announce_cap_permille;
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
/* Send a SINGLE DATA packet and track its delivery proof. A route to the
 * destination is required to learn the signer. Exactly one RNC_NODE_RECEIPT
 * event follows: DELIVERED on a valid proof, FAILED after timeout_ms. The
 * packet hash (also the receipt key) is returned in hash. */
rnc_result rnc_node_send_tracked(rnc_node *node, const rnc_packet *packet,
                                 uint64_t timeout_ms, uint64_t unix_seconds,
                                 uint64_t now_ms, uint8_t hash[32]);
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
