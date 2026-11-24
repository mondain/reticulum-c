/* Network stamps on announces as seen by the node (RNS 1.6): verification against the interface's required
 * cost, the announced link request cost, stripping the extension from delivered app data, enforcement. */
#include <reticulum_c/rnc_netstamp.h>
#include <reticulum_c/rnc_node.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                  \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static uint32_t seed = 5;
static rnc_result rng(void *ctx, uint8_t *p, size_t n) {
  size_t i;
  (void)ctx;
  for (i = 0; i < n; i++) {
    seed = seed * 1664525u + 1013904223u;
    p[i] = (uint8_t)(seed >> 24);
  }
  return RNC_OK;
}
static rnc_identity fresh(void) {
  rnc_identity id;
  CHECK(rnc_identity_generate(&id, rng, NULL) == RNC_OK);
  return id;
}
typedef enum { UNSTAMPED, VALID, WEAK } kind;
/* An announce for `name`; with VALID the extension carries a stamp found at `cost`, with WEAK a stamp that fails it. */
static rnc_packet announce(const rnc_identity *id, const char *name, const char *app, kind k, double cost,
                           double link_cost, uint64_t unix_seconds) {
  rnc_packet probe, p;
  uint8_t data[200], material[90], stamp[RNC_NETSTAMP_SIZE], ext[RNC_NETSTAMP_EXT_SIZE];
  size_t app_size = app ? strlen(app) : 0, n = app_size;
  if (app) memcpy(data, app, app_size);
  CHECK(rnc_announce_create(id, name, NULL, 0, unix_seconds, rng, NULL, &probe) == RNC_OK);
  if (k != UNSTAMPED) {
    rnc_netstamp_announce_material(probe.destination, id->public_key, probe.data + 64, material);
    if (k == VALID) {
      CHECK(rnc_netstamp_find(material, sizeof(material), cost, rng, NULL, 0, stamp, NULL) == RNC_OK);
    } else {
      do CHECK(rng(NULL, stamp, sizeof(stamp)) == RNC_OK);
      while (rnc_netstamp_valid(material, sizeof(material), stamp, sizeof(stamp), cost));
    }
    CHECK(rnc_netstamp_ext_build(stamp, link_cost, ext) == RNC_OK);
    memcpy(data + n, ext, sizeof(ext));
    n += sizeof(ext);
  }
  CHECK(rnc_announce_create(id, name, n ? data : NULL, n, unix_seconds, rng, NULL, &p) == RNC_OK);
  return p;
}
static rnc_node *transport_node(void) {
  rnc_identity me = fresh();
  rnc_node *n = rnc_node_new(&me, 1, rng, NULL);
  CHECK(n && rnc_node_add_interface(n, 1, 1000000) == RNC_OK && rnc_node_add_interface(n, 2, 1000000) == RNC_OK);
  return n;
}
static int learned(rnc_node *n, const rnc_packet *p) {
  rnc_route r;
  return rnc_node_lookup(n, p->destination, 1000, &r) == RNC_OK;
}
/* Verification on, enforcement off (the 1.6.1 default): everything is accepted; only a valid stamp is recorded. */
static void unenforced(void) {
  rnc_node *n = transport_node();
  rnc_identity a = fresh(), b = fresh();
  rnc_packet pa, pb;
  rnc_announce got;
  double link = 0;
  uint64_t filtered = 99;
  CHECK(rnc_node_set_interface_stamp_costs(n, 1, 8.0, -1) == RNC_OK);
  pa = announce(&a, "stamp.plain", "x", UNSTAMPED, 0, 0, 1000);
  pb = announce(&b, "stamp.weak", NULL, WEAK, 8.0, 12.5, 1000);
  CHECK(rnc_node_input(n, 1, &pa, 1000, 1) == RNC_OK && rnc_node_input(n, 1, &pb, 1000, 2) == RNC_OK);
  CHECK(learned(n, &pa) && learned(n, &pb));
  CHECK(rnc_node_recall_link_cost(n, pa.destination, &link) == RNC_STATE);
  CHECK(rnc_node_recall_link_cost(n, pb.destination, &link) == RNC_STATE); /* an insufficient stamp is not recorded */
  CHECK(rnc_node_recall(n, pb.destination, &got) == RNC_OK && got.app_size == RNC_NETSTAMP_EXT_SIZE); /* left in place */
  CHECK(rnc_node_interface_filtered(n, 1, &filtered) == RNC_OK && filtered == 0);
  rnc_node_free(n);
}
static void valid_stamp(void) {
  rnc_node *n = transport_node();
  rnc_identity a = fresh();
  rnc_packet p;
  rnc_announce got;
  double link = 0;
  CHECK(rnc_node_set_interface_stamp_costs(n, 1, 8.0, -1) == RNC_OK);
  p = announce(&a, "stamp.valid", "hi", VALID, 9.0, 12.5, 1000);
  CHECK(rnc_node_input(n, 1, &p, 1000, 1) == RNC_OK && learned(n, &p));
  CHECK(rnc_node_recall(n, p.destination, &got) == RNC_OK && got.app_size == 2 && !memcmp(got.app_data, "hi", 2));
  CHECK(rnc_node_recall_link_cost(n, p.destination, &link) == RNC_OK && link == 12.5);
  rnc_node_free(n);
}
/* With enforcement on, an announce without a sufficient stamp is dropped and counted on its interface. */
static void enforced(void) {
  rnc_node *n = transport_node();
  rnc_identity a = fresh(), b = fresh(), c = fresh();
  rnc_packet none, weak, good;
  rnc_stamp_policy policy;
  uint64_t filtered = 0;
  CHECK(rnc_node_stamp_policy(n, &policy) == RNC_OK && policy.enabled && !policy.enforce_announces &&
        policy.destination_cost == 23.5 && policy.pr_cost == 15.8);
  policy.enforce_announces = 1;
  policy.destination_cost = 8.0;
  CHECK(rnc_node_set_stamp_policy(n, &policy) == RNC_OK);
  none = announce(&a, "stamp.none", NULL, UNSTAMPED, 0, 0, 1000);
  weak = announce(&b, "stamp.weak2", NULL, WEAK, 8.0, 12.5, 1000);
  good = announce(&c, "stamp.good", NULL, VALID, 8.0, 12.5, 1000);
  CHECK(rnc_node_input(n, 1, &none, 1000, 1) == RNC_OK && !learned(n, &none));
  CHECK(rnc_node_input(n, 1, &weak, 1000, 2) == RNC_OK && !learned(n, &weak));
  CHECK(rnc_node_interface_filtered(n, 1, &filtered) == RNC_OK && filtered == 2);
  CHECK(rnc_node_input(n, 1, &good, 1000, 3) == RNC_OK && learned(n, &good));
  /* nothing was passed on for the dropped ones */
  {
    rnc_node_event e;
    unsigned sends = 0;
    CHECK(rnc_node_tick(n, 1000, 10000) == RNC_OK);
    while (rnc_node_poll(n, &e) == RNC_OK)
      sends += e.type == RNC_NODE_SEND && !memcmp(e.packet.destination, none.destination, 16);
    CHECK(sends == 0);
  }
  rnc_node_free(n);
}
/* An interface's own required cost beats the global one; the others keep the global cost. */
static void per_interface(void) {
  rnc_node *n = transport_node();
  rnc_identity a = fresh(), b = fresh();
  rnc_packet p, q;
  rnc_stamp_policy policy;
  CHECK(rnc_node_stamp_policy(n, &policy) == RNC_OK);
  policy.enforce_announces = 1;
  policy.destination_cost = 30.0; /* nobody meets this in a test */
  CHECK(rnc_node_set_stamp_policy(n, &policy) == RNC_OK);
  CHECK(rnc_node_set_interface_stamp_costs(n, 1, 8.0, -1) == RNC_OK);
  p = announce(&a, "stamp.if1", NULL, VALID, 8.0, 12.5, 1000);
  q = announce(&b, "stamp.if2", NULL, VALID, 8.0, 12.5, 1000);
  CHECK(rnc_node_input(n, 1, &p, 1000, 1) == RNC_OK && learned(n, &p));
  CHECK(rnc_node_input(n, 2, &q, 1000, 2) == RNC_OK && !learned(n, &q));
  CHECK(rnc_node_set_interface_stamp_costs(n, 9, 8.0, -1) == RNC_STATE);
  CHECK(rnc_node_set_interface_stamp_costs(n, 1, 500.0, -1) == RNC_INVALID);
  rnc_node_free(n);
}
/* An announce is passed on byte for byte, extension included, so peers can check the stamp themselves. */
static void relayed_unchanged(void) {
  rnc_node *n = transport_node();
  rnc_identity a = fresh();
  rnc_packet p;
  rnc_node_event e;
  int seen = 0;
  CHECK(rnc_node_set_interface_stamp_costs(n, 1, 8.0, -1) == RNC_OK);
  p = announce(&a, "stamp.relay", "app", VALID, 8.0, 12.5, 1000);
  CHECK(rnc_node_input(n, 1, &p, 1000, 1) == RNC_OK);
  CHECK(rnc_node_tick(n, 1000, 20000) == RNC_OK);
  while (rnc_node_poll(n, &e) == RNC_OK)
    if (e.type == RNC_NODE_SEND && e.interface_id == 2 && !memcmp(e.packet.destination, p.destination, 16)) {
      CHECK(e.packet.data_size == p.data_size && !memcmp(e.packet.data, p.data, p.data_size));
      seen = 1;
    }
  CHECK(seen);
  rnc_node_free(n);
}
/* ---- path requests ---- */
static uint64_t clock_ms = 100; /* the node's clock only moves forward */
static unsigned answers(rnc_node *n, const uint8_t dest[16]) {
  rnc_node_event e;
  unsigned sends = 0;
  clock_ms += 3000;
  CHECK(rnc_node_tick(n, 1000 + clock_ms / 1000, clock_ms) == RNC_OK);
  while (rnc_node_poll(n, &e) == RNC_OK)
    sends += e.type == RNC_NODE_SEND && e.packet.context == 0x0b && !memcmp(e.packet.destination, dest, 16);
  return sends;
}
/* A path request for `dest` of the given kind: legacy 32 bytes, 48 with a transport id, 64 stamped. */
static rnc_packet request(const uint8_t dest[16], kind k, double cost, size_t wire_size) {
  rnc_packet p;
  uint8_t tid[16], tag[16], material[32], stamp[RNC_NETSTAMP_SIZE];
  CHECK(rng(NULL, tid, 16) == RNC_OK && rng(NULL, tag, 16) == RNC_OK);
  if (k == UNSTAMPED) {
    CHECK(rnc_path_request_create(dest, wire_size == 32 ? NULL : tid, tag, 16, &p) == RNC_OK);
    return p;
  }
  memcpy(material, dest, 16);
  memcpy(material + 16, tag, 16);
  if (k == VALID) {
    CHECK(rnc_netstamp_find(material, 32, cost, rng, NULL, 0, stamp, NULL) == RNC_OK);
  } else {
    do CHECK(rng(NULL, stamp, sizeof(stamp)) == RNC_OK);
    while (rnc_netstamp_valid(material, 32, stamp, sizeof(stamp), cost));
  }
  CHECK(rnc_path_request_create_stamped(dest, tid, tag, 16, stamp, &p) == RNC_OK && p.data_size == 64);
  return p;
}
static rnc_node *owner(uint8_t dest[16]) {
  rnc_identity me = fresh();
  rnc_node *n = rnc_node_new(&me, 1, rng, NULL);
  CHECK(n && rnc_node_add_interface(n, 1, 1000000) == RNC_OK && rnc_node_add_interface(n, 2, 1000000) == RNC_OK);
  CHECK(rnc_node_add_destination(n, &me, "stamp.owner", NULL, 0, dest) == RNC_OK);
  return n;
}
/* The reference accepts path requests of exactly 32, 48 and 64 bytes; shorter than 16 is ignored and anything
 * else is a protocol violation. Nothing reads past the data. */
static void pr_lengths(void) {
  uint8_t dest[16];
  rnc_node *n = owner(dest);
  size_t sizes[] = {17, 31, 33, 47, 49, 63, 65, 90}, i;
  rnc_packet p;
  p = request(dest, UNSTAMPED, 0, 32);
  CHECK(p.data_size == 32 && rnc_node_input(n, 1, &p, 1000, ++clock_ms) == RNC_OK);
  p = request(dest, UNSTAMPED, 0, 48);
  CHECK(p.data_size == 48 && rnc_node_input(n, 1, &p, 1000, ++clock_ms) == RNC_OK);
  p = request(dest, VALID, 4.0, 64);
  CHECK(rnc_node_input(n, 1, &p, 1000, ++clock_ms) == RNC_OK);
  CHECK(answers(n, dest) >= 1);
  for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
    p = request(dest, UNSTAMPED, 0, 48);
    memset(p.data + 48, 0xa5, sizeof(p.data) - 48 > 64 ? 64 : sizeof(p.data) - 48);
    p.data_size = sizes[i];
    CHECK(rnc_node_input(n, 1, &p, 1000, ++clock_ms) == RNC_PROTOCOL);
  }
  rnc_node_free(n);
}
static void pr_stamp(void) {
  uint8_t dest[16];
  rnc_node *n = owner(dest);
  rnc_stamp_policy policy;
  rnc_packet p;
  uint64_t filtered = 99;
  CHECK(rnc_node_stamp_policy(n, &policy) == RNC_OK);
  policy.enforce_announces = 1;
  policy.pr_cost = 8.0;
  CHECK(rnc_node_set_stamp_policy(n, &policy) == RNC_OK);
  p = request(dest, UNSTAMPED, 0, 48);
  CHECK(rnc_node_input(n, 1, &p, 1000, ++clock_ms) == RNC_OK && answers(n, dest) == 0);
  p = request(dest, WEAK, 8.0, 64);
  CHECK(rnc_node_input(n, 1, &p, 1000, ++clock_ms) == RNC_OK && answers(n, dest) == 0);
  CHECK(rnc_node_interface_filtered_requests(n, 1, &filtered) == RNC_OK && filtered == 2);
  p = request(dest, VALID, 8.0, 64);
  CHECK(rnc_node_input(n, 1, &p, 1000, ++clock_ms) == RNC_OK && answers(n, dest) >= 1);
  /* an interface's own cost wins over the policy's */
  CHECK(rnc_node_set_interface_stamp_costs(n, 2, -1, 20.0) == RNC_OK);
  p = request(dest, VALID, 8.0, 64);
  CHECK(rnc_node_input(n, 2, &p, 1000, ++clock_ms) == RNC_OK && answers(n, dest) == 0);
  rnc_node_free(n);
}
static void pr_unenforced(void) {
  uint8_t dest[16];
  rnc_node *n = owner(dest);
  rnc_packet p;
  p = request(dest, UNSTAMPED, 0, 48);
  CHECK(rnc_node_input(n, 1, &p, 1000, ++clock_ms) == RNC_OK && answers(n, dest) >= 1);
  p = request(dest, WEAK, 8.0, 64);
  CHECK(rnc_node_input(n, 1, &p, 1000, ++clock_ms) == RNC_OK && answers(n, dest) >= 1);
  rnc_node_free(n);
}
/* ---- link requests ---- */
/* A link request the way Link.__init__ builds it: encryption public key, signature public key, MTU signalling.
 * With VALID the encryption key is a stamped key found at `cost` over destination || signature key. */
static rnc_packet link_request(const uint8_t dest[16], kind k, double cost) {
  rnc_packet p = {0};
  uint8_t material[48], priv[32];
  rnc_identity peer = fresh();
  p.flags = 2; /* LINKREQUEST, header 1, broadcast */
  memcpy(p.destination, dest, 16);
  memcpy(p.data, peer.public_key, 32);
  memcpy(p.data + 32, peer.public_key + 32, 32);
  p.data[64] = 0x21; p.data[65] = 0xf4; p.data[66] = 0x00; /* signalling bytes, not interpreted here */
  p.data_size = 67;
  memcpy(material, dest, 16);
  memcpy(material + 16, p.data + 32, 32);
  if (k == VALID) {
    CHECK(rnc_netstamp_find_key(material, 48, cost, rng, NULL, 0, priv, p.data, NULL) == RNC_OK);
  } else if (k == WEAK) {
    while (rnc_netstamp_valid(material, 48, p.data, 32, cost))
      CHECK(rng(NULL, p.data, 32) == RNC_OK);
  }
  return p;
}
static void lr_unenforced(void) {
  uint8_t dest[16];
  rnc_node *n = owner(dest);
  rnc_packet p = link_request(dest, UNSTAMPED, 0);
  CHECK(rnc_node_check_link_request(n, dest, &p) == RNC_OK);
  rnc_node_free(n);
}
static void lr_enforced(void) {
  uint8_t dest[16], other[16];
  rnc_node *n = owner(dest);
  rnc_stamp_policy policy;
  rnc_packet p;
  double cost = 0;
  CHECK(rnc_node_stamp_policy(n, &policy) == RNC_OK && policy.lr_cost == 12.5);
  policy.enforce_link_requests = 1;
  policy.lr_cost = 8.0;
  CHECK(rnc_node_set_stamp_policy(n, &policy) == RNC_OK);
  CHECK(rnc_node_destination_link_cost(n, dest, &cost) == RNC_OK && cost == 8.0); /* the policy's until set */
  p = link_request(dest, UNSTAMPED, 0);
  CHECK(rnc_node_check_link_request(n, dest, &p) == RNC_AUTH);
  p = link_request(dest, WEAK, 8.0);
  CHECK(rnc_node_check_link_request(n, dest, &p) == RNC_AUTH);
  p = link_request(dest, VALID, 8.0);
  CHECK(rnc_node_check_link_request(n, dest, &p) == RNC_OK);
  p.data_size = 40; /* too short to hold both keys */
  CHECK(rnc_node_check_link_request(n, dest, &p) == RNC_PROTOCOL);
  /* a destination's own cost wins; zero turns the requirement off for it */
  CHECK(rnc_node_set_destination_link_cost(n, dest, 0.0) == RNC_OK);
  p = link_request(dest, UNSTAMPED, 0);
  CHECK(rnc_node_check_link_request(n, dest, &p) == RNC_OK);
  CHECK(rnc_node_set_destination_link_cost(n, dest, 10.0) == RNC_OK && rnc_node_destination_link_cost(n, dest, &cost) == RNC_OK && cost == 10.0);
  p = link_request(dest, VALID, 8.0); /* 8.0 does not meet 10.0 (unless the search got lucky) */
  {
    uint8_t material[48];
    memcpy(material, dest, 16);
    memcpy(material + 16, p.data + 32, 32);
    CHECK(rnc_node_check_link_request(n, dest, &p) == (rnc_netstamp_valid(material, 48, p.data, 32, 10.0) ? RNC_OK : RNC_AUTH));
  }
  CHECK(rnc_node_set_destination_link_cost(n, dest, 500.0) == RNC_INVALID);
  memset(other, 0x42, 16);
  CHECK(rnc_node_set_destination_link_cost(n, other, 5.0) == RNC_STATE);
  CHECK(rnc_node_check_link_request(n, other, &p) == RNC_OK); /* not one of ours: nothing to enforce */
  rnc_node_free(n);
}
/* ---- emitting a stamp on our own announces ---- */
static rnc_packet sent_announce(rnc_node *n, uint16_t context) {
  rnc_node_event e;
  rnc_packet none = {0};
  clock_ms += 3000;
  CHECK(rnc_node_tick(n, 1000 + clock_ms / 1000, clock_ms) == RNC_OK);
  while (rnc_node_poll(n, &e) == RNC_OK)
    if (e.type == RNC_NODE_SEND && e.interface_id == 1 && (e.packet.flags & 3u) == RNC_ANNOUNCE &&
        e.packet.context == context)
      return e.packet;
  CHECK(0);
  return none;
}
static void find_for(rnc_node *n, const uint8_t dest[16], double cost, uint8_t stamp[RNC_NETSTAMP_SIZE]) {
  uint8_t material[90];
  CHECK(rnc_node_destination_stamp_material(n, dest, material) == RNC_OK);
  CHECK(rnc_netstamp_find(material, sizeof(material), cost, rng, NULL, 0, stamp, NULL) == RNC_OK);
}
static void emit_with_stamp(void) {
  uint8_t dest[16], stamp[RNC_NETSTAMP_SIZE], material[90];
  rnc_node *n = owner(dest);
  rnc_packet p;
  rnc_announce a;
  rnc_netstamp_ext ext;
  CHECK(rnc_node_set_stamp_emission(n, 0, 8.0) == RNC_OK);
  find_for(n, dest, 8.0, stamp);
  CHECK(rnc_node_set_destination_stamp(n, dest, stamp) == RNC_OK);
  CHECK(rnc_node_announce(n, dest, 1000, ++clock_ms) == RNC_OK);
  p = sent_announce(n, 0);
  CHECK(rnc_announce_verify(&p, &a) == RNC_OK); /* the signature covers the extension */
  CHECK(rnc_netstamp_ext_parse(a.app_data, a.app_size, &ext) == 1 && ext.app_size == 0 && ext.link_cost == 12.5);
  rnc_netstamp_announce_material(a.destination, a.identity.public_key, a.name_hash, material);
  CHECK(rnc_netstamp_valid(material, sizeof(material), ext.stamp, sizeof(ext.stamp), 8.0));
  /* the destination's own link cost is what is announced */
  CHECK(rnc_node_set_destination_link_cost(n, dest, 20.0) == RNC_OK);
  CHECK(rnc_node_announce(n, dest, 1001, ++clock_ms) == RNC_OK);
  p = sent_announce(n, 0);
  CHECK(rnc_announce_verify(&p, &a) == RNC_OK && rnc_netstamp_ext_parse(a.app_data, a.app_size, &ext) == 1 &&
        ext.link_cost == 20.0);
  /* so is the answer to a path request */
  {
    rnc_packet pr = request(dest, UNSTAMPED, 0, 48);
    CHECK(rnc_node_input(n, 1, &pr, 1000, ++clock_ms) == RNC_OK);
    p = sent_announce(n, 0x0b);
    CHECK(rnc_announce_verify(&p, &a) == RNC_OK && rnc_netstamp_ext_parse(a.app_data, a.app_size, &ext) == 1);
  }
  rnc_node_free(n);
}
static void emit_required(void) {
  uint8_t dest[16], stamp[RNC_NETSTAMP_SIZE];
  rnc_node *n = owner(dest);
  rnc_packet p;
  rnc_announce a;
  rnc_netstamp_ext ext;
  /* not required (the default): announces go out unstamped, as before */
  CHECK(rnc_node_announce(n, dest, 1000, ++clock_ms) == RNC_OK);
  p = sent_announce(n, 0);
  CHECK(rnc_announce_verify(&p, &a) == RNC_OK && !rnc_netstamp_ext_parse(a.app_data, a.app_size, &ext));
  /* required and no stamp yet: the host is told to come back */
  CHECK(rnc_node_set_stamp_emission(n, 1, 8.0) == RNC_OK);
  CHECK(rnc_node_announce(n, dest, 1001, ++clock_ms) == RNC_AGAIN);
  find_for(n, dest, 8.0, stamp);
  CHECK(rnc_node_set_destination_stamp(n, dest, stamp) == RNC_OK);
  CHECK(rnc_node_announce(n, dest, 1002, ++clock_ms) == RNC_OK);
  p = sent_announce(n, 0);
  CHECK(rnc_announce_verify(&p, &a) == RNC_OK && rnc_netstamp_ext_parse(a.app_data, a.app_size, &ext) == 1);
  rnc_node_free(n);
}
static void emit_rejects(void) {
  uint8_t dest[16], other[16], stamp[RNC_NETSTAMP_SIZE], material[90];
  rnc_node *n = owner(dest);
  CHECK(rnc_node_set_stamp_emission(n, 0, 8.0) == RNC_OK);
  CHECK(rnc_node_destination_stamp_material(n, dest, material) == RNC_OK);
  do CHECK(rng(NULL, stamp, sizeof(stamp)) == RNC_OK);
  while (rnc_netstamp_valid(material, sizeof(material), stamp, sizeof(stamp), 8.0));
  CHECK(rnc_node_set_destination_stamp(n, dest, stamp) == RNC_AUTH);
  memset(other, 0x42, 16);
  CHECK(rnc_node_set_destination_stamp(n, other, stamp) == RNC_STATE);
  CHECK(rnc_node_destination_stamp_material(n, other, material) == RNC_STATE);
  CHECK(rnc_node_set_stamp_emission(n, 0, 101.0) == RNC_INVALID);
  /* the local SINGLE destinations can be listed, to find the ones that still need a stamp */
  CHECK(rnc_node_destination_at(n, 0, other) == RNC_OK && !memcmp(other, dest, 16));
  CHECK(rnc_node_destination_at(n, 1, other) == RNC_AGAIN);
  rnc_node_free(n);
}
/* Destination app data and the 18 byte extension share the 316 byte limit: when they do not fit, the announce
 * goes out without the stamp (and with all of its app data). */
static void emit_overlong(void) {
  rnc_identity me = fresh();
  rnc_node *n = rnc_node_new(&me, 1, rng, NULL);
  uint8_t dest[16], stamp[RNC_NETSTAMP_SIZE], big[300], fits[298];
  rnc_packet p;
  rnc_announce a;
  rnc_netstamp_ext ext;
  CHECK(n && rnc_node_add_interface(n, 1, 1000000) == RNC_OK);
  memset(big, 'x', sizeof(big));
  memset(fits, 'y', sizeof(fits));
  CHECK(rnc_node_set_stamp_emission(n, 0, 8.0) == RNC_OK);
  CHECK(rnc_node_add_destination(n, &me, "stamp.big", big, sizeof(big), dest) == RNC_OK);
  find_for(n, dest, 8.0, stamp);
  CHECK(rnc_node_set_destination_stamp(n, dest, stamp) == RNC_OK);
  CHECK(rnc_node_announce(n, dest, 1000, ++clock_ms) == RNC_OK);
  p = sent_announce(n, 0);
  CHECK(rnc_announce_verify(&p, &a) == RNC_OK && a.app_size == 300 && !rnc_netstamp_ext_parse(a.app_data, a.app_size, &ext));
  CHECK(rnc_node_add_destination(n, &me, "stamp.fits", fits, sizeof(fits), dest) == RNC_OK); /* 298 + 18 = 316 */
  find_for(n, dest, 8.0, stamp);
  CHECK(rnc_node_set_destination_stamp(n, dest, stamp) == RNC_OK);
  CHECK(rnc_node_announce(n, dest, 1001, ++clock_ms) == RNC_OK);
  p = sent_announce(n, 0);
  CHECK(rnc_announce_verify(&p, &a) == RNC_OK && rnc_netstamp_ext_parse(a.app_data, a.app_size, &ext) == 1 &&
        ext.app_size == 298);
  rnc_node_free(n);
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  if (!strcmp(argv[1], "unenforced"))
    unenforced();
  else if (!strcmp(argv[1], "valid"))
    valid_stamp();
  else if (!strcmp(argv[1], "enforced"))
    enforced();
  else if (!strcmp(argv[1], "per_interface"))
    per_interface();
  else if (!strcmp(argv[1], "relayed_unchanged"))
    relayed_unchanged();
  else if (!strcmp(argv[1], "pr_lengths"))
    pr_lengths();
  else if (!strcmp(argv[1], "pr_stamp"))
    pr_stamp();
  else if (!strcmp(argv[1], "pr_unenforced"))
    pr_unenforced();
  else if (!strcmp(argv[1], "lr_unenforced"))
    lr_unenforced();
  else if (!strcmp(argv[1], "lr_enforced"))
    lr_enforced();
  else if (!strcmp(argv[1], "emit_with_stamp"))
    emit_with_stamp();
  else if (!strcmp(argv[1], "emit_required"))
    emit_required();
  else if (!strcmp(argv[1], "emit_rejects"))
    emit_rejects();
  else if (!strcmp(argv[1], "emit_overlong"))
    emit_overlong();
  else
    CHECK(0);
  puts("node stamps test passed");
  return 0;
}
