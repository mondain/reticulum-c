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
  else
    CHECK(0);
  puts("node stamps test passed");
  return 0;
}
