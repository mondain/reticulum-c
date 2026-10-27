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
static uint32_t seed = 77;
static rnc_result rng(void *ctx, uint8_t *p, size_t n) {
  size_t i;
  (void)ctx;
  for (i = 0; i < n; i++) {
    seed = seed * 1664525u + 1013904223u;
    p[i] = (uint8_t)(seed >> 24);
  }
  return RNC_OK;
}
static rnc_node *make(rnc_identity *own) {
  rnc_node *n;
  CHECK(rnc_identity_generate(own, rng, NULL) == RNC_OK);
  n = rnc_node_new(own, 0, rng, NULL);
  CHECK(n && rnc_node_add_interface(n, 1, 1000000) == RNC_OK);
  return n;
}
static rnc_packet announce(rnc_identity *id, const char *name,
                           uint64_t unix_seconds) {
  rnc_packet p;
  CHECK(rnc_announce_create(id, name, NULL, 0, unix_seconds, rng, NULL, &p) ==
        RNC_OK);
  return p;
}
/* An announce from a blackholed identity is dropped, a lifted one accepted. */
static void drops_announces(void) {
  rnc_identity own, peer;
  rnc_node *n = make(&own);
  rnc_packet p;
  rnc_route r;
  CHECK(rnc_identity_generate(&peer, rng, NULL) == RNC_OK);
  CHECK(rnc_node_blackhole(n, peer.hash, 0, "spam", 1000) == RNC_OK);
  CHECK(rnc_node_is_blackholed(n, peer.hash, 1000));
  p = announce(&peer, "bh.drop", 1000);
  CHECK(rnc_node_input(n, 1, &p, 1000, 0) == RNC_OK);
  CHECK(rnc_node_lookup(n, p.destination, 0, &r) == RNC_AGAIN);
  CHECK(rnc_node_unblackhole(n, peer.hash) == RNC_OK);
  CHECK(!rnc_node_is_blackholed(n, peer.hash, 1000));
  p = announce(&peer, "bh.drop", 1001);
  CHECK(rnc_node_input(n, 1, &p, 1001, 10) == RNC_OK);
  CHECK(rnc_node_lookup(n, p.destination, 10, &r) == RNC_OK);
  rnc_node_free(n);
}
/* Blackholing removes paths that already exist for the identity. */
static void removes_paths(void) {
  rnc_identity own, peer;
  rnc_node *n = make(&own);
  rnc_packet p;
  rnc_route r;
  CHECK(rnc_identity_generate(&peer, rng, NULL) == RNC_OK);
  p = announce(&peer, "bh.path", 1000);
  CHECK(rnc_node_input(n, 1, &p, 1000, 0) == RNC_OK);
  CHECK(rnc_node_lookup(n, p.destination, 0, &r) == RNC_OK);
  CHECK(rnc_node_blackhole(n, peer.hash, 0, NULL, 1000) == RNC_OK);
  CHECK(rnc_node_lookup(n, p.destination, 1, &r) == RNC_AGAIN);
  rnc_node_free(n);
}
static void state_and_bounds(void) {
  rnc_identity own;
  rnc_node *n = make(&own);
  uint8_t id[16] = {1};
  unsigned i;
  rnc_blackhole_entry e;
  CHECK(rnc_node_unblackhole(n, id) == RNC_STATE);
  CHECK(rnc_node_blackhole(n, id, 0, "first", 5) == RNC_OK);
  CHECK(rnc_node_blackhole(n, id, 0, "again", 5) == RNC_STATE);
  CHECK(rnc_node_blackhole_at(n, 0, 5, &e) == RNC_OK &&
        !memcmp(e.identity, id, 16) && !memcmp(e.source, own.hash, 16) &&
        !strcmp(e.reason, "first") && e.until == 0);
  CHECK(rnc_node_blackhole_at(n, 1, 5, &e) == RNC_AGAIN);
  for (i = 1; i < RNC_NODE_BLACKHOLE; ++i) {
    uint8_t other[16] = {0};
    other[0] = (uint8_t)(i >> 8);
    other[1] = (uint8_t)i;
    other[2] = 9;
    CHECK(rnc_node_blackhole(n, other, 0, NULL, 5) == RNC_OK);
  }
  {
    uint8_t extra[16] = {0xff, 0xff, 0xff};
    CHECK(rnc_node_blackhole(n, extra, 0, NULL, 5) == RNC_AGAIN);
  }
  CHECK(rnc_node_blackhole(NULL, id, 0, NULL, 5) == RNC_INVALID);
  rnc_node_free(n);
}
/* `until` is a unix time; the entry lapses on its own. */
static void expiry(void) {
  rnc_identity own, peer;
  rnc_node *n = make(&own);
  rnc_packet p;
  rnc_route r;
  rnc_blackhole_entry e;
  CHECK(rnc_identity_generate(&peer, rng, NULL) == RNC_OK);
  CHECK(rnc_node_blackhole(n, peer.hash, 1010, "temp", 1000) == RNC_OK);
  p = announce(&peer, "bh.expiry", 1005);
  CHECK(rnc_node_input(n, 1, &p, 1005, 0) == RNC_OK);
  CHECK(rnc_node_lookup(n, p.destination, 0, &r) == RNC_AGAIN);
  CHECK(rnc_node_is_blackholed(n, peer.hash, 1009));
  CHECK(!rnc_node_is_blackholed(n, peer.hash, 1011));
  CHECK(rnc_node_blackhole_at(n, 0, 1011, &e) == RNC_AGAIN);
  p = announce(&peer, "bh.expiry", 1012);
  CHECK(rnc_node_input(n, 1, &p, 1012, 20) == RNC_OK);
  CHECK(rnc_node_lookup(n, p.destination, 20, &r) == RNC_OK);
  /* the freed slot can be reused after the sweep in tick */
  CHECK(rnc_node_blackhole(n, peer.hash, 5000, NULL, 1012) == RNC_OK);
  rnc_node_free(n);
}
/* A file written by the reference (umsgpack, float `until`) imports as is. */
static void reads_reference_file(void) {
  /* umsgpack.packb({b"\x11"*16: {"source": b"\x33"*16, "until": 4000000000.5,
   *                              "reason": None}}) */
  static const char hex[] =
      "81c4101111111111111111111111111111111183a6736f75726365c41033333333"
      "333333333333333333333333a5756e74696ccb41edcd6500100000a6726561736f6e"
      "c0";
  uint8_t blob[128], id[16];
  size_t k, n = (sizeof(hex) - 1) / 2;
  rnc_identity own;
  rnc_node *node = make(&own);
  rnc_blackhole_entry e;
  for (k = 0; k < n; ++k) {
    unsigned v;
    CHECK(sscanf(hex + 2 * k, "%2x", &v) == 1);
    blob[k] = (uint8_t)v;
  }
  memset(id, 0x11, 16);
  CHECK(rnc_node_blackhole_import(node, blob, n, NULL, 100) == RNC_OK);
  CHECK(rnc_node_blackhole_at(node, 0, 100, &e) == RNC_OK &&
        !memcmp(e.identity, id, 16) && e.until == 4000000000u &&
        e.reason[0] == 0);
  /* already lapsed when loaded: skipped */
  rnc_node_free(node);
  node = make(&own);
  CHECK(rnc_node_blackhole_import(node, blob, n, NULL, 4000000001u) == RNC_OK);
  CHECK(!rnc_node_is_blackholed(node, id, 4000000001u));
  rnc_node_free(node);
}
/* Reference file format and import rules. */
static void persistence(void) {
  rnc_identity own;
  rnc_node *n = make(&own), *m;
  uint8_t id[16], remote[16], source[16], blob[512];
  size_t written, k;
  rnc_blackhole_entry e;
  memset(id, 0x11, 16);
  memset(remote, 0x22, 16);
  memset(source, 0x33, 16);
  CHECK(rnc_node_blackhole(n, id, 0, "abuse", 100) == RNC_OK);
  CHECK(rnc_node_blackhole_import(n, NULL, 0, source, 100) == RNC_INVALID);
  CHECK(rnc_node_blackhole_export(n, blob, sizeof(blob), &written) == RNC_OK);
  /* {id: {"source": bin16, "until": nil, "reason": "abuse"}} */
  CHECK(blob[0] == 0x81 && blob[1] == 0xc4 && blob[2] == 16 &&
        !memcmp(blob + 3, id, 16) && blob[19] == 0x83 && blob[20] == 0xa6 &&
        !memcmp(blob + 21, "source", 6) && blob[27] == 0xc4 && blob[28] == 16 &&
        !memcmp(blob + 29, own.hash, 16) && blob[45] == 0xa5 &&
        !memcmp(blob + 46, "until", 5) && blob[51] == 0xc0 &&
        blob[52] == 0xa6 && !memcmp(blob + 53, "reason", 6) &&
        blob[59] == 0xa5 && !memcmp(blob + 60, "abuse", 5) && written == 65);
  CHECK(rnc_node_blackhole_export(n, blob, 10, &written) == RNC_NO_SPACE);
  m = make(&own);
  CHECK(rnc_node_blackhole_import(m, blob, 65, NULL, 100) == RNC_OK);
  CHECK(rnc_node_is_blackholed(m, id, 100));
  CHECK(rnc_node_blackhole_at(m, 0, 100, &e) == RNC_OK &&
        !strcmp(e.reason, "abuse"));
  /* a remote source's entries are kept but not exported, and a local entry
   * is never overridden by them */
  CHECK(rnc_node_blackhole(m, remote, 0, NULL, 100) == RNC_OK);
  CHECK(rnc_node_blackhole_import(m, blob, 65, source, 100) == RNC_OK);
  CHECK(rnc_node_blackhole_at(m, 0, 100, &e) == RNC_OK &&
        !memcmp(e.source, own.hash, 16));
  rnc_node_free(m);
  m = make(&own);
  CHECK(rnc_node_blackhole_import(m, blob, 65, source, 100) == RNC_OK);
  CHECK(rnc_node_blackhole_at(m, 0, 100, &e) == RNC_OK &&
        !memcmp(e.source, source, 16));
  CHECK(rnc_node_blackhole_export(m, blob, sizeof(blob), &written) == RNC_OK &&
        written == 1 && blob[0] == 0x80); /* nothing local to persist */
  /* garbage is rejected without changing the table */
  for (k = 0; k < 8; ++k)
    blob[k] = (uint8_t)(0xf0 + k);
  CHECK(rnc_node_blackhole_import(m, blob, 8, NULL, 100) == RNC_PROTOCOL);
  rnc_node_free(m);
  rnc_node_free(n);
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  if (!strcmp(argv[1], "announces"))
    drops_announces();
  else if (!strcmp(argv[1], "paths"))
    removes_paths();
  else if (!strcmp(argv[1], "bounds"))
    state_and_bounds();
  else if (!strcmp(argv[1], "expiry"))
    expiry();
  else if (!strcmp(argv[1], "reference_file"))
    reads_reference_file();
  else if (!strcmp(argv[1], "persistence"))
    persistence();
  else
    CHECK(0);
  puts("blackhole test passed");
  return 0;
}
