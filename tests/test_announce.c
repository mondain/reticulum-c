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
static uint32_t seed = 23;
static rnc_result rng(void *ctx, uint8_t *p, size_t n) {
  size_t i;
  (void)ctx;
  for (i = 0; i < n; i++) {
    seed = seed * 1664525u + 1013904223u;
    p[i] = (uint8_t)(seed >> 24);
  }
  return RNC_OK;
}
static rnc_node *make(int transport, int local_first,
                      const rnc_interface_policy *policy) {
  rnc_identity id;
  rnc_node *n;
  CHECK(rnc_identity_generate(&id, rng, NULL) == RNC_OK);
  n = rnc_node_new(&id, transport, rng, NULL);
  CHECK(n);
  CHECK(rnc_node_add_interface(n, 1, 1000000) == RNC_OK);
  CHECK(rnc_node_add_interface(n, 2, 1000000) == RNC_OK);
  if (local_first)
    CHECK(rnc_node_local_interface(n, 1, 1) == RNC_OK);
  if (policy)
    CHECK(rnc_node_interface_policy(n, 1, policy) == RNC_OK);
  return n;
}
static rnc_packet announce_from(const rnc_identity *id, uint64_t unix_seconds) {
  rnc_packet p;
  CHECK(rnc_announce_create(id, "announce.test", NULL, 0, unix_seconds, rng,
                            NULL, &p) == RNC_OK);
  return p;
}
static size_t sends_on(rnc_node *n, uint32_t iface) {
  rnc_node_event e;
  size_t c = 0;
  while (rnc_node_poll(n, &e) == RNC_OK)
    c += e.type == RNC_NODE_SEND && e.interface_id == iface &&
         (e.packet.flags & 3u) == RNC_ANNOUNCE;
  return c;
}
/* Another node's rebroadcast of the same announce, as heard on interface 1. */
static rnc_packet heard(const rnc_packet *original, uint8_t wire_hops) {
  rnc_packet p = *original;
  p.flags = (uint8_t)((p.flags & 0x2fu) | 0x50u);
  memset(p.transport_id, 0x77, 16);
  p.hops = wire_hops;
  return p;
}
/* One initial rebroadcast plus a single retry after the 5s grace period. */
static void retry(void) {
  rnc_node *n = make(1, 0, NULL);
  rnc_identity src;
  rnc_packet a;
  CHECK(rnc_identity_generate(&src, rng, NULL) == RNC_OK);
  a = announce_from(&src, 1000);
  CHECK(rnc_node_input(n, 1, &a, 1000, 0) == RNC_OK);
  CHECK(rnc_node_tick(n, 1000, 500) == RNC_OK);
  CHECK(sends_on(n, 2) == 1);
  CHECK(rnc_node_tick(n, 1000, 5000) == RNC_OK);
  CHECK(sends_on(n, 2) == 0);
  CHECK(rnc_node_tick(n, 1000, 6500) == RNC_OK);
  CHECK(sends_on(n, 2) == 1);
  CHECK(rnc_node_tick(n, 1000, 60000) == RNC_OK);
  CHECK(sends_on(n, 2) == 0);
  rnc_node_free(n);
}
/* Hearing two neighbours rebroadcast the same announce cancels our retry. */
static void heard_twice(void) {
  rnc_node *n = make(1, 0, NULL);
  rnc_identity src;
  rnc_packet a, h;
  CHECK(rnc_identity_generate(&src, rng, NULL) == RNC_OK);
  a = announce_from(&src, 1000);
  CHECK(rnc_node_input(n, 1, &a, 1000, 0) == RNC_OK);
  CHECK(rnc_node_tick(n, 1000, 500) == RNC_OK);
  CHECK(sends_on(n, 2) == 1);
  /* We stored hops 1, so a neighbour's rebroadcast arrives with wire hops 1. */
  h = heard(&a, 1);
  CHECK(rnc_node_input(n, 1, &h, 1000, 1000) == RNC_OK);
  h.transport_id[0] ^= 1;
  CHECK(rnc_node_input(n, 1, &h, 1000, 2000) == RNC_OK);
  CHECK(rnc_node_tick(n, 1000, 7000) == RNC_OK);
  CHECK(sends_on(n, 2) == 0);
  rnc_node_free(n);
}
static void heard_once(void) {
  rnc_node *n = make(1, 0, NULL);
  rnc_identity src;
  rnc_packet a, h;
  CHECK(rnc_identity_generate(&src, rng, NULL) == RNC_OK);
  a = announce_from(&src, 1000);
  CHECK(rnc_node_input(n, 1, &a, 1000, 0) == RNC_OK);
  CHECK(rnc_node_tick(n, 1000, 500) == RNC_OK);
  CHECK(sends_on(n, 2) == 1);
  h = heard(&a, 1);
  CHECK(rnc_node_input(n, 1, &h, 1000, 1000) == RNC_OK);
  CHECK(rnc_node_tick(n, 1000, 7000) == RNC_OK);
  CHECK(sends_on(n, 2) == 1);
  rnc_node_free(n);
}
/* An announce that was passed on a further hop before our retry is dropped. */
static void passed_on(void) {
  rnc_node *n = make(1, 0, NULL);
  rnc_identity src;
  rnc_packet a, h;
  CHECK(rnc_identity_generate(&src, rng, NULL) == RNC_OK);
  a = announce_from(&src, 1000);
  CHECK(rnc_node_input(n, 1, &a, 1000, 0) == RNC_OK);
  CHECK(rnc_node_tick(n, 1000, 500) == RNC_OK);
  CHECK(sends_on(n, 2) == 1);
  h = heard(&a, 2);
  CHECK(rnc_node_input(n, 1, &h, 1000, 1000) == RNC_OK);
  CHECK(rnc_node_tick(n, 1000, 7000) == RNC_OK);
  CHECK(sends_on(n, 2) == 0);
  rnc_node_free(n);
}
/* Announces from a shared-instance client are relayed immediately, once. */
static void local_client(void) {
  rnc_node *n = make(0, 1, NULL);
  rnc_identity src;
  rnc_packet a;
  CHECK(rnc_identity_generate(&src, rng, NULL) == RNC_OK);
  a = announce_from(&src, 1000);
  CHECK(rnc_node_input(n, 1, &a, 1000, 0) == RNC_OK);
  CHECK(rnc_node_tick(n, 1000, 500) == RNC_OK);
  CHECK(sends_on(n, 2) == 1);
  CHECK(rnc_node_tick(n, 1000, 60000) == RNC_OK);
  CHECK(sends_on(n, 2) == 0);
  rnc_node_free(n);
}
/* Rate limit: after grace violations, announces update paths but are not
 * rebroadcast until the penalised block expires. */
static void rate(void) {
  rnc_interface_policy policy = {0};
  rnc_node *n;
  rnc_identity src;
  rnc_packet a;
  rnc_route route;
  policy.announce_rate_target = 3600;
  policy.announce_rate_grace = 1;
  policy.announce_rate_penalty = 7200;
  n = make(1, 0, &policy);
  CHECK(rnc_identity_generate(&src, rng, NULL) == RNC_OK);
  a = announce_from(&src, 1000);
  CHECK(rnc_node_input(n, 1, &a, 1000, 0) == RNC_OK);
  CHECK(rnc_node_tick(n, 1000, 600) == RNC_OK);
  CHECK(sends_on(n, 2) == 1);
  a = announce_from(&src, 1010); /* first violation, within grace */
  CHECK(rnc_node_input(n, 1, &a, 1010, 10000) == RNC_OK);
  CHECK(rnc_node_tick(n, 1010, 10600) == RNC_OK);
  CHECK(sends_on(n, 2) >= 1);
  a = announce_from(&src, 1020); /* second violation: blocked */
  CHECK(rnc_node_input(n, 1, &a, 1020, 20000) == RNC_OK);
  /* Only the second announce's pending retry may go out, not the third. */
  CHECK(rnc_node_tick(n, 1020, 20600) == RNC_OK);
  CHECK(rnc_node_tick(n, 1020, 60000) == RNC_OK);
  CHECK(sends_on(n, 2) == 1);
  CHECK(rnc_node_lookup(n, a.destination, 60000, &route) == RNC_OK &&
        route.announced_at == 1020);
  rnc_node_free(n);
}
/* Locally originated announces are never sent on access-point interfaces. */
static void access_point(void) {
  rnc_interface_policy policy = {0};
  rnc_identity id;
  rnc_node *n;
  uint8_t dest[16];
  policy.mode = RNC_MODE_ACCESS_POINT;
  n = make(1, 0, &policy);
  CHECK(rnc_identity_generate(&id, rng, NULL) == RNC_OK);
  CHECK(rnc_node_add_destination(n, &id, "announce.local", NULL, 0, dest) ==
        RNC_OK);
  CHECK(rnc_node_announce(n, dest, 1000, 0) == RNC_OK);
  CHECK(rnc_node_tick(n, 1000, 100) == RNC_OK);
  CHECK(sends_on(n, 1) == 0);
  CHECK(rnc_node_announce(n, dest, 1001, 200) == RNC_OK);
  CHECK(rnc_node_tick(n, 1001, 300) == RNC_OK);
  CHECK(sends_on(n, 2) >= 1);
  rnc_node_free(n);
}
int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  if (!strcmp(argv[1], "retry"))
    retry();
  else if (!strcmp(argv[1], "heard_twice"))
    heard_twice();
  else if (!strcmp(argv[1], "heard_once"))
    heard_once();
  else if (!strcmp(argv[1], "passed_on"))
    passed_on();
  else if (!strcmp(argv[1], "local_client"))
    local_client();
  else if (!strcmp(argv[1], "rate"))
    rate();
  else if (!strcmp(argv[1], "access_point"))
    access_point();
  else
    return 2;
  return 0;
}
