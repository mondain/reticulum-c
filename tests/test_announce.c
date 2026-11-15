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
  rnc_rate_entry entry;
  policy.announce_rate_target = 3600;
  policy.announce_rate_grace = 1;
  policy.announce_rate_penalty = 7200;
  n = make(1, 0, &policy);
  CHECK(rnc_identity_generate(&src, rng, NULL) == RNC_OK);
  a = announce_from(&src, 1000);
  CHECK(rnc_node_input(n, 1, &a, 1000, 0) == RNC_OK);
  CHECK(rnc_node_tick(n, 1000, 600) == RNC_OK);
  CHECK(sends_on(n, 2) == 1);
  /* the table the reference reports over RPC: hash, last, rate_violations, blocked_until,
   * timestamps (one per announce seen) */
  CHECK(rnc_node_rate_at(n, 0, &entry) == RNC_OK && !memcmp(entry.destination, a.destination, 16) &&
        entry.violations == 0 && entry.last_ms == 0 && entry.blocked_until_ms == 0 &&
        entry.timestamp_count == 1 && entry.timestamps_ms[0] == 0);
  CHECK(rnc_node_rate_at(n, 1, &entry) == RNC_AGAIN);
  a = announce_from(&src, 1010); /* first violation, within grace */
  CHECK(rnc_node_input(n, 1, &a, 1010, 10000) == RNC_OK);
  CHECK(rnc_node_rate_at(n, 0, &entry) == RNC_OK && entry.violations == 1 && entry.last_ms == 10000 &&
        entry.blocked_until_ms == 0 && entry.timestamp_count == 2 && entry.timestamps_ms[1] == 10000);
  CHECK(rnc_node_tick(n, 1010, 10600) == RNC_OK);
  CHECK(sends_on(n, 2) >= 1);
  a = announce_from(&src, 1020); /* second violation: blocked */
  CHECK(rnc_node_input(n, 1, &a, 1020, 20000) == RNC_OK);
  /* blocked until last (10 s) + target (3600 s) + penalty (7200 s) */
  CHECK(rnc_node_rate_at(n, 0, &entry) == RNC_OK && entry.violations == 2 &&
        entry.blocked_until_ms == 10000u + 3600000u + 7200000u && entry.timestamp_count == 3);
  /* Only the second announce's pending retry may go out, not the third. */
  CHECK(rnc_node_tick(n, 1020, 20600) == RNC_OK);
  CHECK(rnc_node_tick(n, 1020, 60000) == RNC_OK);
  CHECK(sends_on(n, 2) == 1);
  CHECK(rnc_node_lookup(n, a.destination, 60000, &route) == RNC_OK &&
        route.announced_at == 1020);
  rnc_node_free(n);
}
/* MODE_INTERNAL (reference Interface.MODE_INTERNAL, with announces_from_internal and
 * announces_to_internal): what an announce learned on one interface may be passed on to. */
static void internal_mode(void) {
  rnc_interface_policy in = {0}, out = {0};
  rnc_identity src;
  rnc_packet a;
  rnc_node *n;
  /* out = INTERNAL: an announce from a BOUNDARY interface is not passed in ... */
  in.mode = RNC_MODE_BOUNDARY;
  out.mode = RNC_MODE_INTERNAL;
  n = make(1, 0, &in);
  CHECK(rnc_node_interface_policy(n, 2, &out) == RNC_OK);
  CHECK(rnc_identity_generate(&src, rng, NULL) == RNC_OK);
  a = announce_from(&src, 1000);
  CHECK(rnc_node_input(n, 1, &a, 1000, 0) == RNC_OK);
  CHECK(rnc_node_tick(n, 1000, 600) == RNC_OK);
  CHECK(sends_on(n, 2) == 0);
  rnc_node_free(n);
  /* ... unless that interface announces_to_internal */
  in.announces_to_internal = 1;
  n = make(1, 0, &in);
  CHECK(rnc_node_interface_policy(n, 2, &out) == RNC_OK);
  a = announce_from(&src, 1001);
  CHECK(rnc_node_input(n, 1, &a, 1001, 0) == RNC_OK);
  CHECK(rnc_node_tick(n, 1001, 600) == RNC_OK);
  CHECK(sends_on(n, 2) == 1);
  rnc_node_free(n);
  /* a plain interface feeds an INTERNAL one */
  memset(&in, 0, sizeof(in));
  n = make(1, 0, &in);
  CHECK(rnc_node_interface_policy(n, 2, &out) == RNC_OK);
  a = announce_from(&src, 1002);
  CHECK(rnc_node_input(n, 1, &a, 1002, 0) == RNC_OK);
  CHECK(rnc_node_tick(n, 1002, 600) == RNC_OK);
  CHECK(sends_on(n, 2) == 1);
  rnc_node_free(n);
  /* an interface that refuses announces from INTERNAL ones (announces_from_internal off) */
  memset(&in, 0, sizeof(in));
  memset(&out, 0, sizeof(out));
  in.mode = RNC_MODE_INTERNAL;
  out.no_announces_from_internal = 1;
  n = make(1, 0, &in);
  CHECK(rnc_node_interface_policy(n, 2, &out) == RNC_OK);
  a = announce_from(&src, 1003);
  CHECK(rnc_node_input(n, 1, &a, 1003, 0) == RNC_OK);
  CHECK(rnc_node_tick(n, 1003, 600) == RNC_OK);
  CHECK(sends_on(n, 2) == 0);
  rnc_node_free(n);
  /* default: INTERNAL to a plain interface is passed on */
  memset(&out, 0, sizeof(out));
  n = make(1, 0, &in);
  CHECK(rnc_node_interface_policy(n, 2, &out) == RNC_OK);
  a = announce_from(&src, 1004);
  CHECK(rnc_node_input(n, 1, &a, 1004, 0) == RNC_OK);
  CHECK(rnc_node_tick(n, 1004, 600) == RNC_OK);
  CHECK(sends_on(n, 2) == 1);
  rnc_node_free(n);
}
/* An INTERNAL interface is not held to the announce bandwidth cap (the reference sends there
 * outside the queueing branch): a burst goes out together instead of one per interval. */
static void internal_no_cap(void) {
  rnc_interface_policy out = {0};
  rnc_identity src[3];
  rnc_packet a;
  rnc_node *n;
  unsigned i;
  out.mode = RNC_MODE_INTERNAL;
  n = make(1, 0, NULL);
  CHECK(rnc_node_interface_policy(n, 2, &out) == RNC_OK);
  for (i = 0; i < 3; i++) {
    CHECK(rnc_identity_generate(&src[i], rng, NULL) == RNC_OK);
    a = announce_from(&src[i], 1000);
    CHECK(rnc_node_input(n, 1, &a, 1000, 0) == RNC_OK);
  }
  CHECK(rnc_node_tick(n, 1000, 600) == RNC_OK);
  CHECK(sends_on(n, 2) == 3);
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
/* An interface that leaves while its announce retry is pending (a TCP client
 * disconnecting) must not crash the retry, nor resend the announce. */
static void ingress_removed(void) {
  rnc_node *n = make(1, 0, NULL);
  rnc_identity src;
  rnc_packet a;
  CHECK(rnc_identity_generate(&src, rng, NULL) == RNC_OK);
  a = announce_from(&src, 1000);
  CHECK(rnc_node_input(n, 1, &a, 1000, 0) == RNC_OK);
  CHECK(rnc_node_tick(n, 1000, 500) == RNC_OK);
  CHECK(sends_on(n, 2) == 1);
  CHECK(rnc_node_remove_interface(n, 1) == RNC_OK);
  CHECK(rnc_node_tick(n, 1000, 6500) == RNC_OK); /* the retry falls due */
  CHECK(sends_on(n, 2) == 0);
  CHECK(rnc_node_tick(n, 1000, 60000) == RNC_OK);
  rnc_node_free(n);
}
int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  if (!strcmp(argv[1], "retry"))
    retry();
  else if (!strcmp(argv[1], "ingress_removed"))
    ingress_removed();
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
  else if (!strcmp(argv[1], "internal_mode"))
    internal_mode();
  else if (!strcmp(argv[1], "internal_no_cap"))
    internal_no_cap();
  else
    return 2;
  return 0;
}
