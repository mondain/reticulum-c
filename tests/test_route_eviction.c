/* A transport node with a full route table or announce queue: what it gives up for a new announce.
 *
 *   evict_lru          the table is full of routes from one fast interface: a new announce takes
 *                      the slot of the least recently heard route, the rest stay
 *   slow_routes_stay   a flood of announces on a fast interface (a host forwarding a network) does
 *                      not displace the routes learned on a slow radio interface
 *   fast_cannot_evict  with the table full of slow-interface routes, a fast-interface announce is
 *                      refused instead of displacing one
 *   slow_evicts_fast   with the table full of fast-interface routes, a slow-interface announce
 *                      takes a slot
 *   queue_closer_wins  with the announce queue full of far announces, a closer one takes a slot
 *                      and goes out first; one that is not closer is learned but not queued
 *   queue_dedup        an announce heard again while it waits replaces the waiting copy
 */
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
#define SLOW 1u
#define FAST 2u
/* node.c's private announce queue size in the host profile (RNC_NODE_QUEUE); this test is built only there */
#define QUEUE_SLOTS 64u
#define SLOW_BPS 1200u
#define FAST_BPS 1000000u
static uint32_t seed = 41;
static rnc_result rng(void *ctx, uint8_t *p, size_t n) {
  size_t i;
  (void)ctx;
  for (i = 0; i < n; i++) {
    seed = seed * 1664525u + 1013904223u;
    p[i] = (uint8_t)(seed >> 24);
  }
  return RNC_OK;
}
static rnc_node *make(void) {
  rnc_identity id;
  rnc_node *n;
  CHECK(rnc_identity_generate(&id, rng, NULL) == RNC_OK);
  n = rnc_node_new(&id, 1, rng, NULL);
  CHECK(n);
  CHECK(rnc_node_add_interface(n, SLOW, SLOW_BPS) == RNC_OK);
  CHECK(rnc_node_add_interface(n, FAST, FAST_BPS) == RNC_OK);
  return n;
}
static void drain(rnc_node *n) {
  rnc_node_event e;
  while (rnc_node_poll(n, &e) == RNC_OK) {
  }
}
/* A fresh destination announces; `wire_hops` is the hop count on the wire. Returns what the node said. */
static rnc_result learn(rnc_node *n, uint32_t iface, unsigned wire_hops, uint64_t now_ms, uint8_t dest[16]) {
  rnc_identity src;
  rnc_packet p;
  rnc_result r;
  uint64_t unix_s = 1000u + now_ms / 1000u;
  CHECK(rnc_identity_generate(&src, rng, NULL) == RNC_OK);
  CHECK(rnc_announce_create(&src, "evict.test", NULL, 0, unix_s, rng, NULL, &p) == RNC_OK);
  p.hops = (uint8_t)wire_hops;
  memcpy(dest, p.destination, 16);
  CHECK(rnc_node_tick(n, unix_s, now_ms) == RNC_OK);
  r = rnc_node_input(n, iface, &p, unix_s, now_ms);
  drain(n);
  return r;
}
static size_t route_count(const rnc_node *n, uint64_t now_ms) {
  rnc_route r;
  size_t c = 0;
  while (rnc_node_route_at(n, c, now_ms, &r) == RNC_OK)
    c++;
  return c;
}
static int has_route(const rnc_node *n, const uint8_t dest[16], uint64_t now_ms) {
  rnc_route r;
  size_t i = 0;
  while (rnc_node_route_at(n, i++, now_ms, &r) == RNC_OK)
    if (!memcmp(r.destination, dest, 16))
      return 1;
  return 0;
}
#define MAXD (RNC_NODE_ROUTES + 40u)
static void evict_lru(void) {
  rnc_node *n = make();
  uint8_t d[MAXD][16];
  unsigned i, total = RNC_NODE_ROUTES + 5u;
  uint64_t t = 1000;
  for (i = 0; i < total; i++, t += 1000)
    (void)learn(n, FAST, 0, t, d[i]);
  CHECK(route_count(n, t) == RNC_NODE_ROUTES);
  /* the five oldest are gone, the newest are all there */
  for (i = 0; i < 5; i++)
    CHECK(!has_route(n, d[i], t));
  for (i = 5; i < total; i++)
    CHECK(has_route(n, d[i], t));
  rnc_node_free(n);
}
static void slow_routes_stay(void) {
  rnc_node *n = make();
  uint8_t slow[3][16], d[16];
  unsigned i;
  uint64_t t = 1000;
  for (i = 0; i < 3; i++, t += 1000)
    CHECK(learn(n, SLOW, 0, t, slow[i]) == RNC_OK);
  for (i = 0; i < RNC_NODE_ROUTES + 30u; i++, t += 1000)
    (void)learn(n, FAST, 0, t, d);
  CHECK(route_count(n, t) == RNC_NODE_ROUTES);
  for (i = 0; i < 3; i++)
    CHECK(has_route(n, slow[i], t));
  CHECK(has_route(n, d, t)); /* the newest fast announce is there */
  rnc_node_free(n);
}
static void fast_cannot_evict(void) {
  rnc_node *n = make();
  uint8_t slow[MAXD][16], d[16];
  unsigned i;
  uint64_t t = 1000;
  for (i = 0; i < RNC_NODE_ROUTES; i++, t += 1000)
    (void)learn(n, SLOW, 0, t, slow[i]);
  CHECK(route_count(n, t) == RNC_NODE_ROUTES);
  for (i = 0; i < 5; i++, t += 1000) {
    CHECK(learn(n, FAST, 0, t, d) == RNC_AGAIN);
    CHECK(!has_route(n, d, t));
  }
  for (i = 0; i < RNC_NODE_ROUTES; i++)
    CHECK(has_route(n, slow[i], t));
  rnc_node_free(n);
}
static void slow_evicts_fast(void) {
  rnc_node *n = make();
  uint8_t fast[MAXD][16], d[16];
  unsigned i;
  uint64_t t = 1000;
  for (i = 0; i < RNC_NODE_ROUTES; i++, t += 1000)
    (void)learn(n, FAST, 0, t, fast[i]);
  CHECK(route_count(n, t) == RNC_NODE_ROUTES);
  CHECK(learn(n, SLOW, 0, t, d) == RNC_OK);
  CHECK(has_route(n, d, t));
  CHECK(route_count(n, t) == RNC_NODE_ROUTES);
  CHECK(!has_route(n, fast[0], t)); /* the least recently heard fast route made way */
  rnc_node_free(n);
}
/* the first announce sent on `iface`, as the destination it is for */
static int first_send(rnc_node *n, uint32_t iface, uint8_t dest[16]) {
  rnc_node_event e;
  int found = 0;
  while (rnc_node_poll(n, &e) == RNC_OK)
    if (!found && e.type == RNC_NODE_SEND && e.interface_id == iface &&
        (e.packet.flags & 3u) == RNC_ANNOUNCE) {
      memcpy(dest, e.packet.destination, 16);
      found = 1;
    }
  return found;
}
static void queue_closer_wins(void) {
  rnc_node *n = make();
  uint8_t d[16], near_dest[16], got[16];
  unsigned i;
  uint64_t t = 1000;
  /* far announces on the fast interface queue for the slow one, which sends one in a minute */
  for (i = 0; i < QUEUE_SLOTS; i++, t += 600)
    CHECK(learn(n, FAST, 5, t, d) == RNC_OK);
  /* the queue is full of 6-hop entries: another far announce is still learned but not queued, a closer one takes a slot */
  CHECK(learn(n, FAST, 5, t, d) == RNC_OK);
  CHECK(has_route(n, d, t));
  t += 600;
  CHECK(learn(n, FAST, 0, t, near_dest) == RNC_OK);
  t += 600;
  /* the slow interface sent one announce a moment ago and sends the next one a minute on: the closest first */
  CHECK(rnc_node_tick(n, 1000u + t / 1000u, t + 70000) == RNC_OK);
  CHECK(first_send(n, SLOW, got));
  CHECK(!memcmp(got, near_dest, 16)); /* the lowest hop count goes out first */
  rnc_node_free(n);
}
static void queue_dedup(void) {
  rnc_node *n = make();
  rnc_identity src;
  rnc_packet p, again;
  uint64_t t = 1000;
  unsigned i, sent = 0;
  rnc_node_event e;
  CHECK(rnc_identity_generate(&src, rng, NULL) == RNC_OK);
  CHECK(rnc_announce_create(&src, "evict.same", NULL, 0, 1001, rng, NULL, &p) == RNC_OK);
  /* a neighbour's rebroadcast of the same announce while ours waits, seen on the other side */
  for (i = 0; i < 4; i++, t += 700) {
    again = p;
    CHECK(rnc_node_tick(n, 1001, t) == RNC_OK);
    (void)rnc_node_input(n, FAST, &again, 1001, t);
    drain(n);
  }
  CHECK(rnc_node_tick(n, 1001, t + 90000) == RNC_OK);
  while (rnc_node_poll(n, &e) == RNC_OK)
    sent += e.type == RNC_NODE_SEND && e.interface_id == SLOW && (e.packet.flags & 3u) == RNC_ANNOUNCE;
  CHECK(sent <= 1);
  rnc_node_free(n);
}
int main(int argc, char **argv) {
  const char *c = argc > 1 ? argv[1] : "all";
  int all = !strcmp(c, "all");
  if (all || !strcmp(c, "evict_lru"))
    evict_lru();
  if (all || !strcmp(c, "slow_routes_stay"))
    slow_routes_stay();
  if (all || !strcmp(c, "fast_cannot_evict"))
    fast_cannot_evict();
  if (all || !strcmp(c, "slow_evicts_fast"))
    slow_evicts_fast();
  if (all || !strcmp(c, "queue_closer_wins"))
    queue_closer_wins();
  if (all || !strcmp(c, "queue_dedup"))
    queue_dedup();
  puts("route eviction tests passed");
  return 0;
}
