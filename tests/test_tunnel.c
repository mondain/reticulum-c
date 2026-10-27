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
static uint32_t seed = 31;
static rnc_result rng(void *ctx, uint8_t *p, size_t n) {
  size_t i;
  (void)ctx;
  for (i = 0; i < n; i++) {
    seed = seed * 1664525u + 1013904223u;
    p[i] = (uint8_t)(seed >> 24);
  }
  return RNC_OK;
}
typedef struct pair {
  rnc_identity a_id, b_id, peer;
  rnc_node *a, *b;
  uint8_t hash[32];
  uint64_t now;
} pair;
static void setup(pair *p) {
  size_t i;
  memset(p, 0, sizeof(*p));
  CHECK(rnc_identity_generate(&p->a_id, rng, NULL) == RNC_OK);
  CHECK(rnc_identity_generate(&p->b_id, rng, NULL) == RNC_OK);
  CHECK(rnc_identity_generate(&p->peer, rng, NULL) == RNC_OK);
  p->a = rnc_node_new(&p->a_id, 0, rng, NULL);
  p->b = rnc_node_new(&p->b_id, 1, rng, NULL);
  CHECK(p->a && p->b);
  CHECK(rnc_node_add_interface(p->a, 1, 1000000) == RNC_OK);
  CHECK(rnc_node_add_interface(p->b, 1, 1000000) == RNC_OK);
  for (i = 0; i < 32; i++)
    p->hash[i] = (uint8_t)(0x40 + i);
  p->now = 1000;
}
static rnc_packet take_send(rnc_node *n, uint32_t iface) {
  rnc_node_event e;
  rnc_packet none = {0};
  while (rnc_node_poll(n, &e) == RNC_OK)
    if (e.type == RNC_NODE_SEND && e.interface_id == iface)
      return e.packet;
  CHECK(0);
  return none;
}
static rnc_packet synthesis(pair *p, const uint8_t *hash) {
  CHECK(rnc_node_synthesize_tunnel(p->a, 1, hash, p->now) == RNC_OK);
  return take_send(p->a, 1);
}
static void expected_id(const pair *p, const uint8_t *hash, uint8_t id[32]) {
  uint8_t material[96];
  memcpy(material, p->a_id.public_key, 64);
  memcpy(material + 64, hash, 32);
  CHECK(rnc_hash(material, 96, id) == RNC_OK);
}
static void establish(void) {
  pair p;
  rnc_packet syn;
  rnc_tunnel_info t;
  uint8_t id[32];
  setup(&p);
  syn = synthesis(&p, p.hash);
  /* a broadcast PLAIN data packet, 64 + 32 + 16 + 64 bytes */
  CHECK((syn.flags & 0x0f) == 0x08 && syn.data_size == 176);
  CHECK(rnc_node_input(p.b, 1, &syn, 1700000000, p.now) == RNC_OK);
  CHECK(rnc_node_tunnel_count(p.b) == 1);
  CHECK(rnc_node_tunnel_at(p.b, 0, &t) == RNC_OK);
  expected_id(&p, p.hash, id);
  CHECK(!memcmp(t.id, id, 32) && t.interface_id == 1 && t.paths == 0 &&
        t.expires_ms == p.now + RNC_TUNNEL_TIMEOUT_MS);
  CHECK(rnc_node_tunnel_at(p.b, 1, &t) == RNC_AGAIN);
  /* the same tunnel again is the same entry, with a fresh timeout */
  p.now += 5000;
  syn = synthesis(&p, p.hash);
  CHECK(rnc_node_input(p.b, 1, &syn, 1700000005, p.now) == RNC_OK);
  CHECK(rnc_node_tunnel_count(p.b) == 1);
  CHECK(rnc_node_tunnel_at(p.b, 0, &t) == RNC_OK &&
        t.expires_ms == p.now + RNC_TUNNEL_TIMEOUT_MS);
  /* another interface hash is another tunnel */
  {
    uint8_t other[32];
    memset(other, 0x99, 32);
    syn = synthesis(&p, other);
    CHECK(rnc_node_input(p.b, 1, &syn, 1700000005, p.now) == RNC_OK);
    CHECK(rnc_node_tunnel_count(p.b) == 2);
  }
  rnc_node_free(p.a);
  rnc_node_free(p.b);
}
static void rejects_bad_packets(void) {
  pair p;
  rnc_packet syn, bad;
  setup(&p);
  syn = synthesis(&p, p.hash);
  bad = syn;
  bad.data[100] ^= 1; /* signed region */
  CHECK(rnc_node_input(p.b, 1, &bad, 1700000000, p.now) == RNC_PROTOCOL);
  bad = syn;
  bad.data[175] ^= 1; /* signature */
  CHECK(rnc_node_input(p.b, 1, &bad, 1700000000, p.now) == RNC_PROTOCOL);
  bad = syn;
  bad.data_size = 175;
  CHECK(rnc_node_input(p.b, 1, &bad, 1700000000, p.now) == RNC_PROTOCOL);
  CHECK(rnc_node_tunnel_count(p.b) == 0);
  /* guards on the sending side */
  CHECK(rnc_node_synthesize_tunnel(p.a, 9, p.hash, p.now) == RNC_STATE);
  CHECK(rnc_node_synthesize_tunnel(NULL, 1, p.hash, p.now) == RNC_INVALID);
  CHECK(rnc_node_synthesize_tunnel(p.a, 1, NULL, p.now) == RNC_INVALID);
  {
    rnc_identity pub;
    rnc_node *watcher;
    CHECK(rnc_identity_from_public(&pub, p.a_id.public_key) == RNC_OK);
    watcher = rnc_node_new(&pub, 0, rng, NULL);
    CHECK(watcher && rnc_node_add_interface(watcher, 1, 1000) == RNC_OK);
    CHECK(rnc_node_synthesize_tunnel(watcher, 1, p.hash, p.now) == RNC_STATE);
    rnc_node_free(watcher);
  }
  rnc_node_free(p.a);
  rnc_node_free(p.b);
}
static rnc_packet announce_from(pair *p, uint64_t unix_seconds) {
  rnc_packet a;
  CHECK(rnc_announce_create(&p->peer, "tunnel.test", NULL, 0, unix_seconds, rng,
                            NULL, &a) == RNC_OK);
  return a;
}
/* Paths learned through a tunnel come back when it reappears. */
static void restores_paths(void) {
  pair p;
  rnc_packet syn, ann;
  rnc_tunnel_info t;
  rnc_route route;
  uint8_t hops;
  setup(&p);
  syn = synthesis(&p, p.hash);
  CHECK(rnc_node_input(p.b, 1, &syn, 1700000000, p.now) == RNC_OK);
  ann = announce_from(&p, 1700000000);
  CHECK(rnc_node_input(p.b, 1, &ann, 1700000000, p.now) == RNC_OK);
  CHECK(rnc_node_lookup(p.b, ann.destination, p.now, &route) == RNC_OK);
  hops = route.hops;
  CHECK(rnc_node_tunnel_at(p.b, 0, &t) == RNC_OK && t.paths == 1);
  /* the interface goes away: routes through it go, the tunnel keeps its path */
  CHECK(rnc_node_remove_interface(p.b, 1) == RNC_OK);
  CHECK(rnc_node_lookup(p.b, ann.destination, p.now, &route) == RNC_AGAIN);
  CHECK(rnc_node_tunnel_at(p.b, 0, &t) == RNC_OK && t.interface_id == 0 &&
        t.paths == 1);
  /* it returns as interface 2 and announces the same tunnel */
  CHECK(rnc_node_add_interface(p.b, 2, 1000000) == RNC_OK);
  p.now += 60000;
  syn = synthesis(&p, p.hash);
  CHECK(rnc_node_input(p.b, 2, &syn, 1700000060, p.now) == RNC_OK);
  CHECK(rnc_node_lookup(p.b, ann.destination, p.now, &route) == RNC_OK &&
        route.interface_id == 2 && route.hops == hops);
  CHECK(rnc_node_tunnel_at(p.b, 0, &t) == RNC_OK && t.interface_id == 2 &&
        t.paths == 1);
  /* a path learned on the tunnel's new interface keeps the entry in step */
  ann = announce_from(&p, 1700000100);
  CHECK(rnc_node_input(p.b, 2, &ann, 1700000100, p.now + 1000) == RNC_OK);
  CHECK(rnc_node_tunnel_at(p.b, 0, &t) == RNC_OK && t.paths == 1);
  rnc_node_free(p.a);
  rnc_node_free(p.b);
}
/* A newer path learned meanwhile is not overwritten by the older tunnel path. */
static void keeps_newer_path(void) {
  pair p;
  rnc_packet syn, ann;
  rnc_tunnel_info t;
  rnc_route route;
  setup(&p);
  syn = synthesis(&p, p.hash);
  CHECK(rnc_node_input(p.b, 1, &syn, 1700000000, p.now) == RNC_OK);
  ann = announce_from(&p, 1700000000);
  CHECK(rnc_node_input(p.b, 1, &ann, 1700000000, p.now) == RNC_OK);
  CHECK(rnc_node_remove_interface(p.b, 1) == RNC_OK);
  CHECK(rnc_node_add_interface(p.b, 3, 1000000) == RNC_OK);
  CHECK(rnc_node_add_interface(p.b, 2, 1000000) == RNC_OK);
  ann = announce_from(&p, 1700000500); /* newer, via another interface */
  CHECK(rnc_node_input(p.b, 3, &ann, 1700000500, p.now + 1000) == RNC_OK);
  syn = synthesis(&p, p.hash);
  CHECK(rnc_node_input(p.b, 2, &syn, 1700000501, p.now + 2000) == RNC_OK);
  CHECK(rnc_node_lookup(p.b, ann.destination, p.now + 2000, &route) == RNC_OK &&
        route.interface_id == 3 && route.announced_at == 1700000500);
  CHECK(rnc_node_tunnel_at(p.b, 0, &t) == RNC_OK && t.paths == 0);
  rnc_node_free(p.a);
  rnc_node_free(p.b);
}
static void expires(void) {
  pair p;
  rnc_packet syn, ann;
  rnc_tunnel_info t;
  setup(&p);
  syn = synthesis(&p, p.hash);
  CHECK(rnc_node_input(p.b, 1, &syn, 1700000000, p.now) == RNC_OK);
  ann = announce_from(&p, 1700000000);
  CHECK(rnc_node_input(p.b, 1, &ann, 1700000000, p.now) == RNC_OK);
  CHECK(rnc_node_tick(p.b, 1700000000, p.now + RNC_TUNNEL_TIMEOUT_MS - 1) ==
        RNC_OK);
  CHECK(rnc_node_tunnel_count(p.b) == 1);
  CHECK(rnc_node_tunnel_at(p.b, 0, &t) == RNC_OK);
  CHECK(rnc_node_tick(p.b, 1700000000, p.now + RNC_TUNNEL_TIMEOUT_MS + 1000) ==
        RNC_OK);
  CHECK(rnc_node_tunnel_count(p.b) == 0);
  rnc_node_free(p.a);
  rnc_node_free(p.b);
}
/* The tunnel table survives a restart, signed like the route checkpoint. */
static void persistence(void) {
  pair p;
  rnc_packet syn, ann;
  rnc_tunnel_info t;
  rnc_route route;
  rnc_node *fresh;
  static uint8_t blob[RNC_NODE_TUNNEL_STATE_MAX];
  size_t written;
  setup(&p);
  syn = synthesis(&p, p.hash);
  CHECK(rnc_node_input(p.b, 1, &syn, 1700000000, p.now) == RNC_OK);
  ann = announce_from(&p, 1700000000);
  CHECK(rnc_node_input(p.b, 1, &ann, 1700000000, p.now) == RNC_OK);
  CHECK(rnc_node_tunnels_export(p.b, &p.b_id, 1700000010, p.now + 10000, blob,
                                sizeof(blob), &written) == RNC_OK);
  CHECK(written > 100 && written < sizeof(blob));
  /* a restarted node: new object, same identity, interface not yet back */
  fresh = rnc_node_new(&p.b_id, 1, rng, NULL);
  CHECK(fresh && rnc_node_add_interface(fresh, 5, 1000000) == RNC_OK);
  CHECK(rnc_node_tunnels_import(fresh, &p.b_id, 1700000020, p.now + 20000, blob,
                                written) == RNC_OK);
  CHECK(rnc_node_tunnel_count(fresh) == 1);
  CHECK(rnc_node_tunnel_at(fresh, 0, &t) == RNC_OK && t.interface_id == 0 &&
        t.paths == 1);
  /* the peer returns on interface 5 and its path is back without an announce */
  syn = synthesis(&p, p.hash);
  CHECK(rnc_node_input(fresh, 5, &syn, 1700000030, p.now + 30000) == RNC_OK);
  CHECK(rnc_node_lookup(fresh, ann.destination, p.now + 30000, &route) ==
            RNC_OK &&
        route.interface_id == 5);
  /* refusals: occupied table, tampering, a different owner, short input */
  CHECK(rnc_node_tunnels_import(fresh, &p.b_id, 1700000040, p.now + 40000, blob,
                                written) == RNC_STATE);
  rnc_node_free(fresh);
  fresh = rnc_node_new(&p.b_id, 1, rng, NULL);
  CHECK(fresh);
  blob[40] ^= 1;
  CHECK(rnc_node_tunnels_import(fresh, &p.b_id, 1700000020, p.now + 20000, blob,
                                written) == RNC_AUTH);
  blob[40] ^= 1;
  CHECK(rnc_node_tunnels_import(fresh, &p.a_id, 1700000020, p.now + 20000, blob,
                                written) == RNC_INVALID);
  CHECK(rnc_node_tunnels_import(fresh, &p.b_id, 1700000020, p.now + 20000, blob,
                                50) == RNC_PROTOCOL);
  CHECK(rnc_node_tunnel_count(fresh) == 0);
  /* tunnels that have timed out are not brought back */
  CHECK(rnc_node_tunnels_import(fresh, &p.b_id,
                                1700000020 + RNC_TUNNEL_TIMEOUT_MS / 1000u + 60,
                                p.now + 20000, blob, written) == RNC_OK);
  CHECK(rnc_node_tunnel_count(fresh) == 0);
  CHECK(rnc_node_tunnels_export(p.b, &p.b_id, 1700000010, p.now + 10000, blob,
                                20, &written) == RNC_NO_SPACE && written == 0);
  rnc_node_free(fresh);
  rnc_node_free(p.a);
  rnc_node_free(p.b);
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  if (!strcmp(argv[1], "establish"))
    establish();
  else if (!strcmp(argv[1], "reject"))
    rejects_bad_packets();
  else if (!strcmp(argv[1], "restore"))
    restores_paths();
  else if (!strcmp(argv[1], "newer"))
    keeps_newer_path();
  else if (!strcmp(argv[1], "expire"))
    expires();
  else if (!strcmp(argv[1], "persist"))
    persistence();
  else
    CHECK(0);
  puts("tunnel test passed");
  return 0;
}
