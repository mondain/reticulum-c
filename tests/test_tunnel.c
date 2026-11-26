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
/* The receiver takes one synthesis per connection: a repeat comes after a reconnect. */
static void reconnect(rnc_node *n) {
  CHECK(rnc_node_remove_interface(n, 1) == RNC_OK);
  CHECK(rnc_node_add_interface(n, 1, 1000000) == RNC_OK);
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
  /* a broadcast PLAIN data packet, 64 + 32 + 16 + 64 bytes and the signed 1.6 extension map */
  CHECK((syn.flags & 0x0f) == 0x08 && syn.data_size > 176);
  CHECK(rnc_node_input(p.b, 1, &syn, 1700000000, p.now) == RNC_OK);
  CHECK(rnc_node_tunnel_count(p.b) == 1);
  CHECK(rnc_node_tunnel_at(p.b, 0, &t) == RNC_OK);
  expected_id(&p, p.hash, id);
  CHECK(!memcmp(t.id, id, 32) && t.interface_id == 1 && t.paths == 0 &&
        t.expires_ms == p.now + RNC_TUNNEL_TIMEOUT_MS);
  CHECK(rnc_node_tunnel_at(p.b, 1, &t) == RNC_AGAIN);
  /* the same tunnel again is the same entry, with a fresh timeout */
  p.now += 5000;
  reconnect(p.b);
  syn = synthesis(&p, p.hash);
  CHECK(rnc_node_input(p.b, 1, &syn, 1700000005, p.now) == RNC_OK);
  CHECK(rnc_node_tunnel_count(p.b) == 1);
  CHECK(rnc_node_tunnel_at(p.b, 0, &t) == RNC_OK &&
        t.expires_ms == p.now + RNC_TUNNEL_TIMEOUT_MS);
  /* another interface hash is another tunnel */
  {
    uint8_t other[32];
    memset(other, 0x99, 32);
    reconnect(p.b);
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
/* RNS 1.6 appends a signed msgpack map after the signature: implementation name, version, transport
 * status and the interface's destination and path request costs (Transport.synthesize_tunnel). */
static size_t put_f64(uint8_t *o, double v) {
  uint8_t b[8];
  uint64_t u;
  size_t i;
  memcpy(&u, &v, 8);
  for (i = 0; i < 8; i++)
    b[i] = (uint8_t)(u >> (56 - 8 * i));
  o[0] = 0xcb;
  memcpy(o + 1, b, 8);
  return 9;
}
static size_t reference_ext(uint8_t *o, int drop_key, int int_cost) {
  size_t n = 0;
  o[n++] = (uint8_t)(0x80 | (drop_key ? 4 : 5));
  o[n++] = 0xcc; o[n++] = 0xfd; o[n++] = 0xa3; memcpy(o + n, "RNS", 3); n += 3;
  o[n++] = 0xcc; o[n++] = 0xfc; o[n++] = 0xa5; memcpy(o + n, "1.6.1", 5); n += 5;
  if (drop_key != 1) {
    o[n++] = 0x01; o[n++] = 0xc3; /* transport: true */
  }
  o[n++] = 0xcc; o[n++] = 0xfb;
  if (int_cost) o[n++] = 0x17; /* an integer where the reference sends a float */
  else n += put_f64(o + n, 23.5);
  o[n++] = 0xcc; o[n++] = 0xfa;
  n += put_f64(o + n, 15.8);
  return n;
}
static rnc_packet with_ext(pair *p, const uint8_t *ext, size_t ext_size) {
  rnc_packet s = synthesis(p, p->hash);
  uint8_t signed_data[112 + 128];
  memcpy(signed_data, s.data, 112);
  memcpy(signed_data + 112, ext, ext_size);
  CHECK(rnc_identity_sign(&p->a_id, signed_data, 112 + ext_size, s.data + 112) == RNC_OK);
  memcpy(s.data + 176, ext, ext_size);
  s.data_size = 176 + ext_size;
  return s;
}
static void accepts_extension(void) {
  pair p;
  uint8_t ext[128];
  size_t n = reference_ext(ext, 0, 0);
  rnc_packet s;
  setup(&p);
  s = with_ext(&p, ext, n);
  CHECK(rnc_node_input(p.b, 1, &s, 1700000000, p.now) == RNC_OK);
  CHECK(rnc_node_tunnel_count(p.b) == 1);
  rnc_node_free(p.a);
  rnc_node_free(p.b);
}
static void rejects_bad_extension(void) {
  pair p;
  uint8_t ext[128];
  size_t n;
  rnc_packet s;
  setup(&p);
  n = reference_ext(ext, 1, 0); /* no transport status */
  s = with_ext(&p, ext, n);
  CHECK(rnc_node_input(p.b, 1, &s, 1700000000, p.now) == RNC_PROTOCOL);
  n = reference_ext(ext, 0, 1); /* destination cost not a float */
  s = with_ext(&p, ext, n);
  CHECK(rnc_node_input(p.b, 1, &s, 1700000000, p.now) == RNC_PROTOCOL);
  n = reference_ext(ext, 0, 0);
  s = with_ext(&p, ext, n - 3); /* truncated map */
  CHECK(rnc_node_input(p.b, 1, &s, 1700000000, p.now) == RNC_PROTOCOL);
  ext[n] = 0x00; /* extra bytes after the map */
  s = with_ext(&p, ext, n + 1);
  CHECK(rnc_node_input(p.b, 1, &s, 1700000000, p.now) == RNC_PROTOCOL);
  CHECK(rnc_node_tunnel_count(p.b) == 0);
  rnc_node_free(p.a);
  rnc_node_free(p.b);
}
/* The 1.6 extension: what a synthesis tells the peer, the reverse synthesis, and what each side keeps. */
static void peer_info(void) {
  pair p;
  rnc_packet syn, reply, old;
  rnc_tunnel_peer peer;
  uint8_t b_hash[32], id[32];
  rnc_node_event e;
  memset(b_hash, 0x77, sizeof(b_hash));
  setup(&p);
  CHECK(rnc_node_set_interface_stamp_costs(p.a, 1, 14.0, 9.0) == RNC_OK);
  CHECK(rnc_node_set_interface_tunnel(p.b, 1, b_hash, 1) == RNC_OK);
  CHECK(rnc_node_interface_tunnel_peer(p.b, 1, &peer) == RNC_OK && !peer.has_identity && !peer.has_info &&
        !peer.has_tunnel);
  syn = synthesis(&p, p.hash);
  CHECK(rnc_node_input(p.b, 1, &syn, 1700000000, p.now) == RNC_OK);
  CHECK(rnc_node_interface_tunnel_peer(p.b, 1, &peer) == RNC_OK && peer.has_identity && peer.has_info);
  CHECK(!memcmp(peer.identity_hash, p.a_id.hash, 16));
  CHECK(!strcmp(peer.implementation, "reticulum-c") && !strcmp(peer.version, RNC_VERSION_STRING));
  CHECK(!peer.transport && peer.destination_cost == 14.0 && peer.pr_cost == 9.0);
  expected_id(&p, p.hash, id);
  CHECK(peer.has_tunnel && !memcmp(peer.tunnel_id, id, 32) && rnc_node_tunnel_count(p.b) == 1);
  /* the receiver answers with its own synthesis, and the one that asked records it without making a tunnel */
  reply = take_send(p.b, 1);
  CHECK(reply.data_size > 176 && !memcmp(reply.data, p.b_id.public_key, 64) && !memcmp(reply.data + 64, b_hash, 32));
  CHECK(rnc_node_input(p.a, 1, &reply, 1700000000, p.now) == RNC_OK);
  CHECK(rnc_node_tunnel_count(p.a) == 0);
  CHECK(rnc_node_interface_tunnel_peer(p.a, 1, &peer) == RNC_OK && peer.has_info && peer.transport &&
        !memcmp(peer.identity_hash, p.b_id.hash, 16));
  CHECK(peer.destination_cost == rnc_netstamp_quantize(23.5) && peer.pr_cost == rnc_netstamp_quantize(15.8));
  CHECK(peer.has_tunnel && !memcmp(peer.tunnel_id, id, 32)); /* the tunnel it named itself */
  while (rnc_node_poll(p.a, &e) == RNC_OK)
    CHECK(e.type != RNC_NODE_SEND); /* no answer to an answer */
  /* a second synthesis on a connection is a violation */
  CHECK(rnc_node_input(p.b, 1, &syn, 1700000001, p.now) == RNC_PROTOCOL);
  /* the connection goes and what was known about the peer with it */
  CHECK(rnc_node_remove_interface(p.b, 1) == RNC_OK && rnc_node_add_interface(p.b, 1, 1000000) == RNC_OK);
  CHECK(rnc_node_interface_tunnel_peer(p.b, 1, &peer) == RNC_OK && !peer.has_identity && !peer.has_tunnel);
  /* the form without the extension, for a 1.5 peer: 176 bytes, and nothing is answered */
  CHECK(rnc_node_set_interface_tunnel(p.b, 1, b_hash, 1) == RNC_OK);
  CHECK(rnc_node_set_interface_tunnel(p.a, 1, NULL, 0) == RNC_OK);
  old = synthesis(&p, p.hash);
  CHECK(old.data_size == 176);
  while (rnc_node_poll(p.b, &e) == RNC_OK)
    ;
  CHECK(rnc_node_input(p.b, 1, &old, 1700000002, p.now) == RNC_OK);
  while (rnc_node_poll(p.b, &e) == RNC_OK)
    CHECK(e.type != RNC_NODE_SEND);
  CHECK(rnc_node_interface_tunnel_peer(p.b, 1, &peer) == RNC_OK && peer.has_identity && !peer.has_info);
  rnc_node_free(p.a);
  rnc_node_free(p.b);
}
/* A blackholed transport node gets no tunnel and no answer, and the host is told to drop the connection. */
static void peer_blackholed(void) {
  pair p;
  rnc_packet syn;
  rnc_node_event e;
  uint8_t b_hash[32];
  memset(b_hash, 0x77, sizeof(b_hash));
  setup(&p);
  CHECK(rnc_node_set_interface_tunnel(p.b, 1, b_hash, 1) == RNC_OK);
  CHECK(!rnc_node_interface_peer_blackholed(p.b, 1, 1700000000));
  CHECK(rnc_node_blackhole(p.b, p.a_id.hash, 0, "test", 1700000000) == RNC_OK);
  while (rnc_node_poll(p.b, &e) == RNC_OK)
    ;
  syn = synthesis(&p, p.hash);
  CHECK(rnc_node_input(p.b, 1, &syn, 1700000000, p.now) == RNC_OK);
  CHECK(rnc_node_tunnel_count(p.b) == 0);
  while (rnc_node_poll(p.b, &e) == RNC_OK)
    CHECK(e.type != RNC_NODE_SEND);
  CHECK(rnc_node_interface_peer_blackholed(p.b, 1, 1700000000));
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
  else if (!strcmp(argv[1], "extension"))
    accepts_extension();
  else if (!strcmp(argv[1], "extension_reject"))
    rejects_bad_extension();
  else if (!strcmp(argv[1], "peer"))
    peer_info();
  else if (!strcmp(argv[1], "peer_blackholed"))
    peer_blackholed();
  else
    CHECK(0);
  puts("tunnel test passed");
  return 0;
}
