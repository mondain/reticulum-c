#include <reticulum_c/rnc_link.h>
#include <reticulum_c/rnc_node.h>
#include <reticulum_c/rnc_security.h>
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
static uint32_t seed = 7;
static rnc_result rng(void *ctx, uint8_t *p, size_t n) {
  size_t i;
  (void)ctx;
  for (i = 0; i < n; i++) {
    seed = seed * 1664525u + 1013904223u;
    p[i] = (uint8_t)(seed >> 24);
  }
  return RNC_OK;
}
static rnc_identity identity(void) {
  rnc_identity id;
  CHECK(rnc_identity_generate(&id, rng, NULL) == RNC_OK);
  return id;
}
static void discard(rnc_node *n) {
  rnc_node_event e;
  while (rnc_node_poll(n, &e) == RNC_OK) {
  }
}
static rnc_packet sent(rnc_node *n, uint32_t iface) {
  rnc_node_event e;
  while (rnc_node_poll(n, &e) == RNC_OK)
    if (e.type == RNC_NODE_SEND && e.interface_id == iface)
      return e.packet;
  CHECK(0);
  return e.packet;
}
static void paths(void) {
  rnc_packet p;
  rnc_path_request q;
  static const uint8_t expected[16] = {0x6b, 0x9f, 0x66, 0x01, 0x4d, 0x98,
                                       0x53, 0xfa, 0xab, 0x22, 0x0f, 0xba,
                                       0x47, 0xd0, 0x27, 0x61};
  uint8_t dest[16] = {1}, tag[16] = {2}, tid[16] = {3};
  CHECK(rnc_path_request_create(dest, NULL, tag, 16, &p) == RNC_OK);
  CHECK(!memcmp(p.destination, expected, 16));
  CHECK(p.flags == 8 && p.data_size == 32 && memcmp(p.data, dest, 16) == 0);
  CHECK(rnc_path_request_decode(&p, &q) == RNC_OK && !q.has_transport &&
        q.tag_size == 16);
  CHECK(memcmp(q.tag, tag, 16) == 0);
  CHECK(rnc_path_request_create(dest, tid, tag, 16, &p) == RNC_OK &&
        p.data_size == 48);
  CHECK(rnc_path_request_decode(&p, &q) == RNC_OK && q.has_transport &&
        !memcmp(q.transport_id, tid, 16));
  p.data_size = 16;
  CHECK(rnc_path_request_decode(&p, &q) == RNC_PROTOCOL);
  CHECK(rnc_path_request_create(dest, NULL, tag, 0, &p) == RNC_INVALID);
}
static void routing(void) {
  rnc_identity ids[4];
  rnc_node *n[4];
  rnc_packet announce, p, q;
  rnc_route route;
  uint8_t name[10], dest[16], cipher[383];
  size_t size;
  unsigned i;
  for (i = 0; i < 4; i++) {
    ids[i] = identity();
    n[i] = rnc_node_new(&ids[i], i == 1 || i == 2, rng, NULL);
    CHECK(n[i]);
    CHECK(rnc_node_add_interface(n[i], 1, 1000000) == RNC_OK);
    if (i == 1 || i == 2)
      CHECK(rnc_node_add_interface(n[i], 2, 1000000) == RNC_OK);
  }
  CHECK(rnc_announce_create(&ids[3], "node.test", NULL, 0, 1000, rng, NULL,
                            &announce) == RNC_OK);
  CHECK(rnc_node_input(n[2], 2, &announce, 1000, 0) == RNC_OK);
  CHECK(rnc_node_lookup(n[2], announce.destination, 0, &route) == RNC_OK &&
        route.hops == 1 && route.interface_id == 2);
  CHECK(rnc_node_tick(n[2], 1000, 500) == RNC_OK);
  p = sent(n[2], 1);
  CHECK((p.flags & 0x50) == 0x50 && p.hops == 1 &&
        !memcmp(p.transport_id, ids[2].hash, 16));
  CHECK(rnc_node_input(n[1], 2, &p, 1000, 500) == RNC_OK);
  CHECK(rnc_node_tick(n[1], 1001, 1000) == RNC_OK);
  q = sent(n[1], 1);
  CHECK(rnc_node_input(n[0], 1, &q, 1001, 1000) == RNC_OK);
  CHECK(rnc_node_lookup(n[0], announce.destination, 1000, &route) == RNC_OK &&
        route.hops == 3 && !memcmp(route.next_hop, ids[1].hash, 16));
  for (i = 0; i < 4; i++)
    discard(n[i]);
  CHECK(rnc_destination_hash("node.test", &ids[3], name, dest) == RNC_OK);
  CHECK(rnc_identity_encrypt(&ids[3], "routed", 6, rng, NULL, cipher,
                             sizeof(cipher), &size) == RNC_OK);
  memset(&p, 0, sizeof(p));
  memcpy(p.destination, dest, 16);
  memcpy(p.data, cipher, size);
  p.data_size = size;
  CHECK(rnc_node_send(n[0], &p, 1001, 1100) == RNC_OK);
  p = sent(n[0], 1);
  CHECK(p.hops == 0 && !memcmp(p.transport_id, ids[1].hash, 16));
  CHECK(rnc_node_input(n[1], 1, &p, 1001, 1101) == RNC_OK);
  q = sent(n[1], 2);
  CHECK(q.hops == 1 && !memcmp(q.transport_id, ids[2].hash, 16));
  CHECK(rnc_node_input(n[2], 1, &q, 1001, 1102) == RNC_OK);
  p = sent(n[2], 2);
  CHECK(p.hops == 2 && !(p.flags & 0x50));
  /* A transport header addressed to a different router must never be forwarded.
   */
  q.transport_id[0] ^= 1;
  CHECK(rnc_node_input(n[2], 1, &q, 1001, 1103) == RNC_OK);
  discard(n[2]);
  /* Signature tampering must not replace the established path. */
  announce.data[84] ^= 1;
  CHECK(rnc_node_input(n[2], 2, &announce, 1002, 1200) == RNC_AUTH);
  CHECK(rnc_node_lookup(n[2], dest, 1200, &route) == RNC_OK && route.hops == 1);
  CHECK(rnc_node_remove_interface(n[2], 2) == RNC_OK);
  CHECK(rnc_node_lookup(n[2], dest, 1200, &route) == RNC_AGAIN);
  for (i = 0; i < 4; i++) {
    rnc_node_free(n[i]);
    rnc_identity_clear(&ids[i]);
  }
}
static void mesh(void) {
  rnc_identity ids[4];
  rnc_node *nodes[4];
  rnc_link *links[2];
  rnc_announce peer;
  rnc_packet a, p;
  rnc_node_event e;
  rnc_link_event le;
  rnc_route route;
  uint8_t dest[16], address[16];
  unsigned i, step, delivered = 0, round = 0;
  uint64_t now = 2000;
  int accepted = 0, sent_text = 0, got_text = 0;
  for (i = 0; i < 4; i++) {
    ids[i] = identity();
    nodes[i] = rnc_node_new(&ids[i], i == 1 || i == 2, rng, NULL);
    CHECK(nodes[i]);
    CHECK(rnc_node_add_interface(nodes[i], 1, 1000000) == RNC_OK);
    if (i == 1 || i == 2)
      CHECK(rnc_node_add_interface(nodes[i], 2, 1000000) == RNC_OK);
  }
  CHECK(rnc_node_add_destination(nodes[3], &ids[3], "node.mesh", NULL, 0,
                                 dest) == RNC_OK);
  CHECK(rnc_announce_create(&ids[3], "node.mesh", NULL, 0, 1000, rng, NULL,
                            &a) == RNC_OK);
  CHECK(rnc_node_input(nodes[2], 2, &a, 1000, 0) == RNC_OK);
  CHECK(rnc_node_tick(nodes[2], 1000, 500) == RNC_OK);
  p = sent(nodes[2], 1);
  CHECK(rnc_node_input(nodes[1], 2, &p, 1000, 500) == RNC_OK);
  CHECK(rnc_node_tick(nodes[1], 1001, 1000) == RNC_OK);
  p = sent(nodes[1], 1);
  CHECK(rnc_node_input(nodes[0], 1, &p, 1001, 1000) == RNC_OK);
  CHECK(rnc_node_lookup(nodes[0], dest, 1000, &route) == RNC_OK);
  peer = route.announce;
  for (i = 0; i < 4; i++)
    discard(nodes[i]);
  links[0] = rnc_link_new(rng, NULL);
  links[1] = rnc_link_new(rng, NULL);
  CHECK(links[0] && links[1]);
  CHECK(rnc_link_open(links[0], &peer, now) == RNC_OK);
  CHECK(rnc_link_address(links[0], address) == RNC_OK);
  CHECK(rnc_node_bind_link_on(nodes[0], address, 1) == RNC_OK);
  for (step = 0; step < 1000; step++) {
    now++;
    for (i = 0; i < 4; i++)
      CHECK(rnc_node_tick(nodes[i], 1001, now) == RNC_OK);
    for (i = 0; i < 2; i++) {
      unsigned node = i ? 3 : 0;
      while (rnc_link_poll(links[i], &le) == RNC_OK) {
        if (le.type == RNC_LINK_SEND)
          CHECK(rnc_node_send(nodes[node], &le.packet, 1001, now) == RNC_OK);
        if (le.type == RNC_LINK_MESSAGE) {
          CHECK(i == 1 && le.size == 10 && !memcmp(le.data, "mesh hello", 10));
          got_text++;
        }
        if (le.type == RNC_LINK_DELIVERED)
          delivered++;
      }
    }
    for (i = 0; i < 4; i++)
      while (rnc_node_poll(nodes[i], &e) == RNC_OK) {
        if (e.type == RNC_NODE_SEND) {
          unsigned target;
          uint32_t iface;
          if (i == 0) {
            target = 1;
            iface = 1;
          } else if (i == 3) {
            target = 2;
            iface = 2;
          } else if (i == 1 && e.interface_id == 1) {
            target = 0;
            iface = 1;
          } else if (i == 1) {
            target = 2;
            iface = 1;
          } else if (e.interface_id == 1) {
            target = 1;
            iface = 2;
          } else {
            target = 3;
            iface = 1;
          }
          CHECK(rnc_node_input(nodes[target], iface, &e.packet, 1001, now) ==
                RNC_OK);
        } else if (e.type == RNC_NODE_LOCAL) {
          CHECK(i == 0 || i == 3);
          if (i == 3 && (e.packet.flags & 3u) == RNC_LINKREQUEST) {
            CHECK(!accepted);
            CHECK(rnc_link_accept(links[1], &ids[3], dest, &e.packet, now) ==
                  RNC_OK);
            CHECK(rnc_link_address(links[1], address) == RNC_OK);
            CHECK(rnc_node_bind_link_on(nodes[3], address, 1) == RNC_OK);
            accepted = 1;
          } else
            CHECK(rnc_link_input(links[i == 3], &e.packet, now) == RNC_OK);
        }
      }
    if (!sent_text && rnc_link_is_active(links[0]) &&
        rnc_link_is_active(links[1])) {
      CHECK(rnc_link_send(links[0], 123, "mesh hello", 10, now) == RNC_OK);
      sent_text = 1;
    }
    if (delivered) {
      CHECK(got_text == 1);
      if (round == 2)
        break;
      round++;
      now += 170000;
      sent_text = 0;
      got_text = 0;
      delivered = 0;
    }
  }
  CHECK(sent_text && got_text == 1 && delivered == 1);
  CHECK(round == 2);
  rnc_link_free(links[0]);
  rnc_link_free(links[1]);
  for (i = 0; i < 4; i++) {
    rnc_node_free(nodes[i]);
    rnc_identity_clear(&ids[i]);
  }
}
static void discovery(void) {
  rnc_identity ids[3];
  rnc_node *a, *router, *b;
  rnc_packet p, reply;
  rnc_route route;
  uint8_t destination[16];
  unsigned i;
  for (i = 0; i < 3; i++)
    ids[i] = identity();
  a = rnc_node_new(&ids[0], 0, rng, NULL);
  router = rnc_node_new(&ids[1], 1, rng, NULL);
  b = rnc_node_new(&ids[2], 0, rng, NULL);
  CHECK(a && router && b);
  CHECK(rnc_node_add_interface(a, 1, 1000000) == RNC_OK);
  CHECK(rnc_node_add_interface(router, 1, 1000000) == RNC_OK);
  {
    /* Only gateway-style client interfaces search on their clients' behalf. */
    rnc_interface_policy gateway = {0};
    gateway.mode = RNC_MODE_GATEWAY;
    CHECK(rnc_node_interface_policy(router, 1, &gateway) == RNC_OK);
  }
  CHECK(rnc_node_add_interface(router, 2, 1000000) == RNC_OK);
  CHECK(rnc_node_add_interface(b, 1, 1000000) == RNC_OK);
  CHECK(rnc_node_add_destination(b, &ids[2], "node.discover", NULL, 0,
                                 destination) == RNC_OK);
  CHECK(rnc_node_request_path(a, destination, 0) == RNC_OK);
  p = sent(a, 1);
  CHECK(rnc_node_input(router, 1, &p, 1000, 1) == RNC_OK);
  p = sent(router, 2);
  CHECK(rnc_node_input(b, 1, &p, 1000, 2) == RNC_OK);
  CHECK(rnc_node_tick(b, 1000, 2) == RNC_OK);
  reply = sent(b, 1);
  CHECK(reply.context == 11);
  CHECK(rnc_node_input(router, 2, &reply, 1000, 3) == RNC_OK);
  CHECK(rnc_node_tick(router, 1000, 3) == RNC_OK);
  reply = sent(router, 1);
  CHECK(rnc_node_input(a, 1, &reply, 1000, 4) == RNC_OK);
  CHECK(rnc_node_lookup(a, destination, 4, &route) == RNC_OK &&
        route.hops == 2);
  CHECK(rnc_node_lookup(a, destination, 3, &route) == RNC_INVALID);
  CHECK(rnc_node_tick(a, 1000, 604800005) == RNC_OK);
  CHECK(rnc_node_lookup(a, destination, 604800005, &route) == RNC_AGAIN);
  rnc_node_free(a);
  rnc_node_free(router);
  rnc_node_free(b);
  for (i = 0; i < 3; i++)
    rnc_identity_clear(&ids[i]);
}
static void local_binding(void) {
  rnc_identity id = identity();
  rnc_node *n = rnc_node_new(&id, 0, rng, NULL);
  rnc_packet p = {0};
  rnc_node_event e;
  uint8_t link_id[16] = {7};
  CHECK(n && rnc_node_add_interface(n, 1, 1000000) == RNC_OK &&
        rnc_node_add_interface(n, 2, 1000000) == RNC_OK);
  CHECK(rnc_node_bind_link_on(n, link_id, 1) == RNC_OK);
  p.flags = 12;
  p.data_size = 1;
  p.data[0] = 42;
  memcpy(p.destination, link_id, 16);
  CHECK(rnc_node_input(n, 2, &p, 1000, 1) == RNC_PROTOCOL);
  CHECK(rnc_node_poll(n, &e) == RNC_AGAIN);
  CHECK(rnc_node_send(n, &p, 1000, 2) == RNC_OK);
  CHECK(rnc_node_poll(n, &e) == RNC_OK && e.type == RNC_NODE_SEND &&
        e.interface_id == 1);
  CHECK(rnc_node_poll(n, &e) == RNC_AGAIN);
  rnc_node_free(n);
  rnc_identity_clear(&id);
}
static void request_replay(void) {
  rnc_identity id = identity();
  rnc_node *n = rnc_node_new(&id, 1, rng, NULL);
  rnc_packet p;
  rnc_node_event e;
  uint8_t destination[16], tag[16] = {1};
  unsigned responses = 0;
  CHECK(n && rnc_node_add_interface(n, 1, 1000) == RNC_OK);
  CHECK(rnc_node_add_destination(n, &id, "node.replay", NULL, 0, destination) ==
        RNC_OK);
  CHECK(rnc_path_request_create(destination, NULL, tag, 16, &p) == RNC_OK);
  CHECK(rnc_node_input(n, 1, &p, 1000, 1) == RNC_OK);
  CHECK(rnc_node_input(n, 1, &p, 1000, 2) == RNC_OK);
  CHECK(rnc_node_tick(n, 1000, 3) == RNC_OK);
  while (rnc_node_poll(n, &e) == RNC_OK)
    if (e.type == RNC_NODE_SEND)
      responses++;
  CHECK(responses == 1);
  CHECK(rnc_node_tick(n, 1010, 10003) == RNC_OK);
  CHECK(rnc_node_poll(n, &e) == RNC_AGAIN);
  rnc_node_free(n);
  rnc_identity_clear(&id);
}
static void guards(void) {
  rnc_identity local = identity(), peer = identity();
  rnc_node *n = rnc_node_new(&local, 1, rng, NULL);
  rnc_packet a, p;
  rnc_node_event e;
  uint8_t destination[16];
  CHECK(n && rnc_node_add_interface(n, 1, 1000000) == RNC_OK);
  CHECK(rnc_announce_create(&peer, "node.shared", NULL, 0, 1000, rng, NULL,
                            &a) == RNC_OK);
  a.flags |= 0x50;
  a.hops = 1;
  memset(a.transport_id, 3, 16);
  CHECK(rnc_node_input(n, 1, &a, 1000, 0) == RNC_OK);
  discard(n);
  memset(&p, 0, sizeof(p));
  p.flags = 0x50;
  p.data[0] = 1;
  p.data_size = 1;
  memcpy(p.destination, a.destination, 16);
  memcpy(p.transport_id, local.hash, 16);
  CHECK(rnc_node_input(n, 1, &p, 1000, 1) == RNC_OK);
  p = sent(n, 1);
  CHECK(!memcmp(p.transport_id, a.transport_id, 16));
  p.flags = 0;
  p.hops = 0;
  p.data_size = RNC_MTU - 19u;
  memset(p.data, 1, sizeof(p.data));
  CHECK(rnc_node_send(n, &p, 1000, 1) == RNC_NO_SPACE);

  CHECK(rnc_node_add_destination(n, &local, "node.local", NULL, 0,
                                 destination) == RNC_OK);
  memset(&p, 0, sizeof(p));
  memcpy(p.destination, destination, 16);
  p.data[0] = 1;
  p.data_size = 1;
  CHECK(rnc_node_input(n, 1, &p, 1000, 2) == RNC_OK);
  CHECK(rnc_node_remove_interface(n, 1) == RNC_OK);
  CHECK(rnc_node_poll(n, &e) == RNC_AGAIN);
  rnc_node_free(n);
  local_binding();
  request_replay();
  rnc_identity_clear(&local);
  rnc_identity_clear(&peer);
}
static void state_test(void) {
  rnc_identity id = identity(), remote = identity();
  rnc_node *a = rnc_node_new(&id, 1, rng, NULL),
           *b = rnc_node_new(&id, 1, rng, NULL),
           *c = rnc_node_new(&id, 1, rng, NULL);
  rnc_packet p;
  rnc_route route;
  uint8_t state[2048];
  size_t written;
  CHECK(a && b && c && rnc_node_add_interface(a, 1, 1000000) == RNC_OK &&
        rnc_node_add_interface(b, 1, 1000000) == RNC_OK &&
        rnc_node_add_interface(c, 1, 1000000) == RNC_OK);
  CHECK(rnc_announce_create(&remote, "node.state", NULL, 0, 1000, rng, NULL,
                            &p) == RNC_OK);
  CHECK(rnc_node_input(a, 1, &p, 1000, 10) == RNC_OK);
  discard(a);
  CHECK(rnc_node_state_export(a, &id, 1000, 10, state, sizeof(state),
                              &written) == RNC_OK &&
        written > 64);
  CHECK(rnc_node_state_import(b, &id, 1010, 20, state, written) == RNC_OK);
  CHECK(rnc_node_lookup(b, p.destination, 20, &route) == RNC_OK &&
        route.hops == 1 && route.interface_id == 1);
  CHECK(rnc_node_route_at(b, 0, 20, &route) == RNC_OK &&
        rnc_node_route_at(b, 1, 20, &route) == RNC_AGAIN);
  state[written - 1] ^= 1;
  CHECK(rnc_node_state_import(c, &id, 1010, 20, state, written) == RNC_AUTH);
  CHECK(rnc_node_lookup(c, p.destination, 20, &route) == RNC_AGAIN);
  state[written - 1] ^= 1;
  CHECK(rnc_node_state_import(c, &id, 999, 20, state, written) == RNC_INVALID);
  CHECK(rnc_node_state_import(c, &id, 1000000, 20, state, written) == RNC_OK);
  CHECK(rnc_node_lookup(c, p.destination, 20, &route) == RNC_AGAIN);
  rnc_node_free(a);
  rnc_node_free(b);
  rnc_node_free(c);
  rnc_identity_clear(&id);
  rnc_identity_clear(&remote);
}
static void local_clients(void) {
  rnc_identity own = identity(), remote = identity(), child = identity();
  rnc_node *n = rnc_node_new(&own, 0, rng, NULL);
  rnc_packet a, p;
  rnc_route route;
  CHECK(n && rnc_node_add_interface(n, 1, 1000000) == RNC_OK &&
        rnc_node_add_interface(n, 2, 1000000) == RNC_OK);
  CHECK(rnc_node_local_interface(n, 2, 1) == RNC_OK);
  CHECK(rnc_announce_create(&remote, "node.remote", NULL, 0, 1000, rng, NULL,
                            &a) == RNC_OK);
  CHECK(rnc_node_input(n, 1, &a, 1000, 0) == RNC_OK);
  CHECK(rnc_node_tick(n, 1000, 500) == RNC_OK);
  p = sent(n, 2);
  CHECK(p.hops == 1);
  CHECK(rnc_announce_create(&child, "node.child", NULL, 0, 1001, rng, NULL,
                            &a) == RNC_OK);
  CHECK(rnc_node_input(n, 2, &a, 1001, 1000) == RNC_OK);
  CHECK(rnc_node_lookup(n, a.destination, 1000, &route) == RNC_OK &&
        route.hops == 0);
  CHECK(rnc_node_tick(n, 1001, 1500) == RNC_OK);
  p = sent(n, 1);
  CHECK(p.hops == 0);
  discard(n);
  memset(&p, 0, sizeof(p));
  memcpy(p.destination, a.destination, 16);
  p.data[0] = 1;
  p.data_size = 1;
  CHECK(rnc_node_input(n, 1, &p, 1001, 1600) == RNC_OK);
  p = sent(n, 2);
  CHECK(p.hops == 1);
  rnc_node_free(n);
  rnc_identity_clear(&own);
  rnc_identity_clear(&remote);
  rnc_identity_clear(&child);
}
static void destinations(void) {
  rnc_identity id = identity();
  rnc_node *n = rnc_node_new(&id, 0, rng, NULL);
  uint8_t group[16], plain[16], single[16];
  rnc_packet p;
  rnc_node_event e;
  rnc_group_key key;
  rnc_ratchet_key ratchet;
  rnc_announce verified;
  uint8_t data[500];
  size_t size;
  CHECK(n && rnc_node_add_interface(n, 1, 1000000) == RNC_OK);
  CHECK(rnc_node_add_destination_ex(n, &id, RNC_GROUP, "node.group", NULL, 0,
                                    group) == RNC_OK);
  CHECK(rnc_node_add_destination_ex(n, NULL, RNC_PLAIN, "node.plain", NULL, 0,
                                    plain) == RNC_OK);
  CHECK(rnc_group_generate(&key, rng, NULL) == RNC_OK);
  memset(&p, 0, sizeof(p));
  p.flags = 4;
  memcpy(p.destination, group, 16);
  CHECK(rnc_group_encrypt(&key, "group", 5, rng, NULL, p.data, sizeof(p.data),
                          &p.data_size) == RNC_OK);
  CHECK(rnc_node_input(n, 1, &p, 1000, 1) == RNC_OK);
  CHECK(rnc_node_poll(n, &e) == RNC_OK && e.type == RNC_NODE_LOCAL);
  CHECK(rnc_group_decrypt(&key, e.packet.data, e.packet.data_size, data,
                          sizeof(data), &size) == RNC_OK &&
        size == 5 && !memcmp(data, "group", 5));
  CHECK(rnc_node_announce(n, group, 1000, 2) == RNC_STATE);
  CHECK(rnc_node_add_destination(n, &id, "node.ratchet", NULL, 0, single) ==
        RNC_OK);
  CHECK(rnc_ratchet_generate(&ratchet, 1000, rng, NULL) == RNC_OK);
  CHECK(rnc_node_set_ratchet(n, single, ratchet.public_key) == RNC_OK);
  CHECK(rnc_node_announce(n, single, 1000, 2) == RNC_OK);
  CHECK(rnc_node_tick(n, 1000, 2) == RNC_OK);
  p = sent(n, 1);
  CHECK(rnc_announce_verify(&p, &verified) == RNC_OK && verified.has_ratchet &&
        !memcmp(verified.ratchet, ratchet.public_key, 32));
  rnc_group_clear(&key);
  rnc_ratchet_clear(&ratchet);
  rnc_node_free(n);
  rnc_identity_clear(&id);
}
static void destination_data(void) {
  rnc_identity id = identity();
  rnc_node *n = rnc_node_new(&id, 0, rng, NULL);
  uint8_t single[16], plain[16], big[317] = {0};
  rnc_packet p;
  rnc_announce a;
  CHECK(n && rnc_node_add_interface(n, 1, 1000000) == RNC_OK);
  CHECK(rnc_node_add_destination(n, &id, "node.data", "first", 5, single) ==
        RNC_OK);
  CHECK(rnc_node_set_destination_data(n, single, "second payload", 14) ==
        RNC_OK);
  CHECK(rnc_node_announce(n, single, 1000, 1) == RNC_OK);
  CHECK(rnc_node_tick(n, 1000, 1) == RNC_OK);
  p = sent(n, 1);
  CHECK(rnc_announce_verify(&p, &a) == RNC_OK && a.app_size == 14 &&
        !memcmp(a.app_data, "second payload", 14));
  CHECK(rnc_node_set_destination_data(n, single, NULL, 0) == RNC_OK);
  CHECK(rnc_node_set_destination_data(n, single, big, sizeof(big)) ==
        RNC_INVALID);
  CHECK(rnc_node_set_destination_data(n, single, NULL, 3) == RNC_INVALID);
  memset(plain, 7, 16);
  CHECK(rnc_node_set_destination_data(n, plain, "x", 1) == RNC_STATE);
  CHECK(rnc_node_set_destination_data(NULL, single, "x", 1) == RNC_INVALID);
  rnc_node_free(n);
  rnc_identity_clear(&id);
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  if (!strcmp(argv[1], "paths"))
    paths();
  else if (!strcmp(argv[1], "routing"))
    routing();
  else if (!strcmp(argv[1], "guards"))
    guards();
  else if (!strcmp(argv[1], "destinations"))
    destinations();
  else if (!strcmp(argv[1], "local"))
    local_clients();
  else if (!strcmp(argv[1], "state"))
    state_test();
  else if (!strcmp(argv[1], "mesh"))
    mesh();
  else if (!strcmp(argv[1], "discovery"))
    discovery();
  else if (!strcmp(argv[1], "destination_data"))
    destination_data();
  else
    CHECK(0);
  return 0;
}
