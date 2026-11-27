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
/* Which input is discarded traffic (rnstatus -F) and which is link traffic (rnstatus -l). */
static void input_class(void) {
  rnc_identity src = identity(), bad = identity(), self = identity();
  rnc_node *n = rnc_node_new(&self, 0, rng, NULL), *router = rnc_node_new(&self, 1, rng, NULL);
  rnc_packet first, older, newer, response, blocked, request, data;
  uint8_t tag[16] = {9};
  uint64_t discarded = 0;
  CHECK(n && router);
  CHECK(rnc_node_add_interface(n, 1, 1000000) == RNC_OK && rnc_node_add_interface(n, 2, 1000000) == RNC_OK);
  CHECK(rnc_announce_create(&src, "class.test", NULL, 0, 900, rng, NULL, &older) == RNC_OK);
  CHECK(rnc_announce_create(&src, "class.test", NULL, 0, 1000, rng, NULL, &first) == RNC_OK);
  CHECK(rnc_announce_create(&src, "class.test", NULL, 0, 1001, rng, NULL, &newer) == RNC_OK);
  CHECK(rnc_node_input(n, 1, &first, 1002, 10) == RNC_OK && rnc_node_input_class(n) == 0);
  /* the same announce over another interface, or an older one, brings nothing new */
  CHECK(rnc_node_input(n, 2, &first, 1002, 20) == RNC_OK);
  CHECK(rnc_node_input_class(n) == (RNC_INPUT_FILTERED | RNC_INPUT_HEARD));
  CHECK(rnc_node_input(n, 2, &older, 1002, 30) == RNC_OK);
  CHECK(rnc_node_input_class(n) == (RNC_INPUT_FILTERED | RNC_INPUT_HEARD));
  CHECK(rnc_node_interface_filtered(n, 2, &discarded) == RNC_OK && discarded == 2);
  /* a path response is never judged stale */
  response = first;
  response.context = 11;
  CHECK(rnc_node_input(n, 2, &response, 1002, 40) == RNC_OK && rnc_node_input_class(n) == 0);
  CHECK(rnc_node_input(n, 1, &newer, 1002, 50) == RNC_OK && rnc_node_input_class(n) == 0);
  CHECK(rnc_announce_create(&bad, "class.bad", NULL, 0, 1000, rng, NULL, &blocked) == RNC_OK);
  CHECK(rnc_node_blackhole(n, bad.hash, 0, "test", 1002) == RNC_OK);
  CHECK(rnc_node_input(n, 2, &blocked, 1002, 60) == RNC_OK && rnc_node_input_class(n) == RNC_INPUT_FILTERED);
  CHECK(rnc_node_interface_filtered(n, 2, &discarded) == RNC_OK && discarded == 3);
  /* a transport node: forwarded data, then the same packet again */
  CHECK(rnc_node_add_interface(router, 1, 1000000) == RNC_OK && rnc_node_add_interface(router, 2, 1000000) == RNC_OK);
  CHECK(rnc_node_input(router, 1, &first, 1002, 10) == RNC_OK);
  discard(router);
  memset(&data, 0, sizeof(data));
  data.flags = 0x50; /* header type 2, in transport */
  memcpy(data.transport_id, self.hash, 16);
  memcpy(data.destination, first.destination, 16);
  data.data_size = 40;
  CHECK(rnc_node_input(router, 2, &data, 1002, 20) == RNC_OK && rnc_node_input_class(router) == 0);
  CHECK(rnc_node_input(router, 2, &data, 1002, 30) == RNC_OK && rnc_node_input_class(router) == RNC_INPUT_FILTERED);
  /* in transport for another instance */
  data.transport_id[0] ^= 1;
  CHECK(rnc_node_input(router, 2, &data, 1002, 40) == RNC_OK && rnc_node_input_class(router) == RNC_INPUT_FILTERED);
  /* a repeated path request */
  CHECK(rnc_path_request_create(first.destination, NULL, tag, 16, &request) == RNC_OK);
  CHECK(rnc_node_input(router, 2, &request, 1002, 50) == RNC_OK && rnc_node_input_class(router) == 0);
  CHECK(rnc_node_input(router, 2, &request, 1002, 60) == RNC_OK && rnc_node_input_class(router) == RNC_INPUT_FILTERED);
  rnc_node_free(n);
  rnc_node_free(router);
}
/* A flood of new announces and of path requests is seen as a burst, and the announces as held. */
static void ingress_state(void) {
  rnc_identity self = identity();
  rnc_node *n = rnc_node_new(&self, 0, rng, NULL);
  rnc_node_ingress_state state;
  unsigned i;
  CHECK(n && rnc_node_add_interface(n, 1, 1000000) == RNC_OK);
  CHECK(rnc_node_interface_ingress(n, 1, &state) == RNC_OK);
  CHECK(!state.held_announces && !state.burst_active && !state.pr_burst_active && !state.burst_since_ms);
  for (i = 0; i < 20; i++) {
    rnc_identity src = identity();
    rnc_packet a;
    CHECK(rnc_announce_create(&src, "flood.test", NULL, 0, 1000, rng, NULL, &a) == RNC_OK);
    CHECK(rnc_node_input(n, 1, &a, 1000, 1000 + i * 10u) == RNC_OK);
    discard(n);
  }
  CHECK(rnc_node_interface_ingress(n, 1, &state) == RNC_OK);
  CHECK(state.burst_active && state.held_announces > 0 && state.burst_since_ms >= 1000 && state.burst_since_ms < 1200);
  CHECK(!state.pr_burst_active);
  for (i = 0; i < 20; i++) {
    uint8_t wanted[16], tag[16] = {0};
    rnc_packet request;
    CHECK(rng(NULL, wanted, 16) == RNC_OK);
    tag[0] = (uint8_t)i;
    CHECK(rnc_path_request_create(wanted, NULL, tag, 16, &request) == RNC_OK);
    CHECK(rnc_node_input(n, 1, &request, 1000, 2000 + i * 10u) == RNC_OK);
    discard(n);
  }
  CHECK(rnc_node_interface_ingress(n, 1, &state) == RNC_OK);
  CHECK(state.pr_burst_active && state.pr_burst_since_ms >= 2000);
  CHECK(rnc_node_interface_ingress(n, 9, &state) == RNC_STATE);
  CHECK(rnc_node_interface_ingress(n, 1, NULL) == RNC_INVALID);
  rnc_node_free(n);
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
  unsigned classes[4] = {0};
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
          classes[target] |= rnc_node_input_class(nodes[target]) & (RNC_INPUT_LINK_RX | RNC_INPUT_LINK_TX);
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
  /* the ends receive link traffic, the two routers between them receive and forward it */
  CHECK(classes[0] == RNC_INPUT_LINK_RX && classes[3] == RNC_INPUT_LINK_RX);
  CHECK(classes[1] == (RNC_INPUT_LINK_RX | RNC_INPUT_LINK_TX) && classes[2] == (RNC_INPUT_LINK_RX | RNC_INPUT_LINK_TX));
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
/* A local client's path request for an unknown destination is passed on to the other interfaces even by a node
 * that is not a transport instance, and without the transport id in it; a request from an ordinary interface is
 * not passed on by such a node. */
static void local_path_request(void) {
  rnc_identity own = identity();
  rnc_node *n = rnc_node_new(&own, 0, rng, NULL);
  rnc_packet request, out;
  rnc_path_request decoded;
  uint8_t destination[16] = {9}, tag[16] = {1, 2, 3};
  CHECK(n && rnc_node_add_interface(n, 1, 1000000) == RNC_OK && rnc_node_add_interface(n, 2, 1000000) == RNC_OK &&
        rnc_node_add_interface(n, 3, 1000000) == RNC_OK);
  CHECK(rnc_node_local_interface(n, 2, 1) == RNC_OK);
  CHECK(rnc_path_request_create(destination, NULL, tag, sizeof(tag), &request) == RNC_OK);
  CHECK(rnc_node_input(n, 2, &request, 1000, 0) == RNC_OK);
  out = sent(n, 1);
  CHECK(rnc_path_request_decode(&out, &decoded) == RNC_OK && !decoded.has_transport &&
        !memcmp(decoded.destination, destination, 16));
  out = sent(n, 3);
  CHECK(!memcmp(out.destination, request.destination, 16));
  discard(n);
  tag[0] = 7;
  CHECK(rnc_path_request_create(destination, NULL, tag, sizeof(tag), &request) == RNC_OK);
  CHECK(rnc_node_input(n, 1, &request, 1100, 10) == RNC_OK);
  {
    rnc_node_event e;
    CHECK(rnc_node_poll(n, &e) != RNC_OK || e.type != RNC_NODE_SEND); /* nothing is sent on */
  }
  rnc_node_free(n);
  rnc_identity_clear(&own);
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
  /* clearing it (clear_default_app_data): the next announce carries none */
  CHECK(rnc_node_set_destination_data(n, single, NULL, 0) == RNC_OK);
  CHECK(rnc_node_announce(n, single, 1001, 100000) == RNC_OK);
  CHECK(rnc_node_tick(n, 1001, 100000) == RNC_OK);
  p = sent(n, 1);
  CHECK(rnc_announce_verify(&p, &a) == RNC_OK && a.app_size == 0);
  CHECK(rnc_node_set_destination_data(n, single, big, sizeof(big)) ==
        RNC_INVALID);
  CHECK(rnc_node_set_destination_data(n, single, NULL, 3) == RNC_INVALID);
  memset(plain, 7, 16);
  CHECK(rnc_node_set_destination_data(n, plain, "x", 1) == RNC_STATE);
  CHECK(rnc_node_set_destination_data(NULL, single, "x", 1) == RNC_INVALID);
  rnc_node_free(n);
  rnc_identity_clear(&id);
}
/* Transport.request_path options: one interface, a chosen tag, and the
 * recursive form that waits for announce bandwidth and queued announces. */
static void request_path_options(void) {
  rnc_identity id = identity();
  rnc_node *n = rnc_node_new(&id, 0, rng, NULL);
  uint8_t dest[16] = {9}, tag[16] = {7, 7, 7}, announced[16];
  rnc_node_event e;
  rnc_path_request q;
  unsigned sends = 0;
  CHECK(n && rnc_node_add_interface(n, 1, 1000000) == RNC_OK &&
        rnc_node_add_interface(n, 2, 1000000) == RNC_OK);
  /* the default reaches every interface */
  CHECK(rnc_node_request_path(n, dest, 100) == RNC_OK);
  while (rnc_node_poll(n, &e) == RNC_OK)
    sends += e.type == RNC_NODE_SEND;
  CHECK(sends == 2);
  /* on_interface and a caller's tag */
  CHECK(rnc_node_request_path_ex(n, dest, 2, tag, 16, 0, 200) == RNC_OK);
  sends = 0;
  while (rnc_node_poll(n, &e) == RNC_OK) {
    CHECK(e.type == RNC_NODE_SEND && e.interface_id == 2);
    CHECK(rnc_path_request_decode(&e.packet, &q) == RNC_OK &&
          q.tag_size == 16 && !memcmp(q.tag, tag, 16));
    ++sends;
  }
  CHECK(sends == 1);
  CHECK(rnc_node_request_path_ex(n, dest, 9, NULL, 0, 0, 200) == RNC_STATE);
  CHECK(rnc_node_request_path_ex(n, dest, 0, tag, 17, 0, 200) == RNC_INVALID);
  CHECK(rnc_node_request_path_ex(n, dest, 1, NULL, 0, 0, 100) == RNC_INVALID); /* time went backwards */
  /* recursive: the second request waits for announce bandwidth (51 bytes at
   * 1 Mbit/s and 2 percent is 20.4 ms) */
  CHECK(rnc_node_request_path_ex(n, dest, 1, NULL, 0, 1, 300) == RNC_OK);
  discard(n);
  CHECK(rnc_node_request_path_ex(n, dest, 1, NULL, 0, 1, 310) == RNC_AGAIN);
  CHECK(rnc_node_request_path_ex(n, dest, 1, NULL, 0, 1, 321) == RNC_OK);
  /* a non-recursive request ignores the limit */
  CHECK(rnc_node_request_path_ex(n, dest, 1, NULL, 0, 0, 322) == RNC_OK);
  discard(n);
  /* queued announces on the interface block it too */
  CHECK(rnc_node_add_destination(n, &id, "queued.test", NULL, 0, announced) == RNC_OK);
  CHECK(rnc_node_announce(n, announced, 1000, 1000) == RNC_OK);
  CHECK(rnc_node_request_path_ex(n, dest, 1, NULL, 0, 1, 1001) == RNC_AGAIN);
  rnc_node_free(n);
}
/* Transport.hops_to: the hop count of a known path, 128 when there is none. */
static void hops_to(void) {
  rnc_identity a = identity(), b = identity();
  rnc_node *na = rnc_node_new(&a, 0, rng, NULL), *nb = rnc_node_new(&b, 0, rng, NULL);
  uint8_t dest[16];
  rnc_packet announce;
  CHECK(na && nb && rnc_node_add_interface(na, 1, 1000000) == RNC_OK &&
        rnc_node_add_interface(nb, 1, 1000000) == RNC_OK);
  CHECK(rnc_node_add_destination(nb, &b, "hops.test", NULL, 0, dest) == RNC_OK);
  CHECK(rnc_node_hops_to(na, dest, 10) == RNC_PATHFINDER_MAX_HOPS);
  CHECK(rnc_node_announce(nb, dest, 1000, 0) == RNC_OK);
  CHECK(rnc_node_tick(nb, 1000, 5) == RNC_OK);
  announce = sent(nb, 1);
  CHECK(rnc_node_input(na, 1, &announce, 1000, 20) == RNC_OK);
  CHECK(rnc_node_hops_to(na, dest, 30) == 1);
  rnc_node_free(na);
  rnc_node_free(nb);
}
/* Transport hop limit (PATHFINDER_M 128): the reference counts a hop on arrival and accepts an
 * announce up to 128 hops, but its outbound path refuses a packet above 127, so a path at 128
 * hops is learned and never rebroadcast. */
static void announce_hop_limit(void) {
  rnc_identity src = identity(), self = identity();
  rnc_packet announce, relayed;
  rnc_node_event e;
  rnc_route route;
  unsigned hops, relayed_count;
  for (hops = 125; hops <= 128; hops++) {
    rnc_node *n = rnc_node_new(&self, 1, rng, NULL);
    CHECK(n && rnc_node_add_interface(n, 1, 1000000) == RNC_OK &&
          rnc_node_add_interface(n, 2, 1000000) == RNC_OK);
    CHECK(rnc_announce_create(&src, "hop.limit", NULL, 0, 1000, rng, NULL, &announce) == RNC_OK);
    announce.hops = (uint8_t)hops;
    if (hops <= 127) {
      CHECK(rnc_node_input(n, 1, &announce, 1000, 0) == RNC_OK);
      CHECK(rnc_node_lookup(n, announce.destination, 0, &route) == RNC_OK && route.hops == hops + 1u);
    } else {
      CHECK(rnc_node_input(n, 1, &announce, 1000, 0) != RNC_OK); /* 129 hops: refused */
      CHECK(rnc_node_lookup(n, announce.destination, 0, &route) != RNC_OK);
    }
    discard(n);
    CHECK(rnc_node_tick(n, 1000, 2000) == RNC_OK);
    relayed_count = 0;
    while (rnc_node_poll(n, &e) == RNC_OK)
      if (e.type == RNC_NODE_SEND && e.interface_id == 2) {
        relayed = e.packet;
        relayed_count++;
      }
    (void)relayed;
    /* up to 127 hops after arrival the announce is passed on; at 128 it is only learned */
    CHECK(relayed_count == (hops + 1u <= 127u ? 1u : 0u));
    rnc_node_free(n);
  }
}
/* Interface gravity: the same announce heard later on an interface of higher gravity moves the path
 * there (Transport.inbound, RNS 1.5.5); equal or lower gravity, or more hops, keep the path. */
static void set_gravity(rnc_node *n, uint32_t id, int gravity) {
  rnc_interface_policy pol;
  memset(&pol, 0, sizeof(pol));
  pol.announce_cap_permille = 20;
  pol.gravity = gravity;
  CHECK(rnc_node_interface_policy(n, id, &pol) == RNC_OK);
}
static void gravity(void) {
  rnc_identity src = identity(), self = identity();
  rnc_packet announce, far;
  rnc_route route;
  rnc_node *n = rnc_node_new(&self, 0, rng, NULL);
  CHECK(n && rnc_node_add_interface(n, 1, 1000000) == RNC_OK &&
        rnc_node_add_interface(n, 2, 1000000) == RNC_OK &&
        rnc_node_add_interface(n, 3, 1000000) == RNC_OK);
  set_gravity(n, 1, 0);
  set_gravity(n, 2, 5);
  set_gravity(n, 3, 5);
  CHECK(rnc_announce_create(&src, "gravity.test", NULL, 0, 1000, rng, NULL, &announce) == RNC_OK);
  CHECK(rnc_node_input(n, 1, &announce, 1000, 0) == RNC_OK);
  CHECK(rnc_node_lookup(n, announce.destination, 0, &route) == RNC_OK && route.interface_id == 1);
  /* the same announce on a higher-gravity interface takes the path over */
  CHECK(rnc_node_input(n, 2, &announce, 1000, 10) == RNC_OK);
  CHECK(rnc_node_lookup(n, announce.destination, 10, &route) == RNC_OK && route.interface_id == 2 &&
        route.hops == 1);
  /* equal gravity does not */
  CHECK(rnc_node_input(n, 3, &announce, 1000, 20) == RNC_OK);
  CHECK(rnc_node_lookup(n, announce.destination, 20, &route) == RNC_OK && route.interface_id == 2);
  /* lower gravity does not */
  CHECK(rnc_node_input(n, 1, &announce, 1000, 30) == RNC_OK);
  CHECK(rnc_node_lookup(n, announce.destination, 30, &route) == RNC_OK && route.interface_id == 2);
  rnc_node_free(n);
  /* a longer path on the higher-gravity interface does not replace a shorter one */
  n = rnc_node_new(&self, 0, rng, NULL);
  CHECK(n && rnc_node_add_interface(n, 1, 1000000) == RNC_OK &&
        rnc_node_add_interface(n, 2, 1000000) == RNC_OK);
  set_gravity(n, 2, 5);
  far = announce;
  far.hops = 3;
  CHECK(rnc_node_input(n, 1, &announce, 1000, 0) == RNC_OK);
  CHECK(rnc_node_input(n, 2, &far, 1000, 10) == RNC_OK);
  CHECK(rnc_node_lookup(n, announce.destination, 10, &route) == RNC_OK && route.interface_id == 1 &&
        route.hops == 1);
  rnc_node_free(n);
}
/* drop_path, drop_all_via and drop_announce_queues, as the reference's RPC and rnpath use them. */
static void drops(void) {
  rnc_identity src = identity(), other = identity(), self = identity();
  rnc_packet a1, a2;
  rnc_route route;
  rnc_node_event e;
  rnc_node *n = rnc_node_new(&self, 1, rng, NULL);
  unsigned sent = 0;
  CHECK(n && rnc_node_add_interface(n, 1, 1000000) == RNC_OK && rnc_node_add_interface(n, 2, 1000000) == RNC_OK);
  CHECK(rnc_announce_create(&src, "drop.one", NULL, 0, 1000, rng, NULL, &a1) == RNC_OK);
  CHECK(rnc_announce_create(&other, "drop.two", NULL, 0, 1000, rng, NULL, &a2) == RNC_OK);
  CHECK(rnc_node_input(n, 1, &a1, 1000, 0) == RNC_OK && rnc_node_input(n, 1, &a2, 1000, 0) == RNC_OK);
  CHECK(rnc_node_lookup(n, a1.destination, 0, &route) == RNC_OK);
  /* a path is dropped once; asking again, or for an unknown one, says there was none */
  CHECK(rnc_node_drop_path(n, a1.destination) == RNC_OK);
  CHECK(rnc_node_lookup(n, a1.destination, 0, &route) == RNC_AGAIN);
  CHECK(rnc_node_drop_path(n, a1.destination) == RNC_STATE);
  CHECK(rnc_node_lookup(n, a2.destination, 0, &route) == RNC_OK);
  /* everything learned through one next hop; a direct path's next hop is its own destination */
  CHECK(rnc_node_drop_via(n, a2.destination) == 1u);
  CHECK(rnc_node_lookup(n, a2.destination, 0, &route) == RNC_AGAIN);
  CHECK(rnc_node_drop_via(n, a2.destination) == 0u);
  /* announces waiting to be sent are discarded */
  CHECK(rnc_announce_create(&src, "drop.three", NULL, 0, 1000, rng, NULL, &a1) == RNC_OK);
  CHECK(rnc_node_input(n, 1, &a1, 1000, 10) == RNC_OK);
  CHECK(rnc_node_drop_announce_queues(n) >= 1u);
  CHECK(rnc_node_tick(n, 1000, 5000) == RNC_OK);
  while (rnc_node_poll(n, &e) == RNC_OK)
    if (e.type == RNC_NODE_SEND && e.interface_id == 2)
      sent++;
  CHECK(sent == 0);
  CHECK(rnc_node_drop_announce_queues(n) == 0u);
  rnc_node_free(n);
}
/* Destination.accepts_links: link requests to a destination that does not
 * accept them are dropped before the application sees them. */
static void accepts_links(void) {
  rnc_identity id = identity();
  rnc_node *n = rnc_node_new(&id, 0, rng, NULL);
  uint8_t dest[16], unknown[16] = {5};
  rnc_packet request = {0};
  rnc_node_event e;
  unsigned locals;
  CHECK(n && rnc_node_add_interface(n, 1, 1000000) == RNC_OK);
  CHECK(rnc_node_add_destination(n, &id, "links.test", NULL, 0, dest) == RNC_OK);
  CHECK(rnc_node_accepts_links(n, dest) == 1 && rnc_node_accepts_links(n, unknown) == 0);
  request.flags = 2; /* link request */
  memcpy(request.destination, dest, 16);
  request.data_size = 67;
  CHECK(rng(NULL, request.data, 67) == RNC_OK);
  CHECK(rnc_node_input(n, 1, &request, 1000, 10) == RNC_OK);
  locals = 0;
  while (rnc_node_poll(n, &e) == RNC_OK)
    locals += e.type == RNC_NODE_LOCAL;
  CHECK(locals == 1);
  CHECK(rnc_node_set_accepts_links(n, dest, 0) == RNC_OK && rnc_node_accepts_links(n, dest) == 0);
  CHECK(rng(NULL, request.data, 67) == RNC_OK);
  (void)rnc_node_input(n, 1, &request, 1000, 20);
  locals = 0;
  while (rnc_node_poll(n, &e) == RNC_OK)
    locals += e.type == RNC_NODE_LOCAL;
  CHECK(locals == 0);
  CHECK(rnc_node_set_accepts_links(n, dest, 1) == RNC_OK);
  CHECK(rng(NULL, request.data, 67) == RNC_OK);
  CHECK(rnc_node_input(n, 1, &request, 1000, 30) == RNC_OK);
  locals = 0;
  while (rnc_node_poll(n, &e) == RNC_OK)
    locals += e.type == RNC_NODE_LOCAL;
  CHECK(locals == 1);
  CHECK(rnc_node_set_accepts_links(n, unknown, 0) == RNC_STATE &&
        rnc_node_set_accepts_links(n, dest, 2) == RNC_INVALID);
  rnc_node_free(n);
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  if (!strcmp(argv[1], "paths"))
    paths();
  else if (!strcmp(argv[1], "ingress_state"))
    ingress_state();
  else if (!strcmp(argv[1], "input_class"))
    input_class();
  else if (!strcmp(argv[1], "routing"))
    routing();
  else if (!strcmp(argv[1], "guards"))
    guards();
  else if (!strcmp(argv[1], "destinations"))
    destinations();
  else if (!strcmp(argv[1], "local"))
    local_clients();
  else if (!strcmp(argv[1], "local_pr"))
    local_path_request();
  else if (!strcmp(argv[1], "state"))
    state_test();
  else if (!strcmp(argv[1], "mesh"))
    mesh();
  else if (!strcmp(argv[1], "discovery"))
    discovery();
  else if (!strcmp(argv[1], "request_path_options"))
    request_path_options();
  else if (!strcmp(argv[1], "hops_to"))
    hops_to();
  else if (!strcmp(argv[1], "announce_hop_limit"))
    announce_hop_limit();
  else if (!strcmp(argv[1], "drops"))
    drops();
  else if (!strcmp(argv[1], "gravity"))
    gravity();
  else if (!strcmp(argv[1], "accepts_links"))
    accepts_links();
  else if (!strcmp(argv[1], "destination_data"))
    destination_data();
  else
    CHECK(0);
  return 0;
}
