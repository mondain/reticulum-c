#include <reticulum_c/rnc_requester.h>
#include <reticulum_c/rnc_responder.h>
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
#define UNIX 1700000000u
static uint32_t seed = 11;
static rnc_result rng(void *ctx, uint8_t *p, size_t n) {
  size_t i;
  (void)ctx;
  for (i = 0; i < n; i++) {
    seed = seed * 1664525u + 1013904223u;
    p[i] = (uint8_t)(seed >> 24);
  }
  return RNC_OK;
}
/* Interface MTUs and the discovery switch for the next setup(), and the largest
 * packet seen on the wire. */
static size_t client_mtu = 500, server_mtu = 500, max_wire;
static int discovery = 1;
typedef struct net {
  rnc_identity client_id, server_id;
  rnc_node *client, *server;
  rnc_responder *responder;
  rnc_requester *requester;
  uint8_t destination[16];
  uint64_t now;
  unsigned calls, identified_calls;
  rnc_packet announce;
} net;
static rnc_result handler(void *context, const char *path,
                          const uint8_t *request, size_t size,
                          const uint8_t *identity, uint8_t *response,
                          size_t capacity, size_t *written) {
  net *n = context;
  n->calls++;
  if (identity)
    n->identified_calls++;
  if (!strcmp(path, "/quiet"))
    return RNC_AGAIN;
  CHECK(size <= capacity);
  memcpy(response, request, size);
  *written = size;
  return RNC_OK;
}
static void pump(net *n, unsigned steps) {
  unsigned i;
  for (i = 0; i < steps; i++) {
    rnc_node_event e;
    n->now += 10;
    CHECK(rnc_node_tick(n->client, UNIX, n->now) == RNC_OK);
    CHECK(rnc_node_tick(n->server, UNIX, n->now) == RNC_OK);
    CHECK(rnc_responder_tick(n->responder, UNIX, n->now) == RNC_OK);
    CHECK(rnc_requester_tick(n->requester, UNIX, n->now) == RNC_OK);
    while (rnc_node_poll(n->client, &e) == RNC_OK) {
      if (e.type == RNC_NODE_SEND) {
        uint8_t raw[RNC_MAX_MTU];
        size_t wire = 0;
        if (rnc_packet_encode(&e.packet, raw, sizeof(raw), &wire) == RNC_OK &&
            wire > max_wire)
          max_wire = wire;
        CHECK(rnc_node_input(n->server, 1, &e.packet, UNIX, n->now) == RNC_OK);
      }
      else if (e.type == RNC_NODE_LOCAL) {
        rnc_result r = rnc_requester_input(n->requester, &e, UNIX, n->now);
        CHECK(r == RNC_OK);
      }
    }
    while (rnc_node_poll(n->server, &e) == RNC_OK) {
      if (e.type == RNC_NODE_SEND) {
        uint8_t raw[RNC_MAX_MTU];
        size_t wire = 0;
        if (rnc_packet_encode(&e.packet, raw, sizeof(raw), &wire) == RNC_OK &&
            wire > max_wire)
          max_wire = wire;
        CHECK(rnc_node_input(n->client, 1, &e.packet, UNIX, n->now) == RNC_OK);
      }
      else if (e.type == RNC_NODE_LOCAL) {
        rnc_result r = rnc_responder_input(n->responder, &e, UNIX, n->now);
        CHECK(r == RNC_OK || r == RNC_AGAIN);
      }
    }
  }
}
/* with_route: deliver the server's announce so the client has a route. */
static void setup(net *n, int with_route) {
  rnc_node_event e;
  uint8_t allowed[1][16];
  memset(n, 0, sizeof(*n));
  CHECK(rnc_identity_generate(&n->client_id, rng, NULL) == RNC_OK);
  CHECK(rnc_identity_generate(&n->server_id, rng, NULL) == RNC_OK);
  n->client = rnc_node_new(&n->client_id, 0, rng, NULL);
  n->server = rnc_node_new(&n->server_id, 0, rng, NULL);
  CHECK(n->client && n->server);
  CHECK(rnc_node_add_interface(n->client, 1, 1000000) == RNC_OK);
  CHECK(rnc_node_add_interface(n->server, 1, 1000000) == RNC_OK);
  CHECK(rnc_node_interface_mtu(n->client, 1, client_mtu) == RNC_OK);
  CHECK(rnc_node_interface_mtu(n->server, 1, server_mtu) == RNC_OK);
  CHECK(rnc_node_set_link_mtu_discovery(n->client, discovery) == RNC_OK);
  CHECK(rnc_node_set_link_mtu_discovery(n->server, discovery) == RNC_OK);
  CHECK(rnc_node_add_destination(n->server, &n->server_id, "test.requester",
                                 NULL, 0, n->destination) == RNC_OK);
  n->responder = rnc_responder_new(n->server, 4096, rng, NULL);
  n->requester = rnc_requester_new(n->client, 4096, rng, NULL);
  CHECK(n->responder && n->requester);
  CHECK(rnc_responder_add_destination(n->responder, &n->server_id,
                                      n->destination) == RNC_OK);
  CHECK(rnc_responder_register(n->responder, n->destination, "/echo",
                               RNC_SERVICE_ALLOW_ALL, NULL, 0, handler,
                               n) == RNC_OK);
  CHECK(rnc_responder_register(n->responder, n->destination, "/quiet",
                               RNC_SERVICE_ALLOW_ALL, NULL, 0, handler,
                               n) == RNC_OK);
  memcpy(allowed[0], n->client_id.hash, 16);
  CHECK(rnc_responder_register(n->responder, n->destination, "/secret",
                               RNC_SERVICE_ALLOW_LIST,
                               (const uint8_t(*)[16])allowed, 1, handler,
                               n) == RNC_OK);
  n->now = 1000;
  if (!with_route)
    return;
  CHECK(rnc_node_announce(n->server, n->destination, UNIX, n->now) == RNC_OK);
  CHECK(rnc_node_tick(n->server, UNIX, n->now) == RNC_OK);
  while (rnc_node_poll(n->server, &e) == RNC_OK)
    if (e.type == RNC_NODE_SEND)
      CHECK(rnc_node_input(n->client, 1, &e.packet, UNIX, n->now) == RNC_OK);
}
static void teardown(net *n) {
  rnc_requester_free(n->requester);
  rnc_responder_free(n->responder);
  rnc_node_free(n->client);
  rnc_node_free(n->server);
}
static rnc_requester_result finish(net *n, uint8_t *buf, size_t capacity,
                                   unsigned steps) {
  rnc_requester_result r;
  unsigned i;
  for (i = 0; i < steps; i++) {
    pump(n, 1);
    if (rnc_requester_poll(n->requester, &r, buf, capacity) == RNC_OK)
      return r;
  }
  CHECK(0);
  return r;
}
static void echo(void) {
  net n;
  const uint8_t value[] = {0x92, 0x01, 0xa2, 'o', 'k'};
  uint8_t out[64];
  rnc_requester_result r;
  setup(&n, 1);
  CHECK(rnc_requester_start(n.requester, n.destination, NULL, "/echo", value,
                            sizeof(value), 77, 5000, UNIX, n.now) == RNC_OK);
  r = finish(&n, out, sizeof(out), 300);
  CHECK(r.status == RNC_REQUESTER_DONE && r.tag == 77 &&
        !memcmp(r.destination, n.destination, 16) && r.size == sizeof(value) &&
        !memcmp(out, value, sizeof(value)));
  CHECK(n.calls == 1 && !n.identified_calls);
  /* the link is closed once the result is delivered */
  pump(&n, 100);
  CHECK(rnc_responder_link_count(n.responder) == 0);
  teardown(&n);
}
static void no_route(void) {
  net n;
  const uint8_t nil = 0xc0;
  setup(&n, 0);
  CHECK(rnc_requester_start(n.requester, n.destination, NULL, "/echo", &nil, 1,
                            1, 1000, UNIX, n.now) == RNC_STATE);
  teardown(&n);
}
static void silent_handler_times_out(void) {
  net n;
  const uint8_t nil = 0xc0;
  uint8_t out[8];
  rnc_requester_result r;
  setup(&n, 1);
  CHECK(rnc_requester_start(n.requester, n.destination, NULL, "/quiet", &nil, 1,
                            5, 800, UNIX, n.now) == RNC_OK);
  r = finish(&n, out, sizeof(out), 400);
  CHECK(r.status == RNC_REQUESTER_FAILED && r.tag == 5 && n.calls == 1);
  teardown(&n);
}
static void identify(void) {
  net n;
  const uint8_t nil = 0xc0;
  uint8_t out[8];
  rnc_requester_result r;
  setup(&n, 1);
  CHECK(rnc_requester_start(n.requester, n.destination, NULL, "/secret", &nil,
                            1, 1, 800, UNIX, n.now) == RNC_OK);
  r = finish(&n, out, sizeof(out), 400);
  CHECK(r.status == RNC_REQUESTER_FAILED && n.calls == 0);
  CHECK(rnc_requester_start(n.requester, n.destination, &n.client_id,
                            "/secret", &nil, 1, 2, 5000, UNIX,
                            n.now) == RNC_OK);
  r = finish(&n, out, sizeof(out), 400);
  CHECK(r.status == RNC_REQUESTER_DONE && r.tag == 2 && n.calls == 1 &&
        n.identified_calls == 1);
  teardown(&n);
}
static void busy(void) {
  net n;
  const uint8_t nil = 0xc0;
  unsigned i;
  uint8_t out[8];
  rnc_requester_result r;
  setup(&n, 1);
  for (i = 0; i < RNC_REQUESTER_JOBS; i++)
    CHECK(rnc_requester_start(n.requester, n.destination, NULL, "/echo", &nil,
                              1, i, 5000, UNIX, n.now) == RNC_OK);
  CHECK(rnc_requester_start(n.requester, n.destination, NULL, "/echo", &nil, 1,
                            9, 5000, UNIX, n.now) == RNC_AGAIN);
  for (i = 0; i < RNC_REQUESTER_JOBS; i++) {
    r = finish(&n, out, sizeof(out), 500);
    CHECK(r.status == RNC_REQUESTER_DONE);
  }
  /* slots free up once their results are collected */
  CHECK(rnc_requester_start(n.requester, n.destination, NULL, "/echo", &nil, 1,
                            9, 5000, UNIX, n.now) == RNC_OK);
  teardown(&n);
}
static void arguments(void) {
  net n;
  const uint8_t nil = 0xc0, two[2] = {0xc0, 0xc0};
  setup(&n, 1);
  CHECK(rnc_requester_start(NULL, n.destination, NULL, "/echo", &nil, 1, 1,
                            1000, UNIX, n.now) == RNC_INVALID);
  CHECK(rnc_requester_start(n.requester, n.destination, NULL, "", &nil, 1, 1,
                            1000, UNIX, n.now) == RNC_INVALID);
  CHECK(rnc_requester_start(n.requester, n.destination, NULL, "/echo", two, 2,
                            1, 1000, UNIX, n.now) == RNC_INVALID);
  CHECK(rnc_requester_start(n.requester, n.destination, NULL, "/echo", &nil, 1,
                            1, 0, UNIX, n.now) == RNC_INVALID);
  CHECK(rnc_requester_new(NULL, 0, rng, NULL) == NULL);
  teardown(&n);
}
/* Drives the job to completion, recording the request state each step. */
typedef struct trace {
  unsigned seen[5];
  double last, max_receiving;
  int monotonic, partial;
} trace;
static rnc_requester_result run_traced(net *n, uint32_t tag, trace *t,
                                       uint8_t *buf, size_t capacity,
                                       unsigned steps) {
  rnc_requester_result r;
  unsigned i;
  memset(t, 0, sizeof(*t));
  t->monotonic = 1;
  for (i = 0; i < steps; i++) {
    rnc_request_state state;
    double progress;
    pump(n, 1);
    if (rnc_requester_progress(n->requester, tag, &state, &progress) ==
        RNC_OK) {
      t->seen[state]++;
      if (progress < t->last)
        t->monotonic = 0;
      t->last = progress;
      if (state == RNC_REQUEST_RECEIVING && progress > 0 && progress < 1)
        t->partial = 1;
    }
    if (rnc_requester_poll(n->requester, &r, buf, capacity) == RNC_OK)
      return r;
  }
  CHECK(0);
  return r;
}
/* An inline request goes SENT then READY, never through the resource states. */
static void progress_inline(void) {
  net n;
  const uint8_t value[] = {0x92, 0x01, 0xa2, 'o', 'k'};
  uint8_t out[64];
  rnc_request_state state = RNC_REQUEST_READY;
  double progress = 1;
  trace t;
  setup(&n, 1);
  CHECK(rnc_requester_progress(n.requester, 77, &state, &progress) ==
        RNC_STATE);
  CHECK(rnc_requester_start(n.requester, n.destination, NULL, "/echo", value,
                            sizeof(value), 77, 5000, UNIX, n.now) == RNC_OK);
  CHECK(rnc_requester_progress(n.requester, 77, &state, &progress) == RNC_OK &&
        state == RNC_REQUEST_SENT && progress == 0);
  CHECK(run_traced(&n, 77, &t, out, sizeof(out), 300).status ==
        RNC_REQUESTER_DONE);
  CHECK(t.seen[RNC_REQUEST_SENT] && t.seen[RNC_REQUEST_READY] &&
        !t.seen[RNC_REQUEST_DELIVERED] && !t.seen[RNC_REQUEST_RECEIVING] &&
        !t.seen[RNC_REQUEST_FAILED] && t.last == 1.0 && t.monotonic);
  teardown(&n);
}
/* A request and response too large for one packet travel as Resources: the
 * request resource completing is DELIVERED, then the response arrives in
 * parts (RECEIVING with a fractional progress) before READY. */
static void progress_resource(void) {
  net n;
  uint8_t value[3008], out[4096];
  rnc_requester_result r;
  trace t;
  size_t i;
  value[0] = 0xc5; /* bin 16: 3000 bytes */
  value[1] = 0x0b;
  value[2] = 0xb8;
  for (i = 0; i < 3000; i++)
    value[3 + i] = (uint8_t)(i * 7u + 1u);
  setup(&n, 1);
  CHECK(rnc_requester_start(n.requester, n.destination, NULL, "/echo", value,
                            3003, 5, 60000, UNIX, n.now) == RNC_OK);
  r = run_traced(&n, 5, &t, out, sizeof(out), 6000);
  CHECK(r.status == RNC_REQUESTER_DONE && r.size == 3003);
  CHECK(t.seen[RNC_REQUEST_SENT] && t.seen[RNC_REQUEST_DELIVERED] &&
        t.seen[RNC_REQUEST_RECEIVING] && t.seen[RNC_REQUEST_READY]);
  CHECK(t.partial && t.monotonic && t.last == 1.0);
  teardown(&n);
}
/* A request that never gets an answer ends FAILED. */
static void progress_failed(void) {
  net n;
  const uint8_t value[] = {0xc0};
  uint8_t out[16];
  rnc_request_state state;
  double progress;
  rnc_requester_result r;
  unsigned i;
  int failed = 0;
  setup(&n, 1);
  CHECK(rnc_requester_start(n.requester, n.destination, NULL, "/quiet", value,
                            1, 9, 1500, UNIX, n.now) == RNC_OK);
  for (i = 0; i < 600; i++) {
    pump(&n, 1);
    if (rnc_requester_progress(n.requester, 9, &state, &progress) == RNC_OK &&
        state == RNC_REQUEST_FAILED)
      failed = 1;
    if (rnc_requester_poll(n.requester, &r, out, sizeof(out)) == RNC_OK) {
      CHECK(r.status == RNC_REQUESTER_FAILED);
      break;
    }
  }
  CHECK(failed && i < 600);
  teardown(&n);
}
/* A request and response too big for 500 byte packets: run an echo and return
 * the largest packet that crossed the wire. */
static size_t big_echo_wire(void) {
  net n;
  uint8_t value[3008], out[4096];
  rnc_requester_result r;
  size_t i;
  value[0] = 0xc5;
  value[1] = 0x0b;
  value[2] = 0xb8;
  for (i = 0; i < 3000; i++)
    value[3 + i] = (uint8_t)(i * 5u + 2u);
  max_wire = 0;
  setup(&n, 1);
  CHECK(rnc_requester_start(n.requester, n.destination, NULL, "/echo", value,
                            3003, 3, 60000, UNIX, n.now) == RNC_OK);
  r = finish(&n, out, sizeof(out), 6000);
  CHECK(r.status == RNC_REQUESTER_DONE && r.size == 3003 &&
        !memcmp(out, value, 3003));
  teardown(&n);
  return max_wire;
}
/* Both interfaces take 4096 byte packets: the link negotiates that, and the
 * Resource carrying the echo uses large packets. */
static void mtu_discovery(void) {
  client_mtu = server_mtu = RNC_MAX_MTU;
  discovery = 1;
  CHECK(big_echo_wire() > 2000);
}
/* Switched off, links stay at 500 bytes whatever the interfaces allow. */
static void mtu_discovery_off(void) {
  client_mtu = server_mtu = RNC_MAX_MTU;
  discovery = 0;
  CHECK(big_echo_wire() <= 500);
}
/* A path whose far side only takes 500 byte packets: the link is clamped to
 * what both ends accept (a larger one would be dropped by the server). */
static void mtu_mixed(void) {
  client_mtu = RNC_MAX_MTU;
  server_mtu = 500;
  discovery = 1;
  CHECK(big_echo_wire() <= 500);
  /* and between two intermediate sizes */
  client_mtu = 2048;
  server_mtu = 1196;
  CHECK(big_echo_wire() > 500 && max_wire <= 1196);
}
/* The default is on, with the reference's 500 byte interfaces: no change. */
static void mtu_default(void) {
  rnc_identity id;
  rnc_node *node;
  uint8_t dest[16] = {1};
  CHECK(rnc_identity_generate(&id, rng, NULL) == RNC_OK);
  node = rnc_node_new(&id, 0, rng, NULL);
  CHECK(node && rnc_node_link_mtu_discovery(node) == 1);
  CHECK(rnc_node_add_interface(node, 1, 1000000) == RNC_OK);
  CHECK(rnc_node_link_mtu_on(node, 1) == 500);
  CHECK(rnc_node_link_mtu_on(node, 9) == 500); /* unknown interface */
  CHECK(rnc_node_link_mtu_to(node, dest, 100) == 500); /* no route */
  CHECK(rnc_node_interface_mtu(node, 1, 1196) == RNC_OK &&
        rnc_node_link_mtu_on(node, 1) == 1196);
  CHECK(rnc_node_set_link_mtu_discovery(node, 0) == RNC_OK &&
        rnc_node_link_mtu_on(node, 1) == 500);
  CHECK(rnc_node_set_link_mtu_discovery(node, 2) == RNC_INVALID);
  rnc_node_free(node);
}
/* A file handler answers with raw data and metadata; the requester hands both
 * back through poll_file. */
static rnc_result file_handler(void *context, const char *path,
                               const uint8_t *request, size_t size,
                               const uint8_t *identity, uint8_t *response,
                               size_t capacity, size_t *written,
                               rnc_responder_file *file) {
  static const uint8_t meta[] = {0x81, 0x01, 0x00};
  size_t i;
  (void)context; (void)path; (void)request; (void)size; (void)identity;
  (void)response; (void)capacity; (void)written;
  CHECK(file->data_capacity >= 3000 && file->metadata_capacity >= sizeof(meta));
  for (i = 0; i < 3000; i++)
    file->data[i] = (uint8_t)(i * 13u + 1u);
  file->data_size = 3000;
  memcpy(file->metadata, meta, sizeof(meta));
  file->metadata_size = sizeof(meta);
  return RNC_OK;
}
static void file(void) {
  net n;
  const uint8_t value[] = {0xc0};
  uint8_t out[4096], meta[16];
  rnc_requester_result r;
  unsigned i;
  size_t k;
  setup(&n, 1);
  CHECK(rnc_responder_register_file(n.responder, n.destination, "/bundle",
                                    RNC_SERVICE_ALLOW_ALL, NULL, 0,
                                    file_handler, &n) == RNC_OK);
  CHECK(rnc_requester_start(n.requester, n.destination, NULL, "/bundle", value,
                            sizeof(value), 5, 20000, UNIX, n.now) == RNC_OK);
  for (i = 0;; i++) {
    CHECK(i < 3000);
    pump(&n, 1);
    if (rnc_requester_poll_file(n.requester, &r, out, sizeof(out), meta,
                                sizeof(meta)) == RNC_OK)
      break;
  }
  CHECK(r.status == RNC_REQUESTER_DONE && r.size == 3000 && r.tag == 5);
  CHECK(r.metadata_size == 3 && !memcmp(meta, "\x81\x01\x00", 3));
  for (k = 0; k < 3000; k++)
    CHECK(out[k] == (uint8_t)(k * 13u + 1u));
  teardown(&n);
}
/* A handler may keep the node serviced while it works (rngit runs git for
 * minutes): the responder is ticked from inside it, which must not start a
 * second handler, and the handler can read the caller's public key. */
static int nest_depth, nest_max, nest_calls;
static uint8_t seen_key[64];
static rnc_responder *nest_responder;
static net *nest_net;
static rnc_result nest_handler(void *context, const char *path,
                               const uint8_t *request, size_t size,
                               const uint8_t *identity, uint8_t *response,
                               size_t capacity, size_t *written) {
  rnc_identity who;
  (void)context; (void)path; (void)identity;
  nest_calls++;
  nest_depth++;
  if (nest_depth > nest_max)
    nest_max = nest_depth;
  CHECK(rnc_responder_request_identity(nest_responder, &who) == RNC_OK);
  memcpy(seen_key, who.public_key, 64);
  pump(nest_net, 60);
  nest_depth--;
  CHECK(size <= capacity);
  memcpy(response, request, size);
  *written = size;
  return RNC_OK;
}
static void nested(void) {
  net n;
  const uint8_t value[] = {0x92, 0x01, 0x02};
  uint8_t out[64];
  rnc_requester_result r;
  unsigned i, done = 0;
  rnc_identity probe;
  setup(&n, 1);
  nest_responder = n.responder;
  nest_net = &n;
  CHECK(rnc_responder_register(n.responder, n.destination, "/nest",
                               RNC_SERVICE_ALLOW_ALL, NULL, 0, nest_handler,
                               &n) == RNC_OK);
  CHECK(rnc_responder_request_identity(n.responder, &probe) == RNC_STATE);
  CHECK(rnc_requester_start(n.requester, n.destination, &n.client_id, "/nest",
                            value, sizeof(value), 1, 20000, UNIX, n.now) == RNC_OK);
  CHECK(rnc_requester_start(n.requester, n.destination, &n.client_id, "/nest",
                            value, sizeof(value), 2, 20000, UNIX, n.now) == RNC_OK);
  for (i = 0; i < 3000 && done < 2; i++) {
    pump(&n, 1);
    while (rnc_requester_poll(n.requester, &r, out, sizeof(out)) == RNC_OK) {
      CHECK(r.status == RNC_REQUESTER_DONE && r.size == sizeof(value));
      done++;
    }
  }
  CHECK(done == 2 && nest_calls == 2 && nest_max == 1);
  CHECK(!memcmp(seen_key, n.client_id.public_key, 64));
  teardown(&n);
}
/* A handler may defer its answer: it takes a ticket, returns without a
 * response and the answer goes out later, long after the 30 s window the
 * service keeps for a request. */
static rnc_responder_ticket deferred_ticket;
static int deferred_calls;
static rnc_result defer_handler(void *context, const char *path,
                                const uint8_t *request, size_t size,
                                const uint8_t *identity, uint8_t *response,
                                size_t capacity, size_t *written) {
  net *n = context;
  (void)path; (void)request; (void)size; (void)identity; (void)response;
  (void)capacity; (void)written;
  deferred_calls++;
  CHECK(rnc_responder_defer(n->responder, &deferred_ticket, 3600000u) == RNC_OK);
  return RNC_AGAIN;
}
static void deferred(void) {
  net n;
  const uint8_t value[] = {0x92, 0x05, 0x06}, answer[] = {0xa3, 'l', 'a', 't'};
  uint8_t out[64];
  rnc_requester_result r;
  unsigned i;
  setup(&n, 1);
  CHECK(rnc_responder_register(n.responder, n.destination, "/later",
                               RNC_SERVICE_ALLOW_ALL, NULL, 0, defer_handler,
                               &n) == RNC_OK);
  CHECK(rnc_responder_defer(n.responder, &deferred_ticket, 1000) == RNC_STATE);
  CHECK(rnc_requester_start(n.requester, n.destination, NULL, "/later", value,
                            sizeof(value), 3, 7200000, UNIX, n.now) == RNC_OK);
  for (i = 0; i < 300 && !deferred_calls; i++)
    pump(&n, 1);
  CHECK(deferred_calls == 1);
  /* nothing arrives while the handler's work goes on, for over a minute */
  for (i = 0; i < 7000; i++) {
    pump(&n, 1);
    CHECK(rnc_requester_poll(n.requester, &r, out, sizeof(out)) == RNC_AGAIN);
  }
  CHECK(rnc_responder_reply(n.responder, &deferred_ticket, answer,
                            sizeof(answer), n.now) == RNC_OK);
  for (i = 0; i < 500; i++) {
    pump(&n, 1);
    if (rnc_requester_poll(n.requester, &r, out, sizeof(out)) == RNC_OK)
      break;
  }
  CHECK(i < 500 && r.status == RNC_REQUESTER_DONE && r.size == sizeof(answer) &&
        !memcmp(out, answer, sizeof(answer)));
  /* a ticket answers once */
  CHECK(rnc_responder_reply(n.responder, &deferred_ticket, answer,
                            sizeof(answer), n.now) == RNC_STATE);
  teardown(&n);
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  if (!strcmp(argv[1], "deferred"))
    deferred();
  else if (!strcmp(argv[1], "nested"))
    nested();
  else if (!strcmp(argv[1], "file"))
    file();
  else if (!strcmp(argv[1], "echo"))
    echo();
  else if (!strcmp(argv[1], "no_route"))
    no_route();
  else if (!strcmp(argv[1], "silent"))
    silent_handler_times_out();
  else if (!strcmp(argv[1], "identify"))
    identify();
  else if (!strcmp(argv[1], "busy"))
    busy();
  else if (!strcmp(argv[1], "arguments"))
    arguments();
  else if (!strcmp(argv[1], "mtu_discovery"))
    mtu_discovery();
  else if (!strcmp(argv[1], "mtu_discovery_off"))
    mtu_discovery_off();
  else if (!strcmp(argv[1], "mtu_mixed"))
    mtu_mixed();
  else if (!strcmp(argv[1], "mtu_default"))
    mtu_default();
  else if (!strcmp(argv[1], "progress_inline"))
    progress_inline();
  else if (!strcmp(argv[1], "progress_resource"))
    progress_resource();
  else if (!strcmp(argv[1], "progress_failed"))
    progress_failed();
  else
    CHECK(0);
  puts("requester test passed");
  return 0;
}
