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
      if (e.type == RNC_NODE_SEND)
        CHECK(rnc_node_input(n->server, 1, &e.packet, UNIX, n->now) == RNC_OK);
      else if (e.type == RNC_NODE_LOCAL) {
        rnc_result r = rnc_requester_input(n->requester, &e, UNIX, n->now);
        CHECK(r == RNC_OK);
      }
    }
    while (rnc_node_poll(n->server, &e) == RNC_OK) {
      if (e.type == RNC_NODE_SEND)
        CHECK(rnc_node_input(n->client, 1, &e.packet, UNIX, n->now) == RNC_OK);
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
int main(int argc, char **argv) {
  CHECK(argc == 2);
  if (!strcmp(argv[1], "echo"))
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
  else
    CHECK(0);
  puts("requester test passed");
  return 0;
}
