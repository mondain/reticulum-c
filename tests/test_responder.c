#include <reticulum_c/rnc_link.h>
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
static uint32_t seed = 5;
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
  rnc_link *link;
  rnc_service *service;
  uint8_t destination[16];
  uint64_t now;
  unsigned calls, with_identity, responses, timeouts, denied;
  uint8_t identity_seen[16], last[4200];
  size_t last_size;
} net;
/* Echoes the request; "/quiet" produces no response. */
static rnc_result handler(void *context, const char *path,
                          const uint8_t *request, size_t size,
                          const uint8_t *identity, uint8_t *response,
                          size_t capacity, size_t *written) {
  net *n = context;
  n->calls++;
  if (identity) {
    n->with_identity++;
    memcpy(n->identity_seen, identity, 16);
  }
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
    rnc_link_event le;
    rnc_node_event e;
    rnc_service_event se;
    uint8_t value[4200];
    size_t got;
    n->now += 10;
    CHECK(rnc_node_tick(n->client, UNIX, n->now) == RNC_OK);
    CHECK(rnc_node_tick(n->server, UNIX, n->now) == RNC_OK);
    CHECK(rnc_responder_tick(n->responder, UNIX, n->now) == RNC_OK);
    if (n->link) {
      CHECK(rnc_link_tick(n->link, n->now) == RNC_OK);
      while (rnc_link_poll(n->link, &le) == RNC_OK) {
        if (le.type == RNC_LINK_SEND)
          CHECK(rnc_node_send(n->client, &le.packet, UNIX, n->now) == RNC_OK);
        else if (le.type == RNC_LINK_PACKET ||
                 le.type == RNC_LINK_RESOURCE_PACKET ||
                 le.type == RNC_LINK_CLOSED) {
          rnc_result r = rnc_service_input(n->service, &le, n->now);
          CHECK(r == RNC_OK || r == RNC_AGAIN);
        }
      }
      CHECK(rnc_service_pump(n->service, n->now) == RNC_OK);
      CHECK(rnc_service_tick(n->service, n->now) == RNC_OK);
      while (rnc_service_poll(n->service, &se, value, sizeof(value), &got) ==
             RNC_OK) {
        if (se.type == RNC_SERVICE_RESPONSE) {
          n->responses++;
          n->last_size = got;
          memcpy(n->last, value, got);
        } else if (se.type == RNC_SERVICE_TIMEOUT)
          n->timeouts++;
        else if (se.type == RNC_SERVICE_DENIED)
          n->denied++;
      }
    }
    while (rnc_node_poll(n->client, &e) == RNC_OK) {
      if (e.type == RNC_NODE_SEND)
        CHECK(rnc_node_input(n->server, 1, &e.packet, UNIX, n->now) == RNC_OK);
      else if (e.type == RNC_NODE_LOCAL && n->link)
        CHECK(rnc_link_input(n->link, &e.packet, n->now) == RNC_OK);
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
static void setup(net *n) {
  rnc_packet announce;
  rnc_route route;
  rnc_node_event e;
  memset(n, 0, sizeof(*n));
  CHECK(rnc_identity_generate(&n->client_id, rng, NULL) == RNC_OK);
  CHECK(rnc_identity_generate(&n->server_id, rng, NULL) == RNC_OK);
  n->client = rnc_node_new(&n->client_id, 0, rng, NULL);
  n->server = rnc_node_new(&n->server_id, 0, rng, NULL);
  CHECK(n->client && n->server);
  CHECK(rnc_node_add_interface(n->client, 1, 1000000) == RNC_OK);
  CHECK(rnc_node_add_interface(n->server, 1, 1000000) == RNC_OK);
  CHECK(rnc_node_add_destination(n->server, &n->server_id, "test.responder",
                                 NULL, 0, n->destination) == RNC_OK);
  n->responder = rnc_responder_new(n->server, 4096, rng, NULL);
  CHECK(n->responder);
  CHECK(rnc_responder_add_destination(n->responder, &n->server_id,
                                      n->destination) == RNC_OK);
  CHECK(rnc_responder_register(n->responder, n->destination, "/echo",
                               RNC_SERVICE_ALLOW_ALL, NULL, 0, handler,
                               n) == RNC_OK);
  CHECK(rnc_responder_register(n->responder, n->destination, "/quiet",
                               RNC_SERVICE_ALLOW_ALL, NULL, 0, handler,
                               n) == RNC_OK);
  {
    uint8_t allowed[1][16];
    memcpy(allowed[0], n->client_id.hash, 16);
    CHECK(rnc_responder_register(n->responder, n->destination, "/secret",
                                 RNC_SERVICE_ALLOW_LIST, allowed, 1, handler,
                                 n) == RNC_OK);
  }
  n->now = 1000;
  CHECK(rnc_node_announce(n->server, n->destination, UNIX, n->now) == RNC_OK);
  CHECK(rnc_node_tick(n->server, UNIX, n->now) == RNC_OK);
  while (rnc_node_poll(n->server, &e) == RNC_OK)
    if (e.type == RNC_NODE_SEND) {
      announce = e.packet;
      CHECK(rnc_node_input(n->client, 1, &announce, UNIX, n->now) == RNC_OK);
    }
  CHECK(rnc_node_lookup(n->client, n->destination, n->now, &route) == RNC_OK);
  n->link = rnc_link_new(rng, NULL);
  CHECK(n->link);
  {
    uint8_t address[16];
    CHECK(rnc_link_open(n->link, &route.announce, n->now) == RNC_OK);
    CHECK(rnc_link_address(n->link, address) == RNC_OK);
    CHECK(rnc_node_bind_link_on(n->client, address, 1) == RNC_OK);
  }
  n->service = rnc_service_new(n->link, 4096, rng, NULL);
  CHECK(n->service);
  pump(n, 100);
  CHECK(rnc_link_is_active(n->link));
}
static void teardown(net *n) {
  rnc_service_free(n->service);
  rnc_link_free(n->link);
  rnc_responder_free(n->responder);
  rnc_node_free(n->client);
  rnc_node_free(n->server);
}
static void ask(net *n, const char *path, const uint8_t *value, size_t size,
                uint64_t timeout) {
  uint8_t id[16];
  CHECK(rnc_service_request(n->service, path, value, size, UNIX, n->now,
                            timeout, id) == RNC_OK);
}
static void echo(void) {
  net n;
  const uint8_t value[] = {0x92, 0x01, 0xa2, 'o', 'k'};
  setup(&n);
  CHECK(rnc_responder_link_count(n.responder) == 1);
  ask(&n, "/echo", value, sizeof(value), 5000);
  pump(&n, 100);
  CHECK(n.calls == 1 && n.responses == 1 && !n.with_identity);
  CHECK(n.last_size == sizeof(value) && !memcmp(n.last, value, sizeof(value)));
  teardown(&n);
}
/* A handler that declines to answer leaves the client to time out. */
static void quiet(void) {
  net n;
  const uint8_t value[] = {0xc0};
  setup(&n);
  ask(&n, "/quiet", value, sizeof(value), 500);
  pump(&n, 100);
  CHECK(n.calls == 1 && n.responses == 0 && n.timeouts == 1);
  teardown(&n);
}
/* ALLOW_LIST: nothing runs until the client identifies with a listed identity. */
static void allow_list(void) {
  net n;
  const uint8_t value[] = {0xc3};
  setup(&n);
  ask(&n, "/secret", value, sizeof(value), 500);
  pump(&n, 100);
  CHECK(n.calls == 0 && n.responses == 0 && n.timeouts == 1);
  CHECK(rnc_link_identify(n.link, &n.client_id, n.now) == RNC_OK);
  pump(&n, 50);
  ask(&n, "/secret", value, sizeof(value), 5000);
  pump(&n, 100);
  CHECK(n.calls == 1 && n.responses == 1 && n.with_identity == 1 &&
        !memcmp(n.identity_seen, n.client_id.hash, 16));
  teardown(&n);
}
/* A closed link frees its slot. */
static void close_frees_slot(void) {
  net n;
  setup(&n);
  CHECK(rnc_responder_link_count(n.responder) == 1);
  CHECK(rnc_link_close(n.link, n.now) == RNC_OK);
  pump(&n, 100);
  CHECK(rnc_responder_link_count(n.responder) == 0);
  teardown(&n);
}
/* Links that rode a lost interface are dropped at once instead of holding their slots until
 * they time out. */
static void drop_links_frees_slots(void) {
  net n;
  setup(&n);
  CHECK(rnc_responder_link_count(n.responder) == 1);
  CHECK(rnc_responder_drop_links(n.responder) == RNC_OK);
  CHECK(rnc_responder_link_count(n.responder) == 0);
  CHECK(rnc_responder_drop_links(NULL) == RNC_INVALID);
  teardown(&n);
}
/* A link request from a fresh client link, delivered to the server node and responder. */
static rnc_result extra_link(net *n) {
  rnc_route route;
  rnc_link *l = rnc_link_new(rng, NULL);
  rnc_link_event le;
  rnc_node_event e;
  rnc_result r = RNC_AGAIN;
  CHECK(l && rnc_node_lookup(n->client, n->destination, n->now, &route) == RNC_OK);
  CHECK(rnc_link_open(l, &route.announce, n->now) == RNC_OK);
  while (rnc_link_poll(l, &le) == RNC_OK)
    if (le.type == RNC_LINK_SEND)
      CHECK(rnc_node_input(n->server, 1, &le.packet, UNIX, n->now) == RNC_OK);
  rnc_link_free(l);
  while (rnc_node_poll(n->server, &e) == RNC_OK)
    if (e.type == RNC_NODE_LOCAL)
      r = rnc_responder_input(n->responder, &e, UNIX, n->now);
  n->now += 10;
  return r;
}
/* A full table refuses new links, unless it was told to reclaim the oldest one: a small board
 * whose peers vanish (a lost teardown over radio) would otherwise refuse everyone for good. */
static void full_table(void) {
  net n;
  size_t i;
  setup(&n);
  for (i = 1; i < RNC_RESPONDER_LINKS; i++)
    CHECK(extra_link(&n) == RNC_OK);
  CHECK(rnc_responder_link_count(n.responder) == RNC_RESPONDER_LINKS);
  CHECK(extra_link(&n) == RNC_NO_SPACE);
  CHECK(rnc_responder_set_evict_oldest(n.responder, 1) == RNC_OK);
  for (i = 0; i < 3; i++) {
    CHECK(extra_link(&n) == RNC_OK);
    CHECK(rnc_responder_link_count(n.responder) == RNC_RESPONDER_LINKS);
  }
  CHECK(rnc_responder_set_evict_oldest(NULL, 1) == RNC_INVALID);
  teardown(&n);
}
static void arguments(void) {
  net n;
  uint8_t other[16] = {9};
  setup(&n);
  CHECK(rnc_responder_register(n.responder, other, "/x", RNC_SERVICE_ALLOW_ALL,
                               NULL, 0, handler, &n) == RNC_STATE);
  CHECK(rnc_responder_register(n.responder, n.destination, "", RNC_SERVICE_ALLOW_ALL,
                               NULL, 0, handler, &n) == RNC_INVALID);
  CHECK(rnc_responder_register(n.responder, n.destination, "/x",
                               RNC_SERVICE_ALLOW_ALL, NULL, 0, NULL,
                               &n) == RNC_INVALID);
  CHECK(rnc_responder_new(NULL, 0, rng, NULL) == NULL);
  teardown(&n);
}
/* Destination.set_max_request_size: requests above it, inline or as a
 * Resource, are dropped before any handler runs. */
static void max_request_size(void) {
  net n;
  uint8_t small[20], medium[99], large[3003], unknown[16] = {9};
  size_t i;
  small[0] = 0xc4;
  small[1] = 18;
  medium[0] = 0xc4;
  medium[1] = 97;
  large[0] = 0xc5;
  large[1] = 0x0b;
  large[2] = 0xb8;
  for (i = 2; i < sizeof(small); i++)
    small[i] = (uint8_t)i;
  for (i = 2; i < sizeof(medium); i++)
    medium[i] = (uint8_t)i;
  for (i = 3; i < sizeof(large); i++)
    large[i] = (uint8_t)(i * 3u);
  setup(&n);
  CHECK(rnc_responder_set_max_request_size(n.responder, n.destination, 60) ==
        RNC_OK);
  ask(&n, "/echo", small, sizeof(small), 3000);
  pump(&n, 100);
  CHECK(n.calls == 1 && n.responses == 1);
  ask(&n, "/echo", medium, sizeof(medium), 500);
  pump(&n, 150);
  CHECK(n.calls == 1 && n.responses == 1 && n.timeouts == 1);
  ask(&n, "/echo", large, sizeof(large), 1500);
  pump(&n, 400);
  CHECK(n.calls == 1 && n.responses == 1 && n.timeouts == 2);
  CHECK(rnc_responder_set_max_request_size(n.responder, unknown, 10) == RNC_STATE);
  teardown(&n);
  /* the default and an explicit NO_LIMIT take any size */
  setup(&n);
  CHECK(rnc_responder_set_max_request_size(n.responder, n.destination,
                                           RNC_SERVICE_NO_LIMIT) == RNC_OK);
  ask(&n, "/echo", medium, sizeof(medium), 3000);
  pump(&n, 100);
  CHECK(n.calls == 1 && n.responses == 1);
  CHECK(rnc_responder_set_max_request_size(NULL, n.destination, 10) == RNC_INVALID);
  teardown(&n);
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  if (!strcmp(argv[1], "echo"))
    echo();
  else if (!strcmp(argv[1], "quiet"))
    quiet();
  else if (!strcmp(argv[1], "allow_list"))
    allow_list();
  else if (!strcmp(argv[1], "close"))
    close_frees_slot();
  else if (!strcmp(argv[1], "drop_links"))
    drop_links_frees_slots();
  else if (!strcmp(argv[1], "full_table"))
    full_table();
  else if (!strcmp(argv[1], "arguments"))
    arguments();
  else if (!strcmp(argv[1], "max_request"))
    max_request_size();
  else
    CHECK(0);
  puts("responder test passed");
  return 0;
}
