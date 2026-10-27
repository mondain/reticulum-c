#include <reticulum_c/rnc_transfer.h>
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
static uint32_t seed = 21;
static rnc_result rng(void *ctx, uint8_t *p, size_t n) {
  size_t i;
  (void)ctx;
  for (i = 0; i < n; i++) {
    seed = seed * 1664525u + 1013904223u;
    p[i] = (uint8_t)(seed >> 24);
  }
  return RNC_OK;
}
/* Interface MTU for the next setup() and the largest packet on the wire. */
static size_t iface_mtu = 500, max_wire;
typedef struct net {
  rnc_identity client_id, server_id;
  rnc_node *client, *server;
  rnc_transfer_listener *listener;
  rnc_transfer_client *xfer;
  uint8_t destination[16];
  uint64_t now;
  /* what the listener's callbacks saw */
  unsigned received;
  uint8_t received_from[16];
  int received_anonymous;
  uint8_t received_name[RNC_TRANSFER_NAME_MAX];
  size_t received_name_size;
  uint8_t *received_data;
  size_t received_size;
  /* fetch behaviour */
  int fetch_mode; /* RNC_FETCH_* */
  uint8_t fetch_data[200000];
  size_t fetch_size;
  uint8_t fetched_path[64];
  size_t fetched_path_size;
  unsigned fetch_calls;
} net;
static rnc_result on_received(void *ctx, const uint8_t *identity_hash,
                              const uint8_t *name, size_t name_size,
                              const uint8_t *data, size_t size) {
  net *n = ctx;
  n->received++;
  n->received_anonymous = !identity_hash;
  if (identity_hash)
    memcpy(n->received_from, identity_hash, 16);
  memcpy(n->received_name, name, name_size);
  n->received_name_size = name_size;
  free(n->received_data);
  n->received_data = malloc(size ? size : 1);
  CHECK(n->received_data);
  memcpy(n->received_data, data, size);
  n->received_size = size;
  return RNC_OK;
}
static int on_fetch(void *ctx, const uint8_t *path, size_t path_size,
                    const uint8_t *identity_hash, uint8_t **data, size_t *size,
                    uint8_t name[RNC_TRANSFER_NAME_MAX], size_t *name_size) {
  net *n = ctx;
  (void)identity_hash;
  n->fetch_calls++;
  CHECK(path_size < sizeof(n->fetched_path));
  memcpy(n->fetched_path, path, path_size);
  n->fetched_path_size = path_size;
  if (n->fetch_mode != RNC_FETCH_FOUND)
    return n->fetch_mode;
  *data = malloc(n->fetch_size);
  CHECK(*data);
  memcpy(*data, n->fetch_data, n->fetch_size);
  *size = n->fetch_size;
  memcpy(name, "fetched.bin", 11);
  *name_size = 11;
  return RNC_FETCH_FOUND;
}
static void wire_note(const rnc_packet *packet) {
  uint8_t raw[RNC_MAX_MTU];
  size_t wire = 0;
  if (rnc_packet_encode(packet, raw, sizeof(raw), &wire) == RNC_OK &&
      wire > max_wire)
    max_wire = wire;
}
static void pump(net *n, unsigned steps) {
  unsigned i;
  for (i = 0; i < steps; i++) {
    rnc_node_event e;
    n->now += 10;
    CHECK(rnc_node_tick(n->client, UNIX, n->now) == RNC_OK);
    CHECK(rnc_node_tick(n->server, UNIX, n->now) == RNC_OK);
    CHECK(rnc_transfer_listener_tick(n->listener, UNIX, n->now) == RNC_OK);
    CHECK(rnc_transfer_client_tick(n->xfer, UNIX, n->now) == RNC_OK);
    while (rnc_node_poll(n->client, &e) == RNC_OK) {
      if (e.type == RNC_NODE_SEND) {
        wire_note(&e.packet);
        CHECK(rnc_node_input(n->server, 1, &e.packet, UNIX, n->now) == RNC_OK);
      }
      else if (e.type == RNC_NODE_LOCAL)
        CHECK(rnc_transfer_client_input(n->xfer, &e, UNIX, n->now) == RNC_OK);
    }
    while (rnc_node_poll(n->server, &e) == RNC_OK) {
      if (e.type == RNC_NODE_SEND) {
        wire_note(&e.packet);
        CHECK(rnc_node_input(n->client, 1, &e.packet, UNIX, n->now) == RNC_OK);
      }
      else if (e.type == RNC_NODE_LOCAL) {
        rnc_result r = rnc_transfer_listener_input(n->listener, &e, UNIX, n->now);
        CHECK(r == RNC_OK || r == RNC_AGAIN);
      }
    }
  }
}
/* allow: 0 = nobody listed, 1 = the client listed, 2 = allow_all */
static void setup(net *n, int allow, int fetch) {
  rnc_node_event e;
  rnc_transfer_config cfg;
  memset(n, 0, sizeof(*n));
  CHECK(rnc_identity_generate(&n->client_id, rng, NULL) == RNC_OK);
  CHECK(rnc_identity_generate(&n->server_id, rng, NULL) == RNC_OK);
  n->client = rnc_node_new(&n->client_id, 0, rng, NULL);
  n->server = rnc_node_new(&n->server_id, 0, rng, NULL);
  CHECK(n->client && n->server);
  CHECK(rnc_node_add_interface(n->client, 1, 1000000) == RNC_OK);
  CHECK(rnc_node_add_interface(n->server, 1, 1000000) == RNC_OK);
  CHECK(rnc_node_interface_mtu(n->client, 1, iface_mtu) == RNC_OK);
  CHECK(rnc_node_interface_mtu(n->server, 1, iface_mtu) == RNC_OK);
  CHECK(rnc_node_add_destination(n->server, &n->server_id, "rncp.receive",
                                 NULL, 0, n->destination) == RNC_OK);
  memset(&cfg, 0, sizeof(cfg));
  cfg.allow_all = allow == 2;
  if (allow == 1) {
    memcpy(cfg.allowed[0], n->client_id.hash, 16);
    cfg.allowed_count = 1;
  } else if (allow == 0) {
    memset(cfg.allowed[0], 0x55, 16);
    cfg.allowed_count = 1;
  }
  cfg.received = on_received;
  cfg.fetch = fetch ? on_fetch : NULL;
  cfg.context = n;
  n->listener = rnc_transfer_listener_new(n->server, &n->server_id,
                                          n->destination, &cfg, rng, NULL);
  n->xfer = rnc_transfer_client_new(n->client, 0, rng, NULL);
  CHECK(n->listener && n->xfer);
  n->now = 1000;
  CHECK(rnc_node_announce(n->server, n->destination, UNIX, n->now) == RNC_OK);
  CHECK(rnc_node_tick(n->server, UNIX, n->now) == RNC_OK);
  while (rnc_node_poll(n->server, &e) == RNC_OK)
    if (e.type == RNC_NODE_SEND)
      CHECK(rnc_node_input(n->client, 1, &e.packet, UNIX, n->now) == RNC_OK);
}
static void teardown(net *n) {
  free(n->received_data);
  rnc_transfer_client_free(n->xfer);
  rnc_transfer_listener_free(n->listener);
  rnc_node_free(n->client);
  rnc_node_free(n->server);
}
static rnc_transfer_result finish(net *n, uint8_t *buf, size_t capacity,
                                  unsigned steps, double *last_progress,
                                  uint32_t tag) {
  rnc_transfer_result r;
  unsigned i;
  int monotonic = 1;
  double last = 0;
  for (i = 0; i < steps; i++) {
    double p;
    pump(n, 1);
    if (rnc_transfer_client_progress(n->xfer, tag, &p) == RNC_OK) {
      if (p < last)
        monotonic = 0;
      last = p;
    }
    if (rnc_transfer_client_poll(n->xfer, &r, buf, capacity) == RNC_OK) {
      CHECK(monotonic);
      if (last_progress)
        *last_progress = last;
      return r;
    }
  }
  CHECK(0);
  return r;
}
static void fill(uint8_t *p, size_t n) {
  size_t i;
  for (i = 0; i < n; i++)
    p[i] = (uint8_t)(i * 31u + (i >> 8));
}
/* A pushed file arrives complete, with its name and the sender's identity. */
static void send_file(void) {
  net n;
  uint8_t data[3000], out[16];
  rnc_transfer_result r;
  setup(&n, 1, 0);
  fill(data, sizeof(data));
  CHECK(rnc_transfer_send(n.xfer, n.destination, &n.client_id,
                          (const uint8_t *)"notes.txt", 9, data, sizeof(data),
                          4, 60000, UNIX, n.now) == RNC_OK);
  r = finish(&n, out, sizeof(out), 6000, NULL, 4);
  CHECK(r.status == RNC_TRANSFER_DONE && r.tag == 4 && r.size == 0);
  CHECK(n.received == 1 && !n.received_anonymous &&
        !memcmp(n.received_from, n.client_id.hash, 16));
  CHECK(n.received_name_size == 9 && !memcmp(n.received_name, "notes.txt", 9));
  CHECK(n.received_size == sizeof(data) &&
        !memcmp(n.received_data, data, sizeof(data)));
  pump(&n, 300);
  CHECK(rnc_transfer_listener_link_count(n.listener) == 0);
  teardown(&n);
}
/* A file larger than a few windows, progress never going backwards. */
static void send_large(void) {
  net n;
  uint8_t *data = malloc(150000), out[16];
  rnc_transfer_result r;
  double progress = 0;
  CHECK(data);
  setup(&n, 2, 0);
  fill(data, 150000);
  CHECK(rnc_transfer_send(n.xfer, n.destination, &n.client_id,
                          (const uint8_t *)"big.bin", 7, data, 150000, 1,
                          600000, UNIX, n.now) == RNC_OK);
  r = finish(&n, out, sizeof(out), 60000, &progress, 1);
  CHECK(r.status == RNC_TRANSFER_DONE && progress == 1.0);
  CHECK(n.received == 1 && n.received_size == 150000 &&
        !memcmp(n.received_data, data, 150000));
  free(data);
  teardown(&n);
}
/* Not on the allow list: nothing is delivered and the sender fails. */
static void send_denied(void) {
  net n;
  uint8_t data[100], out[16];
  rnc_transfer_result r;
  setup(&n, 0, 0);
  fill(data, sizeof(data));
  CHECK(rnc_transfer_send(n.xfer, n.destination, &n.client_id,
                          (const uint8_t *)"x", 1, data, sizeof(data), 2, 20000,
                          UNIX, n.now) == RNC_OK);
  r = finish(&n, out, sizeof(out), 6000, NULL, 2);
  CHECK(r.status == RNC_TRANSFER_FAILED && n.received == 0);
  teardown(&n);
}
static void fetch_found(void) {
  net n;
  uint8_t *out = malloc(200000);
  rnc_transfer_result r;
  CHECK(out);
  setup(&n, 1, 1);
  n.fetch_size = 5000;
  fill(n.fetch_data, n.fetch_size);
  CHECK(rnc_transfer_fetch(n.xfer, n.destination, &n.client_id,
                           (const uint8_t *)"/tmp/some file", 14, 8, 60000,
                           UNIX, n.now) == RNC_OK);
  r = finish(&n, out, 200000, 8000, NULL, 8);
  CHECK(r.status == RNC_TRANSFER_DONE && r.size == 5000 && r.name_size == 11 &&
        !memcmp(r.name, "fetched.bin", 11) &&
        !memcmp(out, n.fetch_data, 5000));
  CHECK(n.fetch_calls == 1 && n.fetched_path_size == 14 &&
        !memcmp(n.fetched_path, "/tmp/some file", 14));
  free(out);
  teardown(&n);
}
static void fetch_refused(void) {
  net n;
  uint8_t out[16];
  rnc_transfer_result r;
  setup(&n, 1, 1);
  n.fetch_mode = RNC_FETCH_NOT_FOUND;
  CHECK(rnc_transfer_fetch(n.xfer, n.destination, &n.client_id,
                           (const uint8_t *)"missing", 7, 1, 30000, UNIX,
                           n.now) == RNC_OK);
  r = finish(&n, out, sizeof(out), 6000, NULL, 1);
  CHECK(r.status == RNC_TRANSFER_NOT_FOUND);
  n.fetch_mode = RNC_FETCH_NOT_ALLOWED;
  CHECK(rnc_transfer_fetch(n.xfer, n.destination, &n.client_id,
                           (const uint8_t *)"secret", 6, 2, 30000, UNIX,
                           n.now) == RNC_OK);
  r = finish(&n, out, sizeof(out), 6000, NULL, 2);
  CHECK(r.status == RNC_TRANSFER_NOT_ALLOWED && n.fetch_calls == 2);
  teardown(&n);
}
/* Fetch off, or an identity that is not allowed: no file, the client fails. */
static void fetch_unavailable(void) {
  net n;
  uint8_t out[16];
  rnc_transfer_result r;
  setup(&n, 1, 0);
  CHECK(rnc_transfer_fetch(n.xfer, n.destination, &n.client_id,
                           (const uint8_t *)"a", 1, 1, 8000, UNIX,
                           n.now) == RNC_OK);
  r = finish(&n, out, sizeof(out), 6000, NULL, 1);
  CHECK(r.status == RNC_TRANSFER_FAILED);
  teardown(&n);
  setup(&n, 0, 1);
  n.fetch_size = 10;
  CHECK(rnc_transfer_fetch(n.xfer, n.destination, &n.client_id,
                           (const uint8_t *)"a", 1, 2, 8000, UNIX,
                           n.now) == RNC_OK);
  r = finish(&n, out, sizeof(out), 6000, NULL, 2);
  CHECK(r.status == RNC_TRANSFER_FAILED && n.fetch_calls == 0);
  teardown(&n);
}
static void arguments(void) {
  net n;
  uint8_t unknown[16] = {7}, data[4] = {1, 2, 3, 4};
  rnc_identity anon;
  double p;
  setup(&n, 2, 0);
  CHECK(rnc_transfer_send(n.xfer, unknown, &n.client_id,
                          (const uint8_t *)"n", 1, data, 4, 1, 1000, UNIX,
                          n.now) == RNC_STATE);
  CHECK(rnc_transfer_send(n.xfer, n.destination, &n.client_id, NULL, 0, data,
                          4, 1, 1000, UNIX, n.now) == RNC_INVALID);
  CHECK(rnc_identity_from_public(&anon, n.client_id.public_key) == RNC_OK);
  CHECK(rnc_transfer_send(n.xfer, n.destination, &anon,
                          (const uint8_t *)"n", 1, data, 4, 1, 1000, UNIX,
                          n.now) == RNC_INVALID);
  CHECK(rnc_transfer_client_progress(n.xfer, 99, &p) == RNC_STATE);
  CHECK(!rnc_transfer_listener_new(n.server, &anon, n.destination,
                                   &(rnc_transfer_config){0}, rng, NULL));
  teardown(&n);
}
/* With 4096 byte interfaces a pushed file travels in large packets and arrives
 * intact; with 500 byte ones nothing larger than that is ever sent. */
static void large_mtu(void) {
  size_t mtus[2] = {RNC_MAX_MTU, 500}, k;
  for (k = 0; k < 2; ++k) {
    net n;
    uint8_t *data = malloc(60000), out[16];
    rnc_transfer_result r;
    CHECK(data);
    iface_mtu = mtus[k];
    max_wire = 0;
    setup(&n, 2, 0);
    CHECK(rng(NULL, data, 60000) == RNC_OK); /* incompressible */
    CHECK(rnc_transfer_send(n.xfer, n.destination, &n.client_id,
                            (const uint8_t *)"mtu.bin", 7, data, 60000, 1,
                            600000, UNIX, n.now) == RNC_OK);
    r = finish(&n, out, sizeof(out), 60000, NULL, 1);
    CHECK(r.status == RNC_TRANSFER_DONE && n.received == 1 &&
          n.received_size == 60000 && !memcmp(n.received_data, data, 60000));
    CHECK(k == 0 ? max_wire > 2000 : max_wire <= 500);
    free(data);
    teardown(&n);
  }
  iface_mtu = 500;
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  if (!strcmp(argv[1], "send"))
    send_file();
  else if (!strcmp(argv[1], "large"))
    send_large();
  else if (!strcmp(argv[1], "denied"))
    send_denied();
  else if (!strcmp(argv[1], "fetch"))
    fetch_found();
  else if (!strcmp(argv[1], "refused"))
    fetch_refused();
  else if (!strcmp(argv[1], "unavailable"))
    fetch_unavailable();
  else if (!strcmp(argv[1], "large_mtu"))
    large_mtu();
  else if (!strcmp(argv[1], "arguments"))
    arguments();
  else
    CHECK(0);
  puts("transfer test passed");
  return 0;
}
