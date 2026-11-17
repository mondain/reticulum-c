#include <reticulum_c/rnc_buffer.h>
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
static size_t iface_mtu = 500, max_wire, wire_total;
static int listener_no_compress;
static const rnc_transfer_stream listener_stream_fns;
static int on_fetch_stream(void *ctx, const uint8_t *path, size_t path_size, const uint8_t *identity_hash,
                           rnc_transfer_source *src);
static int listener_streams; /* the next setup() makes a listener that streams files in and serves them from a source */
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
  wire_total += wire;
}
static void pump(net *n, unsigned steps) {
  unsigned i;
  for (i = 0; i < steps; i++) {
    rnc_node_event e;
    unsigned rounds, k;
    int moved;
    n->now += 10;
    CHECK(rnc_node_tick(n->client, UNIX, n->now) == RNC_OK);
    CHECK(rnc_node_tick(n->server, UNIX, n->now) == RNC_OK);
    CHECK(rnc_transfer_listener_tick(n->listener, UNIX, n->now) == RNC_OK);
    CHECK(rnc_transfer_client_tick(n->xfer, UNIX, n->now) == RNC_OK);
    /* a window of parts can be larger than a node's queue of undelivered events, so move a few packets each way at a
     * time and let each side take what it was handed before more arrives, as a host does */
    for (rounds = 0, moved = 1; moved && rounds < 100000; rounds++) {
      moved = 0;
      CHECK(rnc_transfer_listener_tick(n->listener, UNIX, n->now) == RNC_OK);
      CHECK(rnc_transfer_client_tick(n->xfer, UNIX, n->now) == RNC_OK);
      for (k = 0; k < 4 && rnc_node_poll(n->client, &e) == RNC_OK; k++) {
        moved = 1;
        if (e.type == RNC_NODE_SEND) {
          wire_note(&e.packet);
          CHECK(rnc_node_input(n->server, 1, &e.packet, UNIX, n->now) == RNC_OK);
        }
        else if (e.type == RNC_NODE_LOCAL)
          CHECK(rnc_transfer_client_input(n->xfer, &e, UNIX, n->now) == RNC_OK);
      }
      for (k = 0; k < 4 && rnc_node_poll(n->server, &e) == RNC_OK; k++) {
        moved = 1;
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
  cfg.no_compress = listener_no_compress;
  cfg.fetch = fetch ? on_fetch : NULL;
  cfg.context = n;
  if (listener_streams) {
    cfg.stream = listener_stream_fns;
    cfg.fetch_stream = on_fetch_stream;
  }
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
/* -C: a pushed file or a fetch answer is sent uncompressed. 100 kB of zeros is a few kB on the wire when
 * compressed and over 100 kB when not; builds without compression send it plain either way. */
static size_t push_zeros(int compress) {
  net n;
  uint8_t *data = calloc(100000, 1), out[16];
  rnc_transfer_result r;
  CHECK(data);
  wire_total = 0;
  setup(&n, 2, 0);
  rnc_transfer_client_set_compression(n.xfer, compress);
  CHECK(rnc_transfer_send(n.xfer, n.destination, &n.client_id, (const uint8_t *)"z.bin", 5, data, 100000, 1,
                          600000, UNIX, n.now) == RNC_OK);
  r = finish(&n, out, sizeof(out), 60000, NULL, 1);
  CHECK(r.status == RNC_TRANSFER_DONE && n.received_size == 100000 && !memcmp(n.received_data, data, 100000));
  free(data);
  teardown(&n);
  return wire_total;
}
static size_t fetch_zeros(int no_compress) {
  net n;
  uint8_t *out = malloc(200000);
  rnc_transfer_result r;
  CHECK(out);
  wire_total = 0;
  listener_no_compress = no_compress;
  setup(&n, 1, 1);
  n.fetch_size = 100000;
  memset(n.fetch_data, 0, n.fetch_size);
  CHECK(rnc_transfer_fetch(n.xfer, n.destination, &n.client_id, (const uint8_t *)"/z", 2, 8, 600000, UNIX,
                           n.now) == RNC_OK);
  r = finish(&n, out, 200000, 60000, NULL, 8);
  CHECK(r.status == RNC_TRANSFER_DONE && r.size == 100000);
  free(out);
  teardown(&n);
  listener_no_compress = 0;
  return wire_total;
}
static void no_compress(void) {
  size_t packed = push_zeros(1), plain = push_zeros(0);
  size_t fetched_packed = fetch_zeros(0), fetched_plain = fetch_zeros(1);
  if (rnc_stream_compression_available()) {
    CHECK(packed < 20000 && plain > 100000);
    CHECK(fetched_packed < 20000 && fetched_plain > 100000);
  } else
    CHECK(plain > 100000 && fetched_plain > 100000);
}
/* ---- streamed files ---- */
typedef struct stream_log {
  unsigned opens, closes, completes, abandoned, releases, serves;
  uint64_t size, next, wanted_size;
  uint8_t name[RNC_TRANSFER_NAME_MAX];
  size_t name_size;
  int anonymous, fail_at, pattern_mismatch, fetch_mode;
  uint8_t who[16];
  uint64_t source_size;
} stream_log;
static stream_log listener_log, client_log, source_log;
static uint8_t pat(uint64_t at) {
  uint64_t x = (at + 1) * 0x9e3779b97f4a7c15ull;
  x ^= x >> 31;
  return (uint8_t)(x * 0xd6e8feb86659fd93ull >> 56);
}
static rnc_result log_open(stream_log *l, const uint8_t *who, const uint8_t *name, size_t name_size, uint64_t size,
                           void **file) {
  l->opens++;
  l->size = size;
  l->anonymous = !who;
  if (who)
    memcpy(l->who, who, 16);
  memcpy(l->name, name, name_size);
  l->name_size = name_size;
  l->next = 0;
  *file = l;
  return RNC_OK;
}
static rnc_result log_write(stream_log *l, uint64_t offset, const void *data, size_t size) {
  size_t i;
  if (offset != l->next)
    l->pattern_mismatch = 1;
  if (l->fail_at && offset >= (uint64_t)l->fail_at)
    return RNC_NO_SPACE;
  for (i = 0; i < size; i++)
    if (((const uint8_t *)data)[i] != pat(offset + i))
      l->pattern_mismatch = 1;
  l->next = offset + size;
  return RNC_OK;
}
static void log_close(stream_log *l, int complete) {
  l->closes++;
  if (complete)
    l->completes++;
  else
    l->abandoned++;
}
static rnc_result listener_open(void *ctx, const uint8_t *who, const uint8_t *name, size_t name_size, uint64_t size,
                                void **file) {
  (void)ctx;
  return log_open(&listener_log, who, name, name_size, size, file);
}
static rnc_result listener_write(void *file, uint64_t offset, const void *data, size_t size) {
  return log_write(file, offset, data, size);
}
static void listener_close(void *file, int complete) { log_close(file, complete); }
static const rnc_transfer_stream listener_stream_fns = {listener_open, listener_write, listener_close};
static rnc_result client_open(void *ctx, const uint8_t *who, const uint8_t *name, size_t name_size, uint64_t size,
                              void **file) {
  (void)ctx;
  return log_open(&client_log, who, name, name_size, size, file);
}
static const rnc_transfer_stream client_stream_fns = {client_open, listener_write, listener_close};
static rnc_result source_read(void *ctx, uint64_t offset, void *out, size_t size) {
  size_t i;
  (void)ctx;
  for (i = 0; i < size; i++)
    ((uint8_t *)out)[i] = pat(offset + i);
  return RNC_OK;
}
static void source_release(void *ctx) {
  (void)ctx;
  source_log.releases++;
}
static int on_fetch_stream(void *ctx, const uint8_t *path, size_t path_size, const uint8_t *identity_hash,
                           rnc_transfer_source *src) {
  (void)ctx;
  (void)path;
  (void)path_size;
  (void)identity_hash;
  source_log.serves++;
  if (source_log.fetch_mode != RNC_FETCH_FOUND)
    return source_log.fetch_mode;
  src->size = source_log.source_size;
  src->read = source_read;
  src->release = source_release;
  memcpy(src->name, "streamed.bin", 12);
  src->name_size = 12;
  return RNC_FETCH_FOUND;
}
static void stream_reset(uint64_t size) {
  memset(&listener_log, 0, sizeof(listener_log));
  memset(&client_log, 0, sizeof(client_log));
  memset(&source_log, 0, sizeof(source_log));
  source_log.source_size = size;
  source_log.fetch_mode = RNC_FETCH_FOUND;
}
/* push a file through a source into the listener's stream */
static void stream_send_case(uint64_t size, unsigned steps) {
  net n;
  rnc_transfer_source src;
  rnc_transfer_result r;
  stream_reset(size);
  listener_streams = 1;
  setup(&n, 1, 0);
  listener_streams = 0;
  memset(&src, 0, sizeof(src));
  src.size = size;
  src.read = source_read;
  src.release = source_release;
  CHECK(rnc_transfer_send_stream(n.xfer, n.destination, &n.client_id, (const uint8_t *)"big.bin", 7, &src, 5, 6000000,
                                 UNIX, n.now) == RNC_OK);
  r = finish(&n, NULL, 0, steps, NULL, 5);
  CHECK(r.status == RNC_TRANSFER_DONE);
  CHECK(listener_log.opens == 1 && listener_log.completes == 1 && listener_log.abandoned == 0);
  CHECK(listener_log.size == size && listener_log.next == size && !listener_log.pattern_mismatch);
  CHECK(!listener_log.anonymous && !memcmp(listener_log.who, n.client_id.hash, 16));
  CHECK(listener_log.name_size == 7 && !memcmp(listener_log.name, "big.bin", 7));
  CHECK(source_log.releases == 1);
  CHECK(n.received == 0); /* it did not take the in-memory route */
  pump(&n, 300);
  CHECK(rnc_transfer_listener_link_count(n.listener) == 0);
  teardown(&n);
}
static void stream_send(void) { stream_send_case(2500000, 400000); }
static void stream_send_small(void) {
  stream_send_case(1000, 20000);
  stream_send_case(0, 20000);
}
static void stream_send_big(void) { stream_send_case((uint64_t)20 * 1024 * 1024 + 99, 3000000); }
/* the listener serves a file from a source and the client fetches it into a stream */
static void stream_fetch_case(uint64_t size, unsigned steps) {
  net n;
  rnc_transfer_result r;
  stream_reset(size);
  listener_streams = 1;
  setup(&n, 1, 0);
  listener_streams = 0;
  CHECK(rnc_transfer_fetch_stream(n.xfer, n.destination, &n.client_id, (const uint8_t *)"some/path", 9,
                                  &client_stream_fns, NULL, 8, 6000000, UNIX, n.now) == RNC_OK);
  r = finish(&n, NULL, 0, steps, NULL, 8);
  CHECK(r.status == RNC_TRANSFER_DONE && r.size == size);
  CHECK(r.name_size == 12 && !memcmp(r.name, "streamed.bin", 12));
  CHECK(client_log.opens == 1 && client_log.completes == 1 && client_log.abandoned == 0);
  CHECK(client_log.size == size && client_log.next == size && !client_log.pattern_mismatch && client_log.anonymous);
  CHECK(source_log.serves == 1);
  pump(&n, 400);
  CHECK(source_log.releases == 1);
  teardown(&n);
}
static void stream_fetch(void) { stream_fetch_case(2500000, 400000); }
static void stream_fetch_big(void) { stream_fetch_case((uint64_t)20 * 1024 * 1024 + 7, 3000000); }
/* a memory-bound client still reaches a streaming listener, and the listener's memory limit does not apply */
static void stream_memory_client(void) {
  net n;
  uint8_t data[40000], out[16];
  rnc_transfer_result r;
  size_t i;
  stream_reset(0);
  for (i = 0; i < sizeof(data); i++)
    data[i] = pat(i);
  listener_streams = 1;
  setup(&n, 1, 0);
  listener_streams = 0;
  CHECK(rnc_transfer_send(n.xfer, n.destination, &n.client_id, (const uint8_t *)"mem.bin", 7, data, sizeof(data), 2,
                          600000, UNIX, n.now) == RNC_OK);
  r = finish(&n, out, sizeof(out), 60000, NULL, 2);
  CHECK(r.status == RNC_TRANSFER_DONE);
  CHECK(listener_log.opens == 1 && listener_log.completes == 1 && listener_log.size == sizeof(data) &&
        !listener_log.pattern_mismatch);
  teardown(&n);
}
/* a sink that refuses fails the job; the file is abandoned (close with 0), the source is released once */
static void stream_failure(void) {
  net n;
  rnc_transfer_source src;
  rnc_transfer_result r;
  stream_reset(3000000);
  listener_log.fail_at = 1500000;
  listener_streams = 1;
  setup(&n, 1, 0);
  listener_streams = 0;
  memset(&src, 0, sizeof(src));
  src.size = 3000000;
  src.read = source_read;
  src.release = source_release;
  CHECK(rnc_transfer_send_stream(n.xfer, n.destination, &n.client_id, (const uint8_t *)"x.bin", 5, &src, 3, 400000,
                                 UNIX, n.now) == RNC_OK);
  r = finish(&n, NULL, 0, 500000, NULL, 3);
  CHECK(r.status == RNC_TRANSFER_FAILED);
  pump(&n, 500);
  CHECK(listener_log.opens == 1 && listener_log.closes == 1 && listener_log.abandoned == 1 && listener_log.completes == 0);
  CHECK(source_log.releases == 1);
  teardown(&n);
}
/* a fetch that finds nothing, or is refused, opens no stream */
static void stream_fetch_refused(void) {
  net n;
  rnc_transfer_result r;
  stream_reset(10);
  source_log.fetch_mode = RNC_FETCH_NOT_FOUND;
  listener_streams = 1;
  setup(&n, 1, 0);
  listener_streams = 0;
  CHECK(rnc_transfer_fetch_stream(n.xfer, n.destination, &n.client_id, (const uint8_t *)"nope", 4, &client_stream_fns,
                                  NULL, 1, 100000, UNIX, n.now) == RNC_OK);
  r = finish(&n, NULL, 0, 60000, NULL, 1);
  CHECK(r.status == RNC_TRANSFER_NOT_FOUND && client_log.opens == 0);
  source_log.fetch_mode = RNC_FETCH_NOT_ALLOWED;
  CHECK(rnc_transfer_fetch_stream(n.xfer, n.destination, &n.client_id, (const uint8_t *)"nope", 4, &client_stream_fns,
                                  NULL, 2, 100000, UNIX, n.now) == RNC_OK);
  r = finish(&n, NULL, 0, 60000, NULL, 2);
  CHECK(r.status == RNC_TRANSFER_NOT_ALLOWED && client_log.opens == 0 && source_log.releases == 0);
  teardown(&n);
}
static void stream_arguments(void) {
  net n;
  rnc_transfer_source src;
  rnc_transfer_stream broken = {NULL, listener_write, listener_close};
  rnc_transfer_config cfg;
  stream_reset(10);
  setup(&n, 1, 0);
  memset(&src, 0, sizeof(src));
  src.size = 10;
  src.release = source_release;
  /* no read function, or too big for the limit: refused, and the source is released */
  CHECK(rnc_transfer_send_stream(n.xfer, n.destination, &n.client_id, (const uint8_t *)"a", 1, &src, 1, 1000, UNIX,
                                 n.now) == RNC_INVALID && source_log.releases == 1);
  src.read = source_read;
  rnc_transfer_client_set_stream_limit(n.xfer, 5);
  CHECK(rnc_transfer_send_stream(n.xfer, n.destination, &n.client_id, (const uint8_t *)"a", 1, &src, 1, 1000, UNIX,
                                 n.now) == RNC_INVALID && source_log.releases == 2);
  rnc_transfer_client_set_stream_limit(n.xfer, 10);
  CHECK(rnc_transfer_send_stream(n.xfer, n.destination, &n.client_id, (const uint8_t *)"a", 1, NULL, 1, 1000, UNIX,
                                 n.now) == RNC_INVALID);
  CHECK(rnc_transfer_fetch_stream(n.xfer, n.destination, &n.client_id, (const uint8_t *)"p", 1, &broken, NULL, 1, 1000,
                                  UNIX, n.now) == RNC_INVALID);
  CHECK(rnc_transfer_fetch_stream(n.xfer, n.destination, &n.client_id, (const uint8_t *)"p", 1, NULL, NULL, 1, 1000,
                                  UNIX, n.now) == RNC_INVALID);
  /* an unknown destination: no route, and a source is released */
  {
    uint8_t unknown[16] = {7};
    CHECK(rnc_transfer_send_stream(n.xfer, unknown, &n.client_id, (const uint8_t *)"a", 1, &src, 1, 1000, UNIX, n.now) ==
              RNC_STATE && source_log.releases == 3);
  }
  /* a listener whose stream is half there is refused */
  memset(&cfg, 0, sizeof(cfg));
  cfg.allow_all = 1;
  cfg.stream = broken;
  CHECK(rnc_transfer_listener_new(n.server, &n.server_id, n.destination, &cfg, rng, NULL) == NULL);
  cfg.stream = listener_stream_fns;
  cfg.max_stream_size = RNC_TRANSFER_STREAM_MAX_SIZE + 1;
  CHECK(rnc_transfer_listener_new(n.server, &n.server_id, n.destination, &cfg, rng, NULL) == NULL);
  teardown(&n);
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
  else if (!strcmp(argv[1], "no_compress"))
    no_compress();
  else if (!strcmp(argv[1], "arguments"))
    arguments();
  else if (!strcmp(argv[1], "stream_send"))
    stream_send();
  else if (!strcmp(argv[1], "stream_send_small"))
    stream_send_small();
  else if (!strcmp(argv[1], "stream_send_big"))
    stream_send_big();
  else if (!strcmp(argv[1], "stream_fetch"))
    stream_fetch();
  else if (!strcmp(argv[1], "stream_fetch_big"))
    stream_fetch_big();
  else if (!strcmp(argv[1], "stream_memory_client"))
    stream_memory_client();
  else if (!strcmp(argv[1], "stream_failure"))
    stream_failure();
  else if (!strcmp(argv[1], "stream_fetch_refused"))
    stream_fetch_refused();
  else if (!strcmp(argv[1], "stream_arguments"))
    stream_arguments();
  else
    CHECK(0);
  puts("transfer test passed");
  return 0;
}
