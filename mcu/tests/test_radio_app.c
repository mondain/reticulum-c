/* Two or more instances of the portable MCU application talk Reticulum over simulated
 * LoRa: announce, path request, link, /echo and /info requests, packets of 400 to 500
 * bytes that need the two-frame split, loss, and the gateway mode (serial side plus LoRa
 * side, transport on) against a leaf-only network. Built in the mcu profile with the
 * portable crypto backend.
 *
 * LIMIT: the radios are models written by the author of the drivers, on a simulated
 * channel; nothing here ran on air. */
#include "radio/sim_board.h"
#include "rnc_lora_cfg.h"
#include "rnc_mcu_app.h"
#include <reticulum_c/rnc.h>
#include <reticulum_c/rnc_node.h>
#include <reticulum_c/rnc_requester.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #x);    \
      failures++;                                                              \
    }                                                                          \
  } while (0)
#define CHECK_EQ(a, b)                                                         \
  do {                                                                         \
    long long va_ = (long long)(a), vb_ = (long long)(b);                      \
    if (va_ != vb_) {                                                          \
      fprintf(stderr, "%s:%d: %s = %lld, expected %lld\n", __FILE__, __LINE__, #a, va_, vb_); \
      failures++;                                                              \
    }                                                                          \
  } while (0)

#define APP_NAME "reticulum_c.mcu.example"
#define MAX_BOARDS 4

/* ---- a fake platform for the application ------------------------------------------------------- */
typedef struct plat {
  sim_medium *med;
  uint32_t seed;
  uint8_t identity[64];
  int has_identity;
  uint8_t in[16384], out[16384];
  size_t in_len, in_pos, out_len;
} plat;

static size_t p_write(void *c, const uint8_t *d, size_t n) {
  plat *p = c;
  if (p->out_len + n > sizeof(p->out))
    return 0;
  memcpy(p->out + p->out_len, d, n);
  p->out_len += n;
  return n;
}
static size_t p_read(void *c, uint8_t *b, size_t n) {
  plat *p = c;
  size_t k = p->in_len - p->in_pos;
  if (k > n)
    k = n;
  memcpy(b, p->in + p->in_pos, k);
  p->in_pos += k;
  if (p->in_pos == p->in_len)
    p->in_pos = p->in_len = 0;
  return k;
}
static int p_random(void *c, uint8_t *b, size_t n) {
  plat *p = c;
  size_t i;
  for (i = 0; i < n; i++) {
    p->seed = p->seed * 1664525u + 1013904223u;
    b[i] = (uint8_t)(p->seed >> 24);
  }
  return 0;
}
static uint64_t p_now(void *c) { return ((plat *)c)->med->now_us / 1000u; }
static int p_persist(void *c, const char *k, const void *d, size_t n) {
  plat *p = c;
  if (!strcmp(k, RNC_MCU_KEY_IDENTITY) && n == 64) {
    memcpy(p->identity, d, n);
    p->has_identity = 1;
  }
  return 0;
}
static int p_load(void *c, const char *k, void *b, size_t n) {
  plat *p = c;
  if (!strcmp(k, RNC_MCU_KEY_IDENTITY) && p->has_identity && n >= 64) {
    memcpy(b, p->identity, 64);
    return 64;
  }
  return -1;
}
static size_t p_heap(void *c) {
  (void)c;
  return 123456;
}

typedef struct board {
  sim_board sb;
  plat pl;
  rnc_mcu_app *app;
  uint8_t dest[16];
} board;

static rnc_lora_params prm(unsigned bw, unsigned sf, int txp) {
  rnc_lora_params p;
  memset(&p, 0, sizeof(p));
  p.freq_hz = 868100000u;
  p.bw_hz = bw;
  p.sf = (uint8_t)sf;
  p.cr = 5;
  p.txp_dbm = (int8_t)txp;
  return p;
}

static int board_make(board *b, sim_medium *med, int chip, uint32_t seed, unsigned mode,
                      const rnc_lora_params *params, const char *name) {
  rnc_mcu_platform plat_table;
  rnc_mcu_config cfg;
  memset(b, 0, sizeof(*b));
  b->pl.med = med;
  b->pl.seed = seed * 7919u + 13u;
  sim_board_init(&b->sb, med, chip, seed, 10000);
  if (sim_board_start(&b->sb, params) != 0)
    return -1;
  memset(&plat_table, 0, sizeof(plat_table));
  plat_table.context = &b->pl;
  plat_table.write = p_write;
  plat_table.read = p_read;
  plat_table.random = p_random;
  plat_table.now_ms = p_now;
  plat_table.persist = p_persist;
  plat_table.load = p_load;
  plat_table.free_heap = p_heap;
  plat_table.board = name;
  memset(&cfg, 0, sizeof(cfg));
  cfg.lora = &b->sb.li;
  cfg.lora_mode = mode;
  b->app = rnc_mcu_app_new(&plat_table, &cfg);
  if (!b->app)
    return -2;
  rnc_mcu_app_destination(b->app, b->dest);
  return 0;
}

/* ---- the client: a plain node with a requester on its own simulated radio ----------------------------- */
typedef struct client {
  sim_board sb;
  plat pl;
  rnc_identity id;
  rnc_node *node;
  rnc_requester *req;
  rnc_hdlc hdlc;
  uint8_t known[4][16];
  unsigned known_hops[4];
  unsigned nknown, announce_events;
  unsigned path_responses;
  uint8_t wire[RNC_MAX_FRAME + 8], pk[RNC_MAX_FRAME];
  int has_lora, serial_side;
  rnc_requester_result last;
  uint8_t response[1200];
  int have_result;
} client;

static rnc_result c_random(void *ctx, uint8_t *out, size_t n) {
  p_random(ctx, out, n);
  return RNC_OK;
}
static uint64_t unix_of(sim_medium *med) { return (uint64_t)RNC_MCU_BUILD_EPOCH + 2000u + med->now_us / 1000000u; }

static int client_make(client *c, sim_medium *med, int chip, uint32_t seed, const rnc_lora_params *params,
                       int serial_side) {
  memset(c, 0, sizeof(*c));
  c->pl.med = med;
  c->pl.seed = seed * 104729u + 7u;
  c->serial_side = serial_side;
  if (!serial_side) {
    sim_board_init(&c->sb, med, chip, seed, 10000);
    if (sim_board_start(&c->sb, params) != 0)
      return -1;
    c->has_lora = 1;
  }
  if (rnc_identity_generate(&c->id, c_random, &c->pl) != RNC_OK)
    return -2;
  c->node = rnc_node_new(&c->id, 0, c_random, &c->pl);
  if (!c->node || rnc_node_add_interface(c->node, 1, serial_side ? 115200u : rnc_lora_if_bitrate(&c->sb.li)) != RNC_OK)
    return -3;
  c->req = rnc_requester_new(c->node, 1200, c_random, &c->pl);
  return c->req ? 0 : -4;
}

static void client_note_announce(client *c, const rnc_node_event *e) {
  unsigned i;
  if (!rnc_announce_matches_aspect(&e->route.announce, APP_NAME))
    return;
  c->announce_events++;
  for (i = 0; i < c->nknown; i++)
    if (!memcmp(c->known[i], e->route.destination, 16)) {
      c->known_hops[i] = e->route.hops;
      return;
    }
  if (c->nknown < 4) {
    memcpy(c->known[c->nknown], e->route.destination, 16);
    c->known_hops[c->nknown++] = e->route.hops;
  }
}

static void client_input(client *c, const uint8_t *data, size_t n, uint64_t unix_now, uint64_t now_ms) {
  rnc_packet pkt;
  rnc_node_event ev;
  if (rnc_packet_decode(data, n, &pkt) != RNC_OK)
    return;
  (void)rnc_node_input(c->node, 1, &pkt, unix_now, now_ms);
  while (rnc_node_poll(c->node, &ev) == RNC_OK) {
    if (ev.type == RNC_NODE_ANNOUNCE)
      client_note_announce(c, &ev);
    else if (ev.type == RNC_NODE_LOCAL)
      (void)rnc_requester_input(c->req, &ev, unix_now, now_ms);
  }
}

static void client_drain(client *c, uint64_t unix_now, uint64_t now_ms) {
  rnc_node_event ev;
  while (rnc_node_poll(c->node, &ev) == RNC_OK) {
    size_t wn = 0, fn = 0;
    if (ev.type == RNC_NODE_ANNOUNCE) {
      client_note_announce(c, &ev);
    } else if (ev.type == RNC_NODE_LOCAL) {
      (void)rnc_requester_input(c->req, &ev, unix_now, now_ms);
    } else if (ev.type == RNC_NODE_SEND && rnc_packet_encode(&ev.packet, c->wire, sizeof(c->wire), &wn) == RNC_OK) {
      if (c->has_lora) {
        (void)rnc_lora_if_send(&c->sb.li, c->wire, wn, now_ms * 1000u);
      } else {
        uint8_t framed[RNC_HDLC_MAX];
        if (rnc_hdlc_encode(c->wire, wn, framed, sizeof(framed), &fn) == RNC_OK) {
          /* to the board's serial input */
          (void)framed;
        }
      }
    }
  }
}

static void client_step(client *c, uint64_t now_ms) {
  uint64_t unix_now = unix_of(c->pl.med);
  size_t n;
  if (c->has_lora) {
    rnc_lora_if_step(&c->sb.li, now_ms * 1000u);
    while ((n = rnc_lora_if_recv(&c->sb.li, c->pk, sizeof(c->pk))) > 0)
      client_input(c, c->pk, n, unix_now, now_ms);
  }
  (void)rnc_node_tick(c->node, unix_now, now_ms);
  (void)rnc_requester_tick(c->req, unix_now, now_ms);
  client_drain(c, unix_now, now_ms);
  while (rnc_requester_poll(c->req, &c->last, c->response, sizeof(c->response)) == RNC_OK)
    c->have_result = 1;
}

/* ---- the world ---------------------------------------------------------------------------------------------- */
typedef struct world {
  sim_medium *med;
  board *boards[MAX_BOARDS];
  unsigned nboards;
  client *clients[2];
  unsigned nclients;
} world;

static void world_run(world *w, unsigned ms) {
  unsigned t, i;
  for (t = 0; t < ms; t++) {
    w->med->now_us += 1000;
    sim_medium_advance(w->med);
    for (i = 0; i < w->nboards; i++)
      (void)rnc_mcu_app_step(w->boards[i]->app, w->med->now_us / 1000u);
    for (i = 0; i < w->nclients; i++)
      client_step(w->clients[i], w->med->now_us / 1000u);
  }
}

static int knows(const client *c, const uint8_t dest[16]) {
  unsigned i;
  for (i = 0; i < c->nknown; i++)
    if (!memcmp(c->known[i], dest, 16))
      return 1;
  return 0;
}

/* run one request to completion; returns the response size, or -1 */
static int request(world *w, client *c, const uint8_t dest[16], const char *path, const uint8_t *value,
                   size_t size, unsigned timeout_s, uint8_t *out, size_t out_cap, unsigned attempts) {
  unsigned a, t;
  for (a = 0; a < attempts; a++) {
    rnc_result r;
    c->have_result = 0;
    r = rnc_requester_start(c->req, dest, NULL, path, value, size, 7, (uint64_t)timeout_s * 1000u,
                            unix_of(w->med), w->med->now_us / 1000u);
    if (r != RNC_OK)
      return -1;
    for (t = 0; t < timeout_s * 1000u + 2000u && !c->have_result; t += 10)
      world_run(w, 10);
    if (c->have_result && c->last.status == RNC_REQUESTER_DONE) {
      size_t n = c->last.size < out_cap ? c->last.size : out_cap;
      memcpy(out, c->response, n);
      return (int)c->last.size;
    }
  }
  return -1;
}

static size_t make_echo_value(uint8_t *v, size_t payload) {
  /* a MessagePack bin16 of `payload` bytes */
  size_t i;
  v[0] = 0xc5;
  v[1] = (uint8_t)(payload >> 8);
  v[2] = (uint8_t)payload;
  for (i = 0; i < payload; i++)
    v[3 + i] = (uint8_t)(i * 13u + payload);
  return payload + 3u;
}

static int contains(const uint8_t *hay, size_t n, const char *needle) {
  size_t k = strlen(needle), i;
  for (i = 0; i + k <= n; ++i)
    if (!memcmp(hay + i, needle, k))
      return 1;
  return 0;
}

/* ---- tests ------------------------------------------------------------------------------------------------------ */
static void test_leaf_network(void) {
  sim_medium med;
  board a, b;
  client c;
  world w;
  rnc_lora_params p = prm(125000, 8, 14);
  uint8_t value[1100], got[1200];
  static const size_t payloads[] = {7, 120, 250, 340, 420};
  unsigned i;
  int n;
  sim_medium_init(&med, 5);
  CHECK_EQ(board_make(&a, &med, 1262, 1, RNC_LORA_MODE_LEAF, &p, "sim-a"), 0);
  CHECK_EQ(board_make(&b, &med, 1276, 2, RNC_LORA_MODE_LEAF, &p, "sim-b"), 0);
  CHECK_EQ(client_make(&c, &med, 1262, 3, &p, 0), 0);
  sim_link_all(&med, 100);
  memset(&w, 0, sizeof(w));
  w.med = &med;
  w.boards[0] = &a;
  w.boards[1] = &b;
  w.nboards = 2;
  w.clients[0] = &c;
  w.nclients = 1;

  /* announces: both boards announce on LoRa within a few seconds and the client learns both */
  world_run(&w, 30000);
  CHECK(knows(&c, a.dest));
  CHECK(knows(&c, b.dest));
  {
    rnc_mcu_stats sa;
    rnc_mcu_app_get_stats(a.app, &sa);
    CHECK(sa.announces >= 2);          /* at start and the early repeat */
    CHECK(sa.lora_tx_packets >= 2);
    CHECK_EQ(sa.tx_dropped, 0);
  }

  /* path request: the destination answers with a path response (an announce) */
  {
    unsigned before = c.announce_events;
    rnc_mcu_stats sa0, sa1;
    rnc_mcu_app_get_stats(a.app, &sa0);
    CHECK_EQ(rnc_node_request_path(c.node, a.dest, med.now_us / 1000u), RNC_OK);
    world_run(&w, 15000);
    rnc_mcu_app_get_stats(a.app, &sa1);
    CHECK(c.announce_events > before);
    CHECK(sa1.lora_rx_packets > sa0.lora_rx_packets);
    CHECK_EQ(sa1.announces, sa0.announces); /* the regular schedule is untouched */
  }

  /* /info over a link, then /echo with growing values; the larger ones are single packets of
   * 400 to 500 bytes that cross the air as two frames */
  {
    uint8_t none = 0xc0;
    n = request(&w, &c, a.dest, "/info", &none, 1, 40, got, sizeof(got), 3);
    CHECK(n > 8);
    CHECK((got[0] & 0xf0) == 0x80);
    CHECK(contains(got, (size_t)n, "reticulum-c-mcu"));
    CHECK(contains(got, (size_t)n, "sim-a"));
    CHECK(contains(got, (size_t)n, "lora"));
    CHECK(contains(got, (size_t)n, "leaf 868100000Hz bw125000 sf8 cr4/5"));
    n = request(&w, &c, b.dest, "/info", &none, 1, 40, got, sizeof(got), 3);
    CHECK(n > 8);
    CHECK(contains(got, (size_t)n, "sim-b"));
  }
  for (i = 0; i < sizeof(payloads) / sizeof(payloads[0]); i++) {
    size_t vn = make_echo_value(value, payloads[i]);
    n = request(&w, &c, i & 1 ? b.dest : a.dest, "/echo", value, vn, 90, got, sizeof(got), 3);
    CHECK_EQ(n, (int)vn);
    if (n == (int)vn)
      CHECK(!memcmp(got, value, vn));
  }
  /* the biggest single packets crossed the air in two frames each way */
  CHECK(c.sb.li.stats.tx_largest >= 400);
  CHECK(a.sb.li.stats.rx_largest >= 400 || b.sb.li.stats.rx_largest >= 400);
  CHECK(a.sb.li.stats.tx_largest >= 400 || b.sb.li.stats.tx_largest >= 400);
  CHECK(med.max_frame == 255);
  /* a value too large for one packet goes as a Resource (several packets) */
  {
    size_t vn = make_echo_value(value, 900);
    n = request(&w, &c, a.dest, "/echo", value, vn, 240, got, sizeof(got), 2);
    CHECK_EQ(n, (int)vn);
    if (n == (int)vn)
      CHECK(!memcmp(got, value, vn));
  }
  fprintf(stderr, "  leaf network: %.1f s simulated; frames on air %u (max %u bytes); largest packet tx by client %u, "
          "rx by A %u / B %u; A tx %u pkts, B tx %u pkts, client tx %u pkts\n",
          (double)med.now_us / 1e6, (unsigned)med.frames_sent, (unsigned)med.max_frame,
          (unsigned)c.sb.li.stats.tx_largest, (unsigned)a.sb.li.stats.rx_largest,
          (unsigned)b.sb.li.stats.rx_largest, (unsigned)a.sb.li.stats.tx_packets,
          (unsigned)b.sb.li.stats.tx_packets, (unsigned)c.sb.li.stats.tx_packets);
  CHECK_EQ(sim_board_violations(&a.sb) + sim_board_violations(&b.sb) + sim_board_violations(&c.sb), 0);
  CHECK_EQ(a.sb.li.stats.tx_failures + b.sb.li.stats.tx_failures + c.sb.li.stats.tx_failures, 0);
  {
    rnc_mcu_stats sa;
    rnc_mcu_app_get_stats(a.app, &sa);
    CHECK_EQ(sa.lora_rx_bad, 0);
    CHECK_EQ(sa.lora_tx_dropped, 0);
  }
  rnc_requester_free(c.req);
  rnc_node_free(c.node);
  rnc_mcu_app_free(a.app);
  rnc_mcu_app_free(b.app);
}

static void test_lossy_channel(void) {
  sim_medium med;
  board a;
  client c;
  world w;
  rnc_lora_params p = prm(250000, 7, 14);
  uint8_t value[600], got[1200];
  size_t vn;
  int n;
  sim_medium_init(&med, 9);
  CHECK_EQ(board_make(&a, &med, 1276, 1, RNC_LORA_MODE_LEAF, &p, "lossy"), 0);
  CHECK_EQ(client_make(&c, &med, 1262, 3, &p, 0), 0);
  sim_link_all(&med, 100);
  sim_link_drop(&med, a.sb.radio_id, c.sb.radio_id, 150); /* 15 % of the frames vanish */
  memset(&w, 0, sizeof(w));
  w.med = &med;
  w.boards[0] = &a;
  w.nboards = 1;
  w.clients[0] = &c;
  w.nclients = 1;
  world_run(&w, 40000);
  CHECK(knows(&c, a.dest));
  vn = make_echo_value(value, 380);
  /* link setup, request and response are each a few packets; requests are retried like any
   * Reticulum application would */
  n = request(&w, &c, a.dest, "/echo", value, vn, 60, got, sizeof(got), 12);
  CHECK_EQ(n, (int)vn);
  if (n == (int)vn)
    CHECK(!memcmp(got, value, vn));
  CHECK(med.lost_random > 0);
  CHECK_EQ(sim_board_violations(&a.sb) + sim_board_violations(&c.sb), 0);
  rnc_requester_free(c.req);
  rnc_node_free(c.node);
  rnc_mcu_app_free(a.app);
}

/* a leaf does not forward: the client hears A but not B; with A a leaf the client never learns
 * B. With A a gateway (transport on, plus an unused serial side) it does, and reaches B's /echo
 * through A. */
static void test_gateway_vs_leaf(void) {
  unsigned pass;
  for (pass = 0; pass < 2; pass++) {
    sim_medium med;
    board a, b;
    client c;
    world w;
    rnc_lora_params p = prm(250000, 7, 14);
    uint8_t value[400], got[1200];
    size_t vn;
    int n;
    sim_medium_init(&med, 15 + pass);
    CHECK_EQ(board_make(&a, &med, 1262, 1, pass ? RNC_LORA_MODE_GATEWAY : RNC_LORA_MODE_LEAF, &p, "relay"), 0);
    CHECK_EQ(board_make(&b, &med, 1276, 2, RNC_LORA_MODE_LEAF, &p, "far"), 0);
    CHECK_EQ(client_make(&c, &med, 1262, 3, &p, 0), 0);
    /* C - A - B in a line: C and B cannot hear each other */
    sim_link(&med, c.sb.radio_id, a.sb.radio_id, 100);
    sim_link(&med, a.sb.radio_id, b.sb.radio_id, 100);
    memset(&w, 0, sizeof(w));
    w.med = &med;
    w.boards[0] = &a;
    w.boards[1] = &b;
    w.nboards = 2;
    w.clients[0] = &c;
    w.nclients = 1;
    world_run(&w, 60000);
    CHECK(knows(&c, a.dest));
    if (!pass) {
      CHECK(!knows(&c, b.dest)); /* a leaf does not forward announces */
    } else {
      CHECK(knows(&c, b.dest));  /* the gateway repeated B's announce */
      {
        unsigned i;
        for (i = 0; i < c.nknown; i++)
          if (!memcmp(c.known[i], b.dest, 16))
            CHECK_EQ(c.known_hops[i], 2);
      }
      vn = make_echo_value(value, 300);
      n = request(&w, &c, b.dest, "/echo", value, vn, 90, got, sizeof(got), 4);
      CHECK_EQ(n, (int)vn);
      if (n == (int)vn)
        CHECK(!memcmp(got, value, vn));
      {
        uint8_t none = 0xc0;
        n = request(&w, &c, b.dest, "/info", &none, 1, 60, got, sizeof(got), 3);
        CHECK(n > 8);
        CHECK(contains(got, (size_t)n, "far"));
      }
    }
    CHECK_EQ(sim_board_violations(&a.sb) + sim_board_violations(&b.sb) + sim_board_violations(&c.sb), 0);
    rnc_requester_free(c.req);
    rnc_node_free(c.node);
    rnc_mcu_app_free(a.app);
    rnc_mcu_app_free(b.app);
  }
}

/* the LoRa interface being down must not stop the application from starting, and a radio that
 * comes up later announces */
static void test_radio_comes_up_later(void) {
  sim_medium med;
  board a;
  client c;
  world w;
  rnc_lora_params p = prm(250000, 7, 14);
  rnc_mcu_platform plat_table;
  rnc_mcu_config cfg;
  sim_medium_init(&med, 25);
  memset(&a, 0, sizeof(a));
  a.pl.med = &med;
  a.pl.seed = 99;
  sim_board_init(&a.sb, &med, 1262, 1, 10000);
  a.sb.m126.absent = 1;
  CHECK(sim_board_start(&a.sb, &p) < 0);
  memset(&plat_table, 0, sizeof(plat_table));
  plat_table.context = &a.pl;
  plat_table.write = p_write;
  plat_table.read = p_read;
  plat_table.random = p_random;
  plat_table.now_ms = p_now;
  plat_table.persist = p_persist;
  plat_table.load = p_load;
  plat_table.board = "late";
  memset(&cfg, 0, sizeof(cfg));
  cfg.lora = &a.sb.li;
  cfg.lora_mode = RNC_LORA_MODE_LEAF;
  a.app = rnc_mcu_app_new(&plat_table, &cfg);
  CHECK(a.app != NULL);
  rnc_mcu_app_destination(a.app, a.dest);
  CHECK_EQ(client_make(&c, &med, 1262, 3, &p, 0), 0);
  sim_link_all(&med, 100);
  memset(&w, 0, sizeof(w));
  w.med = &med;
  w.boards[0] = &a;
  w.nboards = 1;
  w.clients[0] = &c;
  w.nclients = 1;
  world_run(&w, 15000);
  {
    rnc_mcu_stats s;
    rnc_mcu_app_get_stats(a.app, &s);
    CHECK_EQ(s.announces, 0); /* nothing is announced into a dead radio */
  }
  CHECK(!knows(&c, a.dest));
  a.sb.m126.absent = 0;
  world_run(&w, 40000);
  CHECK(knows(&c, a.dest));
  rnc_requester_free(c.req);
  rnc_node_free(c.node);
  rnc_mcu_app_free(a.app);
}

int main(void) {
  test_leaf_network();
  test_lossy_channel();
  test_gateway_vs_leaf();
  test_radio_comes_up_later();
  if (failures) {
    fprintf(stderr, "test_radio_app: %d failure(s)\n", failures);
    return 1;
  }
  puts("test_radio_app: all checks passed");
  return 0;
}
