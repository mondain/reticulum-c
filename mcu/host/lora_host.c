/* Simulated LoRa segment for the host harness; see lora_host.h. */
#include "lora_host.h"
#include "../radio/rnc_radio.h"
#include "../tests/radio/sim_board.h"
#include "rnc_mcu_app.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_PEERS 4

typedef struct peer {
  sim_board sb;
  rnc_mcu_app *app;
  uint8_t identity[64];
  int has_identity;
  struct lora_host *host;
  char name[24];
} peer;

struct lora_host {
  sim_medium med;
  sx126x_model chip126;
  sx127x_model chip127;
  rnc_radio radio;
  int chip;
  int rng_fd;
  uint32_t seed;
  unsigned npeers;
  peer peers[MAX_PEERS];
};

static uint32_t host_random32(void *context) {
  lora_host *h = context;
  h->seed = h->seed * 1664525u + 1013904223u;
  return h->seed ^ (h->seed >> 13);
}

static int peer_random(void *c, uint8_t *b, size_t n) {
  peer *p = c;
  while (n) {
    ssize_t r = read(p->host->rng_fd, b, n);
    if (r <= 0)
      return -1;
    b += r;
    n -= (size_t)r;
  }
  return 0;
}
static size_t peer_write(void *c, const uint8_t *d, size_t n) {
  (void)c;
  (void)d;
  return n;
}
static size_t peer_read(void *c, uint8_t *b, size_t n) {
  (void)c;
  (void)b;
  (void)n;
  return 0;
}
static uint64_t peer_now(void *c) { return ((peer *)c)->host->med.now_us / 1000u; }
static int peer_persist(void *c, const char *k, const void *d, size_t n) {
  peer *p = c;
  if (!strcmp(k, RNC_MCU_KEY_IDENTITY) && n == 64) {
    memcpy(p->identity, d, n);
    p->has_identity = 1;
  }
  return 0;
}
static int peer_load(void *c, const char *k, void *b, size_t n) {
  peer *p = c;
  if (!strcmp(k, RNC_MCU_KEY_IDENTITY) && p->has_identity && n >= 64) {
    memcpy(b, p->identity, 64);
    return 64;
  }
  return -1;
}
static void peer_log(void *c, const char *line) {
  peer *p = c;
  fprintf(stderr, "mcu: %s: %s\n", p->name, line);
}

lora_host *lora_host_new(const lora_host_options *o, int *status) {
  lora_host *h = calloc(1, sizeof(*h));
  rnc_board board;
  rnc_lora_cfg cfg = o->cfg;
  unsigned i;
  int rc;
  rnc_lora_params params;
  if (!h)
    return NULL;
  h->rng_fd = open("/dev/urandom", O_RDONLY);
  h->chip = o->chip == 1276 ? 1276 : 1262;
  h->seed = 0x1234567u;
  sim_medium_init(&h->med, 77);
  {
    /* the channel's clock is the wall clock from the start, so that the peers' application
     * clocks (uptime based) agree with the harness board's */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    h->med.now_us = (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
  }
  /* the harness board: a modelled chip behind the same gate as the firmware's */
  memset(&board, 0, sizeof(board));
  board.id = "host-sim";
  board.name = "host harness (simulated radio)";
  board.supported = 1;
  board.max_txp_dbm = 20;
  if (h->chip == 1276) {
    board.chip = RNC_BOARD_SX1276;
    board.pa_boost = 1;
    sx127x_model_init(&h->chip127, &h->med, 1);
  } else {
    board.chip = RNC_BOARD_SX1262;
    board.sx126x.chip = 1262;
    board.sx126x.tcxo_code = RNC_SX126X_TCXO_1V8;
    board.sx126x.dio2_rf_switch = 1;
    board.sx126x.ocp = 0x28;
    sx126x_model_init(&h->chip126, &h->med, 1262, 1, 1);
  }
  rc = rnc_radio_setup(&h->radio, &board, h->chip == 1276 ? &h->chip127.hal : &h->chip126.hal, &cfg,
                       host_random32, h);
  if (status)
    *status = rc;
  fprintf(stderr, "mcu: lora: %s\n", rnc_radio_status_text(rc));
  if (rc != RNC_RADIO_OK) {
    free(h);
    return NULL;
  }
  rnc_lora_cfg_params(&cfg, &params);
  params.preamble_symbols = 0;
  /* peers: simulated boards of the other chip family, each a leaf node on the same channel */
  h->npeers = o->peers > MAX_PEERS ? MAX_PEERS : o->peers;
  for (i = 0; i < h->npeers; i++) {
    peer *p = &h->peers[i];
    rnc_mcu_platform plat;
    rnc_mcu_config mc;
    rnc_lora_params pp = params;
    p->host = h;
    snprintf(p->name, sizeof(p->name), "peer%u", i + 1);
    sim_board_init(&p->sb, &h->med, h->chip == 1276 ? 1262 : 1276, 100u + i, cfg.airtime);
    pp.txp_dbm = (int8_t)(pp.txp_dbm > 17 ? 17 : pp.txp_dbm); /* inside both chips' range */
    if (sim_board_start(&p->sb, &pp) != 0) {
      fprintf(stderr, "mcu: lora: peer radio did not start\n");
      continue;
    }
    memset(&plat, 0, sizeof(plat));
    plat.context = p;
    plat.write = peer_write;
    plat.read = peer_read;
    plat.random = peer_random;
    plat.now_ms = peer_now;
    plat.persist = peer_persist;
    plat.load = peer_load;
    plat.log = peer_log;
    plat.board = p->name;
    memset(&mc, 0, sizeof(mc));
    mc.lora = &p->sb.li;
    mc.lora_mode = RNC_LORA_MODE_LEAF;
    mc.announce_interval_ms = 600000u;
    p->app = rnc_mcu_app_new(&plat, &mc);
    if (p->app) {
      uint8_t d[16];
      unsigned k;
      rnc_mcu_app_destination(p->app, d);
      fprintf(stderr, "mcu: %s destination <", p->name);
      for (k = 0; k < 16; k++)
        fprintf(stderr, "%02x", d[k]);
      fprintf(stderr, ">\n");
    }
  }
  /* every board hears every other one (the loss applies to each link) */
  sim_link_all(&h->med, 100);
  if (o->loss_permille) {
    unsigned a, b;
    for (a = 0; a < (unsigned)h->med.count; a++)
      for (b = a + 1; b < (unsigned)h->med.count; b++)
        sim_link_drop(&h->med, (int)a, (int)b, o->loss_permille);
  }
  return h;
}

rnc_lora_if *lora_host_interface(lora_host *h) { return &h->radio.li; }

void lora_host_step(lora_host *h, uint64_t real_now_us) {
  unsigned i;
  if (real_now_us > h->med.now_us)
    h->med.now_us = real_now_us;
  sim_medium_advance(&h->med);
  for (i = 0; i < h->npeers; i++)
    if (h->peers[i].app)
      (void)rnc_mcu_app_step(h->peers[i].app, h->med.now_us / 1000u);
}

void lora_host_free(lora_host *h) {
  unsigned i;
  if (!h)
    return;
  for (i = 0; i < h->npeers; i++)
    rnc_mcu_app_free(h->peers[i].app);
  if (h->rng_fd >= 0)
    close(h->rng_fd);
  free(h);
}
