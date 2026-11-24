/* The MCU application and the RNS 1.6 destination stamp: a stamp loaded through the console (RNC_MCU_KEY_STAMP)
 * is verified at start and announced with; one that does not fit this identity is ignored, and the board never
 * searches. A fake platform, built in the mcu profile build. */
#include "rnc_mcu_net.h"
#include <reticulum_c/rnc_netstamp.h>
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

typedef struct fake {
  uint8_t identity[64], stamp[14], time[8], wire[8192];
  int has_identity, has_stamp, has_time;
  size_t wired;
  unsigned seed;
} fake;
static size_t f_write(void *c, const uint8_t *d, size_t n) {
  fake *f = c;
  if (f->wired + n <= sizeof(f->wire)) {
    memcpy(f->wire + f->wired, d, n);
    f->wired += n;
  }
  return n;
}
static size_t f_read(void *c, uint8_t *b, size_t n) {
  (void)c; (void)b; (void)n;
  return 0;
}
static int f_random(void *c, uint8_t *b, size_t n) {
  fake *f = c;
  size_t i;
  for (i = 0; i < n; i++) {
    f->seed = f->seed * 1664525u + 1013904223u;
    b[i] = (uint8_t)(f->seed >> 24);
  }
  return 0;
}
static rnc_result f_rng(void *c, uint8_t *b, size_t n) { return f_random(c, b, n) == 0 ? RNC_OK : RNC_CRYPTO; }
static uint64_t f_now(void *c) { (void)c; return 0; }
static int f_persist(void *c, const char *k, const void *d, size_t n) {
  fake *f = c;
  if (!strcmp(k, RNC_MCU_KEY_IDENTITY) && n == 64) { memcpy(f->identity, d, n); f->has_identity = 1; }
  else if (!strcmp(k, RNC_MCU_KEY_STAMP) && n == 14) { memcpy(f->stamp, d, n); f->has_stamp = 1; }
  else if (!strcmp(k, RNC_MCU_KEY_TIME) && n == 8) { memcpy(f->time, d, n); f->has_time = 1; }
  else return -1;
  return 0;
}
static int f_load(void *c, const char *k, void *b, size_t n) {
  fake *f = c;
  if (!strcmp(k, RNC_MCU_KEY_IDENTITY) && f->has_identity && n >= 64) { memcpy(b, f->identity, 64); return 64; }
  if (!strcmp(k, RNC_MCU_KEY_STAMP) && f->has_stamp && n >= 14) { memcpy(b, f->stamp, 14); return 14; }
  if (!strcmp(k, RNC_MCU_KEY_TIME) && f->has_time && n >= 8) { memcpy(b, f->time, 8); return 8; }
  return -1;
}
static rnc_mcu_platform platform(fake *f) {
  rnc_mcu_platform p;
  memset(&p, 0, sizeof(p));
  p.context = f;
  p.write = f_write;
  p.read = f_read;
  p.random = f_random;
  p.now_ms = f_now;
  p.persist = f_persist;
  p.load = f_load;
  return p;
}
/* the first announce for `dest` in what the board wrote; 0 when there is none */
static int announce_written(const fake *f, const uint8_t dest[16], rnc_announce *out) {
  rnc_hdlc state;
  size_t i, got;
  uint8_t frame[RNC_MAX_FRAME];
  memset(&state, 0, sizeof(state));
  for (i = 0; i < f->wired; i++)
    if (rnc_hdlc_feed(&state, f->wire[i], frame, sizeof(frame), &got) == RNC_OK) {
      rnc_packet p;
      if (rnc_packet_decode(frame, got, &p) == RNC_OK && (p.flags & 3u) == RNC_ANNOUNCE &&
          !memcmp(p.destination, dest, 16) && rnc_announce_verify(&p, out) == RNC_OK)
        return 1;
    }
  return 0;
}
static void boot_and_announce(fake *f, rnc_announce *a, int *found, uint8_t dest[16], double value) {
  rnc_mcu_platform p = platform(f);
  rnc_mcu_config cfg;
  rnc_mcu_app *app;
  memset(&cfg, 0, sizeof(cfg));
  cfg.stamp_value = value;
  f->wired = 0;
  app = rnc_mcu_app_new(&p, &cfg);
  CHECK(app && rnc_mcu_app_destination(app, dest) == 0);
  rnc_mcu_app_step(app, 1);
  rnc_mcu_app_step(app, 5000);
  *found = announce_written(f, dest, a);
  rnc_mcu_app_free(app);
}
int main(void) {
  fake f;
  rnc_mcu_cfg cfg;
  rnc_mcu_platform p;
  rnc_announce a;
  rnc_netstamp_ext ext;
  uint8_t dest[16], material[90], stamp[14], blank[14] = {0};
  int found;
  size_t i;
  memset(&f, 0, sizeof(f));
  f.seed = 9;
  p = platform(&f);
  rnc_mcu_cfg_init(&cfg);
  cfg.stamp_value = 6.0;

  /* before the first boot there is no identity: nothing to stamp yet */
  rnc_mcu_stamp_prepare(&cfg, &p);
  CHECK(!cfg.stamp_material[0] && !strcmp(cfg.stamp_status, "none"));

  /* the first boot creates the identity; an unstamped board announces as before */
  boot_and_announce(&f, &a, &found, dest, 6.0);
  CHECK(f.has_identity && found && !rnc_netstamp_ext_parse(a.app_data, a.app_size, &ext));

  /* the console now has material to show; a stamp found over it is accepted and stored */
  rnc_mcu_stamp_prepare(&cfg, &p);
  CHECK(strlen(cfg.stamp_material) == 180 && !strcmp(cfg.stamp_status, "none"));
  for (i = 0; i < sizeof(material); i++)
    material[i] = (uint8_t)rnc_mcu_hex_byte(cfg.stamp_material + 2 * i);
  CHECK(rnc_netstamp_find(material, sizeof(material), 6.0, f_rng, &f, 0, stamp, NULL) == RNC_OK);
  CHECK(rnc_mcu_stamp_store(&p, stamp) == 0 && f.has_stamp);
  rnc_mcu_stamp_prepare(&cfg, &p);
  CHECK(!strcmp(cfg.stamp_status, "valid"));

  /* at the next boot the stamp is verified and the announce carries it, with the link request cost */
  boot_and_announce(&f, &a, &found, dest, 6.0);
  CHECK(found && rnc_netstamp_ext_parse(a.app_data, a.app_size, &ext) == 1 && ext.app_size == 0 && ext.link_cost == 12.5);
  CHECK(!memcmp(ext.stamp, stamp, 14));
  CHECK(rnc_netstamp_valid(material, sizeof(material), ext.stamp, 14, 6.0));

  /* a stored stamp that falls short of the required value is ignored: unstamped announces, status "stale" */
  boot_and_announce(&f, &a, &found, dest, 12.0);
  {
    rnc_mcu_platform q = platform(&f);
    int fits = rnc_netstamp_valid(material, sizeof(material), stamp, 14, 12.0);
    CHECK(found && (fits ? rnc_netstamp_ext_parse(a.app_data, a.app_size, &ext) == 1
                         : !rnc_netstamp_ext_parse(a.app_data, a.app_size, &ext)));
    cfg.stamp_value = 12.0;
    rnc_mcu_stamp_prepare(&cfg, &q);
    CHECK(!strcmp(cfg.stamp_status, fits ? "valid" : "stale"));
  }

  /* a new identity (a reflash) leaves the old stamp stale and the board unstamped */
  f.has_identity = 0;
  boot_and_announce(&f, &a, &found, dest, 6.0);
  CHECK(found && !rnc_netstamp_ext_parse(a.app_data, a.app_size, &ext));
  cfg.stamp_value = 6.0;
  rnc_mcu_stamp_prepare(&cfg, &p);
  CHECK(!strcmp(cfg.stamp_status, "stale"));

  /* all zero removes the stamp */
  CHECK(rnc_mcu_stamp_store(&p, blank) == 0);
  rnc_mcu_stamp_prepare(&cfg, &p);
  CHECK(!strcmp(cfg.stamp_status, "none"));
  puts("mcu stamp tests passed");
  return 0;
}
