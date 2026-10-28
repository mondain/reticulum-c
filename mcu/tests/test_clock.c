/* Unit test of the MCU application's unix-time policy (mcu/app/rnc_mcu_app.h) and
 * of the persisted identity, with a fake platform. Built in the mcu profile build. */
#include "rnc_mcu_app.h"
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
  uint8_t identity[64], time[8];
  int has_identity, has_time;
  uint64_t real_unix; /* 0 = no clock */
  unsigned seed;
} fake;

static size_t f_write(void *c, const uint8_t *d, size_t n) {
  (void)c;
  (void)d;
  return n;
}
static size_t f_read(void *c, uint8_t *b, size_t n) {
  (void)c;
  (void)b;
  (void)n;
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
static uint64_t f_now(void *c) {
  (void)c;
  return 0;
}
static uint64_t f_unix(void *c) { return ((fake *)c)->real_unix; }
static int f_persist(void *c, const char *k, const void *d, size_t n) {
  fake *f = c;
  if (!strcmp(k, RNC_MCU_KEY_IDENTITY) && n == 64) {
    memcpy(f->identity, d, n);
    f->has_identity = 1;
  } else if (!strcmp(k, RNC_MCU_KEY_TIME) && n == 8) {
    memcpy(f->time, d, n);
    f->has_time = 1;
  } else
    return -1;
  return 0;
}
static int f_load(void *c, const char *k, void *b, size_t n) {
  fake *f = c;
  if (!strcmp(k, RNC_MCU_KEY_IDENTITY) && f->has_identity && n >= 64) {
    memcpy(b, f->identity, 64);
    return 64;
  }
  if (!strcmp(k, RNC_MCU_KEY_TIME) && f->has_time && n >= 8) {
    memcpy(b, f->time, 8);
    return 8;
  }
  return -1;
}
static rnc_mcu_platform platform(fake *f, int with_clock) {
  rnc_mcu_platform p;
  memset(&p, 0, sizeof(p));
  p.context = f;
  p.write = f_write;
  p.read = f_read;
  p.random = f_random;
  p.now_ms = f_now;
  p.persist = f_persist;
  p.load = f_load;
  if (with_clock)
    p.unix_seconds = f_unix;
  return p;
}

int main(void) {
  fake f;
  rnc_mcu_platform p;
  rnc_mcu_app *app;
  uint8_t d1[16], d2[16];
  uint64_t t, last_announced;
  memset(&f, 0, sizeof(f));
  f.seed = 7;

  /* first boot: build epoch, identity created and persisted */
  p = platform(&f, 0);
  app = rnc_mcu_app_new(&p, NULL);
  CHECK(app);
  CHECK(f.has_identity);
  CHECK(rnc_mcu_app_destination(app, d1) == 0);
  CHECK(rnc_mcu_app_unix(app, 0) == (uint64_t)RNC_MCU_BUILD_EPOCH);
  CHECK(rnc_mcu_app_unix(app, 5000) == (uint64_t)RNC_MCU_BUILD_EPOCH + 5);
  /* the mark is stored once RNC_MCU_TIME_PERSIST_S seconds passed */
  CHECK(!f.has_time);
  rnc_mcu_app_step(app, 1000);
  CHECK(!f.has_time);
  rnc_mcu_app_step(app, (RNC_MCU_TIME_PERSIST_S + 1u) * 1000u);
  CHECK(f.has_time);
  last_announced = rnc_mcu_app_unix(app, (RNC_MCU_TIME_PERSIST_S + 1u) * 1000u + 119000u);
  /* going backwards is refused, forwards accepted */
  CHECK(rnc_mcu_app_set_unix(app, 200000, last_announced - 10) == -1);
  CHECK(rnc_mcu_app_set_unix(app, 200000, last_announced + 100000) == 0);
  t = rnc_mcu_app_unix(app, 200000);
  CHECK(t == last_announced + 100000);
  CHECK(rnc_mcu_app_unix(app, 201000) == t + 1);
  rnc_mcu_app_free(app);

  /* reboot: same identity, and the clock starts later than anything announced
   * before the reset (the mark lags by at most RNC_MCU_TIME_PERSIST_S seconds) */
  app = rnc_mcu_app_new(&p, NULL);
  CHECK(app);
  CHECK(rnc_mcu_app_destination(app, d2) == 0 && !memcmp(d1, d2, 16));
  CHECK(rnc_mcu_app_unix(app, 0) > (uint64_t)RNC_MCU_BUILD_EPOCH + RNC_MCU_TIME_PERSIST_S);
  rnc_mcu_app_free(app);

  /* a real clock wins, and is never moved back by the estimate */
  f.real_unix = UINT64_C(1900000000);
  p = platform(&f, 1);
  app = rnc_mcu_app_new(&p, NULL);
  CHECK(app);
  CHECK(rnc_mcu_app_unix(app, 0) == UINT64_C(1900000000));
  f.real_unix = UINT64_C(1900000010);
  CHECK(rnc_mcu_app_unix(app, 3000) == UINT64_C(1900000010));
  f.real_unix = 0; /* the source lost its time: keep counting from uptime */
  CHECK(rnc_mcu_app_unix(app, 13000) == UINT64_C(1900000020));
  rnc_mcu_app_free(app);

  /* missing hooks are refused */
  p = platform(&f, 0);
  p.persist = NULL;
  CHECK(!rnc_mcu_app_new(&p, NULL));
  puts("mcu clock tests passed");
  return 0;
}
