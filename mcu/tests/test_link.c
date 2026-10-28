/* Unit test of the MCU application's transport-link handling (the link_up hook of
 * rnc_mcu_platform.h): no sockets, a fake platform. It proves
 *   - nothing is sent while the link is down (announces are held back),
 *   - an announce goes out soon after the link comes up, and again soon after every
 *     reconnect even though the regular interval (here 10 minutes) has not elapsed,
 *   - output produced while the link is down is dropped, not delivered late,
 *   - the HDLC decoder state is reset on reconnect (a half-received frame from the old
 *     connection must not leak into the new one),
 *   - a platform without a link_up hook behaves as before (always up).
 * The reconnect/backoff policy of the sockets is tested separately by
 * mcu/tests/mcu_tcp.sh. Built in the mcu profile build. */
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
  uint8_t identity[64];
  int has_identity;
  int up;
  unsigned seed;
  size_t written; /* bytes accepted by write */
  uint8_t rx[512];
  size_t rx_size, rx_pos;
} fake;

static size_t f_write(void *c, const uint8_t *d, size_t n) {
  (void)d;
  ((fake *)c)->written += n;
  return n;
}
static size_t f_read(void *c, uint8_t *b, size_t n) {
  fake *f = c;
  size_t k = f->rx_size - f->rx_pos;
  if (k > n)
    k = n;
  memcpy(b, f->rx + f->rx_pos, k);
  f->rx_pos += k;
  return k;
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
static int f_persist(void *c, const char *k, const void *d, size_t n) {
  fake *f = c;
  if (!strcmp(k, RNC_MCU_KEY_IDENTITY) && n == 64) {
    memcpy(f->identity, d, n);
    f->has_identity = 1;
  }
  return 0;
}
static int f_load(void *c, const char *k, void *b, size_t n) {
  fake *f = c;
  if (!strcmp(k, RNC_MCU_KEY_IDENTITY) && f->has_identity && n >= 64) {
    memcpy(b, f->identity, 64);
    return 64;
  }
  return -1;
}
static int f_link_up(void *c) { return ((fake *)c)->up; }

static rnc_mcu_platform platform(fake *f, int with_link) {
  rnc_mcu_platform p;
  memset(&p, 0, sizeof(p));
  p.context = f;
  p.write = f_write;
  p.read = f_read;
  p.random = f_random;
  p.now_ms = f_now;
  p.persist = f_persist;
  p.load = f_load;
  if (with_link)
    p.link_up = f_link_up;
  return p;
}

/* steps every 20 ms from *t for `ms` milliseconds */
static void run(rnc_mcu_app *app, uint64_t *t, uint64_t ms) {
  uint64_t end = *t + ms;
  while (*t < end) {
    (void)rnc_mcu_app_step(app, *t);
    *t += 20;
  }
}

/* a raw Reticulum packet (header, hops, 16 byte destination, context, data), HDLC
 * framed: a well formed DATA packet to nobody in particular */
static size_t frame_packet(uint8_t *out) {
  uint8_t wire[32];
  size_t n = 0, i;
  wire[n++] = 0x00;
  wire[n++] = 0x00;
  for (i = 0; i < 16; i++)
    wire[n++] = (uint8_t)(0xa0 + i);
  wire[n++] = 0x00;
  for (i = 0; i < 5; i++)
    wire[n++] = (uint8_t)('a' + i);
  out[0] = 0x7e;
  memcpy(out + 1, wire, n);
  out[1 + n] = 0x7e;
  return n + 2;
}

int main(void) {
  fake f;
  rnc_mcu_platform p;
  rnc_mcu_config config;
  rnc_mcu_app *app;
  rnc_mcu_stats s;
  uint64_t t = 0;
  size_t before;
  uint8_t partial[] = {0x7e, 0xaa, 0xbb, 0xcc}; /* a frame cut off by the connection */
  memset(&f, 0, sizeof(f));
  f.seed = 11;
  memset(&config, 0, sizeof(config));
  config.announce_interval_ms = 600000u; /* far longer than the test */

  /* link down from the start: nothing is sent */
  p = platform(&f, 1);
  f.up = 0;
  app = rnc_mcu_app_new(&p, &config);
  CHECK(app);
  run(app, &t, 30000);
  CHECK(f.written == 0);
  rnc_mcu_app_get_stats(app, &s);
  CHECK(s.announces == 0 && s.link_ups == 0);

  /* link comes up: announce soon (first, then the early repeat) */
  f.up = 1;
  run(app, &t, 3000);
  CHECK(f.written > 0);
  rnc_mcu_app_get_stats(app, &s);
  CHECK(s.link_ups == 1 && s.announces == 1);
  run(app, &t, 6000);
  rnc_mcu_app_get_stats(app, &s);
  CHECK(s.announces == 2); /* the repeat a few seconds later */
  before = f.written;
  run(app, &t, 60000); /* quiet until the long interval */
  CHECK(f.written == before);

  /* link drops: nothing leaves while it is down, even past the repeat times */
  f.up = 0;
  run(app, &t, 20000);
  CHECK(f.written == before);
  rnc_mcu_app_get_stats(app, &s);
  CHECK(s.link_downs == 1);

  /* the link returns and the new connection delivers a frame */
  f.up = 1;
  f.rx_size = frame_packet(f.rx);
  f.rx_pos = 0;
  run(app, &t, 100);
  rnc_mcu_app_get_stats(app, &s);
  CHECK(s.link_ups == 2);
  CHECK(s.rx_packets >= 1);
  CHECK(s.rx_bad == 0);
  /* and the re-announce follows soon although 10 minutes have not passed */
  run(app, &t, 3000);
  rnc_mcu_app_get_stats(app, &s);
  CHECK(s.announces == 3);

  /* the connection breaks in the middle of a frame; the next one must start clean */
  memcpy(f.rx, partial, sizeof(partial));
  f.rx_size = sizeof(partial);
  f.rx_pos = 0;
  run(app, &t, 40); /* the fragment is consumed while up */
  f.up = 0;
  run(app, &t, 100);
  f.up = 1;
  f.rx_size = f.rx_pos = 0;
  f.rx_size = frame_packet(f.rx);
  run(app, &t, 100);
  rnc_mcu_app_get_stats(app, &s);
  CHECK(s.rx_bad == 0); /* with no reset the stale fragment would be a bad frame */
  CHECK(s.rx_packets >= 2);
  rnc_mcu_app_free(app);

  /* without a link_up hook the transport is always up, as before */
  memset(&f, 0, sizeof(f));
  f.seed = 5;
  p = platform(&f, 0);
  app = rnc_mcu_app_new(&p, &config);
  CHECK(app);
  t = 0;
  run(app, &t, 100);
  CHECK(f.written > 0);
  rnc_mcu_app_free(app);
  puts("mcu link tests passed");
  return 0;
}
