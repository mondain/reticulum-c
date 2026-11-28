/* Unit test of the MCU application's unix-time policy (mcu/app/rnc_mcu_app.h) and
 * of the persisted identity, with a fake platform. Built in the mcu profile build. */
#include "rnc_mcu_app.h"
#include "reticulum_c/rnc_node.h"
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
  int time_fails;       /* this many writes of the time mark fail */
  unsigned time_writes;
  rnc_hdlc tx;                    /* what the board sends, deframed */
  uint8_t rx[1200];               /* what the board is to read */
  size_t rx_size, rx_at;
  unsigned announces;
  uint64_t announce_time;         /* of the last announce sent */
  uint8_t destination[16];        /* its destination */
  unsigned uncovered;             /* announces sent while the stored mark was older than they are */
} fake;

static uint64_t mark(const fake *f) {
  uint64_t v = 0;
  unsigned i;
  for (i = 0; i < 8 && f->has_time; i++)
    v = (v << 8) | f->time[i];
  return v;
}

static size_t f_write(void *c, const uint8_t *d, size_t n) {
  fake *f = c;
  size_t i;
  for (i = 0; i < n; i++) {
    static uint8_t frame[RNC_MAX_FRAME];
    static rnc_packet packet;
    size_t size = 0, j;
    uint64_t t = 0;
    if (rnc_hdlc_feed(&f->tx, d[i], frame, sizeof(frame), &size) != RNC_OK ||
        rnc_packet_decode(frame, size, &packet) != RNC_OK || (packet.flags & 3u) != RNC_ANNOUNCE)
      continue;
    for (j = 0; j < 5; j++) /* key 64, name 10, random 5, then the time */
      t = (t << 8) | packet.data[64 + 10 + 5 + j];
    ++f->announces;
    f->announce_time = t;
    memcpy(f->destination, packet.destination, 16);
    if (f->has_time && mark(f) < t)
      ++f->uncovered;
    if (!f->has_time)
      ++f->uncovered;
  }
  return n;
}
static size_t f_read(void *c, uint8_t *b, size_t n) {
  fake *f = c;
  size_t left = f->rx_size - f->rx_at;
  if (n > left)
    n = left;
  memcpy(b, f->rx + f->rx_at, n);
  f->rx_at += n;
  return n;
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
    if (f->time_fails) {
      --f->time_fails;
      return -1;
    }
    ++f->time_writes;
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

/* Steps the board every 100 ms from *now_ms for `ms`. */
static void run(rnc_mcu_app *app, uint64_t *now_ms, uint64_t ms) {
  const uint64_t end = *now_ms + ms;
  for (; *now_ms <= end; *now_ms += 100u)
    rnc_mcu_app_step(app, *now_ms);
}

static int f_peer_random(void *c, uint8_t *b, size_t n) { return f_random(c, b, n) == 0 ? 0 : -1; }
static rnc_result peer_random(void *c, uint8_t *b, size_t n) {
  return f_peer_random(c, b, n) == 0 ? RNC_OK : RNC_CRYPTO;
}

/* A peer asks the board for its own path: the board's next read holds the request. */
static void ask_path(fake *f, const uint8_t destination[16]) {
  static fake peer_random_state;
  static rnc_identity identity;
  static rnc_node_event event;
  static uint8_t wire[RNC_MAX_MTU], framed[RNC_MAX_FRAME];
  size_t wire_size = 0, framed_size = 0;
  rnc_node *peer;
  if (!peer_random_state.seed)
    peer_random_state.seed = 99;
  CHECK(rnc_identity_generate(&identity, peer_random, &peer_random_state) == RNC_OK);
  peer = rnc_node_new(&identity, 0, peer_random, &peer_random_state);
  CHECK(peer && rnc_node_add_interface(peer, 1, 115200) == RNC_OK);
  CHECK(rnc_node_request_path(peer, destination, 1000) == RNC_OK);
  CHECK(rnc_node_poll(peer, &event) == RNC_OK && event.type == RNC_NODE_SEND);
  CHECK(rnc_packet_encode(&event.packet, wire, sizeof(wire), &wire_size) == RNC_OK);
  CHECK(rnc_hdlc_encode(wire, wire_size, framed, sizeof(framed), &framed_size) == RNC_OK);
  CHECK(framed_size <= sizeof(f->rx));
  memcpy(f->rx, framed, framed_size);
  f->rx_size = framed_size;
  f->rx_at = 0;
  rnc_node_free(peer);
}

/* The clock of a board without one: every announce must be newer than the ones before a restart (peers ignore the
 * rest), restarts must not run it ahead (receivers drop the future), and flash writes must stay few. */
static void restarts(void) {
  static fake f;
  rnc_mcu_platform p;
  rnc_mcu_app *app;
  uint64_t now, last = 0, first_start = 0, start = 0;
  unsigned boot, writes, announces;
  memset(&f, 0, sizeof(f));
  f.seed = 11;
  p = platform(&f, 0);

  for (boot = 0; boot < 8; ++boot) { /* short runs, one after another */
    app = rnc_mcu_app_new(&p, NULL);
    CHECK(app);
    start = rnc_mcu_app_unix(app, 0);
    if (!boot)
      first_start = start;
    announces = f.announces;
    now = 0;
    run(app, &now, 6000); /* the first announce and its repeat */
    CHECK(f.announces == announces + 2);
    CHECK(f.announce_time - 6 <= start + 1 && f.announce_time >= start);
    CHECK(start > last); /* newer than anything announced before the restart */
    last = f.announce_time;
    rnc_mcu_app_free(app);
  }
  CHECK(f.uncovered == 0); /* the mark was stored before each announce left */
  CHECK(start - first_start <= 7u * (RNC_MCU_TIME_RESERVE_S + 1u)); /* not two minutes a restart */

  /* an hour: a write for each announce that needs one, none in between */
  app = rnc_mcu_app_new(&p, NULL);
  CHECK(app);
  writes = f.time_writes;
  announces = f.announces;
  now = 0;
  run(app, &now, 3600u * 1000u);
  CHECK(f.announces >= announces + 7);
  CHECK(f.time_writes - writes <= f.announces - announces);
  CHECK(f.uncovered == 0);

  /* answers to path requests are announces too, and asking often does not mean writing often */
  run(app, &now, 60u * 1000u);
  announces = f.announces;
  writes = f.time_writes;
  ask_path(&f, f.destination);
  run(app, &now, 2000);
  CHECK(f.announces == announces + 1);
  CHECK(f.uncovered == 0 && f.time_writes == writes + 1);
  for (boot = 0; boot < 20; ++boot) { /* twenty more within four seconds */
    ask_path(&f, f.destination);
    run(app, &now, 100);
  }
  CHECK(f.announces > announces + 1);
  CHECK(f.uncovered == 0 && f.time_writes <= writes + 2);
  last = f.announce_time;
  rnc_mcu_app_free(app);

  /* a write that fails does not stop the announce, and the next one stores the mark */
  app = rnc_mcu_app_new(&p, NULL);
  CHECK(app && rnc_mcu_app_unix(app, 0) > last);
  f.time_fails = 1;
  announces = f.announces;
  writes = f.time_writes;
  now = 0;
  run(app, &now, 2000);
  CHECK(f.announces == announces + 1 && f.time_writes == writes && f.uncovered == 1);
  run(app, &now, 4000);
  CHECK(f.announces == announces + 2 && f.time_writes == writes + 1 && f.uncovered == 1);
  rnc_mcu_app_free(app);

  /* a time set by the host is kept at once */
  app = rnc_mcu_app_new(&p, NULL);
  CHECK(app);
  last = rnc_mcu_app_unix(app, 0) + 100000u;
  CHECK(rnc_mcu_app_set_unix(app, 0, last) == 0);
  rnc_mcu_app_free(app);
  app = rnc_mcu_app_new(&p, NULL);
  CHECK(app && rnc_mcu_app_unix(app, 0) > last);
  rnc_mcu_app_free(app);
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
  /* nothing is stored until the board announces or is told the time */
  CHECK(!f.has_time);
  rnc_mcu_app_step(app, 1000);
  rnc_mcu_app_step(app, 2000); /* the first announce */
  CHECK(f.has_time && mark(&f) >= f.announce_time && f.uncovered == 0);
  last_announced = rnc_mcu_app_unix(app, 121000u + 119000u);
  /* going backwards is refused, forwards accepted */
  CHECK(rnc_mcu_app_set_unix(app, 200000, last_announced - 10) == -1);
  CHECK(rnc_mcu_app_set_unix(app, 200000, last_announced + 100000) == 0);
  t = rnc_mcu_app_unix(app, 200000);
  CHECK(t == last_announced + 100000);
  CHECK(rnc_mcu_app_unix(app, 201000) == t + 1);
  rnc_mcu_app_free(app);

  /* reboot: same identity, and the clock starts later than anything announced or set before */
  app = rnc_mcu_app_new(&p, NULL);
  CHECK(app);
  CHECK(rnc_mcu_app_destination(app, d2) == 0 && !memcmp(d1, d2, 16));
  CHECK(rnc_mcu_app_unix(app, 0) > last_announced + 100000);
  rnc_mcu_app_free(app);

  restarts();

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
