/* Unit tests of the portable LoRa core: physical layer arithmetic (time on air against
 * published example values and against an independent implementation of the formula, the
 * RNode bit rate), the air framing (header layout, split and reassembly, sequence handling,
 * orphan fragments, duplicates, the 254/255/256 boundary and the maximum, a differential
 * check against a receiver written from the stock firmware's rules), the airtime budget
 * and the CSMA state machine, and the configuration parser. No hardware, no node. */
#include "../radio/rnc_lora_air.h"
#include "../radio/rnc_lora_cfg.h"
#include "../radio/rnc_lora_mac.h"
#include "../radio/rnc_lora_phy.h"
#include "radio/lora_sim.h"
#include <math.h>
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

static unsigned rng_state = 12345;
static unsigned rnd(void) {
  rng_state = rng_state * 1664525u + 1013904223u;
  return rng_state >> 8;
}

static rnc_lora_params P(unsigned sf, unsigned bw, unsigned cr, unsigned pre) {
  rnc_lora_params p;
  memset(&p, 0, sizeof(p));
  p.freq_hz = 868100000u;
  p.bw_hz = bw;
  p.sf = (uint8_t)sf;
  p.cr = (uint8_t)cr;
  p.preamble_symbols = (uint16_t)pre;
  return p;
}

/* ---- time on air ----------------------------------------------------------------------------- */
static void test_toa(void) {
  rnc_lora_params p;
  unsigned sf, cr, pl, bwi;
  static const uint32_t bws[10] = {7800, 10400, 15600, 20800, 31250, 41700, 62500, 125000, 250000, 500000};
  /* widely published values of the Semtech formula (explicit header, CRC on, 8 preamble
   * symbols): the symbol time is exact for 125 kHz, so the figures are exact too */
  p = P(7, 125000, 5, 8);
  CHECK_EQ(rnc_lora_toa_us(&p, 10), 41216);      /* 41.2 ms: SF7, 10 bytes */
  p = P(12, 125000, 5, 8);
  CHECK_EQ(rnc_lora_toa_us(&p, 10), 991232);     /* 991.2 ms: SF12, 10 bytes */
  CHECK_EQ(rnc_lora_toa_us(&p, 64), 2793472);    /* 2793.5 ms: SF12, 64 bytes (LoRaWAN) */
  p = P(9, 125000, 5, 8);
  CHECK_EQ(rnc_lora_toa_us(&p, 20), 185344);     /* 185.3 ms: SF9, 20 bytes */
  p = P(7, 125000, 5, 8);
  CHECK_EQ(rnc_lora_toa_us(&p, 64), 118016);     /* 118.0 ms: SF7, 64 bytes (LoRaWAN) */
  /* cross-check the whole grid against the independent floating point formula */
  for (sf = 5; sf <= 12; sf++)
    for (bwi = 0; bwi < 10; bwi++)
      for (cr = 5; cr <= 8; cr++)
        for (pl = 1; pl <= 255; pl += (pl < 20 ? 1 : 37)) {
          double ref;
          uint64_t got;
          p = P(sf, bws[bwi], cr, 12);
          ref = sim_toa_us(bws[bwi], sf, cr, 12, pl, rnc_lora_ldro(bws[bwi], sf));
          got = rnc_lora_toa_us(&p, pl);
          if (fabs((double)got - ref) > 2.0 + ref * 1e-6) {
            fprintf(stderr, "toa sf%u bw%u cr%u pl%u: %llu vs %.3f\n", sf, (unsigned)bws[bwi], cr,
                    pl, (unsigned long long)got, ref);
            failures++;
          }
        }
  /* the packet time on air: one frame up to 254, two frames above */
  p = P(8, 125000, 5, 12);
  CHECK_EQ(rnc_lora_packet_toa_us(&p, 254), rnc_lora_toa_us(&p, 255));
  CHECK_EQ(rnc_lora_packet_toa_us(&p, 255), rnc_lora_toa_us(&p, 255) + rnc_lora_toa_us(&p, 2));
  CHECK_EQ(rnc_lora_packet_toa_us(&p, 500), rnc_lora_toa_us(&p, 255) + rnc_lora_toa_us(&p, 247));
  /* SF5 and SF6 use their own preamble and header terms */
  p = P(6, 125000, 5, 8);
  CHECK(rnc_lora_toa_us(&p, 10) > 0);
}

static void test_ldro(void) {
  /* the firmware's rule (integer 2^SF / (BW in kHz) > 16), not "symbol time > 16 ms": they
   * differ exactly where the symbol is 16.384 ms long */
  CHECK_EQ(rnc_lora_ldro(125000, 12), 1);
  CHECK_EQ(rnc_lora_ldro(125000, 11), 0);   /* 16.384 ms: off for the firmware */
  CHECK_EQ(rnc_lora_ldro(250000, 12), 0);   /* 16.384 ms */
  CHECK_EQ(rnc_lora_ldro(62500, 10), 0);    /* 16.384 ms */
  CHECK_EQ(rnc_lora_ldro(31250, 9), 0);     /* 16.384 ms */
  CHECK_EQ(rnc_lora_ldro(62500, 11), 1);
  CHECK_EQ(rnc_lora_ldro(125000, 10), 0);
  CHECK_EQ(rnc_lora_ldro(500000, 12), 0);
  CHECK_EQ(rnc_lora_ldro(7800, 7), 1);      /* 128 / 7 = 18 */
  CHECK_EQ(rnc_lora_ldro(10400, 7), 0);     /* 128 / 10 = 12 */
  CHECK_EQ(rnc_lora_ldro(20800, 9), 1);     /* 512 / 20 = 25 */
  CHECK_EQ(rnc_lora_ldro(20800, 8), 0);     /* 256 / 20 = 12 */
  /* the symbol time itself */
  CHECK_EQ(rnc_lora_symbol_us(125000, 7), 1024);
  CHECK_EQ(rnc_lora_symbol_us(125000, 12), 32768);
  CHECK_EQ(rnc_lora_symbol_us(250000, 12), 16384);
  CHECK_EQ(rnc_lora_symbol_us(500000, 5), 64);
}

static void test_bitrate_and_preamble(void) {
  rnc_lora_params p;
  unsigned sf, cr, bwi;
  static const uint32_t bws[10] = {7800, 10400, 15600, 20800, 31250, 41700, 62500, 125000, 250000, 500000};
  p = P(8, 125000, 5, 0);
  /* host SDK's rnode formula, evaluated here in floating point exactly as the reference
   * stack writes it: sf * ((4 / cr) / (2^sf / (bw / 1000))) * 1000 */
  for (sf = 5; sf <= 12; sf++)
    for (bwi = 0; bwi < 10; bwi++)
      for (cr = 5; cr <= 8; cr++) {
        double ref = sf * ((4.0 / cr) / (pow(2, sf) / (bws[bwi] / 1000.0))) * 1000.0;
        uint32_t got;
        p = P(sf, bws[bwi], cr, 0);
        got = rnc_lora_bitrate(&p);
        if (fabs((double)got - ref) > 0.5 + 1e-9 && !(ref < 1.0 && got == 1)) {
          fprintf(stderr, "bitrate sf%u bw%u cr%u: %u vs %.4f\n", sf, (unsigned)bws[bwi], cr, got, ref);
          failures++;
        }
      }
  p = P(8, 125000, 5, 0);
  CHECK_EQ(rnc_lora_bitrate(&p), 3125);       /* SF8, 125 kHz, 4/5 */
  p = P(7, 500000, 5, 0);
  CHECK_EQ(rnc_lora_bitrate(&p), 21875);
  /* preamble: at least 18 symbols, enough for 24 ms (6 ms above 30 kbit/s) */
  CHECK_EQ(rnc_lora_default_preamble(125000, 7, 5), 24);   /* 24 ms / 1.024 ms */
  CHECK_EQ(rnc_lora_default_preamble(125000, 12, 5), 18);  /* floor of 18 symbols */
  CHECK_EQ(rnc_lora_default_preamble(500000, 5, 5), 94);   /* 30.5 kbit/s: 6 ms / 64 us */
  CHECK_EQ(rnc_lora_default_preamble(500000, 7, 5), 94);   /* 21.9 kbit/s: 24 ms / 0.256 ms */
}

/* ---- air framing ------------------------------------------------------------------------------- */
static void fill(uint8_t *p, size_t n, unsigned seed) {
  size_t i;
  for (i = 0; i < n; i++)
    p[i] = (uint8_t)((i * 7u + seed * 13u + (i >> 3)) & 0xFFu);
}

static void test_air_layout(void) {
  uint8_t pkt[508], frame[255];
  size_t n;
  fill(pkt, sizeof(pkt), 1);
  CHECK_EQ(rnc_air_header(0xA, 0), 0xA0);
  CHECK_EQ(rnc_air_header(0xA, 1), 0xA1);
  CHECK_EQ(rnc_air_header(0x1F, 0), 0xF0); /* only the low nibble of the sequence is used */
  CHECK_EQ(rnc_air_header(0, 1), 0x01);
  /* sizes and frame counts around the boundary */
  CHECK_EQ(rnc_air_frames(0), 0);
  CHECK_EQ(rnc_air_frames(1), 1);
  CHECK_EQ(rnc_air_frames(253), 1);
  CHECK_EQ(rnc_air_frames(254), 1);
  CHECK_EQ(rnc_air_frames(255), 2);
  CHECK_EQ(rnc_air_frames(256), 2);
  CHECK_EQ(rnc_air_frames(500), 2);
  CHECK_EQ(rnc_air_frames(508), 2);
  CHECK_EQ(rnc_air_frames(509), 0);
  /* 254 bytes: one frame of 255, split flag clear */
  n = rnc_air_build(pkt, 254, 0x5, 0, frame);
  CHECK_EQ(n, 255);
  CHECK_EQ(frame[0], 0x50);
  CHECK(!memcmp(frame + 1, pkt, 254));
  CHECK_EQ(rnc_air_build(pkt, 254, 0x5, 1, frame), 0);
  /* 255 bytes: 254 + 1, both with the split flag and the same sequence */
  n = rnc_air_build(pkt, 255, 0x7, 0, frame);
  CHECK_EQ(n, 255);
  CHECK_EQ(frame[0], 0x71);
  CHECK(!memcmp(frame + 1, pkt, 254));
  n = rnc_air_build(pkt, 255, 0x7, 1, frame);
  CHECK_EQ(n, 2);
  CHECK_EQ(frame[0], 0x71);
  CHECK_EQ(frame[1], pkt[254]);
  /* 256 */
  n = rnc_air_build(pkt, 256, 0x3, 1, frame);
  CHECK_EQ(n, 3);
  CHECK(!memcmp(frame + 1, pkt + 254, 2));
  /* 500, the Reticulum MTU: 254 + 246 */
  n = rnc_air_build(pkt, 500, 0x3, 1, frame);
  CHECK_EQ(n, 247);
  CHECK(!memcmp(frame + 1, pkt + 254, 246));
  /* the maximum, 508: two full frames */
  CHECK_EQ(rnc_air_build(pkt, 508, 0xF, 0, frame), 255);
  CHECK_EQ(rnc_air_build(pkt, 508, 0xF, 1, frame), 255);
  CHECK(!memcmp(frame + 1, pkt + 254, 254));
  CHECK_EQ(frame[0], 0xF1);
  CHECK_EQ(rnc_air_build(pkt, 509, 0xF, 0, frame), 0);
  /* sequence numbers: never equal to the previous */
  {
    unsigned i, prev = 3;
    for (i = 0; i < 2000; i++) {
      unsigned s = rnc_air_next_sequence(prev, rnd());
      CHECK(s <= 15 && s != prev);
      prev = s;
    }
  }
}

static size_t air_send(rnc_air_rx *rx, const uint8_t *pkt, size_t n, unsigned seq, uint64_t t,
                       uint8_t *out) {
  uint8_t frame[255];
  unsigned f, frames = rnc_air_frames(n);
  size_t got = 0;
  for (f = 0; f < frames; f++) {
    size_t fn = rnc_air_build(pkt, n, seq, f, frame);
    size_t r = rnc_air_rx_frame(rx, frame, fn, t + f * 10, out);
    if (r)
      got = r;
  }
  return got;
}

static void test_air_roundtrip(void) {
  rnc_air_rx rx;
  uint8_t pkt[508], out[508];
  size_t n;
  rnc_air_rx_init(&rx, 5000000u, 10000000u);
  for (n = 1; n <= 508; n++) {
    fill(pkt, n, (unsigned)n);
    memset(out, 0, sizeof(out));
    CHECK_EQ(air_send(&rx, pkt, n, (unsigned)(n % 16u), 1000000u + n * 100000u, out), n);
    CHECK(!memcmp(pkt, out, n));
  }
}

static void test_air_receive_rules(void) {
  rnc_air_rx rx;
  uint8_t out[508], pkt[508], f0[255], f1[255], tiny[2];
  size_t n0, n1;
  fill(pkt, 400, 9);
  n0 = rnc_air_build(pkt, 400, 0x4, 0, f0);
  n1 = rnc_air_build(pkt, 400, 0x4, 1, f1);

  /* second half alone, nothing pending: it is taken for a first half only if it is full
   * size, which it is not: ignored */
  rnc_air_rx_init(&rx, 5000000u, 10000000u);
  CHECK_EQ(rnc_air_rx_frame(&rx, f1, n1, 0, out), 0);
  CHECK_EQ(rx.dropped_bad, 1);
  CHECK_EQ(rx.pending_seq, RNC_AIR_SEQ_NONE);

  /* orphan first half expires and the late second half is then ignored */
  rnc_air_rx_init(&rx, 5000000u, 10000000u);
  CHECK_EQ(rnc_air_rx_frame(&rx, f0, n0, 1000, out), 0);
  CHECK_EQ(rx.pending_seq, 4);
  rnc_air_rx_tick(&rx, 1000 + 4999999u);
  CHECK_EQ(rx.pending_seq, 4);
  rnc_air_rx_tick(&rx, 1000 + 5000000u);
  CHECK_EQ(rx.pending_seq, RNC_AIR_SEQ_NONE);
  CHECK_EQ(rx.dropped_expired, 1);
  CHECK_EQ(rnc_air_rx_frame(&rx, f1, n1, 7000000u, out), 0);
  /* a second half inside the timeout completes it */
  rnc_air_rx_init(&rx, 5000000u, 10000000u);
  CHECK_EQ(rnc_air_rx_frame(&rx, f0, n0, 0, out), 0);
  CHECK_EQ(rnc_air_rx_frame(&rx, f1, n1, 4000000u, out), 400);
  CHECK(!memcmp(out, pkt, 400));
  /* expiry is checked when a frame arrives, even without a tick */
  rnc_air_rx_init(&rx, 5000000u, 10000000u);
  CHECK_EQ(rnc_air_rx_frame(&rx, f0, n0, 0, out), 0);
  CHECK_EQ(rnc_air_rx_frame(&rx, f1, n1, 6000000u, out), 0);

  /* a different sequence number replaces the pending first half (the stock behaviour) */
  {
    uint8_t g0[255], g1[255], other[400];
    size_t m0, m1;
    fill(other, 400, 77);
    m0 = rnc_air_build(other, 400, 0x9, 0, g0);
    m1 = rnc_air_build(other, 400, 0x9, 1, g1);
    rnc_air_rx_init(&rx, 5000000u, 10000000u);
    CHECK_EQ(rnc_air_rx_frame(&rx, f0, n0, 0, out), 0);
    CHECK_EQ(rnc_air_rx_frame(&rx, g0, m0, 10, out), 0);  /* replaces */
    CHECK_EQ(rx.restarts, 1);
    CHECK_EQ(rnc_air_rx_frame(&rx, g1, m1, 20, out), 400); /* the replacing packet completes */
    CHECK(!memcmp(out, other, 400));
    CHECK_EQ(rnc_air_rx_frame(&rx, f1, n1, 30, out), 0);   /* seq 4: no longer pending */
    /* interleaved senders lose both packets but never deliver a mixture */
    rnc_air_rx_init(&rx, 5000000u, 10000000u);
    CHECK_EQ(rnc_air_rx_frame(&rx, f0, n0, 0, out), 0);
    CHECK_EQ(rnc_air_rx_frame(&rx, g0, m0, 10, out), 0);
    CHECK_EQ(rnc_air_rx_frame(&rx, f1, n1, 20, out), 0);
    CHECK_EQ(rnc_air_rx_frame(&rx, g1, m1, 30, out), 0);
  }

  /* a whole packet drops a pending half and is delivered */
  {
    uint8_t whole[255], small[40];
    size_t wn;
    fill(small, 40, 3);
    wn = rnc_air_build(small, 40, 0x2, 0, whole);
    rnc_air_rx_init(&rx, 5000000u, 10000000u);
    CHECK_EQ(rnc_air_rx_frame(&rx, f0, n0, 0, out), 0);
    CHECK_EQ(rnc_air_rx_frame(&rx, whole, wn, 10, out), 40);
    CHECK(!memcmp(out, small, 40));
    CHECK_EQ(rx.dropped_orphans, 1);
    CHECK_EQ(rx.pending_seq, RNC_AIR_SEQ_NONE);
    CHECK_EQ(rnc_air_rx_frame(&rx, f1, n1, 20, out), 0);
  }

  /* duplicates: the first half repeated is not taken for the second half */
  rnc_air_rx_init(&rx, 5000000u, 10000000u);
  CHECK_EQ(rnc_air_rx_frame(&rx, f0, n0, 0, out), 0);
  CHECK_EQ(rnc_air_rx_frame(&rx, f0, n0, 10, out), 0);
  CHECK_EQ(rx.dropped_dup, 1);
  CHECK_EQ(rnc_air_rx_frame(&rx, f1, n1, 20, out), 400);
  /* the same two frames again within the window: delivered once */
  CHECK_EQ(rnc_air_rx_frame(&rx, f0, n0, 30, out), 0);
  CHECK_EQ(rnc_air_rx_frame(&rx, f1, n1, 40, out), 0);
  CHECK_EQ(rx.dropped_dup, 2);
  /* after the window the same packet is delivered again */
  CHECK_EQ(rnc_air_rx_frame(&rx, f0, n0, 20000000u, out), 0);
  CHECK_EQ(rnc_air_rx_frame(&rx, f1, n1, 20000010u, out), 400);

  /* a header-only frame (an empty body) and a short first half change nothing */
  tiny[0] = 0x41;
  rnc_air_rx_init(&rx, 5000000u, 10000000u);
  CHECK_EQ(rnc_air_rx_frame(&rx, f0, n0, 0, out), 0);
  CHECK_EQ(rnc_air_rx_frame(&rx, tiny, 1, 10, out), 0);
  CHECK_EQ(rx.pending_seq, 4);
  CHECK_EQ(rnc_air_rx_frame(&rx, f1, n1, 20, out), 400);
  {
    uint8_t shortfirst[100];
    shortfirst[0] = 0x61;
    memset(shortfirst + 1, 0xAA, 99);
    rnc_air_rx_init(&rx, 5000000u, 10000000u);
    CHECK_EQ(rnc_air_rx_frame(&rx, shortfirst, 100, 0, out), 0);
    CHECK_EQ(rx.pending_seq, RNC_AIR_SEQ_NONE);
  }
  /* oversize or empty frames are rejected */
  CHECK_EQ(rnc_air_rx_frame(&rx, f0, 0, 0, out), 0);
  CHECK_EQ(rnc_air_rx_frame(&rx, f0, 256, 0, out), 0);
  /* bits 3..1 of the header are ignored on receive */
  {
    uint8_t g[20];
    memset(g, 0x55, sizeof(g));
    g[0] = 0xAE; /* sequence A, junk in the reserved bits, split flag clear */
    rnc_air_rx_init(&rx, 5000000u, 10000000u);
    CHECK_EQ(rnc_air_rx_frame(&rx, g, 20, 0, out), 19);
  }
}

/* A receiver written only from the facts about the stock firmware: header byte with the
 * split flag in bit 0 and the sequence in the high nibble; one pending sequence number. Used
 * to check that, for well formed traffic, ours delivers exactly what that rule delivers. */
typedef struct {
  int seq; /* -1 unset */
  uint8_t buf[600];
  size_t len;
} stock_rx;
static size_t stock_feed(stock_rx *s, const uint8_t *frame, size_t n, uint8_t *out) {
  unsigned seq = frame[0] >> 4;
  int split = frame[0] & 1;
  size_t body = n - 1;
  if (split && s->seq < 0) {
    s->len = 0;
    s->seq = (int)seq;
    memcpy(s->buf, frame + 1, body);
    s->len = body;
  } else if (split && s->seq == (int)seq) {
    memcpy(s->buf + s->len, frame + 1, body);
    s->len += body;
    s->seq = -1;
    memcpy(out, s->buf, s->len);
    return s->len;
  } else if (split) {
    s->len = 0;
    s->seq = (int)seq;
    memcpy(s->buf, frame + 1, body);
    s->len = body;
  } else {
    s->seq = -1;
    s->len = 0;
    memcpy(out, frame + 1, body);
    return body;
  }
  return 0;
}

static void test_air_differential(void) {
  rnc_air_rx rx;
  stock_rx st;
  uint8_t pkt[508], frame[255], a[508], b[508];
  unsigned iter, both = 0, stock_corrupt = 0, ours_only = 0, ours_wrong_alone = 0, missing = 0;
  rnc_air_rx_init(&rx, 0, 0); /* no extras: timeouts and duplicate windows off */
  rnc_air_rx_set_max(&rx, 500);
  st.seq = -1;
  st.len = 0;
  for (iter = 0; iter < 60000; iter++) {
    size_t n = 1 + rnd() % 500, fn;
    unsigned seq = rnd() & 15u, frames = rnc_air_frames(n), f, sent = 0;
    fill(pkt, n, iter);
    for (f = 0; f < frames; f++) {
      size_t ra, rb;
      int ours_bad, stock_bad;
      if (frames == 2 && rnd() % 5 == 0)
        continue; /* a lost frame, either half */
      sent++;
      fn = rnc_air_build(pkt, n, seq, f, frame);
      ra = rnc_air_rx_frame(&rx, frame, fn, iter * 1000u, a);
      rb = stock_feed(&st, frame, fn, b);
      ours_bad = ra && (ra != n || memcmp(a, pkt, n) || sent != frames);
      stock_bad = rb && (rb != n || memcmp(b, pkt, n) || sent != frames);
      if (stock_bad)
        stock_corrupt++; /* the stock rule delivered a mixture or a truncation */
      if (ours_bad && !stock_bad)
        ours_wrong_alone++;
      if (ra && rb)
        both++;
      else if (ra && !rb)
        ours_only++;
      else if (!ra && rb && !stock_bad)
        missing++; /* the stock rule delivered a good packet and ours did not */
    }
  }
  /* for every packet the stock receiver delivers correctly ours does too; ours never
   * delivers a wrong packet unless the stock receiver does the same (a stray second half
   * glued to a pending first half with the same sequence number: the format has no
   * checksum, Reticulum's own authentication rejects such a packet); and ours delivers
   * more, never less */
  (void)ours_only;
  CHECK_EQ(ours_wrong_alone, 0);
  CHECK_EQ(missing, 0);
  CHECK(both > 20000);
  CHECK(stock_corrupt > 0); /* the scenario really occurs in the generated traffic */
}

/* ---- airtime budget ------------------------------------------------------------------------------ */
static void test_airtime(void) {
  rnc_airtime a;
  uint64_t t = 1000000;
  unsigned i;
  rnc_airtime_init(&a, 100); /* 1 % of an hour: 36 s */
  CHECK_EQ(a.budget_ms, 36000);
  CHECK_EQ(rnc_airtime_allows(&a, t, 1000), 1);
  CHECK_EQ(rnc_airtime_allows(&a, t, 36000), 1);
  CHECK_EQ(rnc_airtime_allows(&a, t, 36001), 2); /* never fits */
  /* use it up in 1 s transmissions spread over a few minutes */
  for (i = 0; i < 36; i++) {
    CHECK_EQ(rnc_airtime_allows(&a, t, 1000), 1);
    rnc_airtime_book(&a, t, 1000);
    t += 5000;
  }
  CHECK_EQ(rnc_airtime_used(&a, t), 36000);
  CHECK_EQ(rnc_airtime_allows(&a, t, 1), 0);
  CHECK_EQ(rnc_airtime_allows(&a, t + 55 * 60000u, 1000), 0);   /* still inside the hour */
  /* it comes back as the minutes expire: the bins are a minute wide and a booking is kept
   * for at least an hour */
  {
    uint64_t first = 1000000, last = 1175000;
    uint64_t gone = (last / 60000u + 61u) * 60000u; /* the minute after the last one is an hour old */
    CHECK_EQ(rnc_airtime_used(&a, gone), 0);
    CHECK_EQ(rnc_airtime_allows(&a, gone, 36000), 1);
    CHECK(rnc_airtime_used(&a, first + 3600000u - 1u) > 0); /* never expires early */
    CHECK(rnc_airtime_used(&a, last + 3600000u - 1u) > 0);
  }
  /* a smaller budget, and a zero is not "unlimited" */
  rnc_airtime_init(&a, 10); /* 0.1 %: 3.6 s */
  CHECK_EQ(a.budget_ms, 3600);
  rnc_airtime_init(&a, 0);
  CHECK(a.budget_ms > 0 && a.budget_ms < 400);
  rnc_airtime_init(&a, 10000); /* 100 % */
  CHECK_EQ(a.budget_ms, 3600000);
  /* the limiter in steady state: sending as fast as allowed never exceeds the budget in any
   * window of an hour */
  {
    uint64_t sent_total = 0, now = 0, step;
    unsigned sent_packets = 0, denied = 0;
    rnc_airtime_init(&a, 100);
    for (step = 0; step < 5u * 3600u * 100u; step++) { /* 5 hours in 10 ms steps */
      now = step * 10u;
      if (rnc_airtime_allows(&a, now, 1500) == 1) {
        rnc_airtime_book(&a, now, 1500);
        sent_total += 1500;
        sent_packets++;
      } else {
        denied++;
      }
      if (rnc_airtime_used(&a, now) > a.budget_ms) {
        failures++;
        break;
      }
    }
    /* 5 hours at 1 %: at most 180 s plus the first window's slack */
    CHECK(sent_total <= 5u * 36000u + 36000u);
    CHECK(sent_total >= 4u * 36000u);
    CHECK(denied > 0 && sent_packets > 100);
  }
}

/* ---- CSMA -------------------------------------------------------------------------------------------- */
static void test_csma(void) {
  rnc_csma c;
  uint64_t t;
  int go;
  /* slot: 12 symbols, between 24 and 100 ms; SF7 125k: 12 x 1.024 = 12 ms -> 24 */
  rnc_csma_init(&c, 1024, 0);
  CHECK_EQ(c.slot_ms, 24);
  CHECK_EQ(c.difs_ms, 48);
  rnc_csma_init(&c, 1024, 1);
  CHECK_EQ(c.slot_ms, 6); /* fast: the lower minimum applies only below the limit */
  rnc_csma_init(&c, 16384, 0); /* 12 x 16.4 = 196 ms -> capped */
  CHECK_EQ(c.slot_ms, 100);
  rnc_csma_init(&c, 4096, 0); /* 49 ms */
  CHECK_EQ(c.slot_ms, 49);
  rnc_csma_init(&c, 4096, 0);

  /* free channel, zero backoff draw: transmits after exactly the DIFS (98 ms) */
  rnc_csma_begin(&c);
  go = 0;
  for (t = 1000; t < 1200 && !go; t++)
    go = rnc_csma_step(&c, t, 0, 0);
  CHECK(go);
  CHECK_EQ(t - 1 - 1000, 98);

  /* a busy channel restarts the DIFS and counts as a deferral; the backoff is frozen */
  rnc_csma_begin(&c);
  CHECK_EQ(rnc_csma_step(&c, 0, 0, 14), 0);
  CHECK_EQ(rnc_csma_step(&c, 98, 0, 14), 0);    /* DIFS over: the countdown of 14 slots starts */
  CHECK_EQ(rnc_csma_step(&c, 500, 0, 14), 0);   /* 402 ms of 686 counted */
  CHECK_EQ(rnc_csma_step(&c, 501, 1, 14), 0);   /* busy */
  CHECK_EQ(c.deferrals, 1);
  CHECK_EQ(rnc_csma_step(&c, 900, 1, 14), 0);   /* still the same busy period */
  CHECK_EQ(c.deferrals, 1);
  CHECK_EQ(rnc_csma_step(&c, 901, 0, 14), 0);   /* free again: DIFS from 901 */
  CHECK_EQ(rnc_csma_step(&c, 998, 0, 14), 0);
  CHECK_EQ(rnc_csma_step(&c, 999, 0, 14), 0);   /* DIFS over: resumes with 284 ms to go */
  CHECK_EQ(rnc_csma_step(&c, 1282, 0, 14), 0);
  CHECK_EQ(rnc_csma_step(&c, 1283, 0, 14), 1);

  /* the contention window doubles after an interruption: draws now span 0..29 slots */
  rnc_csma_begin(&c);
  CHECK_EQ(rnc_csma_step(&c, 0, 1, 0), 0);
  CHECK_EQ(c.attempts, 1);
  CHECK_EQ(rnc_csma_step(&c, 10, 0, 0), 0);
  CHECK_EQ(rnc_csma_step(&c, 60, 0, 0), 0);
  CHECK_EQ(rnc_csma_step(&c, 108, 0, 29), 0); /* the DIFS ends; 29 slots (= 1421 ms) drawn */
  CHECK_EQ(rnc_csma_step(&c, 108 + 1420, 0, 29), 0);
  CHECK_EQ(rnc_csma_step(&c, 108 + 1421, 0, 29), 1);
}

/* ---- configuration ---------------------------------------------------------------------------------------- */
static void test_cfg(void) {
  rnc_lora_cfg c;
  char out[256];
  rnc_lora_cfg_init(&c);
  /* nothing is set: the radio must not run, whatever the mode */
  CHECK(!rnc_lora_cfg_ready(&c));
  CHECK_EQ(c.mode, RNC_LORA_MODE_OFF);
  CHECK_EQ(c.airtime, 100); /* the only default: 1 percent */
  CHECK_EQ(rnc_lora_cfg_set(&c, "mode", "leaf"), 0);
  CHECK(!rnc_lora_cfg_ready(&c));
  CHECK_EQ(rnc_lora_cfg_set(&c, "freq", "868.1"), 0);
  CHECK_EQ(c.freq_hz, 868100000);
  CHECK(!rnc_lora_cfg_ready(&c));
  CHECK_EQ(rnc_lora_cfg_set(&c, "bw", "125"), 0);
  CHECK_EQ(c.bw_hz, 125000);
  CHECK_EQ(rnc_lora_cfg_set(&c, "sf", "8"), 0);
  CHECK_EQ(rnc_lora_cfg_set(&c, "cr", "4/5"), 0);
  CHECK_EQ(c.cr, 5);
  CHECK(!rnc_lora_cfg_ready(&c)); /* the power is still missing */
  CHECK_EQ(rnc_lora_cfg_set(&c, "txp", "0"), 0); /* zero dBm is a deliberate value */
  CHECK(rnc_lora_cfg_ready(&c));
  CHECK_EQ(rnc_lora_cfg_set(&c, "mode", "off"), 0);
  CHECK(!rnc_lora_cfg_ready(&c));
  CHECK_EQ(rnc_lora_cfg_set(&c, "mode", "gateway"), 0);
  CHECK(rnc_lora_cfg_ready(&c));
  /* refused values change nothing */
  CHECK_EQ(rnc_lora_cfg_set(&c, "freq", "12"), -1);
  CHECK_EQ(rnc_lora_cfg_set(&c, "freq", "2400.0"), -1);
  CHECK_EQ(rnc_lora_cfg_set(&c, "freq", "868.1x"), -1);
  CHECK_EQ(rnc_lora_cfg_set(&c, "bw", "100"), -1);
  CHECK_EQ(rnc_lora_cfg_set(&c, "bw", "125001"), -1);
  CHECK_EQ(rnc_lora_cfg_set(&c, "sf", "4"), -1);
  CHECK_EQ(rnc_lora_cfg_set(&c, "sf", "13"), -1);
  CHECK_EQ(rnc_lora_cfg_set(&c, "cr", "9"), -1);
  CHECK_EQ(rnc_lora_cfg_set(&c, "cr", "4"), -1);
  CHECK_EQ(rnc_lora_cfg_set(&c, "txp", "23"), -1);
  CHECK_EQ(rnc_lora_cfg_set(&c, "txp", "-10"), -1);
  CHECK_EQ(rnc_lora_cfg_set(&c, "txp", "x"), -1);
  CHECK_EQ(rnc_lora_cfg_set(&c, "airtime", "0"), -1);
  CHECK_EQ(rnc_lora_cfg_set(&c, "airtime", "101"), -1);
  CHECK_EQ(rnc_lora_cfg_set(&c, "mode", "on"), -1);
  CHECK_EQ(rnc_lora_cfg_set(&c, "nope", "1"), -1);
  CHECK_EQ(c.freq_hz, 868100000);
  CHECK_EQ(c.sf, 8);
  CHECK_EQ(rnc_lora_cfg_set(&c, "txp", "-9"), 0);
  CHECK_EQ(c.txp_dbm, -9);
  CHECK_EQ(rnc_lora_cfg_set(&c, "txp", "22"), 0);
  CHECK_EQ(rnc_lora_cfg_set(&c, "airtime", "0.5"), 0);
  CHECK_EQ(c.airtime, 50);
  CHECK_EQ(rnc_lora_cfg_set(&c, "airtime", "10"), 0);
  CHECK_EQ(c.airtime, 1000);
  CHECK_EQ(rnc_lora_cfg_set(&c, "airtime", "100"), 0);
  CHECK_EQ(c.airtime, 10000);
  CHECK_EQ(rnc_lora_cfg_set(&c, "bw", "62.5"), 0);
  CHECK_EQ(c.bw_hz, 62500);
  CHECK_EQ(rnc_lora_cfg_set(&c, "bw", "7.8"), 0);
  CHECK_EQ(c.bw_hz, 7800);
  CHECK_EQ(rnc_lora_cfg_set(&c, "bw", "500000"), 0);
  CHECK_EQ(c.bw_hz, 500000);
  CHECK_EQ(rnc_lora_cfg_set(&c, "freq", "915000000"), 0);
  CHECK_EQ(c.freq_hz, 915000000);
  /* printing */
  rnc_lora_cfg_get(&c, "freq", out, sizeof(out));
  CHECK(!strcmp(out, "lora.freq=915000000"));
  rnc_lora_cfg_get(&c, "airtime", out, sizeof(out));
  CHECK(!strcmp(out, "lora.airtime=100.00"));
  rnc_lora_cfg_init(&c);
  rnc_lora_cfg_get(&c, "txp", out, sizeof(out));
  CHECK(!strcmp(out, "lora.txp=(not set)"));
  rnc_lora_cfg_get(&c, NULL, out, sizeof(out));
  CHECK(strstr(out, "lora.mode=off") && strstr(out, "lora.freq=(not set)") && strstr(out, "lora.airtime=1.00"));
  rnc_lora_cfg_get(&c, "bogus", out, sizeof(out));
  CHECK(strstr(out, "error"));
}

int main(void) {
  test_toa();
  test_ldro();
  test_bitrate_and_preamble();
  test_air_layout();
  test_air_roundtrip();
  test_air_receive_rules();
  test_air_differential();
  test_airtime();
  test_csma();
  test_cfg();
  if (failures) {
    fprintf(stderr, "test_radio_core: %d failure(s)\n", failures);
    return 1;
  }
  puts("test_radio_core: all checks passed");
  return 0;
}
