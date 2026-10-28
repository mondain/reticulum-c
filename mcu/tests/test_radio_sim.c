/* Tests of the LoRa interface (framing, CSMA, airtime budget) on simulated boards: radios
 * modelled at command/register level on a shared medium with configurable loss,
 * collisions and hidden nodes. Boards of both chip families exchange packets of every size
 * up to the Reticulum MTU, including the ones that need the two-frame split.
 *
 * LIMIT: simulation with models written by the author of the drivers; it checks logic and
 * consistency, not the behaviour of real radios on a real channel. */
#include "../radio/rnc_radio.h"
#include "radio/sim_board.h"
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

/* advances the world: every board is stepped every `step_ms` of simulated time */
static void pump(sim_medium *m, sim_board **boards, unsigned n, unsigned ms, unsigned step_ms) {
  unsigned t, i;
  for (t = 0; t < ms; t += step_ms) {
    m->now_us += (uint64_t)step_ms * 1000u;
    sim_medium_advance(m);
    for (i = 0; i < n; i++)
      rnc_lora_if_step(&boards[i]->li, m->now_us);
  }
}

static void fill(uint8_t *p, size_t n, unsigned seed) {
  size_t i;
  for (i = 0; i < n; i++)
    p[i] = (uint8_t)(i * 31u + seed * 7u + (i >> 4));
}

/* send one packet and wait for it at the other end */
static size_t transfer(sim_medium *m, sim_board **boards, unsigned n, sim_board *from, sim_board *to,
                       const uint8_t *pkt, size_t size, uint8_t *got, unsigned wait_ms) {
  unsigned t;
  size_t r;
  if (rnc_lora_if_send(&from->li, pkt, size, m->now_us) != 0)
    return 0;
  for (t = 0; t < wait_ms; t += 2) {
    pump(m, boards, n, 2, 2);
    r = rnc_lora_if_recv(&to->li, got, 508);
    if (r)
      return r;
  }
  return 0;
}

static void test_sizes_between_chips(void) {
  static const size_t sizes[] = {1, 2, 100, 253, 254, 255, 256, 257, 400, 450, 499, 500};
  static const int chips[] = {1262, 1276, 1261};
  unsigned ci, si, k;
  for (ci = 0; ci < 3; ci++) {
    sim_medium med;
    sim_board a, b;
    sim_board *bs[2];
    rnc_lora_params p = prm(125000, 8, 14);
    uint8_t pkt[508], got[508];
    uint32_t air_logged = 0;
    sim_medium_init(&med, 11);
    sim_board_init(&a, &med, 1262, 1, 100);
    sim_board_init(&b, &med, chips[ci], 2, 100);
    bs[0] = &a;
    bs[1] = &b;
    sim_link_all(&med, 100);
    CHECK_EQ(sim_board_start(&a, &p), 0);
    CHECK_EQ(sim_board_start(&b, &p), 0);
    pump(&med, bs, 2, 50, 1);
    for (si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
      size_t n = sizes[si];
      uint32_t before = med.log_count;
      fill(pkt, n, (unsigned)n);
      memset(got, 0, sizeof(got));
      CHECK_EQ(transfer(&med, bs, 2, &a, &b, pkt, n, got, 8000), n);
      CHECK(!memcmp(pkt, got, n));
      /* the frames on the air: one up to 254 bytes, else two of 255 and the rest */
      {
        uint32_t frames = med.log_count - before;
        CHECK_EQ(frames, n > 254 ? 2 : 1);
        if (frames == 2 && before + 1 < 256) {
          CHECK_EQ(med.log_len[before], 255);
          CHECK_EQ(med.log_len[before + 1], n - 254 + 1);
          CHECK_EQ(med.log_first[before] & 1, 1);
          CHECK_EQ(med.log_first[before], med.log_first[before + 1]);
        } else if (frames == 1 && before < 256) {
          CHECK_EQ(med.log_len[before], n + 1);
          CHECK_EQ(med.log_first[before] & 0x0F, 0);
        }
        air_logged += frames;
      }
      /* and back */
      memset(got, 0, sizeof(got));
      CHECK_EQ(transfer(&med, bs, 2, &b, &a, pkt, n, got, 8000), n);
      CHECK(!memcmp(pkt, got, n));
    }
    CHECK(air_logged >= 12);
    CHECK_EQ(sim_board_violations(&a), 0);
    CHECK_EQ(sim_board_violations(&b), 0);
    CHECK(med.max_frame <= 255);
    CHECK_EQ(a.li.stats.tx_failures + b.li.stats.tx_failures, 0);
    /* the sequence number changes from packet to packet */
    {
      unsigned changed = 0;
      for (k = 1; k < med.log_count && k < 256; k++)
        if ((med.log_first[k] >> 4) != (med.log_first[k - 1] >> 4))
          changed++;
      CHECK(changed >= 6);
    }
  }
}

static void test_other_modem_settings(void) {
  static const struct { unsigned bw, sf; int chip; } cfg[] = {
      {500000, 5, 1262}, {250000, 7, 1276}, {125000, 12, 1262}, {62500, 10, 1276}, {125000, 11, 1262},
      {31250, 9, 1276}, {250000, 12, 1262}, {500000, 12, 1276}};
  unsigned k;
  for (k = 0; k < sizeof(cfg) / sizeof(cfg[0]); k++) {
    sim_medium med;
    sim_board a, b;
    sim_board *bs[2];
    rnc_lora_params p = prm(cfg[k].bw, cfg[k].sf, 14);
    uint8_t pkt[508], got[508];
    size_t n = 300;
    sim_medium_init(&med, 11);
    sim_board_init(&a, &med, 1262, 1, 10000);
    sim_board_init(&b, &med, cfg[k].chip, 2, 10000);
    bs[0] = &a;
    bs[1] = &b;
    sim_link_all(&med, 90);
    if (cfg[k].chip == 1276 && cfg[k].sf < 7) {
      continue;
    }
    CHECK_EQ(sim_board_start(&a, &p), 0);
    CHECK_EQ(sim_board_start(&b, &p), 0);
    pump(&med, bs, 2, 100, 1);
    fill(pkt, n, k);
    CHECK_EQ(transfer(&med, bs, 2, &a, &b, pkt, n, got, 120000), n);
    CHECK(!memcmp(pkt, got, n));
    CHECK_EQ(transfer(&med, bs, 2, &b, &a, pkt, n, got, 120000), n);
    CHECK_EQ(sim_board_violations(&a) + sim_board_violations(&b), 0);
  }
}

static void test_loss(void) {
  sim_medium med;
  sim_board a, b;
  sim_board *bs[2];
  rnc_lora_params p = prm(250000, 7, 14);
  uint8_t pkt[508], got[508];
  unsigned i, delivered = 0, wrong = 0;
  sim_medium_init(&med, 21);
  sim_board_init(&a, &med, 1262, 1, 10000);
  sim_board_init(&b, &med, 1276, 2, 10000);
  bs[0] = &a;
  bs[1] = &b;
  sim_link_all(&med, 100);
  sim_link_drop(&med, a.radio_id, b.radio_id, 250); /* a quarter of all frames lost */
  CHECK_EQ(sim_board_start(&a, &p), 0);
  CHECK_EQ(sim_board_start(&b, &p), 0);
  pump(&med, bs, 2, 50, 1);
  for (i = 0; i < 300; i++) {
    size_t r;
    fill(pkt, 400, i);
    rnc_lora_if_send(&a.li, pkt, 400, med.now_us);
    pump(&med, bs, 2, 1500, 2);
    r = rnc_lora_if_recv(&b.li, got, sizeof(got));
    if (r) {
      delivered++;
      if (r != 400 || memcmp(got, pkt, 400))
      { wrong++; if (wrong < 4) { size_t q; for (q = 0; q < 400 && got[q] == pkt[q]; q++) { } fprintf(stderr, "wrong: i=%u r=%zu first diff at %zu\n", i, r, q); } }
    }
  }
  /* each 400 byte packet needs both frames: 0.75^2 = 56 % */
  CHECK(delivered > 120 && delivered < 220);
  CHECK_EQ(wrong, 0);
  CHECK(b.li.air.dropped_orphans + b.li.air.dropped_expired + b.li.air.dropped_bad +
            b.li.air.restarts > 0);
  CHECK(med.lost_random > 100);
  CHECK_EQ(sim_board_violations(&a) + sim_board_violations(&b), 0);
}

static void test_collision(void) {
  sim_medium med;
  sim_board a, b, c;
  sim_board *bs[3];
  rnc_lora_params p = prm(125000, 7, 14);
  uint8_t pkt_a[100], pkt_c[100], got[508];
  size_t r;
  sim_medium_init(&med, 31);
  sim_board_init(&a, &med, 1262, 1, 10000);
  sim_board_init(&b, &med, 1262, 2, 10000);
  sim_board_init(&c, &med, 1276, 3, 10000);
  bs[0] = &a;
  bs[1] = &b;
  bs[2] = &c;
  sim_link_all(&med, 100);
  CHECK_EQ(sim_board_start(&a, &p), 0);
  CHECK_EQ(sim_board_start(&b, &p), 0);
  CHECK_EQ(sim_board_start(&c, &p), 0);
  pump(&med, bs, 3, 100, 1);
  fill(pkt_a, 100, 1);
  fill(pkt_c, 100, 2);
  /* identical backoff draws: both transmit at the same instant; B hears neither */
  a.use_fixed = c.use_fixed = 1;
  a.fixed_random = c.fixed_random = 3;
  rnc_lora_if_send(&a.li, pkt_a, 100, med.now_us);
  rnc_lora_if_send(&c.li, pkt_c, 100, med.now_us);
  pump(&med, bs, 3, 2000, 1);
  CHECK(med.lost_collision >= 1);
  CHECK(b.li.stats.rx_crc_errors >= 1);
  CHECK_EQ(rnc_lora_if_recv(&b.li, got, sizeof(got)), 0);
  /* with different draws the CSMA keeps them apart and B hears both (the quieter one waits) */
  a.use_fixed = c.use_fixed = 0;
  med.lost_collision = 0;
  rnc_lora_if_send(&a.li, pkt_a, 100, med.now_us);
  rnc_lora_if_send(&c.li, pkt_c, 100, med.now_us);
  {
    unsigned got_a = 0, got_c = 0, t;
    for (t = 0; t < 6000; t += 1) {
      pump(&med, bs, 3, 1, 1);
      r = rnc_lora_if_recv(&b.li, got, sizeof(got));
      if (r == 100 && !memcmp(got, pkt_a, 100))
        got_a++;
      if (r == 100 && !memcmp(got, pkt_c, 100))
        got_c++;
    }
    CHECK_EQ(got_a, 1);
    CHECK_EQ(got_c, 1);
  }
  CHECK_EQ(med.lost_collision, 0);
  CHECK(a.li.stats.deferrals + c.li.stats.deferrals >= 1);
  CHECK_EQ(sim_board_violations(&a) + sim_board_violations(&b) + sim_board_violations(&c), 0);
}

/* the hidden node: A and C cannot hear each other, both reach B. CSMA cannot help them. */
static unsigned run_topology(int hidden, unsigned *collisions, unsigned seed) {
  sim_medium med;
  sim_board a, b, c;
  sim_board *bs[3];
  rnc_lora_params p = prm(125000, 7, 14);
  uint8_t pkt[100], got[508];
  unsigned i, t, received = 0;
  sim_medium_init(&med, seed);
  sim_board_init(&a, &med, 1262, seed * 3 + 1, 10000);
  sim_board_init(&b, &med, 1262, seed * 3 + 2, 10000);
  sim_board_init(&c, &med, 1276, seed * 3 + 3, 10000);
  bs[0] = &a;
  bs[1] = &b;
  bs[2] = &c;
  sim_link(&med, a.radio_id, b.radio_id, 100);
  sim_link(&med, c.radio_id, b.radio_id, 100);
  if (!hidden)
    sim_link(&med, a.radio_id, c.radio_id, 100);
  sim_board_start(&a, &p);
  sim_board_start(&b, &p);
  sim_board_start(&c, &p);
  pump(&med, bs, 3, 100, 1);
  fill(pkt, 100, 5);
  for (i = 0; i < 60; i++) {
    rnc_lora_if_send(&a.li, pkt, 100, med.now_us);
    rnc_lora_if_send(&c.li, pkt, 100, med.now_us);
    for (t = 0; t < 700; t += 2) { /* 700 ms per round: both packets take 2 x 190 ms */
      pump(&med, bs, 3, 2, 2);
      while (rnc_lora_if_recv(&b.li, got, sizeof(got)))
        received++;
    }
  }
  *collisions = med.lost_collision;
  CHECK_EQ(sim_board_violations(&a) + sim_board_violations(&b) + sim_board_violations(&c), 0);
  return received;
}

static void test_hidden_node(void) {
  unsigned coll_hidden = 0, coll_open = 0, rx_hidden, rx_open, seed, hidden_total = 0, open_total = 0;
  unsigned ch_total = 0, co_total = 0;
  for (seed = 1; seed <= 4; seed++) {
    rx_hidden = run_topology(1, &coll_hidden, seed);
    rx_open = run_topology(0, &coll_open, seed);
    hidden_total += rx_hidden;
    open_total += rx_open;
    ch_total += coll_hidden;
    co_total += coll_open;
  }
  /* with carrier sensing between them the two senders almost never collide; hidden from one
   * another they transmit blindly and lose frames at B */
  CHECK(co_total * 4 <= ch_total || co_total == 0);
  CHECK(ch_total >= 4);
  CHECK(hidden_total < open_total);
  CHECK(open_total >= 4 * 100); /* 4 x 60 x 2 sent: nearly all arrive when they can hear each other */
  fprintf(stderr, "  hidden node: %u received, %u collisions; open: %u received, %u collisions (of 480 sent)\n",
          hidden_total, ch_total, open_total, co_total);
}

static void test_csma_waits_for_the_channel(void) {
  sim_medium med;
  sim_board a, c, d;
  sim_board *bs[3];
  rnc_lora_params p = prm(125000, 8, 14);
  uint8_t pkt[250], got[508];
  int k, started = 0;
  uint64_t c_end = 0, a_start = 0;
  sim_medium_init(&med, 41);
  sim_board_init(&a, &med, 1262, 1, 10000);
  sim_board_init(&c, &med, 1276, 2, 10000);
  sim_board_init(&d, &med, 1262, 3, 10000);
  bs[0] = &a;
  bs[1] = &c;
  bs[2] = &d;
  sim_link_all(&med, 100);
  sim_board_start(&a, &p);
  sim_board_start(&c, &p);
  sim_board_start(&d, &p);
  pump(&med, bs, 3, 100, 1);
  fill(pkt, 250, 1);
  rnc_lora_if_send(&c.li, pkt, 250, med.now_us);
  pump(&med, bs, 3, 300, 1);   /* C is well into its frame (SF8: ~690 ms) */
  rnc_lora_if_send(&a.li, pkt, 100, med.now_us);
  pump(&med, bs, 3, 6000, 1);
  for (k = 0; k < SIM_MAX_TX; k++) {
    const sim_tx *t = &med.tx[k];
    if (!t->len)
      continue;
    if (t->radio == c.radio_id)
      c_end = t->end_us;
    if (t->radio == a.radio_id && t->len == 101) {
      a_start = t->start_us;
      started = 1;
    }
  }
  CHECK(started);
  /* A started after C finished plus the DIFS (two slots: 2 x 24.6 ms at SF8) */
  CHECK(a_start >= c_end + 2u * a.li.csma.slot_ms * 1000u);
  CHECK_EQ(med.lost_collision, 0);
  CHECK(a.li.stats.deferrals >= 1);
  CHECK(rnc_lora_if_recv(&d.li, got, sizeof(got)) > 0);
  CHECK_EQ(sim_board_violations(&a) + sim_board_violations(&c) + sim_board_violations(&d), 0);
}

static void test_airtime_budget(void) {
  sim_medium med;
  sim_board a, b;
  sim_board *bs[2];
  rnc_lora_params p = prm(125000, 7, 14);
  uint8_t pkt[100];
  unsigned minute, sent_attempts = 0, i;
  uint64_t air_at_minute[130], worst = 0, budget_us;
  sim_medium_init(&med, 51);
  sim_board_init(&a, &med, 1262, 1, 50); /* 0.5 % of an hour: 18 s */
  sim_board_init(&b, &med, 1276, 2, 10000);
  bs[0] = &a;
  bs[1] = &b;
  sim_link_all(&med, 100);
  CHECK_EQ(sim_board_start(&a, &p), 0);
  CHECK_EQ(sim_board_start(&b, &p), 0);
  budget_us = (uint64_t)a.li.budget.budget_ms * 1000u;
  CHECK_EQ(a.li.budget.budget_ms, 18000);
  fill(pkt, 100, 1);
  /* offer far more than the budget for two hours: a 100 byte packet is 0.19 s on air, we
   * try one every 400 ms (about 45 % duty) */
  for (minute = 0; minute < 125; minute++) {
    air_at_minute[minute] = med.air_us[a.radio_id];
    for (i = 0; i < 150; i++) { /* 150 x 400 ms = 60 s */
      sent_attempts++;
      rnc_lora_if_send(&a.li, pkt, 100, med.now_us);
      pump(&med, bs, 2, 400, 4);
      while (rnc_lora_if_recv(&b.li, pkt + 0 * 100, 100) > 0)
        ;
      (void)0;
      fill(pkt, 100, 1);
    }
  }
  /* no window of an hour ever carried more airtime than the budget (plus the frame in
   * flight at the edge of the window: at most one packet) */
  for (minute = 60; minute < 125; minute++) {
    uint64_t w = air_at_minute[minute] - air_at_minute[minute - 60];
    if (w > worst)
      worst = w;
  }
  CHECK(worst <= budget_us + 400000u);
  CHECK(worst >= budget_us / 2u);      /* the limiter lets the allowed airtime through */
  CHECK(a.li.stats.tx_deferred_budget > 0);
  CHECK(a.li.stats.tx_dropped_stale + a.li.stats.tx_dropped_queue > 100);
  CHECK(a.li.budget.denied > 0);
  CHECK(sent_attempts > 18000);
  CHECK_EQ(sim_board_violations(&a) + sim_board_violations(&b), 0);
  fprintf(stderr, "  airtime: busiest hour %.1f s of %.1f s allowed; %u packets sent, %u dropped (queue/stale)\n",
          (double)worst / 1e6, (double)budget_us / 1e6, (unsigned)a.li.stats.tx_packets,
          (unsigned)(a.li.stats.tx_dropped_stale + a.li.stats.tx_dropped_queue));
}

/* the budget is checked again at the moment the channel is won, not only when the packet
 * started waiting for it: here the airtime is used up (by something else on the same budget)
 * while the packet waits behind another station's long frame */
static void test_budget_checked_at_transmit_time(void) {
  sim_medium med;
  sim_board a, c;
  sim_board *bs[2];
  rnc_lora_params p = prm(125000, 9, 14);
  uint8_t pkt[200];
  sim_medium_init(&med, 91);
  sim_board_init(&a, &med, 1262, 1, 100);
  sim_board_init(&c, &med, 1276, 2, 10000);
  bs[0] = &a;
  bs[1] = &c;
  sim_link_all(&med, 100);
  CHECK_EQ(sim_board_start(&a, &p), 0);
  CHECK_EQ(sim_board_start(&c, &p), 0);
  pump(&med, bs, 2, 50, 1);
  fill(pkt, 200, 3);
  rnc_lora_if_send(&c.li, pkt, 200, med.now_us); /* a long frame (about 1.1 s) */
  pump(&med, bs, 2, 300, 1);
  rnc_lora_if_send(&a.li, pkt, 100, med.now_us);
  pump(&med, bs, 2, 200, 1);                     /* A is waiting for the channel */
  CHECK_EQ(a.li.state, 2);
  rnc_airtime_book(&a.li.budget, med.now_us / 1000u, 35990u); /* the budget is gone */
  pump(&med, bs, 2, 4000, 1);
  CHECK_EQ(a.li.stats.tx_packets, 0);
  CHECK_EQ(med.air_us[a.radio_id], 0);
  CHECK(a.li.q_count == 1);
  CHECK_EQ(sim_board_violations(&a) + sim_board_violations(&c), 0);
}

static void test_budget_edge_cases(void) {
  sim_medium med;
  sim_board a, b;
  sim_board *bs[2];
  rnc_lora_params p = prm(125000, 12, 14);
  uint8_t pkt[508];
  sim_medium_init(&med, 61);
  sim_board_init(&a, &med, 1262, 1, 1); /* 0.01 % of an hour: 360 ms */
  sim_board_init(&b, &med, 1262, 2, 10000);
  bs[0] = &a;
  bs[1] = &b;
  sim_link_all(&med, 100);
  CHECK_EQ(sim_board_start(&a, &p), 0);
  CHECK_EQ(sim_board_start(&b, &p), 0);
  fill(pkt, 508, 1);
  /* a packet longer than the whole budget can never be sent: dropped, not retried forever */
  CHECK_EQ(rnc_lora_if_send(&a.li, pkt, 500, med.now_us), 0);
  pump(&med, bs, 2, 3000, 2);
  CHECK_EQ(a.li.stats.tx_dropped_budget, 1);
  CHECK_EQ(a.li.q_count, 0);
  CHECK_EQ(a.li.stats.tx_packets, 0);
  CHECK_EQ(med.frames_sent, 0);
  /* queue overflow: the queue holds three packets */
  {
    unsigned i, accepted = 0;
    sim_medium med2;
    sim_board c, d;
    sim_board *bs2[2];
    rnc_lora_params q = prm(125000, 7, 14);
    sim_medium_init(&med2, 62);
    sim_board_init(&c, &med2, 1262, 1, 10000);
    sim_board_init(&d, &med2, 1262, 2, 10000);
    bs2[0] = &c;
    bs2[1] = &d;
    sim_link_all(&med2, 100);
    sim_board_start(&c, &q);
    sim_board_start(&d, &q);
    pump(&med2, bs2, 2, 50, 1);
    for (i = 0; i < 10; i++)
      if (rnc_lora_if_send(&c.li, pkt, 100, med2.now_us) == 0)
        accepted++;
    CHECK_EQ(accepted, RNC_LORA_TXQ);
    CHECK_EQ(c.li.stats.tx_dropped_queue, 10 - RNC_LORA_TXQ);
    /* oversized and empty packets are refused */
    CHECK_EQ(rnc_lora_if_send(&c.li, pkt, 509, med2.now_us), -1);
    CHECK_EQ(rnc_lora_if_send(&c.li, pkt, 0, med2.now_us), -1);
    pump(&med2, bs2, 2, 4000, 2);
    CHECK_EQ(c.li.stats.tx_packets, RNC_LORA_TXQ);
    {
      unsigned got = 0;
      uint8_t buf[508];
      /* the receiver holds one packet until it is collected: the others are counted as overrun */
      while (rnc_lora_if_recv(&d.li, buf, sizeof(buf)))
        got++;
      CHECK(got >= 1);
      CHECK_EQ(d.li.stats.rx_packets + d.li.stats.rx_overrun, RNC_LORA_TXQ);
    }
  }
}

/* REGULATORY GATE: the radio is not touched until the mode is on and every transmit setting
 * was set explicitly; nothing is ever transmitted or received before that */
static uint32_t gate_random(void *c) {
  (void)c;
  return 4;
}
static void test_regulatory_gate(void) {
  static const char *const missing[] = {"freq", "bw", "sf", "cr", "txp"};
  static const char *const values[] = {"868.1", "125", "8", "5", "14"};
  unsigned skip, k;
  rnc_board board;
  memset(&board, 0, sizeof(board));
  board.id = "test";
  board.chip = RNC_BOARD_SX1262;
  board.sx126x.chip = 1262;
  board.sx126x.tcxo_code = RNC_SX126X_TCXO_1V8;
  board.sx126x.dio2_rf_switch = 1;
  board.supported = 1;
  board.max_txp_dbm = 22;
  for (skip = 0; skip <= 6; skip++) { /* 0..4: one setting missing; 5: mode off; 6: all set */
    sim_medium med;
    sim_board other;
    sx126x_model chip;
    rnc_radio radio;
    rnc_lora_cfg cfg;
    uint8_t pkt[50];
    int rc;
    sim_medium_init(&med, 100 + skip);
    sx126x_model_init(&chip, &med, 1262, 1, 1);
    sim_board_init(&other, &med, 1262, 7, 10000);
    sim_link_all(&med, 90);
    rnc_lora_cfg_init(&cfg);
    for (k = 0; k < 5; k++)
      if (k != skip)
        CHECK_EQ(rnc_lora_cfg_set(&cfg, missing[k], values[k]), 0);
    CHECK_EQ(rnc_lora_cfg_set(&cfg, "mode", skip == 5 ? "off" : "leaf"), 0);
    memset(pkt, 1, sizeof(pkt));
    rc = rnc_radio_setup(&radio, &board, &chip.hal, &cfg, gate_random, NULL);
    if (skip == 6) {
      CHECK_EQ(rc, RNC_RADIO_OK);
      CHECK(rnc_lora_if_up(&radio.li));
      CHECK(chip.commands > 0);
    } else {
      CHECK_EQ(rc, skip == 5 ? RNC_RADIO_OFF : RNC_RADIO_NOT_CONFIGURED);
      CHECK(!rnc_lora_if_up(&radio.li));
      CHECK_EQ(chip.commands, 0);                     /* the chip was not spoken to at all */
      CHECK_EQ(rnc_lora_if_send(&radio.li, pkt, 50, 0), -1);
      {
        unsigned t;
        for (t = 0; t < 5000; t++) {
          med.now_us += 1000;
          sim_medium_advance(&med);
          rnc_lora_if_step(&radio.li, med.now_us);
        }
      }
      CHECK_EQ(chip.commands, 0);
      CHECK_EQ(med.frames_sent, 0);
      CHECK_EQ(chip.mode, 2);                         /* still in its reset state: nothing sent */
    }
    CHECK(rnc_radio_status_text(rc)[0] != 0);
  }
  /* the board limits */
  {
    sim_medium med;
    sx126x_model chip;
    rnc_radio radio;
    rnc_lora_cfg cfg;
    unsigned k;
    sim_medium_init(&med, 120);
    sx126x_model_init(&chip, &med, 1262, 1, 1);
    rnc_lora_cfg_init(&cfg);
    for (k = 0; k < 5; k++)
      CHECK_EQ(rnc_lora_cfg_set(&cfg, missing[k], values[k]), 0);
    CHECK_EQ(rnc_lora_cfg_set(&cfg, "mode", "gateway"), 0);
    board.max_txp_dbm = 10;
    CHECK_EQ(rnc_radio_setup(&radio, &board, &chip.hal, &cfg, gate_random, NULL), RNC_RADIO_BAD_SETTINGS);
    board.max_txp_dbm = 22;
    board.supported = 0;
    CHECK_EQ(rnc_radio_setup(&radio, &board, &chip.hal, &cfg, gate_random, NULL), RNC_RADIO_BOARD_UNSUPPORTED);
    board.supported = 1;
    CHECK_EQ(chip.commands, 0);
    CHECK_EQ(rnc_lora_cfg_set(&cfg, "freq", "880.0"), 0); /* between the SX126x calibration bands */
    CHECK_EQ(rnc_radio_setup(&radio, &board, &chip.hal, &cfg, gate_random, NULL), RNC_RADIO_BAD_SETTINGS);
    CHECK_EQ(radio.li.retry_us, 0);                       /* no pointless retries */
    CHECK_EQ(rnc_lora_cfg_set(&cfg, "freq", "868.1"), 0);
    chip.absent = 1;                                      /* a valid setup, but the chip is dead */
    CHECK_EQ(rnc_radio_setup(&radio, &board, &chip.hal, &cfg, gate_random, NULL), RNC_RADIO_CHIP_FAILED);
    CHECK(radio.li.retry_us != 0);
  }
  /* the board table */
  {
    unsigned i, j, supported = 0;
    CHECK(rnc_board_count() >= 8);
    for (i = 0; i < rnc_board_count(); i++) {
      const rnc_board *b = rnc_board_at(i);
      CHECK(b && b->id && b->name);
      CHECK(rnc_board_find(b->id) == b);
      for (j = i + 1; j < rnc_board_count(); j++)
        CHECK(strcmp(b->id, rnc_board_at(j)->id) != 0);
      CHECK(b->cs >= 0 && b->sck >= 0 && b->mosi >= 0 && b->miso >= 0 && b->reset >= 0 && b->dio >= 0);
      if (b->chip == RNC_BOARD_SX1262) {
        CHECK(b->busy >= 0);
        CHECK(b->sx126x.chip == 1262);
        CHECK(b->sx126x.tcxo_code >= 0 && b->sx126x.tcxo_code <= RNC_SX126X_TCXO_3V3);
        CHECK(b->max_txp_dbm <= 22);
      } else {
        CHECK(b->chip == RNC_BOARD_SX1276);
        CHECK(b->max_txp_dbm <= 20);
      }
      supported += b->supported;
    }
    CHECK(rnc_board_find("nonexistent") == NULL);
    CHECK(supported >= 7);
    CHECK(rnc_board_find("lilygo_t_beam_supreme") && !rnc_board_find("lilygo_t_beam_supreme")->supported);
  }
}

static void test_init_failure_and_retry(void) {
  sim_medium med;
  sim_board a, b;
  sim_board *bs[2];
  rnc_lora_params p = prm(125000, 7, 14);
  uint8_t pkt[50], got[508];
  sim_medium_init(&med, 71);
  sim_board_init(&a, &med, 1262, 1, 10000);
  sim_board_init(&b, &med, 1262, 2, 10000);
  bs[0] = &a;
  bs[1] = &b;
  sim_link_all(&med, 100);
  a.m126.absent = 1; /* the radio is not on the bus */
  CHECK(sim_board_start(&a, &p) < 0);
  CHECK(!rnc_lora_if_up(&a.li));
  CHECK_EQ(rnc_lora_if_send(&a.li, pkt, 50, med.now_us), -1); /* nothing is queued while down */
  CHECK_EQ(sim_board_start(&b, &p), 0);
  pump(&med, bs, 2, 5000, 5);
  CHECK(!rnc_lora_if_up(&a.li));
  a.m126.absent = 0; /* it comes back */
  pump(&med, bs, 2, 12000, 5);
  CHECK(rnc_lora_if_up(&a.li));
  CHECK(a.li.stats.restarts >= 1);
  fill(pkt, 50, 3);
  CHECK_EQ(transfer(&med, bs, 2, &a, &b, pkt, 50, got, 3000), 50);
  CHECK_EQ(sim_board_violations(&b), 0);
}

static void test_orphan_timeout_on_the_air(void) {
  /* a first half whose second half never comes (the sender stops: here, its packet is lost in
   * the second frame by a dead link for exactly that frame) does not linger or poison the
   * next packet */
  sim_medium med;
  sim_board a, b;
  sim_board *bs[2];
  rnc_lora_params p = prm(250000, 7, 14);
  uint8_t pkt[500], got[508];
  unsigned i, lost_halves = 0, good = 0;
  sim_medium_init(&med, 81);
  sim_board_init(&a, &med, 1262, 1, 10000);
  sim_board_init(&b, &med, 1276, 2, 10000);
  bs[0] = &a;
  bs[1] = &b;
  sim_link_all(&med, 100);
  sim_board_start(&a, &p);
  sim_board_start(&b, &p);
  pump(&med, bs, 2, 50, 1);
  for (i = 0; i < 80; i++) {
    size_t r;
    fill(pkt, 500, i);
    /* every third packet loses its second frame: the link goes quiet for a moment after the
     * first frame ends */
    sim_link_drop(&med, a.radio_id, b.radio_id, 0);
    rnc_lora_if_send(&a.li, pkt, 500, med.now_us);
    if (i % 3 == 0) {
      uint32_t before = med.frames_delivered; /* the first frame has been heard by B */
      while (med.frames_delivered == before)
        pump(&med, bs, 2, 1, 1);
      pump(&med, bs, 2, 1, 1);
      sim_link_drop(&med, a.radio_id, b.radio_id, 1000);
      lost_halves++;
    }
    pump(&med, bs, 2, 2500, 2);
    sim_link_drop(&med, a.radio_id, b.radio_id, 0);
    r = rnc_lora_if_recv(&b.li, got, sizeof(got));
    if (r == 500 && !memcmp(got, pkt, 500))
      good++;
    else
      CHECK_EQ(r, 0);
  }
  CHECK(lost_halves > 20);
  CHECK(good >= 80 - lost_halves - 2 && good <= 80 - lost_halves);
  CHECK(b.li.air.dropped_orphans + b.li.air.restarts + b.li.air.dropped_expired > 0 || lost_halves == 0);
  CHECK_EQ(sim_board_violations(&a) + sim_board_violations(&b), 0);
}

int main(void) {
  test_sizes_between_chips();
  test_other_modem_settings();
  test_loss();
  test_collision();
  test_hidden_node();
  test_csma_waits_for_the_channel();
  test_airtime_budget();
  test_budget_checked_at_transmit_time();
  test_budget_edge_cases();
  test_regulatory_gate();
  test_init_failure_and_retry();
  test_orphan_timeout_on_the_air();
  if (failures) {
    fprintf(stderr, "test_radio_sim: %d failure(s)\n", failures);
    return 1;
  }
  puts("test_radio_sim: all checks passed");
  return 0;
}
