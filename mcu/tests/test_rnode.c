/* Tests of the RNode KISS device side (rnc_rnode): framing, identity commands, radio
 * settings, data path and the boot window helper, against simulated boards.
 *
 * LIMIT: checks the logic against the command set the project's host adapter and the
 * reference RNodeInterface use; it is not a test on real hardware. */
#include "../radio/rnc_rnode.h"
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

#define FEND 0xC0
#define FESC 0xDB
#define TFEND 0xDC
#define TFESC 0xDD

/* feeds `n` bytes and returns what the device wants to send, in `out` */
static size_t exchange(rnc_rnode *rn, const uint8_t *in, size_t n, uint8_t *out, size_t cap) {
  rnc_rnode_feed(rn, in, n, 1000);
  return rnc_rnode_pull(rn, out, cap);
}
#define EXCHANGE(rn, out, ...)                                                 \
  exchange(rn, (const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__}), out, sizeof(out))
#define CHECK_BYTES(out, n, ...)                                               \
  do {                                                                         \
    static const uint8_t want_[] = {__VA_ARGS__};                              \
    CHECK_EQ(n, sizeof(want_));                                                \
    CHECK((n) == sizeof(want_) && !memcmp(out, want_, sizeof(want_)));         \
  } while (0)

static void test_identity_commands(void) {
  rnc_rnode rn;
  uint8_t out[64];
  size_t n;
  rnc_rnode_init(&rn, NULL, 0x70, 0x71, 0x42);
  n = EXCHANGE(&rn, out, FEND, 0x08, 0x73, FEND); /* DETECT */
  CHECK_BYTES(out, n, FEND, 0x08, 0x46, FEND);
  n = EXCHANGE(&rn, out, FEND, 0x50, 0x00, FEND); /* firmware version */
  CHECK_BYTES(out, n, FEND, 0x50, RNC_RNODE_FW_MAJOR, RNC_RNODE_FW_MINOR, FEND);
  CHECK(RNC_RNODE_FW_MAJOR == 1 && RNC_RNODE_FW_MINOR == 74);
  n = EXCHANGE(&rn, out, FEND, 0x48, 0x00, FEND); /* platform */
  CHECK_BYTES(out, n, FEND, 0x48, 0x70, FEND);
  n = EXCHANGE(&rn, out, FEND, 0x49, 0x00, FEND); /* MCU */
  CHECK_BYTES(out, n, FEND, 0x49, 0x71, FEND);
  n = EXCHANGE(&rn, out, FEND, 0x47, 0x00, FEND); /* board */
  CHECK_BYTES(out, n, FEND, 0x47, 0x42, FEND);
  n = EXCHANGE(&rn, out, FEND, 0x08, 0x00, FEND); /* a DETECT without the request byte */
  CHECK_EQ(n, 0);
  n = EXCHANGE(&rn, out, FEND, 0xEE, 0x01, FEND); /* unknown command: ignored */
  CHECK_EQ(n, 0);
}

static void test_escaping(void) {
  rnc_rnode rn;
  uint8_t out[64];
  size_t n;
  rnc_rnode_init(&rn, NULL, 0x70, 0x71, 0xC0); /* a board id that needs escaping */
  n = EXCHANGE(&rn, out, FEND, 0x47, 0x00, FEND);
  CHECK_BYTES(out, n, FEND, 0x47, FESC, TFEND, FEND);
  rnc_rnode_init(&rn, NULL, 0x70, 0x71, 0xDB);
  n = EXCHANGE(&rn, out, FEND, 0x47, 0x00, FEND);
  CHECK_BYTES(out, n, FEND, 0x47, FESC, TFESC, FEND);
  /* an escaped payload byte is decoded on the way in */
  rnc_rnode_init(&rn, NULL, 0x70, 0x71, 0x42);
  n = EXCHANGE(&rn, out, FEND, 0xEE, FESC, TFEND, FESC, TFESC, FEND);
  CHECK_EQ(n, 0);
  CHECK_EQ(rn.stats.last_cmd, 0xEE);
  CHECK_EQ(rn.stats.last_len, 2);
  CHECK_EQ(rn.stats.frames_bad, 0);
}

/* Review Focus 2: malformed input changes nothing and the parser resynchronises */
static void test_malformed_input(void) {
  rnc_rnode rn;
  uint8_t out[64], big[10000];
  size_t n;
  rnc_rnode_init(&rn, NULL, 0x70, 0x71, 0x42);
  n = EXCHANGE(&rn, out, FEND, 0x08, FESC, 0x41, 0x73, FEND); /* bad escape */
  CHECK_EQ(n, 0);
  CHECK_EQ(rn.stats.frames_bad, 1);
  n = EXCHANGE(&rn, out, FEND, 0x08, 0x73, FEND);
  CHECK_BYTES(out, n, FEND, 0x08, 0x46, FEND);
  /* a frame above the largest packet plus header */
  memset(big, 0x55, sizeof(big));
  big[0] = FEND;
  big[1] = 0x08;
  big[601] = FEND;
  n = exchange(&rn, big, 602, out, sizeof(out));
  CHECK_EQ(n, 0);
  CHECK_EQ(rn.stats.frames_bad, 2);
  n = EXCHANGE(&rn, out, FEND, 0x08, 0x73, FEND);
  CHECK_BYTES(out, n, FEND, 0x08, 0x46, FEND);
  /* a flood with no closing delimiter, then a valid frame */
  big[0] = FEND;
  big[1] = 0x08;
  n = exchange(&rn, big, 10000, out, sizeof(out));
  CHECK_EQ(n, 0);
  n = EXCHANGE(&rn, out, FEND, 0x08, 0x73, FEND);
  CHECK_BYTES(out, n, FEND, 0x08, 0x46, FEND);
  /* a setting command with a short payload: no reply, nothing applied */
  n = EXCHANGE(&rn, out, FEND, 0x01, 0x36, FEND);
  CHECK_EQ(n, 0);
  /* bytes outside a frame are ignored */
  n = EXCHANGE(&rn, out, 0x41, 0x42, FEND, 0x08, 0x73, FEND);
  CHECK_BYTES(out, n, FEND, 0x08, 0x46, FEND);
}

/* ---- radio settings (Task 3) ------------------------------------------------------ */

/* builds one KISS frame with escaping */
static size_t kiss(uint8_t *out, uint8_t cmd, const uint8_t *data, size_t n) {
  size_t i, k = 0;
  out[k++] = FEND;
  out[k++] = cmd;
  for (i = 0; i < n; i++) {
    if (data[i] == FEND) {
      out[k++] = FESC;
      out[k++] = TFEND;
    } else if (data[i] == FESC) {
      out[k++] = FESC;
      out[k++] = TFESC;
    } else {
      out[k++] = data[i];
    }
  }
  out[k++] = FEND;
  return k;
}
static size_t put32(uint8_t *b, uint32_t v) {
  b[0] = (uint8_t)(v >> 24);
  b[1] = (uint8_t)(v >> 16);
  b[2] = (uint8_t)(v >> 8);
  b[3] = (uint8_t)v;
  return 4;
}
/* sends one command with its payload and returns the reply frame bytes (without copying
 * them anywhere: `reply` receives them) */
static size_t send_cmd(rnc_rnode *rn, uint8_t cmd, const uint8_t *data, size_t n, uint8_t *reply, size_t cap) {
  uint8_t frame[64];
  size_t k = kiss(frame, cmd, data, n);
  return exchange(rn, frame, k, reply, cap);
}
/* a command whose reply must be the same command with the same payload */
static int echoed(rnc_rnode *rn, uint8_t cmd, const uint8_t *data, size_t n) {
  uint8_t reply[64], want[64];
  size_t r = send_cmd(rn, cmd, data, n, reply, sizeof(reply)), k = kiss(want, cmd, data, n);
  return r == k && !memcmp(reply, want, k);
}
static int silent(rnc_rnode *rn, uint8_t cmd, const uint8_t *data, size_t n) {
  uint8_t reply[64];
  return send_cmd(rn, cmd, data, n, reply, sizeof(reply)) == 0;
}
static int set_u32(rnc_rnode *rn, uint8_t cmd, uint32_t v) {
  uint8_t b[4];
  put32(b, v);
  return echoed(rn, cmd, b, 4);
}
static int set_u8(rnc_rnode *rn, uint8_t cmd, uint8_t v) { return echoed(rn, cmd, &v, 1); }

typedef struct fixture {
  sim_medium med;
  sim_board a;
  rnc_rnode rn;
} fixture;
static void fixture_init(fixture *f, int chip, int sf_min, int txp_max) {
  memset(f, 0, sizeof(*f));
  sim_medium_init(&f->med, 71);
  sim_board_init(&f->a, &f->med, chip, 1, 100);
  rnc_rnode_init(&f->rn, &f->a.li, 0x70, 0x71, 0x42);
  rnc_rnode_set_limits(&f->rn, (uint8_t)sf_min, (int8_t)txp_max);
}
static void configure_all(fixture *f) {
  CHECK(set_u32(&f->rn, 1, 915000000u)); /* the bytes contain 0xC0, so the escaping is used */
  CHECK(set_u32(&f->rn, 2, 125000u));
  CHECK(set_u8(&f->rn, 3, 10));
  CHECK(set_u8(&f->rn, 4, 8));
  CHECK(set_u8(&f->rn, 5, 5));
}

static void test_settings_and_state(void) {
  fixture f;
  fixture_init(&f, 1262, 5, 22);
  CHECK(!rnc_rnode_radio_on(&f.rn));
  /* state on with a parameter missing: no reply, the chip is never touched */
  CHECK(set_u32(&f.rn, 1, 915000000u));
  CHECK(set_u32(&f.rn, 2, 125000u));
  CHECK(set_u8(&f.rn, 3, 10));
  CHECK(set_u8(&f.rn, 4, 8));
  CHECK(silent(&f.rn, 6, (const uint8_t[]){1}, 1));
  CHECK(!rnc_rnode_radio_on(&f.rn));
  CHECK(!rnc_lora_if_up(&f.a.li));
  CHECK_EQ(f.a.m126.have_freq, 0);
  /* the last parameter, then state on */
  CHECK(set_u8(&f.rn, 5, 5));
  CHECK(!rnc_rnode_radio_on(&f.rn)); /* setting alone does not start the radio */
  CHECK(set_u8(&f.rn, 6, 1));
  CHECK(rnc_rnode_radio_on(&f.rn));
  CHECK(rnc_lora_if_up(&f.a.li));
  CHECK_EQ(f.a.li.params.freq_hz, 915000000u);
  CHECK_EQ(f.a.li.params.sf, 8);
  CHECK_EQ(f.a.li.params.txp_dbm, 10);
  /* a changed setting while running is applied at once */
  CHECK(set_u8(&f.rn, 4, 9));
  CHECK(rnc_rnode_radio_on(&f.rn));
  CHECK_EQ(f.a.li.params.sf, 9);
  /* state off stops it */
  CHECK(set_u8(&f.rn, 6, 0));
  CHECK(!rnc_rnode_radio_on(&f.rn));
  CHECK(!rnc_lora_if_up(&f.a.li));
  /* a query reports without changing anything */
  {
    uint8_t reply[16];
    size_t n = send_cmd(&f.rn, 6, (const uint8_t[]){0xFF}, 1, reply, sizeof(reply));
    CHECK_BYTES(reply, n, FEND, 6, 0, FEND); /* the state (0), not the query byte */
  }
}

/* Review Focus 3: values the chip or the protocol cannot take are not applied, not echoed */
static void test_invalid_values(void) {
  fixture f;
  uint8_t b[4];
  fixture_init(&f, 1262, 5, 22);
  configure_all(&f);
  CHECK(set_u8(&f.rn, 6, 1));
  put32(b, 12345u);
  CHECK(silent(&f.rn, 2, b, 4)); /* a bandwidth not in the table */
  put32(b, 136999999u);
  CHECK(silent(&f.rn, 1, b, 4)); /* below the supported band */
  put32(b, 1020000001u);
  CHECK(silent(&f.rn, 1, b, 4));
  CHECK(silent(&f.rn, 4, (const uint8_t[]){4}, 1));  /* spreading factor 4 */
  CHECK(silent(&f.rn, 4, (const uint8_t[]){13}, 1)); /* and 13 */
  CHECK(silent(&f.rn, 5, (const uint8_t[]){9}, 1));  /* coding rate 4/9 */
  CHECK(silent(&f.rn, 5, (const uint8_t[]){4}, 1));
  CHECK(silent(&f.rn, 3, (const uint8_t[]){23}, 1)); /* above the board limit */
  CHECK(silent(&f.rn, 3, (const uint8_t[]){0xF6}, 1)); /* -10 dBm */
  CHECK(silent(&f.rn, 1, (const uint8_t[]){0x36, 0x89}, 2)); /* wrong payload size */
  CHECK_EQ(f.a.li.params.freq_hz, 915000000u);
  CHECK_EQ(f.a.li.params.bw_hz, 125000u);
  CHECK_EQ(f.a.li.params.sf, 8);
  CHECK_EQ(f.a.li.params.cr, 5);
  CHECK_EQ(f.a.li.params.txp_dbm, 10);
  CHECK(rnc_rnode_radio_on(&f.rn));
  /* an SX127x board: spreading factor 5 is not available, the board's power limit is lower */
  fixture_init(&f, 1276, 6, 20);
  CHECK(silent(&f.rn, 4, (const uint8_t[]){5}, 1));
  CHECK(set_u8(&f.rn, 4, 6));
  CHECK(silent(&f.rn, 3, (const uint8_t[]){21}, 1));
  CHECK(set_u8(&f.rn, 3, 20));
  CHECK(set_u8(&f.rn, 3, (uint8_t)-9));
}

static void test_airtime_locks(void) {
  fixture f;
  uint8_t b[2];
  fixture_init(&f, 1262, 5, 22);
  CHECK_EQ(f.a.li.budget.budget_ms, 36000); /* the default: 1 percent of an hour */
  b[0] = 0;
  b[1] = 50; /* hundredths of a percent, big endian: 0.50 percent */
  CHECK(echoed(&f.rn, 0x0b, b, 2));
  CHECK_EQ(f.a.li.budget.budget_ms, 18000);
  b[1] = 0;
  CHECK(silent(&f.rn, 0x0b, b, 2)); /* 0 is not "unlimited": refused */
  CHECK_EQ(f.a.li.budget.budget_ms, 18000);
  b[0] = 0x27;
  b[1] = 0x11; /* 10001: above 100 percent */
  CHECK(silent(&f.rn, 0x0c, b, 2));
  b[1] = 0x10; /* 10000: 100 percent */
  CHECK(echoed(&f.rn, 0x0c, b, 2));
  CHECK_EQ(f.a.li.budget.budget_ms, 18000); /* the smaller of the two locks wins */
  fixture_init(&f, 1262, 5, 22); /* alone, the long lock can raise the budget to 100 percent */
  CHECK(echoed(&f.rn, 0x0c, b, 2));
  CHECK_EQ(f.a.li.budget.budget_ms, 3600000);
  b[0] = 0;
  b[1] = 100; /* a short lock of 1 percent now undercuts the long lock */
  CHECK(echoed(&f.rn, 0x0b, b, 2));
  CHECK_EQ(f.a.li.budget.budget_ms, 36000);
}

/* ---- data path, flow control, signal reports (Task 4) ------------------------------ */

/* two boards on one medium: `f.a` is driven through the RNode module, `peer` is a plain
 * LoRa interface */
typedef struct duo {
  fixture f;
  sim_board peer;
  uint8_t host_out[8192]; /* everything the module has said to the host */
  size_t host_out_len;
} duo;
static void duo_init(duo *d) {
  rnc_lora_params p = {0};
  fixture_init(&d->f, 1262, 5, 22);
  sim_board_init(&d->peer, &d->f.med, 1276, 2, 10000);
  sim_link_all(&d->f.med, 100);
  p.freq_hz = 915000000u;
  p.bw_hz = 125000u;
  p.sf = 8;
  p.cr = 5;
  p.txp_dbm = 10;
  CHECK_EQ(sim_board_start(&d->peer, &p), 0);
  d->host_out_len = 0;
  configure_all(&d->f);
  CHECK(set_u8(&d->f.rn, 6, 1));
  CHECK(rnc_rnode_radio_on(&d->f.rn));
}
static void duo_run(duo *d, unsigned ms) {
  unsigned t;
  for (t = 0; t < ms; t += 4) {
    d->f.med.now_us += 4000u;
    sim_medium_advance(&d->f.med);
    rnc_lora_if_step(&d->peer.li, d->f.med.now_us);
    rnc_rnode_step(&d->f.rn, d->f.med.now_us);
    d->host_out_len += rnc_rnode_pull(&d->f.rn, d->host_out + d->host_out_len, sizeof(d->host_out) - d->host_out_len);
  }
}
/* sends a data frame (command 0) to the module */
static void host_sends_packet(duo *d, const uint8_t *pkt, size_t n) {
  uint8_t frame[2048];
  size_t k = kiss(frame, 0x00, pkt, n);
  rnc_rnode_feed(&d->f.rn, frame, k, d->f.med.now_us);
}
/* the next KISS frame in `buf` from `*pos`: its command, and its unescaped payload */
static int next_frame(const uint8_t *buf, size_t len, size_t *pos, uint8_t *cmd, uint8_t *payload, size_t *plen) {
  size_t i = *pos, k = 0;
  int esc = 0;
  while (i < len && buf[i] != FEND)
    i++;
  while (i < len && buf[i] == FEND) /* the closing delimiter of one frame, the opening of the next */
    i++;
  if (i >= len)
    return 0;
  *cmd = buf[i++];
  for (; i < len && buf[i] != FEND; i++) {
    uint8_t b = buf[i];
    if (esc) {
      b = b == TFEND ? FEND : FESC;
      esc = 0;
    } else if (b == FESC) {
      esc = 1;
      continue;
    }
    payload[k++] = b;
  }
  if (i >= len)
    return 0;
  *plen = k;
  *pos = i; /* the closing delimiter is the next frame's opening one */
  return 1;
}
static void fill_pattern(uint8_t *p, size_t n) {
  size_t i;
  for (i = 0; i < n; i++)
    p[i] = (uint8_t)(i * 7u + 3u);
  p[5] = FEND; /* bytes that need escaping in both directions */
  p[6] = FESC;
  p[n - 1] = FEND;
}

static void test_data_path(void) {
  static duo d;
  uint8_t pkt[500], got[508], payload[600], cmd;
  size_t pos = 0, plen, n;
  int seen_rssi = 0, seen_snr = 0, seen_data = 0;
  duo_init(&d);
  /* host to air */
  fill_pattern(pkt, sizeof(pkt));
  host_sends_packet(&d, pkt, sizeof(pkt));
  duo_run(&d, 3000);
  n = rnc_lora_if_recv(&d.peer.li, got, sizeof(got));
  CHECK_EQ(n, 500);
  CHECK(n == 500 && !memcmp(got, pkt, 500));
  /* air to host: the signal figures first, then the packet */
  d.host_out_len = 0;
  fill_pattern(pkt, 300);
  CHECK_EQ(rnc_lora_if_send(&d.peer.li, pkt, 300, d.f.med.now_us), 0);
  duo_run(&d, 3000);
  while (next_frame(d.host_out, d.host_out_len, &pos, &cmd, payload, &plen)) {
    if (cmd == 0x23) {
      CHECK(!seen_snr && !seen_data);
      CHECK_EQ(plen, 1);
      CHECK_EQ(payload[0], d.f.a.li.stats.last_rssi_dbm + 157);
      seen_rssi = 1;
    } else if (cmd == 0x24) {
      CHECK(seen_rssi && !seen_data);
      CHECK_EQ(plen, 1);
      CHECK_EQ((int8_t)payload[0], d.f.a.li.stats.last_snr_quarter_db);
      seen_snr = 1;
    } else if (cmd == 0x00) {
      CHECK(seen_rssi && seen_snr);
      CHECK_EQ(plen, 300);
      CHECK(plen == 300 && !memcmp(payload, pkt, 300));
      seen_data = 1;
    }
  }
  CHECK(seen_rssi && seen_snr && seen_data);
}

/* Review Focus 1 */
static void test_data_before_radio_on(void) {
  static duo d;
  uint8_t pkt[100];
  fixture_init(&d.f, 1262, 5, 22);
  sim_board_init(&d.peer, &d.f.med, 1276, 2, 10000);
  sim_link_all(&d.f.med, 100);
  d.host_out_len = 0;
  fill_pattern(pkt, sizeof(pkt));
  host_sends_packet(&d, pkt, sizeof(pkt)); /* nothing configured */
  configure_all(&d.f);                     /* settings made, state still off */
  host_sends_packet(&d, pkt, sizeof(pkt));
  duo_run(&d, 10000);
  CHECK_EQ(d.f.rn.stats.drops_radio_off, 2);
  CHECK_EQ(d.f.med.air_us[d.f.a.radio_id], 0);
  CHECK(!rnc_lora_if_up(&d.f.a.li));
}

/* Review Focus 4 */
static void test_reset_drops_everything(void) {
  static duo d;
  uint8_t pkt[100], out[64];
  size_t n;
  duo_init(&d);
  fill_pattern(pkt, sizeof(pkt));
  host_sends_packet(&d, pkt, sizeof(pkt));
  host_sends_packet(&d, pkt, sizeof(pkt));
  host_sends_packet(&d, pkt, sizeof(pkt));
  rnc_rnode_feed(&d.f.rn, (const uint8_t[]){FEND, 0x08, 0x73}, 3, 0); /* half a frame */
  rnc_rnode_reset(&d.f.rn);
  CHECK(!rnc_rnode_radio_on(&d.f.rn)); /* the radio is off until the next host configures it */
  CHECK(!rnc_lora_if_up(&d.f.a.li));
  duo_run(&d, 10000);
  CHECK_EQ(d.f.med.air_us[d.f.a.radio_id], 0);
  d.host_out_len = 0;
  n = EXCHANGE(&d.f.rn, out, FEND, 0x08, 0x73, FEND);
  CHECK_BYTES(out, n, FEND, 0x08, 0x46, FEND);
  /* the next host starts from scratch: settings are gone, state on is refused */
  CHECK(silent(&d.f.rn, 6, (const uint8_t[]){1}, 1));
}

static void test_reset_restores_default_budget(void) {
  fixture f;
  fixture_init(&f, 1262, 5, 22);
  CHECK(echoed(&f.rn, 0x0c, (const uint8_t[]){0x27, 0x10}, 2)); /* a host raises it to 100 percent */
  CHECK_EQ(f.a.li.budget.budget_ms, 3600000);
  rnc_rnode_reset(&f.rn); /* the next host starts from the 1 percent default */
  CHECK_EQ(f.a.li.budget.budget_ms, 36000);
}

static size_t count_ready(const uint8_t *buf, size_t len) {
  size_t pos = 0, plen, count = 0;
  uint8_t cmd, payload[600];
  while (next_frame(buf, len, &pos, &cmd, payload, &plen))
    if (cmd == 0x0F)
      count++;
  return count;
}
static void test_flow_control(void) {
  static duo d;
  uint8_t pkt[100];
  unsigned i;
  size_t ready_before;
  duo_init(&d);
  d.host_out_len = 0;
  fill_pattern(pkt, sizeof(pkt));
  /* the queue takes RNC_LORA_TXQ packets; READY follows each one that leaves room */
  for (i = 0; i < RNC_LORA_TXQ; i++)
    host_sends_packet(&d, pkt, sizeof(pkt));
  d.host_out_len += rnc_rnode_pull(&d.f.rn, d.host_out, sizeof(d.host_out));
  CHECK_EQ(count_ready(d.host_out, d.host_out_len), RNC_LORA_TXQ - 1u);
  /* a packet beyond the queue is dropped and counted, with no READY */
  ready_before = count_ready(d.host_out, d.host_out_len);
  host_sends_packet(&d, pkt, sizeof(pkt));
  d.host_out_len += rnc_rnode_pull(&d.f.rn, d.host_out + d.host_out_len, sizeof(d.host_out) - d.host_out_len);
  CHECK_EQ(count_ready(d.host_out, d.host_out_len), ready_before);
  CHECK_EQ(d.f.rn.stats.drops_queue, 1);
  /* once one has gone out, READY comes */
  duo_run(&d, 3000);
  CHECK(count_ready(d.host_out, d.host_out_len) > ready_before);
}

int main(void) {
  test_identity_commands();
  test_escaping();
  test_malformed_input();
  test_settings_and_state();
  test_invalid_values();
  test_airtime_locks();
  test_data_path();
  test_data_before_radio_on();
  test_reset_drops_everything();
  test_flow_control();
  test_reset_restores_default_budget();
  if (failures) {
    fprintf(stderr, "test_rnode: %d failure(s)\n", failures);
    return 1;
  }
  puts("test_rnode: all checks passed");
  return 0;
}
