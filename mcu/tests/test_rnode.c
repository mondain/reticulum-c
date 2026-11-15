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

int main(void) {
  test_identity_commands();
  test_escaping();
  test_malformed_input();
  test_settings_and_state();
  test_invalid_values();
  test_airtime_locks();
  if (failures) {
    fprintf(stderr, "test_rnode: %d failure(s)\n", failures);
    return 1;
  }
  puts("test_rnode: all checks passed");
  return 0;
}
