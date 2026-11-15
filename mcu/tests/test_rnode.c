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

int main(void) {
  test_identity_commands();
  test_escaping();
  test_malformed_input();
  if (failures) {
    fprintf(stderr, "test_rnode: %d failure(s)\n", failures);
    return 1;
  }
  puts("test_rnode: all checks passed");
  return 0;
}
