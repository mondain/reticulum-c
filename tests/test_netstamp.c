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
/* Fixed-point cost encoding, RNS.Stamps.cost_to_fp / cost_to_bytes (8 fractional bits, capped at 100). */
static void cost_encoding(void) {
  uint8_t b[2];
  CHECK(rnc_netstamp_cost_to_fp(23.5) == 6016);
  CHECK(rnc_netstamp_cost_to_fp(0) == 0);
  CHECK(rnc_netstamp_cost_to_fp(-3) == 0);
  CHECK(rnc_netstamp_cost_to_fp(500) == 100 * 256);
  CHECK(rnc_netstamp_cost_to_fp(15.8) == 4045); /* floor(15.8 * 256 + 0.5) */
  rnc_netstamp_cost_to_bytes(12.5, b);
  CHECK(b[0] == 12 && b[1] == 128);
  CHECK(rnc_netstamp_cost_from_bytes(b) == 12.5);
  CHECK(rnc_netstamp_cost_from_fp(6016) == 23.5);
  CHECK(rnc_netstamp_quantize(15.84) == 4055 / 256.0); /* 15.83984375 */
  CHECK(rnc_netstamp_quantize(15.84375) == 15.84375);
  CHECK(rnc_netstamp_quantize(15.8) == 4045 / 256.0);
}
/* The mantissa table is authoritative: its digest is the one RNS.Stamps asserts at import. */
static void table(void) {
  char text[256 * 14], hex[65];
  uint8_t digest[32];
  size_t i, n = 0;
  static const char want[] = "55ba3ce1df224895b0dfdc102eb4359fc2f5a7efefee68df0cc90c8a8ac24f48";
  for (i = 0; i < 256; i++)
    n += (size_t)sprintf(text + n, i ? ",%llu" : "%llu", (unsigned long long)rnc_netstamp_table(i));
  CHECK(rnc_hash(text, n, digest) == RNC_OK);
  for (i = 0; i < 32; i++)
    sprintf(hex + 2 * i, "%02x", digest[i]);
  CHECK(!strcmp(hex, want));
  CHECK(rnc_netstamp_table(0) == 1ull << 33 && rnc_netstamp_table(256) == 0);
}
/* valid() is hash <= target(cost); value() floors the hash onto the same grid, so a stamp is valid at its own
 * value and not a whole unit above it. Cost 0 accepts everything. */
static void value_and_valid(void) {
  const uint8_t material[4] = {1, 2, 3, 4};
  uint8_t stamp[14];
  unsigned i, hits = 0;
  for (i = 0; i < 200; i++) {
    double v;
    memset(stamp, 0, sizeof(stamp));
    stamp[0] = (uint8_t)i;
    stamp[13] = (uint8_t)(i * 7);
    v = rnc_netstamp_value(material, sizeof(material), stamp, sizeof(stamp));
    CHECK(v >= 0 && v < 256);
    CHECK(rnc_netstamp_valid(material, sizeof(material), stamp, sizeof(stamp), 0));
    CHECK(rnc_netstamp_valid(material, sizeof(material), stamp, sizeof(stamp), v));
    CHECK(!rnc_netstamp_valid(material, sizeof(material), stamp, sizeof(stamp), v + 1.0));
    hits += v >= 3.0;
  }
  CHECK(hits > 0 && hits < 200); /* a spread of values, not a constant */
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  if (!strcmp(argv[1], "cost_encoding"))
    cost_encoding();
  else if (!strcmp(argv[1], "table"))
    table();
  else if (!strcmp(argv[1], "value_and_valid"))
    value_and_valid();
  else
    CHECK(0);
  puts("netstamp test passed");
  return 0;
}
