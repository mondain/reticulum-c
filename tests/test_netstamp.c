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
static uint32_t seed = 11;
static rnc_result rng(void *ctx, uint8_t *p, size_t n) {
  size_t i;
  (void)ctx;
  for (i = 0; i < n; i++) {
    seed = seed * 1664525u + 1013904223u;
    p[i] = (uint8_t)(seed >> 24);
  }
  return RNC_OK;
}
/* A search at a low cost ends with a stamp the validator accepts at that cost, and reports its work. */
static void find_low_cost(void) {
  const uint8_t material[6] = {9, 8, 7, 6, 5, 4};
  uint8_t stamp[RNC_NETSTAMP_SIZE];
  uint64_t attempts = 0;
  CHECK(rnc_netstamp_find(material, sizeof(material), 8.0, rng, NULL, 0, stamp, &attempts) == RNC_OK);
  CHECK(attempts >= 1 && attempts < 100000);
  CHECK(rnc_netstamp_valid(material, sizeof(material), stamp, sizeof(stamp), 8.0));
  CHECK(rnc_netstamp_value(material, sizeof(material), stamp, sizeof(stamp)) >= 8.0);
  /* fractional costs work the same way */
  CHECK(rnc_netstamp_find(material, sizeof(material), 9.5, rng, NULL, 0, stamp, NULL) == RNC_OK);
  CHECK(rnc_netstamp_valid(material, sizeof(material), stamp, sizeof(stamp), 9.5));
}
/* A stamped key is an X25519 key pair whose public key meets the cost over the material. */
static void find_key_low_cost(void) {
  const uint8_t material[8] = {1, 1, 2, 3, 5, 8, 13, 21};
  uint8_t priv[32], pub[32], seed64[64] = {0};
  rnc_identity id;
  CHECK(rnc_netstamp_find_key(material, sizeof(material), 8.0, rng, NULL, 0, priv, pub, NULL) == RNC_OK);
  CHECK(rnc_netstamp_valid(material, sizeof(material), pub, 32, 8.0));
  /* the private half loads as the encryption key of an identity whose public key is the stamped one */
  memcpy(seed64, priv, 32);
  CHECK(rnc_identity_from_private(&id, seed64) == RNC_OK && !memcmp(id.public_key, pub, 32));
}
/* A search that runs out of attempts reports RNC_TIMEOUT and leaves the outputs alone; bad arguments are refused. */
static void find_exhausted(void) {
  const uint8_t material[2] = {1, 2};
  uint8_t stamp[RNC_NETSTAMP_SIZE], priv[32], pub[32], blank[32];
  memset(stamp, 0xa5, sizeof(stamp));
  memset(priv, 0xa5, sizeof(priv));
  memset(pub, 0xa5, sizeof(pub));
  memset(blank, 0xa5, sizeof(blank));
  CHECK(rnc_netstamp_find(material, sizeof(material), 40.0, rng, NULL, 1, stamp, NULL) == RNC_TIMEOUT);
  CHECK(!memcmp(stamp, blank, sizeof(stamp)));
  CHECK(rnc_netstamp_find_key(material, sizeof(material), 40.0, rng, NULL, 1, priv, pub, NULL) == RNC_TIMEOUT);
  CHECK(!memcmp(priv, blank, 32) && !memcmp(pub, blank, 32));
  CHECK(rnc_netstamp_find(NULL, 2, 8.0, rng, NULL, 0, stamp, NULL) == RNC_INVALID);
  CHECK(rnc_netstamp_find(material, 2, 8.0, NULL, NULL, 0, stamp, NULL) == RNC_INVALID);
  CHECK(rnc_netstamp_find(material, 2, 100.5, rng, NULL, 0, stamp, NULL) == RNC_INVALID);
  CHECK(rnc_netstamp_find_key(material, 2, 8.0, rng, NULL, 0, NULL, pub, NULL) == RNC_INVALID);
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  if (!strcmp(argv[1], "cost_encoding"))
    cost_encoding();
  else if (!strcmp(argv[1], "table"))
    table();
  else if (!strcmp(argv[1], "value_and_valid"))
    value_and_valid();
  else if (!strcmp(argv[1], "find_low_cost"))
    find_low_cost();
  else if (!strcmp(argv[1], "find_key_low_cost"))
    find_key_low_cost();
  else if (!strcmp(argv[1], "find_exhausted"))
    find_exhausted();
  else
    CHECK(0);
  puts("netstamp test passed");
  return 0;
}
