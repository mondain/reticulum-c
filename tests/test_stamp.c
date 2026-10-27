#include <reticulum_c/rnc_stamp.h>
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
static uint32_t seed = 3;
static rnc_result rng(void *ctx, uint8_t *p, size_t n) {
  size_t i;
  (void)ctx;
  for (i = 0; i < n; i++) {
    seed = seed * 1664525u + 1013904223u;
    p[i] = (uint8_t)(seed >> 24);
  }
  return RNC_OK;
}
static void hex(const uint8_t *in, size_t n, char *out) {
  size_t i;
  for (i = 0; i < n; i++)
    sprintf(out + 2 * i, "%02x", in[i]);
}
/* Expected digests come from LXMF.LXStamper.stamp_workblock on the same
 * material: rounds 1 and 3 use one-byte msgpack counters, 200 crosses into the
 * two-byte form. */
static void workblock(void) {
  static const struct {
    unsigned rounds;
    const char *digest;
  } cases[] = {
      {1, "7fbf49b7a5e79e4a70268b4267e6f9abb6540f8b265b6fb13ed9b58494c7a581"},
      {3, "6b36631af315c9d1c3450a1c69f4392551f1e4ac142f2450c9be315fbc97d1af"},
      {20, "7c06f15571960ba62e26a1d51bc4f9c86ebc44810701d232af0fe9a6c10f9e61"},
      {200, "65441d8d49fa6113d54577e28dea88c5c5812574f9bd260b68a18dac71454d9b"}};
  uint8_t material[32], *block, digest[32];
  char text[65];
  size_t i, written;
  for (i = 0; i < 32; i++)
    material[i] = (uint8_t)i;
  block = malloc(256u * 200u);
  CHECK(block);
  for (i = 0; i < sizeof(cases) / sizeof(*cases); i++) {
    CHECK(rnc_stamp_workblock(material, 32, cases[i].rounds, block,
                              256u * 200u, &written) == RNC_OK);
    CHECK(written == 256u * cases[i].rounds);
    CHECK(rnc_hash(block, written, digest) == RNC_OK);
    hex(digest, 32, text);
    CHECK(!strcmp(text, cases[i].digest));
  }
  CHECK(rnc_stamp_workblock(material, 32, 3, block, 767, &written) ==
            RNC_NO_SPACE && written == 0);
  CHECK(rnc_stamp_workblock(material, 32, 0, block, 100, &written) ==
        RNC_INVALID);
  CHECK(rnc_stamp_workblock(NULL, 32, 3, block, 768, &written) == RNC_INVALID);
  free(block);
}
/* stamp 0x...0237 has value 13 over the 20-round workblock of this material. */
static void value_and_validity(void) {
  uint8_t material[32], block[256 * 20], stamp[32] = {0};
  size_t i, written;
  for (i = 0; i < 32; i++)
    material[i] = (uint8_t)i;
  stamp[30] = 0x02;
  stamp[31] = 0x37;
  CHECK(rnc_stamp_workblock(material, 32, 20, block, sizeof(block), &written) ==
        RNC_OK);
  CHECK(rnc_stamp_value(block, written, stamp) == 13);
  CHECK(rnc_stamp_valid(block, written, stamp, 10));
  CHECK(rnc_stamp_valid(block, written, stamp, 13));
  CHECK(!rnc_stamp_valid(block, written, stamp, 14));
  CHECK(rnc_stamp_valid(block, written, stamp, 0));
}
static void generation(void) {
  uint8_t material[32] = {7}, stamp[32], block[256 * 20];
  size_t written;
  CHECK(rnc_stamp_generate(material, 32, 20, 12, rng, NULL, 0, stamp) ==
        RNC_OK);
  CHECK(rnc_stamp_workblock(material, 32, 20, block, sizeof(block), &written) ==
        RNC_OK);
  CHECK(rnc_stamp_valid(block, written, stamp, 12));
  CHECK(rnc_stamp_value(block, written, stamp) >= 12);
  /* an impossible budget reports a timeout and leaves the output alone */
  memset(stamp, 0xaa, 32);
  CHECK(rnc_stamp_generate(material, 32, 20, 30, rng, NULL, 50, stamp) ==
        RNC_TIMEOUT);
  CHECK(stamp[0] == 0xaa && stamp[31] == 0xaa);
  CHECK(rnc_stamp_generate(material, 32, 20, 300, rng, NULL, 10, stamp) ==
        RNC_INVALID);
  CHECK(rnc_stamp_generate(material, 32, 0, 12, rng, NULL, 10, stamp) ==
        RNC_INVALID);
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  if (!strcmp(argv[1], "workblock"))
    workblock();
  else if (!strcmp(argv[1], "value"))
    value_and_validity();
  else if (!strcmp(argv[1], "generate"))
    generation();
  else
    CHECK(0);
  puts("stamp test passed");
  return 0;
}
