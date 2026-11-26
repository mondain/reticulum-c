/* Network stamp arithmetic against the unmodified reference: every record tests/netstamp_reference.py prints
 * (cost encoding, stamp_valid, stamp_value, the announce extension) must come out the same here. */
#define _POSIX_C_SOURCE 200809L
#include <reticulum_c/rnc_netstamp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: %s (line %u: %s)\n", __FILE__, __LINE__, #x, lineno, line); \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static unsigned lineno;
static char line[4096];
static size_t unhex(const char *s, uint8_t *out, size_t cap) {
  size_t n = 0;
  if (!strcmp(s, "-"))
    return 0;
  while (s[0] && s[1] && n < cap) {
    unsigned v;
    sscanf(s, "%2x", &v);
    out[n++] = (uint8_t)v;
    s += 2;
  }
  return n;
}
static rnc_result rng(void *context, uint8_t *out, size_t size) {
  static FILE *f;
  (void)context;
  if (!f)
    f = fopen("/dev/urandom", "rb");
  return f && fread(out, 1, size, f) == size ? RNC_OK : RNC_CRYPTO;
}
static void hex(const uint8_t *in, size_t n, char *out) {
  size_t i;
  for (i = 0; i < n; i++)
    sprintf(out + 2 * i, "%02x", in[i]);
}
int main(int argc, char **argv) {
  char cmd[1024];
  FILE *p;
  unsigned costs = 0, valids = 0, values = 0, exts = 0, identities = 0, ours = 0;
  rnc_identity mine_id;
  char mine_hex[129];
  CHECK(argc == 3); /* python executable, tests/netstamp_reference.py */
  /* one stamped identity of ours for the reference to load */
  CHECK(rnc_netstamp_identity_generate(&mine_id, 8.0, rng, NULL, 0, NULL) == RNC_OK);
  hex(mine_id.private_key, 64, mine_hex);
  snprintf(cmd, sizeof(cmd), "'%s' '%s' %s", argv[1], argv[2], mine_hex);
  p = popen(cmd, "r");
  CHECK(p);
  while (fgets(line, sizeof(line), p)) {
    ++lineno;
    line[strcspn(line, "\n")] = 0;
    if (line[0] == 'C') {
      char bytes_hex[16], mine[8];
      double cost, quant;
      unsigned fp;
      uint8_t b[2];
      CHECK(sscanf(line, "C %lf %u %15s %lf", &cost, &fp, bytes_hex, &quant) == 4);
      CHECK(rnc_netstamp_cost_to_fp(cost) == fp);
      rnc_netstamp_cost_to_bytes(cost, b);
      hex(b, 2, mine);
      CHECK(!strcmp(mine, bytes_hex));
      CHECK(rnc_netstamp_quantize(cost) == quant);
      ++costs;
    } else if (line[0] == 'V') {
      char mat_hex[400], stamp_hex[64];
      uint8_t material[200], stamp[16];
      double cost, value;
      int valid;
      size_t m, s;
      CHECK(sscanf(line, "V %399s %63s %lf %d %lf", mat_hex, stamp_hex, &cost, &valid, &value) == 5);
      m = unhex(mat_hex, material, sizeof(material));
      s = unhex(stamp_hex, stamp, sizeof(stamp));
      CHECK(s == RNC_NETSTAMP_SIZE);
      CHECK(rnc_netstamp_valid(material, m, stamp, s, cost) == valid);
      CHECK(rnc_netstamp_value(material, m, stamp, s) == value);
      ++valids;
      values += valid;
    } else if (line[0] == 'I' || line[0] == 'J') { /* I: the reference's identity; J: how it reads ours */
      char prv_hex[129], pub_hex[129], mine[129];
      uint8_t prv[64];
      rnc_identity id;
      double value;
      CHECK(sscanf(line + 1, " %128s %128s %lf", prv_hex, pub_hex, &value) == 3);
      CHECK(unhex(prv_hex, prv, sizeof(prv)) == 64);
      CHECK(rnc_identity_from_private(&id, prv) == RNC_OK);
      hex(id.public_key, 64, mine);
      CHECK(!strcmp(mine, pub_hex));
      CHECK(rnc_netstamp_identity_value(&id) == value);
      if (line[0] == 'J') {
        CHECK(value >= 8.0 && !strcmp(prv_hex, mine_hex));
        ++ours;
      } else
        identities += value >= 8.0;
    } else if (line[0] == 'E') {
      char stamp_hex[64], ext_hex[64], mine[64];
      uint8_t stamp[16], ext[RNC_NETSTAMP_EXT_SIZE];
      rnc_netstamp_ext got;
      double link_cost;
      CHECK(sscanf(line, "E %63s %lf %63s", stamp_hex, &link_cost, ext_hex) == 3);
      CHECK(unhex(stamp_hex, stamp, sizeof(stamp)) == RNC_NETSTAMP_SIZE);
      CHECK(rnc_netstamp_ext_build(stamp, link_cost, ext) == RNC_OK);
      hex(ext, sizeof(ext), mine);
      CHECK(!strcmp(mine, ext_hex));
      CHECK(rnc_netstamp_ext_parse(ext, sizeof(ext), &got) == 1 && got.link_cost == link_cost &&
            !memcmp(got.stamp, stamp, sizeof(stamp)));
      ++exts;
    }
  }
  CHECK(pclose(p) == 0);
  CHECK(costs == 18 && valids > 2000 && values > 500 && values < valids && exts == 4);
  CHECK(identities >= 3 && ours == 1);
  printf("netstamp reference: %u costs, %u validity checks, %u extensions agree\n", costs, valids, exts);
  return 0;
}
