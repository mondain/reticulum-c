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
static void hex(const uint8_t *in, size_t n, char *out) {
  size_t i;
  for (i = 0; i < n; i++)
    sprintf(out + 2 * i, "%02x", in[i]);
}
int main(int argc, char **argv) {
  char cmd[1024];
  FILE *p;
  unsigned costs = 0, valids = 0, values = 0, exts = 0;
  CHECK(argc == 3); /* python executable, tests/netstamp_reference.py */
  snprintf(cmd, sizeof(cmd), "'%s' '%s'", argv[1], argv[2]);
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
  printf("netstamp reference: %u costs, %u validity checks, %u extensions agree\n", costs, valids, exts);
  return 0;
}
