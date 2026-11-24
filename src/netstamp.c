#include "crypto_backend.h"
#include <reticulum_c/rnc_netstamp.h>
#include <string.h>
#include <stdint.h>
#include "netstamp_tab.h"

uint16_t rnc_netstamp_cost_to_fp(double cost) {
  double v;
  if (!(cost > 0))
    return 0;
  v = cost * 256.0 + 0.5; /* positive, so truncation is the floor; no libm needed on the boards */
  if (v >= RNC_NETSTAMP_COST_CAP * 256.0)
    return RNC_NETSTAMP_COST_CAP * 256u;
  return (uint16_t)v;
}
double rnc_netstamp_cost_from_fp(uint16_t fp) { return fp / 256.0; }
void rnc_netstamp_cost_to_bytes(double cost, uint8_t out[2]) {
  uint16_t fp = rnc_netstamp_cost_to_fp(cost);
  out[0] = (uint8_t)(fp >> 8);
  out[1] = (uint8_t)fp;
}
double rnc_netstamp_cost_from_bytes(const uint8_t in[2]) {
  return rnc_netstamp_cost_from_fp((uint16_t)((in[0] << 8) | in[1]));
}
double rnc_netstamp_quantize(double cost) {
  return rnc_netstamp_cost_from_fp(rnc_netstamp_cost_to_fp(cost));
}
uint64_t rnc_netstamp_table(size_t index) { return index < 256 ? rnc_netstamp_tab[index] : 0; }

static int hash_of(const void *material, size_t material_size, const void *stamp,
                   size_t stamp_size, uint8_t out[32]) {
  rnc_sha256_ctx c;
  if (!material && material_size)
    return 0;
  if (!stamp || !stamp_size)
    return 0;
  if (!rnc_sha256_init(&c)) {
    rnc_sha256_discard(&c);
    return 0;
  }
  if ((material_size && !rnc_sha256_update(&c, material, material_size)) ||
      !rnc_sha256_update(&c, stamp, stamp_size)) {
    rnc_sha256_discard(&c);
    return 0;
  }
  return rnc_sha256_final(&c, out);
}
/* target_from_fp: (TAB[f] << i) >> 33 with i, f = divmod(256 * 256 - fp, 256), as a 256 bit big-endian
 * integer. A target of 2^256 or more accepts every hash and is returned saturated. */
static void target_of(uint16_t fp, uint8_t out[32]) {
  uint8_t wide[40] = {0}; /* 320 bits, big-endian */
  unsigned i = (65536u - fp) / 256u, f = (65536u - fp) % 256u;
  uint64_t t = rnc_netstamp_tab[f];
  int shift = (int)i - 33, k;
  size_t b;
  for (k = 0; k < 8; k++)
    wide[39 - k] = (uint8_t)(t >> (8 * k));
  if (shift > 0) {
    unsigned bytes = (unsigned)shift / 8u, bits = (unsigned)shift % 8u;
    for (b = 0; b + bytes < 40; b++) {
      unsigned v = (unsigned)wide[b + bytes] << bits;
      if (bits && b + bytes + 1 < 40)
        v |= (unsigned)wide[b + bytes + 1] >> (8 - bits);
      wide[b] = (uint8_t)v;
    }
    for (b = 40 - bytes; b < 40; b++)
      wide[b] = 0;
  } else if (shift < 0) {
    unsigned bytes = (unsigned)(-shift) / 8u, bits = (unsigned)(-shift) % 8u;
    for (b = 40; b-- > 0;) {
      unsigned v = b >= bytes ? (unsigned)wide[b - bytes] >> bits : 0;
      if (bits && b > bytes)
        v |= (unsigned)wide[b - bytes - 1] << (8 - bits);
      wide[b] = (uint8_t)v;
    }
  }
  for (b = 0; b < 8; b++)
    if (wide[b]) {
      memset(out, 0xff, 32);
      return;
    }
  memcpy(out, wide + 8, 32);
}
int rnc_netstamp_valid(const void *material, size_t material_size, const void *stamp,
                       size_t stamp_size, double cost) {
  uint8_t hash[32], target[32];
  if (!hash_of(material, material_size, stamp, stamp_size, hash))
    return 0;
  target_of(rnc_netstamp_cost_to_fp(cost), target);
  return memcmp(hash, target, 32) <= 0;
}
static int bit_of(const uint8_t hash[32], unsigned n) { return (hash[31 - n / 8u] >> (n % 8u)) & 1; }
double rnc_netstamp_value(const void *material, size_t material_size, const void *stamp,
                          size_t stamp_size) {
  uint8_t hash[32];
  unsigned bl = 256, k, lo, hi, mid;
  uint64_t mn = 0;
  if (!hash_of(material, material_size, stamp, stamp_size, hash))
    return 0;
  for (bl = 256; bl && !bit_of(hash, bl - 1); bl--)
    ;
  if (!bl)
    return 256.0;
  for (k = 0; k < 34; k++)
    mn = (mn << 1) | (k < bl ? (uint64_t)bit_of(hash, bl - 1 - k) : 0u);
  /* bisect_right(TAB, mn): the number of entries not above mn */
  lo = 0;
  hi = 256;
  while (lo < hi) {
    mid = (lo + hi) / 2;
    if (mn < rnc_netstamp_tab[mid])
      hi = mid;
    else
      lo = mid + 1;
  }
  return (double)(((256u - bl + 1u) << 8) - lo) / 256.0;
}
