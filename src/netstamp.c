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

static int search_args_ok(const void *material, size_t size, double cost, rnc_random_fn random) {
  return (material || !size) && random && cost >= 0 && cost <= RNC_NETSTAMP_COST_CAP;
}
rnc_result rnc_netstamp_find(const void *material, size_t material_size, double cost, rnc_random_fn random,
                             void *random_context, uint64_t max_attempts, uint8_t stamp[RNC_NETSTAMP_SIZE],
                             uint64_t *attempts) {
  rnc_sha256_ctx base, c;
  uint8_t cursor[RNC_NETSTAMP_SIZE], hash[32], target[32];
  uint64_t tried = 0;
  rnc_result r = RNC_TIMEOUT;
  int k;
  if (!search_args_ok(material, material_size, cost, random) || !stamp)
    return RNC_INVALID;
  if (!max_attempts)
    max_attempts = UINT64_C(1) << 32;
  target_of(rnc_netstamp_cost_to_fp(cost), target);
  r = random(random_context, cursor, sizeof(cursor));
  if (r != RNC_OK)
    return r;
  if (!rnc_sha256_init(&base) || (material_size && !rnc_sha256_update(&base, material, material_size))) {
    rnc_sha256_discard(&base);
    return RNC_CRYPTO;
  }
  r = RNC_TIMEOUT;
  while (tried < max_attempts) {
    int ok = rnc_sha256_copy(&c, &base) && rnc_sha256_update(&c, cursor, sizeof(cursor)) &&
             rnc_sha256_final(&c, hash);
    if (!ok) {
      rnc_sha256_discard(&c);
      r = RNC_CRYPTO;
      break;
    }
    tried++;
    if (memcmp(hash, target, 32) <= 0) {
      memcpy(stamp, cursor, sizeof(cursor));
      r = RNC_OK;
      break;
    }
    for (k = RNC_NETSTAMP_SIZE - 1; k >= 0 && ++cursor[k] == 0; k--)
      ;
  }
  rnc_sha256_discard(&base);
  if (attempts)
    *attempts = tried;
  return r;
}
rnc_result rnc_netstamp_find_key(const void *material, size_t material_size, double cost,
                                 rnc_random_fn random, void *random_context, uint64_t max_attempts,
                                 uint8_t private_key[32], uint8_t public_key[32], uint64_t *attempts) {
  rnc_sha256_ctx base, c;
  uint8_t priv[32], pub[32], hash[32], target[32];
  uint64_t tried = 0;
  rnc_result r = RNC_TIMEOUT;
  if (!search_args_ok(material, material_size, cost, random) || !private_key || !public_key)
    return RNC_INVALID;
  if (!max_attempts)
    max_attempts = UINT64_C(1) << 32;
  target_of(rnc_netstamp_cost_to_fp(cost), target);
  if (!rnc_sha256_init(&base) || (material_size && !rnc_sha256_update(&base, material, material_size))) {
    rnc_sha256_discard(&base);
    return RNC_CRYPTO;
  }
  while (tried < max_attempts) {
    int ok;
    r = random(random_context, priv, sizeof(priv));
    if (r != RNC_OK)
      break;
    ok = rnc_x25519_public(priv, pub) && rnc_sha256_copy(&c, &base) && rnc_sha256_update(&c, pub, 32) &&
         rnc_sha256_final(&c, hash);
    if (!ok) {
      rnc_sha256_discard(&c);
      r = RNC_CRYPTO;
      break;
    }
    tried++;
    r = RNC_TIMEOUT;
    if (memcmp(hash, target, 32) <= 0) {
      memcpy(private_key, priv, 32);
      memcpy(public_key, pub, 32);
      r = RNC_OK;
      break;
    }
  }
  rnc_cleanse(priv, sizeof(priv));
  rnc_sha256_discard(&base);
  if (attempts)
    *attempts = tried;
  return r;
}

void rnc_netstamp_announce_material(const uint8_t destination[16], const uint8_t public_key[64],
                                    const uint8_t name_hash[10], uint8_t out[90]) {
  memcpy(out, destination, 16);
  memcpy(out + 16, public_key, 64);
  memcpy(out + 80, name_hash, 10);
}
rnc_result rnc_netstamp_ext_build(const uint8_t stamp[RNC_NETSTAMP_SIZE], double link_cost,
                                  uint8_t out[RNC_NETSTAMP_EXT_SIZE]) {
  uint8_t cost[2];
  if (!stamp || !out)
    return RNC_INVALID;
  rnc_netstamp_cost_to_bytes(link_cost, cost);
  out[0] = 0xc1;
  out[1] = 0x00;
  memcpy(out + 2, stamp, RNC_NETSTAMP_SIZE);
  out[16] = cost[1]; /* fraction first, as Destination._announce writes it */
  out[17] = cost[0];
  return RNC_OK;
}
int rnc_netstamp_ext_parse(const uint8_t *app_data, size_t size, rnc_netstamp_ext *ext) {
  const uint8_t *e;
  uint8_t cost[2];
  double link_cost;
  if (!app_data || !ext || size < RNC_NETSTAMP_EXT_SIZE)
    return 0;
  e = app_data + size - RNC_NETSTAMP_EXT_SIZE;
  if (e[0] != 0xc1 || (e[17] & 0x80))
    return 0;
  cost[0] = e[17];
  cost[1] = e[16];
  link_cost = rnc_netstamp_cost_from_bytes(cost);
  if (link_cost > RNC_NETSTAMP_COST_CAP)
    return 0;
  memcpy(ext->stamp, e + 2, RNC_NETSTAMP_SIZE);
  ext->link_cost = link_cost;
  ext->app_size = size - RNC_NETSTAMP_EXT_SIZE;
  return 1;
}
int rnc_netstamp_link_stamper_run(void *context, const uint8_t material[48], double cost, uint8_t private_key[32],
                                  uint8_t public_key[32]) {
  const rnc_netstamp_link_stamper *c = context;
  if (!c || !c->random)
    return 0;
  return rnc_netstamp_find_key(material, 48, cost, c->random, c->random_context, c->max_attempts, private_key,
                               public_key, NULL) == RNC_OK;
}
rnc_result rnc_netstamp_identity_generate(rnc_identity *identity, double value, rnc_random_fn random,
                                          void *random_context, uint64_t max_attempts, uint64_t *attempts) {
  rnc_identity fresh, stamped;
  uint8_t key[64], encryption_public[32];
  rnc_result r;
  if (!identity || !random || !(value >= 0) || value > RNC_NETSTAMP_COST_CAP)
    return RNC_INVALID;
  r = rnc_identity_generate(&fresh, random, random_context);
  if (r != RNC_OK)
    return r;
  if (attempts)
    *attempts = 0;
  if (value == 0) {
    *identity = fresh;
    rnc_identity_clear(&fresh);
    return RNC_OK;
  }
  /* the signature key stays; the encryption key is the one searched for */
  memcpy(key, fresh.private_key, 64);
  r = rnc_netstamp_find_key(fresh.public_key + 32, 32, value, random, random_context, max_attempts, key,
                            encryption_public, attempts);
  if (r == RNC_OK)
    r = rnc_identity_from_private(&stamped, key);
  if (r == RNC_OK)
    *identity = stamped;
  rnc_identity_clear(&stamped);
  rnc_identity_clear(&fresh);
  rnc_cleanse(key, sizeof(key));
  return r;
}
double rnc_netstamp_identity_value(const rnc_identity *identity) {
  return identity ? rnc_netstamp_value(identity->public_key + 32, 32, identity->public_key, 32) : 0;
}
