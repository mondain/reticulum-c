#include "service_msgpack.h"
#include "crypto_backend.h"
#include <reticulum_c/rnc_stamp.h>
#include <stdlib.h>
#include <string.h>

static int sha256_parts(const void *a, size_t an, const void *b, size_t bn,
                        uint8_t out[32]) {
  rnc_sha256_ctx c;
  if (!rnc_sha256_init(&c)) {
    rnc_sha256_discard(&c);
    return 0;
  }
  if (!rnc_sha256_update(&c, a, an) || (bn && !rnc_sha256_update(&c, b, bn))) {
    rnc_sha256_discard(&c);
    return 0;
  }
  return rnc_sha256_final(&c, out);
}
/* HKDF-SHA256 with an empty info string, as RNS.Cryptography.hkdf(context=None) */
static int hkdf256(const void *key, size_t key_size, const uint8_t salt[32],
                   uint8_t out[RNC_STAMP_ROUND_SIZE]) {
  return rnc_hkdf_sha256(salt, 32, key, key_size, NULL, 0, out, RNC_STAMP_ROUND_SIZE);
}
rnc_result rnc_stamp_workblock(const void *material, size_t size,
                               unsigned rounds, uint8_t *workblock,
                               size_t capacity, size_t *written) {
  uint8_t *input, salt[32];
  unsigned n;
  rnc_result r = RNC_OK;
  if (written)
    *written = 0;
  if (!material || !size || size > 4096 || !rounds ||
      rounds > RNC_STAMP_MAX_ROUNDS || !workblock || !written)
    return RNC_INVALID;
  if (capacity < (size_t)rounds * RNC_STAMP_ROUND_SIZE)
    return RNC_NO_SPACE;
  input = malloc(size + 5u);
  if (!input)
    return RNC_NO_SPACE;
  memcpy(input, material, size);
  for (n = 0; n < rounds && r == RNC_OK; n++) {
    /* salt = SHA256(material || msgpack(n)) */
    size_t extra = rmp_put_uint(input + size, n);
    if (!sha256_parts(input, size + extra, NULL, 0, salt) ||
        !hkdf256(material, size, salt, workblock + (size_t)n * RNC_STAMP_ROUND_SIZE))
      r = RNC_CRYPTO;
  }
  rnc_cleanse(input, size + 5u);
  free(input);
  if (r != RNC_OK) {
    rnc_cleanse(workblock, (size_t)rounds * RNC_STAMP_ROUND_SIZE);
    return r;
  }
  *written = (size_t)rounds * RNC_STAMP_ROUND_SIZE;
  return RNC_OK;
}
static unsigned leading_zero_bits(const uint8_t hash[32]) {
  unsigned bits = 0, i;
  for (i = 0; i < 32; i++) {
    uint8_t b = hash[i];
    if (!b) {
      bits += 8;
      continue;
    }
    while (!(b & 0x80)) {
      b = (uint8_t)(b << 1);
      bits++;
    }
    return bits;
  }
  return 256;
}
/* hash <= 2^(256-cost): either enough leading zeros, or exactly the target. */
static int meets_cost(const uint8_t hash[32], unsigned cost) {
  unsigned lz = leading_zero_bits(hash), i;
  if (cost > 256)
    return 0;
  if (lz >= cost)
    return 1;
  if (lz + 1u != cost)
    return 0;
  for (i = lz + 1u; i < 256; i++)
    if (hash[i / 8] & (0x80 >> (i % 8)))
      return 0;
  return 1;
}
unsigned rnc_stamp_value(const uint8_t *workblock, size_t size,
                         const uint8_t stamp[RNC_STAMP_SIZE]) {
  uint8_t hash[32];
  if (!workblock || !size || !stamp ||
      !sha256_parts(workblock, size, stamp, RNC_STAMP_SIZE, hash))
    return 0;
  return leading_zero_bits(hash);
}
int rnc_stamp_valid(const uint8_t *workblock, size_t size,
                    const uint8_t stamp[RNC_STAMP_SIZE], unsigned cost) {
  uint8_t hash[32];
  if (!workblock || !size || !stamp ||
      !sha256_parts(workblock, size, stamp, RNC_STAMP_SIZE, hash))
    return 0;
  return meets_cost(hash, cost);
}
rnc_result rnc_stamp_find(const uint8_t *workblock, size_t workblock_size,
                          unsigned cost, uint8_t cursor[RNC_STAMP_SIZE],
                          uint64_t attempts, uint8_t stamp[RNC_STAMP_SIZE]) {
  rnc_sha256_ctx base, work;
  uint8_t candidate[RNC_STAMP_SIZE], hash[32];
  uint64_t attempt;
  unsigned i;
  rnc_result r = RNC_AGAIN;
  if (!workblock || !workblock_size || cost > 256 || !cursor || !stamp)
    return RNC_INVALID;
  memcpy(candidate, cursor, sizeof(candidate));
  /* hash the workblock once; each attempt only adds the stamp */
  if (!rnc_sha256_init(&base) || !rnc_sha256_update(&base, workblock, workblock_size)) {
    rnc_sha256_discard(&base);
    return RNC_CRYPTO;
  }
  for (attempt = 0; attempt < attempts; attempt++) {
    if (!rnc_sha256_copy(&work, &base) ||
        !rnc_sha256_update(&work, candidate, sizeof(candidate)) ||
        !rnc_sha256_final(&work, hash)) {
      rnc_sha256_discard(&work);
      r = RNC_CRYPTO;
      break;
    }
    /* count up through the low 8 bytes (big endian) */
    if (meets_cost(hash, cost)) {
      memcpy(stamp, candidate, sizeof(candidate));
      r = RNC_OK;
    }
    for (i = 0; i < 8; i++)
      if (++candidate[31 - i])
        break;
    if (r == RNC_OK)
      break;
  }
  if (r == RNC_OK || r == RNC_AGAIN)
    memcpy(cursor, candidate, sizeof(candidate));
  rnc_sha256_discard(&base);
  return r;
}
rnc_result rnc_stamp_generate(const void *material, size_t size, unsigned rounds,
                              unsigned cost, rnc_random_fn random,
                              void *random_context, uint64_t max_attempts,
                              uint8_t stamp[RNC_STAMP_SIZE]) {
  uint8_t *block, cursor[RNC_STAMP_SIZE], found[RNC_STAMP_SIZE];
  size_t block_size;
  rnc_result r;
  if (!material || !size || !rounds || rounds > RNC_STAMP_MAX_ROUNDS ||
      cost > 256 || !random || !stamp)
    return RNC_INVALID;
  if (!max_attempts)
    max_attempts = UINT64_C(1) << 32;
  block = malloc((size_t)rounds * RNC_STAMP_ROUND_SIZE);
  if (!block)
    return RNC_NO_SPACE;
  r = rnc_stamp_workblock(material, size, rounds, block,
                          (size_t)rounds * RNC_STAMP_ROUND_SIZE, &block_size);
  if (r == RNC_OK)
    r = random(random_context, cursor, sizeof(cursor));
  if (r == RNC_OK) {
    r = rnc_stamp_find(block, block_size, cost, cursor, max_attempts, found);
    if (r == RNC_OK)
      memcpy(stamp, found, sizeof(found));
    else if (r == RNC_AGAIN)
      r = RNC_TIMEOUT;
  }
  rnc_cleanse(block, (size_t)rounds * RNC_STAMP_ROUND_SIZE);
  free(block);
  return r;
}
