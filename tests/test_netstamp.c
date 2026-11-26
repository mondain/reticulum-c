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
/* Identity(value=n): the encryption key is searched until it is a stamp over the signature key. */
static void identity_stamp(void) {
  rnc_identity id, loaded, plain, untouched;
  uint8_t signature[64], cipher[256], clear[64];
  uint64_t attempts = 0;
  size_t size, got;
  memset(&id, 0, sizeof(id));
  CHECK(rnc_netstamp_identity_generate(&id, 8.0, rng, NULL, 0, &attempts) == RNC_OK && attempts > 0);
  CHECK(id.has_private && rnc_netstamp_identity_value(&id) >= 8.0);
  CHECK(rnc_netstamp_valid(id.public_key + 32, 32, id.public_key, 32, 8.0));
  CHECK(rnc_netstamp_value(id.public_key + 32, 32, id.public_key, 32) == rnc_netstamp_identity_value(&id));
  /* it is an ordinary identity: the private key loads, signs and decrypts */
  CHECK(rnc_identity_from_private(&loaded, id.private_key) == RNC_OK && !memcmp(loaded.public_key, id.public_key, 64) &&
        !memcmp(loaded.hash, id.hash, 16));
  CHECK(rnc_identity_sign(&id, "stamped", 7, signature) == RNC_OK &&
        rnc_identity_verify(&id, "stamped", 7, signature) == RNC_OK);
  CHECK(rnc_identity_encrypt(&id, "secret", 6, rng, NULL, cipher, sizeof(cipher), &size) == RNC_OK);
  CHECK(rnc_identity_decrypt(&loaded, cipher, size, clear, sizeof(clear), &got) == RNC_OK && got == 6 &&
        !memcmp(clear, "secret", 6));
  CHECK(rnc_netstamp_identity_generate(&plain, 0, rng, NULL, 0, NULL) == RNC_OK && plain.has_private);
  /* running out of attempts, or bad arguments, leave the identity alone */
  memset(&id, 0xa5, sizeof(id));
  memset(&untouched, 0xa5, sizeof(untouched));
  CHECK(rnc_netstamp_identity_generate(&id, 40.0, rng, NULL, 1, NULL) == RNC_TIMEOUT);
  CHECK(rnc_netstamp_identity_generate(&id, 100.5, rng, NULL, 1, NULL) == RNC_INVALID);
  CHECK(rnc_netstamp_identity_generate(&id, -1, rng, NULL, 1, NULL) == RNC_INVALID);
  CHECK(rnc_netstamp_identity_generate(&id, 8.0, NULL, NULL, 1, NULL) == RNC_INVALID);
  CHECK(rnc_netstamp_identity_generate(NULL, 8.0, rng, NULL, 1, NULL) == RNC_INVALID);
  CHECK(!memcmp(&id, &untouched, sizeof(id)));
  CHECK(rnc_netstamp_identity_value(NULL) == 0);
}
/* The 18 byte extension at the end of announce app data (Destination._announce): marker 0xC1, a reserved flags
 * byte, the 14 byte stamp, then the announced link request cost as its fraction byte and its integer byte. */
static void ext_roundtrip(void) {
  uint8_t stamp[14], ext[RNC_NETSTAMP_EXT_SIZE], app[40];
  rnc_netstamp_ext got;
  size_t i;
  for (i = 0; i < 14; i++)
    stamp[i] = (uint8_t)(0x10 + i);
  CHECK(rnc_netstamp_ext_build(stamp, 12.5, ext) == RNC_OK);
  CHECK(ext[0] == 0xc1 && ext[1] == 0x00 && !memcmp(ext + 2, stamp, 14) && ext[16] == 0x80 && ext[17] == 12);
  CHECK(rnc_netstamp_ext_parse(ext, sizeof(ext), &got) == 1);
  CHECK(!memcmp(got.stamp, stamp, 14) && got.link_cost == 12.5 && got.app_size == 0);
  /* app data in front of it stays, and is what app_size counts */
  memset(app, 0x55, 22);
  memcpy(app + 22, ext, sizeof(ext));
  CHECK(rnc_netstamp_ext_parse(app, 22 + sizeof(ext), &got) == 1 && got.app_size == 22);
  CHECK(rnc_netstamp_ext_build(stamp, 500.0, ext) == RNC_OK && ext[16] == 0 && ext[17] == 100); /* capped */
}
static void ext_rejects(void) {
  uint8_t stamp[14] = {0}, ext[RNC_NETSTAMP_EXT_SIZE], bad[RNC_NETSTAMP_EXT_SIZE];
  rnc_netstamp_ext got;
  memset(&got, 0x77, sizeof(got));
  CHECK(rnc_netstamp_ext_build(stamp, 12.5, ext) == RNC_OK);
  memcpy(bad, ext, sizeof(ext));
  bad[0] = 0xc0; /* wrong marker */
  CHECK(rnc_netstamp_ext_parse(bad, sizeof(bad), &got) == 0);
  memcpy(bad, ext, sizeof(ext));
  bad[17] |= 0x80; /* reserved extension bit set */
  CHECK(rnc_netstamp_ext_parse(bad, sizeof(bad), &got) == 0);
  memcpy(bad, ext, sizeof(ext));
  bad[17] = 101; /* a cost above the cap */
  bad[16] = 0;
  CHECK(rnc_netstamp_ext_parse(bad, sizeof(bad), &got) == 0);
  CHECK(rnc_netstamp_ext_parse(ext, sizeof(ext) - 1, &got) == 0); /* too short */
  CHECK(rnc_netstamp_ext_parse(NULL, 0, &got) == 0);
  {
    size_t sentinel;
    memset(&sentinel, 0x77, sizeof(sentinel));
    CHECK(got.app_size == sentinel); /* untouched on every refusal (size_t is 32 bits on armv6/armv7) */
  }
  memcpy(bad, ext, sizeof(ext));
  bad[1] = 0x42; /* the flags byte is reserved for the future and not checked, as in the reference */
  CHECK(rnc_netstamp_ext_parse(bad, sizeof(bad), &got) == 1);
}
/* The announce stamp material is destination hash, public key and name hash, in that order. */
static void announce_material(void) {
  uint8_t dest[16], pub[64], name[10], out[90];
  size_t i;
  for (i = 0; i < 16; i++) dest[i] = (uint8_t)i;
  for (i = 0; i < 64; i++) pub[i] = (uint8_t)(0x20 + i);
  for (i = 0; i < 10; i++) name[i] = (uint8_t)(0xa0 + i);
  rnc_netstamp_announce_material(dest, pub, name, out);
  CHECK(!memcmp(out, dest, 16) && !memcmp(out + 16, pub, 64) && !memcmp(out + 80, name, 10));
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
  else if (!strcmp(argv[1], "identity_stamp"))
    identity_stamp();
  else if (!strcmp(argv[1], "find_exhausted"))
    find_exhausted();
  else if (!strcmp(argv[1], "ext_roundtrip"))
    ext_roundtrip();
  else if (!strcmp(argv[1], "ext_rejects"))
    ext_rejects();
  else if (!strcmp(argv[1], "announce_material"))
    announce_material();
  else
    CHECK(0);
  puts("netstamp test passed");
  return 0;
}
