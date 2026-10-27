/* I2P helpers: the I2P base64 alphabet, destination and b32 handling against
 * values the reference's i2plib produced, and SAM reply parsing. */
#include "i2p_vectors.h"
#include <reticulum_c/rnc_i2p.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d %s\n", __FILE__, __LINE__, #x);                   \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

static void vector(const char *dest, const char *b32, const char *priv) {
  uint8_t bin[1024], again[1024];
  char text[1400], address[RNC_I2P_B32_SIZE];
  size_t n, m, len;
  CHECK(rnc_i2p_b64_decode(dest, bin, sizeof(bin), &n) == RNC_OK);
  CHECK(rnc_i2p_destination_size(bin, n, &len) == RNC_OK && len == n);
  CHECK(rnc_i2p_b64_encode(bin, n, text, sizeof(text)) == RNC_OK);
  CHECK(!strcmp(text, dest));
  CHECK(rnc_i2p_b32(bin, n, address) == RNC_OK);
  CHECK(!strcmp(address, b32));
  /* a private key starts with its destination */
  CHECK(rnc_i2p_b64_decode(priv, again, sizeof(again), &m) == RNC_OK && m > n);
  CHECK(!memcmp(again, bin, n));
  CHECK(rnc_i2p_destination_size(again, m, &len) == RNC_OK && len == n);
  CHECK(rnc_i2p_private_to_public(priv, text, sizeof(text)) == RNC_OK);
  CHECK(!strcmp(text, dest));
}

int main(void) {
  uint8_t out[8];
  char text[16];
  size_t n;
  rnc_i2p_reply reply;
  vector(V0_DEST, V0_B32, V0_PRIV);
  vector(V1_DEST, V1_B32, V1_PRIV);
  /* the alphabet swaps + and / for - and ~, and keeps padding */
  CHECK(rnc_i2p_b64_encode((const uint8_t *)"\xfb\xff\xfe", 3, text,
                           sizeof(text)) == RNC_OK);
  CHECK(!strcmp(text, "-~~-"));
  CHECK(rnc_i2p_b64_decode("-~~-", out, sizeof(out), &n) == RNC_OK && n == 3 &&
        !memcmp(out, "\xfb\xff\xfe", 3));
  CHECK(rnc_i2p_b64_encode((const uint8_t *)"ab", 2, text, sizeof(text)) ==
            RNC_OK &&
        !strcmp(text, "YWI="));
  CHECK(rnc_i2p_b64_decode("YWI", out, sizeof(out), &n) == RNC_INVALID);
  CHECK(rnc_i2p_b64_decode("Y+I=", out, sizeof(out), &n) == RNC_INVALID);
  CHECK(rnc_i2p_b64_decode("YWI=", out, 1, &n) == RNC_NO_SPACE);
  CHECK(rnc_i2p_b64_encode((const uint8_t *)"abc", 3, text, 4) ==
        RNC_NO_SPACE);
  /* too short for the certificate length, and a certificate running past it */
  {
    uint8_t d[400] = {0};
    size_t len;
    CHECK(rnc_i2p_destination_size(d, 100, &len) == RNC_INVALID);
    d[385] = 0x01;
    d[386] = 0x90;
    CHECK(rnc_i2p_destination_size(d, 390, &len) == RNC_INVALID);
  }
  /* SAM replies */
  CHECK(rnc_i2p_reply_parse("HELLO REPLY RESULT=OK VERSION=3.1", &reply) ==
        RNC_OK);
  CHECK(!strcmp(reply.topic, "HELLO") && !strcmp(reply.action, "REPLY") &&
        reply.ok);
  {
    char v[16];
    CHECK(rnc_i2p_reply_value(&reply, "VERSION", v, sizeof(v)) == RNC_OK &&
          !strcmp(v, "3.1"));
    CHECK(rnc_i2p_reply_value(&reply, "NOPE", v, sizeof(v)) == RNC_STATE);
    CHECK(rnc_i2p_reply_value(&reply, "VERSION", v, 3) == RNC_NO_SPACE);
  }
  CHECK(rnc_i2p_reply_parse("STREAM STATUS RESULT=CANT_REACH_PEER "
                            "MESSAGE=\"no route to peer\"",
                            &reply) == RNC_OK);
  CHECK(!reply.ok);
  {
    char v[40];
    CHECK(rnc_i2p_reply_value(&reply, "RESULT", v, sizeof(v)) == RNC_OK &&
          !strcmp(v, "CANT_REACH_PEER"));
    CHECK(rnc_i2p_reply_value(&reply, "MESSAGE", v, sizeof(v)) == RNC_OK &&
          !strcmp(v, "no route to peer"));
  }
  CHECK(rnc_i2p_reply_parse("", &reply) == RNC_INVALID);
  CHECK(rnc_i2p_reply_parse("HELLO", &reply) == RNC_INVALID);
  /* a keyed value that merely ends in the sought name does not match */
  CHECK(rnc_i2p_reply_parse("DEST REPLY PUB=AAAA PRIV=BBBB", &reply) == RNC_OK);
  {
    char v[16];
    CHECK(rnc_i2p_reply_value(&reply, "PRIV", v, sizeof(v)) == RNC_OK &&
          !strcmp(v, "BBBB"));
    CHECK(rnc_i2p_reply_value(&reply, "IV", v, sizeof(v)) == RNC_STATE);
  }
  puts("i2p ok");
  return 0;
}
