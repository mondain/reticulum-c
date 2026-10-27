#ifndef RETICULUM_C_I2P_H
#define RETICULUM_C_I2P_H
/* I2P pieces that need no sockets: the I2P base64 alphabet, destination and
 * b32 address handling, and SAM v3 reply parsing. The host adapter drives the
 * SAM conversation itself. */
#include <reticulum_c/rnc.h>
#ifdef __cplusplus
extern "C" {
#endif
/* "<52 base32 characters>" plus a terminator; the address is that text with
 * ".b32.i2p" appended. */
#define RNC_I2P_B32_SIZE 53u
#define RNC_I2P_REPLY_MAX 2048u
/* I2P base64 uses '-' and '~' where the standard alphabet has '+' and '/'.
 * Padding is required on decode. Capacity includes the terminator for encode. */
rnc_result rnc_i2p_b64_encode(const uint8_t *data, size_t size, char *out,
                              size_t capacity);
rnc_result rnc_i2p_b64_decode(const char *text, uint8_t *out, size_t capacity,
                              size_t *written);
/* Length of the destination at the start of data (a public destination or a
 * private key): 387 bytes plus the certificate length it declares. */
rnc_result rnc_i2p_destination_size(const uint8_t *data, size_t size,
                                    size_t *destination_size);
/* Lower-case base32 of the SHA-256 of the binary destination. */
rnc_result rnc_i2p_b32(const uint8_t *destination, size_t size,
                       char out[RNC_I2P_B32_SIZE]);
/* The destination (base64) contained in a base64 private key. */
rnc_result rnc_i2p_private_to_public(const char *private_key, char *out,
                                     size_t capacity);
/* One SAM reply line. */
typedef struct rnc_i2p_reply {
  char topic[16], action[16];
  int ok; /* RESULT=OK */
  char line[RNC_I2P_REPLY_MAX];
} rnc_i2p_reply;
rnc_result rnc_i2p_reply_parse(const char *line, rnc_i2p_reply *out);
/* STATE when the key is absent; quoted values are returned without quotes. */
rnc_result rnc_i2p_reply_value(const rnc_i2p_reply *reply, const char *key,
                               char *out, size_t capacity);
#ifdef __cplusplus
}
#endif
#endif
