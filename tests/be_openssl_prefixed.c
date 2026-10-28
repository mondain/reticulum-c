/* Compiles the OpenSSL backend with a distinct symbol prefix for the differential test. */
#define RNC_BE(n) rncossl_##n
#include "../src/crypto_openssl.c"
