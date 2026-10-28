/* Compiles the portable backend with a distinct symbol prefix for the differential test. */
#define RNC_BE(n) port_##n
#include "../src/crypto_portable.c"
