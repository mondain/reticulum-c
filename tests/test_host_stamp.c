/* The host library stamps link requests on several threads: a stamped key for a cost the single threaded default would
 * need seconds for, a refusal when the trial budget runs out, and the hook the node daemon uses (always stamping). */
#include <reticulum_c/rnc_host.h>
#include <reticulum_c/rnc_netstamp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                  \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static uint32_t seed = 17;
static rnc_result rng(void *ctx, uint8_t *p, size_t n) {
  size_t i;
  (void)ctx;
  for (i = 0; i < n; i++) {
    seed = seed * 1664525u + 1013904223u;
    p[i] = (uint8_t)(seed >> 24);
  }
  return RNC_OK;
}
int main(void) {
  rnc_identity me;
  rnc_node *node;
  rnc_host *host;
  uint8_t material[48], priv[32], pub[32], seed64[64] = {0};
  rnc_identity id;
  size_t i;
  CHECK(rnc_identity_generate(&me, rng, NULL) == RNC_OK);
  node = rnc_node_new(&me, 0, rng, NULL);
  host = rnc_host_new(node);
  CHECK(node && host);
  for (i = 0; i < sizeof(material); i++)
    material[i] = (uint8_t)(i * 11 + 5);
  /* a host that stamps with 4 workers: the key meets cost 15 over the material and belongs to its private half */
  CHECK(rnc_host_set_link_stamping(host, 4, 0, 0) == RNC_OK);
  CHECK(rnc_host_link_stamper(host, material, 15.0, priv, pub) == 1);
  CHECK(rnc_netstamp_valid(material, sizeof(material), pub, 32, 15.0));
  memcpy(seed64, priv, 32);
  CHECK(rnc_identity_from_private(&id, seed64) == RNC_OK && !memcmp(id.public_key, pub, 32));
  /* a trial budget that runs out fails the stamp instead of hanging */
  CHECK(rnc_host_set_link_stamping(host, 2, 20000, 0) == RNC_OK);
  CHECK(rnc_host_link_stamper(host, material, 60.0, priv, pub) == 0);
  /* a worker count of 0 means one per core, and nonsense is refused */
  CHECK(rnc_host_set_link_stamping(host, 0, 0, 1) == RNC_OK);
  CHECK(rnc_host_set_link_stamping(host, 1000, 0, 0) == RNC_INVALID);
  rnc_host_free(host);
  rnc_node_free(node);
  puts("host stamp tests passed");
  return 0;
}
