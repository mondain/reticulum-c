/* Path request stamps (RNS 1.6), shared by the daemon and the command line tools: the search runs inline, since
 * at the reference's value of 15.8 it takes milliseconds, and gives up after `timeout` seconds. */
#ifndef RNC_EXAMPLES_PR_STAMP_H
#define RNC_EXAMPLES_PR_STAMP_H
#include <openssl/rand.h>
#include <reticulum_c/rnc_netstamp.h>
#include <reticulum_c/rnc_node.h>
#include <stdint.h>
#include <time.h>
#define PR_STAMP_VALUE 15.8
#define PR_STAMP_TIMEOUT 15.0
static inline rnc_result stamp_random(void *context, uint8_t *out, size_t size) {
  (void)context;
  return size <= 0x7fffffffu && RAND_priv_bytes(out, (int)size) == 1 ? RNC_OK : RNC_CRYPTO;
}
static inline uint64_t stamp_now_ms(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t) < 0)
    return 0;
  return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
static inline int pr_stamp_search(const uint8_t material[32], double value, double timeout,
                                  uint8_t stamp[RNC_NETSTAMP_SIZE]) {
  uint64_t deadline = stamp_now_ms() + (uint64_t)(timeout * 1000.0);
  do {
    rnc_result r = rnc_netstamp_find(material, 32, value, stamp_random, NULL, 1u << 14, stamp, NULL);
    if (r == RNC_OK)
      return 1;
    if (r != RNC_TIMEOUT)
      return 0;
  } while (stamp_now_ms() < deadline);
  return 0;
}
/* An rnc_stamp_provider_fn with the reference's defaults, for rnc_node_set_stamp_provider. */
static inline int pr_stamp_default_provider(void *context, const uint8_t material[32],
                                            uint8_t stamp[RNC_NETSTAMP_SIZE]) {
  (void)context;
  return pr_stamp_search(material, PR_STAMP_VALUE, PR_STAMP_TIMEOUT, stamp);
}
#endif
