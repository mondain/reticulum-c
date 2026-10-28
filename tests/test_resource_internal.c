/* White-box checks of the Resource timeout formulas. Expected values were
 * computed with the reference's own arithmetic (Resource.py update_eifr and
 * the watchdog job) in floating point; integer milliseconds may differ by a
 * rounding step. */
#include <stdio.h>
#include "../src/resource.c"

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d %s\n", __FILE__, __LINE__, #x);                   \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static int near_value(uint64_t got, uint64_t want, uint64_t tolerance) {
  return got + tolerance >= want && got <= want + tolerance;
}
static void eifr_estimate(void) {
  /* measured data rate wins (bytes/s to bits/s) */
  CHECK(resource_eifr_bps(618, 0, 287, 50) == 4944);
  /* otherwise the previous resource's rate */
  CHECK(resource_eifr_bps(0, 12345, 287, 50) == 12345);
  /* otherwise link establishment cost over the link RTT */
  CHECK(resource_eifr_bps(0, 0, 287, 50) == 45920);
  /* a zero RTT must not divide by zero */
  CHECK(resource_eifr_bps(0, 0, 287, 0) > 0);
}
static void receiver_timeout(void) {
  /* steady state: two requested rounds' worth of parts still outstanding */
  CHECK(near_value(resource_part_timeout_ms(464, 5, 4944, 1, 2, 0, 0), 7758, 2));
  /* before any response: the reference's short initial wait */
  CHECK(near_value(resource_part_timeout_ms(464, 4, 45920, 0, 4, 0, 0), 371, 2));
  CHECK(near_value(resource_part_timeout_ms(464, 4, 12345, 0, 4, 0, 0), 701, 2));
  /* waiting for a hashmap update, three retries used */
  CHECK(near_value(resource_part_timeout_ms(464, 0, 4944, 1, 2, 1, 3), 4378, 2));
  /* a very slow measured rate gives minutes, not the old fixed 2 s */
  CHECK(near_value(resource_part_timeout_ms(464, 10, 320, 1, 2, 0, 1), 232750, 3));
  /* each retry adds half a second */
  CHECK(resource_part_timeout_ms(464, 5, 4944, 1, 2, 0, 4) ==
        resource_part_timeout_ms(464, 5, 4944, 1, 2, 0, 0) + 2000);
}
static void sender_timeouts(void) {
  CHECK(resource_sender_timeout_ms(RES_TX_ADV, 50) == 1300);
  CHECK(resource_sender_timeout_ms(RES_TX_DATA, 50) == 82800);
  CHECK(resource_sender_timeout_ms(RES_TX_PROOF, 50) == 10150);
}
int main(void) {
  eifr_estimate();
  receiver_timeout();
  sender_timeouts();
  puts("resource timeout tests passed");
  return 0;
}
