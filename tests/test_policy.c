#include <reticulum_c/rnc_node.h>
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
static uint32_t seed = 5;
static rnc_result rng(void *ctx, uint8_t *p, size_t n) {
  size_t i;
  (void)ctx;
  for (i = 0; i < n; i++) {
    seed = seed * 1664525u + 1013904223u;
    p[i] = (uint8_t)(seed >> 24);
  }
  return RNC_OK;
}
static rnc_node *transport(const uint32_t *ids, const rnc_interface_mode *modes,
                           size_t count, uint32_t bitrate) {
  rnc_identity id;
  rnc_node *n;
  size_t i;
  CHECK(rnc_identity_generate(&id, rng, NULL) == RNC_OK);
  n = rnc_node_new(&id, 1, rng, NULL);
  CHECK(n);
  for (i = 0; i < count; i++) {
    rnc_interface_policy policy = {0};
    policy.mode = modes[i];
    CHECK(rnc_node_add_interface(n, ids[i], bitrate) == RNC_OK);
    CHECK(rnc_node_interface_policy(n, ids[i], &policy) == RNC_OK);
  }
  return n;
}
static rnc_packet announce_for(const char *name, uint64_t unix_seconds) {
  rnc_identity id;
  rnc_packet p;
  CHECK(rnc_identity_generate(&id, rng, NULL) == RNC_OK);
  CHECK(rnc_announce_create(&id, name, NULL, 0, unix_seconds, rng, NULL, &p) ==
        RNC_OK);
  return p;
}
/* Count SEND events per interface after a long tick. */
static size_t sends_on(rnc_node *n, uint32_t iface) {
  rnc_node_event e;
  size_t c = 0;
  while (rnc_node_poll(n, &e) == RNC_OK)
    c += e.type == RNC_NODE_SEND && e.interface_id == iface;
  return c;
}
static size_t relayed(rnc_interface_mode in, rnc_interface_mode out) {
  static const uint32_t ids[2] = {1, 2};
  rnc_interface_mode modes[2];
  rnc_node *n;
  rnc_packet p = announce_for("policy.relay", 1000);
  size_t c;
  modes[0] = in;
  modes[1] = out;
  n = transport(ids, modes, 2, 1000000);
  CHECK(rnc_node_input(n, 1, &p, 1000, 0) == RNC_OK);
  CHECK(rnc_node_tick(n, 1000, 1000) == RNC_OK);
  c = sends_on(n, 2);
  rnc_node_free(n);
  return c;
}
static void modes(void) {
  /* Access points stay quiet; others receive announces. */
  CHECK(relayed(RNC_MODE_FULL, RNC_MODE_FULL) == 1);
  CHECK(relayed(RNC_MODE_FULL, RNC_MODE_GATEWAY) == 1);
  CHECK(relayed(RNC_MODE_FULL, RNC_MODE_ACCESS_POINT) == 0);
  /* Roaming and boundary segments do not feed each other or roaming peers. */
  CHECK(relayed(RNC_MODE_FULL, RNC_MODE_ROAMING) == 1);
  CHECK(relayed(RNC_MODE_ROAMING, RNC_MODE_ROAMING) == 0);
  CHECK(relayed(RNC_MODE_BOUNDARY, RNC_MODE_ROAMING) == 0);
  CHECK(relayed(RNC_MODE_ROAMING, RNC_MODE_BOUNDARY) == 0);
  CHECK(relayed(RNC_MODE_ROAMING, RNC_MODE_FULL) == 1);
  CHECK(relayed(RNC_MODE_BOUNDARY, RNC_MODE_FULL) == 1);
}
static void expiry(void) {
  static const rnc_interface_mode kinds[3] = {
      RNC_MODE_FULL, RNC_MODE_ACCESS_POINT, RNC_MODE_ROAMING};
  static const uint64_t lifetime[3] = {UINT64_C(604800000), UINT64_C(86400000),
                                       UINT64_C(21600000)};
  size_t i;
  for (i = 0; i < 3; i++) {
    static const uint32_t ids[1] = {1};
    rnc_node *n = transport(ids, &kinds[i], 1, 1000000);
    rnc_packet p = announce_for("policy.expiry", 1000);
    rnc_route r;
    CHECK(rnc_node_input(n, 1, &p, 1000, 0) == RNC_OK);
    CHECK(rnc_node_lookup(n, p.destination, lifetime[i] - 1, &r) == RNC_OK);
    CHECK(rnc_node_lookup(n, p.destination, lifetime[i], &r) == RNC_AGAIN);
    rnc_node_free(n);
  }
}
/* Two queued announces share one interface; the cap sets their spacing. */
static size_t second_after(uint32_t permille, uint64_t gap) {
  static const uint32_t ids[2] = {1, 2};
  static const rnc_interface_mode m[2] = {RNC_MODE_FULL, RNC_MODE_FULL};
  rnc_node *n = transport(ids, m, 2, 10000);
  rnc_interface_policy policy = {0};
  rnc_packet a = announce_for("policy.cap.a", 1000);
  rnc_packet b = announce_for("policy.cap.b", 1000);
  size_t first, second;
  policy.announce_cap_permille = permille;
  CHECK(rnc_node_interface_policy(n, 2, &policy) == RNC_OK);
  CHECK(rnc_node_input(n, 1, &a, 1000, 0) == RNC_OK);
  CHECK(rnc_node_input(n, 1, &b, 1000, 0) == RNC_OK);
  CHECK(rnc_node_tick(n, 1000, 1000) == RNC_OK);
  first = sends_on(n, 2);
  CHECK(first == 1);
  CHECK(rnc_node_tick(n, 1000, 1000 + gap) == RNC_OK);
  second = sends_on(n, 2);
  rnc_node_free(n);
  return second;
}
static void cap(void) {
  /* Relayed announces are 183 wire bytes: at 10 kbit/s, 2 percent spaces them ~7.3 s. */
  CHECK(second_after(0, 1000) == 0);
  CHECK(second_after(20, 1000) == 0);
  CHECK(second_after(0, 8000) == 1);
  /* 20 percent shrinks the spacing tenfold. */
  CHECK(second_after(200, 1000) == 1);
  CHECK(second_after(200, 300) == 0);
}
static void invalid(void) {
  static const uint32_t ids[1] = {1};
  static const rnc_interface_mode m[1] = {RNC_MODE_FULL};
  rnc_node *n = transport(ids, m, 1, 1000);
  rnc_interface_policy policy = {0};
  CHECK(rnc_node_interface_policy(n, 9, &policy) == RNC_STATE);
  policy.mode = (rnc_interface_mode)99;
  CHECK(rnc_node_interface_policy(n, 1, &policy) == RNC_INVALID);
  policy.mode = RNC_MODE_FULL;
  policy.announce_cap_permille = 1001;
  CHECK(rnc_node_interface_policy(n, 1, &policy) == RNC_INVALID);
  CHECK(rnc_node_interface_policy(n, 1, NULL) == RNC_INVALID);
  rnc_node_free(n);
}
int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  if (!strcmp(argv[1], "modes"))
    modes();
  else if (!strcmp(argv[1], "expiry"))
    expiry();
  else if (!strcmp(argv[1], "cap"))
    cap();
  else if (!strcmp(argv[1], "invalid"))
    invalid();
  else
    return 2;
  return 0;
}
