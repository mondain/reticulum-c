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
static uint32_t seed = 31;
static rnc_result rng(void *ctx, uint8_t *p, size_t n) {
  size_t i;
  (void)ctx;
  for (i = 0; i < n; i++) {
    seed = seed * 1664525u + 1013904223u;
    p[i] = (uint8_t)(seed >> 24);
  }
  return RNC_OK;
}
static rnc_node *make(const rnc_interface_policy *first,
                      const rnc_interface_policy *second) {
  rnc_identity id;
  rnc_node *n;
  CHECK(rnc_identity_generate(&id, rng, NULL) == RNC_OK);
  n = rnc_node_new(&id, 1, rng, NULL);
  CHECK(n);
  CHECK(rnc_node_add_interface(n, 1, 1000000) == RNC_OK);
  CHECK(rnc_node_add_interface(n, 2, 1000000) == RNC_OK);
  if (first)
    CHECK(rnc_node_interface_policy(n, 1, first) == RNC_OK);
  if (second)
    CHECK(rnc_node_interface_policy(n, 2, second) == RNC_OK);
  return n;
}
static rnc_packet fresh_announce(uint64_t unix_seconds) {
  rnc_identity id;
  rnc_packet p;
  CHECK(rnc_identity_generate(&id, rng, NULL) == RNC_OK);
  CHECK(rnc_announce_create(&id, "ingress.test", NULL, 0, unix_seconds, rng,
                            NULL, &p) == RNC_OK);
  return p;
}
static int known(rnc_node *n, const rnc_packet *p, uint64_t now) {
  rnc_route r;
  return rnc_node_lookup(n, p->destination, now, &r) == RNC_OK;
}
static size_t path_requests_on(rnc_node *n, uint32_t iface) {
  rnc_node_event e;
  rnc_path_request q;
  size_t c = 0;
  while (rnc_node_poll(n, &e) == RNC_OK)
    c += e.type == RNC_NODE_SEND && e.interface_id == iface &&
         rnc_path_request_decode(&e.packet, &q) == RNC_OK;
  return c;
}
/* Eight announces for unknown destinations 100ms apart exceed the 3 Hz new
 * interface threshold; the later ones are held, then released one at a time. */
static void burst_hold(void) {
  rnc_node *n = make(NULL, NULL);
  rnc_packet a[8];
  size_t i, learned = 0;
  for (i = 0; i < 8; i++) {
    a[i] = fresh_announce(1000);
    CHECK(rnc_node_input(n, 1, &a[i], 1000, 100 * i) == RNC_OK);
  }
  for (i = 0; i < 8; i++)
    learned += known(n, &a[i], 800);
  CHECK(learned >= 2 && learned < 8);
  /* Still inside the penalty window: nothing is released. */
  CHECK(rnc_node_tick(n, 1000, 5000) == RNC_OK);
  {
    size_t before = 0;
    for (i = 0; i < 8; i++)
      before += known(n, &a[i], 5000);
    CHECK(before == learned);
  }
  /* After the 15s penalty one held announce is released per 5s interval. */
  CHECK(rnc_node_tick(n, 1000, 20000) == RNC_OK);
  {
    size_t one = 0;
    for (i = 0; i < 8; i++)
      one += known(n, &a[i], 20000);
    CHECK(one == learned + 1);
  }
  CHECK(rnc_node_tick(n, 1000, 20100) == RNC_OK);
  {
    size_t still = 0;
    for (i = 0; i < 8; i++)
      still += known(n, &a[i], 20100);
    CHECK(still == learned + 1);
  }
  CHECK(rnc_node_tick(n, 1000, 25500) == RNC_OK);
  {
    size_t two = 0;
    for (i = 0; i < 8; i++)
      two += known(n, &a[i], 25500);
    CHECK(two == learned + 2);
  }
  rnc_node_free(n);
}
static void disabled(void) {
  rnc_interface_policy policy = {0};
  rnc_node *n;
  rnc_packet a[8];
  size_t i;
  policy.ingress.disabled = 1;
  n = make(&policy, NULL);
  for (i = 0; i < 8; i++) {
    a[i] = fresh_announce(1000);
    CHECK(rnc_node_input(n, 1, &a[i], 1000, 100 * i) == RNC_OK);
    CHECK(known(n, &a[i], 100 * i));
  }
  rnc_node_free(n);
}
/* Re-announces of known destinations are governed by announce rate limits,
 * not by ingress control. */
static void known_exempt(void) {
  rnc_node *n = make(NULL, NULL);
  rnc_identity src;
  rnc_packet first, again;
  rnc_route route;
  size_t i;
  CHECK(rnc_identity_generate(&src, rng, NULL) == RNC_OK);
  CHECK(rnc_announce_create(&src, "ingress.known", NULL, 0, 1000, rng, NULL,
                            &first) == RNC_OK);
  CHECK(rnc_node_input(n, 1, &first, 1000, 0) == RNC_OK);
  for (i = 0; i < 8; i++) {
    CHECK(rnc_announce_create(&src, "ingress.known", NULL, 0, 1001 + i, rng,
                              NULL, &again) == RNC_OK);
    CHECK(rnc_node_input(n, 1, &again, 1001 + i, 10 + 10 * i) == RNC_OK);
  }
  CHECK(rnc_node_lookup(n, first.destination, 100, &route) == RNC_OK &&
        route.announced_at == 1008);
  rnc_node_free(n);
}
static rnc_packet request_for(const uint8_t dest[16], uint8_t tag) {
  rnc_packet p;
  uint8_t t[16];
  memset(t, tag, sizeof(t));
  CHECK(rnc_path_request_create(dest, NULL, t, 16, &p) == RNC_OK);
  return p;
}
/* Only modes that discover paths for their clients recurse for unknown
 * destinations; boundary interfaces search boundary and gateway peers only. */
static void search_modes(void) {
  static const rnc_interface_mode modes[] = {RNC_MODE_FULL, RNC_MODE_GATEWAY,
                                             RNC_MODE_ACCESS_POINT,
                                             RNC_MODE_ROAMING};
  static const size_t expect[] = {0, 1, 1, 1};
  uint8_t dest[16] = {9};
  size_t i;
  for (i = 0; i < 4; i++) {
    rnc_interface_policy p1 = {0};
    rnc_node *n;
    rnc_packet q = request_for(dest, (uint8_t)i);
    p1.mode = modes[i];
    n = make(&p1, NULL);
    CHECK(rnc_node_input(n, 1, &q, 1000, 0) == RNC_OK);
    CHECK(path_requests_on(n, 2) == expect[i]);
    rnc_node_free(n);
  }
  {
    rnc_interface_policy p1 = {0}, p2 = {0};
    rnc_node *n;
    rnc_packet q = request_for(dest, 77);
    p1.mode = RNC_MODE_BOUNDARY;
    p2.mode = RNC_MODE_FULL;
    n = make(&p1, &p2);
    CHECK(rnc_node_input(n, 1, &q, 1000, 0) == RNC_OK);
    CHECK(path_requests_on(n, 2) == 0);
    rnc_node_free(n);
    p2.mode = RNC_MODE_GATEWAY;
    n = make(&p1, &p2);
    q = request_for(dest, 78);
    CHECK(rnc_node_input(n, 1, &q, 1000, 0) == RNC_OK);
    CHECK(path_requests_on(n, 2) == 1);
    rnc_node_free(n);
  }
  {
    rnc_interface_policy p1 = {0};
    rnc_node *n;
    rnc_packet q = request_for(dest, 79);
    p1.recursive_path_requests = 1;
    n = make(&p1, NULL);
    CHECK(rnc_node_input(n, 1, &q, 1000, 0) == RNC_OK);
    CHECK(path_requests_on(n, 2) == 1);
    rnc_node_free(n);
  }
}
/* A flood of path requests from a gateway interface stops being forwarded. */
static void pr_burst(void) {
  rnc_interface_policy policy = {0};
  rnc_node *n;
  size_t i, forwarded = 0;
  policy.mode = RNC_MODE_GATEWAY;
  n = make(&policy, NULL);
  for (i = 0; i < 12; i++) {
    uint8_t dest[16] = {1};
    rnc_packet q;
    dest[1] = (uint8_t)i;
    q = request_for(dest, (uint8_t)i);
    CHECK(rnc_node_input(n, 1, &q, 1000, 50 * i) == RNC_OK);
    forwarded += path_requests_on(n, 2);
  }
  CHECK(forwarded >= 2 && forwarded < 12);
  rnc_node_free(n);
}
/* Egress control: recursive requests leave an interface at most ~5 Hz. */
static void egress(void) {
  rnc_interface_policy policy = {0};
  rnc_node *n;
  size_t i, forwarded = 0;
  policy.mode = RNC_MODE_GATEWAY;
  policy.ingress.disabled = 1; /* isolate egress control from burst detection */
  n = make(&policy, NULL);
  for (i = 0; i < 16; i++) {
    uint8_t dest[16] = {2};
    rnc_packet q;
    dest[1] = (uint8_t)i;
    q = request_for(dest, (uint8_t)i);
    CHECK(rnc_node_input(n, 1, &q, 1000, 20 * i) == RNC_OK);
    forwarded += path_requests_on(n, 2);
  }
  CHECK(forwarded >= 2 && forwarded < 16);
  rnc_node_free(n);
}
int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  if (!strcmp(argv[1], "burst_hold"))
    burst_hold();
  else if (!strcmp(argv[1], "disabled"))
    disabled();
  else if (!strcmp(argv[1], "known_exempt"))
    known_exempt();
  else if (!strcmp(argv[1], "search_modes"))
    search_modes();
  else if (!strcmp(argv[1], "pr_burst"))
    pr_burst();
  else if (!strcmp(argv[1], "egress"))
    egress();
  else
    return 2;
  return 0;
}
