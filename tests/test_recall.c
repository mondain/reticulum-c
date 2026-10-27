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
static uint32_t seed = 41;
static rnc_result rng(void *ctx, uint8_t *p, size_t n) {
  size_t i;
  (void)ctx;
  for (i = 0; i < n; i++) {
    seed = seed * 1664525u + 1013904223u;
    p[i] = (uint8_t)(seed >> 24);
  }
  return RNC_OK;
}
static rnc_node *make(void) {
  rnc_identity id;
  rnc_node *n;
  CHECK(rnc_identity_generate(&id, rng, NULL) == RNC_OK);
  n = rnc_node_new(&id, 0, rng, NULL);
  CHECK(n && rnc_node_add_interface(n, 1, 1000000) == RNC_OK);
  return n;
}
static rnc_packet announce(rnc_identity *id, const char *name, const char *app,
                           uint64_t unix_seconds) {
  rnc_packet p;
  CHECK(rnc_identity_generate(id, rng, NULL) == RNC_OK);
  CHECK(rnc_announce_create(id, name, app, app ? strlen(app) : 0, unix_seconds,
                            rng, NULL, &p) == RNC_OK);
  return p;
}
/* A heard announce stays recallable after its route has expired. */
static void recall(void) {
  rnc_node *n = make();
  rnc_identity id;
  rnc_packet p = announce(&id, "recall.test", "hello", 1000);
  rnc_announce a;
  rnc_route r;
  CHECK(rnc_node_recall(n, p.destination, &a) == RNC_STATE);
  CHECK(rnc_node_input(n, 1, &p, 1000, 0) == RNC_OK);
  CHECK(rnc_node_recall(n, p.destination, &a) == RNC_OK);
  CHECK(!memcmp(a.identity.public_key, id.public_key, 64));
  CHECK(a.app_size == 5 && !memcmp(a.app_data, "hello", 5));
  CHECK(rnc_node_tick(n, 1000, UINT64_C(700000000)) == RNC_OK);
  CHECK(rnc_node_lookup(n, p.destination, UINT64_C(700000000), &r) ==
        RNC_AGAIN);
  memset(&a, 0, sizeof(a));
  CHECK(rnc_node_recall(n, p.destination, &a) == RNC_OK);
  CHECK(a.app_size == 5);
  rnc_node_free(n);
}
/* A newer announce replaces app data; an older replayed one does not. */
static void refresh(void) {
  rnc_node *n = make();
  rnc_identity id;
  rnc_packet first = announce(&id, "recall.refresh", "one", 1000), second;
  rnc_announce a;
  CHECK(rnc_node_input(n, 1, &first, 1000, 0) == RNC_OK);
  CHECK(rnc_announce_create(&id, "recall.refresh", "two", 3, 1100, rng, NULL,
                            &second) == RNC_OK);
  CHECK(rnc_node_input(n, 1, &second, 1100, 10) == RNC_OK);
  CHECK(rnc_node_recall(n, first.destination, &a) == RNC_OK && a.app_size == 3 &&
        !memcmp(a.app_data, "two", 3));
  CHECK(rnc_node_input(n, 1, &first, 1100, 20) == RNC_OK);
  CHECK(rnc_node_recall(n, first.destination, &a) == RNC_OK &&
        !memcmp(a.app_data, "two", 3));
  rnc_node_free(n);
}
/* The table is bounded; the least recently heard entry is evicted. */
static void bounded(void) {
  rnc_node *n = make();
  rnc_packet first = {0}, p;
  rnc_identity id;
  rnc_announce a;
  rnc_node_event drain;
  size_t i;
  for (i = 0; i < RNC_NODE_KNOWN + 5; i++) {
    p = announce(&id, "recall.bound", NULL, 1000);
    if (!i)
      first = p;
    /* Space announces past route lifetime so only the known table fills. */
    CHECK(rnc_node_input(n, 1, &p, 1000, UINT64_C(700000000) * i) == RNC_OK);
    while (rnc_node_poll(n, &drain) == RNC_OK) {
    }
    CHECK(rnc_node_tick(n, 1000, UINT64_C(700000000) * i) == RNC_OK);
  }
  CHECK(rnc_node_recall(n, first.destination, &a) == RNC_STATE);
  CHECK(rnc_node_recall(n, p.destination, &a) == RNC_OK);
  rnc_node_free(n);
}
static void persistence(void) {
  rnc_node *n = make(), *m = make();
  rnc_identity id;
  rnc_packet p = announce(&id, "recall.save", "kept", 1000);
  rnc_announce a;
  static uint8_t blob[300000];
  size_t size = 0;
  CHECK(rnc_node_input(n, 1, &p, 1000, 0) == RNC_OK);
  CHECK(rnc_node_known_export(n, blob, sizeof(blob), &size) == RNC_OK &&
        size > 0);
  CHECK(rnc_node_known_import(m, blob, size) == RNC_OK);
  CHECK(rnc_node_recall(m, p.destination, &a) == RNC_OK && a.app_size == 4);
  /* Any modification is rejected as a whole. */
  blob[size / 2] ^= 1;
  CHECK(rnc_node_known_import(make(), blob, size) == RNC_AUTH);
  blob[size / 2] ^= 1;
  CHECK(rnc_node_known_export(n, blob, 8, &size) == RNC_NO_SPACE);
  rnc_node_free(n);
  rnc_node_free(m);
}
static void aspect(void) {
  rnc_identity id;
  rnc_packet p = announce(&id, "app.chat.v1", NULL, 1000);
  rnc_announce a;
  CHECK(rnc_announce_verify(&p, &a) == RNC_OK);
  CHECK(rnc_announce_matches_aspect(&a, "app.chat.v1") == 1);
  CHECK(rnc_announce_matches_aspect(&a, "app.chat.v2") == 0);
  CHECK(rnc_announce_matches_aspect(&a, "") == 0);
}
int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  if (!strcmp(argv[1], "recall"))
    recall();
  else if (!strcmp(argv[1], "refresh"))
    refresh();
  else if (!strcmp(argv[1], "bounded"))
    bounded();
  else if (!strcmp(argv[1], "persistence"))
    persistence();
  else if (!strcmp(argv[1], "aspect"))
    aspect();
  else
    return 2;
  return 0;
}
