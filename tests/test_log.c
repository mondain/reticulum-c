#include <reticulum_c/rnc_link.h>
#include <reticulum_c/rnc_log.h>
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
typedef struct sink {
  unsigned count;
  int level;
  char module[32], message[RNC_LOG_MESSAGE_MAX + 8];
} sink;
static void collect(void *context, int level, const char *module,
                    const char *message) {
  sink *s = context;
  s->count++;
  s->level = level;
  snprintf(s->module, sizeof(s->module), "%s", module);
  snprintf(s->message, sizeof(s->message), "%s", message);
}
static void levels_and_filtering(void) {
  sink s = {0};
  rnc_log_set_handler(NULL, NULL);
  rnc_log_set_level(RNC_LOG_NOTICE);
  CHECK(rnc_log_level() == RNC_LOG_NOTICE);
  /* silent without a handler, and cheap to ask */
  rnc_logf(RNC_LOG_ERROR, "test", "nobody listens");
  rnc_log_set_handler(collect, &s);
  CHECK(rnc_log_enabled(RNC_LOG_NOTICE) && rnc_log_enabled(RNC_LOG_CRITICAL));
  CHECK(!rnc_log_enabled(RNC_LOG_INFO) && !rnc_log_enabled(RNC_LOG_DEBUG));
  rnc_logf(RNC_LOG_DEBUG, "test", "too chatty");
  CHECK(s.count == 0);
  rnc_logf(RNC_LOG_WARNING, "link", "closed after %d ms (%s)", 42, "timeout");
  CHECK(s.count == 1 && s.level == RNC_LOG_WARNING &&
        !strcmp(s.module, "link") &&
        !strcmp(s.message, "closed after 42 ms (timeout)"));
  rnc_log_set_level(RNC_LOG_DEBUG);
  rnc_logf(RNC_LOG_DEBUG, "node", "now visible");
  CHECK(s.count == 2 && !strcmp(s.message, "now visible"));
  rnc_logf(RNC_LOG_EXTREME, "node", "still hidden");
  CHECK(s.count == 2);
  /* NONE silences everything, even critical */
  rnc_log_set_level(RNC_LOG_NONE);
  CHECK(!rnc_log_enabled(RNC_LOG_CRITICAL));
  rnc_logf(RNC_LOG_CRITICAL, "node", "silenced");
  CHECK(s.count == 2);
  /* out-of-range levels clamp */
  rnc_log_set_level(99);
  CHECK(rnc_log_level() == RNC_LOG_EXTREME);
  rnc_log_set_level(-50);
  CHECK(rnc_log_level() == RNC_LOG_NONE);
  rnc_log_set_level(RNC_LOG_NOTICE);
  rnc_log_set_handler(NULL, NULL);
}
static void truncation(void) {
  sink s = {0};
  char big[2000];
  memset(big, 'x', sizeof(big) - 1);
  big[sizeof(big) - 1] = 0;
  rnc_log_set_handler(collect, &s);
  rnc_log_set_level(RNC_LOG_DEBUG);
  rnc_logf(RNC_LOG_INFO, "test", "%s", big);
  CHECK(s.count == 1 && strlen(s.message) == RNC_LOG_MESSAGE_MAX - 1 &&
        s.message[0] == 'x');
  rnc_logf(RNC_LOG_INFO, NULL, "no module");
  CHECK(s.count == 2 && !strcmp(s.module, "") && !strcmp(s.message, "no module"));
  rnc_logf(RNC_LOG_INFO, "test", NULL);
  CHECK(s.count == 2);
  rnc_log_set_level(RNC_LOG_NOTICE);
  rnc_log_set_handler(NULL, NULL);
}
static void names(void) {
  CHECK(!strcmp(rnc_log_level_name(RNC_LOG_CRITICAL), "[Critical]"));
  CHECK(!strcmp(rnc_log_level_name(RNC_LOG_ERROR), "[Error]   "));
  CHECK(!strcmp(rnc_log_level_name(RNC_LOG_WARNING), "[Warning] "));
  CHECK(!strcmp(rnc_log_level_name(RNC_LOG_NOTICE), "[Notice]  "));
  CHECK(!strcmp(rnc_log_level_name(RNC_LOG_INFO), "[Info]    "));
  CHECK(!strcmp(rnc_log_level_name(RNC_LOG_VERBOSE), "[Verbose] "));
  CHECK(!strcmp(rnc_log_level_name(RNC_LOG_DEBUG), "[Debug]   "));
  CHECK(!strcmp(rnc_log_level_name(RNC_LOG_PATHING), "[Pathing] "));
  CHECK(!strcmp(rnc_log_level_name(RNC_LOG_EXTREME), "[Extra]   "));
  CHECK(!strcmp(rnc_log_level_name(RNC_LOG_NONE), "Unknown"));
  CHECK(!strcmp(rnc_log_level_name(42), "Unknown"));
}
/* every message, kept, to look for particular events */
typedef struct journal {
  unsigned count;
  struct {
    int level;
    char module[16], message[200];
  } entry[64];
} journal;
static void record(void *context, int level, const char *module,
                   const char *message) {
  journal *j = context;
  if (j->count < 64) {
    j->entry[j->count].level = level;
    snprintf(j->entry[j->count].module, sizeof(j->entry[0].module), "%s", module);
    snprintf(j->entry[j->count].message, sizeof(j->entry[0].message), "%s", message);
  }
  j->count++;
}
static const char *find(const journal *j, const char *module, const char *needle,
                        int *level) {
  unsigned i;
  for (i = 0; i < j->count && i < 64; i++)
    if (!strcmp(j->entry[i].module, module) && strstr(j->entry[i].message, needle)) {
      if (level)
        *level = j->entry[i].level;
      return j->entry[i].message;
    }
  return NULL;
}
static uint32_t seed = 21;
static rnc_result rng(void *ctx, uint8_t *p, size_t n) {
  size_t i;
  (void)ctx;
  for (i = 0; i < n; i++) {
    seed = seed * 1664525u + 1013904223u;
    p[i] = (uint8_t)(seed >> 24);
  }
  return RNC_OK;
}
static void node_events(void) {
  journal j = {0};
  rnc_identity own, peer;
  rnc_node *n;
  rnc_packet p;
  int level = -1;
  CHECK(rnc_identity_generate(&own, rng, NULL) == RNC_OK);
  CHECK(rnc_identity_generate(&peer, rng, NULL) == RNC_OK);
  n = rnc_node_new(&own, 0, rng, NULL);
  CHECK(n && rnc_node_add_interface(n, 1, 1000000) == RNC_OK);
  rnc_log_set_handler(record, &j);
  rnc_log_set_level(RNC_LOG_DEBUG);
  CHECK(rnc_announce_create(&peer, "log.node", NULL, 0, 1000, rng, NULL, &p) ==
        RNC_OK);
  CHECK(rnc_node_input(n, 1, &p, 1000, 0) == RNC_OK);
  CHECK(find(&j, "node", "learned path", &level) && level == RNC_LOG_DEBUG);
  /* a blackholed identity's announce is dropped, and the log says why */
  CHECK(rnc_node_blackhole(n, peer.hash, 0, "test", 1000) == RNC_OK);
  CHECK(rnc_announce_create(&peer, "log.node", NULL, 0, 1001, rng, NULL, &p) ==
        RNC_OK);
  CHECK(rnc_node_input(n, 1, &p, 1001, 10) == RNC_OK);
  CHECK(find(&j, "node", "blackholed", &level) && level == RNC_LOG_DEBUG);
  /* at the default level none of that is shown */
  j.count = 0;
  rnc_log_set_level(RNC_LOG_NOTICE);
  CHECK(rnc_announce_create(&peer, "log.node", NULL, 0, 1002, rng, NULL, &p) ==
        RNC_OK);
  CHECK(rnc_node_input(n, 1, &p, 1002, 20) == RNC_OK && j.count == 0);
  rnc_log_set_handler(NULL, NULL);
  rnc_node_free(n);
}
static void link_events(void) {
  journal j = {0};
  rnc_identity id;
  rnc_announce a;
  rnc_packet pkt;
  rnc_link *client, *server;
  rnc_link_event e;
  uint64_t now = 100;
  int level = -1;
  CHECK(rnc_identity_generate(&id, rng, NULL) == RNC_OK);
  CHECK(rnc_announce_create(&id, "log.link", NULL, 0, 1000, rng, NULL, &pkt) ==
        RNC_OK);
  CHECK(rnc_announce_verify(&pkt, &a) == RNC_OK);
  client = rnc_link_new(rng, NULL);
  server = rnc_link_new(rng, NULL);
  CHECK(client && server);
  rnc_log_set_handler(record, &j);
  rnc_log_set_level(RNC_LOG_VERBOSE);
  CHECK(rnc_link_open(client, &a, now) == RNC_OK);
  while (rnc_link_poll(client, &e) == RNC_OK)
    if (e.type == RNC_LINK_SEND)
      pkt = e.packet;
  CHECK(rnc_link_accept(server, &id, a.destination, &pkt, ++now) == RNC_OK);
  while (rnc_link_poll(server, &e) == RNC_OK)
    if (e.type == RNC_LINK_SEND)
      pkt = e.packet;
  CHECK(rnc_link_input(client, &pkt, ++now) == RNC_OK);
  CHECK(find(&j, "link", "established", &level) && level == RNC_LOG_INFO);
  j.count = 0;
  CHECK(rnc_link_close(client, ++now) == RNC_OK);
  CHECK(find(&j, "link", "closed", NULL));
  rnc_log_set_handler(NULL, NULL);
  rnc_link_free(client);
  rnc_link_free(server);
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  if (!strcmp(argv[1], "filtering"))
    levels_and_filtering();
  else if (!strcmp(argv[1], "truncation"))
    truncation();
  else if (!strcmp(argv[1], "names"))
    names();
  else if (!strcmp(argv[1], "node"))
    node_events();
  else if (!strcmp(argv[1], "link"))
    link_events();
  else
    CHECK(0);
  puts("log test passed");
  return 0;
}
