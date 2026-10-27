/* Link-terminating management destinations of the transport identity:
 * rnstransport.remote.management (/status, /path; identities on the allow list
 * only) and rnstransport.info.blackhole (/list; everyone), as the reference
 * Transport registers them. Included by node_daemon.c after node_rpc.h. */
#include <reticulum_c/rnc_requester.h>
#include <reticulum_c/rnc_responder.h>
typedef struct management {
  rnc_identity network;
  int has_network;
  uint8_t probe[16];
  int probing;
  rnc_responder *responder;
  rnc_requester *requester; /* blackhole source updates */
  uint64_t source_last[RNC_SERVICE_ALLOWLIST], source_retry[RNC_SERVICE_ALLOWLIST],
      source_path_since[RNC_SERVICE_ALLOWLIST],
      source_path_asked[RNC_SERVICE_ALLOWLIST];
  int source_pending[RNC_SERVICE_ALLOWLIST];
  rnc_host *host;
  rnc_node *node;
  config settings; /* a copy: the caller's config may be replaced on reload */
  const rnc_identity *identity;
  uint64_t started;
} management;
static management mgmt;
static const uint8_t *network_identity_hash(void) {
  return mgmt.has_network ? mgmt.network.hash : NULL;
}
static const uint8_t *probe_responder_hash(void) {
  return mgmt.probing ? mgmt.probe : NULL;
}
/* defined in node_discovery.h */
static void discovery_stop(void);
static int discovery_start(const config *c, const rnc_identity *transport,
                           const rnc_identity *network, rnc_node *node);
static void discovery_step(uint64_t unix_seconds, uint64_t now);
static void mgmt_stop(void) {
  discovery_stop();
  rnc_identity_clear(&mgmt.network);
  rnc_responder_free(mgmt.responder);
  rnc_requester_free(mgmt.requester);
  memset(&mgmt, 0, sizeof(mgmt));
}
/* Only the shapes the reference clients send are accepted. */
static int mp_bool_true(const uint8_t *p, size_t size, size_t index) {
  return index < size && p[index] == 0xc3;
}
static rnc_result mgmt_status(void *context, const char *path,
                              const uint8_t *request, size_t size,
                              const uint8_t *identity, uint8_t *response,
                              size_t capacity, size_t *written) {
  management *m = context;
  rnc_rpc_writer w;
  int link_count;
  (void)path;
  if (!identity || size < 2 || (request[0] & 0xf0) != 0x90 ||
      (request[0] & 0x0f) < 1)
    return RNC_AGAIN; /* the reference answers only list requests */
  link_count = mp_bool_true(request, size, 1);
  rnc_rpc_writer_init(&w, response, capacity);
  (void)rnc_rpc_write_array(&w, link_count ? 2 : 1);
  all_stats(&w, m->host, &m->settings, m->identity,
            monotonic_ms() - m->started);
  if (link_count)
    (void)rnc_rpc_write_uint(&w, rnc_node_link_count(m->node, 0));
  return rnc_rpc_writer_finish(&w, written);
}
static rnc_result mgmt_path(void *context, const char *path,
                            const uint8_t *request, size_t size,
                            const uint8_t *identity, uint8_t *response,
                            size_t capacity, size_t *written) {
  management *m = context;
  rnc_rpc_writer w;
  size_t items, at = 1, command_size;
  const uint8_t *only = NULL;
  uint32_t max_hops = 0;
  int has_max = 0;
  (void)path;
  if (!identity || size < 2 || (request[0] & 0xf0) != 0x90 ||
      (items = request[0] & 0x0f) < 1 || (request[1] & 0xe0) != 0xa0)
    return RNC_AGAIN;
  command_size = request[1] & 0x1f;
  at = 2 + command_size;
  if (at > size)
    return RNC_AGAIN;
  if (items > 1) { /* destination hash, or nil */
    if (at < size && request[at] == 0xc0)
      at++;
    else if (at + 18 <= size && request[at] == 0xc4 && request[at + 1] == 16) {
      only = request + at + 2;
      at += 18;
    } else
      return RNC_AGAIN;
  }
  if (items > 2) { /* max hops, or nil */
    if (at < size && request[at] == 0xc0)
      at++;
    else if (at < size && request[at] <= 0x7f) {
      max_hops = request[at++];
      has_max = 1;
    } else if (at + 1 < size && request[at] == 0xcc) {
      max_hops = request[at + 1];
      at += 2;
      has_max = 1;
    } else
      return RNC_AGAIN;
  }
  rnc_rpc_writer_init(&w, response, capacity);
  if (command_size == 5 && !memcmp(request + 2, "table", 5))
    write_path_table(&w, m->host, m->node, has_max, max_hops, only,
                     monotonic_ms());
  else if (command_size == 5 && !memcmp(request + 2, "rates", 5))
    (void)rnc_rpc_write_array(&w, 0); /* no rate table is kept */
  else
    return RNC_AGAIN;
  return rnc_rpc_writer_finish(&w, written);
}
static rnc_result mgmt_blackhole_list(void *context, const char *path,
                                      const uint8_t *request, size_t size,
                                      const uint8_t *identity,
                                      uint8_t *response, size_t capacity,
                                      size_t *written) {
  management *m = context;
  rnc_rpc_writer w;
  (void)path;
  (void)request;
  (void)size;
  (void)identity;
  rnc_rpc_writer_init(&w, response, capacity);
  write_blackhole_list(&w, m->node);
  return rnc_rpc_writer_finish(&w, written);
}
static int mgmt_start(const config *c, const rnc_identity *id, rnc_node *node,
                      rnc_host *host) {
  uint8_t destination[16];
  mgmt_stop();
  if (c->network_identity[0]) {
    /* The reference registers the network and per-instance destinations on the
     * network identity (they carry interface discovery). */
    char name[128];
    size_t i;
    if (rnc_host_identity_load(c->network_identity, secure_random, NULL,
                               &mgmt.network) != RNC_OK)
      return 0;
    mgmt.has_network = 1;
    (void)snprintf(name, sizeof(name), "rnstransport.network.instance.");
    for (i = 0; i < 16; ++i)
      (void)snprintf(name + strlen(name), 3, "%02x", mgmt.network.hash[i]);
    if (rnc_node_add_destination(node, &mgmt.network, name, NULL, 0,
                                 destination) != RNC_OK ||
        rnc_node_add_destination(node, &mgmt.network, "rnstransport.network",
                                 NULL, 0, destination) != RNC_OK) {
      mgmt_stop();
      return 0;
    }
  }
  mgmt.settings = *c;
  {
    size_t k;
    for (k = 0; k < mgmt.settings.count; ++k)
      interface_bind(&mgmt.settings.interfaces[k]);
  }
  mgmt.node = node;
  mgmt.host = host;
  mgmt.identity = id;
  if (!discovery_start(c, id, mgmt.has_network ? &mgmt.network : NULL, node)) {
    mgmt_stop();
    return 0;
  }
  if (c->respond_to_probes) {
    /* rnstransport.probe proves every packet it receives (PROVE_ALL) and takes
     * no links, as Transport registers it */
    if (rnc_node_add_destination(node, id, "rnstransport.probe", NULL, 0,
                                 destination) != RNC_OK ||
        rnc_node_set_proof_strategy(node, destination, RNC_PROVE_ALL) !=
            RNC_OK)
      return 0;
    memcpy(mgmt.probe, destination, 16);
    mgmt.probing = 1;
  }
  if (!c->remote_management && !c->publish_blackhole && !c->bh_source_count)
    return 1;
  if (c->remote_management || c->publish_blackhole) {
    mgmt.responder =
        rnc_responder_new(node, RNC_RPC_MESSAGE_MAX, secure_random, NULL);
    if (!mgmt.responder)
      return 0;
  }
  if (c->bh_source_count) {
    mgmt.requester =
        rnc_requester_new(node, RNC_RPC_MESSAGE_MAX, secure_random, NULL);
    if (!mgmt.requester)
      goto fail;
  }
  mgmt.host = host;
  mgmt.node = node;
  mgmt.settings = *c;
  mgmt.identity = id;
  mgmt.started = monotonic_ms();
  if (c->remote_management) {
    if (rnc_node_add_destination(node, id, "rnstransport.remote.management",
                                 NULL, 0, destination) != RNC_OK ||
        rnc_responder_add_destination(mgmt.responder, id, destination) !=
            RNC_OK ||
        rnc_responder_register(
            mgmt.responder, destination, "/status", RNC_SERVICE_ALLOW_LIST,
            (const uint8_t(*)[16])c->mgmt_allowed, c->mgmt_allowed_count,
            mgmt_status, &mgmt) != RNC_OK ||
        rnc_responder_register(
            mgmt.responder, destination, "/path", RNC_SERVICE_ALLOW_LIST,
            (const uint8_t(*)[16])c->mgmt_allowed, c->mgmt_allowed_count,
            mgmt_path, &mgmt) != RNC_OK)
      goto fail;
  }
  if (c->publish_blackhole) {
    if (rnc_node_add_destination(node, id, "rnstransport.info.blackhole", NULL,
                                 0, destination) != RNC_OK ||
        rnc_responder_add_destination(mgmt.responder, id, destination) !=
            RNC_OK ||
        rnc_responder_register(mgmt.responder, destination, "/list",
                               RNC_SERVICE_ALLOW_ALL, NULL, 0,
                               mgmt_blackhole_list, &mgmt) != RNC_OK)
      goto fail;
  }
  return 1;
fail:
  mgmt_stop();
  return 0;
}
/* Hands a LOCAL node event to whichever link engine owns it. */
static void mgmt_local_event(const rnc_node_event *event,
                             uint64_t unix_seconds, uint64_t now) {
  if (mgmt.responder &&
      rnc_responder_input(mgmt.responder, event, unix_seconds, now) !=
          RNC_AGAIN)
    return;
  if (mgmt.requester)
    (void)rnc_requester_input(mgmt.requester, event, unix_seconds, now);
}
#define BLACKHOLE_SOURCE_TIMEOUT_MS 25000u
#define BLACKHOLE_JOB_INTERVAL_MS 60000u
/* BlackholeUpdater: after an initial wait, fetch each subscribed source's
 * published list once per interval, merge the identities not yet listed and
 * keep the list on disk. */
static void blackhole_updates(uint64_t unix_seconds, uint64_t now) {
  const config *c = &mgmt.settings;
  rnc_requester_result result;
  static uint8_t response[RNC_RPC_MESSAGE_MAX];
  size_t i;
  uint64_t wait = (c->bh_initial_wait ? c->bh_initial_wait : 20u) * 1000u;
  uint64_t interval =
      (c->bh_interval_minutes ? c->bh_interval_minutes : 60u) * 60000u;
  while (rnc_requester_poll(mgmt.requester, &result, response,
                            sizeof(response)) == RNC_OK) {
    size_t source = result.tag, added = 0;
    if (source >= c->bh_source_count)
      continue;
    mgmt.source_pending[source] = 0;
    if (result.status != RNC_REQUESTER_DONE ||
        rnc_node_blackhole_merge(mgmt.node, response, result.size,
                                 c->bh_sources[source], unix_seconds,
                                 &added) != RNC_OK) {
      printf("blackhole update failed source=");
      print_hex(c->bh_sources[source], 16);
      printf("\n");
      continue;
    }
    printf("blackhole update source=");
    print_hex(c->bh_sources[source], 16);
    printf(" added=%zu\n", added);
    if (added) {
      char path[1200];
      if (blackhole_source_path(path, sizeof(path), c->bh_sources[source]))
        (void)write_file_atomic(path, response, result.size);
    }
  }
  if (now < mgmt.started + wait)
    return;
  for (i = 0; i < c->bh_source_count; ++i) {
    uint8_t destination[16], name_hash[10];
    rnc_identity source = {0};
    rnc_route route;
    const uint8_t nil = 0xc0;
    if (mgmt.source_pending[i] || now < mgmt.source_retry[i] ||
        (mgmt.source_last[i] && now < mgmt.source_last[i] + interval))
      continue;
    memcpy(source.hash, c->bh_sources[i], 16);
    if (rnc_destination_hash("rnstransport.info.blackhole", &source, name_hash,
                             destination) != RNC_OK)
      continue;
    if (rnc_node_lookup(mgmt.node, destination, now, &route) != RNC_OK) {
      if (!mgmt.source_path_since[i])
        mgmt.source_path_since[i] = now;
      /* ask again while waiting: the first request may predate the link */
      if (!mgmt.source_path_asked[i] || now - mgmt.source_path_asked[i] >= 5000u) {
        mgmt.source_path_asked[i] = now;
        (void)rnc_node_request_path(mgmt.node, destination, now);
      }
      if (now - mgmt.source_path_since[i] > BLACKHOLE_SOURCE_TIMEOUT_MS) {
        mgmt.source_path_since[i] = 0; /* no path: try again next job round */
        mgmt.source_path_asked[i] = 0;
        mgmt.source_retry[i] = now + BLACKHOLE_JOB_INTERVAL_MS;
      }
      continue;
    }
    mgmt.source_path_since[i] = 0;
    if (rnc_requester_start(mgmt.requester, destination, NULL, "/list", &nil, 1,
                            (uint32_t)i, BLACKHOLE_SOURCE_TIMEOUT_MS,
                            unix_seconds, now) == RNC_OK) {
      mgmt.source_pending[i] = 1;
      mgmt.source_last[i] = now;
    }
  }
}
static void mgmt_step(uint64_t unix_seconds, uint64_t now) {
  discovery_step(unix_seconds, now);
  if (mgmt.responder)
    (void)rnc_responder_tick(mgmt.responder, unix_seconds, now);
  if (mgmt.requester) {
    (void)rnc_requester_tick(mgmt.requester, unix_seconds, now);
    blackhole_updates(unix_seconds, now);
  }
}
