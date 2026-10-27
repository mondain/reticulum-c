/* Link-terminating management destinations of the transport identity:
 * rnstransport.remote.management (/status, /path; identities on the allow list
 * only) and rnstransport.info.blackhole (/list; everyone), as the reference
 * Transport registers them. Included by node_daemon.c after node_rpc.h. */
#include <reticulum_c/rnc_responder.h>
typedef struct management {
  rnc_responder *responder;
  rnc_host *host;
  rnc_node *node;
  config settings; /* a copy: the caller's config may be replaced on reload */
  const rnc_identity *identity;
  uint64_t started;
} management;
static management mgmt;
static void mgmt_stop(void) {
  rnc_responder_free(mgmt.responder);
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
  if (!c->remote_management && !c->publish_blackhole)
    return 1;
  mgmt.responder = rnc_responder_new(node, RNC_RPC_MESSAGE_MAX, secure_random, NULL);
  if (!mgmt.responder)
    return 0;
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
