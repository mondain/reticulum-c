#ifndef RNC_NODE_RPC_H
#define RNC_NODE_RPC_H
/* Host-only shared-instance RPC adapter; included after the daemon helpers. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <reticulum_c/rnc_ipc.h>
typedef struct rpc_client {
  int fd, replied, closing;
  rnc_rpc *engine;
  uint8_t input[4096], output[RNC_RPC_MESSAGE_MAX + 12u];
  size_t input_size, input_offset, output_size, output_offset;
} rpc_client;
typedef struct rpc_server {
  int fd;
  uint8_t key[RNC_RPC_KEY_MAX];
  size_t key_size;
  uint64_t started;
  rpc_client clients[4];
} rpc_server;
/* the management module (node_mgmt.h) owns the probe destination */
static const uint8_t *probe_responder_hash(void);
static void rpc_close_client(rpc_client *c) {
  if (c->fd >= 0)
    close(c->fd);
  rnc_rpc_free(c->engine);
  OPENSSL_cleanse(c, sizeof(*c));
  c->fd = -1;
}
static void rpc_stop(rpc_server *s) {
  size_t i;
  if (s->fd >= 0)
    close(s->fd);
  for (i = 0; i < 4; ++i)
    rpc_close_client(&s->clients[i]);
  OPENSSL_cleanse(s, sizeof(*s));
  s->fd = -1;
  for (i = 0; i < 4; ++i)
    s->clients[i].fd = -1;
}
static int rpc_open(rpc_server *s, const config *c, const rnc_identity *id) {
  struct sockaddr_in addr;
  size_t i;
  int one = 1;
  memset(s, 0, sizeof(*s));
  s->fd = -1;
  for (i = 0; i < 4; ++i)
    s->clients[i].fd = -1;
  if (!c->share)
    return 1;
  if (c->rpc_key_size) {
    memcpy(s->key, c->rpc_key, c->rpc_key_size);
    s->key_size = c->rpc_key_size;
  } else {
    if (rnc_rpc_key(id, s->key) != RNC_OK)
      return 0;
    s->key_size = 32;
  }
  s->fd = socket(AF_INET, SOCK_STREAM, 0);
  if (s->fd < 0)
    return 0;
  (void)setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(c->control_port);
  if (fcntl(s->fd, F_SETFD, FD_CLOEXEC) < 0 ||
      fcntl(s->fd, F_SETFL, O_NONBLOCK) < 0 ||
      bind(s->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
      listen(s->fd, 4) < 0) {
    rpc_stop(s);
    return 0;
  }
  s->started = monotonic_ms();
  return 1;
}
static void key_uint(rnc_rpc_writer *w, const char *key, uint64_t value) {
  (void)rnc_rpc_write_string(w, key);
  (void)rnc_rpc_write_uint(w, value);
}
static void key_bool(rnc_rpc_writer *w, const char *key, int value) {
  (void)rnc_rpc_write_string(w, key);
  (void)rnc_rpc_write_bool(w, value);
}
static void key_real(rnc_rpc_writer *w, const char *key, double value) {
  (void)rnc_rpc_write_string(w, key);
  (void)rnc_rpc_write_real(w, value);
}
static void key_string(rnc_rpc_writer *w, const char *key, const char *value) {
  (void)rnc_rpc_write_string(w, key);
  (void)rnc_rpc_write_string(w, value);
}
static void key_nil(rnc_rpc_writer *w, const char *key) {
  (void)rnc_rpc_write_string(w, key);
  (void)rnc_rpc_write_nil(w);
}
static const char *kind_name(const rnc_host_status *s) {
  if (s->local)
    return s->parent_id ? "LocalClientInterface" : "LocalServerInterface";
  switch (s->kind) {
  case RNC_HOST_TCP_LISTEN:
    return "TCPServerInterface";
  case RNC_HOST_TCP_CONNECT:
    return "TCPClientInterface";
  case RNC_HOST_UDP:
    return "UDPInterface";
  case RNC_HOST_AUTO:
    return s->parent_id ? "AutoInterfacePeer" : "AutoInterface";
  case RNC_HOST_SERIAL:
    return "SerialInterface";
  case RNC_HOST_KISS:
    return "KISSInterface";
  case RNC_HOST_RNODE:
    return "RNodeInterface";
  case RNC_HOST_PIPE:
    return "PipeInterface";
  case RNC_HOST_AX25:
    return "AX25KISSInterface";
  default:
    return "Interface";
  }
}
static size_t peer_count(rnc_host *h, uint32_t parent) {
  size_t i, count = 0;
  rnc_host_status s;
  for (i = 0; i < RNC_HOST_SLOTS; ++i)
    if (rnc_host_status_at(h, i, &s) == RNC_OK && s.parent_id == parent)
      ++count;
  return count;
}
/* Interface mode as the reference numbers it: FULL=1, ACCESS_POINT=3,
 * ROAMING=4, BOUNDARY=5, GATEWAY=6, and 7 for the internal shared-instance
 * interface. */
static unsigned mode_number(const rnc_host_status *s) {
  if (s->local)
    return 7u;
  switch (s->mode) {
  case RNC_MODE_ACCESS_POINT:
    return 3u;
  case RNC_MODE_ROAMING:
    return 4u;
  case RNC_MODE_BOUNDARY:
    return 5u;
  case RNC_MODE_GATEWAY:
    return 6u;
  default:
    return 1u;
  }
}
static void interface_stats(rnc_rpc_writer *w, rnc_host *h,
                            const rnc_host_status *s) {
  static const char *zeros[] = {"rxs",
                                "txs",
                                "arxs",
                                "atxs",
                                "prxs",
                                "ptxs",
                                "prxb",
                                "ptxb",
                                "prxc",
                                "ptxc",
                                "incoming_announce_frequency",
                                "outgoing_announce_frequency",
                                "incoming_pr_frequency",
                                "outgoing_pr_frequency",
                                "txdrb",
                                "packet_filter_hits",
                                "gravity",
                                "burst_count",
                                "pr_burst_count"};
  static const char *nils[] = {"announce_rate_target", "announce_rate_grace",
                               "announce_rate_penalty", "burst_activated",
                               "pr_burst_activated"};
  size_t i;
  (void)rnc_rpc_write_map(w, 24u + sizeof(zeros) / sizeof(*zeros) +
                                 sizeof(nils) / sizeof(*nils) + 4u);
  key_string(w, "name", s->name);
  key_string(w, "short_name", s->name);
  key_string(w, "type", kind_name(s));
  (void)rnc_rpc_write_string(w, "hash");
  (void)rnc_rpc_write_bin(w, s->hash, 32);
  key_bool(w, "status",
           s->online && (s->kind != RNC_HOST_RNODE || s->radio_ready));
  key_uint(w, "mode", mode_number(s));
  key_uint(w, "bitrate", s->bitrate);
  key_uint(w, "mtu", s->mtu);
  if (s->kind == RNC_HOST_TCP_LISTEN)
    key_uint(w, "clients", peer_count(h, s->interface_id));
  else
    key_nil(w, "clients");
  if (s->kind == RNC_HOST_AUTO && !s->parent_id)
    key_uint(w, "peers", peer_count(h, s->interface_id));
  else
    key_nil(w, "peers");
  key_uint(w, "rxb", s->rx_bytes);
  key_uint(w, "txb", s->tx_bytes);
  key_uint(w, "arxb", s->rx_announce_bytes);
  key_uint(w, "atxb", s->tx_announce_bytes);
  key_uint(w, "arxc", s->rx_announces);
  key_uint(w, "atxc", s->tx_announces);
  key_uint(w, "txdrp", s->dropped_packets);
  key_uint(w, "txbuffered", s->queued_frames);
  key_uint(w, "held_announces", 0);
  key_uint(w, "protocol_violations", s->protocol_violations);
  key_uint(w, "ifac_violations", s->ifac_violations);
  (void)rnc_rpc_write_string(w, "ifac_signature");
  if (s->ifac_size)
    (void)rnc_rpc_write_bin(w, s->ifac_signature, 64);
  else
    (void)rnc_rpc_write_nil(w);
  if (s->ifac_size)
    key_uint(w, "ifac_size", s->ifac_size);
  else
    key_nil(w, "ifac_size");
  key_nil(w, "ifac_netname");
  for (i = 0; i < sizeof(zeros) / sizeof(*zeros); ++i)
    key_uint(w, zeros[i], 0);
  for (i = 0; i < sizeof(nils) / sizeof(*nils); ++i)
    key_nil(w, nils[i]);
  key_bool(w, "txstalled", 0);
  key_bool(w, "burst_active", 0);
  key_bool(w, "pr_burst_active", 0);
  key_bool(w, "announces_to_internal", s->local);
}
static void all_stats(rnc_rpc_writer *w, rnc_host *h, const config *c,
                      const rnc_identity *id, uint64_t uptime) {
  static const char *zeros[] = {
      "rxs",        "txs",        "arxs",       "atxs",       "arxf",
      "atxf",       "prxb",       "ptxb",       "prxs",       "ptxs",
      "prxf",       "ptxf",       "rxpps",      "txpps",      "rxqt",
      "rxqd",       "rxqa",       "rxqp",       "rxqil",      "rxqtd",
      "rxqdd",      "rxqad",      "rxqpd",      "rxqild",     "tqpressure",
      "dqpressure", "aqpressure", "pqpressure", "ilqpressure"};
  size_t i, count = 0;
  uint64_t rxb = 0, txb = 0, arxb = 0, atxb = 0;
  rnc_host_status s;
  for (i = 0; i < RNC_HOST_SLOTS; ++i)
    if (rnc_host_status_at(h, i, &s) == RNC_OK) {
      ++count;
      rxb += s.rx_bytes;
      txb += s.tx_bytes;
      arxb += s.rx_announce_bytes;
      atxb += s.tx_announce_bytes;
    }
  (void)rnc_rpc_write_map(w, 7u + sizeof(zeros) / sizeof(*zeros) +
                                 (c->transport ? 4u : 0u));
  (void)rnc_rpc_write_string(w, "interfaces");
  (void)rnc_rpc_write_array(w, count);
  for (i = 0; i < RNC_HOST_SLOTS; ++i)
    if (rnc_host_status_at(h, i, &s) == RNC_OK)
      interface_stats(w, h, &s);
  key_uint(w, "rxb", rxb);
  key_uint(w, "txb", txb);
  key_uint(w, "arxb", arxb);
  key_uint(w, "atxb", atxb);
  key_nil(w, "rss");
  key_nil(w, "txq");
  for (i = 0; i < sizeof(zeros) / sizeof(*zeros); ++i)
    key_uint(w, zeros[i], 0);
  if (c->transport) {
    (void)rnc_rpc_write_string(w, "transport_id");
    (void)rnc_rpc_write_bin(w, id->hash, 16);
    if (network_identity_hash()) {
      (void)rnc_rpc_write_string(w, "network_id");
      (void)rnc_rpc_write_bin(w, network_identity_hash(), 16);
    } else
      key_nil(w, "network_id");
    key_real(w, "transport_uptime", (double)uptime / 1000.0);
    if (probe_responder_hash()) {
      (void)rnc_rpc_write_string(w, "probe_responder");
      (void)rnc_rpc_write_bin(w, probe_responder_hash(), 16);
    } else
      key_nil(w, "probe_responder");
  }
}
static uint32_t lowest_bitrate(rnc_host *h) {
  size_t i;
  uint32_t lowest = 0;
  rnc_host_status s;
  for (i = 0; i < RNC_HOST_SLOTS; ++i)
    if (rnc_host_status_at(h, i, &s) == RNC_OK && s.online && !s.local &&
        s.bitrate && (!lowest || s.bitrate < lowest))
      lowest = s.bitrate;
  return lowest;
}
/* Path table as the reference reports it: a list of dicts, optionally limited
 * by hop count and destination. */
static void write_path_table(rnc_rpc_writer *w, rnc_host *h, rnc_node *node,
                             int has_max_hops, uint32_t max_hops,
                             const uint8_t *only, uint64_t now) {
  rnc_route route;
  rnc_host_status s;
  size_t i, count = 0;
  for (i = 0; rnc_node_route_at(node, i, now, &route) == RNC_OK; ++i)
    if ((!has_max_hops || route.hops <= max_hops) &&
        (!only || !memcmp(only, route.destination, 16)))
      ++count;
  (void)rnc_rpc_write_array(w, count);
  for (i = 0; rnc_node_route_at(node, i, now, &route) == RNC_OK; ++i)
    if ((!has_max_hops || route.hops <= max_hops) &&
        (!only || !memcmp(only, route.destination, 16))) {
      (void)rnc_rpc_write_map(w, 6);
      (void)rnc_rpc_write_string(w, "hash");
      (void)rnc_rpc_write_bin(w, route.destination, 16);
      key_real(w, "timestamp", (double)route.announced_at);
      (void)rnc_rpc_write_string(w, "via");
      (void)rnc_rpc_write_bin(w, route.next_hop, 16);
      key_uint(w, "hops", route.hops);
      key_real(w, "expires",
               (double)time(NULL) + (double)(route.expires_ms - now) / 1000.0);
      if (rnc_host_get_status(h, route.interface_id, &s) == RNC_OK)
        key_string(w, "interface", s.name);
      else
        key_string(w, "interface", "unknown");
    }
}
/* identity hash -> {source, until, reason}, as Transport.blackholed_identities */
static void write_blackhole_list(rnc_rpc_writer *w, rnc_node *node) {
  rnc_blackhole_entry e;
  size_t i;
  uint64_t unix_now = (uint64_t)time(NULL);
  for (i = 0; rnc_node_blackhole_at(node, i, unix_now, &e) == RNC_OK; ++i) {
  }
  (void)rnc_rpc_write_map(w, i);
  for (i = 0; rnc_node_blackhole_at(node, i, unix_now, &e) == RNC_OK; ++i) {
    (void)rnc_rpc_write_bin(w, e.identity, 16);
    (void)rnc_rpc_write_map(w, 3);
    (void)rnc_rpc_write_string(w, "source");
    (void)rnc_rpc_write_bin(w, e.source, 16);
    (void)rnc_rpc_write_string(w, "until");
    if (e.until)
      (void)rnc_rpc_write_uint(w, e.until);
    else
      (void)rnc_rpc_write_nil(w);
    (void)rnc_rpc_write_string(w, "reason");
    if (e.reason[0])
      (void)rnc_rpc_write_string(w, e.reason);
    else
      (void)rnc_rpc_write_nil(w);
  }
}
static int rpc_response(uint8_t *out, size_t capacity, size_t *written,
                        const uint8_t *query, size_t query_size, rnc_host *h,
                        rnc_node *node, const config *c, const rnc_identity *id,
                        uint64_t uptime, uint64_t now) {
  rnc_rpc_query q;
  rnc_rpc_writer w;
  rnc_route route;
  rnc_host_status s;
  uint32_t bitrate = 0;
  rnc_rpc_writer_init(&w, out, capacity);
  {
    /* blackhole_identity / unblackhole_identity return True, None (no change)
     * or False, like Transport does */
    rnc_rpc_command command;
    if (rnc_rpc_decode_command(query, query_size, &command) == RNC_OK) {
      rnc_result r =
          command.type == RNC_RPC_BLACKHOLE_IDENTITY
              ? rnc_node_blackhole(node, command.identity, command.until,
                                   command.reason, (uint64_t)time(NULL))
              : rnc_node_unblackhole(node, command.identity);
      if (r == RNC_OK) {
        (void)blackhole_save(node);
        (void)rnc_rpc_write_bool(&w, 1);
      } else if (r == RNC_STATE)
        (void)rnc_rpc_write_nil(&w);
      else
        (void)rnc_rpc_write_bool(&w, 0);
      return rnc_rpc_writer_finish(&w, written) == RNC_OK;
    }
  }
  if (rnc_rpc_decode_query(query, query_size, &q) != RNC_OK) {
    (void)rnc_rpc_write_nil(&w);
    return rnc_rpc_writer_finish(&w, written) == RNC_OK;
  }
  switch (q.type) {
  case RNC_RPC_INTERFACE_STATS:
    all_stats(&w, h, c, id, uptime);
    break;
  case RNC_RPC_PATH_TABLE:
    write_path_table(&w, h, node, q.has_max_hops, q.max_hops, NULL, now);
    break;
  case RNC_RPC_LINK_COUNT:
    (void)rnc_rpc_write_uint(&w, rnc_node_link_count(node, 0));
    break;
  case RNC_RPC_ACTIVE_LINK_COUNT:
    (void)rnc_rpc_write_uint(&w, rnc_node_link_count(node, 1));
    break;
  case RNC_RPC_NEXT_HOP:
    if (rnc_node_lookup(node, q.destination_hash, now, &route) == RNC_OK)
      (void)rnc_rpc_write_bin(&w, route.next_hop, 16);
    else
      (void)rnc_rpc_write_nil(&w);
    break;
  case RNC_RPC_NEXT_HOP_IF_NAME:
    if (rnc_node_lookup(node, q.destination_hash, now, &route) == RNC_OK &&
        rnc_host_get_status(h, route.interface_id, &s) == RNC_OK)
      (void)rnc_rpc_write_string(&w, s.name);
    else
      (void)rnc_rpc_write_nil(&w);
    break;
  case RNC_RPC_FIRST_HOP_TIMEOUT:
    if (rnc_node_lookup(node, q.destination_hash, now, &route) == RNC_OK &&
        rnc_host_get_status(h, route.interface_id, &s) == RNC_OK)
      bitrate = s.bitrate;
    (void)rnc_rpc_write_real(&w, 6.0 + (bitrate ? 4000.0 / bitrate : 0));
    break;
  case RNC_RPC_LOWEST_INTERFACE_BITRATE:
    (void)rnc_rpc_write_uint(&w, lowest_bitrate(h));
    break;
  case RNC_RPC_MEDIUM_PATH_TIMEOUT:
    bitrate = lowest_bitrate(h);
    (void)rnc_rpc_write_real(&w, bitrate ? 6.0 + 8000.0 / bitrate : 0);
    break;
  case RNC_RPC_RATE_TABLE:
    (void)rnc_rpc_write_array(&w, 0);
    break;
  case RNC_RPC_BLACKHOLED_IDENTITIES:
    write_blackhole_list(&w, node);
    break;
  case RNC_RPC_IS_BLACKHOLED:
    (void)rnc_rpc_write_bool(
        &w, rnc_node_is_blackholed(node, q.identity_hash, (uint64_t)time(NULL)));
    break;
  default:
    (void)rnc_rpc_write_nil(&w);
    break;
  }
  return rnc_rpc_writer_finish(&w, written) == RNC_OK;
}
static void rpc_drain(rpc_server *s, rpc_client *c, rnc_host *h, rnc_node *node,
                      const config *cfg, const rnc_identity *id, uint64_t now) {
  rnc_rpc_event event;
  while (!c->output_size && rnc_rpc_poll(c->engine, &event) == RNC_OK) {
    if (event.type == RNC_RPC_SEND) {
      memcpy(c->output, event.data, event.size);
      c->output_size = event.size;
      c->output_offset = 0;
    } else if (event.type == RNC_RPC_CLOSED)
      c->closing = 1;
    else if (event.type == RNC_RPC_MESSAGE) {
      uint8_t response[RNC_RPC_MESSAGE_MAX];
      size_t n;
      if (c->replied ||
          !rpc_response(response, sizeof(response), &n, event.data, event.size,
                        h, node, cfg, id, now - s->started, now) ||
          rnc_rpc_send(c->engine, response, n, now) != RNC_OK)
        c->closing = 1;
      else
        c->replied = 1;
    }
  }
}
static void rpc_step(rpc_server *s, rnc_host *h, rnc_node *node,
                     const config *cfg, const rnc_identity *id, uint64_t now) {
  size_t i;
  if (s->fd < 0)
    return;
  for (i = 0; i < 4; ++i)
    if (s->clients[i].fd < 0) {
      int fd = accept(s->fd, NULL, NULL);
      if (fd >= 0) {
        rpc_client *c = &s->clients[i];
        if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0 ||
            fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
          close(fd);
          break;
        }
        memset(c, 0, sizeof(*c));
        c->fd = fd;
        c->engine = rnc_rpc_new(s->key, s->key_size, 1, secure_random, NULL,
                                RNC_RPC_MESSAGE_MAX);
        if (!c->engine || rnc_rpc_start(c->engine, now) != RNC_OK)
          rpc_close_client(c);
      }
      break;
    }
  for (i = 0; i < 4; ++i) {
    rpc_client *c = &s->clients[i];
    rnc_result r;
    size_t consumed;
    if (c->fd < 0)
      continue;
    if (c->output_size) {
      ssize_t n = write(c->fd, c->output + c->output_offset,
                        c->output_size - c->output_offset);
      if (n > 0)
        c->output_offset += (size_t)n;
      else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
               errno != EINTR) {
        rpc_close_client(c);
        continue;
      }
      if (c->output_offset == c->output_size)
        c->output_size = c->output_offset = 0;
    }
    if (!c->closing && !c->replied) {
      if (c->input_offset == c->input_size) {
        ssize_t n = read(c->fd, c->input, sizeof(c->input));
        if (n > 0) {
          c->input_size = (size_t)n;
          c->input_offset = 0;
        } else if (n == 0 || (n < 0 && errno != EAGAIN &&
                              errno != EWOULDBLOCK && errno != EINTR)) {
          rpc_close_client(c);
          continue;
        }
      }
      while (c->input_offset < c->input_size) {
        r = rnc_rpc_input(c->engine, c->input + c->input_offset,
                          c->input_size - c->input_offset, &consumed, now);
        c->input_offset += consumed;
        if (r != RNC_OK && r != RNC_AGAIN)
          c->closing = 1;
        rpc_drain(s, c, h, node, cfg, id, now);
        if (r == RNC_AGAIN || !consumed || c->closing)
          break;
      }
    }
    (void)rnc_rpc_tick(c->engine, now);
    rpc_drain(s, c, h, node, cfg, id, now);
    if ((c->replied || c->closing) && !c->output_size)
      rpc_close_client(c);
  }
}
#endif
