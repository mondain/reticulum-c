#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <poll.h>
#include <reticulum_c/rnc_host.h>
#include <reticulum_c/rnc_i2p.h>
#include <reticulum_c/rnc_log.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

rnc_result rnc_host_frame_encode(rnc_host_framing mode, uint8_t command,
                                 const uint8_t *data, size_t size,
                                 uint8_t *output, size_t capacity,
                                 size_t *written) {
  uint8_t frame[RNC_HOST_FRAME_MAX], delimiter, escape;
  size_t i, n = 0;
  if (written)
    *written = 0;
  if ((!data && size) || !output || !written || size > RNC_MAX_FRAME ||
      (mode != RNC_HOST_HDLC && mode != RNC_HOST_KISS_FRAMING))
    return RNC_INVALID;
  delimiter = mode == RNC_HOST_HDLC ? 0x7e : 0xc0;
  escape = mode == RNC_HOST_HDLC ? 0x7d : 0xdb;
  frame[n++] = delimiter;
  for (i = 0; i < size + (mode == RNC_HOST_KISS_FRAMING ? 1u : 0u); ++i) {
    uint8_t b =
        mode == RNC_HOST_KISS_FRAMING ? (i ? data[i - 1] : command) : data[i];
    if (b == delimiter || b == escape) {
      frame[n++] = escape;
      frame[n++] = mode == RNC_HOST_HDLC ? (uint8_t)(b ^ 0x20)
                                         : (b == delimiter ? 0xdc : 0xdd);
    } else
      frame[n++] = b;
  }
  frame[n++] = delimiter;
  if (capacity < n)
    return RNC_NO_SPACE;
  memcpy(output, frame, n);
  *written = n;
  return RNC_OK;
}
rnc_result rnc_host_frame_feed(rnc_host_framer *s, rnc_host_framing mode,
                               uint8_t b, uint8_t *command, uint8_t *output,
                               size_t capacity, size_t *written) {
  uint8_t delimiter = mode == RNC_HOST_HDLC ? 0x7e : 0xc0,
          escape = mode == RNC_HOST_HDLC ? 0x7d : 0xdb;
  size_t skip = mode == RNC_HOST_KISS_FRAMING ? 1u : 0u, n;
  if (written)
    *written = 0;
  if (!s || !command || !output || !written ||
      (mode != RNC_HOST_HDLC && mode != RNC_HOST_KISS_FRAMING))
    return RNC_INVALID;
  if (b == delimiter) {
    rnc_result result = RNC_AGAIN;
    if (s->active && s->size >= skip && s->size && !s->discard && !s->escaped) {
      n = s->size - skip;
      if (capacity < n)
        result = RNC_NO_SPACE;
      else {
        *command = skip ? s->data[0] : 0;
        memcpy(output, s->data + skip, n);
        *written = n;
        result = RNC_OK;
      }
    }
    s->active = 1;
    s->escaped = s->discard = 0;
    s->size = 0;
    return result;
  }
  if (!s->active || s->discard)
    return RNC_AGAIN;
  if (s->escaped) {
    s->escaped = 0;
    if (mode == RNC_HOST_HDLC)
      b ^= 0x20;
    else if (b == 0xdc)
      b = 0xc0;
    else if (b == 0xdd)
      b = 0xdb;
    else {
      s->discard = 1;
      return RNC_AGAIN;
    }
  } else if (b == escape) {
    s->escaped = 1;
    return RNC_AGAIN;
  }
  if (s->size == RNC_MAX_FRAME + skip) {
    s->discard = 1;
    return RNC_AGAIN;
  }
  s->data[s->size++] = b;
  return RNC_AGAIN;
}
rnc_result rnc_host_auto_group(const char *group, uint8_t out[16]) {
  uint8_t hash[32], address[16] = {0xff, 0x12, 0, 0};
  size_t n;
  if (!out)
    return RNC_INVALID;
  if (!group)
    group = "reticulum";
  n = strlen(group);
  if (!n || n > 63)
    return RNC_INVALID;
  if (rnc_hash(group, n, hash) != RNC_OK)
    return RNC_CRYPTO;
  memcpy(address + 4, hash + 2, 12);
  memcpy(out, address, 16);
  return RNC_OK;
}
rnc_result rnc_host_auto_token(const char *group, const char *ipv6,
                               uint8_t out[32]) {
  struct in6_addr addr;
  char canonical[INET6_ADDRSTRLEN];
  uint8_t material[128];
  size_t n, m;
  if (!ipv6 || !out || inet_pton(AF_INET6, ipv6, &addr) != 1 ||
      !inet_ntop(AF_INET6, &addr, canonical, sizeof(canonical)))
    return RNC_INVALID;
  if (!group)
    group = "reticulum";
  n = strlen(group);
  m = strlen(canonical);
  if (!n || n > 63)
    return RNC_INVALID;
  memcpy(material, group, n);
  memcpy(material + n, canonical, m);
  return rnc_hash(material, n + m, out);
}

rnc_result rnc_host_identity_save(const char *path, const rnc_identity *identity,
                                  int public_only, int overwrite) {
  const uint8_t *key;
  char temporary[4096];
  mode_t mode = public_only ? 0644 : 0600;
  size_t used = 0;
  int fd;
  struct stat st;
  if (!path || !identity || (!public_only && !identity->has_private))
    return RNC_INVALID;
  key = public_only ? identity->public_key : identity->private_key;
  if (!overwrite && lstat(path, &st) == 0)
    return RNC_STATE;
  if (snprintf(temporary, sizeof(temporary), "%s.tmp-%ld", path,
               (long)getpid()) >= (int)sizeof(temporary))
    return RNC_INVALID;
  fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            mode);
  if (fd < 0)
    return RNC_STATE;
  (void)fchmod(fd, mode); /* not subject to the umask */
  while (used < 64) {
    ssize_t n = write(fd, key + used, 64 - used);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0) {
      close(fd);
      (void)unlink(temporary);
      return RNC_STATE;
    }
    used += (size_t)n;
  }
  if (fsync(fd) < 0 || close(fd) < 0 ||
      (overwrite ? rename(temporary, path) : link(temporary, path)) < 0) {
    (void)unlink(temporary);
    return errno == EEXIST ? RNC_STATE : RNC_STATE;
  }
  if (!overwrite)
    (void)unlink(temporary);
  return RNC_OK;
}
rnc_result rnc_host_identity_load(const char *path, rnc_random_fn random,
                                  void *context, rnc_identity *identity) {
  int fd = -1;
  uint8_t key[65];
  size_t used = 0;
  rnc_identity temporary = {0};
  struct stat st;
  rnc_result result = RNC_STATE;
  if (!path || !random || !identity)
    return RNC_INVALID;
  fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0 && errno == ENOENT) {
    result = rnc_identity_generate(&temporary, random, context);
    if (result != RNC_OK)
      goto done;
    result = RNC_STATE;
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
      goto done;
    while (used < 64) {
      ssize_t n = write(fd, temporary.private_key + used, 64 - used);
      if (n < 0 && errno == EINTR)
        continue;
      if (n <= 0)
        goto done;
      used += (size_t)n;
    }
    if (fsync(fd) < 0)
      goto done;
  } else if (fd >= 0) {
    if (fstat(fd, &st) < 0)
      goto done;
    if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 077) ||
        st.st_size != 64) {
      result = RNC_AUTH;
      goto done;
    }
    while (used < sizeof(key)) {
      ssize_t n = read(fd, key + used, sizeof(key) - used);
      if (n < 0 && errno == EINTR)
        continue;
      if (n < 0)
        goto done;
      if (!n)
        break;
      used += (size_t)n;
    }
    if (used != 64) {
      result = RNC_AUTH;
      goto done;
    }
    result = rnc_identity_from_private(&temporary, key);
    if (result != RNC_OK)
      goto done;
  } else
    goto done;
  if (close(fd) < 0) {
    fd = -1;
    result = RNC_STATE;
    goto done;
  }
  fd = -1;
  *identity = temporary;
  result = RNC_OK;
done:
  if (fd >= 0)
    close(fd);
  OPENSSL_cleanse(key, sizeof(key));
  rnc_identity_clear(&temporary);
  return result;
}

typedef struct host_frame {
  size_t size, offset, wire_size;
  int announce, control, beacon;
  uint8_t data[RNC_HOST_FRAME_MAX];
} host_frame;
/* KISS TNCs share one setup sequence, ready-flow control and station ID. */
#define TNC_KIND(k) ((k) == RNC_HOST_KISS || (k) == RNC_HOST_AX25)
/* Kinds backed by a device node, as opposed to sockets. */
#define DEVICE_KIND(k)                                                       \
  (((k) >= RNC_HOST_SERIAL && (k) <= RNC_HOST_AX25) ||                        \
   (k) == RNC_HOST_RNODE_MULTI || (k) == RNC_HOST_WEAVE)
/* I2P: the SAM conversation a socket is in. Zero once the socket carries the
 * stream (or, for the controller, never: it keeps answering PING). */
enum { SAM_NONE = 0, SAM_SESSION, SAM_CONNECT, SAM_ACCEPT };
enum {
  SS_IDLE = 0,
  SS_HELLO,
  SS_DEST,
  SS_SESSION,
  SS_CONTROL,
  SS_LOOKUP,
  SS_CONNECT,
  SS_ACCEPT,
  SS_REMOTE
};
#define I2P_MTU 1064u
#define I2P_RECONNECT_MS 15000u
#define I2P_SESSION_TIMEOUT_MS 180000u
#define I2P_STREAM_TIMEOUT_MS 120000u
#define I2P_PROBE_AFTER_MS 10000u
#define I2P_READ_TIMEOUT_MS 110000u
#define I2P_PEER_MAX 704u
#define HOST_FLAP_SLOTS 32u
/* Weave: WDCL frames in HDLC to a switch at 3 Mbaud; every endpoint the
 * switch reports is a peer interface. */
#define WEAVE_MTU 1024u
#define WEAVE_BITRATE 250000u
#define WEAVE_BAUD 3000000u
#define WEAVE_HANDSHAKE_MS 2000u
#define WEAVE_PEER_TIMEOUT_MS 20000u
#define WEAVE_RETRY_MS 5000u
#define WEAVE_DEDUPE_SLOTS 48u
#define WEAVE_DEDUPE_TTL_MS 750u
enum { WEAVE_IDLE = 0, WEAVE_DISCOVERING, WEAVE_CONNECTING, WEAVE_CONNECTED };
typedef struct host_flap {
  char ip[INET6_ADDRSTRLEN];
  uint64_t last;
  unsigned count;
} host_flap;
typedef struct host_interface {
  int used, fd, discovery_fd, unicast_fd, connecting, node_added, accepted,
      has_ifac, ready;
  rnc_host_status status;
  char address[256], target[256], device[64], group[64],
      local_ip[INET6_ADDRSTRLEN];
  uint16_t target_port, discovery_port, data_port;
  unsigned baud, kiss_port, ifindex;
  uint32_t bitrate;
  rnc_interface_policy policy;
  int flow_control;
  unsigned radio_ack_mask;
  uint64_t radio_deadline;
  pid_t child;
  int kiss, gave_up, connect_failed, rnode_detected, rnode_tcp;
  uint64_t last_write_ms;
  int sam_role, sam_step, i2p_ready, sam_streamed;
  char sam_line[RNC_I2P_REPLY_MAX];
  size_t sam_len;
  uint64_t sam_deadline, accept_after, last_read_ms;
  unsigned peer_index;
  char sam_peer[I2P_PEER_MAX]; /* connect: name or destination being dialled */
  char sam_dest[I2P_PEER_MAX]; /* connect: the name, once looked up */
  int sam_resolved;
  char i2p_key_path[256], i2p_session[24];
  char i2p_private[1024];
  char *i2p_peers; /* connectable peers, NUL separated */
  size_t i2p_peers_size;
  unsigned i2p_peer_count;
  /* RNODE_MULTI: the device owns the fd; each radio is a child (multi_sub)
   * addressed by sub_vport. types[] holds what the device reported per vport:
   * 0 SX127X, 1 SX126X, 2 SX128X. */
  int multi_sub, subs_spawned;
  unsigned sub_vport, type_count, sub_count;
  uint8_t selected, types[RNC_HOST_SUBRADIOS];
  uint64_t detect_at;
  uint32_t tx_owner;
  rnc_host_subradio subs[RNC_HOST_SUBRADIOS];
  char sub_names[RNC_HOST_SUBRADIOS][64];
  /* WEAVE: the switch identity, kept across reconnects, and what the handshake
   * learnt; a peer (weave_peer) keeps the switch id and its endpoint. The
   * dedupe ring drops a packet that two endpoints deliver in quick succession,
   * as the reference does when a switch relays through several routes. */
  int weave_peer, weave_step;
  rnc_identity weave_id;
  uint8_t weave_sw[4], weave_remote[4], weave_endpoint[8];
  uint64_t weave_deadline;
  uint8_t dedupe[WEAVE_DEDUPE_SLOTS][8];
  uint64_t dedupe_at[WEAVE_DEDUPE_SLOTS];
  unsigned dedupe_used, dedupe_next;
  unsigned tries;
  uint64_t connect_deadline;
  char ax_call[7];
  int flap_on, flap_pending, no_output;
  uint64_t flap_threshold_ms, flap_expiry_ms, spawned_at;
  unsigned flap_grace;
  char peer_ip[INET6_ADDRSTRLEN];
  host_flap flaps[HOST_FLAP_SLOTS];
  uint64_t lock_at;
  rnc_host_config radio;
  char callsign[RNC_HOST_CALLSIGN_MAX + 1u];
  size_t callsign_size;
  uint64_t first_tx;
  int first_tx_set;
  struct sockaddr_storage peer, multicast;
  socklen_t peer_size, multicast_size;
  rnc_ifac ifac;
  rnc_host_framer framer;
  size_t queue_count;
  host_frame queue[RNC_HOST_QUEUE_FRAMES];
  uint8_t input[4096];
  size_t input_size, input_offset;
  int pending;
  rnc_packet pending_packet;
  size_t pending_wire_size;
  uint64_t retry_at, next_tx, next_announce, discover_at, last_heard;
} host_interface;
struct rnc_host {
  rnc_node *node;
  host_interface interfaces[RNC_HOST_SLOTS];
  uint32_t next_id;
  uint64_t now;
  int has_time;
  size_t head, count;
  rnc_host_event events[RNC_NODE_EVENTS];
  int held;
  rnc_node_event held_event;
};
static host_interface *find_interface(rnc_host *h, uint32_t id) {
  size_t i;
  for (i = 0; i < RNC_HOST_SLOTS; ++i)
    if (h->interfaces[i].used && h->interfaces[i].status.interface_id == id)
      return &h->interfaces[i];
  return NULL;
}
static host_interface *empty_interface(rnc_host *h) {
  size_t i;
  for (i = 0; i < RNC_HOST_SLOTS; ++i)
    if (!h->interfaces[i].used)
      return &h->interfaces[i];
  return NULL;
}
static int copy_text(char *out, size_t capacity, const char *in) {
  size_t n = in ? strlen(in) : 0;
  if (n >= capacity)
    return 0;
  if (n)
    memcpy(out, in, n);
  out[n] = 0;
  return 1;
}
static int nonblock(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
      fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
    return -1;
#ifdef SO_NOSIGPIPE
  {
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
  }
#endif
  return 0;
}
static int emit_host(rnc_host *h, rnc_host_event_type type, uint32_t id,
                     int error, const rnc_node_event *node) {
  rnc_host_event *e;
  if (h->count >= (type == RNC_HOST_DOWN
                       ? RNC_NODE_EVENTS
                       : RNC_NODE_EVENTS - RNC_NODE_INTERFACES))
    return 0;
  e = &h->events[(h->head + h->count) % RNC_NODE_EVENTS];
  memset(e, 0, sizeof(*e));
  e->type = type;
  e->interface_id = id;
  e->error_number = error;
  if (node)
    e->node = *node;
  if (type == RNC_HOST_NODE) {
    const host_interface *f = find_interface(h, id);
    if (f && f->status.has_signal) {
      e->has_signal = 1;
      e->rssi = f->status.rssi;
      e->snr = f->status.snr;
      e->quality = f->status.quality;
    }
  }
  ++h->count;
  return 1;
}
static uint16_t bound_port(int fd);
static rnc_result activate(rnc_host *h, host_interface *f) {
  rnc_result r;
  if (f->node_added)
    return RNC_OK;
  if (h->count >= RNC_NODE_EVENTS - RNC_NODE_INTERFACES)
    return RNC_AGAIN;
  r = rnc_node_add_interface(h->node, f->status.interface_id, f->bitrate);
  if (r != RNC_OK)
    return r;
  r = rnc_node_interface_mtu(h->node, f->status.interface_id, f->status.mtu);
  if (r != RNC_OK) {
    (void)rnc_node_remove_interface(h->node, f->status.interface_id);
    return r;
  }
  {
    r = rnc_node_interface_policy(h->node, f->status.interface_id, &f->policy);
    if (r != RNC_OK) {
      (void)rnc_node_remove_interface(h->node, f->status.interface_id);
      return r;
    }
  }
  if (f->status.local) {
    r = rnc_node_local_interface(h->node, f->status.interface_id, 1);
    if (r != RNC_OK) {
      (void)rnc_node_remove_interface(h->node, f->status.interface_id);
      return r;
    }
  }
  f->node_added = 1;
  f->tries = 0;
  f->status.online = 1;
  f->status.last_errno = 0;
  f->status.bound_port = f->fd >= 0 ? bound_port(f->fd) : 0;
  (void)emit_host(h, RNC_HOST_UP, f->status.interface_id, 0, NULL);
  rnc_logf(RNC_LOG_INFO, "host", "interface %s is up", f->status.name);
  /* A client that may return from another address names its tunnel to the peer,
   * as the reference's TCP client does after connecting. */
  if (f->status.kind == RNC_HOST_TCP_CONNECT && !f->accepted && !f->kiss)
    (void)rnc_node_synthesize_tunnel(h->node, f->status.interface_id,
                                     f->status.hash, h->now);
  return RNC_OK;
}
static int flap_expired(const host_interface *l, const host_flap *e,
                       uint64_t now) {
  return now > e->last && now - e->last > l->flap_expiry_ms;
}
static int flap_blocked(const host_interface *l, const char *ip, uint64_t now) {
  size_t i;
  for (i = 0; i < HOST_FLAP_SLOTS; ++i)
    if (l->flaps[i].count && !strcmp(l->flaps[i].ip, ip))
      return l->flaps[i].count > l->flap_grace &&
             !flap_expired(l, &l->flaps[i], now);
  return 0;
}
static void flap_record(host_interface *l, const char *ip, uint64_t now) {
  size_t i, slot = 0;
  for (i = 0; i < HOST_FLAP_SLOTS; ++i) {
    host_flap *e = &l->flaps[i];
    if (e->count && flap_expired(l, e, now))
      e->count = 0;
    if (e->count && !strcmp(e->ip, ip)) {
      ++e->count;
      e->last = now;
      return;
    }
  }
  for (i = 0; i < HOST_FLAP_SLOTS; ++i) {
    if (!l->flaps[i].count) {
      slot = i;
      break;
    }
    if (l->flaps[i].last < l->flaps[slot].last)
      slot = i;
  }
  (void)snprintf(l->flaps[slot].ip, sizeof(l->flaps[slot].ip), "%s", ip);
  l->flaps[slot].count = 1;
  l->flaps[slot].last = now;
}
static void i2p_session_lost(rnc_host *h, host_interface *controller);
static void disconnect_interface(rnc_host *h, host_interface *f, int error) {
  int was_connecting = f->connecting || f->connect_failed;
  if (f->flap_pending) {
    host_interface *parent = find_interface(h, f->status.parent_id);
    f->flap_pending = 0;
    if (parent && parent->flap_on &&
        h->now - f->spawned_at < parent->flap_threshold_ms)
      flap_record(parent, f->peer_ip, h->now);
  }
  if (f->fd >= 0) {
    close(f->fd);
    f->fd = -1;
  }
  if (f->status.kind == RNC_HOST_PIPE && f->child > 0) {
    (void)kill(f->child, SIGKILL);
    (void)waitpid(f->child, NULL, 0);
    f->child = 0;
  }
  if (f->node_added) {
    (void)rnc_node_remove_interface(h->node, f->status.interface_id);
    f->node_added = 0;
    (void)emit_host(h, RNC_HOST_DOWN, f->status.interface_id, error, NULL);
    if (error)
      rnc_logf(RNC_LOG_WARNING, "host", "interface %s is down: %s",
               f->status.name, strerror(error));
    else
      rnc_logf(RNC_LOG_INFO, "host", "interface %s is down", f->status.name);
  }
  if (f->status.kind == RNC_HOST_RNODE_MULTI) {
    size_t i;
    for (i = 0; i < RNC_HOST_SLOTS; ++i)
      if (h->interfaces[i].used && h->interfaces[i].multi_sub &&
          h->interfaces[i].status.parent_id == f->status.interface_id)
        (void)rnc_host_remove(h, h->interfaces[i].status.interface_id);
    f->rnode_detected = f->subs_spawned = 0;
    f->type_count = 0;
    f->tx_owner = 0;
    f->radio_deadline = 0;
  }
  if (f->status.kind == RNC_HOST_WEAVE && !f->weave_peer) {
    size_t i;
    for (i = 0; i < RNC_HOST_SLOTS; ++i)
      if (h->interfaces[i].used && h->interfaces[i].weave_peer &&
          h->interfaces[i].status.parent_id == f->status.interface_id)
        (void)rnc_host_remove(h, h->interfaces[i].status.interface_id);
    f->weave_step = WEAVE_IDLE;
    f->weave_deadline = 0;
    f->tx_owner = 0;
    f->dedupe_used = f->dedupe_next = 0;
  }
  f->status.online = 0;
  f->sam_step = 0;
  f->sam_len = 0;
  f->sam_resolved = 0;
  if (f->status.kind == RNC_HOST_I2P)
    i2p_session_lost(h, f);
  if (f->status.kind == RNC_HOST_RNODE) {
    f->status.radio_ready = 0;
    f->radio_ack_mask = 0;
    f->radio_deadline = 0;
    f->ready = 0;
    f->first_tx_set = 0;
  }
  f->status.last_errno = error;
  f->connecting = 0;
  f->connect_failed = 0;
  f->queue_count = 0;
  if ((f->status.kind == RNC_HOST_TCP_CONNECT && !f->accepted) ||
      f->status.kind == RNC_HOST_I2P) {
    if (was_connecting && f->radio.max_reconnect_tries &&
        ++f->tries >= f->radio.max_reconnect_tries)
      f->gave_up = 1;
    f->retry_at = h->now + (f->radio.reconnect_wait_ms
                                ? f->radio.reconnect_wait_ms
                                : 5000u);
  }
  else if (f->status.kind == RNC_HOST_RNODE_MULTI ||
           (f->status.kind == RNC_HOST_WEAVE && !f->weave_peer))
    f->retry_at = h->now + 5000u; /* the reference's reconnect wait */
  else if (f->status.kind == RNC_HOST_PIPE)
    f->retry_at = h->now + (f->radio.respawn_delay_ms
                                ? f->radio.respawn_delay_ms
                                : 5000u);
  else
    f->retry_at = h->now + 1000u;
  f->input_offset = f->input_size = 0;
  f->pending = 0;
  memset(&f->framer, 0, sizeof(f->framer));
}
static void note_connect_failure(rnc_host *h, host_interface *f) {
  if (f->radio.max_reconnect_tries &&
      ++f->tries >= f->radio.max_reconnect_tries)
    f->gave_up = 1;
  f->retry_at = h->now + (f->radio.reconnect_wait_ms ? f->radio.reconnect_wait_ms
                                                      : 5000u);
}
static int resolve(const char *address, uint16_t port, int socktype,
                   int passive, int family, int prefer_ipv6,
                   struct sockaddr_storage *out, socklen_t *size) {
  struct addrinfo hints, *result = NULL, *pick;
  char service[6];
  int rc;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = family;
  hints.ai_socktype = socktype;
  hints.ai_flags = passive ? AI_PASSIVE : 0;
  (void)snprintf(service, sizeof(service), "%u", (unsigned)port);
  rc = getaddrinfo(address && *address ? address : NULL, service, &hints,
                   &result);
  if (rc || !result) {
    errno = EINVAL;
    return -1;
  }
  pick = result;
  if (prefer_ipv6)
    for (pick = result; pick && pick->ai_family != AF_INET6;)
      pick = pick->ai_next;
  if (!pick)
    pick = result;
  if (pick->ai_addrlen > sizeof(*out)) {
    freeaddrinfo(result);
    errno = EINVAL;
    return -1;
  }
  memcpy(out, pick->ai_addr, pick->ai_addrlen);
  *size = (socklen_t)pick->ai_addrlen;
  freeaddrinfo(result);
  return 0;
}
static uint16_t bound_port(int fd) {
  struct sockaddr_storage a;
  socklen_t n = sizeof(a);
  if (getsockname(fd, (struct sockaddr *)&a, &n) < 0)
    return 0;
  return a.ss_family == AF_INET ? ntohs(((struct sockaddr_in *)&a)->sin_port)
         : a.ss_family == AF_INET6
             ? ntohs(((struct sockaddr_in6 *)&a)->sin6_port)
             : 0;
}
static int socket_bound(struct sockaddr_storage *a, socklen_t size, int type) {
  int fd = socket(a->ss_family, type, 0), one = 1;
  if (fd < 0)
    return -1;
  (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  if (type == SOCK_DGRAM)
    (void)setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
  if (nonblock(fd) < 0 || bind(fd, (struct sockaddr *)a, size) < 0) {
    int e = errno;
    close(fd);
    errno = e;
    return -1;
  }
  return fd;
}
/* Dead-peer detection as the reference sets it: probe after 5 s idle, every
 * 2 s, 12 times; unacknowledged data aborts after 24 s. */
static void tcp_tune_with(int fd, int idle, int interval, int probes,
                          int user_timeout_ms) {
  int on = 1;
  /* small frames go out at once instead of waiting for the previous ACK */
  (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
  (void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
#ifdef TCP_KEEPIDLE
  {
    (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval,
                     sizeof(interval));
    (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &probes, sizeof(probes));
  }
#else
  (void)idle;
  (void)interval;
  (void)probes;
#endif
#ifdef TCP_USER_TIMEOUT
  (void)setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout_ms,
                   sizeof(user_timeout_ms));
#else
  (void)user_timeout_ms;
#endif
}
static void tcp_tune(int fd) { tcp_tune_with(fd, 5, 2, 12, 24000); }
/* The reference's I2P peers probe after 10 s idle, every 9 s, 5 times, and
 * abort unacknowledged data after 45 s. */
static void i2p_tune(int fd) { tcp_tune_with(fd, 10, 9, 5, 45000); }
static rnc_result sam_start(rnc_host *h, host_interface *f);
static int connect_interface(rnc_host *h, host_interface *f) {
  int fd = socket(f->peer.ss_family, SOCK_STREAM, 0), rc;
  if (fd < 0)
    return -1;
  if (nonblock(fd) < 0) {
    close(fd);
    return -1;
  }
  if (f->sam_role)
    i2p_tune(fd);
  else
    tcp_tune(fd);
  rc = connect(fd, (struct sockaddr *)&f->peer, f->peer_size);
  if (rc < 0 && errno != EINPROGRESS) {
    int e = errno;
    close(fd);
    errno = e;
    return -1;
  }
  f->fd = fd;
  f->connecting = rc < 0;
  /* rnc_host_add has no clock, so h->now may still be stale; the deadline is
   * set from the first step that sees the connection pending. */
  f->connect_deadline = 0;
  if (!f->connecting &&
      (f->sam_role ? sam_start(h, f) : activate(h, f)) != RNC_OK) {
    close(fd);
    f->fd = -1;
    errno = ENOSPC;
    return -1;
  }
  return 0;
}
static speed_t baud_value(unsigned value) {
  switch (value) {
  case 9600:
    return B9600;
  case 19200:
    return B19200;
  case 38400:
    return B38400;
  case 57600:
    return B57600;
  case 0:
  case 115200:
    return B115200;
#ifdef B230400
  case 230400:
    return B230400;
#endif
#ifdef B3000000
  case 3000000:
    return B3000000;
#endif
  default:
    return (speed_t)0;
  }
}
/* Splits a command line on blanks; single and double quotes group words. */
static int split_command(char *line, char *argv[], size_t max) {
  size_t n = 0;
  char *r = line, *w = line, quote = 0;
  int in_word = 0;
  for (;; ++r) {
    if (!*r || (!quote && (*r == ' ' || *r == '\t'))) {
      if (in_word) {
        *w++ = 0;
        in_word = 0;
      }
      if (!*r)
        break;
      continue;
    }
    if (!in_word) {
      if (n + 1u >= max)
        return -1;
      argv[n++] = w;
      in_word = 1;
    }
    if (quote ? *r == quote : (*r == '"' || *r == '\'')) {
      quote = quote ? 0 : *r;
      continue;
    }
    *w++ = *r;
  }
  if (quote)
    return -1;
  argv[n] = NULL;
  return (int)n;
}
/* Runs the command with both stdio streams on one end of a socketpair and
 * returns the other end, non-blocking. */
static int pipe_open(const char *command, pid_t *child) {
  char line[256], *argv[32];
  int sv[2], flags;
  pid_t pid;
  if (strlen(command) >= sizeof(line)) {
    errno = EINVAL;
    return -1;
  }
  strcpy(line, command);
  if (split_command(line, argv, sizeof(argv) / sizeof(*argv)) < 1) {
    errno = EINVAL;
    return -1;
  }
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
    return -1;
  (void)fcntl(sv[0], F_SETFD, FD_CLOEXEC);
  (void)fcntl(sv[1], F_SETFD, FD_CLOEXEC);
  pid = fork();
  if (pid < 0) {
    close(sv[0]);
    close(sv[1]);
    return -1;
  }
  if (!pid) {
    long fd, max = sysconf(_SC_OPEN_MAX);
    if (dup2(sv[1], 0) < 0 || dup2(sv[1], 1) < 0)
      _exit(126);
    for (fd = 3; fd < (max > 0 && max < 4096 ? max : 4096); ++fd)
      close((int)fd);
    execvp(argv[0], argv);
    _exit(127);
  }
  close(sv[1]);
  flags = fcntl(sv[0], F_GETFL);
  if (flags < 0 || fcntl(sv[0], F_SETFL, flags | O_NONBLOCK) < 0) {
    close(sv[0]);
    (void)kill(pid, SIGKILL);
    (void)waitpid(pid, NULL, 0);
    return -1;
  }
  *child = pid;
  return sv[0];
}
static int serial_open(const host_interface *f);
/* A WiFi RNode listens on TCP port 7633 and speaks the KISS protocol there. The
 * connection is started here and finished in the poll loop like a TCP client's;
 * the radio is set up once it is open. */
static int rnode_tcp_open(host_interface *f) {
  int fd = socket(f->peer.ss_family, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;
  if (nonblock(fd) < 0) {
    close(fd);
    return -1;
  }
  tcp_tune(fd);
  if (connect(fd, (struct sockaddr *)&f->peer, f->peer_size) < 0 &&
      errno != EINPROGRESS) {
    int e = errno;
    close(fd);
    errno = e;
    return -1;
  }
  f->connecting = 1;
  f->connect_deadline = 0;
  return fd;
}
static int device_open(host_interface *f) {
  if (f->rnode_tcp)
    return rnode_tcp_open(f);
  if (f->status.kind == RNC_HOST_PIPE)
    return pipe_open(f->address, &f->child);
  return serial_open(f);
}
/* Frame parameters (data bits, parity, stop bits) on top of raw mode. */
static void serial_flags(const rnc_host_config *c, struct termios *t) {
  t->c_cflag &= ~(CSIZE | PARENB | PARODD | CSTOPB);
  t->c_cflag |= CLOCAL | CREAD;
  switch (c->serial_databits) {
  case 5:
    t->c_cflag |= CS5;
    break;
  case 6:
    t->c_cflag |= CS6;
    break;
  case 7:
    t->c_cflag |= CS7;
    break;
  default:
    t->c_cflag |= CS8;
    break;
  }
  if (c->serial_parity == 'E' || c->serial_parity == 'O') {
    t->c_cflag |= PARENB;
    t->c_iflag |= INPCK;
    if (c->serial_parity == 'O')
      t->c_cflag |= PARODD;
  }
  if (c->serial_stopbits == 2)
    t->c_cflag |= CSTOPB;
}
static int serial_open(const host_interface *f) {
  const char *path = f->address;
  unsigned baud = f->baud;
  int fd;
  struct termios t;
  struct stat st;
  speed_t speed = baud_value(baud);
  if (!speed) {
    errno = EINVAL;
    return -1;
  }
  fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0)
    return -1;
  if (fstat(fd, &st) < 0 || !S_ISCHR(st.st_mode) || tcgetattr(fd, &t) < 0) {
    close(fd);
    errno = EINVAL;
    return -1;
  }
  t.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL |
                 IXON | IXOFF);
  t.c_oflag &= ~OPOST;
  t.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
  serial_flags(&f->radio, &t);
  t.c_cc[VMIN] = 0;
  t.c_cc[VTIME] = 0;
  if (cfsetispeed(&t, speed) < 0 || cfsetospeed(&t, speed) < 0 ||
      tcsetattr(fd, TCSANOW, &t) < 0 || nonblock(fd) < 0) {
    int e = errno;
    close(fd);
    errno = e;
    return -1;
  }
  return fd;
}
/* Every frame for one radio of a multi device is preceded by the frame that
 * selects it. */
static rnc_result select_prefix(const host_interface *f, host_frame *q) {
  if (!f->multi_sub)
    return RNC_OK;
  if (q->size + 4u > sizeof(q->data))
    return RNC_NO_SPACE;
  memmove(q->data + 4, q->data, q->size);
  q->data[0] = 0xc0;
  q->data[1] = 0x1f;
  q->data[2] = (uint8_t)f->sub_vport;
  q->data[3] = 0xc0;
  q->size += 4u;
  return RNC_OK;
}
static rnc_result queue_command(host_interface *f, uint8_t command,
                                const uint8_t *data, size_t size) {
  host_frame *q;
  rnc_result r;
  if (f->queue_count == RNC_HOST_QUEUE_FRAMES)
    return RNC_AGAIN;
  q = &f->queue[f->queue_count];
  memset(q, 0, sizeof(*q));
  q->control = 1;
  r = rnc_host_frame_encode(RNC_HOST_KISS_FRAMING, command, data, size, q->data,
                            sizeof(q->data), &q->size);
  if (r == RNC_OK)
    r = select_prefix(f, q);
  if (r == RNC_OK)
    ++f->queue_count;
  return r;
}
static void put32(uint8_t out[4], uint32_t x) {
  out[0] = (uint8_t)(x >> 24);
  out[1] = (uint8_t)(x >> 16);
  out[2] = (uint8_t)(x >> 8);
  out[3] = (uint8_t)x;
}
/* TNC timing in 10 ms units, as the reference sends them. */
static uint8_t tnc_units(unsigned ms) {
  return ms / 10u > 255u ? 255u : (uint8_t)(ms / 10u);
}
/* The reference detects the RNode and checks its firmware before it configures
 * the radio: DETECT, then the firmware version, platform and MCU are asked
 * for, and configure_radio() runs when the device answers the detection. */
static rnc_result queue_detect(host_interface *f) {
  static const uint8_t detect = 0x73, zero = 0;
  rnc_result r = queue_command(f, 0x08, &detect, 1);
  if (r == RNC_OK)
    r = queue_command(f, 0x50, &zero, 1);
  if (r == RNC_OK)
    r = queue_command(f, 0x48, &zero, 1);
  if (r == RNC_OK)
    r = queue_command(f, 0x49, &zero, 1);
  return r;
}
static rnc_result begin_rnode(host_interface *f) {
  f->radio_ack_mask = 0;
  f->status.radio_ready = 0;
  f->radio_deadline = 0;
  f->ready = 0;
  f->rnode_detected = 0;
  return queue_detect(f);
}
/* A multi device is asked what it is and which radios it has in one go. */
static rnc_result begin_multi(host_interface *f) {
  static const uint8_t zero = 0;
  rnc_result r;
  f->rnode_detected = 0;
  f->subs_spawned = 0;
  f->type_count = 0;
  f->radio_deadline = 0;
  r = queue_detect(f);
  if (r == RNC_OK)
    r = queue_command(f, 0x71, &zero, 1);
  return r;
}
static rnc_result configure_ax25(host_interface *f, const rnc_host_config *c) {
  uint8_t b[1];
  rnc_result r;
  b[0] = tnc_units(c->preamble_ms ? c->preamble_ms : 350u);
  r = queue_command(f, 1, b, 1);
  if (r == RNC_OK) {
    b[0] = tnc_units(c->txtail_ms ? c->txtail_ms : 20u);
    r = queue_command(f, 4, b, 1);
  }
  if (r == RNC_OK) {
    b[0] = (uint8_t)(c->persistence > 255u ? 255u
                                           : c->persistence ? c->persistence
                                                            : 64u);
    r = queue_command(f, 2, b, 1);
  }
  if (r == RNC_OK) {
    b[0] = tnc_units(c->slottime_ms ? c->slottime_ms : 20u);
    r = queue_command(f, 3, b, 1);
  }
  if (r == RNC_OK) {
    b[0] = 1; /* the reference always sends READY=1 after configuring */
    r = queue_command(f, 0x0f, b, 1);
  }
  f->ready = 1;
  return r;
}
static rnc_result configure_radio(host_interface *f, const rnc_host_config *c) {
  uint8_t b[4];
  rnc_result r;
  uint8_t command[] = {1, 2, 3, 4, 5, 6};
  f->radio_ack_mask = 0;
  f->status.radio_ready = 0;
  f->radio_deadline = 0;
  f->ready = 0;
  unsigned i;
  for (i = 0; i < sizeof(command); ++i) {
    size_t n = 1;
    switch (command[i]) {
    case 1:
      put32(b, c->frequency);
      n = 4;
      break;
    case 2:
      put32(b, c->bandwidth);
      n = 4;
      break;
    case 3:
      b[0] = (uint8_t)c->tx_power;
      break;
    case 4:
      b[0] = (uint8_t)c->spreading_factor;
      break;
    case 5:
      b[0] = (uint8_t)c->coding_rate;
      break;
    default:
      b[0] = 1;
      break;
    }
    r = queue_command(f, command[i], b, n);
    if (r != RNC_OK)
      return r;
  }
  {
    /* airtime lock commands carry hundredths of a percent, big endian */
    const double limit[2] = {c->airtime_limit_short, c->airtime_limit_long};
    for (i = 0; i < 2; ++i) {
      unsigned at = (unsigned)(limit[i] * 100.0);
      if (limit[i] <= 0.0)
        continue;
      b[0] = (uint8_t)(at >> 8);
      b[1] = (uint8_t)at;
      r = queue_command(f, i ? 0x0c : 0x0b, b, 2);
      if (r != RNC_OK)
        return r;
    }
  }
  return RNC_OK;
}
static int auto_socket(uint16_t port) {
  struct sockaddr_storage address;
  struct sockaddr_in6 *a = (struct sockaddr_in6 *)&address;
  int fd;
  memset(&address, 0, sizeof(address));
  a->sin6_family = AF_INET6;
  a->sin6_addr = in6addr_any;
  a->sin6_port = htons(port);
  fd = socket_bound(&address, sizeof(*a), SOCK_DGRAM);
  if (fd >= 0) {
    int one = 1;
    (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
  }
  return fd;
}
static int setup_auto(host_interface *f) {
  struct ifaddrs *all = NULL, *it;
  struct in6_addr local;
  struct ipv6_mreq join;
  struct sockaddr_in6 *m = (struct sockaddr_in6 *)&f->multicast;
  int found = 0;
  if (getifaddrs(&all) < 0)
    return -1;
  for (it = all; it; it = it->ifa_next) {
    if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET6 ||
        (f->device[0] && strcmp(f->device, it->ifa_name)))
      continue;
    local = ((struct sockaddr_in6 *)it->ifa_addr)->sin6_addr;
    if (!IN6_IS_ADDR_LINKLOCAL(&local))
      continue;
    if (!copy_text(f->device, sizeof(f->device), it->ifa_name))
      break;
    f->ifindex = if_nametoindex(it->ifa_name);
    if (!f->ifindex ||
        !inet_ntop(AF_INET6, &local, f->local_ip, sizeof(f->local_ip)))
      break;
    found = 1;
    break;
  }
  freeifaddrs(all);
  if (!found) {
    errno = ENODEV;
    return -1;
  }
  memset(m, 0, sizeof(*m));
  m->sin6_family = AF_INET6;
  m->sin6_port = htons(f->discovery_port);
  m->sin6_scope_id = f->ifindex;
  if (rnc_host_auto_group(f->group, (uint8_t *)&m->sin6_addr) != RNC_OK) {
    errno = EINVAL;
    return -1;
  }
  f->multicast_size = sizeof(*m);
  f->fd = auto_socket(f->data_port);
  if (f->fd < 0)
    return -1;
  f->discovery_fd = auto_socket(f->discovery_port);
  if (f->discovery_fd < 0)
    return -1;
  f->unicast_fd = auto_socket((uint16_t)(f->discovery_port + 1u));
  if (f->unicast_fd < 0)
    return -1;
  memset(&join, 0, sizeof(join));
  join.ipv6mr_multiaddr = m->sin6_addr;
  join.ipv6mr_interface = f->ifindex;
  if (setsockopt(f->discovery_fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &join,
                 sizeof(join)) < 0 ||
      setsockopt(f->discovery_fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &f->ifindex,
                 sizeof(f->ifindex)) < 0)
    return -1;
  f->status.online = 1;
  f->status.bound_port = f->data_port;
  return 0;
}
rnc_host *rnc_host_new(rnc_node *node) {
  rnc_host *h;
  if (!node)
    return NULL;
  h = calloc(1, sizeof(*h));
  if (h) {
    h->node = node;
    h->next_id = 0x80000000u;
  }
  return h;
}
rnc_result rnc_host_remove(rnc_host *h, uint32_t id) {
  host_interface *f;
  size_t i;
  if (!h || !id)
    return RNC_INVALID;
  f = find_interface(h, id);
  if (!f)
    return RNC_STATE;
  for (i = 0; i < RNC_HOST_SLOTS; ++i)
    if (h->interfaces[i].used && h->interfaces[i].status.parent_id == id)
      (void)rnc_host_remove(h, h->interfaces[i].status.interface_id);
  disconnect_interface(h, f, 0);
  free(f->i2p_peers);
  if (f->discovery_fd >= 0)
    close(f->discovery_fd);
  if (f->unicast_fd >= 0)
    close(f->unicast_fd);
  OPENSSL_cleanse(f, sizeof(*f));
  return RNC_OK;
}
void rnc_host_free(rnc_host *h) {
  size_t i;
  if (!h)
    return;
  for (i = 0; i < RNC_HOST_SLOTS; ++i)
    if (h->interfaces[i].used)
      (void)rnc_host_remove(h, h->interfaces[i].status.interface_id);
  OPENSSL_cleanse(h, sizeof(*h));
  free(h);
}
static rnc_result weave_begin(host_interface *f);
static rnc_result host_random(void *context, uint8_t *out, size_t size) {
  (void)context;
  return size <= INT_MAX && RAND_priv_bytes(out, (int)size) == 1 ? RNC_OK
                                                                  : RNC_CRYPTO;
}
rnc_result rnc_host_add(rnc_host *h, uint32_t id, const rnc_host_config *c) {
  host_interface *f;
  struct sockaddr_storage bind_address;
  socklen_t bind_size;
  rnc_result r = RNC_STATE;
  if (!h || !c || !id || id >= 0x80000000u || c->kind < RNC_HOST_TCP_LISTEN ||
      c->kind > RNC_HOST_WEAVE || c->kiss_port > 15 || find_interface(h, id))
    return RNC_INVALID;
  if (c->kind == RNC_HOST_RNODE &&
      (!c->frequency || !c->bandwidth || c->spreading_factor < 5 ||
       c->spreading_factor > 12 || c->coding_rate < 5 || c->coding_rate > 8 ||
       c->tx_power < 0 || c->tx_power > 27))
    return RNC_INVALID;
  if (c->kind == RNC_HOST_RNODE_MULTI) {
    size_t k, j;
    if (!c->address || !*c->address || !strncasecmp(c->address, "tcp://", 6) ||
        !c->subradios || !c->subradio_count ||
        c->subradio_count > RNC_HOST_SUBRADIOS || c->ifac)
      return RNC_INVALID;
    for (k = 0; k < c->subradio_count; ++k) {
      const rnc_host_subradio *s = &c->subradios[k];
      if (!s->name || !*s->name || strlen(s->name) >= 48u ||
          s->vport >= RNC_HOST_SUBRADIOS || !s->frequency ||
          s->bandwidth < 7800u || s->bandwidth > 1625000u ||
          s->spreading_factor < 5 || s->spreading_factor > 12 ||
          s->coding_rate < 5 || s->coding_rate > 8 || s->tx_power < -9 ||
          s->tx_power > 37 ||
          !(s->airtime_limit_short >= 0.0 && s->airtime_limit_short <= 100.0) ||
          !(s->airtime_limit_long >= 0.0 && s->airtime_limit_long <= 100.0))
        return RNC_INVALID;
      for (j = 0; j < k; ++j)
        if (c->subradios[j].vport == s->vport)
          return RNC_INVALID;
    }
  }
  if ((c->kind == RNC_HOST_RNODE || c->kind == RNC_HOST_KISS ||
       c->kind == RNC_HOST_RNODE_MULTI) &&
      (!(c->airtime_limit_short >= 0.0 && c->airtime_limit_short <= 100.0) ||
       !(c->airtime_limit_long >= 0.0 && c->airtime_limit_long <= 100.0) ||
       !c->id_callsign != !c->id_interval ||
       (c->id_callsign && (!*c->id_callsign ||
                           strlen(c->id_callsign) > RNC_HOST_CALLSIGN_MAX))))
    return RNC_INVALID;
  if (c->fast_flap.enabled && c->kind != RNC_HOST_TCP_LISTEN)
    return RNC_INVALID;
  if ((c->serial_databits && (c->serial_databits < 5 || c->serial_databits > 8)) ||
      c->serial_stopbits > 2 ||
      (c->serial_parity && c->serial_parity != 'N' && c->serial_parity != 'E' &&
       c->serial_parity != 'O'))
    return RNC_INVALID;
  if (c->kiss_framing && c->kind != RNC_HOST_TCP_CONNECT)
    return RNC_INVALID;
  if (c->kind == RNC_HOST_WEAVE &&
      (!c->address || !*c->address || (c->mtu && c->mtu != WEAVE_MTU) ||
       (c->serial_baud && !baud_value(c->serial_baud))))
    return RNC_INVALID;
  if (c->kind == RNC_HOST_I2P) {
    size_t k;
    if (!c->i2p_key_path || !*c->i2p_key_path ||
        strlen(c->i2p_key_path) >= sizeof(((host_interface *)0)->i2p_key_path) ||
        (c->i2p_peer_count && !c->i2p_peers) || c->i2p_peer_count > 8u)
      return RNC_INVALID;
    for (k = 0; k < c->i2p_peer_count; ++k)
      if (!c->i2p_peers[k] || !*c->i2p_peers[k] ||
          strlen(c->i2p_peers[k]) >= I2P_PEER_MAX)
        return RNC_INVALID;
  }
  if (c->kind == RNC_HOST_AX25) {
    size_t k, len = c->callsign ? strlen(c->callsign) : 0;
    if (len < 3 || len > 6 || c->ssid > 15)
      return RNC_INVALID;
    for (k = 0; k < len; ++k)
      if (c->callsign[k] < '0' || c->callsign[k] > 'z' ||
          (c->callsign[k] > '9' && c->callsign[k] < 'A') ||
          (c->callsign[k] > 'Z' && c->callsign[k] < 'a'))
        return RNC_INVALID;
  }
  if (c->mtu && (c->mtu < RNC_MTU || c->mtu > RNC_MAX_MTU ||
                 (DEVICE_KIND(c->kind) && c->kind != RNC_HOST_WEAVE &&
                  c->mtu > RNC_MTU) ||
                 (c->kind == RNC_HOST_AUTO && c->mtu > 1196)))
    return RNC_INVALID;
  if (c->ifac && (!c->ifac->size || c->ifac->size > RNC_IFAC_MAX_SIZE))
    return RNC_INVALID;
  if (c->mode > RNC_MODE_BOUNDARY || c->announce_cap_permille > 1000u)
    return RNC_INVALID;
  f = empty_interface(h);
  if (!f)
    return RNC_NO_SPACE;
  memset(f, 0, sizeof(*f));
  f->fd = f->discovery_fd = f->unicast_fd = -1;
  f->used = 1;
  f->status.interface_id = id;
  f->status.kind = c->kind;
  f->status.radio_ready = c->kind != RNC_HOST_RNODE;
  f->status.mtu = c->mtu                       ? c->mtu
                  : c->kind == RNC_HOST_AUTO ? 1196
                  : c->kind == RNC_HOST_I2P  ? I2P_MTU
                  : c->kind == RNC_HOST_WEAVE ? WEAVE_MTU
                                             : RNC_MTU;
  f->status.mode = c->mode;
  f->status.announce_cap_permille = c->announce_cap_permille;
  f->policy.mode = c->mode;
  f->policy.announce_cap_permille = c->announce_cap_permille;
  f->policy.announce_rate_target = c->announce_rate_target;
  f->policy.announce_rate_grace = c->announce_rate_grace;
  f->policy.announce_rate_penalty = c->announce_rate_penalty;
  f->policy.recursive_path_requests = c->recursive_path_requests;
  f->policy.ingress = c->ingress;
  if (!copy_text(f->address, sizeof(f->address), c->address) ||
      !copy_text(f->target, sizeof(f->target), c->target) ||
      !copy_text(f->device, sizeof(f->device), c->device) ||
      !copy_text(f->group, sizeof(f->group),
                 c->group ? c->group : "reticulum")) {
    r = RNC_INVALID;
    goto fail;
  }
  f->target_port = c->target_port;
  f->baud = c->kind == RNC_HOST_WEAVE && !c->serial_baud ? WEAVE_BAUD
                                                          : c->serial_baud;
  f->kiss_port = c->kiss_port;
  f->flow_control = c->flow_control;
  f->ready = !c->flow_control;
  f->kiss = c->kiss_framing;
  f->flap_on = c->fast_flap.enabled;
  f->no_output = c->no_output;
  f->flap_threshold_ms =
      (c->fast_flap.threshold_seconds ? c->fast_flap.threshold_seconds : 20u) *
      1000u;
  f->flap_grace = c->fast_flap.grace ? c->fast_flap.grace : 5u;
  f->flap_expiry_ms = (uint64_t)(c->fast_flap.expiry_seconds
                                     ? c->fast_flap.expiry_seconds
                                     : 12u * 3600u) *
                      1000u;
  if (c->bitrate)
    f->bitrate = c->bitrate;
  else if (c->kind == RNC_HOST_RNODE) {
    /* on-air rate as the reference computes it: sf * (4/cr) / (2^sf / bw) */
    uint64_t den = (uint64_t)c->coding_rate << c->spreading_factor;
    f->bitrate = (uint32_t)(((uint64_t)c->spreading_factor * 4u *
                                 c->bandwidth + den / 2u) / den);
    if (!f->bitrate)
      f->bitrate = 1u;
  } else
    f->bitrate = c->kind == RNC_HOST_PIPE  ? 1000000u
                 : c->kind == RNC_HOST_I2P  ? 256000u
                 : c->kind == RNC_HOST_AX25 ? 1200u
                 : c->kind == RNC_HOST_WEAVE ? WEAVE_BITRATE
                                            : 10000000u;
  f->status.bitrate = f->bitrate;
  f->status.local = c->local;
  if (c->name) {
    if (!copy_text(f->status.name, sizeof(f->status.name), c->name)) {
      r = RNC_INVALID;
      goto fail;
    }
  } else
    (void)snprintf(f->status.name, sizeof(f->status.name), "reticulum-c/%u",
                   id);
  if (rnc_hash(f->status.name, strlen(f->status.name), f->status.hash) !=
      RNC_OK) {
    r = RNC_CRYPTO;
    goto fail;
  }
  f->radio = *c;
  f->radio.address = f->radio.target = f->radio.device = f->radio.group = NULL;
  f->radio.ifac = NULL;
  f->radio.name = NULL;
  f->radio.id_callsign = NULL;
  f->radio.callsign = NULL;
  f->radio.i2p_key_path = NULL;
  f->radio.i2p_peers = NULL;
  if (c->kind == RNC_HOST_I2P) {
    size_t k, used = 0;
    if (!f->radio.reconnect_wait_ms)
      f->radio.reconnect_wait_ms = I2P_RECONNECT_MS;
    (void)copy_text(f->i2p_key_path, sizeof(f->i2p_key_path), c->i2p_key_path);
    (void)snprintf(f->i2p_session, sizeof(f->i2p_session), "rnc%08x", id);
    f->i2p_peer_count = (unsigned)c->i2p_peer_count;
    for (k = 0; k < c->i2p_peer_count; ++k)
      used += strlen(c->i2p_peers[k]) + 1u;
    if (used) {
      f->i2p_peers = malloc(used);
      if (!f->i2p_peers) {
        r = RNC_NO_SPACE;
        goto fail;
      }
      f->i2p_peers_size = used;
      for (used = k = 0; k < c->i2p_peer_count; ++k) {
        size_t n = strlen(c->i2p_peers[k]) + 1u;
        memcpy(f->i2p_peers + used, c->i2p_peers[k], n);
        used += n;
      }
    }
  }
  if (c->kind == RNC_HOST_WEAVE) {
    /* the switch identity is new for every run, as in the reference */
    if (rnc_identity_generate(&f->weave_id, host_random, NULL) != RNC_OK) {
      r = RNC_CRYPTO;
      goto fail;
    }
    memcpy(f->weave_sw, f->weave_id.public_key + 60, 4);
  }
  if (c->kind == RNC_HOST_AX25) {
    size_t k;
    for (k = 0; c->callsign[k]; ++k)
      f->ax_call[k] = (char)(c->callsign[k] >= 'a' ? c->callsign[k] - 32
                                                    : c->callsign[k]);
  }
  if (c->kind == RNC_HOST_RNODE_MULTI) {
    size_t k;
    f->sub_count = (unsigned)c->subradio_count;
    for (k = 0; k < c->subradio_count; ++k) {
      f->subs[k] = c->subradios[k];
      (void)copy_text(f->sub_names[k], sizeof(f->sub_names[k]),
                      c->subradios[k].name);
      f->subs[k].name = f->sub_names[k];
    }
    f->radio.subradios = NULL;
  }
  if ((c->kind == RNC_HOST_RNODE || c->kind == RNC_HOST_KISS ||
       c->kind == RNC_HOST_RNODE_MULTI) &&
      c->id_callsign) {
    f->callsign_size = strlen(c->id_callsign);
    memcpy(f->callsign, c->id_callsign, f->callsign_size);
  }
  if (c->ifac) {
    f->ifac = *c->ifac;
    f->has_ifac = 1;
    f->status.ifac_size = f->ifac.size;
    {
      uint8_t hash[32];
      if (rnc_hash(f->ifac.key, 64, hash) != RNC_OK ||
          rnc_identity_sign(&f->ifac.identity, hash, 32,
                            f->status.ifac_signature) != RNC_OK) {
        r = RNC_CRYPTO;
        goto fail;
      }
    }
  }
  if (c->kind == RNC_HOST_TCP_LISTEN) {
    if (resolve(c->address, c->port, SOCK_STREAM, 1, AF_UNSPEC,
                c->prefer_ipv6, &bind_address, &bind_size) < 0)
      goto fail;
    f->fd = socket_bound(&bind_address, bind_size, SOCK_STREAM);
    if (f->fd < 0 || listen(f->fd, 8) < 0)
      goto fail;
    f->status.bound_port = bound_port(f->fd);
    f->status.online = 1;
  } else if (c->kind == RNC_HOST_TCP_CONNECT) {
    if (!c->port || resolve(c->address, c->port, SOCK_STREAM, 0, AF_UNSPEC,
                            c->prefer_ipv6, &f->peer, &f->peer_size) < 0) {
      r = RNC_INVALID;
      goto fail;
    }
    if (connect_interface(h, f) < 0) {
      f->status.last_errno = errno;
      note_connect_failure(h, f);
    }
  } else if (c->kind == RNC_HOST_I2P) {
    if (resolve(*f->address ? f->address : "127.0.0.1",
                c->port ? c->port : 7656, SOCK_STREAM, 0, AF_UNSPEC,
                c->prefer_ipv6, &f->peer, &f->peer_size) < 0) {
      r = RNC_INVALID;
      goto fail;
    }
    f->sam_role = SAM_SESSION;
    if (connect_interface(h, f) < 0) {
      f->status.last_errno = errno;
      note_connect_failure(h, f);
    }
  } else if (c->kind == RNC_HOST_UDP) {
    if (resolve(c->address, c->port, SOCK_DGRAM, 1, AF_UNSPEC, 0, &bind_address,
                &bind_size) < 0)
      goto fail;
    f->fd = socket_bound(&bind_address, bind_size, SOCK_DGRAM);
    if (f->fd < 0)
      goto fail;
    f->status.bound_port = bound_port(f->fd);
    if (c->target && c->target_port &&
        resolve(c->target, c->target_port, SOCK_DGRAM, 0,
                bind_address.ss_family, 0, &f->peer, &f->peer_size) < 0)
      goto fail;
    r = activate(h, f);
    if (r != RNC_OK)
      goto fail;
  } else if (c->kind == RNC_HOST_AUTO) {
    f->discovery_port = c->discovery_port ? c->discovery_port : 29716;
    f->data_port = c->data_port ? c->data_port : 42671;
    if (f->discovery_port == 65535 || setup_auto(f) < 0)
      goto fail;
  } else {
    if (c->kind == RNC_HOST_PIPE && !*f->address) {
      r = RNC_INVALID;
      goto fail;
    }
    if (c->kind == RNC_HOST_RNODE && !strncasecmp(f->address, "tcp://", 6)) {
      /* a WiFi RNode: connect now, set the radio up when the socket opens */
      f->rnode_tcp = 1;
      if (resolve(f->address + 6, c->port ? c->port : 7633u, SOCK_STREAM, 0,
                  AF_UNSPEC, c->prefer_ipv6, &f->peer, &f->peer_size) < 0) {
        r = RNC_INVALID;
        goto fail;
      }
      f->fd = device_open(f);
      if (f->fd < 0) {
        f->status.last_errno = errno;
        note_connect_failure(h, f);
      }
    } else {
      f->fd = device_open(f);
      if (f->fd < 0)
        goto fail;
      if (c->kind == RNC_HOST_WEAVE) {
        /* the switch is not itself a node interface; its endpoints are */
        r = weave_begin(f);
        if (r != RNC_OK)
          goto fail;
        return RNC_OK;
      }
      if (c->kind == RNC_HOST_RNODE_MULTI) {
        /* the device is not itself a node interface; its radios are */
        f->status.online = 1;
        r = begin_multi(f);
        if (r != RNC_OK)
          goto fail;
        return RNC_OK;
      }
      r = activate(h, f);
      if (r != RNC_OK)
        goto fail;
      if (c->kind == RNC_HOST_RNODE) {
        r = begin_rnode(f);
        if (r != RNC_OK)
          goto fail;
      } else if (TNC_KIND(c->kind)) {
        r = configure_ax25(f, c);
        if (r != RNC_OK)
          goto fail;
      }
    }
  }
  return RNC_OK;
fail: {
  int e = errno;
  (void)rnc_host_remove(h, id);
  errno = e;
  return r;
}
}
static size_t blocked_count(const rnc_host *h, const host_interface *l) {
  size_t i, n = 0;
  if (!l->flap_on)
    return 0;
  for (i = 0; i < HOST_FLAP_SLOTS; ++i)
    if (l->flaps[i].count > l->flap_grace &&
        !flap_expired(l, &l->flaps[i], h->now))
      ++n;
  return n;
}
rnc_result rnc_host_get_status(const rnc_host *h, uint32_t id,
                               rnc_host_status *out) {
  size_t i;
  if (!h || !out)
    return RNC_INVALID;
  for (i = 0; i < RNC_HOST_SLOTS; ++i)
    if (h->interfaces[i].used && h->interfaces[i].status.interface_id == id) {
      *out = h->interfaces[i].status;
      out->queued_frames = h->interfaces[i].queue_count;
      out->blocked_ips = blocked_count(h, &h->interfaces[i]);
      return RNC_OK;
    }
  return RNC_AGAIN;
}
rnc_result rnc_host_status_at(const rnc_host *h, size_t index,
                              rnc_host_status *out) {
  if (!h || !out)
    return RNC_INVALID;
  if (index >= RNC_HOST_SLOTS || !h->interfaces[index].used ||
      (h->interfaces[index].sam_role == SAM_ACCEPT &&
       !h->interfaces[index].sam_streamed))
    return RNC_AGAIN; /* an I2P acceptor still waiting is not yet a peer */
  *out = h->interfaces[index].status;
  out->queued_frames = h->interfaces[index].queue_count;
  out->blocked_ips = blocked_count(h, &h->interfaces[index]);
  return RNC_OK;
}
rnc_result rnc_host_poll(rnc_host *h, rnc_host_event *out) {
  if (!h || !out)
    return RNC_INVALID;
  if (!h->count)
    return RNC_AGAIN;
  *out = h->events[h->head];
  memset(&h->events[h->head], 0, sizeof(*out));
  h->head = (h->head + 1u) % RNC_NODE_EVENTS;
  --h->count;
  return RNC_OK;
}
static rnc_result queue_packet(host_interface *f, const rnc_packet *p) {
  uint8_t raw[RNC_MAX_MTU], wire[RNC_MAX_FRAME];
  size_t n, m;
  rnc_result r;
  host_frame *q;
  if (f->queue_count == RNC_HOST_QUEUE_FRAMES)
    return RNC_AGAIN;
  r = rnc_packet_encode(p, raw, sizeof(raw), &n);
  if (r != RNC_OK)
    return r;
  if (n > f->status.mtu)
    return RNC_UNSUPPORTED;
  if (f->has_ifac) {
    r = rnc_ifac_apply(&f->ifac, raw, n, wire, sizeof(wire), &m);
    if (r != RNC_OK)
      return r;
  } else {
    memcpy(wire, raw, n);
    m = n;
  }
  q = &f->queue[f->queue_count];
  memset(q, 0, sizeof(*q));
  q->announce = (p->flags & 3u) == RNC_ANNOUNCE;
  q->wire_size = m;
  if (f->status.kind == RNC_HOST_UDP || f->status.kind == RNC_HOST_AUTO) {
    memcpy(q->data, wire, m);
    q->size = m;
  } else if (f->weave_peer) {
    /* a command to the switch: deliver this packet to one endpoint */
    uint8_t cmd[RNC_MAX_FRAME];
    if (m + 15u > sizeof(cmd))
      return RNC_NO_SPACE;
    memcpy(cmd, f->weave_remote, 4);
    cmd[4] = 0x02; /* WDCL command */
    cmd[5] = 0x00;
    cmd[6] = 0x01; /* deliver an endpoint packet */
    memcpy(cmd + 7, f->weave_endpoint, 8);
    memcpy(cmd + 15, wire, m);
    r = rnc_host_frame_encode(RNC_HOST_HDLC, 0, cmd, 15u + m, q->data,
                              sizeof(q->data), &q->size);
    if (r != RNC_OK)
      return r;
  } else if (f->status.kind == RNC_HOST_AX25) {
    uint8_t ax[16 + RNC_MAX_FRAME];
    size_t k;
    for (k = 0; k < 6; ++k) {
      ax[k] = (uint8_t)("APZRNS"[k] << 1);
      ax[7 + k] = k < strlen(f->ax_call) ? (uint8_t)(f->ax_call[k] << 1) : 0x20;
    }
    ax[6] = 0x60;
    ax[13] = (uint8_t)(0x60u | (f->radio.ssid << 1) | 1u);
    ax[14] = 0x03; /* UI frame */
    ax[15] = 0xf0; /* no layer 3 */
    memcpy(ax + 16, wire, m);
    r = rnc_host_frame_encode(RNC_HOST_KISS_FRAMING,
                              (uint8_t)(f->kiss_port << 4), ax, 16 + m,
                              q->data, sizeof(q->data), &q->size);
    if (r != RNC_OK)
      return r;
  } else {
    r = rnc_host_frame_encode((f->status.kind == RNC_HOST_TCP_LISTEN ||
                               f->status.kind == RNC_HOST_TCP_CONNECT ||
                               f->status.kind == RNC_HOST_SERIAL ||
                               f->status.kind == RNC_HOST_PIPE) &&
                                      !f->kiss
                                  ? RNC_HOST_HDLC
                                  : RNC_HOST_KISS_FRAMING,
                              (uint8_t)(f->kiss_port << 4), wire, m, q->data,
                              sizeof(q->data), &q->size);
    if (r != RNC_OK)
      return r;
  }
  r = select_prefix(f, q);
  if (r != RNC_OK)
    return r;
  ++f->queue_count;
  return RNC_OK;
}
static rnc_result pump_node(rnc_host *h) {
  for (;;) {
    rnc_node_event e;
    rnc_result r;
    host_interface *f;
    if (h->held)
      e = h->held_event;
    else {
      r = rnc_node_poll(h->node, &e);
      if (r == RNC_AGAIN)
        return RNC_OK;
      if (r != RNC_OK)
        return r;
    }
    if (e.type == RNC_NODE_SEND) {
      f = find_interface(h, e.interface_id);
      if (!f || !f->node_added || f->no_output) {
        h->held = 0;
        continue;
      }
      r = queue_packet(f, &e.packet);
      if (r == RNC_AGAIN) {
        h->held = 1;
        h->held_event = e;
        return RNC_OK;
      }
      if (r != RNC_OK) {
        ++f->status.dropped_packets;
        h->held = 0;
        continue;
      }
    } else if (!emit_host(h, RNC_HOST_NODE, e.interface_id, 0, &e)) {
      h->held = 1;
      h->held_event = e;
      return RNC_OK;
    }
    h->held = 0;
  }
}
static rnc_result input_packet(rnc_host *h, host_interface *f,
                               const uint8_t *data, size_t size,
                               uint64_t unix_seconds) {
  uint8_t raw[RNC_MAX_MTU];
  size_t n, wire_size = size;
  rnc_packet p;
  rnc_result r;
  if (f->has_ifac) {
    r = rnc_ifac_verify(&f->ifac, data, size, raw, sizeof(raw), &n);
    if (r != RNC_OK) {
      ++f->status.dropped_packets;
      ++f->status.ifac_violations;
      return RNC_OK;
    }
    data = raw;
    size = n;
  }
  if (size > f->status.mtu) {
    ++f->status.dropped_packets;
    return RNC_OK;
  }
  r = rnc_packet_decode(data, size, &p);
  if (r != RNC_OK) {
    ++f->status.dropped_packets;
    ++f->status.protocol_violations;
    return RNC_OK;
  }
  r = rnc_node_input(h->node, f->status.interface_id, &p, unix_seconds, h->now);
  if (r == RNC_AGAIN) {
    f->pending = 1;
    f->pending_packet = p;
    f->pending_wire_size = wire_size;
    return RNC_AGAIN;
  }
  if (r == RNC_OK) {
    ++f->status.rx_packets;
    f->status.rx_bytes += wire_size;
    if ((p.flags & 3u) == RNC_ANNOUNCE) {
      ++f->status.rx_announces;
      f->status.rx_announce_bytes += wire_size;
    }
    f->last_heard = h->now;
  } else
    ++f->status.dropped_packets;
  return pump_node(h);
}
static void accept_tcp(rnc_host *h, host_interface *parent) {
  int fd;
  host_interface *f;
  struct sockaddr_storage peer;
  socklen_t peer_size = sizeof(peer);
  char ip[INET6_ADDRSTRLEN] = "";
  fd = accept(parent->fd, (struct sockaddr *)&peer, &peer_size);
  if (fd < 0)
    return;
  if (peer.ss_family == AF_INET)
    (void)inet_ntop(AF_INET, &((struct sockaddr_in *)&peer)->sin_addr, ip,
                    sizeof(ip));
  else if (peer.ss_family == AF_INET6)
    (void)inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&peer)->sin6_addr, ip,
                    sizeof(ip));
  if (parent->flap_on && flap_blocked(parent, ip, h->now)) {
    rnc_logf(RNC_LOG_NOTICE, "host",
             "refusing connection from fast-flapping address %s on %s", ip,
             parent->status.name);
    close(fd);
    ++parent->status.dropped_packets;
    return;
  }
  if (nonblock(fd) < 0) {
    close(fd);
    return;
  }
  tcp_tune(fd);
  f = empty_interface(h);
  if (!f || h->next_id < 0x80000000u) {
    close(fd);
    ++parent->status.dropped_packets;
    return;
  }
  memset(f, 0, sizeof(*f));
  f->used = 1;
  f->fd = fd;
  f->discovery_fd = f->unicast_fd = -1;
  f->accepted = 1;
  f->spawned_at = h->now;
  f->flap_pending = parent->flap_on;
  f->no_output = parent->no_output;
  (void)snprintf(f->peer_ip, sizeof(f->peer_ip), "%s", ip);
  f->status.kind = RNC_HOST_TCP_CONNECT;
  f->status.interface_id = h->next_id++;
  f->status.parent_id = parent->status.interface_id;
  f->status.mtu = parent->status.mtu;
  f->status.mode = parent->status.mode;
  f->status.announce_cap_permille = parent->status.announce_cap_permille;
  f->policy = parent->policy;
  f->bitrate = parent->bitrate;
  f->status.bitrate = parent->status.bitrate;
  f->status.local = parent->status.local;
  f->status.ifac_size = parent->status.ifac_size;
  memcpy(f->status.ifac_signature, parent->status.ifac_signature, 64);
  (void)snprintf(f->status.name, sizeof(f->status.name),
                 "TCPInterface[Client on %.80s/%u]", parent->status.name,
                 f->status.interface_id);
  (void)rnc_hash(f->status.name, strlen(f->status.name), f->status.hash);
  f->has_ifac = parent->has_ifac;
  if (f->has_ifac)
    f->ifac = parent->ifac;
  if (activate(h, f) != RNC_OK) {
    close(fd);
    OPENSSL_cleanse(f, sizeof(*f));
    ++parent->status.dropped_packets;
  }
}
/* ---- I2P through a router's SAM v3 bridge ----
 * The controller interface keeps one SAM socket open for the session (the
 * session ends with it). Every stream is a further socket to the bridge: it
 * says HELLO, then either STREAM CONNECT (after a NAMING LOOKUP when the peer
 * is a name) or STREAM ACCEPT, and once the router answers the same socket
 * carries HDLC frames like a TCP connection. Replies are read line by line
 * through the interface's input buffer, so bytes that follow the last reply
 * flow into the framer unchanged. */
static int sam_send(host_interface *f, const char *text) {
  size_t n = strlen(text);
#ifdef MSG_NOSIGNAL
  ssize_t w = send(f->fd, text, n, MSG_NOSIGNAL);
#else
  ssize_t w = send(f->fd, text, n, 0);
#endif
  return w == (ssize_t)n ? 0 : -1;
}
static void sam_fail(rnc_host *h, host_interface *f, const char *what) {
  rnc_logf(RNC_LOG_ERROR, "host", "%s: %s", f->status.name, what);
  disconnect_interface(h, f, EPROTO);
}
static rnc_result sam_start(rnc_host *h, host_interface *f) {
  (void)h;
  f->sam_step = SS_HELLO;
  f->sam_len = 0;
  f->sam_deadline = 0;
  f->last_read_ms = 0;
  return sam_send(f, "HELLO VERSION MIN=3.1 MAX=3.1\n") == 0 ? RNC_OK
                                                           : RNC_STATE;
}
/* 1 = key loaded, 0 = no key file yet, -1 = unusable file (never overwritten) */
static int i2p_load_key(host_interface *f) {
  char text[sizeof(f->i2p_private)], pub[700];
  size_t n;
  FILE *file = fopen(f->i2p_key_path, "r");
  if (!file)
    return errno == ENOENT ? 0 : -1;
  n = fread(text, 1, sizeof(text) - 1u, file);
  fclose(file);
  while (n && (text[n - 1] == '\n' || text[n - 1] == '\r' ||
               text[n - 1] == ' '))
    --n;
  text[n] = 0;
  if (!n || rnc_i2p_private_to_public(text, pub, sizeof(pub)) != RNC_OK) {
    OPENSSL_cleanse(text, sizeof(text));
    return -1;
  }
  memcpy(f->i2p_private, text, n + 1u);
  OPENSSL_cleanse(text, sizeof(text));
  return 1;
}
static int i2p_save_key(host_interface *f) {
  char tmp[sizeof(f->i2p_key_path) + 8u];
  size_t n = strlen(f->i2p_private);
  int fd, ok;
  (void)snprintf(tmp, sizeof(tmp), "%s.tmp", f->i2p_key_path);
  fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0)
    return -1;
  ok = write(fd, f->i2p_private, n) == (ssize_t)n && fsync(fd) == 0;
  ok = close(fd) == 0 && ok;
  if (!ok || rename(tmp, f->i2p_key_path) != 0) {
    (void)unlink(tmp);
    return -1;
  }
  return 0;
}
static int sam_session_create(host_interface *f) {
  char cmd[sizeof(f->i2p_private) + 96u];
  int r;
  (void)snprintf(cmd, sizeof(cmd),
                 "SESSION CREATE STYLE=STREAM ID=%s DESTINATION=%s\n",
                 f->i2p_session, f->i2p_private);
  r = sam_send(f, cmd);
  OPENSSL_cleanse(cmd, sizeof(cmd));
  f->sam_step = SS_SESSION;
  return r;
}
static int sam_stream_connect(host_interface *f, const char *destination) {
  char cmd[I2P_PEER_MAX + 96u];
  (void)snprintf(cmd, sizeof(cmd),
                 "STREAM CONNECT ID=%s DESTINATION=%s SILENT=false\n",
                 f->i2p_session, destination);
  f->sam_step = SS_CONNECT;
  return sam_send(f, cmd);
}
/* A peer written as a b32 name, as 52 bare characters or as a destination.
 * Like the reference, a name is looked up on a socket of its own; the stream
 * is then made on a fresh one. */
static int sam_dial(host_interface *f) {
  size_t n = strlen(f->sam_peer);
  char cmd[I2P_PEER_MAX + 64u];
  if (f->sam_resolved)
    return sam_stream_connect(f, f->sam_dest);
  if (n >= 400u)
    return sam_stream_connect(f, f->sam_peer);
  if (n == 52u && !strchr(f->sam_peer, '.'))
    (void)snprintf(cmd, sizeof(cmd), "NAMING LOOKUP NAME=%s.b32.i2p\n",
                   f->sam_peer);
  else
    (void)snprintf(cmd, sizeof(cmd), "NAMING LOOKUP NAME=%s\n", f->sam_peer);
  f->sam_step = SS_LOOKUP;
  return sam_send(f, cmd);
}
static void sam_stream_up(rnc_host *h, host_interface *f) {
  f->sam_step = SS_IDLE;
  f->sam_deadline = 0;
  f->sam_streamed = 1;
  f->last_read_ms = h->now;
  f->last_write_ms = h->now;
  if (activate(h, f) != RNC_OK)
    disconnect_interface(h, f, ENOSPC);
}
static void sam_line_in(rnc_host *h, host_interface *f) {
  rnc_i2p_reply r;
  char value[1100], reason[96];
  if (f->sam_step == SS_CONTROL) {
    /* routers may ping the session socket and expect the text back */
    if (!strncmp(f->sam_line, "PING", 4)) {
      char pong[RNC_I2P_REPLY_MAX + 8u];
      (void)snprintf(pong, sizeof(pong), "PONG%s\n", f->sam_line + 4);
      (void)sam_send(f, pong);
    }
    return;
  }
  if (f->sam_step == SS_REMOTE) {
    uint8_t bin[700];
    size_t n, size;
    char b32[RNC_I2P_B32_SIZE];
    if (rnc_i2p_b64_decode(f->sam_line, bin, sizeof(bin), &n) != RNC_OK ||
        rnc_i2p_destination_size(bin, n, &size) != RNC_OK ||
        rnc_i2p_b32(bin, size, b32) != RNC_OK) {
      sam_fail(h, f, "the router sent an invalid remote destination");
      return;
    }
    rnc_logf(RNC_LOG_INFO, "host", "accepted I2P connection from %s.b32.i2p",
             b32);
    sam_stream_up(h, f);
    return;
  }
  if (rnc_i2p_reply_parse(f->sam_line, &r) != RNC_OK) {
    sam_fail(h, f, "unreadable reply from the SAM bridge");
    return;
  }
  if (f->sam_step != SS_DEST && !r.ok) {
    if (rnc_i2p_reply_value(&r, "RESULT", value, sizeof(value)) != RNC_OK)
      (void)snprintf(value, sizeof(value), "no result");
    (void)snprintf(reason, sizeof(reason), "the SAM bridge refused: %.40s",
                   value);
    sam_fail(h, f, reason);
    return;
  }
  switch (f->sam_step) {
  case SS_HELLO:
    if (strcmp(r.topic, "HELLO")) {
      sam_fail(h, f, "unexpected reply to HELLO");
      return;
    }
    if (f->sam_role == SAM_SESSION) {
      int loaded = i2p_load_key(f);
      if (loaded < 0) {
        sam_fail(h, f, "the key file is unreadable or not an I2P key");
        return;
      }
      if (loaded) {
        if (sam_session_create(f))
          disconnect_interface(h, f, EPIPE);
      } else {
        f->sam_step = SS_DEST;
        if (sam_send(f, "DEST GENERATE SIGNATURE_TYPE=7\n"))
          disconnect_interface(h, f, EPIPE);
      }
    } else if (f->sam_role == SAM_CONNECT) {
      if (sam_dial(f))
        disconnect_interface(h, f, EPIPE);
    } else {
      char cmd[96];
      (void)snprintf(cmd, sizeof(cmd), "STREAM ACCEPT ID=%s SILENT=false\n",
                     f->i2p_session);
      f->sam_step = SS_ACCEPT;
      if (sam_send(f, cmd))
        disconnect_interface(h, f, EPIPE);
    }
    break;
  case SS_DEST: {
    host_interface *c = f;
    if (strcmp(r.topic, "DEST") ||
        rnc_i2p_reply_value(&r, "PRIV", c->i2p_private,
                            sizeof(c->i2p_private)) != RNC_OK ||
        rnc_i2p_private_to_public(c->i2p_private, value, sizeof(value)) !=
            RNC_OK) {
      sam_fail(h, f, "the router did not generate a destination");
      return;
    }
    if (i2p_save_key(c) != 0) {
      sam_fail(h, f, "cannot write the key file");
      return;
    }
    if (sam_session_create(f))
      disconnect_interface(h, f, EPIPE);
    break;
  }
  case SS_SESSION: {
    uint8_t bin[700];
    size_t n, size;
    if (strcmp(r.topic, "SESSION") ||
        rnc_i2p_private_to_public(f->i2p_private, value, sizeof(value)) !=
            RNC_OK ||
        rnc_i2p_b64_decode(value, bin, sizeof(bin), &n) != RNC_OK ||
        rnc_i2p_destination_size(bin, n, &size) != RNC_OK ||
        rnc_i2p_b32(bin, size, f->status.i2p_b32) != RNC_OK) {
      sam_fail(h, f, "unexpected reply to SESSION CREATE");
      return;
    }
    f->i2p_ready = 1;
    f->status.online = 1;
    f->status.last_errno = 0;
    f->tries = 0;
    f->sam_step = SS_CONTROL;
    f->sam_deadline = 0;
    rnc_logf(RNC_LOG_INFO, "host", "%s is reachable at %s.b32.i2p",
             f->status.name, f->status.i2p_b32);
    break;
  }
  case SS_LOOKUP:
    if (strcmp(r.topic, "NAMING") ||
        rnc_i2p_reply_value(&r, "VALUE", f->sam_dest, sizeof(f->sam_dest)) !=
            RNC_OK) {
      sam_fail(h, f, "unexpected reply to NAMING LOOKUP");
      return;
    }
    /* done with this socket; the stream gets its own */
    close(f->fd);
    f->fd = -1;
    f->sam_step = 0;
    f->sam_len = 0;
    f->input_offset = f->input_size = 0;
    f->sam_resolved = 1;
    if (connect_interface(h, f) < 0) {
      f->status.last_errno = errno;
      f->sam_resolved = 0;
      note_connect_failure(h, f);
    }
    break;
  case SS_CONNECT:
    if (strcmp(r.topic, "STREAM")) {
      sam_fail(h, f, "unexpected reply to STREAM CONNECT");
      return;
    }
    sam_stream_up(h, f);
    break;
  case SS_ACCEPT:
    if (strcmp(r.topic, "STREAM")) {
      sam_fail(h, f, "unexpected reply to STREAM ACCEPT");
      return;
    }
    /* now waiting, without limit, for someone to dial in */
    f->sam_step = SS_REMOTE;
    f->sam_deadline = 0;
    break;
  default:
    break;
  }
}
static void sam_feed(rnc_host *h, host_interface *f) {
  while (f->sam_step && f->fd >= 0 && f->input_offset < f->input_size) {
    uint8_t b = f->input[f->input_offset++];
    if (b == '\n') {
      if (f->sam_len && f->sam_line[f->sam_len - 1u] == '\r')
        --f->sam_len;
      f->sam_line[f->sam_len] = 0;
      f->sam_len = 0;
      sam_line_in(h, f);
    } else if (f->sam_len + 1u < sizeof(f->sam_line))
      f->sam_line[f->sam_len++] = (char)b;
    else
      sam_fail(h, f, "line from the SAM bridge is too long");
  }
}
static host_interface *i2p_child_of(rnc_host *h, const host_interface *c,
                                    int role, unsigned index) {
  size_t i;
  for (i = 0; i < RNC_HOST_SLOTS; ++i) {
    host_interface *f = &h->interfaces[i];
    if (f->used && f->status.parent_id == c->status.interface_id &&
        f->sam_role == role &&
        (role != SAM_CONNECT || f->peer_index == index) &&
        (role != SAM_ACCEPT || !f->sam_streamed))
      return f;
  }
  return NULL;
}
static void i2p_spawn(rnc_host *h, host_interface *c, int role,
                      unsigned index) {
  host_interface *f = empty_interface(h);
  if (!f || h->next_id < 0x80000000u) {
    ++c->status.dropped_packets;
    return;
  }
  memset(f, 0, sizeof(*f));
  f->used = 1;
  f->fd = f->discovery_fd = f->unicast_fd = -1;
  f->sam_role = role;
  f->peer_index = index;
  f->accepted = role == SAM_ACCEPT;
  f->no_output = c->no_output;
  f->status.kind = RNC_HOST_TCP_CONNECT;
  f->status.interface_id = h->next_id++;
  f->status.parent_id = c->status.interface_id;
  f->status.mtu = c->status.mtu;
  f->status.mode = c->status.mode;
  f->status.announce_cap_permille = c->status.announce_cap_permille;
  f->policy = c->policy;
  f->bitrate = c->bitrate;
  f->status.bitrate = c->status.bitrate;
  f->status.ifac_size = c->status.ifac_size;
  memcpy(f->status.ifac_signature, c->status.ifac_signature, 64);
  f->has_ifac = c->has_ifac;
  if (f->has_ifac)
    f->ifac = c->ifac;
  f->radio = c->radio;
  f->peer = c->peer;
  f->peer_size = c->peer_size;
  (void)snprintf(f->i2p_session, sizeof(f->i2p_session), "%s", c->i2p_session);
  if (role == SAM_CONNECT) {
    const char *p = c->i2p_peers;
    unsigned k;
    for (k = 0; k < index; ++k)
      p += strlen(p) + 1u;
    (void)snprintf(f->sam_peer, sizeof(f->sam_peer), "%s", p);
    (void)snprintf(f->status.name, sizeof(f->status.name),
                   "I2PInterfacePeer[%.100s]", f->sam_peer);
  } else
    (void)snprintf(f->status.name, sizeof(f->status.name),
                   "I2PInterfacePeer[Connected peer on %.80s]",
                   c->status.name);
  (void)rnc_hash(f->status.name, strlen(f->status.name), f->status.hash);
  if (connect_interface(h, f) < 0) {
    f->status.last_errno = errno;
    if (role == SAM_ACCEPT) {
      c->accept_after = h->now + 5000u;
      OPENSSL_cleanse(f, sizeof(*f));
    } else
      note_connect_failure(h, f);
  }
}
/* The controller keeps a dialler per configured peer and, when connectable,
 * exactly one acceptor waiting on the router. */
static void i2p_maintain(rnc_host *h, host_interface *c) {
  unsigned k;
  if (!c->i2p_ready)
    return;
  for (k = 0; k < c->i2p_peer_count; ++k)
    if (!i2p_child_of(h, c, SAM_CONNECT, k))
      i2p_spawn(h, c, SAM_CONNECT, k);
  if (c->radio.i2p_connectable && h->now >= c->accept_after &&
      !i2p_child_of(h, c, SAM_ACCEPT, 0))
    i2p_spawn(h, c, SAM_ACCEPT, 0);
}
/* With the session gone every stream it carried is gone too. */
static void i2p_session_lost(rnc_host *h, host_interface *c) {
  size_t i;
  c->i2p_ready = 0;
  c->status.i2p_b32[0] = 0;
  OPENSSL_cleanse(c->i2p_private, sizeof(c->i2p_private));
  for (i = 0; i < RNC_HOST_SLOTS; ++i) {
    host_interface *f = &h->interfaces[i];
    if (f->used && f->status.parent_id == c->status.interface_id &&
        f->fd >= 0)
      disconnect_interface(h, f, ECONNRESET);
  }
}
/* Idle streams are kept alive with an empty HDLC frame, and one that has gone
 * silent for the reference's whole probe window is dropped. */
static void i2p_watchdog(rnc_host *h, host_interface *f, uint64_t now) {
  if (now - f->last_read_ms > I2P_READ_TIMEOUT_MS) {
    rnc_logf(RNC_LOG_WARNING, "host", "%s is unresponsive", f->status.name);
    disconnect_interface(h, f, ETIMEDOUT);
  } else if (!f->queue_count && now - f->last_write_ms > I2P_PROBE_AFTER_MS) {
    static const char flags[2] = {0x7e, 0x7e};
#ifdef MSG_NOSIGNAL
    ssize_t w = send(f->fd, flags, sizeof(flags), MSG_NOSIGNAL);
#else
    ssize_t w = send(f->fd, flags, sizeof(flags), 0);
#endif
    if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
      disconnect_interface(h, f, errno);
    else
      f->last_write_ms = now;
  }
}
static host_interface *auto_peer(rnc_host *h, host_interface *parent,
                                 const struct sockaddr_in6 *source) {
  size_t i;
  for (i = 0; i < RNC_HOST_SLOTS; ++i) {
    host_interface *f = &h->interfaces[i];
    struct sockaddr_in6 *p = (struct sockaddr_in6 *)&f->peer;
    if (f->used && f->status.parent_id == parent->status.interface_id &&
        f->status.kind == RNC_HOST_AUTO &&
        p->sin6_scope_id == source->sin6_scope_id &&
        !memcmp(&p->sin6_addr, &source->sin6_addr, sizeof(p->sin6_addr)))
      return f;
  }
  return NULL;
}
static void discovery_input(rnc_host *h, host_interface *parent, int fd,
                            int reverse) {
  uint8_t token[64], expected[32];
  struct sockaddr_in6 source;
  char text[INET6_ADDRSTRLEN];
  socklen_t n = sizeof(source);
  ssize_t size =
      recvfrom(fd, token, sizeof(token), 0, (struct sockaddr *)&source, &n);
  host_interface *f;
  if (size < 32 || source.sin6_family != AF_INET6 ||
      !IN6_IS_ADDR_LINKLOCAL(&source.sin6_addr))
    return;
  if (!source.sin6_scope_id)
    source.sin6_scope_id = parent->ifindex;
  if (source.sin6_scope_id != parent->ifindex ||
      !inet_ntop(AF_INET6, &source.sin6_addr, text, sizeof(text)) ||
      !strcmp(text, parent->local_ip) ||
      rnc_host_auto_token(parent->group, text, expected) != RNC_OK ||
      CRYPTO_memcmp(token, expected, 32))
    return;
  f = auto_peer(h, parent, &source);
  if (!f) {
    f = empty_interface(h);
    if (!f || h->next_id < 0x80000000u) {
      ++parent->status.dropped_packets;
      return;
    }
    memset(f, 0, sizeof(*f));
    f->used = 1;
    f->fd = f->discovery_fd = f->unicast_fd = -1;
    f->status.kind = RNC_HOST_AUTO;
    f->status.interface_id = h->next_id++;
    f->status.parent_id = parent->status.interface_id;
    f->status.mtu = parent->status.mtu;
    f->status.mode = parent->status.mode;
    f->status.announce_cap_permille = parent->status.announce_cap_permille;
    f->policy = parent->policy;
    f->peer_size = sizeof(source);
    source.sin6_port = htons(parent->data_port);
    memcpy(&f->peer, &source, sizeof(source));
    f->has_ifac = parent->has_ifac;
    if (f->has_ifac)
      f->ifac = parent->ifac;
    f->bitrate = parent->bitrate;
    f->status.bitrate = parent->status.bitrate;
    f->status.ifac_size = parent->status.ifac_size;
    memcpy(f->status.ifac_signature, parent->status.ifac_signature, 64);
    (void)snprintf(f->status.name, sizeof(f->status.name),
                   "AutoInterfacePeer[%.40s/%s]", parent->device, text);
    (void)rnc_hash(f->status.name, strlen(f->status.name), f->status.hash);
    if (activate(h, f) != RNC_OK) {
      OPENSSL_cleanse(f, sizeof(*f));
      ++parent->status.dropped_packets;
      return;
    }
  }
  f->last_heard = h->now;
  if (reverse && rnc_host_auto_token(parent->group, parent->local_ip,
                                     expected) == RNC_OK) {
    source.sin6_port = htons((uint16_t)(parent->discovery_port + 1u));
    (void)sendto(parent->unicast_fd, expected, 32, 0,
                 (struct sockaddr *)&source, sizeof(source));
  }
}
static rnc_result receive_datagram(rnc_host *h, host_interface *f,
                                   uint64_t unix_seconds) {
  uint8_t data[RNC_MAX_FRAME + 1u];
  struct sockaddr_storage source;
  socklen_t n = sizeof(source);
  ssize_t size =
      recvfrom(f->fd, data, sizeof(data), 0, (struct sockaddr *)&source, &n);
  host_interface *peer = f;
  if (size < 0)
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR
               ? RNC_OK
               : RNC_STATE;
  if ((size_t)size > RNC_MAX_FRAME) {
    ++f->status.dropped_packets;
    return RNC_OK;
  }
  if (f->status.kind == RNC_HOST_AUTO) {
    if (source.ss_family != AF_INET6)
      return RNC_OK;
    peer = auto_peer(h, f, (struct sockaddr_in6 *)&source);
    if (!peer) {
      ++f->status.dropped_packets;
      return RNC_OK;
    }
  }
  return input_packet(h, peer, data, (size_t)size, unix_seconds) == RNC_AGAIN
             ? RNC_OK
             : pump_node(h);
}
static int rnode_report(host_interface *f, uint8_t command, const uint8_t *raw,
                        size_t n) {
  if (command == 0x23 && n >= 1) { /* RSSI of the next frame */
    f->status.rssi = (int)raw[0] - 157;
    f->status.has_signal = 1;
  } else if (command == 0x24 && n >= 1) { /* SNR in quarter dB */
    int sfs = (int)f->radio.spreading_factor - 7;
    double snr = (int8_t)raw[0] * 0.25;
    double min = -9.0 - sfs * 2.0, q = (snr - min) / (6.0 - min) * 100.0;
    q = (double)((long)(q * 10.0 + (q < 0 ? -0.5 : 0.5))) / 10.0;
    f->status.snr = (float)snr;
    f->status.quality = (float)(q > 100.0 ? 100.0 : q < 0.0 ? 0.0 : q);
    f->status.has_signal = 1;
  } else if (command >= 1 && command <= 6) {
    uint8_t expected[4];
    size_t expected_size = 1;
    switch (command) {
    case 1:
      put32(expected, f->radio.frequency);
      expected_size = 4;
      break;
    case 2:
      put32(expected, f->radio.bandwidth);
      expected_size = 4;
      break;
    case 3:
      expected[0] = (uint8_t)f->radio.tx_power;
      break;
    case 4:
      expected[0] = (uint8_t)f->radio.spreading_factor;
      break;
    case 5:
      expected[0] = (uint8_t)f->radio.coding_rate;
      break;
    default:
      expected[0] = 1;
      break;
    }
    int matches = n == expected_size && !memcmp(raw, expected, n);
    if (command == 1 && n == 4) {
      uint32_t observed = ((uint32_t)raw[0] << 24) |
                          ((uint32_t)raw[1] << 16) |
                          ((uint32_t)raw[2] << 8) | raw[3];
      uint32_t delta = observed > f->radio.frequency
                           ? observed - f->radio.frequency
                           : f->radio.frequency - observed;
      matches =
          delta <= 100u; /* SX127x frequency register granularity. */
    }
    if (matches) {
      f->radio_ack_mask |= 1u << (command - 1);
      if (f->radio_ack_mask == 0x3f && !f->status.radio_ready) {
        f->status.radio_ready = 1;
        f->ready = 1;
        f->radio_deadline = 0;
      }
    }
  } else if (command == 0x0f && n && f->status.radio_ready) {
    f->ready = 1;
  } else
    return 0;
  return 1;
}

static host_interface *find_sub(rnc_host *h, const host_interface *dev,
                                unsigned vport) {
  size_t i;
  for (i = 0; i < RNC_HOST_SLOTS; ++i) {
    host_interface *c = &h->interfaces[i];
    if (c->used && c->multi_sub && c->status.parent_id == dev->status.interface_id &&
        c->sub_vport == vport)
      return c;
  }
  return NULL;
}
static int multi_blocked(rnc_host *h, const host_interface *dev) {
  size_t i;
  for (i = 0; i < RNC_HOST_SLOTS; ++i)
    if (h->interfaces[i].used && h->interfaces[i].multi_sub &&
        h->interfaces[i].status.parent_id == dev->status.interface_id &&
        h->interfaces[i].pending)
      return 1;
  return 0;
}
static rnc_result input_packet(rnc_host *h, host_interface *f,
                               const uint8_t *data, size_t size,
                               uint64_t unix_seconds);
/* One frame from a multi device: a selection changes whose frames follow, and
 * everything that concerns a radio is applied to the selected one. */
static rnc_result multi_frame(rnc_host *h, host_interface *dev,
                              uint8_t command, const uint8_t *raw, size_t n,
                              uint64_t unix_seconds) {
  host_interface *radio;
  switch (command) {
  case 0x1f:
    if (n >= 1)
      dev->selected = raw[0];
    return RNC_OK;
  case 0x08:
    if (n >= 1 && raw[0] == 0x46 && !dev->rnode_detected) {
      dev->rnode_detected = 1;
      dev->detect_at = h->now;
    }
    return RNC_OK;
  case 0x50:
    /* the multi interface needs 1.74 or newer */
    if (n >= 2 && !(raw[0] > 1 || (raw[0] == 1 && raw[1] >= 74))) {
      rnc_logf(RNC_LOG_ERROR, "host",
               "RNode %s reports firmware %u.%u, at least 1.74 is required",
               dev->status.name, (unsigned)raw[0], (unsigned)raw[1]);
      dev->gave_up = 1;
      disconnect_interface(h, dev, EPROTONOSUPPORT);
    }
    return RNC_OK;
  case 0x71:
    /* radios are numbered in the order they are reported */
    if (n >= 2 && dev->type_count < RNC_HOST_SUBRADIOS)
      dev->types[dev->type_count++] = raw[1] == 0x10 || raw[1] == 0x11   ? 1u
                                      : raw[1] == 0x20 || raw[1] == 0x21 ? 2u
                                                                         : 0u;
    return RNC_OK;
  case 0x90:
    disconnect_interface(h, dev, EIO);
    return RNC_OK;
  case 0x55:
    if (n && raw[0] == 0xf8)
      disconnect_interface(h, dev, EIO);
    return RNC_OK;
  case 0x00:
    radio = find_sub(h, dev, dev->selected);
    if (!radio || !n)
      return RNC_OK;
    return input_packet(h, radio, raw, n, unix_seconds);
  default:
    radio = find_sub(h, dev, dev->selected);
    if (radio)
      (void)rnode_report(radio, command, raw, n);
    return RNC_OK;
  }
}
/* The device has named its radios: check every configured one against them
 * and bring them up as interfaces of their own. */
static void multi_spawn(rnc_host *h, host_interface *dev) {
  unsigned k;
  for (k = 0; k < dev->sub_count; ++k) {
    const rnc_host_subradio *s = &dev->subs[k];
    uint32_t low = dev->types[s->vport < RNC_HOST_SUBRADIOS ? s->vport : 0] == 2
                       ? 2200000000u
                       : 137000000u,
             high = dev->types[s->vport < RNC_HOST_SUBRADIOS ? s->vport : 0] == 2
                        ? 2600000000u
                        : 1000000000u;
    if (s->vport >= dev->type_count) {
      rnc_logf(RNC_LOG_ERROR, "host",
               "virtual port %u for %s does not exist on %s", s->vport, s->name,
               dev->status.name);
      disconnect_interface(h, dev, EINVAL);
      return;
    }
    if (s->frequency < low || s->frequency > high) {
      rnc_logf(RNC_LOG_ERROR, "host", "invalid frequency configured for %s[%s]",
               dev->status.name, s->name);
      disconnect_interface(h, dev, EINVAL);
      return;
    }
  }
  for (k = 0; k < dev->sub_count; ++k) {
    const rnc_host_subradio *s = &dev->subs[k];
    host_interface *c = empty_interface(h);
    uint64_t den;
    if (!c || h->next_id < 0x80000000u) {
      disconnect_interface(h, dev, ENOSPC);
      return;
    }
    memset(c, 0, sizeof(*c));
    c->used = 1;
    c->fd = c->discovery_fd = c->unicast_fd = -1;
    c->multi_sub = 1;
    c->sub_vport = s->vport;
    c->status.kind = RNC_HOST_RNODE;
    c->status.interface_id = h->next_id++;
    c->status.parent_id = dev->status.interface_id;
    c->status.mtu = dev->status.mtu;
    c->status.mode = dev->status.mode;
    c->status.announce_cap_permille = dev->status.announce_cap_permille;
    c->policy = dev->policy;
    c->no_output = s->no_output;
    c->flow_control = s->flow_control;
    c->ready = !s->flow_control;
    c->callsign_size = dev->callsign_size;
    memcpy(c->callsign, dev->callsign, sizeof(c->callsign));
    c->radio.kind = RNC_HOST_RNODE;
    c->radio.frequency = s->frequency;
    c->radio.bandwidth = s->bandwidth;
    c->radio.tx_power = s->tx_power;
    c->radio.spreading_factor = s->spreading_factor;
    c->radio.coding_rate = s->coding_rate;
    c->radio.airtime_limit_short = s->airtime_limit_short;
    c->radio.airtime_limit_long = s->airtime_limit_long;
    c->radio.id_interval = dev->radio.id_interval;
    den = (uint64_t)s->coding_rate << s->spreading_factor;
    c->bitrate = (uint32_t)(((uint64_t)s->spreading_factor * 4u * s->bandwidth +
                             den / 2u) /
                            den);
    if (!c->bitrate)
      c->bitrate = 1u;
    c->status.bitrate = c->bitrate;
    (void)snprintf(c->status.name, sizeof(c->status.name), "%.60s[%.60s]",
                   dev->status.name, s->name);
    (void)rnc_hash(c->status.name, strlen(c->status.name), c->status.hash);
    if (activate(h, c) != RNC_OK ||
        configure_radio(c, &c->radio) != RNC_OK) {
      OPENSSL_cleanse(c, sizeof(*c));
      disconnect_interface(h, dev, ENOSPC);
      return;
    }
  }
  dev->subs_spawned = 1;
  dev->radio_deadline = 0;
}
/* Weave. Every frame of the switch's protocol (WDCL) starts with the four byte
 * id of the switch it is for, then a type: discovery, connection, command,
 * log, display and endpoint packet. The host's id is the last four bytes of a
 * signing key it makes up for the run. */
enum {
  WDCL_DISCOVER = 0x00,
  WDCL_CONNECT = 0x01,
  WDCL_CMD = 0x02,
  WDCL_LOG = 0x03,
  WDCL_ENDPOINT_PKT = 0x05
};
enum {
  WEAVE_EVT_CONNECTION = 0x3002,
  WEAVE_EVT_HOST_ENDPOINT = 0x3003,
  WEAVE_EVT_EP_ALIVE = 0x3102
};
static rnc_result weave_send(host_interface *f, const uint8_t dest[4],
                             uint8_t type, const uint8_t *body, size_t size) {
  uint8_t frame[RNC_MAX_FRAME];
  host_frame *q;
  rnc_result r;
  if (f->queue_count == RNC_HOST_QUEUE_FRAMES)
    return RNC_AGAIN;
  if (size + 5u > sizeof(frame))
    return RNC_NO_SPACE;
  memcpy(frame, dest, 4);
  frame[4] = type;
  if (size)
    memcpy(frame + 5, body, size);
  q = &f->queue[f->queue_count];
  memset(q, 0, sizeof(*q));
  q->control = 1;
  r = rnc_host_frame_encode(RNC_HOST_HDLC, 0, frame, size + 5u, q->data,
                            sizeof(q->data), &q->size);
  if (r == RNC_OK)
    ++f->queue_count;
  return r;
}
/* The first step of a connection: ask whoever is on the line who they are. */
static rnc_result weave_begin(host_interface *f) {
  static const uint8_t broadcast[4] = {0xff, 0xff, 0xff, 0xff};
  f->weave_step = WEAVE_DISCOVERING;
  f->weave_deadline = 0;
  return weave_send(f, broadcast, WDCL_DISCOVER, f->weave_sw, 4);
}
static host_interface *weave_find(rnc_host *h, const host_interface *dev,
                                  const uint8_t endpoint[8]) {
  size_t i;
  for (i = 0; i < RNC_HOST_SLOTS; ++i) {
    host_interface *c = &h->interfaces[i];
    if (c->used && c->weave_peer && c->status.parent_id == dev->status.interface_id &&
        !memcmp(c->weave_endpoint, endpoint, 8))
      return c;
  }
  return NULL;
}
static int weave_blocked(rnc_host *h, const host_interface *dev) {
  size_t i;
  for (i = 0; i < RNC_HOST_SLOTS; ++i)
    if (h->interfaces[i].used && h->interfaces[i].weave_peer &&
        h->interfaces[i].status.parent_id == dev->status.interface_id &&
        h->interfaces[i].pending)
      return 1;
  return 0;
}
/* An endpoint of the switch is a peer: an interface of its own that sends to
 * that endpoint alone. Heard again, it is kept; not heard for twenty seconds,
 * it goes. */
static host_interface *weave_peer(rnc_host *h, host_interface *dev,
                                  const uint8_t endpoint[8]) {
  static const char digits[] = "0123456789abcdef";
  host_interface *c = weave_find(h, dev, endpoint);
  char name[sizeof(c->status.name)];
  size_t k;
  if (c) {
    c->last_heard = h->now;
    return c;
  }
  if (dev->weave_step != WEAVE_CONNECTED)
    return NULL;
  c = empty_interface(h);
  if (!c || h->next_id < 0x80000000u)
    return NULL;
  memset(c, 0, sizeof(*c));
  c->used = 1;
  c->fd = c->discovery_fd = c->unicast_fd = -1;
  c->weave_peer = 1;
  memcpy(c->weave_endpoint, endpoint, 8);
  memcpy(c->weave_remote, dev->weave_remote, 4);
  c->status.kind = RNC_HOST_WEAVE;
  c->status.interface_id = h->next_id++;
  c->status.parent_id = dev->status.interface_id;
  c->status.mtu = dev->status.mtu;
  c->status.mode = dev->status.mode;
  c->status.announce_cap_permille = dev->status.announce_cap_permille;
  c->status.radio_ready = 1;
  c->policy = dev->policy;
  c->no_output = dev->no_output;
  c->bitrate = dev->bitrate;
  c->status.bitrate = dev->bitrate;
  c->has_ifac = dev->has_ifac;
  if (dev->has_ifac) {
    c->ifac = dev->ifac;
    c->status.ifac_size = dev->status.ifac_size;
    memcpy(c->status.ifac_signature, dev->status.ifac_signature,
           sizeof(c->status.ifac_signature));
  }
  c->last_heard = h->now;
  {
    char hex[17];
    for (k = 0; k < 8; ++k) {
      hex[2 * k] = digits[endpoint[k] >> 4];
      hex[2 * k + 1] = digits[endpoint[k] & 15u];
    }
    hex[16] = 0;
    (void)snprintf(name, sizeof(name), "%.90s[%s]", dev->status.name, hex);
  }
  (void)copy_text(c->status.name, sizeof(c->status.name), name);
  (void)rnc_hash(c->status.name, strlen(c->status.name), c->status.hash);
  if (activate(h, c) != RNC_OK) {
    rnc_logf(RNC_LOG_WARNING, "host", "%s: no room for endpoint %s",
             dev->status.name, name);
    OPENSSL_cleanse(c, sizeof(*c));
    return NULL;
  }
  return c;
}
/* The same bytes from a second endpoint within three quarters of a second are
 * one packet that took two routes. */
static int weave_duplicate(host_interface *dev, const uint8_t *data,
                           size_t size, uint64_t now) {
  uint8_t hash[32];
  unsigned i;
  if (rnc_hash(data, size, hash) != RNC_OK)
    return 0;
  for (i = 0; i < dev->dedupe_used; ++i)
    if (!memcmp(dev->dedupe[i], hash, 8) &&
        now < dev->dedupe_at[i] + WEAVE_DEDUPE_TTL_MS)
      return 1;
  memcpy(dev->dedupe[dev->dedupe_next], hash, 8);
  dev->dedupe_at[dev->dedupe_next] = now;
  dev->dedupe_next = (dev->dedupe_next + 1u) % WEAVE_DEDUPE_SLOTS;
  if (dev->dedupe_used < WEAVE_DEDUPE_SLOTS)
    ++dev->dedupe_used;
  return 0;
}
/* The switch answered the discovery with its key and a signature of the id the
 * host announced; the host replies with its own key and a signature of the
 * switch's id. */
static void weave_discovered(rnc_host *h, host_interface *dev,
                             const uint8_t *frame) {
  uint8_t key[64], body[32 + 64];
  rnc_identity remote;
  (void)h;
  memcpy(key, frame + 5, 32);
  memcpy(key + 32, frame + 5, 32);
  if (rnc_identity_from_public(&remote, key) != RNC_OK ||
      rnc_identity_verify(&remote, frame, 4, frame + 5 + 32) != RNC_OK) {
    rnc_logf(RNC_LOG_ERROR, "host",
             "%s: invalid remote device discovery response",
             dev->status.name);
    return;
  }
  memcpy(dev->weave_remote, frame + 5 + 28, 4);
  memcpy(body, dev->weave_id.public_key + 32, 32);
  if (rnc_identity_sign(&dev->weave_id, dev->weave_remote, 4, body + 32) !=
      RNC_OK)
    return;
  if (weave_send(dev, dev->weave_remote, WDCL_CONNECT, body, sizeof(body)) ==
      RNC_OK)
    dev->weave_step = WEAVE_CONNECTING;
}
static void weave_event(rnc_host *h, host_interface *dev, unsigned event,
                        const uint8_t *data, size_t size) {
  switch (event) {
  case WEAVE_EVT_CONNECTION:
    if (dev->weave_step != WEAVE_CONNECTED) {
      dev->weave_step = WEAVE_CONNECTED;
      dev->weave_deadline = 0;
      dev->status.online = 1;
      dev->status.last_errno = 0;
      rnc_logf(RNC_LOG_INFO, "host", "%s: connected to Weave switch %02x%02x%02x%02x",
               dev->status.name, dev->weave_remote[0], dev->weave_remote[1],
               dev->weave_remote[2], dev->weave_remote[3]);
    }
    break;
  case WEAVE_EVT_HOST_ENDPOINT:
    if (size == 8)
      memcpy(dev->weave_endpoint, data, 8);
    break;
  case WEAVE_EVT_EP_ALIVE:
    if (size == 8)
      (void)weave_peer(h, dev, data);
    break;
  default:
    break;
  }
}
static rnc_result weave_frame(rnc_host *h, host_interface *dev,
                              const uint8_t *f, size_t n,
                              uint64_t unix_seconds) {
  if (n <= 5)
    return RNC_OK;
  if (f[4] == WDCL_ENDPOINT_PKT && n >= 13 &&
      !memcmp(f, dev->weave_sw, 4)) {
    host_interface *peer = weave_peer(h, dev, f + n - 8);
    size_t size = n - 13;
    if (!peer || !size || weave_duplicate(dev, f + 5, size, h->now))
      return RNC_OK;
    return input_packet(h, peer, f + 5, size, unix_seconds);
  }
  if (f[4] == WDCL_DISCOVER && n == 4 + 1 + 32 + 64 &&
      dev->weave_step != WEAVE_IDLE)
    weave_discovered(h, dev, f);
  else if (f[4] == WDCL_LOG && n >= 14)
    weave_event(h, dev, (unsigned)f[12] << 8 | f[13], f + 14, n - 14);
  return RNC_OK;
}
static rnc_result receive_stream(rnc_host *h, host_interface *f,
                                 uint64_t unix_seconds) {
  uint8_t raw[RNC_MAX_FRAME], command;
  size_t n;
  rnc_result r;
  ssize_t got;
  rnc_host_framing mode =
      f->status.kind == RNC_HOST_KISS || f->status.kind == RNC_HOST_RNODE ||
              f->status.kind == RNC_HOST_RNODE_MULTI ||
              f->status.kind == RNC_HOST_AX25 || f->kiss
          ? RNC_HOST_KISS_FRAMING
          : RNC_HOST_HDLC;
  if (f->status.kind == RNC_HOST_RNODE_MULTI && multi_blocked(h, f))
    return RNC_OK;
  if (f->status.kind == RNC_HOST_WEAVE && weave_blocked(h, f))
    return RNC_OK;
  if (f->pending) {
    r = rnc_node_input(h->node, f->status.interface_id, &f->pending_packet,
                       unix_seconds, h->now);
    if (r == RNC_AGAIN)
      return RNC_OK;
    f->pending = 0;
    if (r == RNC_OK) {
      ++f->status.rx_packets;
      f->last_heard = h->now;
    } else
      ++f->status.dropped_packets;
    r = pump_node(h);
    if (r != RNC_OK)
      return r;
  }
  if (f->input_offset == f->input_size) {
    f->input_offset = f->input_size = 0;
    if (f->status.kind == RNC_HOST_TCP_CONNECT || f->status.kind == RNC_HOST_I2P)
      got = recv(f->fd, f->input, sizeof(f->input), 0);
    else
      got = read(f->fd, f->input, sizeof(f->input));
    if (got < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
        disconnect_interface(h, f, errno);
      return RNC_OK;
    }
    if (!got) {
      /* VMIN=VTIME=0 serial reads can return zero while idle. Only TCP zero
       * is EOF; actual serial hangup is handled from POLLHUP in the pump. */
      if (f->status.kind == RNC_HOST_TCP_CONNECT ||
          f->status.kind == RNC_HOST_I2P || f->status.kind == RNC_HOST_PIPE ||
          f->rnode_tcp)
        disconnect_interface(h, f, 0);
      return RNC_OK;
    }
    f->input_size = (size_t)got;
    f->last_read_ms = h->now;
  }
  if (f->sam_step) {
    sam_feed(h, f);
    if (f->sam_step || f->fd < 0)
      return RNC_OK;
  }
  while (f->input_offset < f->input_size) {
    r = rnc_host_frame_feed(&f->framer, mode, f->input[f->input_offset++],
                            &command, raw, sizeof(raw), &n);
    if (r == RNC_OK) {
      if (f->status.kind == RNC_HOST_WEAVE) {
        r = weave_frame(h, f, raw, n, unix_seconds);
        if (r == RNC_AGAIN)
          return RNC_OK;
        if (r != RNC_OK)
          return r;
        if (f->fd < 0)
          return RNC_OK;
        continue;
      }
      if (f->status.kind == RNC_HOST_RNODE_MULTI) {
        r = multi_frame(h, f, command, raw, n, unix_seconds);
        if (r == RNC_AGAIN)
          return RNC_OK;
        if (r != RNC_OK)
          return r;
        if (f->fd < 0)
          return RNC_OK;
        continue;
      }
      if (f->status.kind == RNC_HOST_RNODE && command) {
        if (command == 0x08) {
          if (n >= 1 && raw[0] == 0x46 && !f->rnode_detected) {
            f->rnode_detected = 1;
            (void)configure_radio(f, &f->radio);
          }
        } else if (command == 0x50) {
          if (n >= 2 && !(raw[0] > 1 || (raw[0] == 1 && raw[1] >= 52))) {
            rnc_logf(RNC_LOG_ERROR, "host",
                     "RNode %s reports firmware %u.%u, at least 1.52 is "
                     "required",
                     f->status.name, (unsigned)raw[0], (unsigned)raw[1]);
            f->gave_up = 1; /* a firmware that is too old does not fix itself */
            disconnect_interface(h, f, EPROTONOSUPPORT);
            return RNC_OK;
          }
        } else if (rnode_report(f, command, raw, n)) {
          /* signal statistics, radio parameter acknowledgements, ready */
        } else if (command == 0x90 || (command == 0x55 && n && raw[0] == 0xf8)) {
          disconnect_interface(h, f, EIO);
          return RNC_OK;
        }
        continue;
      }
      if (TNC_KIND(f->status.kind) && (command & 15u) == 0x0f) {
        if (f->flow_control)
          f->ready = 1;
        continue;
      }
      if ((f->status.kind == RNC_HOST_KISS || f->status.kind == RNC_HOST_AX25 ||
           f->kiss) &&
          ((command & 15u) != 0 || (command >> 4) != f->kiss_port))
        continue;
      if (f->status.kind == RNC_HOST_AX25) {
        if (n <= 16u) {
          ++f->status.dropped_packets;
          continue;
        }
        r = input_packet(h, f, raw + 16, n - 16u, unix_seconds);
      } else
        r = input_packet(h, f, raw, n, unix_seconds);
      if (r == RNC_AGAIN)
        return RNC_OK;
      if (r != RNC_OK)
        return r;
    } else if (r != RNC_AGAIN)
      ++f->status.dropped_packets;
  }
  return RNC_OK;
}
static rnc_result flush_interface(rnc_host *h, host_interface *f) {
  host_frame *q;
  host_interface *socket_owner = f;
  size_t i, index = 0;
  ssize_t sent;
  int fd, delivered = 1;
  if (f->callsign_size && f->first_tx_set && f->status.online &&
      f->status.radio_ready && f->queue_count < RNC_HOST_QUEUE_FRAMES &&
      h->now >= f->first_tx + (uint64_t)f->radio.id_interval * 1000u) {
    host_frame *b = &f->queue[f->queue_count];
    memset(b, 0, sizeof(*b));
    b->beacon = 1;
    if (rnc_host_frame_encode(RNC_HOST_KISS_FRAMING,
                              (uint8_t)(f->kiss_port << 4),
                              (const uint8_t *)f->callsign, f->callsign_size,
                              b->data, sizeof(b->data), &b->size) == RNC_OK &&
        select_prefix(f, b) == RNC_OK) {
      ++f->queue_count;
      f->first_tx_set = 0; /* restarts with the next ordinary transmission */
    }
  }
  /* the line to a Weave switch carries the handshake before it is "online" */
  if (!f->queue_count || f->connecting ||
      !(f->status.kind == RNC_HOST_WEAVE && !f->weave_peer ? f->fd >= 0
                                                          : f->status.online))
    return RNC_OK;
  for (i = 0; i < f->queue_count; ++i)
    if (f->queue[i].offset) {
      index = i;
      break;
    }
  if (i == f->queue_count) {
    if (h->now < f->next_tx)
      return RNC_OK;
    if (f->queue[0].announce && h->now < f->next_announce) {
      for (index = 1; index < f->queue_count && f->queue[index].announce;
           ++index) {
      }
      if (index == f->queue_count)
        return RNC_OK;
    }
  }
  q = &f->queue[index];
  if (f->status.kind == RNC_HOST_RNODE && !q->control &&
      (!f->status.radio_ready || (f->flow_control && !f->ready)))
    return RNC_OK;
  if (TNC_KIND(f->status.kind) && !q->control && f->flow_control &&
      !f->ready) {
    if (h->now < f->lock_at + 5000u) /* reference unlock timeout */
      return RNC_OK;
    f->ready = 1;
  }
  if ((f->status.kind == RNC_HOST_AUTO || f->multi_sub || f->weave_peer) &&
      f->status.parent_id) {
    socket_owner = find_interface(h, f->status.parent_id);
    if (!socket_owner)
      return RNC_STATE;
  }
  fd = socket_owner->fd;
  if (fd < 0)
    return RNC_OK;
  /* radios of a device share its line: one frame is written out whole before
   * another radio's begins */
  if ((f->multi_sub || f->status.kind == RNC_HOST_WEAVE) &&
      socket_owner->tx_owner && socket_owner->tx_owner != f->status.interface_id)
    return RNC_OK;
  if (f->status.kind == RNC_HOST_UDP || f->status.kind == RNC_HOST_AUTO) {
    if (!f->peer_size) {
      ++f->status.dropped_packets;
      delivered = 0;
      sent = (ssize_t)q->size;
    } else
      sent = sendto(fd, q->data, q->size, 0, (struct sockaddr *)&f->peer,
                    f->peer_size);
  } else if (f->status.kind == RNC_HOST_TCP_CONNECT ||
             f->status.kind == RNC_HOST_PIPE || f->rnode_tcp) {
#ifdef MSG_NOSIGNAL
    sent = send(fd, q->data + q->offset, q->size - q->offset, MSG_NOSIGNAL);
#else
    sent = send(fd, q->data + q->offset, q->size - q->offset, 0);
#endif
  } else
    sent = write(fd, q->data + q->offset, q->size - q->offset);
  if (sent < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
      return RNC_OK;
    if (f->status.kind == RNC_HOST_UDP || f->status.kind == RNC_HOST_AUTO) {
      f->status.last_errno = errno;
      ++f->status.dropped_packets;
      delivered = 0;
      sent = (ssize_t)q->size;
    } else {
      disconnect_interface(h, f->multi_sub ? socket_owner : f, errno);
      return RNC_OK;
    }
  }
  f->last_write_ms = h->now;
  if ((f->status.kind == RNC_HOST_UDP || f->status.kind == RNC_HOST_AUTO) &&
      sent != (ssize_t)q->size) {
    ++f->status.dropped_packets;
    delivered = 0;
    sent = (ssize_t)q->size;
  }
  q->offset += (size_t)sent;
  if (f->multi_sub || f->status.kind == RNC_HOST_WEAVE)
    socket_owner->tx_owner = q->offset == q->size ? 0 : f->status.interface_id;
  if (q->offset == q->size) {
    uint64_t duration =
        ((uint64_t)q->size * 8000u + f->bitrate - 1u) / f->bitrate;
    if (!duration)
      duration = 1;
    f->next_tx = h->now + duration;
    if (q->announce)
      f->next_announce = h->now + duration * 50u;
    if (q->beacon) {
      if (f->flow_control)
        f->ready = 0;
    } else if (!q->control) {
      if (f->callsign_size && !f->first_tx_set) {
        f->first_tx = h->now;
        f->first_tx_set = 1;
      }
      if (delivered) {
        ++f->status.tx_packets;
        f->status.tx_bytes += q->wire_size;
        if (q->announce) {
          ++f->status.tx_announces;
          f->status.tx_announce_bytes += q->wire_size;
        }
      }
      if ((f->status.kind == RNC_HOST_RNODE || TNC_KIND(f->status.kind)) &&
          f->flow_control) {
        f->ready = 0;
        f->lock_at = h->now;
      }
    }
    if (index + 1u < f->queue_count)
      memmove(&f->queue[index], &f->queue[index + 1u],
              (f->queue_count - index - 1u) * sizeof(*q));
    --f->queue_count;
    memset(&f->queue[f->queue_count], 0, sizeof(*q));
  }
  return RNC_OK;
}
rnc_result rnc_host_step(rnc_host *h, int timeout, uint64_t unix_seconds,
                         uint64_t now) {
  struct pollfd pf[RNC_HOST_SLOTS * 3u];
  host_interface *owners[RNC_HOST_SLOTS * 3u];
  unsigned kinds[RNC_HOST_SLOTS * 3u];
  size_t i, count = 0;
  rnc_result r;
  int rc;
  host_interface *parent;
  if (!h || timeout < 0 || timeout > 1000 || (h->has_time && now < h->now))
    return RNC_INVALID;
  h->now = now;
  h->has_time = 1;
  r = pump_node(h);
  if (r != RNC_OK)
    return r;
  for (i = 0; i < RNC_HOST_SLOTS; ++i) {
    host_interface *f = &h->interfaces[i];
    if (!f->used)
      continue;
    if (f->status.kind == RNC_HOST_AUTO && f->status.parent_id) {
      if (f->pending) {
        r = rnc_node_input(h->node, f->status.interface_id, &f->pending_packet,
                           unix_seconds, now);
        if (r != RNC_AGAIN) {
          f->pending = 0;
          if (r == RNC_OK)
            ++f->status.rx_packets;
          else
            ++f->status.dropped_packets;
        }
      }
      if (now - f->last_heard >= RNC_HOST_AUTO_PEER_TIMEOUT)
        (void)rnc_host_remove(h, f->status.interface_id);
      continue;
    }
    if (f->weave_peer) {
      if (f->pending) {
        r = rnc_node_input(h->node, f->status.interface_id, &f->pending_packet,
                           unix_seconds, now);
        if (r != RNC_AGAIN) {
          f->pending = 0;
          if (r == RNC_OK)
            ++f->status.rx_packets;
          else
            ++f->status.dropped_packets;
        }
      }
      if (now - f->last_heard >= WEAVE_PEER_TIMEOUT_MS)
        (void)rnc_host_remove(h, f->status.interface_id);
      continue;
    }
    if (f->multi_sub) {
      host_interface *dev = find_interface(h, f->status.parent_id);
      if (f->pending) {
        r = rnc_node_input(h->node, f->status.interface_id, &f->pending_packet,
                           unix_seconds, now);
        if (r != RNC_AGAIN) {
          f->pending = 0;
          if (r == RNC_OK)
            ++f->status.rx_packets;
          else
            ++f->status.dropped_packets;
        }
      }
      /* a radio that never confirms its parameters takes the device down for
       * another attempt */
      if (dev && !f->status.radio_ready) {
        if (!f->radio_deadline)
          f->radio_deadline = now + 5000u;
        else if (now >= f->radio_deadline) {
          rnc_logf(RNC_LOG_ERROR, "host",
                   "%s: the radio did not confirm its configuration",
                   f->status.name);
          disconnect_interface(h, dev, ETIMEDOUT);
        }
      }
      continue;
    }
    if (f->status.kind == RNC_HOST_RNODE_MULTI && f->fd >= 0 &&
        !f->subs_spawned) {
      if (!f->radio_deadline)
        f->radio_deadline = now + 5000u;
      else if (now >= f->radio_deadline) {
        disconnect_interface(h, f, ETIMEDOUT);
        continue;
      }
      if (f->rnode_detected && now >= f->detect_at + 300u) {
        multi_spawn(h, f);
        if (f->fd < 0)
          continue;
      }
    }
    if (f->status.kind == RNC_HOST_WEAVE && f->fd >= 0 &&
        f->weave_step != WEAVE_CONNECTED) {
      /* the switch has two seconds to complete the handshake */
      if (!f->weave_deadline)
        f->weave_deadline = now + WEAVE_HANDSHAKE_MS;
      else if (now >= f->weave_deadline) {
        rnc_logf(RNC_LOG_WARNING, "host",
                 "%s: the Weave handshake timed out", f->status.name);
        disconnect_interface(h, f, ETIMEDOUT);
        continue;
      }
    }
    if (f->status.kind == RNC_HOST_I2P)
      i2p_maintain(h, f);
    if (f->fd < 0 && !f->accepted && !f->gave_up && now >= f->retry_at &&
        !(f->sam_role == SAM_CONNECT &&
          !((parent = find_interface(h, f->status.parent_id)) &&
            parent->i2p_ready))) {
      if (f->status.kind == RNC_HOST_TCP_CONNECT ||
          f->status.kind == RNC_HOST_I2P) {
        if (connect_interface(h, f) < 0) {
          f->status.last_errno = errno;
          note_connect_failure(h, f);
        } else
          ++f->status.reconnects;
      } else if (f->rnode_tcp) {
        f->fd = device_open(f);
        if (f->fd >= 0)
          ++f->status.reconnects;
        else {
          f->status.last_errno = errno;
          note_connect_failure(h, f);
        }
      } else if (DEVICE_KIND(f->status.kind)) {
        f->fd = device_open(f);
        if (f->fd >= 0 && f->status.kind == RNC_HOST_WEAVE) {
          ++f->status.reconnects;
          (void)weave_begin(f);
        } else if (f->fd >= 0 && f->status.kind == RNC_HOST_RNODE_MULTI) {
          ++f->status.reconnects;
          f->status.online = 1;
          (void)begin_multi(f);
        } else if (f->fd >= 0 && activate(h, f) == RNC_OK) {
          ++f->status.reconnects;
          if (f->status.kind == RNC_HOST_RNODE)
            (void)begin_rnode(f);
          else if (TNC_KIND(f->status.kind))
            (void)configure_ax25(f, &f->radio);
        } else {
          if (f->fd >= 0) {
            close(f->fd);
            f->fd = -1;
          }
          f->retry_at = now + 1000u;
        }
      }
    }
    if (f->status.kind == RNC_HOST_AUTO && !f->status.parent_id &&
        now >= f->discover_at) {
      uint8_t token[32];
      if (rnc_host_auto_token(f->group, f->local_ip, token) == RNC_OK)
        (void)sendto(f->discovery_fd, token, 32, 0,
                     (struct sockaddr *)&f->multicast, f->multicast_size);
      f->discover_at = now + 1600u;
    }
    if (f->pending && f->status.kind == RNC_HOST_UDP) {
      r = rnc_node_input(h->node, f->status.interface_id, &f->pending_packet,
                         unix_seconds, now);
      if (r != RNC_AGAIN) {
        f->pending = 0;
        if (r == RNC_OK)
          ++f->status.rx_packets;
        else
          ++f->status.dropped_packets;
      }
    }
    if (f->status.kind == RNC_HOST_RNODE && f->fd >= 0 && !f->connecting &&
        !f->status.radio_ready) {
      if (!f->radio_deadline)
        f->radio_deadline = now + 5000u;
      else if (now >= f->radio_deadline) {
        disconnect_interface(h, f, ETIMEDOUT);
        continue;
      }
    }
    /* like the reference, a WiFi RNode that has been quiet is asked to
     * identify itself again, so a dead connection shows up */
    if (f->rnode_tcp && f->fd >= 0 && !f->connecting && f->status.radio_ready &&
        !f->queue_count && now >= f->last_write_ms + 3500u) {
      (void)queue_detect(f);
      f->last_write_ms = now;
    }
    if (f->sam_step && f->fd >= 0 && !f->connecting &&
        f->sam_step != SS_CONTROL && f->sam_step != SS_REMOTE) {
      if (!f->sam_deadline)
        f->sam_deadline = now + (f->sam_role == SAM_SESSION
                                     ? I2P_SESSION_TIMEOUT_MS
                                     : I2P_STREAM_TIMEOUT_MS);
      else if (now >= f->sam_deadline) {
        rnc_logf(RNC_LOG_WARNING, "host", "%s: the SAM bridge did not answer",
                 f->status.name);
        disconnect_interface(h, f, ETIMEDOUT);
        continue;
      }
    }
    if (f->sam_streamed && f->node_added && f->fd >= 0) {
      i2p_watchdog(h, f, now);
      if (f->fd < 0)
        continue;
    }
    if (f->connecting && !f->connect_deadline)
      f->connect_deadline =
          now + (f->radio.connect_timeout_ms ? f->radio.connect_timeout_ms
                                             : 5000u);
    if (f->connecting && now >= f->connect_deadline) {
      disconnect_interface(h, f, ETIMEDOUT);
      continue;
    }
    if (f->fd >= 0) {
      pf[count].fd = f->fd;
      pf[count].events =
          POLLIN | (f->connecting || f->queue_count ? POLLOUT : 0);
      pf[count].revents = 0;
      owners[count] = f;
      kinds[count++] = 0;
    }
    if (f->discovery_fd >= 0) {
      pf[count].fd = f->discovery_fd;
      pf[count].events = POLLIN;
      pf[count].revents = 0;
      owners[count] = f;
      kinds[count++] = 1;
    }
    if (f->unicast_fd >= 0) {
      pf[count].fd = f->unicast_fd;
      pf[count].events = POLLIN;
      pf[count].revents = 0;
      owners[count] = f;
      kinds[count++] = 2;
    }
  }
  rc = poll(pf, count, timeout);
  if (rc < 0 && errno != EINTR)
    return RNC_STATE;
  for (i = 0; i < count && rc > 0; ++i) {
    host_interface *f = owners[i];
    int fd = kinds[i] == 1   ? f->discovery_fd
             : kinds[i] == 2 ? f->unicast_fd
                             : f->fd;
    if (!f->used || fd != pf[i].fd)
      continue;
    if (kinds[i]) {
      if (pf[i].revents & POLLIN)
        discovery_input(h, f, fd, kinds[i] == 1);
      continue;
    }
    if (f->connecting && (pf[i].revents & (POLLOUT | POLLERR | POLLHUP))) {
      int error = 0;
      socklen_t n = sizeof(error);
      if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &n) < 0)
        error = errno;
      f->connecting = 0;
      if (error ||
          (f->sam_role ? sam_start(h, f) : activate(h, f)) != RNC_OK) {
        f->connect_failed = 1;
        disconnect_interface(h, f, error ? error : ENOSPC);
        continue;
      }
      if (f->rnode_tcp) {
        f->last_write_ms = h->now;
        (void)begin_rnode(f);
      }
    }
    if (f->status.kind == RNC_HOST_TCP_LISTEN) {
      if (pf[i].revents & POLLIN)
        accept_tcp(h, f);
      continue;
    }
    if ((f->status.kind == RNC_HOST_UDP || f->status.kind == RNC_HOST_AUTO) &&
        (pf[i].revents & (POLLERR | POLLHUP))) {
      int error = 0;
      socklen_t error_size = sizeof(error);
      if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_size) < 0)
        error = errno;
      if (error) {
        f->status.last_errno = error;
        ++f->status.dropped_packets;
      }
      /* ICMP errors concern individual datagrams, not a stream lifetime. */
    }
    if ((pf[i].revents & POLLNVAL) ||
        ((pf[i].revents & (POLLERR | POLLHUP)) &&
         f->status.kind != RNC_HOST_UDP && f->status.kind != RNC_HOST_AUTO &&
         !(pf[i].revents & POLLIN) && f->input_offset == f->input_size &&
         !f->pending)) {
      disconnect_interface(h, f, ECONNRESET);
      continue;
    }
    if (pf[i].revents & POLLIN) {
      if (f->status.kind == RNC_HOST_UDP || f->status.kind == RNC_HOST_AUTO) {
        int blocked = f->pending;
        size_t peer_index;
        if (f->status.kind == RNC_HOST_AUTO)
          for (peer_index = 0; peer_index < RNC_HOST_SLOTS; ++peer_index)
            if (h->interfaces[peer_index].used &&
                h->interfaces[peer_index].status.parent_id ==
                    f->status.interface_id &&
                h->interfaces[peer_index].pending)
              blocked = 1;
        if (!blocked)
          (void)receive_datagram(h, f, unix_seconds);
      } else {
        r = receive_stream(h, f, unix_seconds);
        if (r != RNC_OK)
          return r;
      }
    }
    if ((pf[i].revents & POLLHUP) && DEVICE_KIND(f->status.kind) &&
        !f->pending && f->input_offset == f->input_size)
      disconnect_interface(h, f, 0);
  }
  for (i = 0; i < RNC_HOST_SLOTS; ++i) {
    host_interface *f = &h->interfaces[i];
    if (!f->used)
      continue;
    if (f->accepted && f->fd < 0) {
      if (f->sam_role == SAM_ACCEPT && !f->sam_streamed) {
        host_interface *owner = find_interface(h, f->status.parent_id);
        if (owner)
          owner->accept_after = now + 5000u;
      }
      (void)rnc_host_remove(h, f->status.interface_id);
      continue;
    }
    if ((f->input_offset < f->input_size || f->pending) && !f->weave_peer &&
        !f->multi_sub) {
      if (f->status.kind != RNC_HOST_UDP && f->status.kind != RNC_HOST_AUTO) {
        r = receive_stream(h, f, unix_seconds);
        if (r != RNC_OK)
          return r;
      }
    }
    r = flush_interface(h, f);
    if (r != RNC_OK)
      return r;
  }
  r = pump_node(h);
  if (r != RNC_OK)
    return r;
  r = rnc_node_tick(h->node, unix_seconds, now);
  if (r != RNC_OK && r != RNC_AGAIN)
    return r;
  return pump_node(h);
}
static uint64_t await_now_ms(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
rnc_result rnc_host_await_path(rnc_host *h, const uint8_t destination[16],
                               unsigned timeout_ms, rnc_host_await_fn callback,
                               void *context) {
  uint64_t start = await_now_ms(), last_request = 0;
  int requested = 0, stop = 0;
  rnc_route route;
  if (!h || !destination || !timeout_ms)
    return RNC_INVALID;
  for (;;) {
    uint64_t now = await_now_ms();
    rnc_host_event event;
    rnc_result r;
    if (rnc_node_lookup(h->node, destination, now, &route) == RNC_OK)
      return RNC_OK;
    if (now - start >= timeout_ms)
      return RNC_TIMEOUT;
    if (!requested || now - last_request >= 5000u) {
      rnc_host_status s;
      size_t i;
      for (i = 0; i < RNC_HOST_SLOTS; ++i)
        if (rnc_host_status_at(h, i, &s) == RNC_OK && s.online) {
          (void)rnc_node_request_path(h->node, destination, now);
          requested = 1;
          last_request = now;
          break;
        }
    }
    r = rnc_host_step(h, 10, (uint64_t)time(NULL), now);
    if (r != RNC_OK)
      return r;
    while (rnc_host_poll(h, &event) == RNC_OK)
      if (callback && callback(context, &event))
        stop = 1;
    if (callback && callback(context, NULL))
      stop = 1;
    if (stop)
      return RNC_AGAIN;
  }
}
