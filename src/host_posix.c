#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <openssl/crypto.h>
#include <poll.h>
#include <reticulum_c/rnc_host.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#define HOST_FLAP_SLOTS 32u
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
  char ax_call[7];
  int flap_on, flap_pending;
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
  f->status.online = 1;
  f->status.last_errno = 0;
  f->status.bound_port = f->fd >= 0 ? bound_port(f->fd) : 0;
  (void)emit_host(h, RNC_HOST_UP, f->status.interface_id, 0, NULL);
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
static void disconnect_interface(rnc_host *h, host_interface *f, int error) {
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
  }
  f->status.online = 0;
  if (f->status.kind == RNC_HOST_RNODE) {
    f->status.radio_ready = 0;
    f->radio_ack_mask = 0;
    f->radio_deadline = 0;
    f->ready = 0;
    f->first_tx_set = 0;
  }
  f->status.last_errno = error;
  f->connecting = 0;
  f->queue_count = 0;
  if (f->status.kind == RNC_HOST_PIPE)
    f->retry_at = h->now + (f->radio.respawn_delay_ms
                                ? f->radio.respawn_delay_ms
                                : 5000u);
  f->input_offset = f->input_size = 0;
  f->pending = 0;
  memset(&f->framer, 0, sizeof(f->framer));
  f->retry_at = h->now + 1000u;
}
static int resolve(const char *address, uint16_t port, int socktype,
                   int passive, int family, struct sockaddr_storage *out,
                   socklen_t *size) {
  struct addrinfo hints, *result = NULL;
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
  if (result->ai_addrlen > sizeof(*out)) {
    freeaddrinfo(result);
    errno = EINVAL;
    return -1;
  }
  memcpy(out, result->ai_addr, result->ai_addrlen);
  *size = (socklen_t)result->ai_addrlen;
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
static int connect_interface(rnc_host *h, host_interface *f) {
  int fd = socket(f->peer.ss_family, SOCK_STREAM, 0), rc;
  if (fd < 0)
    return -1;
  if (nonblock(fd) < 0) {
    close(fd);
    return -1;
  }
  rc = connect(fd, (struct sockaddr *)&f->peer, f->peer_size);
  if (rc < 0 && errno != EINPROGRESS) {
    int e = errno;
    close(fd);
    errno = e;
    return -1;
  }
  f->fd = fd;
  f->connecting = rc < 0;
  if (!f->connecting && activate(h, f) != RNC_OK) {
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
static int serial_open(const char *path, unsigned baud);
static int device_open(host_interface *f) {
  if (f->status.kind == RNC_HOST_PIPE)
    return pipe_open(f->address, &f->child);
  return serial_open(f->address, f->baud);
}
static int serial_open(const char *path, unsigned baud) {
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
  t.c_cflag &= ~(CSIZE | PARENB | CSTOPB);
  t.c_cflag |= CS8 | CLOCAL | CREAD;
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
rnc_result rnc_host_add(rnc_host *h, uint32_t id, const rnc_host_config *c) {
  host_interface *f;
  struct sockaddr_storage bind_address;
  socklen_t bind_size;
  rnc_result r = RNC_STATE;
  if (!h || !c || !id || id >= 0x80000000u || c->kind < RNC_HOST_TCP_LISTEN ||
      c->kind > RNC_HOST_AX25 || c->kiss_port > 15 || find_interface(h, id))
    return RNC_INVALID;
  if (c->kind == RNC_HOST_RNODE &&
      (!c->frequency || !c->bandwidth || c->spreading_factor < 5 ||
       c->spreading_factor > 12 || c->coding_rate < 5 || c->coding_rate > 8 ||
       c->tx_power < 0 || c->tx_power > 27))
    return RNC_INVALID;
  if (c->kind == RNC_HOST_RNODE &&
      (!(c->airtime_limit_short >= 0.0 && c->airtime_limit_short <= 100.0) ||
       !(c->airtime_limit_long >= 0.0 && c->airtime_limit_long <= 100.0) ||
       !c->id_callsign != !c->id_interval ||
       (c->id_callsign && (!*c->id_callsign ||
                           strlen(c->id_callsign) > RNC_HOST_CALLSIGN_MAX))))
    return RNC_INVALID;
  if (c->fast_flap.enabled && c->kind != RNC_HOST_TCP_LISTEN)
    return RNC_INVALID;
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
                 (c->kind >= RNC_HOST_SERIAL && c->mtu > RNC_MTU) ||
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
  f->status.mtu = c->mtu ? c->mtu : c->kind == RNC_HOST_AUTO ? 1196 : RNC_MTU;
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
  f->baud = c->serial_baud;
  f->kiss_port = c->kiss_port;
  f->flow_control = c->flow_control;
  f->ready = !c->flow_control;
  f->flap_on = c->fast_flap.enabled;
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
                 : c->kind == RNC_HOST_AX25 ? 1200u
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
  if (c->kind == RNC_HOST_AX25) {
    size_t k;
    for (k = 0; c->callsign[k]; ++k)
      f->ax_call[k] = (char)(c->callsign[k] >= 'a' ? c->callsign[k] - 32
                                                    : c->callsign[k]);
  }
  if (c->kind == RNC_HOST_RNODE && c->id_callsign) {
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
    if (resolve(c->address, c->port, SOCK_STREAM, 1, AF_UNSPEC, &bind_address,
                &bind_size) < 0)
      goto fail;
    f->fd = socket_bound(&bind_address, bind_size, SOCK_STREAM);
    if (f->fd < 0 || listen(f->fd, 8) < 0)
      goto fail;
    f->status.bound_port = bound_port(f->fd);
    f->status.online = 1;
  } else if (c->kind == RNC_HOST_TCP_CONNECT) {
    if (!c->port || resolve(c->address, c->port, SOCK_STREAM, 0, AF_UNSPEC,
                            &f->peer, &f->peer_size) < 0) {
      r = RNC_INVALID;
      goto fail;
    }
    if (connect_interface(h, f) < 0) {
      f->status.last_errno = errno;
      f->retry_at = h->now + 1000u;
    }
  } else if (c->kind == RNC_HOST_UDP) {
    if (resolve(c->address, c->port, SOCK_DGRAM, 1, AF_UNSPEC, &bind_address,
                &bind_size) < 0)
      goto fail;
    f->fd = socket_bound(&bind_address, bind_size, SOCK_DGRAM);
    if (f->fd < 0)
      goto fail;
    f->status.bound_port = bound_port(f->fd);
    if (c->target && c->target_port &&
        resolve(c->target, c->target_port, SOCK_DGRAM, 0,
                bind_address.ss_family, &f->peer, &f->peer_size) < 0)
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
    f->fd = device_open(f);
    if (f->fd < 0)
      goto fail;
    r = activate(h, f);
    if (r != RNC_OK)
      goto fail;
    if (c->kind == RNC_HOST_RNODE) {
      r = configure_radio(f, c);
      if (r != RNC_OK)
        goto fail;
    } else if (c->kind == RNC_HOST_AX25) {
      r = configure_ax25(f, c);
      if (r != RNC_OK)
        goto fail;
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
  if (index >= RNC_HOST_SLOTS || !h->interfaces[index].used)
    return RNC_AGAIN;
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
    r = rnc_host_frame_encode(f->status.kind == RNC_HOST_TCP_LISTEN ||
                                      f->status.kind == RNC_HOST_TCP_CONNECT ||
                                      f->status.kind == RNC_HOST_SERIAL ||
                                      f->status.kind == RNC_HOST_PIPE
                                  ? RNC_HOST_HDLC
                                  : RNC_HOST_KISS_FRAMING,
                              (uint8_t)(f->kiss_port << 4), wire, m, q->data,
                              sizeof(q->data), &q->size);
    if (r != RNC_OK)
      return r;
  }
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
      if (!f || !f->node_added) {
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
    close(fd);
    ++parent->status.dropped_packets;
    return;
  }
  if (nonblock(fd) < 0) {
    close(fd);
    return;
  }
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
static rnc_result receive_stream(rnc_host *h, host_interface *f,
                                 uint64_t unix_seconds) {
  uint8_t raw[RNC_MAX_FRAME], command;
  size_t n;
  rnc_result r;
  ssize_t got;
  rnc_host_framing mode =
      f->status.kind == RNC_HOST_KISS || f->status.kind == RNC_HOST_RNODE ||
              f->status.kind == RNC_HOST_AX25
          ? RNC_HOST_KISS_FRAMING
          : RNC_HOST_HDLC;
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
    if (f->status.kind == RNC_HOST_TCP_CONNECT)
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
          f->status.kind == RNC_HOST_PIPE)
        disconnect_interface(h, f, 0);
      return RNC_OK;
    }
    f->input_size = (size_t)got;
  }
  while (f->input_offset < f->input_size) {
    r = rnc_host_frame_feed(&f->framer, mode, f->input[f->input_offset++],
                            &command, raw, sizeof(raw), &n);
    if (r == RNC_OK) {
      if (f->status.kind == RNC_HOST_RNODE && command) {
        if (command >= 1 && command <= 6) {
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
        } else if (command == 0x0f && n && f->status.radio_ready)
          f->ready = 1;
        else if (command == 0x90 || (command == 0x55 && n && raw[0] == 0xf8)) {
          disconnect_interface(h, f, EIO);
          return RNC_OK;
        }
        continue;
      }
      if (f->status.kind == RNC_HOST_AX25 && (command & 15u) == 0x0f) {
        if (f->flow_control)
          f->ready = 1;
        continue;
      }
      if ((f->status.kind == RNC_HOST_KISS || f->status.kind == RNC_HOST_AX25) &&
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
                              b->data, sizeof(b->data), &b->size) == RNC_OK) {
      ++f->queue_count;
      f->first_tx_set = 0; /* restarts with the next ordinary transmission */
    }
  }
  if (!f->queue_count || !f->status.online || f->connecting)
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
  if (f->status.kind == RNC_HOST_AX25 && !q->control && f->flow_control &&
      !f->ready) {
    if (h->now < f->lock_at + 5000u) /* reference unlock timeout */
      return RNC_OK;
    f->ready = 1;
  }
  if (f->status.kind == RNC_HOST_AUTO && f->status.parent_id) {
    socket_owner = find_interface(h, f->status.parent_id);
    if (!socket_owner)
      return RNC_STATE;
  }
  fd = socket_owner->fd;
  if (fd < 0)
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
             f->status.kind == RNC_HOST_PIPE) {
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
      disconnect_interface(h, f, errno);
      return RNC_OK;
    }
  }
  if ((f->status.kind == RNC_HOST_UDP || f->status.kind == RNC_HOST_AUTO) &&
      sent != (ssize_t)q->size) {
    ++f->status.dropped_packets;
    delivered = 0;
    sent = (ssize_t)q->size;
  }
  q->offset += (size_t)sent;
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
      if ((f->status.kind == RNC_HOST_RNODE ||
           f->status.kind == RNC_HOST_AX25) &&
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
    if (f->fd < 0 && !f->accepted && now >= f->retry_at) {
      if (f->status.kind == RNC_HOST_TCP_CONNECT) {
        if (connect_interface(h, f) < 0) {
          f->status.last_errno = errno;
          f->retry_at = now + 1000u;
        } else
          ++f->status.reconnects;
      } else if (f->status.kind >= RNC_HOST_SERIAL) {
        f->fd = device_open(f);
        if (f->fd >= 0 && activate(h, f) == RNC_OK) {
          ++f->status.reconnects;
          if (f->status.kind == RNC_HOST_RNODE)
            (void)configure_radio(f, &f->radio);
          else if (f->status.kind == RNC_HOST_AX25)
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
    if (f->status.kind == RNC_HOST_RNODE && f->fd >= 0 &&
        !f->status.radio_ready) {
      if (!f->radio_deadline)
        f->radio_deadline = now + 5000u;
      else if (now >= f->radio_deadline) {
        disconnect_interface(h, f, ETIMEDOUT);
        continue;
      }
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
      if (error || activate(h, f) != RNC_OK) {
        disconnect_interface(h, f, error ? error : ENOSPC);
        continue;
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
    if ((pf[i].revents & POLLHUP) && f->status.kind >= RNC_HOST_SERIAL &&
        !f->pending && f->input_offset == f->input_size)
      disconnect_interface(h, f, 0);
  }
  for (i = 0; i < RNC_HOST_SLOTS; ++i) {
    host_interface *f = &h->interfaces[i];
    if (!f->used)
      continue;
    if (f->accepted && f->fd < 0) {
      (void)rnc_host_remove(h, f->status.interface_id);
      continue;
    }
    if (f->input_offset < f->input_size || f->pending) {
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
