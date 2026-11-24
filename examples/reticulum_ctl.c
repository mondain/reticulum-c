/* reticulum-c-ctl: operator tools for a running reticulum-c-node and for
 * identity files.
 *
 *   status  interface statistics over the authenticated RPC port (rnstatus)
 *   path    path table, blackhole list and changes (rnpath)
 *   id      identity files, hashes, signatures, file encryption (rnid)
 *
 * The RPC key is derived from the daemon's identity file (--identity) or given
 * directly (--rpc-key). Identity files are the raw 64-byte private key the
 * reference uses, so they are interchangeable with rnid. */
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include <arpa/inet.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <poll.h>
#include "msgpack_tree.h"
#include "rnid_b256.h"
#include "rsg_meta.h"
#include <reticulum_c/rnc.h>
#include <reticulum_c/rnc_host.h>
#include <reticulum_c/rnc_ipc.h>
#include <reticulum_c/rnc_requester.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* exit codes shared with rnid where it defines one */
enum {
  RC_OK = 0,
  RC_NO_IDENTITY = 2,
  RC_NO_PRVKEY = 4,
  RC_NO_FILE = 6,
  RC_INVALID_IDENTITY = 8,
  RC_INVALID_ASPECTS = 9,
  RC_INVALID_SIGNATURE = 10,
  RC_FILE_EXISTS = 11,
  RC_DECRYPT_FAILED = 12,
  RC_INVALID_ARGS = 250,
  RC_READ_ERROR = 252,
  RC_WRITE_ERROR = 253,
  RC_UNKNOWN_ERROR = 254
};
#define DEFAULT_CONTROL_PORT 37429u
#define DEFAULT_DATA_PORT 37428u
#define DEFAULT_PATH_TIMEOUT 15.0 /* Transport.PATH_REQUEST_TIMEOUT */
#define ENC_CHUNK (16u * 1024u * 1024u)
#define DEC_CHUNK (ENC_CHUNK + 96u)

static rnc_result random_bytes(void *context, uint8_t *out, size_t size) {
  (void)context;
  return RAND_priv_bytes(out, (int)size) == 1 ? RNC_OK : RNC_INVALID;
}
static void hex_encode(const uint8_t *data, size_t size, char *out) {
  size_t i;
  for (i = 0; i < size; ++i)
    sprintf(out + 2 * i, "%02x", data[i]);
}
static int hex_value(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}
/* exact-length hex string into bytes; 0 on a malformed string */
static int hex_decode(const char *text, uint8_t *out, size_t size) {
  size_t i;
  if (strlen(text) != size * 2)
    return 0;
  for (i = 0; i < size; ++i) {
    int hi = hex_value(text[2 * i]), lo = hex_value(text[2 * i + 1]);
    if (hi < 0 || lo < 0)
      return 0;
    out[i] = (uint8_t)(hi * 16 + lo);
  }
  return 1;
}
static int number(const char *text, unsigned long maximum, unsigned long *out) {
  char *end;
  unsigned long v;
  if (!*text)
    return 0;
  errno = 0;
  v = strtoul(text, &end, 10);
  if (errno || *end || v > maximum)
    return 0;
  *out = v;
  return 1;
}
static void pretty_size(double bytes, char *out, size_t size) {
  static const char *units[] = {"B", "KB", "MB", "GB", "TB"};
  unsigned i = 0;
  while (bytes >= 1000.0 && i < 4) {
    bytes /= 1000.0;
    ++i;
  }
  snprintf(out, size, i ? "%.2f %s" : "%.0f %s", bytes, units[i]);
}
static void pretty_rate(double bits, char *out, size_t size) {
  static const char *units[] = {"bps", "kbps", "Mbps", "Gbps"};
  unsigned i = 0;
  while (bits >= 1000.0 && i < 3) {
    bits /= 1000.0;
    ++i;
  }
  snprintf(out, size, "%.2f %s", bits, units[i]);
}
static void pretty_time(double unix_seconds, char *out, size_t size) {
  time_t t = (time_t)unix_seconds;
  struct tm tm;
  if (!gmtime_r(&t, &tm) || !strftime(out, size, "%Y-%m-%d %H:%M:%S UTC", &tm))
    snprintf(out, size, "unknown");
}

/* MessagePack values: see msgpack_tree.h */
#define POOL 16384u
static void json_string(const uint8_t *s, size_t n) {
  size_t i;
  putchar('"');
  for (i = 0; i < n; ++i) {
    if (s[i] == '"' || s[i] == '\\')
      printf("\\%c", s[i]);
    else if (s[i] < 0x20)
      printf("\\u%04x", s[i]);
    else
      putchar(s[i]);
  }
  putchar('"');
}
/* Bytes become hex strings, the form the reference utilities print in JSON. */
static void json_value(const val *v) {
  size_t i;
  switch (v->type) {
  case V_NIL:
    fputs("null", stdout);
    break;
  case V_BOOL:
    fputs(v->u ? "true" : "false", stdout);
    break;
  case V_INT:
    printf("%lld", (long long)v->i);
    break;
  case V_UINT:
    printf("%llu", (unsigned long long)v->u);
    break;
  case V_REAL:
    printf("%.6f", v->d);
    break;
  case V_STR:
    json_string(v->p, v->n);
    break;
  case V_BIN:
    putchar('"');
    for (i = 0; i < v->n; ++i)
      printf("%02x", v->p[i]);
    putchar('"');
    break;
  case V_ARR:
    putchar('[');
    for (i = 0; i < v->n; ++i) {
      if (i)
        fputs(", ", stdout);
      json_value(&v->kids[i]);
    }
    putchar(']');
    break;
  case V_MAP:
    putchar('{');
    for (i = 0; i < v->n; ++i) {
      const val *k = &v->kids[2 * i];
      if (i)
        fputs(", ", stdout);
      if (k->type == V_STR)
        json_string(k->p, k->n);
      else if (k->type == V_BIN) {
        size_t j;
        putchar('"');
        for (j = 0; j < k->n; ++j)
          printf("%02x", k->p[j]);
        putchar('"');
      } else
        fputs("\"?\"", stdout);
      fputs(": ", stdout);
      json_value(&v->kids[2 * i + 1]);
    }
    putchar('}');
    break;
  }
}

/* ---- RPC client --------------------------------------------------------- */
typedef struct target {
  unsigned port;
  unsigned data_port; /* the shared instance's data port, for a TCP instance */
  char unix_name[RNC_HOST_UNIX_NAME_MAX + 1]; /* set: the abstract Unix socket of this instance, port unused */
  uint8_t key[RNC_RPC_KEY_MAX];
  size_t key_size;
} target;
static unsigned long now_ms(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (unsigned long)t.tv_sec * 1000ul + (unsigned long)t.tv_nsec / 1000000ul;
}
static int write_all(int fd, const uint8_t *data, size_t size) {
  size_t sent = 0;
  while (sent < size) {
    ssize_t n = write(fd, data + sent, size - sent);
    if (n <= 0)
      return 0;
    sent += (size_t)n;
  }
  return 1;
}
/* One authenticated request/response. The response is copied into *response
 * (caller frees) so the engine can be released before it is parsed. */
static int rpc_call(const target *t, const uint8_t *request, size_t size,
                    uint8_t **response, size_t *response_size) {
  struct sockaddr_storage addr;
  socklen_t addr_size = sizeof(struct sockaddr_in);
  int fd, done = 0, ok = 0;
  rnc_rpc *rpc;
  rnc_rpc_event event;
  unsigned long deadline = now_ms() + 10000ul;
  uint8_t buf[4096];
  memset(&addr, 0, sizeof(addr));
  if (t->unix_name[0]) {
    size_t len = rnc_host_abstract_address(t->unix_name, "/rpc", &addr, sizeof(addr));
    if (!len) {
      fprintf(stderr, "The instance name %s cannot be used\n", t->unix_name);
      return 0;
    }
    addr_size = (socklen_t)len;
  } else {
    struct sockaddr_in *in = (struct sockaddr_in *)&addr;
    in->sin_family = AF_INET;
    in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    in->sin_port = htons((uint16_t)t->port);
  }
  fd = socket(addr.ss_family, SOCK_STREAM, 0);
  if (fd < 0)
    return 0;
  if (connect(fd, (struct sockaddr *)&addr, addr_size)) {
    if (t->unix_name[0])
      fprintf(stderr, "Could not connect to the shared instance %s: %s\n", t->unix_name, strerror(errno));
    else
      fprintf(stderr, "Could not connect to the daemon RPC port %u: %s\n", t->port, strerror(errno));
    close(fd);
    return 0;
  }
  rpc = rnc_rpc_new(t->key, t->key_size, 0, random_bytes, NULL,
                    RNC_RPC_MESSAGE_MAX);
  if (!rpc || rnc_rpc_start(rpc, now_ms()) != RNC_OK) {
    rnc_rpc_free(rpc);
    close(fd);
    return 0;
  }
  while (!done && now_ms() < deadline) {
    struct pollfd p = {fd, POLLIN, 0};
    while (rnc_rpc_poll(rpc, &event) == RNC_OK) {
      if (event.type == RNC_RPC_SEND) {
        if (!write_all(fd, event.data, event.size))
          done = 1;
      } else if (event.type == RNC_RPC_AUTHENTICATED) {
        if (rnc_rpc_send(rpc, request, size, now_ms()) != RNC_OK)
          done = 1;
      } else if (event.type == RNC_RPC_MESSAGE) {
        *response = malloc(event.size ? event.size : 1);
        if (*response) {
          memcpy(*response, event.data, event.size);
          *response_size = event.size;
          ok = 1;
        }
        done = 1;
      } else if (event.type == RNC_RPC_CLOSED)
        done = 1;
    }
    if (done)
      break;
    if (poll(&p, 1, 100) > 0 && (p.revents & (POLLIN | POLLHUP))) {
      ssize_t n = read(fd, buf, sizeof(buf));
      size_t offset = 0, consumed;
      if (n <= 0)
        break;
      while (offset < (size_t)n) {
        rnc_result r =
            rnc_rpc_input(rpc, buf + offset, (size_t)n - offset, &consumed, now_ms());
        offset += consumed;
        if ((r != RNC_OK && r != RNC_AGAIN) || !consumed)
          break;
      }
    }
    (void)rnc_rpc_tick(rpc, now_ms());
  }
  if (!ok)
    fprintf(stderr, "The daemon did not accept the RPC key or did not answer\n");
  rnc_rpc_free(rpc);
  close(fd);
  return ok;
}
/* Runs one request, decodes the response into a value tree. */
typedef struct reply {
  uint8_t *data;
  val *pool;
  val root;
} reply;
static int rpc_query(const target *t, const uint8_t *request, size_t size,
                     reply *out) {
  size_t n;
  reader r;
  memset(out, 0, sizeof(*out));
  if (!rpc_call(t, request, size, &out->data, &n))
    return 0;
  out->pool = calloc(POOL, sizeof(val));
  r.p = out->data;
  r.end = out->data + n;
  r.pool = out->pool;
  r.used = 0;
  r.cap = POOL;
  if (!out->pool || !parse(&r, &out->root, 0)) {
    fprintf(stderr, "Unreadable response from the daemon\n");
    return 0;
  }
  return 1;
}
static void reply_free(reply *r) {
  free(r->data);
  free(r->pool);
}
/* ---- remote management (-R) --------------------------------------------
 * rnstatus -R and rnpath -R talk to another transport instance's management destination,
 * "rnstransport.remote.management", whose hash comes from that instance's identity hash. The
 * link needs a node of its own: --attach HOST:PORT is a TCP server interface to reach the network
 * through, --mgmt-identity the identity the remote instance has on its allow list. */
static struct {
  const char *hash, *attach, *identity;
  double wait;
} remote;
static rnc_result remote_random(void *context, uint8_t *out, size_t size) {
  (void)context;
  return RAND_priv_bytes(out, (int)size) == 1 ? RNC_OK : RNC_CRYPTO;
}
static int remote_destination(const char *identity_hex, uint8_t destination[16]) {
  static const char name[] = "rnstransport.remote.management";
  uint8_t identity_hash[16], name_hash[32], material[26], full[32];
  if (strlen(identity_hex) != 32 || !hex_decode(identity_hex, identity_hash, 16))
    return 0;
  if (rnc_hash(name, sizeof(name) - 1, name_hash) != RNC_OK)
    return 0;
  memcpy(material, name_hash, 10);
  memcpy(material + 10, identity_hash, 16);
  if (rnc_hash(material, sizeof(material), full) != RNC_OK)
    return 0;
  memcpy(destination, full, 16);
  return 1;
}
/* One request to the remote instance; the answer is parsed into *out. */
static int remote_call(const char *path, const uint8_t *request, size_t request_size, reply *out) {
  rnc_identity id;
  rnc_node *node = NULL;
  rnc_host *host = NULL;
  rnc_requester *requester = NULL;
  rnc_host_config hc;
  rnc_requester_result result;
  uint8_t destination[16], *answer = NULL;
  char address[256];
  const char *colon = remote.attach ? strrchr(remote.attach, ':') : NULL;
  unsigned long port = 0, started;
  double wait = remote.wait > 0 ? remote.wait : 15.0;
  int ok = 0, have_id = 0;
  memset(out, 0, sizeof(*out));
  if (!remote.attach || !remote.identity || !colon || colon == remote.attach ||
      (size_t)(colon - remote.attach) >= sizeof(address) || !number(colon + 1, 65535, &port) || !port) {
    fprintf(stderr, "A remote query needs --attach HOST:PORT and --mgmt-identity FILE\n");
    return 0;
  }
  memcpy(address, remote.attach, (size_t)(colon - remote.attach));
  address[colon - remote.attach] = 0;
  if (!remote_destination(remote.hash, destination)) {
    fprintf(stderr, "The remote instance is its 32 hexadecimal character identity hash\n");
    return 0;
  }
  if (rnc_host_identity_load(remote.identity, remote_random, NULL, &id) != RNC_OK) {
    fprintf(stderr, "Cannot load the management identity %s\n", remote.identity);
    return 0;
  }
  have_id = 1;
  node = rnc_node_new(&id, 0, remote_random, NULL);
  host = node ? rnc_host_new(node) : NULL;
  memset(&hc, 0, sizeof(hc));
  hc.kind = RNC_HOST_TCP_CONNECT;
  hc.name = "ctl remote";
  hc.address = address;
  hc.port = (uint16_t)port;
  hc.mtu = RNC_MAX_MTU;
  hc.bitrate = 1000000000u;
  if (!host || rnc_host_add(host, 1, &hc) != RNC_OK) {
    fprintf(stderr, "Cannot attach to %s\n", remote.attach);
    goto done;
  }
  requester = rnc_requester_new(node, 1u << 20, remote_random, NULL);
  answer = malloc(1u << 20);
  if (!requester || !answer)
    goto done;
  if (rnc_host_await_path(host, destination, (unsigned)(wait * 1000.0), NULL, NULL) != RNC_OK) {
    fprintf(stderr, "No path to the remote instance\n");
    goto done;
  }
  if (rnc_requester_start(requester, destination, &id, path, request, request_size, 1,
                          (uint64_t)(wait * 1000.0), (uint64_t)time(NULL), now_ms()) != RNC_OK) {
    fprintf(stderr, "Could not start the remote request\n");
    goto done;
  }
  started = now_ms();
  while (now_ms() - started < (unsigned long)(wait * 1000.0) + 2000ul) {
    rnc_host_event event;
    uint64_t unix_now = (uint64_t)time(NULL), now = now_ms();
    if (rnc_host_step(host, 20, unix_now, now) != RNC_OK)
      break;
    while (rnc_host_poll(host, &event) == RNC_OK)
      if (event.type == RNC_HOST_NODE && event.node.type == RNC_NODE_LOCAL)
        (void)rnc_requester_input(requester, &event.node, unix_now, now);
    (void)rnc_requester_tick(requester, unix_now, now_ms());
    if (rnc_requester_poll(requester, &result, answer, 1u << 20) == RNC_OK) {
      reader r;
      if (result.status != RNC_REQUESTER_DONE) {
        fprintf(stderr, "The remote request failed. Likely an authentication failure.\n");
        break;
      }
      out->pool = calloc(POOL, sizeof(val));
      r.p = answer;
      r.end = answer + result.size;
      r.pool = out->pool;
      r.used = 0;
      r.cap = POOL;
      if (!out->pool || !parse(&r, &out->root, 0)) {
        fprintf(stderr, "Unreadable response from the remote instance\n");
        break;
      }
      out->data = answer; /* the parsed values point into it */
      answer = NULL;
      ok = 1;
      break;
    }
  }
done:
  free(answer);
  rnc_requester_free(requester);
  rnc_host_free(host);
  rnc_node_free(node);
  if (have_id)
    rnc_identity_clear(&id);
  if (!ok) {
    free(out->pool);
    memset(out, 0, sizeof(*out));
  }
  return ok;
}
/* get_request, answered by the remote instance when -R is given. */
static int remote_get(const char *method, const uint8_t *dest, long max_hops, reply *out) {
  uint8_t buf[128];
  rnc_rpc_writer w;
  size_t n;
  int status = !strcmp(method, "interface_stats");
  rnc_rpc_writer_init(&w, buf, sizeof(buf));
  if (status) {
    (void)rnc_rpc_write_array(&w, 1);
    (void)rnc_rpc_write_bool(&w, 0);
  } else if (!strcmp(method, "path_table") || !strcmp(method, "rate_table")) {
    int table = !strcmp(method, "path_table");
    (void)rnc_rpc_write_array(&w, table ? 3 : 2);
    (void)rnc_rpc_write_string(&w, table ? "table" : "rates");
    if (dest)
      (void)rnc_rpc_write_bin(&w, dest, 16);
    else
      (void)rnc_rpc_write_nil(&w);
    if (table) {
      if (max_hops > 0)
        (void)rnc_rpc_write_uint(&w, (uint64_t)max_hops);
      else
        (void)rnc_rpc_write_nil(&w);
    }
  } else {
    fprintf(stderr, "%s is not available from a remote instance\n", method);
    return 0;
  }
  if (rnc_rpc_writer_finish(&w, &n) != RNC_OK)
    return 0;
  if (!remote_call(status ? "/status" : "/path", buf, n, out))
    return 0;
  if (status) { /* [statistics, link count]: the statistics are what the local call returns */
    if (out->root.type != V_ARR || !out->root.n) {
      fprintf(stderr, "Unreadable response from the remote instance\n");
      reply_free(out);
      return 0;
    }
    out->root = out->root.kids[0];
  }
  return 1;
}
static int get_request(const target *t, const char *method, const uint8_t *dest,
                       long max_hops, reply *out) {
  uint8_t buf[256];
  rnc_rpc_writer w;
  size_t n, pairs = 1 + (dest ? 1 : 0) + (max_hops > 0 ? 1 : 0);
  if (remote.hash)
    return remote_get(method, dest, max_hops, out);
  rnc_rpc_writer_init(&w, buf, sizeof(buf));
  (void)rnc_rpc_write_map(&w, pairs);
  (void)rnc_rpc_write_string(&w, "get");
  (void)rnc_rpc_write_string(&w, method);
  if (dest) {
    (void)rnc_rpc_write_string(&w, "destination_hash");
    (void)rnc_rpc_write_bin(&w, dest, 16);
  }
  if (max_hops > 0) {
    (void)rnc_rpc_write_string(&w, "max_hops");
    (void)rnc_rpc_write_uint(&w, (uint64_t)max_hops);
  }
  if (rnc_rpc_writer_finish(&w, &n) != RNC_OK)
    return 0;
  return rpc_query(t, buf, n, out);
}

/* ---- connection options shared by status and path ----------------------- */
typedef struct conn {
  unsigned long port;
  const char *identity, *config, *rpc_key;
  int tcp;                               /* the config names shared_instance_type = tcp */
  unsigned long data_port;               /* the config's shared_instance_port */
  char instance_name[RNC_HOST_UNIX_NAME_MAX + 1]; /* the config's instance_name */
} conn;
static int load_private(const char *path, rnc_identity *id) {
  uint8_t key[64];
  struct stat st;
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return RC_NO_FILE;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size != 64 ||
      read(fd, key, 64) != 64) {
    close(fd);
    return RC_INVALID_IDENTITY;
  }
  close(fd);
  if (rnc_identity_from_private(id, key) != RNC_OK)
    return RC_INVALID_IDENTITY;
  memset(key, 0, sizeof(key));
  return RC_OK;
}
/* instance_control_port and rpc_key from a reference-style config file */
static void read_config(const char *path, conn *c, char *rpc_key, size_t size) {
  FILE *f = fopen(path, "r");
  char line[512];
  if (!f)
    return;
  while (fgets(line, sizeof(line), f)) {
    char *eq = strchr(line, '='), *k = line, *v, *e;
    if (!eq)
      continue;
    *eq = 0;
    v = eq + 1;
    while (*k == ' ' || *k == '\t')
      ++k;
    for (e = eq - 1; e >= k && (*e == ' ' || *e == '\t'); --e)
      *e = 0;
    while (*v == ' ' || *v == '\t')
      ++v;
    for (e = v + strlen(v); e > v && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' '); --e)
      e[-1] = 0;
    if (!strcmp(k, "instance_control_port") && !c->port)
      (void)number(v, 65535, &c->port);
    else if (!strcmp(k, "shared_instance_port") && !c->data_port)
      (void)number(v, 65535, &c->data_port);
    else if (!strcmp(k, "shared_instance_type") && !strcasecmp(v, "tcp"))
      c->tcp = 1;
    else if (!strcmp(k, "instance_name") && !c->instance_name[0] && strlen(v) <= RNC_HOST_UNIX_NAME_MAX)
      strcpy(c->instance_name, v);
    else if (!strcmp(k, "rpc_key") && !c->rpc_key && strlen(v) < size) {
      strcpy(rpc_key, v);
      c->rpc_key = rpc_key;
    }
  }
  fclose(f);
}
/* The reference's configuration directory: /etc/reticulum if it holds a config, else ~/.config/reticulum if
 * it does, else ~/.reticulum */
static int default_config_dir(char *out, size_t size) {
  const char *home = getenv("HOME");
  char probe[1100];
  struct stat sb;
  if (!stat("/etc/reticulum/config", &sb) && S_ISREG(sb.st_mode))
    return snprintf(out, size, "/etc/reticulum") < (int)size;
  if (!home || !*home)
    return 0;
  if (snprintf(probe, sizeof(probe), "%s/.config/reticulum/config", home) < (int)sizeof(probe) &&
      !stat(probe, &sb) && S_ISREG(sb.st_mode))
    return snprintf(out, size, "%s/.config/reticulum", home) < (int)size;
  return snprintf(out, size, "%s/.reticulum", home) < (int)size;
}
static int make_target(conn *c, target *t) {
  rnc_identity id;
  char config_key[RNC_RPC_KEY_MAX * 2 + 2];
  static char dir_config[1100], dir_identity[1100], dir_path[1100];
  struct stat sb;
  memset(t, 0, sizeof(*t));
  /* as the daemon: --config may be a configuration directory, and with nothing to go on the reference's search
   * order is used; the identity then defaults to <dir>/storage/transport_identity */
  if (!remote.hash && !c->rpc_key) {
    int use_dir = 0;
    if (c->config && !stat(c->config, &sb) && S_ISDIR(sb.st_mode))
      use_dir = snprintf(dir_path, sizeof(dir_path), "%s", c->config) < (int)sizeof(dir_path);
    else if (!c->config && !c->identity)
      use_dir = default_config_dir(dir_path, sizeof(dir_path));
    if (use_dir && snprintf(dir_config, sizeof(dir_config), "%s/config", dir_path) < (int)sizeof(dir_config) &&
        snprintf(dir_identity, sizeof(dir_identity), "%s/storage/transport_identity", dir_path) <
            (int)sizeof(dir_identity)) {
      c->config = dir_config;
      if (!c->identity)
        c->identity = dir_identity;
    }
  }
  if (remote.hash) { /* answered by the remote instance: no local RPC key is needed */
    return 1;
  }
  if (c->config)
    read_config(c->config, c, config_key, sizeof(config_key));
  t->port = c->port ? (unsigned)c->port : DEFAULT_CONTROL_PORT;
  t->data_port = c->data_port ? (unsigned)c->data_port : DEFAULT_DATA_PORT;
  /* As the reference: on Linux the shared instance is an abstract Unix socket unless the config says TCP or a
   * control port was given on the command line */
#ifdef __linux__
  if (!c->tcp && !c->port)
    (void)snprintf(t->unix_name, sizeof(t->unix_name), "%s", c->instance_name[0] ? c->instance_name : "default");
#endif
  if (c->rpc_key) {
    size_t n = strlen(c->rpc_key) / 2;
    if (!n || n > RNC_RPC_KEY_MAX || !hex_decode(c->rpc_key, t->key, n)) {
      fprintf(stderr, "The RPC key must be hexadecimal\n");
      return 0;
    }
    t->key_size = n;
    return 1;
  }
  if (c->identity) {
    int rc = load_private(c->identity, &id);
    if (rc) {
      fprintf(stderr, "Could not load the daemon identity %s\n", c->identity);
      return 0;
    }
    if (rnc_rpc_key(&id, t->key) != RNC_OK)
      return 0;
    t->key_size = 32;
    rnc_identity_clear(&id);
    return 1;
  }
  fprintf(stderr, "Specify the daemon identity with --identity or --rpc-key\n");
  return 0;
}
/* shared option handling; returns 1 if argv[*i] was consumed */
static int conn_option(conn *c, int argc, char **argv, int *i) {
  const char *a = argv[*i];
  if (!strcmp(a, "-R") || !strcmp(a, "--attach") || !strcmp(a, "--mgmt-identity") || !strcmp(a, "-w")) {
    if (*i + 1 >= argc)
      return -1;
    ++*i;
    if (!strcmp(a, "-R"))
      remote.hash = argv[*i];
    else if (!strcmp(a, "--attach"))
      remote.attach = argv[*i];
    else if (!strcmp(a, "--mgmt-identity"))
      remote.identity = argv[*i];
    else {
      char *end;
      remote.wait = strtod(argv[*i], &end);
      if (*end || !(remote.wait > 0) || remote.wait > 3600)
        return -1;
    }
    return 1;
  }
  if (!strcmp(a, "--port") || !strcmp(a, "--data-port") || !strcmp(a, "--identity") ||
      !strcmp(a, "--config") || !strcmp(a, "--rpc-key")) {
    if (*i + 1 >= argc)
      return -1;
    ++*i;
    if (!strcmp(a, "--port")) {
      if (!number(argv[*i], 65535, &c->port) || !c->port)
        return -1;
    } else if (!strcmp(a, "--data-port")) {
      if (!number(argv[*i], 65535, &c->data_port) || !c->data_port)
        return -1;
    } else if (!strcmp(a, "--identity"))
      c->identity = argv[*i];
    else if (!strcmp(a, "--config"))
      c->config = argv[*i];
    else
      c->rpc_key = argv[*i];
    return 1;
  }
  return 0;
}

/* ---- status ------------------------------------------------------------- */
static const char *mode_name(uint64_t mode) {
  switch (mode) {
  case 1:
    return "Full";
  case 2:
    return "Point-to-Point";
  case 3:
    return "Access Point";
  case 4:
    return "Roaming";
  case 5:
    return "Boundary";
  case 6:
    return "Gateway";
  case 7:
    return "Internal";
  default:
    return "Unknown";
  }
}
static void print_str(const val *v, const char *fallback) {
  if (v && v->type == V_STR)
    printf("%.*s", (int)v->n, (const char *)v->p);
  else
    fputs(fallback, stdout);
}
static void print_hex(const val *v) {
  size_t i;
  if (v && v->type == V_BIN)
    for (i = 0; i < v->n; ++i)
      printf("%02x", v->p[i]);
}
/* The values an interface is sorted by (rnstatus -s): one statistics key, or the sum of two */
typedef struct sort_def {
  const char *name, *alias, *first, *second;
} sort_def;
static const sort_def sort_defs[] = {
    {"rate", "bitrate", "bitrate", NULL},
    {"rx", NULL, "rxb", NULL},
    {"tx", NULL, "txb", NULL},
    {"rxs", NULL, "rxs", NULL},
    {"txs", NULL, "txs", NULL},
    {"traffic", NULL, "rxb", "txb"},
    {"anns", "announces", "incoming_announce_frequency", "outgoing_announce_frequency"},
    {"arx", NULL, "incoming_announce_frequency", NULL},
    {"atx", NULL, "outgoing_announce_frequency", NULL},
    {"arxc", NULL, "arxc", NULL},
    {"atxc", NULL, "atxc", NULL},
    {"prx", NULL, "incoming_pr_frequency", NULL},
    {"ptx", NULL, "outgoing_pr_frequency", NULL},
    {"prxc", NULL, "prxc", NULL},
    {"ptxc", NULL, "ptxc", NULL},
    {"held", NULL, "held_announces", NULL},
    {"pvs", NULL, "protocol_violations", NULL},
    {"ivs", NULL, "ifac_violations", NULL},
    {"flt", NULL, "packet_filter_hits", NULL},
    {"gravity", "g", "gravity", NULL},
    {"txdrp", NULL, "txdrp", NULL},
    {"txdrb", NULL, "txdrb", NULL},
    {"txbuf", NULL, "txbuffered", NULL}};
static const sort_def *sort_find(const char *key) {
  size_t k;
  char lower[16];
  size_t n = strlen(key);
  if (n >= sizeof(lower))
    return NULL;
  for (k = 0; k <= n; ++k) /* the reference lower-cases the key */
    lower[k] = (char)tolower((unsigned char)key[k]);
  for (k = 0; k < sizeof(sort_defs) / sizeof(*sort_defs); ++k)
    if (!strcmp(lower, sort_defs[k].name) || (sort_defs[k].alias && !strcmp(lower, sort_defs[k].alias)))
      return &sort_defs[k];
  return NULL;
}
static int sort_key_known(const char *key) {
  return sort_find(key) != NULL;
}
static double sort_value(const val *f, const char *key) {
  const sort_def *d = sort_find(key);
  double v;
  if (!d)
    return 0.0;
  v = as_double(map_get(f, d->first));
  if (d->second)
    v += as_double(map_get(f, d->second));
  return v;
}
static int name_matches(const val *f, const char *filter) {
  const val *name = map_get(f, "name");
  char text[256];
  size_t n;
  if (!filter)
    return 1;
  if (!name || name->type != V_STR)
    return 0;
  n = name->n < sizeof(text) - 1 ? name->n : sizeof(text) - 1;
  memcpy(text, name->p, n);
  text[n] = 0;
  return strstr(text, filter) != NULL;
}
static int discovered_listing(const char *dir, const char *filter, int details, int json, int show_stale,
                              int show_unknown);
static int cmd_status(int argc, char **argv) {
  conn c = {0};
  int i, json = 0, reverse = 0, link_stats = 0, monitor = 0, discovered = 0, details = 0, show_stale = 0, show_unknown = 0;
  double interval = 1.0;
  const char *discovery_dir = NULL;
  const char *sort = NULL, *filter = NULL;
  size_t order[256], shown = 0, m;
  target t;
  reply r;
  const val *ifaces, *v;
  size_t k;
  char a[32], b[32];
  for (i = 0; i < argc; ++i) {
    int used = conn_option(&c, argc, argv, &i);
    if (used < 0)
      return RC_INVALID_ARGS;
    if (used)
      continue;
    if (!strcmp(argv[i], "-j") || !strcmp(argv[i], "--json"))
      json = 1;
    else if (!strcmp(argv[i], "-r") || !strcmp(argv[i], "--reverse"))
      reverse = 1;
    else if (!strcmp(argv[i], "-l") || !strcmp(argv[i], "--link-stats"))
      link_stats = 1;
    else if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--discovered"))
      discovered = 1;
    else if (!strcmp(argv[i], "-D"))
      details = 1;
    else if (!strcmp(argv[i], "--show-stale"))
      show_stale = 1;
    else if (!strcmp(argv[i], "--show-unknown"))
      show_unknown = 1;
    else if (!strcmp(argv[i], "--discovery-dir")) {
      if (++i >= argc)
        return RC_INVALID_ARGS;
      discovery_dir = argv[i];
    }
    else if (!strcmp(argv[i], "-m") || !strcmp(argv[i], "--monitor"))
      monitor = 1;
    else if (!strcmp(argv[i], "-I") || !strcmp(argv[i], "--monitor-interval")) {
      char *end;
      if (++i >= argc)
        return RC_INVALID_ARGS;
      interval = strtod(argv[i], &end);
      if (*end || !(interval > 0) || interval > 3600)
        return RC_INVALID_ARGS;
    }
    else if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--sort")) {
      if (++i >= argc || !sort_key_known(argv[i])) {
        fprintf(stderr, "Sort by one of rate, traffic, rx, tx, rxs, txs, anns, arx, atx, arxc, atxc, held, prx, ptx, prxc, ptxc, pvs, ivs, flt, gravity, txdrp, txdrb, txbuf\n");
        return RC_INVALID_ARGS;
      }
      sort = argv[i];
    } else if (argv[i][0] != '-' && !filter)
      filter = argv[i];
    else {
      fprintf(stderr, "Unknown option %s\n", argv[i]);
      return RC_INVALID_ARGS;
    }
  }
  if (discovered || details) {
    /* the records live in <configuration directory>/storage/discovery/interfaces, as the reference keeps them */
    char dir[1300], base[1100];
    struct stat sb;
    if (!discovery_dir) {
      if (c.config && !stat(c.config, &sb) && S_ISDIR(sb.st_mode))
        (void)snprintf(base, sizeof(base), "%s", c.config);
      else if (c.config) { /* a configuration file: its directory */
        const char *slash = strrchr(c.config, '/');
        if (slash)
          (void)snprintf(base, sizeof(base), "%.*s", (int)(slash - c.config), c.config);
        else
          (void)snprintf(base, sizeof(base), ".");
      } else if (!default_config_dir(base, sizeof(base))) {
        fprintf(stderr, "No configuration directory: give --config or --discovery-dir\n");
        return RC_INVALID_ARGS;
      }
      (void)snprintf(dir, sizeof(dir), "%s/storage/discovery/interfaces", base);
      discovery_dir = dir;
    }
    return discovered_listing(discovery_dir, filter, details, json, show_stale, show_unknown);
  }
  if (!make_target(&c, &t))
    return RC_INVALID_ARGS;
  for (;;) { /* once, or every `interval` seconds in monitor mode */
  shown = 0;
  if (monitor && !json)
    fputs("\033[H\033[J", stdout); /* home the cursor and clear the screen */
  if (!get_request(&t, "interface_stats", NULL, 0, &r))
    return RC_UNKNOWN_ERROR;
  if (r.root.type != V_MAP) {
    fprintf(stderr, "The daemon returned no statistics\n");
    reply_free(&r);
    return RC_UNKNOWN_ERROR;
  }
  if (json) {
    json_value(&r.root);
    putchar('\n');
    reply_free(&r);
    return RC_OK;
  }
  ifaces = map_get(&r.root, "interfaces");
  for (k = 0; ifaces && ifaces->type == V_ARR && k < ifaces->n && shown < 256; ++k)
    if (name_matches(&ifaces->kids[k], filter))
      order[shown++] = k;
  if (sort) /* a stable insertion sort, largest first as the reference sorts, smallest first with -r */
    for (k = 1; k < shown; ++k) {
      size_t at = order[k];
      for (m = k; m > 0; --m) {
        double above = sort_value(&ifaces->kids[order[m - 1]], sort), mine = sort_value(&ifaces->kids[at], sort);
        if (reverse ? above <= mine : above >= mine)
          break;
        order[m] = order[m - 1];
      }
      order[m] = at;
    }
  else if (reverse)
    for (k = 0; k < shown / 2; ++k) {
      size_t swap = order[k];
      order[k] = order[shown - 1 - k];
      order[shown - 1 - k] = swap;
    }
  for (k = 0; k < shown; ++k) {
    const val *f = &ifaces->kids[order[k]];
    putchar(' ');
    print_str(map_get(f, "name"), "?");
    printf("\n    Status    : %s\n",
           as_uint(map_get(f, "status")) ? "Up" : "Down");
    printf("    Mode      : %s\n", mode_name(as_uint(map_get(f, "mode"))));
    v = map_get(f, "bitrate");
    if (as_uint(v)) {
      pretty_rate((double)as_uint(v), a, sizeof(a));
      printf("    Rate      : %s\n", a);
    }
    v = map_get(f, "rssi");
    if (v && (v->type == V_INT || v->type == V_UINT)) {
      printf("    Signal    : RSSI %lld dBm, SNR %.2f dB, quality %.1f%%\n",
             v->type == V_INT ? (long long)v->i : (long long)v->u,
             as_double(map_get(f, "snr")), as_double(map_get(f, "q")));
    }
    v = map_get(f, "clients");
    if (v && v->type == V_UINT)
      printf("    Clients   : %llu\n", (unsigned long long)v->u);
    pretty_size((double)as_uint(map_get(f, "txb")), a, sizeof(a));
    pretty_size((double)as_uint(map_get(f, "rxb")), b, sizeof(b));
    printf("    Traffic   : %s sent, %s received\n", a, b);
    v = map_get(f, "txstalled");
    if (v && as_uint(v))
      puts("    Egress    : stalled, nothing is draining to this peer");
    v = map_get(f, "ingress_gated");
    if (v && as_uint(v))
      puts("    Ingress   : throttled, reading from this peer is held back");
    printf("    Announces : %llu sent, %llu received\n",
           (unsigned long long)as_uint(map_get(f, "atxc")),
           (unsigned long long)as_uint(map_get(f, "arxc")));
    putchar('\n');
  }
  v = map_get(&r.root, "transport_id");
  if (v && v->type == V_BIN) {
    fputs(" Transport Instance <", stdout);
    print_hex(v);
    printf("> running\n");
  }
  v = map_get(&r.root, "network_id");
  if (v && v->type == V_BIN) {
    fputs(" Network Identity   <", stdout);
    print_hex(v);
    printf(">\n");
  }
  {
    char link_text[96] = "";
    if (link_stats) { /* the reference's footer: entries in the link table, and how many of them are active */
      reply links;
      unsigned long long total, active = 0;
      if (get_request(&t, "link_count", NULL, 0, &links)) {
        total = as_uint(&links.root);
        reply_free(&links);
        if (get_request(&t, "active_link_count", NULL, 0, &links)) {
          active = as_uint(&links.root);
          reply_free(&links);
        }
        (void)snprintf(link_text, sizeof(link_text), "%s%llu entr%s in link table%s", map_get(&r.root, "transport_id") ? ", " : " ",
                       total, total == 1 ? "y" : "ies", "");
        if (active) {
          size_t used = strlen(link_text);
          (void)snprintf(link_text + used, sizeof(link_text) - used, " (%llu active)", active);
        }
      }
    }
    v = map_get(&r.root, "transport_uptime");
    if (v && as_double(v) > 0)
      printf(" Uptime is %.0f seconds%s\n", as_double(v), link_text);
    else if (link_text[0])
      printf("%s\n", link_text);
  }
  reply_free(&r);
  if (!monitor)
    return RC_OK;
  (void)fflush(stdout);
  {
    struct timespec pause = {(time_t)interval, (long)((interval - (double)(time_t)interval) * 1e9)};
    nanosleep(&pause, NULL);
  }
  }
}


/* ---- path --------------------------------------------------------------- */
static void print_path(const val *e) {
  char when[48];
  uint64_t hops = as_uint(map_get(e, "hops"));
  print_hex(map_get(e, "hash"));
  printf(" is %llu hop%s away via ", (unsigned long long)hops,
         hops == 1 ? "" : "s");
  print_hex(map_get(e, "via"));
  fputs(" on ", stdout);
  print_str(map_get(e, "interface"), "?");
  pretty_time(as_double(map_get(e, "expires")), when, sizeof(when));
  printf(" expires %s\n", when);
}
static int send_command(const target *t, const char *method, const uint8_t *id,
                        uint64_t until, const char *reason) {
  uint8_t buf[256];
  rnc_rpc_writer w;
  size_t n;
  reply r;
  int ok;
  rnc_rpc_writer_init(&w, buf, sizeof(buf));
  (void)rnc_rpc_write_map(&w, 1 + (until ? 1 : 0) + (reason ? 1 : 0));
  (void)rnc_rpc_write_string(&w, method);
  (void)rnc_rpc_write_bin(&w, id, 16);
  if (until) {
    (void)rnc_rpc_write_string(&w, "until");
    (void)rnc_rpc_write_uint(&w, until);
  }
  if (reason) {
    (void)rnc_rpc_write_string(&w, "reason");
    (void)rnc_rpc_write_string(&w, reason);
  }
  if (rnc_rpc_writer_finish(&w, &n) != RNC_OK)
    return 0;
  if (!rpc_query(t, buf, n, &r))
    return 0;
  ok = r.root.type != V_BOOL || r.root.u;
  reply_free(&r);
  return ok;
}
/* drop calls: {"drop": what} plus the destination_hash for "path" and "all_via". The reply is True or False
 * for a path, the number of paths for all_via and None for the announce queues. */
static int send_drop(const target *t, const char *what, const uint8_t *hash, reply *r) {
  uint8_t buf[128];
  rnc_rpc_writer w;
  size_t n;
  rnc_rpc_writer_init(&w, buf, sizeof(buf));
  (void)rnc_rpc_write_map(&w, hash ? 2 : 1);
  (void)rnc_rpc_write_string(&w, "drop");
  (void)rnc_rpc_write_string(&w, what);
  if (hash) {
    (void)rnc_rpc_write_string(&w, "destination_hash");
    (void)rnc_rpc_write_bin(&w, hash, 16);
  }
  if (rnc_rpc_writer_finish(&w, &n) != RNC_OK)
    return 0;
  return rpc_query(t, buf, n, r);
}
static void print_hash(const uint8_t *hash) {
  size_t k;
  for (k = 0; k < 16; ++k)
    printf("%02x", hash[k]);
}
/* Ask the shared instance for a path the way the reference's clients do: as a local client of its data port,
 * send a path request for the destination. The answer arrives in the instance's path table, which the caller
 * polls. */
static int send_packet(const target *t, const rnc_packet *packet) {
  struct sockaddr_storage addr;
  socklen_t addr_size = sizeof(struct sockaddr_in);
  uint8_t raw[RNC_MAX_MTU], framed[RNC_HOST_FRAME_MAX];
  size_t n, m;
  int fd, ok;
  memset(&addr, 0, sizeof(addr));
  if (t->unix_name[0]) {
    size_t len = rnc_host_abstract_address(t->unix_name, "", &addr, sizeof(addr));
    if (!len)
      return 0;
    addr_size = (socklen_t)len;
  } else {
    struct sockaddr_in *in = (struct sockaddr_in *)&addr;
    in->sin_family = AF_INET;
    in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    in->sin_port = htons((uint16_t)t->data_port);
  }
  if (rnc_packet_encode(packet, raw, sizeof(raw), &n) != RNC_OK ||
      rnc_host_frame_encode(RNC_HOST_HDLC, 0, raw, n, framed, sizeof(framed), &m) != RNC_OK)
    return 0;
  fd = socket(addr.ss_family, SOCK_STREAM, 0);
  if (fd < 0)
    return 0;
  ok = !connect(fd, (struct sockaddr *)&addr, addr_size) && write_all(fd, framed, m);
  /* give the instance time to read the request before the connection goes */
  if (ok) {
    struct timespec pause = {0, 100000000L};
    nanosleep(&pause, NULL);
  }
  close(fd);
  return ok;
}
static int send_path_request(const target *t, const uint8_t hash[16]) {
  uint8_t tag[16];
  rnc_packet packet;
  return RAND_bytes(tag, sizeof(tag)) == 1 && rnc_path_request_create(hash, NULL, tag, sizeof(tag), &packet) == RNC_OK &&
         send_packet(t, &packet);
}
/* The path table entry for `hash`, or no pool at all; the reply stays alive until reply_free */
static const val *find_path(const reply *r, const uint8_t hash[16]) {
  size_t k;
  if (r->root.type != V_ARR)
    return NULL;
  for (k = 0; k < r->root.n; ++k) {
    const val *h = map_get(&r->root.kids[k], "hash");
    if (h && h->type == V_BIN && h->n == 16 && !memcmp(h->p, hash, 16))
      return &r->root.kids[k];
  }
  return NULL;
}
static int cmd_path(int argc, char **argv) {
  conn c = {0};
  int i, json = 0, table = 0, list = 0, have_hash = 0, rc = RC_OK;
  long max_hops = 0;
  uint8_t hash[16], add[16], remove_hash[16];
  int do_add = 0, do_remove = 0, rates = 0, drop = 0, drop_via = 0, drop_queues = 0;
  unsigned long hours = 0;
  const char *reason = NULL;
  double timeout = DEFAULT_PATH_TIMEOUT;
  target t;
  reply r;
  size_t k;
  for (i = 0; i < argc; ++i) {
    int used = conn_option(&c, argc, argv, &i);
    unsigned long n;
    if (used < 0)
      return RC_INVALID_ARGS;
    if (used)
      continue;
    if (!strcmp(argv[i], "-j") || !strcmp(argv[i], "--json"))
      json = 1;
    else if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--table"))
      table = 1;
    else if (!strcmp(argv[i], "-b") || !strcmp(argv[i], "--blackholed"))
      list = 1;
    else if (!strcmp(argv[i], "-r") || !strcmp(argv[i], "--rates"))
      rates = 1;
    else if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--drop"))
      drop = 1;
    else if (!strcmp(argv[i], "-x") || !strcmp(argv[i], "--drop-via"))
      drop_via = 1;
    else if (!strcmp(argv[i], "-D") || !strcmp(argv[i], "--drop-announces"))
      drop_queues = 1;
    else if (!strcmp(argv[i], "-m") || !strcmp(argv[i], "--max")) {
      if (++i >= argc || !number(argv[i], 128, &n))
        return RC_INVALID_ARGS;
      max_hops = (long)n;
    } else if (!strcmp(argv[i], "--duration")) {
      if (++i >= argc || !number(argv[i], 100000, &hours))
        return RC_INVALID_ARGS;
    } else if (!strcmp(argv[i], "--reason")) {
      if (++i >= argc || strlen(argv[i]) > 63)
        return RC_INVALID_ARGS;
      reason = argv[i];
    } else if (!strcmp(argv[i], "-B") || !strcmp(argv[i], "--blackhole")) {
      if (++i >= argc || !hex_decode(argv[i], add, 16))
        return RC_INVALID_ARGS;
      do_add = 1;
    } else if (!strcmp(argv[i], "-U") || !strcmp(argv[i], "--unblackhole")) {
      if (++i >= argc || !hex_decode(argv[i], remove_hash, 16))
        return RC_INVALID_ARGS;
      do_remove = 1;
    } else if (argv[i][0] != '-' && !have_hash) {
      if (!hex_decode(argv[i], hash, 16)) {
        fprintf(stderr, "Destination hashes are 32 hexadecimal characters\n");
        return RC_INVALID_ARGS;
      }
      have_hash = 1;
    } else {
      fprintf(stderr, "Unknown option %s\n", argv[i]);
      return RC_INVALID_ARGS;
    }
  }
  if (!table && !list && !have_hash && !do_add && !do_remove && !rates && !drop_queues) {
    fprintf(stderr, "Specify a destination hash, -t, -r, -b, -B, -U or -D\n");
    return RC_INVALID_ARGS;
  }
  if ((drop || drop_via) && !have_hash) {
    fprintf(stderr, "-d and -x need a destination hash\n");
    return RC_INVALID_ARGS;
  }
  if (!make_target(&c, &t))
    return RC_INVALID_ARGS;
  if (drop_queues) {
    if (!send_drop(&t, "announce_queues", NULL, &r))
      return RC_UNKNOWN_ERROR;
    reply_free(&r);
    puts("Dropped the queued announces");
  }
  if (drop) {
    int dropped;
    if (!send_drop(&t, "path", hash, &r))
      return RC_UNKNOWN_ERROR;
    dropped = r.root.type == V_BOOL && r.root.u;
    reply_free(&r);
    if (dropped) {
      fputs("Dropped path to ", stdout);
      print_hash(hash);
      putchar('\n');
    } else {
      fputs("No path to drop for ", stdout);
      print_hash(hash);
      putchar('\n');
      return 1;
    }
    return RC_OK;
  }
  if (drop_via) {
    unsigned long long count;
    if (!send_drop(&t, "all_via", hash, &r))
      return RC_UNKNOWN_ERROR;
    count = as_uint(&r.root);
    reply_free(&r);
    printf("Dropped %llu path%s via ", count, count == 1 ? "" : "s");
    print_hash(hash);
    putchar('\n');
    return RC_OK;
  }
  if (rates) {
    if (!get_request(&t, "rate_table", NULL, 0, &r))
      return RC_UNKNOWN_ERROR;
    if (json) {
      json_value(&r.root);
      putchar('\n');
    } else if (r.root.type != V_ARR || !r.root.n)
      puts("No announce rate information");
    else
      for (k = 0; k < r.root.n; ++k) {
        const val *e = &r.root.kids[k], *h = map_get(e, "hash");
        char when[48];
        if (have_hash && (!h || h->type != V_BIN || h->n != 16 || memcmp(h->p, hash, 16)))
          continue;
        print_hex(h);
        pretty_time(as_double(map_get(e, "last")), when, sizeof(when));
        printf(" last announce %s, %llu rate violation%s", when,
               (unsigned long long)as_uint(map_get(e, "rate_violations")),
               as_uint(map_get(e, "rate_violations")) == 1 ? "" : "s");
        if (as_double(map_get(e, "blocked_until")) > 0) {
          pretty_time(as_double(map_get(e, "blocked_until")), when, sizeof(when));
          printf(", blocked until %s", when);
        }
        putchar('\n');
      }
    reply_free(&r);
    if (!table && !(have_hash && !rates) && !list && !do_add && !do_remove)
      return RC_OK;
  }
  if (do_add) {
    uint64_t until = hours ? (uint64_t)time(NULL) + hours * 3600u : 0;
    if (!send_command(&t, "blackhole_identity", add, until, reason))
      return RC_UNKNOWN_ERROR;
    printf("Blackholed identity ");
    for (k = 0; k < 16; ++k)
      printf("%02x", add[k]);
    putchar('\n');
  }
  if (do_remove) {
    if (!send_command(&t, "unblackhole_identity", remove_hash, 0, NULL))
      return RC_UNKNOWN_ERROR;
    printf("Lifted blackhole for identity ");
    for (k = 0; k < 16; ++k)
      printf("%02x", remove_hash[k]);
    putchar('\n');
  }
  if (list) {
    if (!get_request(&t, "blackholed_identities", NULL, 0, &r))
      return RC_UNKNOWN_ERROR;
    if (json) {
      json_value(&r.root);
      putchar('\n');
    } else if (r.root.type != V_MAP || !r.root.n)
      puts("No identities are blackholed");
    else
      for (k = 0; k < r.root.n; ++k) {
        const val *e = &r.root.kids[2 * k + 1];
        const val *until = map_get(e, "until"), *why = map_get(e, "reason");
        print_hex(&r.root.kids[2 * k]);
        if (until && until->type != V_NIL) {
          char when[48];
          pretty_time(as_double(until), when, sizeof(when));
          printf(" until %s", when);
        } else
          fputs(" indefinitely", stdout);
        if (why && why->type == V_STR) {
          fputs(" (", stdout);
          print_str(why, "");
          putchar(')');
        }
        putchar('\n');
      }
    reply_free(&r);
  }
  if (have_hash && !table && !list && !do_add && !do_remove && !json && !remote.hash) {
    /* the reference's lookup: a known path is reported, an unknown one is requested and waited for */
    unsigned long long deadline = now_ms() + (unsigned long long)((remote.wait > 0 ? remote.wait : timeout) * 1000.0);
    int requested = 0;
    for (;;) {
      const val *e;
      if (!get_request(&t, "path_table", NULL, 0, &r))
        return RC_UNKNOWN_ERROR;
      e = find_path(&r, hash);
      if (e) {
        uint64_t hops = as_uint(map_get(e, "hops"));
        if (requested)
          fputs("\r", stdout);
        fputs("Path found, destination ", stdout);
        print_hash(hash);
        printf(" is %llu hop%s away via ", (unsigned long long)hops, hops == 1 ? "" : "s");
        print_hex(map_get(e, "via"));
        fputs(" on ", stdout);
        print_str(map_get(e, "interface"), "?");
        putchar('\n');
        reply_free(&r);
        return RC_OK;
      }
      reply_free(&r);
      if (!requested) {
        if (!send_path_request(&t, hash)) {
          fprintf(stderr, "Could not send the path request to the shared instance\n");
          return RC_UNKNOWN_ERROR;
        }
        fputs("Path to ", stdout);
        print_hash(hash);
        fputs(" requested  \n", stdout);
        requested = 1;
      }
      if (now_ms() >= deadline) {
        puts("Path not found");
        return 1;
      }
      {
        struct timespec pause = {0, 100000000L};
        nanosleep(&pause, NULL);
      }
    }
  }
  if (table || have_hash) {
    int shown = 0;
    if (!get_request(&t, "path_table", NULL, max_hops, &r))
      return RC_UNKNOWN_ERROR;
    if (r.root.type != V_ARR) {
      reply_free(&r);
      return RC_UNKNOWN_ERROR;
    }
    if (json)
      putchar('[');
    for (k = 0; k < r.root.n; ++k) {
      const val *e = &r.root.kids[k], *h = map_get(e, "hash");
      if (have_hash && (!h || h->type != V_BIN || h->n != 16 || memcmp(h->p, hash, 16)))
        continue;
      if (json) {
        if (shown)
          fputs(", ", stdout);
        json_value(e);
      } else
        print_path(e);
      ++shown;
    }
    if (json)
      puts("]");
    else if (!shown && have_hash) {
      printf("No path known for ");
      for (k = 0; k < 16; ++k)
        printf("%02x", hash[k]);
      putchar('\n');
    } else if (!shown)
      puts("No paths known");
    if (!shown && have_hash)
      rc = 1;
    reply_free(&r);
  }
  return rc;
}


/* ---- discovered interfaces (rnstatus -d / -D) ---------------------------- */
/* The reference lists the records InterfaceDiscovery keeps, one msgpack file per interface, in
 * <storage>/discovery/interfaces; this daemon keeps them in the same format (its discovery_storage, or the
 * configuration directory's storage when started from one). */
static int read_file(const char *path, uint8_t **data, size_t *size);
static void py_float_repr(double v, char *out, size_t cap);
#define DISC_MAX 256
typedef struct disc_record {
  uint8_t *data;
  val *pool;
  val root;
  double heard, discovered;
  int status; /* 2 available, 1 unknown, 0 stale (the reference's STATUS_CODE_MAP) */
  uint64_t value;
  char name[256];
} disc_record;
static void disc_free(disc_record *r) {
  free(r->data);
  free(r->pool);
}
/* InterfaceAnnounceHandler.sanitize_name: ASCII only, runs of spaces folded, alphanumeric at the start and
 * alphanumeric or ")" at the end */
static void disc_name(const val *v, char *out, size_t cap) {
  char tmp[256];
  size_t n = 0, i, start = 0, end;
  int k;
  if (!v || v->type != V_STR) {
    out[0] = 0;
    return;
  }
  for (i = 0; i < v->n && n < sizeof(tmp) - 1; ++i)
    if (v->p[i] < 128)
      tmp[n++] = (char)v->p[i];
  tmp[n] = 0;
  while (n && isspace((unsigned char)tmp[n - 1]))
    tmp[--n] = 0;
  while (start < n && isspace((unsigned char)tmp[start]))
    ++start;
  memmove(tmp, tmp + start, n - start + 1);
  n -= start;
  for (k = 0; k < 3; ++k) {
    static const char *runs[] = {"     ", "   ", "  "};
    char *at;
    size_t len = strlen(runs[k]);
    while ((at = strstr(tmp, runs[k])) != NULL) {
      memmove(at + 1, at + len, strlen(at + len) + 1);
    }
  }
  n = strlen(tmp);
  for (start = 0; start < n && !isalnum((unsigned char)tmp[start]); ++start) {
  }
  memmove(tmp, tmp + start, n - start + 1);
  n -= start;
  for (end = n; end && !isalnum((unsigned char)tmp[end - 1]) && tmp[end - 1] != ')'; --end) {
  }
  tmp[end] = 0;
  (void)snprintf(out, cap, "%s", tmp);
}
static int disc_type_ok(const val *t) {
  static const char *types[] = {"BackboneInterface", "TCPServerInterface", "I2PInterface",
                                "RNodeInterface", "WeaveInterface", "KISSInterface"};
  size_t k;
  if (!t || t->type != V_STR)
    return 0;
  for (k = 0; k < sizeof(types) / sizeof(*types); ++k)
    if (t->n == strlen(types[k]) && !memcmp(t->p, types[k], t->n))
      return 1;
  return 0;
}
/* an IP address or a host name, as the reference's is_ip_address / is_hostname decide it */
static int disc_host_ok(const val *v) {
  char text[256];
  struct in_addr a4;
  struct in6_addr a6;
  size_t i, label = 0;
  if (!v || v->type != V_STR || !v->n || v->n >= sizeof(text))
    return 0;
  memcpy(text, v->p, v->n);
  text[v->n] = 0;
  if (inet_pton(AF_INET, text, &a4) == 1 || inet_pton(AF_INET6, text, &a6) == 1)
    return 1;
  if (v->n > 253)
    return 0;
  for (i = 0; i <= v->n; ++i) {
    if (i == v->n || text[i] == '.') {
      if (!label || label > 63 || text[i - label] == '-' || text[i - 1] == '-')
        return 0;
      label = 0;
    } else if (isalnum((unsigned char)text[i]) || text[i] == '-')
      ++label;
    else
      return 0;
  }
  return 1;
}
static int disc_load(const char *dir, disc_record *list, size_t *count, double now, const char *filter) {
  DIR *d = opendir(dir);
  struct dirent *entry;
  *count = 0;
  if (!d)
    return 0;
  while ((entry = readdir(d)) != NULL && *count < DISC_MAX) {
    char path[1400];
    disc_record rec;
    uint8_t *data;
    size_t size;
    reader rd;
    const val *v;
    double heard_delta;
    char lower_name[256], lower_filter[256];
    size_t k;
    if (entry->d_name[0] == '.')
      continue;
    if (snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name) >= (int)sizeof(path) || !read_file(path, &data, &size))
      continue;
    memset(&rec, 0, sizeof(rec));
    rec.data = data;
    rec.pool = calloc(POOL, sizeof(val));
    rd.p = data;
    rd.end = data + size;
    rd.pool = rec.pool;
    rd.used = 0;
    rd.cap = POOL;
    if (!rec.pool || !parse(&rd, &rec.root, 0) || rec.root.type != V_MAP) {
      disc_free(&rec);
      continue;
    }
    v = map_get(&rec.root, "last_heard");
    if (!v) {
      disc_free(&rec);
      continue;
    }
    rec.heard = as_double(v);
    rec.discovered = as_double(map_get(&rec.root, "discovered"));
    rec.value = as_uint(map_get(&rec.root, "value"));
    disc_name(map_get(&rec.root, "name"), rec.name, sizeof(rec.name));
    heard_delta = now - rec.heard;
    {
      const val *tid = map_get(&rec.root, "transport_id"), *nid = map_get(&rec.root, "network_id");
      const val *reach = map_get(&rec.root, "reachable_on");
      int drop = heard_delta > 7 * 86400.0 || !tid || tid->type != V_STR || !tid->n || !nid || nid->type != V_STR ||
                 !nid->n || !disc_type_ok(map_get(&rec.root, "type")) || (reach && !disc_host_ok(reach));
      if (drop) {
        disc_free(&rec);
        continue;
      }
    }
    rec.status = heard_delta > 3 * 86400.0 ? 0 : heard_delta > 86400.0 ? 1 : 2;
    if (filter && *filter) {
      for (k = 0; rec.name[k] && k < sizeof(lower_name) - 1; ++k)
        lower_name[k] = (char)tolower((unsigned char)rec.name[k]);
      lower_name[k] = 0;
      for (k = 0; filter[k] && k < sizeof(lower_filter) - 1; ++k)
        lower_filter[k] = (char)tolower((unsigned char)filter[k]);
      lower_filter[k] = 0;
      if (!strstr(lower_name, lower_filter)) {
        disc_free(&rec);
        continue;
      }
    }
    list[(*count)++] = rec;
  }
  closedir(d);
  /* (status, value, last heard), largest first */
  for (size_t a = 1; a < *count; ++a) {
    disc_record cur = list[a];
    size_t b = a;
    while (b > 0) {
      const disc_record *o = &list[b - 1];
      int before = o->status != cur.status ? o->status > cur.status
                   : o->value != cur.value ? o->value > cur.value
                                           : o->heard >= cur.heard;
      if (before)
        break;
      list[b] = list[b - 1];
      --b;
    }
    list[b] = cur;
  }
  return 1;
}
/* RNS.prettytime(t, compact=True) */
static void disc_pretty(double seconds, char *out, size_t cap) {
  unsigned long long t = (unsigned long long)(seconds < 0 ? -seconds : seconds);
  unsigned long long parts[4] = {t / 86400, (t % 86400) / 3600, (t % 3600) / 60, t % 60};
  static const char unit[4] = {'d', 'h', 'm', 's'};
  char comp[2][32];
  int shown = 0, k;
  for (k = 0; k < 4 && shown < 2; ++k)
    if (parts[k] > 0)
      (void)snprintf(comp[shown++], sizeof(comp[0]), "%llu%c", parts[k], unit[k]);
  if (!shown)
    (void)snprintf(out, cap, "0s");
  else if (shown == 1)
    (void)snprintf(out, cap, "%s", comp[0]);
  else
    (void)snprintf(out, cap, "%s and %s", comp[0], comp[1]);
}
static size_t utf8_len(const char *s) {
  size_t n = 0;
  for (; *s; ++s)
    if (((unsigned char)*s & 0xc0) != 0x80)
      ++n;
  return n;
}
static void print_padded(const char *s, size_t width) {
  size_t n = utf8_len(s);
  fputs(s, stdout);
  for (; n < width; ++n)
    putchar(' ');
}
static void disc_str(const val *v, char *out, size_t cap) {
  size_t n;
  if (!v || v->type != V_STR) {
    out[0] = 0;
    return;
  }
  n = v->n < cap - 1 ? v->n : cap - 1;
  memcpy(out, v->p, n);
  out[n] = 0;
}
static void disc_thousands(uint64_t v, char *out, size_t cap) {
  char raw[32];
  size_t n, i, o = 0;
  (void)snprintf(raw, sizeof(raw), "%llu", (unsigned long long)v);
  n = strlen(raw);
  for (i = 0; i < n && o + 2 < cap; ++i) {
    if (i && (n - i) % 3 == 0)
      out[o++] = ',';
    out[o++] = raw[i];
  }
  out[o] = 0;
}
/* a latitude, longitude or height as Python prints round(x, 4) */
static void disc_coordinate(const val *v, int digits, char *out, size_t cap) {
  char tmp[48];
  if (v->type == V_INT || v->type == V_UINT) {
    (void)snprintf(out, cap, "%lld", v->type == V_INT ? (long long)v->i : (long long)v->u);
    return;
  }
  (void)snprintf(tmp, sizeof(tmp), "%.*f", digits, as_double(v));
  py_float_repr(strtod(tmp, NULL), out, cap);
}
static int disc_has_number(const val *v) {
  return v && (v->type == V_INT || v->type == V_UINT || v->type == V_REAL);
}
static int discovered_listing(const char *dir, const char *filter, int details, int json, int show_stale,
                              int show_unknown) {
  static disc_record list[DISC_MAX];
  size_t count, k, shown = 0;
  struct timespec ts;
  double now;
  clock_gettime(CLOCK_REALTIME, &ts);
  now = (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
  if (!disc_load(dir, list, &count, now, json ? NULL : filter)) {
    fprintf(stderr, "Could not read the discovered interfaces in %s\n", dir);
    return RC_UNKNOWN_ERROR;
  }
  putchar('\n');
  if (json) {
    putchar('[');
    for (k = 0; k < count; ++k) {
      if (k)
        fputs(", ", stdout);
      json_value(&list[k].root);
    }
    puts("]");
    for (k = 0; k < count; ++k)
      disc_free(&list[k]);
    return RC_OK;
  }
  if (!details) {
    printf("%-25s %-10s   %-10s %-12s %-7s %-16s %-15s\n", "Name", "Type", "Status", "Last Heard", "Value", "Running",
           "Location");
    for (k = 0; k < 110; ++k)
      putchar('-');
    putchar('\n');
  }
  for (k = 0; k < count; ++k) {
    const val *r = &list[k].root, *impl = map_get(r, "impl_name"), *ver = map_get(r, "version");
    const val *lat = map_get(r, "latitude"), *lon = map_get(r, "longitude"), *height = map_get(r, "height");
    char impl_str[200], type[64], name[270], status[24], location[400], tmp[128], tmp2[128];
    int has_impl = impl && ver && impl->type == V_STR && impl->n && ver->type == V_STR && ver->n;
    int have_location = disc_has_number(lat) && disc_has_number(lon);
    if (has_impl) {
      char a[80], b[80];
      disc_str(impl, a, sizeof(a));
      disc_str(ver, b, sizeof(b));
      (void)snprintf(impl_str, sizeof(impl_str), "%s %s", a, b);
    } else
      (void)snprintf(impl_str, sizeof(impl_str), "Unknown");
    if ((list[k].status == 0 && !show_stale) || (!has_impl && !show_unknown))
      continue;
    if (details) {
      double heard_ago = now - list[k].heard, found_ago = now - list[k].discovered;
      char disc_text[160], heard_text[160], addr[256];
      const val *tid = map_get(r, "transport_id"), *nid = map_get(r, "network_id"), *lx = map_get(r, "operator_lxmf_address");
      const val *hops = map_get(r, "hops"), *tr = map_get(r, "transport"), *cfg = map_get(r, "config_entry");
      const val *f;
      char line[256], num[48];
      disc_pretty(found_ago, tmp, sizeof(tmp));
      (void)snprintf(disc_text, sizeof(disc_text), "%s ago", tmp);
      disc_pretty(heard_ago, tmp, sizeof(tmp));
      (void)snprintf(heard_text, sizeof(heard_text), "%s ago", tmp);
      if (have_location) {
        disc_coordinate(lat, 4, tmp, sizeof(tmp));
        disc_coordinate(lon, 4, tmp2, sizeof(tmp2));
        if (disc_has_number(height)) {
          char h[128];
          disc_coordinate(height, 4, h, sizeof(h));
          (void)snprintf(location, sizeof(location), "%s, %s, %sm h", tmp, tmp2, h);
        } else
          (void)snprintf(location, sizeof(location), "%s, %s", tmp, tmp2);
      } else
        (void)snprintf(location, sizeof(location), "Unknown");
      if (shown++)
        printf("\n===============================================\n\n");
      if (tid && nid && tid->type == V_STR && nid->type == V_STR && (tid->n != nid->n || memcmp(tid->p, nid->p, tid->n))) {
        disc_str(nid, line, sizeof(line));
        printf("Network   ID : %s\n", line);
      }
      if (tid && tid->type == V_STR && tid->n) {
        disc_str(tid, line, sizeof(line));
        printf("Transport ID : %s\n", line);
      }
      if (lx && lx->type == V_STR && lx->n) {
        disc_str(lx, line, sizeof(line));
        printf("LXMF address : %s\n", line);
      }
      disc_str(map_get(r, "type"), type, sizeof(type));
      printf("Name         : %s\nType         : %s\nStack        : %s\n", list[k].name, type, impl_str);
      printf("Status       : %s\n", list[k].status == 2 ? "Available" : list[k].status == 1 ? "Unknown" : "Stale");
      printf("Transport    : %s\n", tr && tr->type == V_BOOL && tr->u ? "Enabled" : "Disabled");
      printf("Stamp Value  : %.3f\n", (double)list[k].value); /* after Transport since RNS 1.6 */
      printf("Distance     : %llu hop%s\n", (unsigned long long)as_uint(hops), as_uint(hops) == 1 ? "" : "s");
      printf("Discovered   : %s\nLast Heard   : %s\nLocation     : %s\n", disc_text, heard_text, location);
      if ((f = map_get(r, "frequency")) != NULL) {
        disc_thousands(as_uint(f), num, sizeof(num));
        printf("Frequency    : %s Hz\n", num);
      }
      if ((f = map_get(r, "bandwidth")) != NULL) {
        disc_thousands(as_uint(f), num, sizeof(num));
        printf("Bandwidth    : %s Hz\n", num);
      }
      if ((f = map_get(r, "sf")) != NULL)
        printf("Sprd. Factor : %llu\n", (unsigned long long)as_uint(f));
      if ((f = map_get(r, "cr")) != NULL)
        printf("Coding Rate  : %llu\n", (unsigned long long)as_uint(f));
      if ((f = map_get(r, "modulation")) != NULL && f->type == V_STR) {
        disc_str(f, line, sizeof(line));
        printf("Modulation   : %s\n", line);
      } else if (f && f->type != V_NIL)
        printf("Modulation   : %llu\n", (unsigned long long)as_uint(f));
      if ((f = map_get(r, "reachable_on")) != NULL) {
        disc_str(f, addr, sizeof(addr));
        printf("Address      : %s\n", addr);
      }
      if ((f = map_get(r, "port")) != NULL)
        printf("Port         : %llu\n", (unsigned long long)as_uint(f));
      printf("\nConfiguration Entry:\n");
      if (cfg && cfg->type == V_STR) {
        const char *at = (const char *)cfg->p, *end = at + cfg->n;
        while (at <= end) {
          const char *nl = memchr(at, '\n', (size_t)(end - at));
          size_t len = nl ? (size_t)(nl - at) : (size_t)(end - at);
          printf("  %.*s\n", (int)len, at);
          if (!nl)
            break;
          at = nl + 1;
        }
      }
    } else {
      double diff = now - list[k].heard;
      char heard_text[24], value_text[24], type_text[64];
      char *at;
      if (utf8_len(list[k].name) > 24) { /* the reference cuts at 24 characters and adds an ellipsis */
        size_t cut = 0, chars = 0;
        while (list[k].name[cut] && chars < 24) {
          ++cut;
          ++chars;
        }
        (void)snprintf(name, sizeof(name), "%.*s\xe2\x80\xa6", (int)cut, list[k].name);
      } else
        (void)snprintf(name, sizeof(name), "%s", list[k].name);
      if (utf8_len(impl_str) > 16) {
        size_t cut = 0, chars = 0; /* the first 15 characters, then an ellipsis */
        while (impl_str[cut] && chars < 15) {
          ++cut;
          while (((unsigned char)impl_str[cut] & 0xc0) == 0x80)
            ++cut;
          ++chars;
        }
        memcpy(impl_str + cut, "\xe2\x80\xa6", 4);
      }
      disc_str(map_get(r, "type"), type_text, sizeof(type_text));
      while ((at = strstr(type_text, "Interface")) != NULL)
        memmove(at, at + 9, strlen(at + 9) + 1);
      (void)snprintf(status, sizeof(status), "%s", list[k].status == 2 ? "\xe2\x9c\x93 Available"
                                                    : list[k].status == 1 ? "? Unknown" : "\xc3\x97 Stale");
      if (diff < 60)
        (void)snprintf(heard_text, sizeof(heard_text), "Just now");
      else if (diff < 3600)
        (void)snprintf(heard_text, sizeof(heard_text), "%dm ago", (int)(diff / 60));
      else if (diff < 86400)
        (void)snprintf(heard_text, sizeof(heard_text), "%dh ago", (int)(diff / 3600));
      else
        (void)snprintf(heard_text, sizeof(heard_text), "%dd ago", (int)(diff / 86400));
      (void)snprintf(value_text, sizeof(value_text), "%.3f", (double)list[k].value); /* RNS.prettycost, three decimals since 1.6 */
      if (have_location) {
        disc_coordinate(lat, 4, tmp, sizeof(tmp));
        disc_coordinate(lon, 4, tmp2, sizeof(tmp2));
        (void)snprintf(location, sizeof(location), "%s, %s", tmp, tmp2);
      } else
        (void)snprintf(location, sizeof(location), "N/A");
      print_padded(name, 25);
      putchar(' ');
      print_padded(type_text, 10);
      putchar(' ');
      print_padded(status, 12);
      putchar(' ');
      print_padded(heard_text, 12);
      putchar(' ');
      print_padded(value_text, 7);
      putchar(' ');
      print_padded(impl_str, 16);
      putchar(' ');
      print_padded(location, 15);
      putchar('\n');
      ++shown;
    }
  }
  for (k = 0; k < count; ++k)
    disc_free(&list[k]);
  return RC_OK;
}

/* ---- id ----------------------------------------------------------------- */
static int file_exists(const char *path) {
  struct stat st;
  return !stat(path, &st);
}
static int read_file(const char *path, uint8_t **data, size_t *size) {
  FILE *f = fopen(path, "rb");
  long n;
  if (!f)
    return 0;
  if (fseek(f, 0, SEEK_END) || (n = ftell(f)) < 0 || fseek(f, 0, SEEK_SET)) {
    fclose(f);
    return 0;
  }
  *data = malloc((size_t)n ? (size_t)n : 1);
  if (!*data || fread(*data, 1, (size_t)n, f) != (size_t)n) {
    free(*data);
    fclose(f);
    return 0;
  }
  fclose(f);
  *size = (size_t)n;
  return 1;
}
static int write_private_file(const char *path, const uint8_t *data, size_t size,
                              int force) {
  int fd = open(path, O_WRONLY | O_CREAT | (force ? O_TRUNC : O_EXCL), 0600);
  int ok;
  if (fd < 0)
    return errno == EEXIST ? RC_FILE_EXISTS : RC_WRITE_ERROR;
  ok = write_all(fd, data, size);
  close(fd);
  return ok ? RC_OK : RC_WRITE_ERROR;
}
/* Text forms of a key, as rnid writes them: hex, base32 (RFC 4648 with padding) or URL-safe base64. */
enum { FORMAT_HEX, FORMAT_B32, FORMAT_B64, FORMAT_B256 };
static void encode_bits(const uint8_t *in, size_t n, const char *alphabet, unsigned bits, char *out) {
  unsigned long acc = 0;
  unsigned have = 0, group = bits == 5 ? 8u : 4u; /* characters per padded group */
  size_t o = 0, chars = 0;
  size_t i;
  for (i = 0; i < n; ++i) {
    acc = (acc << 8) | in[i];
    have += 8;
    while (have >= bits) {
      out[o++] = alphabet[(acc >> (have - bits)) & ((1u << bits) - 1u)];
      have -= bits;
      ++chars;
    }
  }
  if (have) {
    out[o++] = alphabet[(acc << (bits - have)) & ((1u << bits) - 1u)];
    ++chars;
  }
  while (chars % group) {
    out[o++] = '=';
    ++chars;
  }
  out[o] = 0;
}
/* rnid prints keys in hex, base32 and base64 only; -U changes nothing about them */
static void encode_key(int format, const uint8_t *key, size_t n, char *out) {
  if (format == FORMAT_B32)
    encode_bits(key, n, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 5, out);
  else if (format == FORMAT_B64)
    encode_bits(key, n, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", 6, out);
  else
    hex_encode(key, n, out);
}
/* Decodes padded base32 or base64 text to exactly `want` bytes; 0 on any other input. */
static int decode_bits(const char *text, const char *alphabet, unsigned bits, uint8_t *out, size_t want) {
  unsigned long acc = 0;
  unsigned have = 0, group = bits == 5 ? 8u : 4u;
  size_t o = 0, chars = 0, len = strlen(text);
  size_t i;
  for (i = 0; i < len && text[i] != '='; ++i) {
    const char *at = strchr(alphabet, text[i]);
    if (!at || !text[i])
      return 0;
    acc = (acc << bits) | (unsigned long)(at - alphabet);
    have += bits;
    ++chars;
    if (have >= 8) {
      if (o >= want)
        return 0;
      out[o++] = (uint8_t)(acc >> (have - 8));
      have -= 8;
    }
  }
  for (; i < len; ++i, ++chars)
    if (text[i] != '=')
      return 0;
  return chars % group == 0 && o == want;
}
/* rnid -m and -M: an identity given as a file, hex, base32 or base64. */
static int import_identity(const char *text, int is_private, rnc_identity *id, const char **how) {
  uint8_t key[64];
  const size_t want = 64u; /* a private and a public identity are both 64 bytes of key */
  size_t n = 0;
  uint8_t *data;
  if (read_file(text, &data, &n)) {
    int ok = n == want;
    if (ok)
      memcpy(key, data, 64);
    free(data);
    if (ok) {
      *how = "file";
      goto built;
    }
  }
  if (strlen(text) == want * 2 && hex_decode(text, key, want)) {
    *how = "hex";
    goto built;
  }
  if (decode_bits(text, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 5, key, want)) {
    *how = "base32";
    goto built;
  }
  if (decode_bits(text, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", 6, key, want)) {
    *how = "base64";
    goto built;
  }
  return 0;
built:
  return (is_private ? rnc_identity_from_private(id, key) : rnc_identity_from_public(id, key)) == RNC_OK;
}
static void print_identity(const rnc_identity *id, int show_private, int format) {
  char hex[129];
  encode_key(format, id->public_key, 64, hex);
  printf("Public Key    : %s\n", hex);
  if (id->has_private && show_private) {
    encode_key(format, id->private_key, 64, hex);
    printf("Private Key   : %s\n", hex);
  } else
    printf("Private Key   : %s\n", id->has_private ? "Hidden" : "Not available");
}
/* Streams a file through chunked identity encryption, as rnid does, so the
 * outputs interoperate with the reference. */
static int crypt_file(const rnc_identity *id, const char *in_path,
                      const char *out_path, int force, int encrypt) {
  FILE *in = fopen(in_path, "rb"), *out;
  size_t chunk = encrypt ? ENC_CHUNK : DEC_CHUNK, got, wrote, total = 0;
  uint8_t *buf = malloc(chunk), *res = malloc(DEC_CHUNK + 128u);
  int rc = RC_OK, fd;
  if (!in || !buf || !res) {
    rc = in ? RC_UNKNOWN_ERROR : RC_NO_FILE;
    goto done;
  }
  fd = open(out_path, O_WRONLY | O_CREAT | (force ? O_TRUNC : O_EXCL), 0600);
  if (fd < 0) {
    rc = errno == EEXIST ? RC_FILE_EXISTS : RC_WRITE_ERROR;
    goto done;
  }
  out = fdopen(fd, "wb");
  if (!out) {
    close(fd);
    rc = RC_WRITE_ERROR;
    goto done;
  }
  while ((got = fread(buf, 1, chunk, in)) > 0) {
    rnc_result r =
        encrypt ? rnc_identity_encrypt(id, buf, got, random_bytes, NULL, res,
                                       DEC_CHUNK + 128u, &wrote)
                : rnc_identity_decrypt(id, buf, got, res, DEC_CHUNK + 128u,
                                       &wrote);
    if (r != RNC_OK) {
      rc = encrypt ? RC_UNKNOWN_ERROR : RC_DECRYPT_FAILED;
      break;
    }
    if (fwrite(res, 1, wrote, out) != wrote) {
      rc = RC_WRITE_ERROR;
      break;
    }
    total += wrote;
  }
  if (fclose(out) && rc == RC_OK)
    rc = RC_WRITE_ERROR;
  if (rc != RC_OK)
    unlink(out_path);
  else
    printf("%s %s to %s (%zu bytes)\n", in_path,
           encrypt ? "encrypted" : "decrypted", out_path, total);
done:
  if (in)
    fclose(in);
  free(buf);
  free(res);
  return rc;
}
static int ends_with(const char *s, const char *suffix) {
  size_t n = strlen(s), m = strlen(suffix);
  return n >= m && !strcmp(s + n - m, suffix);
}
/* ---- signature envelopes (.rsg) -------------------------------------------
 * The reference's non-raw signature: Ed25519 over a MessagePack envelope, written as signature || envelope.
 * The envelope is {"hashtype": "sha256", "hash": SHA-256 of the file, "meta": {"signer": identity hash,
 * "pubkey": 64 byte public key}} in that key order, so the bytes match what the reference signs. */
/* `message` (NULL for a plain file signature) is embedded after "meta" as a binary value, which is what
 * makes a .rsm: the reference adds it to the dict last, so it is also last on the wire. */
/* `meta` (NULL for none) adds its entries to the "meta" map after "signer" and "pubkey", skipping those two names,
 * in ConfigObj's order (plain values, then subsections). */
/* Nodes available when an envelope is read back: its metadata can have a few hundred entries. */
#define RSG_POOL 2048u
/* The whole envelope has to fit one RPC writer message (64 KiB), so a signed message and its metadata share that. */
#define RSG_MAX_MESSAGE 60000u
static int rsg_create(const rnc_identity *id, const uint8_t hash[32], const uint8_t *message, size_t message_size,
                      const mv *meta, uint8_t *out, size_t cap, size_t *size) {
  size_t room = RNC_RPC_MESSAGE_MAX;
  uint8_t *envelope = malloc(room);
  rnc_rpc_writer w;
  size_t n;
  int ok = 0;
  if (!envelope)
    return 0;
  rnc_rpc_writer_init(&w, envelope, room);
  if (rnc_rpc_write_map(&w, message ? 4 : 3) == RNC_OK && rnc_rpc_write_string(&w, "hashtype") == RNC_OK &&
      rnc_rpc_write_string(&w, "sha256") == RNC_OK && rnc_rpc_write_string(&w, "hash") == RNC_OK &&
      rnc_rpc_write_bin(&w, hash, 32) == RNC_OK && rnc_rpc_write_string(&w, "meta") == RNC_OK &&
      rnc_rpc_write_map(&w, 2 + (meta ? mv_visible(meta, "signer", "pubkey") : 0)) == RNC_OK &&
      rnc_rpc_write_string(&w, "signer") == RNC_OK &&
      rnc_rpc_write_bin(&w, id->hash, 16) == RNC_OK && rnc_rpc_write_string(&w, "pubkey") == RNC_OK &&
      rnc_rpc_write_bin(&w, id->public_key, 64) == RNC_OK &&
      (!meta || mv_pack_entries(&w, meta, "signer", "pubkey")) &&
      (!message || (rnc_rpc_write_string(&w, "message") == RNC_OK && rnc_rpc_write_bin(&w, message, message_size) == RNC_OK)) &&
      rnc_rpc_writer_finish(&w, &n) == RNC_OK && cap >= 64 + n && rnc_identity_sign(id, envelope, n, out) == RNC_OK) {
    memcpy(out + 64, envelope, n);
    *size = 64 + n;
    ok = 1;
  }
  free(envelope);
  return ok;
}
/* The message embedded in an envelope (points into rsg), or 0. */
static int rsg_message(const uint8_t *rsg, size_t size, const uint8_t **message, size_t *message_size) {
  static val pool[RSG_POOL];
  val root;
  reader rd;
  const val *m;
  if (size < 65)
    return 0;
  rd.p = rsg + 64;
  rd.end = rsg + size;
  rd.pool = pool;
  rd.used = 0;
  rd.cap = RSG_POOL;
  if (!parse(&rd, &root, 0) || rd.p != rd.end || root.type != V_MAP)
    return 0;
  m = map_get(&root, "message");
  if (!m || m->type != V_BIN)
    return 0;
  *message = m->p;
  *message_size = m->n;
  return 1;
}
/* 1 valid, 0 invalid or unreadable. `required` is the identity the signature must verify under (NULL: the
 * public key the envelope carries); *signer receives the identity that was used. */
static int rsg_validate(const uint8_t *rsg, size_t size, const uint8_t hash[32], const rnc_identity *required,
                        rnc_identity *signer) {
  static val pool[RSG_POOL];
  val root;
  reader rd;
  const val *hashtype, *sig_hash, *meta, *pubkey;
  if (size < 65)
    return 0;
  rd.p = rsg + 64;
  rd.end = rsg + size;
  rd.pool = pool;
  rd.used = 0;
  rd.cap = RSG_POOL;
  if (!parse(&rd, &root, 0) || rd.p != rd.end || root.type != V_MAP)
    return 0;
  hashtype = map_get(&root, "hashtype");
  sig_hash = map_get(&root, "hash");
  meta = map_get(&root, "meta");
  if (!hashtype || hashtype->type != V_STR || hashtype->n != 6 || memcmp(hashtype->p, "sha256", 6) || !sig_hash ||
      sig_hash->type != V_BIN || sig_hash->n != 32 || !meta || meta->type != V_MAP || !map_get(meta, "signer"))
    return 0;
  pubkey = map_get(meta, "pubkey");
  if (!pubkey || pubkey->type != V_BIN || pubkey->n != 64)
    return 0;
  if (required)
    *signer = *required;
  else if (rnc_identity_from_public(signer, pubkey->p) != RNC_OK)
    return 0;
  if (memcmp(sig_hash->p, hash, 32))
    return 0;
  return rnc_identity_verify(signer, rsg + 64, size - 64, rsg) == RNC_OK;
}
/* ---- showing a message's metadata (rnid --meta) -------------------------------
 * The reference prints every entry as <type letter><indent><key>=<value>, values cut into 64 character rows,
 * the value as Python would format it (str() of a list is its repr). */
static void py_repr_string(const uint8_t *s, size_t n, char *out, size_t *o, size_t cap, int bytes) {
  char quote = '\'';
  size_t i;
  if (memchr(s, '\'', n) && !memchr(s, '"', n))
    quote = '"';
  if (bytes && *o < cap)
    out[(*o)++] = 'b';
  if (*o < cap)
    out[(*o)++] = quote;
  for (i = 0; i < n && *o + 5 < cap; ++i) {
    unsigned char c = s[i];
    if (c == (unsigned char)quote || c == '\\') {
      out[(*o)++] = '\\';
      out[(*o)++] = (char)c;
    } else if (c == '\n') {
      out[(*o)++] = '\\';
      out[(*o)++] = 'n';
    } else if (c == '\r') {
      out[(*o)++] = '\\';
      out[(*o)++] = 'r';
    } else if (c == '\t') {
      out[(*o)++] = '\\';
      out[(*o)++] = 't';
    } else if (c < 0x20 || c == 0x7f || (bytes && c >= 0x80)) {
      *o += (size_t)snprintf(out + *o, cap - *o, "\\x%02x", c);
    } else
      out[(*o)++] = (char)c;
  }
  if (*o < cap)
    out[(*o)++] = quote;
}
/* Python's repr() of a float: the shortest digits that read back the same, positional for exponents -4..15. */
static void py_float_repr(double v, char *out, size_t cap) {
  char digits[32], tmp[48];
  int p, exp10, decpt, nd, k;
  if (v != v) {
    (void)snprintf(out, cap, "nan");
    return;
  }
  if (v > 1.7976931348623157e308 || v < -1.7976931348623157e308) {
    (void)snprintf(out, cap, v < 0 ? "-inf" : "inf");
    return;
  }
  if (v == 0) {
    (void)snprintf(out, cap, signbit(v) ? "-0.0" : "0.0");
    return;
  }
  for (p = 1; p <= 17; ++p) {
    (void)snprintf(tmp, sizeof(tmp), "%.*e", p - 1, v);
    if (strtod(tmp, NULL) == v)
      break;
  }
  {
    const char *e = strchr(tmp, 'e');
    char *d = digits;
    const char *s = tmp + (tmp[0] == '-');
    for (; s < e; ++s)
      if (*s != '.')
        *d++ = *s;
    *d = 0;
    exp10 = atoi(e + 1);
  }
  nd = (int)strlen(digits);
  while (nd > 1 && digits[nd - 1] == '0')
    digits[--nd] = 0;
  decpt = exp10 + 1;
  {
    char *o = out;
    size_t left = cap;
    int w;
    if (v < 0) {
      *o++ = '-';
      --left;
    }
    if (exp10 < -4 || exp10 >= 16) {
      w = snprintf(o, left, "%c%s%.*s%se%c%02d", digits[0], nd > 1 ? "." : "", nd > 1 ? nd - 1 : 0, digits + 1, "",
                   exp10 < 0 ? '-' : '+', abs(exp10));
    } else if (decpt <= 0) {
      w = snprintf(o, left, "0.");
      for (k = 0; k < -decpt && w + 1 < (int)left; ++k)
        o[w++] = '0';
      (void)snprintf(o + w, left - (size_t)w, "%s", digits);
    } else if (decpt >= nd) {
      w = snprintf(o, left, "%s", digits);
      for (k = nd; k < decpt && w + 3 < (int)left; ++k)
        o[w++] = '0';
      (void)snprintf(o + w, left - (size_t)w, ".0");
    } else
      (void)snprintf(o, left, "%.*s.%s", decpt, digits, digits + decpt);
  }
}
/* repr() of a decoded value, for elements of lists and dicts. */
static void py_repr(const val *v, char *out, size_t *o, size_t cap) {
  size_t i;
  char num[48];
  switch (v->type) {
  case V_NIL:
    *o += (size_t)snprintf(out + *o, cap - *o, "None");
    break;
  case V_BOOL:
    *o += (size_t)snprintf(out + *o, cap - *o, v->u ? "True" : "False");
    break;
  case V_INT:
    *o += (size_t)snprintf(out + *o, cap - *o, "%lld", (long long)v->i);
    break;
  case V_UINT:
    *o += (size_t)snprintf(out + *o, cap - *o, "%llu", (unsigned long long)v->u);
    break;
  case V_REAL:
    py_float_repr(v->d, num, sizeof(num));
    *o += (size_t)snprintf(out + *o, cap - *o, "%s", num);
    break;
  case V_STR:
  case V_BIN:
    py_repr_string(v->p, v->n, out, o, cap, v->type == V_BIN);
    break;
  case V_ARR:
    if (*o < cap)
      out[(*o)++] = '[';
    for (i = 0; i < v->n; ++i) {
      if (i)
        *o += (size_t)snprintf(out + *o, cap - *o, ", ");
      py_repr(&v->kids[i], out, o, cap);
    }
    if (*o < cap)
      out[(*o)++] = ']';
    break;
  case V_MAP:
    if (*o < cap)
      out[(*o)++] = '{';
    for (i = 0; i < v->n; ++i) {
      if (i)
        *o += (size_t)snprintf(out + *o, cap - *o, ", ");
      py_repr(&v->kids[2 * i], out, o, cap);
      *o += (size_t)snprintf(out + *o, cap - *o, ": ");
      py_repr(&v->kids[2 * i + 1], out, o, cap);
    }
    if (*o < cap)
      out[(*o)++] = '}';
    break;
  }
  if (*o >= cap)
    *o = cap - 1;
  out[*o] = 0;
}
static size_t utf8_chars(const char *s, size_t n) {
  size_t c = 0, i;
  for (i = 0; i < n; ++i)
    c += ((unsigned char)s[i] & 0xc0) != 0x80;
  return c;
}
static void show_meta_entry(const val *entry, const uint8_t *key, size_t key_len, int level) {
  char indent[64], text[8192], lead[512];
  size_t o = 0, i, lead_chars;
  char etype = 'u';
  const char *t;
  size_t left;
  if (level > 30)
    return;
  memset(indent, ' ', (size_t)level * 2 < sizeof(indent) ? (size_t)level * 2 : sizeof(indent) - 1);
  indent[(size_t)level * 2 < sizeof(indent) ? (size_t)level * 2 : sizeof(indent) - 1] = 0;
  if (entry->type == V_MAP) {
    printf("d%s%.*s:\n", indent, (int)key_len, (const char *)key);
    for (i = 0; i < entry->n; ++i)
      if (entry->kids[2 * i].type == V_STR)
        show_meta_entry(&entry->kids[2 * i + 1], entry->kids[2 * i].p, entry->kids[2 * i].n, level + 1);
    return;
  }
  if (entry->type == V_NIL && key_len == 4 && !memcmp(key, "note", 4))
    return; /* the reference skips an empty "note" */
  switch (entry->type) {
  case V_STR:
    etype = 's';
    break;
  case V_BIN:
    etype = 'b';
    break;
  case V_ARR:
    etype = 'l';
    break;
  case V_INT:
  case V_UINT:
    etype = 'i';
    break;
  case V_REAL:
    etype = 'f';
    break;
  case V_NIL:
    etype = 'N';
    break;
  default:
    etype = 'u';
  }
  if (entry->type == V_BIN) { /* shown as hex */
    for (i = 0; i < entry->n && o + 3 < sizeof(text); ++i)
      o += (size_t)snprintf(text + o, sizeof(text) - o, "%02x", entry->p[i]);
    text[o] = 0;
  } else if (entry->type == V_STR) {
    o = entry->n < sizeof(text) - 1 ? entry->n : sizeof(text) - 1;
    memcpy(text, entry->p, o);
    text[o] = 0;
  } else
    py_repr(entry, text, &o, sizeof(text));
  (void)snprintf(lead, sizeof(lead), "%c%s%.*s=", etype, indent, (int)key_len, (const char *)key);
  lead_chars = utf8_chars(lead, strlen(lead));
  t = text;
  left = strlen(text);
  for (i = 0;; ++i) { /* 64 characters per row */
    size_t chars = 0, bytes = 0;
    while (bytes < left && chars < 64) {
      ++bytes;
      while (bytes < left && ((unsigned char)t[bytes] & 0xc0) == 0x80)
        ++bytes;
      ++chars;
    }
    if (i == 0)
      printf("%s%.*s\n", lead, (int)bytes, t);
    else
      printf("%*s%.*s\n", (int)lead_chars, "", (int)bytes, t);
    t += bytes;
    left -= bytes;
    if (!left)
      break;
  }
}
/* Prints the "meta" map of an envelope the way `rnid --meta` does. */
static int show_rsg_meta(const uint8_t *rsg, size_t size) {
  static val pool[RSG_POOL];
  val root;
  reader rd;
  const val *meta;
  size_t i;
  if (size < 65)
    return 0;
  rd.p = rsg + 64;
  rd.end = rsg + size;
  rd.pool = pool;
  rd.used = 0;
  rd.cap = RSG_POOL;
  if (!parse(&rd, &root, 0) || rd.p != rd.end || root.type != V_MAP)
    return 0;
  meta = map_get(&root, "meta");
  if (!meta || meta->type != V_MAP)
    return 0;
  printf("RSM Metadata\n============\n\n");
  for (i = 0; i < meta->n; ++i)
    if (meta->kids[2 * i].type == V_STR)
      show_meta_entry(&meta->kids[2 * i + 1], meta->kids[2 * i].p, meta->kids[2 * i].n, 1);
  printf("\nValidation\n==========\n");
  return 1;
}
static int ends_with_nocase(const char *s, const char *suffix) {
  size_t n = strlen(s), m = strlen(suffix);
  return n >= m && !strcasecmp(s + n - m, suffix);
}
/* rnid -V on a .rsm: a signed message that carries its own text. `id` as for validate_file. */
static int validate_message(const rnc_identity *id, const char *path, int show_meta) {
  uint8_t *rsg, hash[32];
  const uint8_t *message;
  size_t size, message_size;
  rnc_identity signer;
  char label[33];
  if (!read_file(path, &rsg, &size)) {
    fprintf(stderr, "The signature file \"%s\" does not exist\n", path);
    return RC_NO_FILE;
  }
  if (!rsg_message(rsg, size, &message, &message_size)) {
    printf("No embedded message in %s\n", path);
    free(rsg);
    return RC_INVALID_SIGNATURE;
  }
  if (rnc_hash(message, message_size, hash) != RNC_OK || !rsg_validate(rsg, size, hash, id, &signer)) {
    printf("Invalid signature in %s\n", path);
    if (id) {
      hex_encode(id->hash, 16, label);
      printf("The message was NOT signed by <%s>\n", label);
    }
    free(rsg);
    return RC_INVALID_SIGNATURE;
  }
  hex_encode(signer.hash, 16, label);
  if (show_meta) { /* the metadata comes first, then the verdict and the message under their own headings */
    (void)show_rsg_meta(rsg, size);
    printf("\nSignature is valid, the message was signed by <%s>\n\nMessage\n=======\n\n", label);
  } else
    printf("\nSignature is valid, the following message was signed by <%s>:\n\n", label);
  fwrite(message, 1, message_size, stdout);
  putchar('\n');
  free(rsg);
  return RC_OK;
}
/* rnid -V: a signature file next to the file it covers. `id` is the identity the signature must verify under
 * (NULL: whoever the envelope names). `--raw` signatures are the bare 64 bytes and need `id`. */
static int validate_file(const rnc_identity *id, const char *validate, const char *read_path, int raw,
                         int show_meta) {
  char data_path[1024];
  uint8_t *data, *sig, file_hash[32];
  size_t size, sig_size;
  rnc_identity signer;
  char label[33];
  int rc = RC_OK, valid;
  if (ends_with_nocase(validate, ".rsm"))
    return validate_message(id, validate, show_meta);
  if (read_path)
    snprintf(data_path, sizeof(data_path), "%s", read_path);
  else if (ends_with(validate, ".rsg") && strlen(validate) - 4 < sizeof(data_path)) {
    memcpy(data_path, validate, strlen(validate) - 4);
    data_path[strlen(validate) - 4] = 0;
  } else {
    fprintf(stderr, "Specify the signed file with -r\n");
    return RC_INVALID_ARGS;
  }
  if (!read_file(validate, &sig, &sig_size)) {
    fprintf(stderr, "The signature file %s does not exist\n", validate);
    return RC_NO_FILE;
  }
  if (!read_file(data_path, &data, &size)) {
    fprintf(stderr, "The file %s does not exist\n", data_path);
    free(sig);
    return RC_NO_FILE;
  }
  if (sig_size == 64 && !raw && !id) {
    fprintf(stderr, "Cannot validate legacy rsg signatures without an explicit required identity\n");
    rc = RC_NO_IDENTITY;
  } else if (sig_size == 64 || raw) { /* a bare signature */
    if (!id) {
      fprintf(stderr, "Raw signatures need an identity, use -i\n");
      rc = RC_NO_IDENTITY;
    } else if (sig_size == 64 && rnc_identity_verify(id, data, size, sig) == RNC_OK)
      printf("Signature of %s is valid\n", data_path);
    else {
      printf("Signature of %s is invalid\n", data_path);
      rc = RC_INVALID_SIGNATURE;
    }
  } else {
    valid = rnc_hash(data, size, file_hash) == RNC_OK && rsg_validate(sig, sig_size, file_hash, id, &signer);
    if (valid) {
      hex_encode(signer.hash, 16, label);
      printf("Signature is valid, the file %s was signed by <%s>\n", data_path, label);
    } else {
      printf("Invalid signature %s for file %s\n", validate, data_path);
      if (id) {
        hex_encode(id->hash, 16, label);
        printf("This file was NOT signed by <%s>\n", label);
      }
      rc = RC_INVALID_SIGNATURE;
    }
  }
  free(sig);
  free(data);
  return rc;
}
/* rnid -S: sign a message and keep the text inside the signature file, written to WRITE_PATH with ".rsm"
 * added. The text comes from the command line or, with -r, from a file. The reference can also open an editor
 * when neither is given, and print the result as armoured base32/64 text; neither is offered here. */
/* The text form of a signature (rnid -B, -b, -F, -U on -s and -S): the data in that encoding, cut into rows of 64
 * characters padded with "=", between a header and a footer line, printed with a blank line either side. */
#define ARMOUR_ROW 64u
static void armour_print(const uint8_t *rsg, size_t n, int format) {
  static const char header[] = "#### Start of rsg data ", footer[] = " End of rsg data ####";
  char *ascii = NULL;
  size_t chars = n, i, row;
  if (format != FORMAT_B256) {
    ascii = malloc(n * 2 + 16);
    if (!ascii)
      return;
    if (format == FORMAT_B32)
      encode_bits(rsg, n, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 5, ascii);
    else if (format == FORMAT_B64)
      encode_bits(rsg, n, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", 6, ascii);
    else
      hex_encode(rsg, n, ascii);
    chars = strlen(ascii);
  }
  putchar('\n');
  fputs(header, stdout);
  for (i = sizeof(header) - 1; i < ARMOUR_ROW; ++i)
    putchar('#');
  putchar('\n');
  for (row = 0; row < chars; row += ARMOUR_ROW) {
    size_t k, end = row + ARMOUR_ROW < chars ? row + ARMOUR_ROW : chars;
    for (k = row; k < end; ++k) {
      if (ascii)
        putchar(ascii[k]);
      else /* a base-256 character is several bytes, but one of the 64 */
        fputs(rnid_b256[rsg[k]], stdout);
    }
    for (; k < row + ARMOUR_ROW; ++k)
      putchar('=');
    putchar('\n');
  }
  for (i = 0; i + (sizeof(footer) - 1) < ARMOUR_ROW; ++i)
    putchar('#');
  fputs(footer, stdout);
  fputs("\n\n", stdout);
  free(ascii);
}
static int sign_message_file(const rnc_identity *id, const char *text, const char *read_path, const char *write_path,
                             int force, int armoured_format, const char *meta_path, const char *meta_spec) {
  const int armoured = armoured_format >= 0; /* -B, -b, -F or -U was given: print the text form instead of a file */
  char path[1024], label[33], spec_default[1100], problem[240];
  uint8_t *file_message = NULL, *rsg, hash[32];
  const uint8_t *message;
  size_t message_size, rsg_size;
  mv *meta = NULL;
  int rc;
  if (!armoured && !write_path) {
    fprintf(stderr, "No write path specified\n");
    return RC_INVALID_ARGS;
  }
  if (!id->has_private) {
    fprintf(stderr, "Cannot sign, the identity does not hold a private key\n");
    return RC_NO_PRVKEY;
  }
  if (text && read_path) {
    fprintf(stderr, "Both an input file and command-line provided message was specified, aborting\n");
    return RC_INVALID_ARGS;
  }
  if (read_path) {
    if (!read_file(read_path, &file_message, &message_size)) {
      fprintf(stderr, "The file %s does not exist\n", read_path);
      return RC_NO_FILE;
    }
    message = file_message;
  } else if (text) {
    message = (const uint8_t *)text;
    message_size = strlen(text);
  } else {
    fprintf(stderr, "No message specified\n");
    return RC_INVALID_ARGS;
  }
  if (message_size > RSG_MAX_MESSAGE) {
    fprintf(stderr, "The message is too long: at most %u bytes can be signed this way\n", RSG_MAX_MESSAGE);
    free(file_message);
    return RC_INVALID_ARGS;
  }
  if (!message_size) {
    fprintf(stderr, "No message specified\n");
    free(file_message);
    return RC_INVALID_ARGS;
  }
  path[0] = 0;
  if (write_path && snprintf(path, sizeof(path), "%s%s", write_path, ends_with(write_path, ".rsm") ? "" : ".rsm") >= (int)sizeof(path)) {
    free(file_message);
    return RC_INVALID_ARGS;
  }
  if (meta_path) { /* the metadata file, checked against its spec when there is one */
    uint8_t *meta_text, *spec_text = NULL;
    size_t meta_size, spec_size = 0;
    mv *spec = NULL;
    const char *spec_path = meta_spec;
    int loaded;
    if (!spec_path) {
      (void)snprintf(spec_default, sizeof(spec_default), "%s.spec", meta_path);
      spec_path = spec_default;
    }
    if (!read_file(meta_path, &meta_text, &meta_size)) {
      fprintf(stderr, "Metadata file %s does not exist\n", meta_path);
      free(file_message);
      return RC_NO_FILE;
    }
    if (read_file(spec_path, &spec_text, &spec_size))
      printf("Embedding metadata from %s using spec from %s\n", meta_path, spec_path);
    else {
      spec_text = NULL; /* a spec that is not there is not an error, as in the reference */
      spec_path = NULL;
      printf("Embedding metadata from %s\n", meta_path);
    }
    problem[0] = 0;
    loaded = meta_parse((const char *)meta_text, meta_size, &meta, problem, sizeof(problem));
    if (loaded && spec_text)
      loaded = meta_parse((const char *)spec_text, spec_size, &spec, problem, sizeof(problem)) &&
               meta_validate(meta, spec, problem, sizeof(problem));
    free(meta_text);
    free(spec_text);
    mv_free(spec);
    if (!loaded) {
      fprintf(stderr, "Could not load metadata from %s: %s\n", meta_path,
              problem[0] ? problem : "Metadata did not pass spec validation");
      mv_free(meta);
      free(file_message);
      return RC_UNKNOWN_ERROR;
    }
  }
  rsg = malloc(RNC_RPC_MESSAGE_MAX + 128);
  if (!rsg || rnc_hash(message, message_size, hash) != RNC_OK ||
      !rsg_create(id, hash, message, message_size, meta, rsg, RNC_RPC_MESSAGE_MAX + 128, &rsg_size)) {
    fprintf(stderr, "Could not sign message (the message and its metadata must fit in 64 KiB together)\n");
    free(rsg);
    mv_free(meta);
    free(file_message);
    return RC_UNKNOWN_ERROR;
  }
  mv_free(meta);
  if (armoured) {
    armour_print(rsg, rsg_size, armoured_format);
    hex_encode(id->hash, 16, label);
    printf("Message signed with <%s>\n", label);
    free(rsg);
    free(file_message);
    return RC_OK;
  }
  rc = write_private_file(path, rsg, rsg_size, force);
  if (rc == RC_FILE_EXISTS)
    fprintf(stderr, "The signature file \"%s\" already exists, not overwriting\n", path);
  else if (rc == RC_OK) {
    hex_encode(id->hash, 16, label);
    printf("Message signed with <%s> saved to %s\n", label, path);
  }
  free(rsg);
  free(file_message);
  return rc;
}
/* Where the shared instance's data port is: the config's instance (a file or a directory, else the reference's
 * search) by Unix socket on Linux, or TCP when the config says so or a data port is given. */
static void data_target(const char *config, unsigned long data_port, target *t) {
  conn c = {0};
  char dir[1100], file[1200], key[RNC_RPC_KEY_MAX * 2 + 2];
  struct stat sb;
  memset(t, 0, sizeof(*t));
  c.data_port = data_port;
  if (config && !stat(config, &sb) && S_ISDIR(sb.st_mode))
    (void)snprintf(file, sizeof(file), "%s/config", config);
  else if (config)
    (void)snprintf(file, sizeof(file), "%s", config);
  else if (default_config_dir(dir, sizeof(dir)))
    (void)snprintf(file, sizeof(file), "%s/config", dir);
  else
    file[0] = 0;
  if (file[0])
    read_config(file, &c, key, sizeof(key));
  t->data_port = c.data_port ? (unsigned)c.data_port : DEFAULT_DATA_PORT;
#ifdef __linux__
  if (!c.tcp && !c.data_port)
    (void)snprintf(t->unix_name, sizeof(t->unix_name), "%s", c.instance_name[0] ? c.instance_name : "default");
#endif
}
static int cmd_id(int argc, char **argv) {
  const char *identity_path = NULL, *generate = NULL, *aspects = NULL,
             *encrypt = NULL, *decrypt = NULL, *sign = NULL, *validate = NULL,
             *read_path = NULL, *write_path = NULL;
  int i, print = 0, show_private = 0, force = 0, raw = 0, export_pub = 0,
         export_prv = 0, rc;
  rnc_identity id;
  char hex[129], out_path[1024];
  const char *import_pub = NULL, *import_prv = NULL, *how = NULL, *sign_message = NULL, *meta_path = NULL,
             *meta_spec = NULL, *announce = NULL, *config_arg = NULL;
  unsigned long data_port_arg = 0;
  int format = FORMAT_HEX, formats = 0, has_sign_message = 0, show_meta = 0;
  for (i = 0; i < argc; ++i) {
    const char *a = argv[i];
    const char **slot = NULL;
    if (!strcmp(a, "-i") || !strcmp(a, "--identity"))
      slot = &identity_path;
    else if (!strcmp(a, "-E") || !strcmp(a, "--embed-meta"))
      slot = &meta_path;
    else if (!strcmp(a, "--meta-spec"))
      slot = &meta_spec;
    else if (!strcmp(a, "-m") || !strcmp(a, "--import-pub"))
      slot = &import_pub;
    else if (!strcmp(a, "-M") || !strcmp(a, "--import-prv"))
      slot = &import_prv;
    else if (!strcmp(a, "-g") || !strcmp(a, "--generate"))
      slot = &generate;
    else if (!strcmp(a, "-H") || !strcmp(a, "--hash"))
      slot = &aspects;
    else if (!strcmp(a, "-e") || !strcmp(a, "--encrypt"))
      slot = &encrypt;
    else if (!strcmp(a, "-d") || !strcmp(a, "--decrypt"))
      slot = &decrypt;
    else if (!strcmp(a, "-s") || !strcmp(a, "--sign"))
      slot = &sign;
    else if (!strcmp(a, "-V") || !strcmp(a, "--validate"))
      slot = &validate;
    else if (!strcmp(a, "-r") || !strcmp(a, "--read"))
      slot = &read_path;
    else if (!strcmp(a, "-w") || !strcmp(a, "--write"))
      slot = &write_path;
    else if (!strcmp(a, "--config"))
      slot = &config_arg;
    if (slot) {
      if (++i >= argc)
        return RC_INVALID_ARGS;
      *slot = argv[i];
    } else if (!strcmp(a, "-B") || !strcmp(a, "--base32")) {
      format = FORMAT_B32;
      ++formats;
    } else if (!strcmp(a, "-b") || !strcmp(a, "--base64")) {
      format = FORMAT_B64;
      ++formats;
    } else if (!strcmp(a, "-F") || !strcmp(a, "--hex")) {
      format = FORMAT_HEX;
      ++formats;
    } else if (!strcmp(a, "-U") || !strcmp(a, "--base256")) {
      format = FORMAT_B256;
      ++formats;
    } else if (!strcmp(a, "-p") || !strcmp(a, "--print-identity"))
      print = 1;
    else if (!strcmp(a, "-P") || !strcmp(a, "--print-private"))
      show_private = 1;
    else if (!strcmp(a, "-f") || !strcmp(a, "--force"))
      force = 1;
    else if (!strcmp(a, "-S") || !strcmp(a, "--sign-message")) {
      has_sign_message = 1; /* the text may follow; without it -r names a file holding the message */
      if (i + 1 < argc && argv[i + 1][0] != '-')
        sign_message = argv[++i];
    } else if (!strcmp(a, "-a") || !strcmp(a, "--announce")) {
      announce = "rnid.id"; /* the aspects may follow; without them the reference announces rnid.id */
      if (i + 1 < argc && argv[i + 1][0] != '-')
        announce = argv[++i];
    } else if (!strcmp(a, "--data-port")) {
      if (++i >= argc || !number(argv[i], 65535, &data_port_arg) || !data_port_arg)
        return RC_INVALID_ARGS;
    } else if (!strcmp(a, "--meta"))
      show_meta = 1;
    else if (!strcmp(a, "--raw"))
      raw = 1;
    else if (!strcmp(a, "-x") || !strcmp(a, "--export-pub"))
      export_pub = 1;
    else if (!strcmp(a, "-X") || !strcmp(a, "--export-prv"))
      export_prv = 1;
    else {
      fprintf(stderr, "Unknown option %s\n", a);
      return RC_INVALID_ARGS;
    }
  }
  if (formats > 1) {
    puts("The -b, -B, --hex and --base256 args are mutually exclusive");
    return RC_INVALID_ARGS;
  }
  if (generate) {
    rc = rnc_identity_generate(&id, random_bytes, NULL);
    if (rc != RNC_OK)
      return RC_UNKNOWN_ERROR;
    rc = write_private_file(generate, id.private_key, 64, force);
    if (rc == RC_FILE_EXISTS)
      fprintf(stderr, "The file %s already exists, not overwriting\n", generate);
    else if (rc == RC_OK) {
      hex_encode(id.hash, 16, hex);
      printf("New identity <%s> generated and saved to %s\n", hex, generate);
    }
    rnc_identity_clear(&id);
    return rc;
  }
  if (validate && !raw && !identity_path && !import_pub && !import_prv && !print && !sign && !encrypt && !decrypt)
    return validate_file(NULL, validate, read_path, 0, show_meta); /* the envelope names its signer */
  if (import_pub || import_prv) {
    const char *text = import_prv ? import_prv : import_pub;
    if (!import_identity(text, import_prv != NULL, &id, &how)) {
      printf("Could not decode specified data to a valid %s Reticulum Identity\n",
             import_prv ? "private" : "public");
      return RC_INVALID_IDENTITY;
    }
    if (!strcmp(how, "file"))
      puts("Reticulum Identity imported from file");
    else
      printf("Reticulum Identity imported from %s input\n", how);
    hex_encode(id.hash, 16, hex);
    printf("Loaded Identity <%s>\n", hex);
  } else {
    if (!identity_path) {
      fprintf(stderr, "No identity specified, use -i\n");
      return RC_NO_IDENTITY;
    }
    rc = load_private(identity_path, &id);
    if (rc) {
      fprintf(stderr, "Could not load the identity file %s\n", identity_path);
      return rc;
    }
    hex_encode(id.hash, 16, hex);
    printf("Loaded Identity <%s> from %s\n", hex, identity_path);
  }
  rc = RC_OK;
  if (print)
    print_identity(&id, show_private, format);
  if (export_pub) {
    encode_key(format, id.public_key, 64, hex);
    printf("Public identity : %s\n", hex);
  }
  if (export_prv) {
    if (!id.has_private) {
      fprintf(stderr, "This identity has no private key\n");
      rnc_identity_clear(&id);
      return RC_NO_PRVKEY;
    }
    encode_key(format, id.private_key, 64, hex);
    printf("Private identity: %s\n", hex);
  }
  if (aspects) {
    uint8_t name_hash[10], dest[16];
    if (rnc_destination_hash(aspects, &id, name_hash, dest) != RNC_OK) {
      fprintf(stderr, "Invalid aspects \"%s\"\n", aspects);
      rc = RC_INVALID_ASPECTS;
    } else {
      hex_encode(dest, 16, hex);
      printf("The %s destination for this Identity is <%s>\n", aspects, hex);
    }
  }
  if (rc == RC_OK && announce) {
    /* the destination of this identity for the aspects, announced through the shared instance as a local client */
    uint8_t name_hash[10], dest[16];
    char dest_hex[33];
    rnc_packet packet;
    target t;
    if (!strchr(announce, '.')) {
      puts("Invalid destination aspects specified");
      rc = RC_INVALID_ASPECTS;
    } else if (!id.has_private) {
      puts("Cannot announce this destination, since the private key is not held");
      rc = RC_NO_PRVKEY;
    } else if (rnc_destination_hash(announce, &id, name_hash, dest) != RNC_OK) {
      puts("Invalid destination aspects specified");
      rc = RC_INVALID_ASPECTS;
    } else {
      hex_encode(dest, 16, dest_hex);
      hex_encode(id.hash, 16, hex);
      printf("Announcing %s destination <%s> for identity <%s>\n", announce, dest_hex, hex);
      data_target(config_arg, data_port_arg, &t);
      if (rnc_announce_create(&id, announce, NULL, 0, (uint64_t)time(NULL), random_bytes, NULL, &packet) != RNC_OK ||
          !send_packet(&t, &packet)) {
        puts("An error ocurred while attempting to send the announce: could not reach the shared instance");
        rc = RC_UNKNOWN_ERROR;
      }
    }
  }
  if (rc == RC_OK && sign) {
    uint8_t *data, signature[64], file_hash[32], rsg[512];
    size_t size, rsg_size;
    if (snprintf(out_path, sizeof(out_path), "%s.rsg", sign) >= (int)sizeof(out_path))
      rc = RC_INVALID_ARGS;
    else if (!id.has_private) {
      fprintf(stderr, "Cannot sign \"%s\", the identity does not hold a private key\n", sign);
      rc = RC_NO_PRVKEY;
    } else if (!read_file(sign, &data, &size)) {
      fprintf(stderr, "The file %s does not exist\n", sign);
      rc = RC_NO_FILE;
    } else {
      if (raw) { /* the reference's legacy form: the bare signature */
        if (rnc_identity_sign(&id, data, size, signature) != RNC_OK)
          rc = RC_UNKNOWN_ERROR;
        else {
          rc = write_private_file(out_path, signature, 64, force);
          if (rc == RC_FILE_EXISTS)
            fprintf(stderr, "The signature file %s already exists, not overwriting\n", out_path);
          else if (rc == RC_OK)
            printf("Signed file %s, signature written to %s\n", sign, out_path);
        }
      } else if (rnc_hash(data, size, file_hash) != RNC_OK || !rsg_create(&id, file_hash, NULL, 0, NULL, rsg, sizeof(rsg), &rsg_size))
        rc = RC_UNKNOWN_ERROR;
      else if (formats) { /* the text form is printed, no file is written */
        armour_print(rsg, rsg_size, format);
        hex_encode(id.hash, 16, hex);
        printf("Signed file %s with <%s>\n", sign, hex);
      } else {
        rc = write_private_file(out_path, rsg, rsg_size, force);
        if (rc == RC_FILE_EXISTS)
          fprintf(stderr, "The signature file %s already exists, not overwriting\n", out_path);
        else if (rc == RC_OK) {
          hex_encode(id.hash, 16, hex);
          printf("Signed file %s with <%s>\n", sign, hex);
        }
      }
      free(data);
    }
  }
  if (rc == RC_OK && has_sign_message)
    rc = sign_message_file(&id, sign_message, read_path, write_path, force, formats ? format : -1, meta_path, meta_spec);
  if (rc == RC_OK && validate)
    rc = validate_file(&id, validate, read_path, raw, show_meta);
  if (rc == RC_OK && encrypt) {
    if (write_path)
      snprintf(out_path, sizeof(out_path), "%s", write_path);
    else if (snprintf(out_path, sizeof(out_path), "%s.rfe", encrypt) >= (int)sizeof(out_path))
      rc = RC_INVALID_ARGS;
    if (rc == RC_OK)
      rc = crypt_file(&id, encrypt, out_path, force, 1);
  }
  if (rc == RC_OK && decrypt) {
    if (!ends_with(decrypt, ".rfe") && !write_path) {
      fprintf(stderr, "%s does not end in .rfe, specify an output with -w\n", decrypt);
      rc = RC_INVALID_ARGS;
    } else {
      if (write_path)
        snprintf(out_path, sizeof(out_path), "%s", write_path);
      else {
        snprintf(out_path, sizeof(out_path), "%s", decrypt);
        out_path[strlen(out_path) - 4] = 0;
      }
      if (!file_exists(decrypt)) {
        fprintf(stderr, "The file %s does not exist\n", decrypt);
        rc = RC_NO_FILE;
      } else
        rc = crypt_file(&id, decrypt, out_path, force, 0);
      if (rc == RC_DECRYPT_FAILED)
        fprintf(stderr, "The provided identity could not decrypt the file\n");
    }
  }
  rnc_identity_clear(&id);
  return rc;
}

static void usage(void) {
  fputs("usage: reticulum-c-ctl status [-j] [--port N] (--identity FILE | --rpc-key HEX | --config FILE)\n"
        "       reticulum-c-ctl path [-t] [-m HOPS] [-j] [HASH] [-b] [-B HASH [--duration HOURS] [--reason TEXT]] [-U HASH] [connection options]\n"
        "       reticulum-c-ctl id (-g FILE | -i FILE [-p] [-P] [-x] [-X] [-H ASPECTS]\n"
        "                          [-s FILE --raw] [-V SIG -r FILE --raw] [-e FILE] [-d FILE] [-w OUT] [-f])\n",
        stderr);
}
int main(int argc, char **argv) {
  if (argc < 2) {
    usage();
    return RC_INVALID_ARGS;
  }
  if (!strcmp(argv[1], "status"))
    return cmd_status(argc - 2, argv + 2);
  if (!strcmp(argv[1], "path"))
    return cmd_path(argc - 2, argv + 2);
  if (!strcmp(argv[1], "id"))
    return cmd_id(argc - 2, argv + 2);
  usage();
  return RC_INVALID_ARGS;
}
