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
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <poll.h>
#include "msgpack_tree.h"
#include <reticulum_c/rnc.h>
#include <reticulum_c/rnc_ipc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
  struct sockaddr_in addr;
  int fd = socket(AF_INET, SOCK_STREAM, 0), done = 0, ok = 0;
  rnc_rpc *rpc;
  rnc_rpc_event event;
  unsigned long deadline = now_ms() + 10000ul;
  uint8_t buf[4096];
  if (fd < 0)
    return 0;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons((uint16_t)t->port);
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
    fprintf(stderr, "Could not connect to the daemon RPC port %u: %s\n", t->port,
            strerror(errno));
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
static int get_request(const target *t, const char *method, const uint8_t *dest,
                       long max_hops, reply *out) {
  uint8_t buf[256];
  rnc_rpc_writer w;
  size_t n, pairs = 1 + (dest ? 1 : 0) + (max_hops > 0 ? 1 : 0);
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
    else if (!strcmp(k, "rpc_key") && !c->rpc_key && strlen(v) < size) {
      strcpy(rpc_key, v);
      c->rpc_key = rpc_key;
    }
  }
  fclose(f);
}
static int make_target(conn *c, target *t) {
  rnc_identity id;
  char config_key[RNC_RPC_KEY_MAX * 2 + 2];
  if (c->config)
    read_config(c->config, c, config_key, sizeof(config_key));
  t->port = c->port ? (unsigned)c->port : DEFAULT_CONTROL_PORT;
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
  if (!strcmp(a, "--port") || !strcmp(a, "--identity") ||
      !strcmp(a, "--config") || !strcmp(a, "--rpc-key")) {
    if (*i + 1 >= argc)
      return -1;
    ++*i;
    if (!strcmp(a, "--port")) {
      if (!number(argv[*i], 65535, &c->port) || !c->port)
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
static int cmd_status(int argc, char **argv) {
  conn c = {0, NULL, NULL, NULL};
  int i, json = 0;
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
    else {
      fprintf(stderr, "Unknown option %s\n", argv[i]);
      return RC_INVALID_ARGS;
    }
  }
  if (!make_target(&c, &t))
    return RC_INVALID_ARGS;
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
  for (k = 0; ifaces && ifaces->type == V_ARR && k < ifaces->n; ++k) {
    const val *f = &ifaces->kids[k];
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
  v = map_get(&r.root, "transport_uptime");
  if (v && as_double(v) > 0)
    printf(" Uptime is %.0f seconds\n", as_double(v));
  reply_free(&r);
  return RC_OK;
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
static int cmd_path(int argc, char **argv) {
  conn c = {0, NULL, NULL, NULL};
  int i, json = 0, table = 0, list = 0, have_hash = 0, rc = RC_OK;
  long max_hops = 0;
  uint8_t hash[16], add[16], remove_hash[16];
  int do_add = 0, do_remove = 0;
  unsigned long hours = 0;
  const char *reason = NULL;
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
  if (!table && !list && !have_hash && !do_add && !do_remove) {
    fprintf(stderr, "Specify a destination hash, -t, -b, -B or -U\n");
    return RC_INVALID_ARGS;
  }
  if (!make_target(&c, &t))
    return RC_INVALID_ARGS;
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
static void print_identity(const rnc_identity *id, int show_private) {
  char hex[129];
  hex_encode(id->public_key, 64, hex);
  printf("Public Key    : %s\n", hex);
  if (id->has_private && show_private) {
    hex_encode(id->private_key, 64, hex);
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
static int cmd_id(int argc, char **argv) {
  const char *identity_path = NULL, *generate = NULL, *aspects = NULL,
             *encrypt = NULL, *decrypt = NULL, *sign = NULL, *validate = NULL,
             *read_path = NULL, *write_path = NULL;
  int i, print = 0, show_private = 0, force = 0, raw = 0, export_pub = 0,
         export_prv = 0, rc;
  rnc_identity id;
  char hex[129], out_path[1024];
  for (i = 0; i < argc; ++i) {
    const char *a = argv[i];
    const char **slot = NULL;
    if (!strcmp(a, "-i") || !strcmp(a, "--identity"))
      slot = &identity_path;
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
    if (slot) {
      if (++i >= argc)
        return RC_INVALID_ARGS;
      *slot = argv[i];
    } else if (!strcmp(a, "-p") || !strcmp(a, "--print-identity"))
      print = 1;
    else if (!strcmp(a, "-P") || !strcmp(a, "--print-private"))
      show_private = 1;
    else if (!strcmp(a, "-f") || !strcmp(a, "--force"))
      force = 1;
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
  rc = RC_OK;
  if (print)
    print_identity(&id, show_private);
  if (export_pub) {
    hex_encode(id.public_key, 64, hex);
    printf("Public identity : %s\n", hex);
  }
  if (export_prv) {
    hex_encode(id.private_key, 64, hex);
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
  if (rc == RC_OK && sign) {
    uint8_t *data, signature[64];
    size_t size;
    if (!raw) {
      fprintf(stderr, "Only raw signatures are supported, add --raw\n");
      rc = RC_INVALID_ARGS;
    } else if (snprintf(out_path, sizeof(out_path), "%s.rsg", sign) >= (int)sizeof(out_path))
      rc = RC_INVALID_ARGS;
    else if (!read_file(sign, &data, &size)) {
      fprintf(stderr, "The file %s does not exist\n", sign);
      rc = RC_NO_FILE;
    } else {
      if (rnc_identity_sign(&id, data, size, signature) != RNC_OK)
        rc = RC_UNKNOWN_ERROR;
      else {
        rc = write_private_file(out_path, signature, 64, force);
        if (rc == RC_FILE_EXISTS)
          fprintf(stderr, "The signature file %s already exists, not overwriting\n", out_path);
        else if (rc == RC_OK)
          printf("Signed file %s, signature written to %s\n", sign, out_path);
      }
      free(data);
    }
  }
  if (rc == RC_OK && validate) {
    uint8_t *data, *sig;
    size_t size, sig_size;
    const char *data_path = read_path;
    if (!raw) {
      fprintf(stderr, "Only raw signatures are supported, add --raw\n");
      rc = RC_INVALID_ARGS;
    } else if (!data_path && ends_with(validate, ".rsg") &&
               strlen(validate) - 4 < sizeof(out_path)) {
      memcpy(out_path, validate, strlen(validate) - 4);
      out_path[strlen(validate) - 4] = 0;
      data_path = out_path;
    }
    if (rc == RC_OK && !data_path) {
      fprintf(stderr, "Specify the signed file with -r\n");
      rc = RC_INVALID_ARGS;
    } else if (rc == RC_OK) {
      if (!read_file(validate, &sig, &sig_size)) {
        fprintf(stderr, "The signature file %s does not exist\n", validate);
        rc = RC_NO_FILE;
      } else if (!read_file(data_path, &data, &size)) {
        fprintf(stderr, "The file %s does not exist\n", data_path);
        free(sig);
        rc = RC_NO_FILE;
      } else {
        if (sig_size == 64 &&
            rnc_identity_verify(&id, data, size, sig) == RNC_OK)
          printf("Signature of %s is valid\n", data_path);
        else {
          printf("Signature of %s is invalid\n", data_path);
          rc = RC_INVALID_SIGNATURE;
        }
        free(sig);
        free(data);
      }
    }
  }
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
