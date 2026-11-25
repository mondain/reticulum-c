/* reticulum-c-cp: file transfer compatible with the reference rncp.
 *
 *   reticulum-c-cp --connect HOST:PORT --identity FILE -l [-a HASH]... [-n]
 *                  [-s DIR] [-O] [-F [-j DIR]] [-b SECONDS] [--stamp-value N]
 *   reticulum-c-cp --connect HOST:PORT --identity FILE FILE DESTINATION
 *   reticulum-c-cp --connect HOST:PORT --identity FILE -f REMOTE_FILE DESTINATION
 *                  [-s DIR] [-O]
 *
 * It attaches to a Reticulum node over TCP (a daemon's shared-instance port or
 * any TCP server interface), so it runs next to reticulum-c-node. DESTINATION
 * is the 32 hex character hash printed by the listener ("rncp.receive"). -a
 * takes the 32 hex character hash of an allowed sender identity. */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include "tool_stamps.h"
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <openssl/rand.h>
#include <reticulum_c/rnc_host.h>
#include <reticulum_c/rnc_transfer.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define APP_NAME "rncp.receive"
#define DEFAULT_PATH_WAIT 15u

static volatile sig_atomic_t stopping;
static void on_signal(int sig) {
  (void)sig;
  stopping = 1;
}
static rnc_result secure_random(void *context, uint8_t *out, size_t size) {
  (void)context;
  return size <= INT_MAX && RAND_priv_bytes(out, (int)size) == 1 ? RNC_OK
                                                                 : RNC_CRYPTO;
}
static uint64_t monotonic_ms(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
static void print_hex(const uint8_t *data, size_t size) {
  size_t i;
  for (i = 0; i < size; ++i)
    printf("%02x", data[i]);
}
static int hex_decode(const char *text, uint8_t *out, size_t size) {
  size_t i;
  if (strlen(text) != size * 2)
    return 0;
  for (i = 0; i < size; ++i) {
    unsigned v;
    char pair[3] = {text[2 * i], text[2 * i + 1], 0};
    char *end;
    v = (unsigned)strtoul(pair, &end, 16);
    if (*end || pair[0] == '+' || pair[0] == '-' || pair[0] == ' ')
      return 0;
    out[i] = (uint8_t)v;
  }
  return 1;
}

/* ---- file handling ------------------------------------------------------ */
typedef struct options {
  const char *connect, *identity, *save, *jail, *fetch_path;
  int listen, fetch, no_auth, allow_fetch, overwrite, silent, no_compress, print_identity, phy_rates;
  long announce; /* seconds between announces; -1 = never */
  unsigned wait;
  double stamp_value;
  rnc_transfer_config config;
  char saved_dir[PATH_MAX], jail_dir[PATH_MAX];
} options;
static options opt;

/* Final path component only; refuses names that could escape the directory. */
static int safe_name(const uint8_t *name, size_t n, char *out, size_t cap) {
  size_t i, start = 0;
  for (i = 0; i < n; ++i)
    if (name[i] == '/')
      start = i + 1;
  n -= start;
  name += start;
  if (!n || n >= cap || (n == 1 && name[0] == '.') ||
      (n == 2 && name[0] == '.' && name[1] == '.'))
    return 0;
  for (i = 0; i < n; ++i)
    if (name[i] == 0)
      return 0;
  memcpy(out, name, n);
  out[n] = 0;
  return 1;
}
/* Incoming files are written as they arrive, to a temporary file in the save directory that is moved to its
 * final name only when the whole file has come in, so a transfer that fails leaves nothing behind and a file of
 * any size never sits in memory. */
typedef struct incoming {
  int fd, listening;
  char temp[PATH_MAX], name[256];
  uint8_t from[16];
  int has_from;
} incoming;
static int save_failed;
static rnc_result rx_open(void *context, const uint8_t *identity_hash, const uint8_t *name, size_t name_size,
                          uint64_t size, void **file) {
  incoming *in;
  (void)size;
  in = calloc(1, sizeof(*in));
  if (!in)
    return RNC_NO_SPACE;
  in->listening = context != NULL;
  if (!safe_name(name, name_size, in->name, sizeof(in->name))) {
    fprintf(stderr, in->listening ? "Ignoring a file with an invalid name\n" : "The remote sent an invalid file name\n");
    free(in);
    return RNC_INVALID;
  }
  if (snprintf(in->temp, sizeof(in->temp), "%s/.rncp-XXXXXX", opt.saved_dir) >= (int)sizeof(in->temp) ||
      (in->fd = mkstemp(in->temp)) < 0) {
    fprintf(stderr, "Could not save %s: %s\n", in->name, strerror(errno));
    free(in);
    return RNC_STATE;
  }
  if (identity_hash) {
    in->has_from = 1;
    memcpy(in->from, identity_hash, 16);
  }
  *file = in;
  return RNC_OK;
}
static rnc_result rx_write(void *file, uint64_t offset, const void *data, size_t size) {
  incoming *in = file;
  const uint8_t *p = data;
  while (size) {
    ssize_t n = pwrite(in->fd, p, size, (off_t)offset);
    if (n <= 0) {
      fprintf(stderr, "Could not write %s: %s\n", in->name, strerror(errno));
      return RNC_STATE;
    }
    p += n;
    offset += (uint64_t)n;
    size -= (size_t)n;
  }
  return RNC_OK;
}
/* Gives the finished temporary file its name: replacing an existing file with -O, otherwise the first of name,
 * name.1, name.2 ... that is free (linked, so that two receivers never take the same name). */
static int place(const incoming *in, char *saved, size_t cap) {
  unsigned counter = 0;
  if (opt.overwrite)
    return snprintf(saved, cap, "%s/%s", opt.saved_dir, in->name) < (int)cap && !rename(in->temp, saved);
  for (; counter <= 100000u; ++counter) {
    if ((counter ? snprintf(saved, cap, "%s/%s.%u", opt.saved_dir, in->name, counter)
                 : snprintf(saved, cap, "%s/%s", opt.saved_dir, in->name)) >= (int)cap)
      return 0;
    if (!link(in->temp, saved)) {
      (void)unlink(in->temp);
      return 1;
    }
    if (errno == EEXIST)
      continue;
    /* no hard links on this filesystem: take the name if it is free */
    if (access(saved, F_OK) != 0 && !rename(in->temp, saved))
      return 1;
    if (access(saved, F_OK) != 0)
      return 0;
  }
  return 0;
}
static void rx_close(void *file, int complete) {
  incoming *in = file;
  char saved[PATH_MAX];
  int ok = close(in->fd) == 0;
  if (!complete || !ok) {
    (void)unlink(in->temp);
    if (complete)
      save_failed = 1;
  } else if (!place(in, saved, sizeof(saved))) {
    fprintf(stderr, "Could not save %s: %s\n", in->name, strerror(errno));
    (void)unlink(in->temp);
    save_failed = 1;
  } else {
    if (in->listening && in->has_from) {
      fputs("Received from <", stdout);
      print_hex(in->from, 16);
      fputs(">\n", stdout);
    }
    printf(in->listening ? "Saved received file to %s\n" : "Saved fetched file to %s\n", saved);
    fflush(stdout);
  }
  free(in);
}
static const rnc_transfer_stream rx_stream = {rx_open, rx_write, rx_close};

/* A file leaving: read where the transfer layer asks, a piece at a time */
static rnc_result file_read(void *context, uint64_t offset, void *out, size_t size) {
  int fd = (int)(intptr_t)context;
  uint8_t *p = out;
  while (size) {
    ssize_t n = pread(fd, p, size, (off_t)offset);
    if (n <= 0)
      return RNC_STATE; /* shorter than it was: the file changed under us */
    p += n;
    offset += (uint64_t)n;
    size -= (size_t)n;
  }
  return RNC_OK;
}
static void file_release(void *context) { (void)close((int)(intptr_t)context); }
/* Normalises a path without touching the filesystem: no "." or ".." parts. */
static int normalise(const char *path, char *out, size_t cap) {
  char work[PATH_MAX], cwd[PATH_MAX], *part, *save = NULL;
  size_t used = 0, n;
  if (path[0] == '/') {
    if (strlen(path) >= sizeof(work))
      return 0;
    strcpy(work, path);
  } else {
    if (!getcwd(cwd, sizeof(cwd)) ||
        snprintf(work, sizeof(work), "%s/%s", cwd, path) >= (int)sizeof(work))
      return 0;
  }
  out[0] = 0;
  for (part = strtok_r(work, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
    if (!strcmp(part, "."))
      continue;
    if (!strcmp(part, "..")) {
      while (used && out[used - 1] != '/')
        --used;
      if (used)
        --used;
      out[used] = 0;
      continue;
    }
    n = strlen(part);
    if (used + n + 2 > cap)
      return 0;
    out[used++] = '/';
    memcpy(out + used, part, n);
    used += n;
    out[used] = 0;
  }
  if (!used) {
    out[0] = '/';
    out[1] = 0;
  }
  return 1;
}
static int expand_home(const char *path, char *out, size_t cap) {
  const char *home = getenv("HOME");
  if (path[0] == '~' && (path[1] == '/' || !path[1]) && home)
    return snprintf(out, cap, "%s%s", home, path + 1) < (int)cap;
  return snprintf(out, cap, "%s", path) < (int)cap;
}
static int within(const char *dir, const char *path) {
  size_t n = strlen(dir);
  return !strncmp(path, dir, n) && path[n] == '/';
}
/* Which file a fetch names, with the jail and path rules; RNC_FETCH_FOUND fills `file` with the path to read. */
static int resolve_fetch(const uint8_t *path, size_t path_size, char file[PATH_MAX]) {
  char requested[PATH_MAX], expanded[PATH_MAX], real[PATH_MAX], jail_real[PATH_MAX];
  struct stat st;
  if (path_size == 0 || path_size >= sizeof(requested))
    return RNC_FETCH_NOT_FOUND;
  memcpy(requested, path, path_size);
  requested[path_size] = 0;
  if (memchr(path, 0, path_size))
    return RNC_FETCH_NOT_FOUND;
  if (opt.jail) {
    const char *rel = requested;
    char joined[PATH_MAX];
    size_t jn = strlen(opt.jail_dir);
    if (!strncmp(rel, opt.jail_dir, jn) && rel[jn] == '/')
      rel += jn + 1;
    if (snprintf(joined, sizeof(joined), "%s/%s", opt.jail_dir, rel) >=
            (int)sizeof(joined) ||
        !normalise(joined, file, PATH_MAX) || !within(opt.jail_dir, file)) {
      fprintf(stderr, "Disallowing fetch request outside of the fetch jail\n");
      return RNC_FETCH_NOT_ALLOWED;
    }
    /* a symlink must not lead out of the jail either */
    if (realpath(file, real) && realpath(opt.jail_dir, jail_real) &&
        !within(jail_real, real)) {
      fprintf(stderr, "Disallowing fetch request through a symlink\n");
      return RNC_FETCH_NOT_ALLOWED;
    }
  } else if (!expand_home(requested, expanded, sizeof(expanded)) ||
             !normalise(expanded, file, PATH_MAX))
    return RNC_FETCH_NOT_FOUND;
  if (stat(file, &st) || !S_ISREG(st.st_mode)) {
    printf("Client-requested file not found: %s\n", file);
    return RNC_FETCH_NOT_FOUND;
  }
  return RNC_FETCH_FOUND;
}
static int on_fetch(void *context, const uint8_t *path, size_t path_size,
                    const uint8_t *identity_hash, rnc_transfer_source *source) {
  char file[PATH_MAX], copy[PATH_MAX], *base;
  struct stat st;
  int found, fd;
  (void)context;
  (void)identity_hash;
  found = resolve_fetch(path, path_size, file);
  if (found != RNC_FETCH_FOUND)
    return found;
  fd = open(file, O_RDONLY);
  if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode)) {
    if (fd >= 0)
      close(fd);
    return RNC_FETCH_NOT_FOUND;
  }
  source->size = (uint64_t)st.st_size;
  source->read = file_read;
  source->context = (void *)(intptr_t)fd;
  source->release = file_release;
  snprintf(copy, sizeof(copy), "%s", file);
  base = basename(copy);
  source->name_size = strlen(base);
  if (source->name_size > RNC_TRANSFER_NAME_MAX)
    source->name_size = RNC_TRANSFER_NAME_MAX;
  memcpy(source->name, base, source->name_size);
  printf("Sending file %s to client\n", file);
  fflush(stdout);
  return RNC_FETCH_FOUND;
}

/* ---- node setup --------------------------------------------------------- */
static int open_node(rnc_identity *id, rnc_node **node, rnc_host **host) {
  rnc_host_config hc;
  char address[256];
  const char *colon = strrchr(opt.connect, ':');
  unsigned long port;
  char *end;
  if (!colon || colon == opt.connect || (size_t)(colon - opt.connect) >= sizeof(address))
    return 0;
  memcpy(address, opt.connect, (size_t)(colon - opt.connect));
  address[colon - opt.connect] = 0;
  port = strtoul(colon + 1, &end, 10);
  if (*end || !port || port > 65535)
    return 0;
  if (rnc_host_identity_load(opt.identity, secure_random, NULL, id) != RNC_OK) {
    fprintf(stderr, "Cannot load or create the identity file %s\n", opt.identity);
    return 0;
  }
  *node = rnc_node_new(id, 0, secure_random, NULL);
  *host = *node ? rnc_host_new(*node) : NULL;
  if (!*host)
    return 0;
  tool_stamps_requests(*node, opt.stamp_value);
  memset(&hc, 0, sizeof(hc));
  hc.kind = RNC_HOST_TCP_CONNECT;
  hc.name = "rncp link";
  hc.address = address;
  hc.port = (uint16_t)port;
  hc.mtu = RNC_MAX_MTU;
  hc.bitrate = 1000000000u;
  if (rnc_host_add(*host, 1, &hc) != RNC_OK) {
    fprintf(stderr, "Cannot connect to %s: %s\n", opt.connect, strerror(errno));
    return 0;
  }
  return 1;
}
typedef struct app {
  rnc_node *node;
  rnc_host *host;
  rnc_transfer_listener *listener;
  rnc_transfer_client *client;
} app;
/* One pump: I/O, node events into the listener/client, then their timers. */
static int pump(app *a) {
  rnc_host_event event;
  uint64_t unix_now = (uint64_t)time(NULL), now = monotonic_ms();
  if (rnc_host_step(a->host, 10, unix_now, now) != RNC_OK)
    return 0;
  while (rnc_host_poll(a->host, &event) == RNC_OK) {
    if (event.type != RNC_HOST_NODE || event.node.type != RNC_NODE_LOCAL)
      continue;
    /* a burst of packets can fill a link's event queue: tick to drain it and offer the packet again */
    if (a->listener && rnc_transfer_listener_input(a->listener, &event.node, unix_now, now) == RNC_NO_SPACE) {
      (void)rnc_transfer_listener_tick(a->listener, unix_now, now);
      (void)rnc_transfer_listener_input(a->listener, &event.node, unix_now, now);
    }
    if (a->client && rnc_transfer_client_input(a->client, &event.node, unix_now, now) == RNC_NO_SPACE) {
      (void)rnc_transfer_client_tick(a->client, unix_now, now);
      (void)rnc_transfer_client_input(a->client, &event.node, unix_now, now);
    }
  }
  now = monotonic_ms();
  if (a->listener)
    (void)rnc_transfer_listener_tick(a->listener, unix_now, now);
  if (a->client)
    (void)rnc_transfer_client_tick(a->client, unix_now, now);
  return 1;
}

/* Keeps the node running briefly so the link close and any queued packets
 * actually leave the socket before the process exits; otherwise the listener
 * keeps a link slot until its timeout. */
static void flush_out(app *a) {
  uint64_t start = monotonic_ms();
  while (monotonic_ms() - start < 300u && pump(a)) {
  }
}
/* The reference reads extra allowed identities from the first of /etc/rncp, ~/.config/rncp and ~/.rncp that
 * has an allowed_identities file: one hash per line, lines of other lengths are ignored. */
static int load_allowed_file(void) {
  static const char *places[] = {"/etc/rncp/allowed_identities", "~/.config/rncp/allowed_identities",
                                 "~/.rncp/allowed_identities"};
  char path[PATH_MAX], line[256];
  FILE *f = NULL;
  size_t k;
  for (k = 0; k < sizeof(places) / sizeof(*places) && !f; ++k)
    if (expand_home(places[k], path, sizeof(path)))
      f = fopen(path, "r");
  if (!f)
    return 1;
  while (fgets(line, sizeof(line), f)) {
    size_t n = strcspn(line, "\r\n");
    line[n] = 0;
    if (n != 32)
      continue;
    if (opt.config.allowed_count >= RNC_TRANSFER_ALLOWED ||
        !hex_decode(line, opt.config.allowed[opt.config.allowed_count], 16)) {
      fprintf(stderr, "Could not apply allowed identity %s from %s\n", line, path);
      fclose(f);
      return 0;
    }
    ++opt.config.allowed_count;
  }
  fclose(f);
  return 1;
}
static int listen_mode(rnc_identity *id, app *a) {
  uint8_t destination[16];
  uint64_t next_announce = 0;
  int announced = 0;
  if (rnc_node_add_destination(a->node, id, APP_NAME, NULL, 0, destination) !=
      RNC_OK)
    return 1;
  opt.config.stream = rx_stream;
  opt.config.context = (void *)1; /* tells rx_open it is the listener */
  opt.config.fetch_stream = opt.allow_fetch ? on_fetch : NULL;
  opt.config.allow_all = opt.no_auth;
  opt.config.no_compress = opt.no_compress;
  a->listener = rnc_transfer_listener_new(a->node, id, destination, &opt.config,
                                          secure_random, NULL);
  if (!a->listener)
    return 1;
  if (!opt.no_auth && !opt.config.allowed_count)
    fprintf(stderr,
            "No allowed identities configured, rncp will not accept any "
            "files!\n");
  fputs("rncp listening on <", stdout);
  print_hex(destination, 16);
  puts(">");
  fflush(stdout);
  tool_stamps_listen(a->node, opt.identity, opt.stamp_value);
  while (!stopping) {
    uint64_t now = monotonic_ms();
    if (!pump(a))
      break;
    tool_stamps_step();
    /* announce once the TCP link is up, then every -b seconds */
    if (opt.announce >= 0 && now >= next_announce && (!announced || opt.announce > 0) && tool_stamps_ready()) {
      rnc_host_status s;
      if (rnc_host_get_status(a->host, 1, &s) == RNC_OK && s.online) {
        (void)rnc_node_announce(a->node, destination, (uint64_t)time(NULL), now);
        announced = 1;
        next_announce = now + (uint64_t)opt.announce * 1000u;
      }
    }
  }
  tool_stamps_stop();
  return stopping ? 0 : 1;
}
/* Feeds what arrives while waiting for a path to the listener and client. */
static int await_callback(void *context, const rnc_host_event *event) {
  app *a = context;
  uint64_t unix_now = (uint64_t)time(NULL), now = monotonic_ms();
  if (event) {
    if (event->type == RNC_HOST_NODE && event->node.type == RNC_NODE_LOCAL) {
      if (a->listener)
        (void)rnc_transfer_listener_input(a->listener, &event->node, unix_now, now);
      if (a->client)
        (void)rnc_transfer_client_input(a->client, &event->node, unix_now, now);
    }
    return stopping != 0;
  }
  if (a->listener)
    (void)rnc_transfer_listener_tick(a->listener, unix_now, now);
  if (a->client)
    (void)rnc_transfer_client_tick(a->client, unix_now, now);
  return stopping != 0;
}
static int await_path(app *a, const uint8_t destination[16]) {
  return rnc_host_await_path(a->host, destination, opt.wait * 1000u,
                             await_callback, a) == RNC_OK;
}
/* -P: the rate the data moves at, and the rate the link's interface carried bytes at (every frame in either
 * direction, so it includes the protocol's own traffic and any compression), over a window of the last 32
 * samples as the reference averages. */
typedef struct rate_sample {
  double t, data, wire;
} rate_sample;
static rate_sample rate_window[32];
static size_t rate_count;
static void note_rates(app *a, double data_bytes, double *data_rate, double *wire_rate) {
  rnc_host_status status;
  rate_sample now;
  now.t = (double)monotonic_ms() / 1000.0;
  now.data = data_bytes;
  now.wire = rnc_host_get_status(a->host, 1, &status) == RNC_OK ? (double)(status.rx_bytes + status.tx_bytes) : 0.0;
  if (rate_count == sizeof(rate_window) / sizeof(*rate_window)) {
    memmove(rate_window, rate_window + 1, sizeof(rate_window) - sizeof(*rate_window));
    --rate_count;
  }
  rate_window[rate_count++] = now;
  *data_rate = *wire_rate = 0.0;
  if (now.t > rate_window[0].t) {
    *data_rate = 8.0 * (now.data - rate_window[0].data) / (now.t - rate_window[0].t);
    *wire_rate = 8.0 * (now.wire - rate_window[0].wire) / (now.t - rate_window[0].t);
  }
}
static void rate_text(double bits_per_second, char *out, size_t cap) {
  static const char *units[] = {"bps", "Kbps", "Mbps", "Gbps"};
  size_t u = 0;
  while (bits_per_second >= 1000.0 && u < 3) {
    bits_per_second /= 1000.0;
    ++u;
  }
  (void)snprintf(out, cap, "%.2f %s", bits_per_second, units[u]);
}
static int run_client(rnc_identity *id, app *a, const uint8_t destination[16],
                      const char *send_path) {
  uint64_t size = 0, timeout = UINT64_C(86400000); /* the transfer layer's own timeouts end a stalled transfer */
  rnc_transfer_result r;
  rnc_result status;
  int last_percent = -1, rc = 1;
  a->client = rnc_transfer_client_new(a->node, 0, secure_random, NULL);
  if (a->client)
    rnc_transfer_client_set_compression(a->client, !opt.no_compress);
  if (!a->client)
    return 1;
  if (!await_path(a, destination)) {
    fprintf(stderr, "Path to <");
    print_hex(destination, 16);
    fprintf(stderr, "> not found\n");
    return 1;
  }
  if (send_path) {
    struct stat st;
    int fd = open(send_path, O_RDONLY);
    char copy[PATH_MAX], *name;
    rnc_transfer_source source;
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode)) {
      fprintf(stderr, "Cannot send %s: not a readable file\n", send_path);
      if (fd >= 0)
        close(fd);
      return 1;
    }
    size = (uint64_t)st.st_size;
    snprintf(copy, sizeof(copy), "%s", send_path);
    name = basename(copy);
    memset(&source, 0, sizeof(source));
    source.size = size;
    source.read = file_read;
    source.context = (void *)(intptr_t)fd;
    source.release = file_release; /* closes the file, also when the call below fails */
    status = rnc_transfer_send_stream(a->client, destination, id, (const uint8_t *)name, strlen(name), &source, 1,
                                      timeout, (uint64_t)time(NULL), monotonic_ms());
    if (status != RNC_OK) {
      fprintf(stderr, "Could not start the transfer (%d)\n", (int)status);
      return 1;
    }
    printf("Sending %s (%llu bytes)\n", name, (unsigned long long)size);
  } else {
    status = rnc_transfer_fetch_stream(a->client, destination, id, (const uint8_t *)opt.fetch_path,
                                       strlen(opt.fetch_path), &rx_stream, NULL, 1, timeout, (uint64_t)time(NULL),
                                       monotonic_ms());
    if (status != RNC_OK) {
      fprintf(stderr, "Could not start the fetch (%d)\n", (int)status);
      return 1;
    }
    printf("Fetching %s\n", opt.fetch_path);
  }
  fflush(stdout);
  while (!stopping) {
    double progress;
    if (!pump(a))
      break;
    if (rnc_transfer_client_progress(a->client, 1, &progress) == RNC_OK) {
      int percent = (int)(progress * 100.0);
      if (!opt.silent && percent / 10 != last_percent / 10) {
        if (opt.phy_rates) {
          double data_rate, wire_rate;
          char data_text[32], wire_text[32];
          note_rates(a, progress * (double)size, &data_rate, &wire_rate);
          rate_text(data_rate, data_text, sizeof(data_text));
          rate_text(wire_rate, wire_text, sizeof(wire_text));
          fprintf(stderr, "Progress: %d%% - %s (%s at physical layer)\n", percent, data_text, wire_text);
        } else
          fprintf(stderr, "Progress: %d%%\n", percent);
        last_percent = percent;
      }
    }
    if (rnc_transfer_client_poll(a->client, &r, NULL, 0) == RNC_OK) {
      if (r.status == RNC_TRANSFER_DONE) {
        if (send_path) {
          puts("Transfer complete");
          rc = 0;
        } else if (!save_failed)
          rc = 0; /* rx_close has told where the file went */
        else
          fprintf(stderr, "The fetched file could not be saved\n");
      } else if (r.status == RNC_TRANSFER_NOT_FOUND)
        fprintf(stderr, "The remote does not have the file %s\n",
                opt.fetch_path ? opt.fetch_path : "");
      else if (r.status == RNC_TRANSFER_NOT_ALLOWED)
        fprintf(stderr, "Fetch request failed, fetching the file was not "
                        "allowed by the remote\n");
      else
        fprintf(stderr, "The transfer failed\n");
      break;
    }
  }
  flush_out(a);
  return rc;
}

static void usage(void) {
  fputs("usage: reticulum-c-cp --connect HOST:PORT --identity FILE\n"
        "         -l [-a IDENTITY_HASH]... [-n] [-s DIR] [-O] [-F [-j DIR]] [-b SECONDS]\n"
        "       | FILE DESTINATION [-w SECONDS]\n"
        "       | -f REMOTE_FILE DESTINATION [-s DIR] [-O] [-w SECONDS]\n",
        stderr);
}
int main(int argc, char **argv) {
  int i;
  const char *positional[2] = {NULL, NULL};
  size_t positional_count = 0;
  rnc_identity id;
  app a = {0};
  uint8_t destination[16];
  int rc;
  opt.announce = -1;
  opt.wait = DEFAULT_PATH_WAIT;
  opt.save = ".";
  opt.stamp_value = tool_stamp_default();
  for (i = 1; i < argc; ++i) {
    const char *arg = argv[i];
#define VALUE (i + 1 < argc ? argv[++i] : (usage(), exit(2), (char *)NULL))
    if (!strcmp(arg, "--connect"))
      opt.connect = VALUE;
    else if (!strcmp(arg, "--identity"))
      opt.identity = VALUE;
    else if (!strcmp(arg, "-l") || !strcmp(arg, "--listen"))
      opt.listen = 1;
    else if (!strcmp(arg, "--stamp-value")) {
      if (!tool_stamp_parse(VALUE, &opt.stamp_value))
        return usage(), 2;
    }
    else if (!strcmp(arg, "-n") || !strcmp(arg, "--no-auth"))
      opt.no_auth = 1;
    else if (!strcmp(arg, "-F") || !strcmp(arg, "--allow-fetch"))
      opt.allow_fetch = 1;
    else if (!strcmp(arg, "-O") || !strcmp(arg, "--overwrite"))
      opt.overwrite = 1;
    else if (!strcmp(arg, "-S") || !strcmp(arg, "--silent"))
      opt.silent = 1;
    else if (!strcmp(arg, "-C") || !strcmp(arg, "--no-compress"))
      opt.no_compress = 1;
    else if (!strcmp(arg, "-p") || !strcmp(arg, "--print-identity"))
      opt.print_identity = 1;
    else if (!strcmp(arg, "-P") || !strcmp(arg, "--phy-rates"))
      opt.phy_rates = 1;
    else if (!strcmp(arg, "-s") || !strcmp(arg, "--save"))
      opt.save = VALUE;
    else if (!strcmp(arg, "-j") || !strcmp(arg, "--jail"))
      opt.jail = VALUE;
    else if (!strcmp(arg, "-f") || !strcmp(arg, "--fetch"))
      opt.fetch = 1;
    else if (!strcmp(arg, "-b")) {
      char *end;
      opt.announce = strtol(VALUE, &end, 10);
      if (*end || opt.announce < 0)
        return usage(), 2;
    } else if (!strcmp(arg, "-w")) {
      char *end;
      unsigned long w = strtoul(VALUE, &end, 10);
      if (*end || !w || w > 3600)
        return usage(), 2;
      opt.wait = (unsigned)w;
    } else if (!strcmp(arg, "-a") || !strcmp(arg, "--allowed")) {
      if (opt.config.allowed_count >= RNC_TRANSFER_ALLOWED ||
          !hex_decode(VALUE, opt.config.allowed[opt.config.allowed_count], 16)) {
        fprintf(stderr, "Allowed identities are 32 hexadecimal characters\n");
        return 2;
      }
      ++opt.config.allowed_count;
    } else if (arg[0] != '-' && positional_count < 2)
      positional[positional_count++] = arg;
    else
      return usage(), 2;
  }
  if (opt.print_identity) {
    uint8_t name_hash[10];
    char label[33];
    size_t k;
    if (!opt.identity || positional_count)
      return usage(), 2;
    if (rnc_host_identity_load(opt.identity, secure_random, NULL, &id) != RNC_OK ||
        rnc_destination_hash(APP_NAME, &id, name_hash, destination) != RNC_OK) {
      fprintf(stderr, "Cannot load or create the identity file %s\n", opt.identity);
      return 1;
    }
    for (k = 0; k < 16; ++k)
      (void)snprintf(label + 2 * k, 3, "%02x", id.hash[k]);
    printf("Identity     : <%s>\n", label);
    fputs("Listening on : <", stdout);
    print_hex(destination, 16);
    puts(">");
    rnc_identity_clear(&id);
    return 0;
  }
  if (!opt.connect || !opt.identity)
    return usage(), 2;
  if (opt.listen ? positional_count != 0 || opt.fetch : positional_count != 2)
    return usage(), 2;
  if (opt.fetch)
    opt.fetch_path = positional[0];
  if (opt.jail && !opt.allow_fetch)
    return usage(), 2;
  if (!realpath(opt.save, opt.saved_dir)) {
    fprintf(stderr, "The save directory %s does not exist\n", opt.save);
    return 1;
  }
  if (opt.jail) {
    char expanded[PATH_MAX];
    if (!expand_home(opt.jail, expanded, sizeof(expanded)) ||
        !realpath(expanded, opt.jail_dir)) {
      fprintf(stderr, "The fetch jail %s does not exist\n", opt.jail);
      return 1;
    }
  }
  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);
  signal(SIGPIPE, SIG_IGN);
  if (!open_node(&id, &a.node, &a.host))
    return 1;
  if (opt.listen && !load_allowed_file())
    return 1;
  if (opt.listen)
    rc = listen_mode(&id, &a);
  else {
    const char *dest_text = positional[1];
    if (!hex_decode(dest_text, destination, 16)) {
      fprintf(stderr, "The destination must be 32 hexadecimal characters\n");
      return 2;
    }
    rc = run_client(&id, &a, destination, opt.fetch ? NULL : positional[0]);
  }
  rnc_transfer_listener_free(a.listener);
  rnc_transfer_client_free(a.client);
  rnc_host_free(a.host);
  rnc_node_free(a.node);
  rnc_identity_clear(&id);
  return rc;
}
