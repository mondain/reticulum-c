/* reticulum-c-cp: file transfer compatible with the reference rncp.
 *
 *   reticulum-c-cp --connect HOST:PORT --identity FILE -l [-a HASH]... [-n]
 *                  [-s DIR] [-O] [-F [-j DIR]] [-b SECONDS]
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
  int listen, fetch, no_auth, allow_fetch, overwrite;
  long announce; /* seconds between announces; -1 = never */
  unsigned wait;
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
/* Writes data to dir/name; an existing file is replaced with -O and otherwise
 * kept, saving as name.1, name.2 and so on. */
static int save_file(const char *dir, const char *name, const uint8_t *data,
                     size_t size, int overwrite, char *saved, size_t cap) {
  unsigned counter = 0;
  int fd;
  size_t written = 0;
  if (overwrite) {
    if (snprintf(saved, cap, "%s/%s", dir, name) >= (int)cap)
      return 0;
    (void)unlink(saved);
  }
  for (;;) {
    if (counter) {
      if (snprintf(saved, cap, "%s/%s.%u", dir, name, counter) >= (int)cap)
        return 0;
    } else if (snprintf(saved, cap, "%s/%s", dir, name) >= (int)cap)
      return 0;
    fd = open(saved, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd >= 0)
      break;
    if (errno != EEXIST || ++counter > 100000u)
      return 0;
  }
  while (written < size) {
    ssize_t n = write(fd, data + written, size - written);
    if (n <= 0) {
      close(fd);
      (void)unlink(saved);
      return 0;
    }
    written += (size_t)n;
  }
  return close(fd) == 0;
}
static rnc_result on_received(void *context, const uint8_t *identity_hash,
                              const uint8_t *name, size_t name_size,
                              const uint8_t *data, size_t size) {
  char base[256], saved[PATH_MAX];
  (void)context;
  if (!safe_name(name, name_size, base, sizeof(base))) {
    fprintf(stderr, "Ignoring a file with an invalid name\n");
    return RNC_INVALID;
  }
  if (!save_file(opt.saved_dir, base, data, size, opt.overwrite, saved,
                 sizeof(saved))) {
    fprintf(stderr, "Could not save %s: %s\n", base, strerror(errno));
    return RNC_STATE;
  }
  if (identity_hash) {
    fputs("Received from <", stdout);
    print_hex(identity_hash, 16);
    fputs(">\n", stdout);
  }
  printf("Saved received file to %s\n", saved);
  fflush(stdout);
  return RNC_OK;
}
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
static int on_fetch(void *context, const uint8_t *path, size_t path_size,
                    const uint8_t *identity_hash, uint8_t **data, size_t *size,
                    uint8_t name[RNC_TRANSFER_NAME_MAX], size_t *name_size) {
  char requested[PATH_MAX], expanded[PATH_MAX], file[PATH_MAX], real[PATH_MAX],
      jail_real[PATH_MAX], copy[PATH_MAX], *base;
  struct stat st;
  FILE *f;
  (void)context;
  (void)identity_hash;
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
        !normalise(joined, file, sizeof(file)) || !within(opt.jail_dir, file)) {
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
             !normalise(expanded, file, sizeof(file)))
    return RNC_FETCH_NOT_FOUND;
  if (stat(file, &st) || !S_ISREG(st.st_mode)) {
    printf("Client-requested file not found: %s\n", file);
    return RNC_FETCH_NOT_FOUND;
  }
  if ((uintmax_t)st.st_size > RNC_TRANSFER_MAX_SIZE) {
    fprintf(stderr, "Requested file is too large to send\n");
    return RNC_FETCH_NOT_FOUND;
  }
  f = fopen(file, "rb");
  *data = malloc(st.st_size ? (size_t)st.st_size : 1);
  if (!f || !*data || fread(*data, 1, (size_t)st.st_size, f) != (size_t)st.st_size) {
    if (f)
      fclose(f);
    free(*data);
    *data = NULL;
    return RNC_FETCH_NOT_FOUND;
  }
  fclose(f);
  *size = (size_t)st.st_size;
  snprintf(copy, sizeof(copy), "%s", file);
  base = basename(copy);
  *name_size = strlen(base);
  if (*name_size > RNC_TRANSFER_NAME_MAX)
    *name_size = RNC_TRANSFER_NAME_MAX;
  memcpy(name, base, *name_size);
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
    if (a->listener)
      (void)rnc_transfer_listener_input(a->listener, &event.node, unix_now, now);
    if (a->client)
      (void)rnc_transfer_client_input(a->client, &event.node, unix_now, now);
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
static int listen_mode(rnc_identity *id, app *a) {
  uint8_t destination[16];
  uint64_t next_announce = 0;
  int announced = 0;
  if (rnc_node_add_destination(a->node, id, APP_NAME, NULL, 0, destination) !=
      RNC_OK)
    return 1;
  opt.config.context = NULL;
  opt.config.received = on_received;
  opt.config.fetch = opt.allow_fetch ? on_fetch : NULL;
  opt.config.allow_all = opt.no_auth;
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
  while (!stopping) {
    uint64_t now = monotonic_ms();
    if (!pump(a))
      return 1;
    /* announce once the TCP link is up, then every -b seconds */
    if (opt.announce >= 0 && now >= next_announce && (!announced || opt.announce > 0)) {
      rnc_host_status s;
      if (rnc_host_get_status(a->host, 1, &s) == RNC_OK && s.online) {
        (void)rnc_node_announce(a->node, destination, (uint64_t)time(NULL), now);
        announced = 1;
        next_announce = now + (uint64_t)opt.announce * 1000u;
      }
    }
  }
  return 0;
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
static int run_client(rnc_identity *id, app *a, const uint8_t destination[16],
                      const char *send_path) {
  uint8_t *data = NULL, *result_data = NULL;
  size_t size = 0, capacity = RNC_TRANSFER_MAX_SIZE;
  rnc_transfer_result r;
  rnc_result status;
  uint64_t timeout = 120000u;
  int last_percent = -1, rc = 1;
  char base[PATH_MAX], saved[PATH_MAX];
  a->client = rnc_transfer_client_new(a->node, 0, secure_random, NULL);
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
    FILE *f = fopen(send_path, "rb");
    char copy[PATH_MAX], *name;
    if (!f || fstat(fileno(f), &st) || !S_ISREG(st.st_mode) ||
        (uintmax_t)st.st_size > RNC_TRANSFER_MAX_SIZE) {
      fprintf(stderr, "Cannot send %s: not a readable file of at most %u bytes\n",
              send_path, (unsigned)RNC_TRANSFER_MAX_SIZE);
      if (f)
        fclose(f);
      return 1;
    }
    size = (size_t)st.st_size;
    data = malloc(size ? size : 1);
    if (!data || fread(data, 1, size, f) != size) {
      fclose(f);
      free(data);
      return 1;
    }
    fclose(f);
    snprintf(copy, sizeof(copy), "%s", send_path);
    name = basename(copy);
    status = rnc_transfer_send(a->client, destination, id, (const uint8_t *)name,
                               strlen(name), data, size, 1, timeout,
                               (uint64_t)time(NULL), monotonic_ms());
    if (status != RNC_OK) {
      fprintf(stderr, "Could not start the transfer (%d)\n", (int)status);
      free(data);
      return 1;
    }
    printf("Sending %s (%zu bytes)\n", name, size);
  } else {
    status = rnc_transfer_fetch(a->client, destination, id,
                                (const uint8_t *)opt.fetch_path,
                                strlen(opt.fetch_path), 1, timeout,
                                (uint64_t)time(NULL), monotonic_ms());
    if (status != RNC_OK) {
      fprintf(stderr, "Could not start the fetch (%d)\n", (int)status);
      return 1;
    }
    printf("Fetching %s\n", opt.fetch_path);
  }
  fflush(stdout);
  result_data = malloc(capacity);
  if (!result_data) {
    free(data);
    return 1;
  }
  while (!stopping) {
    double progress;
    if (!pump(a))
      break;
    if (rnc_transfer_client_progress(a->client, 1, &progress) == RNC_OK) {
      int percent = (int)(progress * 100.0);
      if (percent / 10 != last_percent / 10) {
        fprintf(stderr, "Progress: %d%%\n", percent);
        last_percent = percent;
      }
    }
    if (rnc_transfer_client_poll(a->client, &r, result_data, capacity) ==
        RNC_OK) {
      if (r.status == RNC_TRANSFER_DONE) {
        if (send_path) {
          puts("Transfer complete");
          rc = 0;
        } else if (!safe_name(r.name, r.name_size, base, sizeof(base))) {
          fprintf(stderr, "The remote sent an invalid file name\n");
        } else if (!save_file(opt.saved_dir, base, result_data, r.size,
                              opt.overwrite, saved, sizeof(saved))) {
          fprintf(stderr, "Could not save %s: %s\n", base, strerror(errno));
        } else {
          printf("Saved fetched file to %s\n", saved);
          rc = 0;
        }
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
  free(data);
  OPENSSL_cleanse(result_data, capacity);
  free(result_data);
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
  for (i = 1; i < argc; ++i) {
    const char *arg = argv[i];
#define VALUE (i + 1 < argc ? argv[++i] : (usage(), exit(2), (char *)NULL))
    if (!strcmp(arg, "--connect"))
      opt.connect = VALUE;
    else if (!strcmp(arg, "--identity"))
      opt.identity = VALUE;
    else if (!strcmp(arg, "-l") || !strcmp(arg, "--listen"))
      opt.listen = 1;
    else if (!strcmp(arg, "-n") || !strcmp(arg, "--no-auth"))
      opt.no_auth = 1;
    else if (!strcmp(arg, "-F") || !strcmp(arg, "--allow-fetch"))
      opt.allow_fetch = 1;
    else if (!strcmp(arg, "-O") || !strcmp(arg, "--overwrite"))
      opt.overwrite = 1;
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
