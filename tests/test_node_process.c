#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <reticulum_c/rnc_host.h>
#include <reticulum_c/rnc_discovery.h>
#include <reticulum_c/rnc_ipc.h>
#include <reticulum_c/rnc_link.h>
#include <reticulum_c/rnc_service.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d %s errno=%d\n", __FILE__, __LINE__, #x, errno);   \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static void config_file(const char *path, const char *text) {
  FILE *f = fopen(path, "w");
  CHECK(f);
  CHECK(fputs(text, f) >= 0 && !fclose(f));
}
static int run_check(const char *exe, const char *config) {
  pid_t p = fork();
  int status;
  CHECK(p >= 0);
  if (!p) {
    execl(exe, exe, "--config", config, "--check", (char *)NULL);
    _exit(127);
  }
  CHECK(waitpid(p, &status, 0) == p && WIFEXITED(status));
  return WEXITSTATUS(status);
}
static const char *valid =
    "[reticulum]\nenable_transport = Yes\nshare_instance = "
    "No\n[interfaces]\n[[Local TCP]]\ntype = TCPServerInterface\nenabled = "
    "Yes\nlisten_ip = 127.0.0.1\nlisten_port = 0\n";
static void cli(const char *exe) {
  char dir[] = "/tmp/rnc-node-cli-XXXXXX", path[256];
  CHECK(mkdtemp(dir));
  CHECK(snprintf(path, sizeof(path), "%s/config", dir) > 0);
  config_file(path, valid);
  CHECK(run_check(exe, path) == 0);
  config_file(
      path,
      "[interfaces]\n[[Broken]]\ntype=TCPServerInterface\nlisten_port=70000\n");
  CHECK(run_check(exe, path) != 0);
  config_file(path, "[reticulum]\nshare_instance=Yes\n");
  CHECK(run_check(exe, path) != 0);
  config_file(path, "[interfaces]\n[[Bad]]\ntype=UnknownInterface\n");
  CHECK(run_check(exe, path) != 0);
  CHECK(!unlink(path) && !rmdir(dir));
  puts("node CLI tests passed");
}
static pid_t start(const char *exe, const char *cfg, const char *key,
                   const char *admin, int *out) {
  int fds[2];
  pid_t p;
  CHECK(!pipe(fds));
  p = fork();
  CHECK(p >= 0);
  if (!p) {
    close(fds[0]);
    CHECK(dup2(fds[1], STDOUT_FILENO) >= 0);
    close(fds[1]);
    execl(exe, exe, "--config", cfg, "--identity", key, "--admin", admin,
          (char *)NULL);
    _exit(127);
  }
  close(fds[1]);
  *out = fds[0];
  return p;
}
static void ready_line(int fd, char identity[33]) {
  char buf[4096];
  size_t n = 0;
  unsigned tries;
  for (tries = 0; tries < 100; ++tries) {
    struct pollfd p = {fd, POLLIN, 0};
    int r = poll(&p, 1, 100);
    CHECK(r >= 0);
    if (r > 0) {
      ssize_t got = read(fd, buf + n, sizeof(buf) - 1 - n);
      CHECK(got > 0);
      n += (size_t)got;
      buf[n] = 0;
      {
        char *id = strstr(buf, "Ready identity=");
        if (id) {
          CHECK(strlen(id + 15) >= 32);
          memcpy(identity, id + 15, 32);
          identity[32] = 0;
          return;
        }
      }
      CHECK(n < sizeof(buf) - 1);
    }
  }
  CHECK(0);
}
static unsigned admin_status(const char *path) {
  struct sockaddr_un addr;
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  char buf[4096];
  ssize_t n;
  CHECK(fd >= 0);
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  CHECK(strlen(path) < sizeof(addr.sun_path));
  strcpy(addr.sun_path, path);
  CHECK(!connect(fd, (struct sockaddr *)&addr, sizeof(addr)));
  CHECK(write(fd, "STATUS\n", 7) == 7);
  n = read(fd, buf, sizeof(buf) - 1);
  CHECK(n > 0);
  buf[n] = 0;
  CHECK(strstr(buf, "interface id=") && strstr(buf, "port="));
  close(fd);
  return (unsigned)strtoul(strstr(buf, "port=") + 5, NULL, 10);
}
static void stop(pid_t pid, int fd) {
  int status;
  CHECK(!kill(pid, SIGTERM));
  CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
        !WEXITSTATUS(status));
  close(fd);
}
static void network(const char *exe) {
  char dir[] = "/tmp/rnc-node-proc-XXXXXX", cfg[256], key[256], admin[256],
       first[33], second[33];
  int fd;
  pid_t p;
  struct stat st;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  config_file(cfg, valid);
  p = start(exe, cfg, key, admin, &fd);
  ready_line(fd, first);
  CHECK(!stat(key, &st) && st.st_size == 64 && (st.st_mode & 0777) == 0600);
  CHECK(!stat(admin, &st) && (st.st_mode & 0777) == 0600);
  admin_status(admin);
  CHECK(!kill(p, SIGHUP));
  {
    struct timespec t = {0, 100000000};
    nanosleep(&t, NULL);
  }
  admin_status(admin);
  stop(p, fd);
  CHECK(lstat(admin, &st) < 0 && errno == ENOENT);
  p = start(exe, cfg, key, admin, &fd);
  ready_line(fd, second);
  CHECK(!strcmp(first, second));
  admin_status(admin);
  stop(p, fd);
  CHECK(!unlink(cfg) && !unlink(key) && !rmdir(dir));
  puts("node process tests passed");
}

static unsigned unused_port(void) {
  struct sockaddr_in addr;
  socklen_t size = sizeof(addr);
  unsigned port;
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  CHECK(fd >= 0);
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(!bind(fd, (struct sockaddr *)&addr, sizeof(addr)) &&
        !getsockname(fd, (struct sockaddr *)&addr, &size));
  port = ntohs(addr.sin_port);
  close(fd);
  return port;
}
static int tcp_connect(unsigned port) {
  struct sockaddr_in addr;
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  CHECK(fd >= 0);
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons((uint16_t)port);
  CHECK(!connect(fd, (struct sockaddr *)&addr, sizeof(addr)));
  return fd;
}
static uint64_t now_ms(void) {
  struct timespec t;
  CHECK(!clock_gettime(CLOCK_MONOTONIC, &t));
  return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
static rnc_result rng(void *context, uint8_t *out, size_t size) {
  unsigned *s = context;
  size_t i;
  for (i = 0; i < size; ++i)
    out[i] = (uint8_t)(*s)++;
  return RNC_OK;
}
static int contains(const uint8_t *data, size_t size, const char *needle) {
  size_t n = strlen(needle), i;
  if (n > size)
    return 0;
  for (i = 0; i <= size - n; ++i)
    if (!memcmp(data + i, needle, n))
      return 1;
  return 0;
}
static void rpc_client_test(unsigned port, const uint8_t key[32],
                            int valid_key) {
  int fd = tcp_connect(port), authenticated = 0, message = 0, closed = 0;
  unsigned random = 19, tries;
  rnc_rpc *rpc = rnc_rpc_new(key, 32, 0, rng, &random, RNC_RPC_MESSAGE_MAX);
  rnc_rpc_event event;
  CHECK(rpc && rnc_rpc_start(rpc, now_ms()) == RNC_OK);
  for (tries = 0; tries < 200 && !message && !closed; ++tries) {
    struct pollfd p = {fd, POLLIN, 0};
    uint8_t data[4096];
    ssize_t size;
    size_t offset = 0, consumed;
    while (rnc_rpc_poll(rpc, &event) == RNC_OK) {
      if (event.type == RNC_RPC_SEND) {
        size_t sent = 0;
        while (sent < event.size) {
          ssize_t n = write(fd, event.data + sent, event.size - sent);
          CHECK(n > 0);
          sent += (size_t)n;
        }
      } else if (event.type == RNC_RPC_AUTHENTICATED) {
        rnc_rpc_writer w;
        size_t n;
        authenticated = 1;
        rnc_rpc_writer_init(&w, data, sizeof(data));
        CHECK(rnc_rpc_write_map(&w, 1) == RNC_OK &&
              rnc_rpc_write_string(&w, "get") == RNC_OK &&
              rnc_rpc_write_string(&w, "interface_stats") == RNC_OK &&
              rnc_rpc_writer_finish(&w, &n) == RNC_OK);
        CHECK(rnc_rpc_send(rpc, data, n, now_ms()) == RNC_OK);
      } else if (event.type == RNC_RPC_MESSAGE) {
        CHECK(valid_key && authenticated &&
              contains(event.data, event.size, "interfaces") &&
              contains(event.data, event.size,
                       "LocalInterface[Shared Instance]") &&
              contains(event.data, event.size, "rxb"));
        message = 1;
      } else if (event.type == RNC_RPC_CLOSED)
        closed = 1;
    }
    if (message || closed)
      break;
    CHECK(poll(&p, 1, 50) >= 0);
    if (p.revents & POLLIN) {
      size = read(fd, data, sizeof(data));
      if (!size) {
        closed = 1;
        break;
      }
      CHECK(size > 0);
      while (offset < (size_t)size) {
        rnc_result r = rnc_rpc_input(rpc, data + offset, (size_t)size - offset,
                                     &consumed, now_ms());
        offset += consumed;
        if (r != RNC_OK && r != RNC_AGAIN) {
          CHECK(!valid_key);
          closed = 1;
          break;
        }
        CHECK(consumed || r == RNC_AGAIN);
        if (!consumed)
          break;
      }
    }
    CHECK(rnc_rpc_tick(rpc, now_ms()) == RNC_OK);
  }
  CHECK(valid_key ? message : (!message && closed));
  rnc_rpc_free(rpc);
  close(fd);
}
static void shared_data_test(unsigned local_port, unsigned world_port) {
  int world = tcp_connect(world_port), local = tcp_connect(local_port);
  uint8_t private_key[64] = {7}, raw[RNC_MAX_MTU], framed[RNC_HOST_FRAME_MAX],
          decoded[RNC_MAX_FRAME], command;
  size_t n, m, i;
  unsigned random = 12, tries;
  int found = 0;
  rnc_identity id;
  rnc_packet packet;
  rnc_announce announce;
  rnc_host_framer parser = {0};
  CHECK(rnc_identity_from_private(&id, private_key) == RNC_OK &&
        rnc_announce_create(&id, "reticulum_c.shared.test", NULL, 0,
                            (uint64_t)time(NULL), rng, &random,
                            &packet) == RNC_OK);
  CHECK(rnc_packet_encode(&packet, raw, sizeof(raw), &n) == RNC_OK &&
        rnc_host_frame_encode(RNC_HOST_HDLC, 0, raw, n, framed, sizeof(framed),
                              &m) == RNC_OK);
  CHECK(write(local, framed, m) == (ssize_t)m);
  for (tries = 0; tries < 100 && !found; ++tries) {
    struct pollfd p = {world, POLLIN, 0};
    CHECK(poll(&p, 1, 50) >= 0);
    if (!(p.revents & POLLIN))
      continue;
    {
      ssize_t size = read(world, framed, sizeof(framed));
      CHECK(size > 0);
      for (i = 0; i < (size_t)size; ++i)
        if (rnc_host_frame_feed(&parser, RNC_HOST_HDLC, framed[i], &command,
                                decoded, sizeof(decoded), &n) == RNC_OK) {
          rnc_packet received;
          CHECK(rnc_packet_decode(decoded, n, &received) == RNC_OK);
          if ((received.flags & 3u) == RNC_ANNOUNCE &&
              !memcmp(received.destination, packet.destination, 16)) {
            CHECK(received.hops == 0 &&
                  rnc_announce_verify(&received, &announce) == RNC_OK);
            found = 1;
          }
        }
    }
  }
  CHECK(found);
  close(local);
  close(world);
  rnc_identity_clear(&id);
}
static void remove_tree(const char *path) {
  struct stat st;
  DIR *dir;
  struct dirent *entry;
  if (lstat(path, &st) < 0)
    return;
  if (!S_ISDIR(st.st_mode)) {
    CHECK(!unlink(path));
    return;
  }
  dir = opendir(path);
  CHECK(dir);
  while ((entry = readdir(dir)) != NULL) {
    char child[1024];
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;
    CHECK(snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) <
          (int)sizeof(child));
    remove_tree(child);
  }
  closedir(dir);
  CHECK(!rmdir(path));
}
static void rns_status(const char *python, const char *reference,
                       const char *dir) {
  int fds[2], status;
  pid_t child;
  char out[65536];
  size_t used = 0;
  unsigned tries;
  CHECK(!pipe(fds));
  child = fork();
  CHECK(child >= 0);
  if (!child) {
    close(fds[0]);
    CHECK(dup2(fds[1], STDOUT_FILENO) >= 0 && dup2(fds[1], STDERR_FILENO) >= 0);
    close(fds[1]);
    CHECK(!setenv("PYTHONPATH", reference, 1));
    execl(python, python, "-m", "RNS.Utilities.rnstatus", "--config", dir,
          "--json", (char *)NULL);
    _exit(127);
  }
  close(fds[1]);
  for (tries = 0; tries < 200; ++tries) {
    struct pollfd p = {fds[0], POLLIN, 0};
    int r = poll(&p, 1, 50);
    CHECK(r >= 0);
    if (p.revents & (POLLIN | POLLHUP)) {
      ssize_t n = read(fds[0], out + used, sizeof(out) - 1 - used);
      CHECK(n >= 0);
      if (!n)
        break;
      used += (size_t)n;
      CHECK(used < sizeof(out) - 1);
    }
  }
  CHECK(tries < 200);
  out[used] = 0;
  close(fds[0]);
  CHECK(waitpid(child, &status, 0) == child);
  if (!WIFEXITED(status) || WEXITSTATUS(status) || !strstr(out, "interfaces") ||
      !strstr(out, "LocalInterface[Shared Instance]")) {
    fprintf(stderr, "RNS rnstatus output:\n%s\n", out);
    CHECK(0);
  }
}
static pid_t start_with_state(const char *exe, const char *cfg,
                              const char *key, const char *admin,
                              const char *state, int *out) {
  int fds[2];
  pid_t p;
  CHECK(!pipe(fds));
  p = fork();
  CHECK(p >= 0);
  if (!p) {
    close(fds[0]);
    CHECK(dup2(fds[1], STDOUT_FILENO) >= 0);
    close(fds[1]);
    execl(exe, exe, "--config", cfg, "--identity", key, "--admin", admin,
          "--state", state, (char *)NULL);
    _exit(127);
  }
  close(fds[1]);
  *out = fds[0];
  return p;
}
static void admin_command(const char *path, const char *command, char *reply,
                          size_t size) {
  struct sockaddr_un addr;
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  char line[256];
  ssize_t n;
  CHECK(fd >= 0 && size > 1);
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, path);
  CHECK(!connect(fd, (struct sockaddr *)&addr, sizeof(addr)));
  CHECK(snprintf(line, sizeof(line), "%s\n", command) > 0);
  CHECK(write(fd, line, strlen(line)) == (ssize_t)strlen(line));
  n = read(fd, reply, size - 1);
  CHECK(n > 0);
  reply[n] = 0;
  close(fd);
}
/* Blackhole entries are managed from the admin socket and survive a restart. */
static void blackhole(const char *exe) {
  char dir[] = "/tmp/rnc-node-bh-XXXXXX", cfg[256], key[256], admin[256],
       state[256], file[300], reply[1024], id[33];
  const char *hash = "11111111111111111111111111111111";
  int fd;
  pid_t p;
  struct stat st;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(state, sizeof(state), "%s/state", dir) > 0);
  CHECK(snprintf(file, sizeof(file), "%s.blackhole", state) > 0);
  config_file(cfg, valid);
  p = start_with_state(exe, cfg, key, admin, state, &fd);
  ready_line(fd, id);
  admin_command(admin, "BLACKHOLES", reply, sizeof(reply));
  CHECK(!strncmp(reply, "EMPTY", 5));
  admin_command(admin, "BLACKHOLE 11111111111111111111111111111111 0 spam run",
                reply, sizeof(reply));
  CHECK(!strncmp(reply, "OK", 2));
  admin_command(admin, "BLACKHOLE 11111111111111111111111111111111", reply,
                sizeof(reply));
  CHECK(strstr(reply, "EXISTS"));
  admin_command(admin, "BLACKHOLE not-hex", reply, sizeof(reply));
  CHECK(strstr(reply, "ERROR"));
  admin_command(admin, "BLACKHOLES", reply, sizeof(reply));
  CHECK(strstr(reply, hash) && strstr(reply, "reason=spam run"));
  CHECK(!stat(file, &st) && (st.st_mode & 0777) == 0600);
  stop(p, fd);
  /* restart: the entry is loaded back */
  p = start_with_state(exe, cfg, key, admin, state, &fd);
  ready_line(fd, id);
  admin_command(admin, "BLACKHOLES", reply, sizeof(reply));
  CHECK(strstr(reply, hash) && strstr(reply, "reason=spam run"));
  admin_command(admin, "UNBLACKHOLE 11111111111111111111111111111111", reply,
                sizeof(reply));
  CHECK(!strncmp(reply, "OK", 2));
  admin_command(admin, "UNBLACKHOLE 11111111111111111111111111111111", reply,
                sizeof(reply));
  CHECK(strstr(reply, "NOT_FOUND"));
  stop(p, fd);
  p = start_with_state(exe, cfg, key, admin, state, &fd);
  ready_line(fd, id);
  admin_command(admin, "BLACKHOLES", reply, sizeof(reply));
  CHECK(!strncmp(reply, "EMPTY", 5));
  stop(p, fd);
  remove_tree(dir);
  puts("node blackhole tests passed");
}
/* Runs a reference utility against the shared instance and returns its
 * output; fails the test if it exits non-zero. */
static void reference_tool(const char *python, const char *reference,
                           const char *module, char *const args[], char *out,
                           size_t size) {
  int fds[2], status;
  pid_t child;
  size_t used = 0;
  unsigned tries;
  char *argv[16];
  size_t k = 0, a;
  CHECK(!pipe(fds));
  argv[k++] = (char *)python;
  argv[k++] = "-m";
  argv[k++] = (char *)module;
  for (a = 0; args[a] && k < 14; ++a)
    argv[k++] = args[a];
  argv[k] = NULL;
  child = fork();
  CHECK(child >= 0);
  if (!child) {
    close(fds[0]);
    CHECK(dup2(fds[1], STDOUT_FILENO) >= 0 && dup2(fds[1], STDERR_FILENO) >= 0);
    close(fds[1]);
    CHECK(!setenv("PYTHONPATH", reference, 1));
    execv(python, argv);
    _exit(127);
  }
  close(fds[1]);
  for (tries = 0; tries < 300; ++tries) {
    struct pollfd p = {fds[0], POLLIN, 0};
    CHECK(poll(&p, 1, 50) >= 0);
    if (p.revents & (POLLIN | POLLHUP)) {
      ssize_t n = read(fds[0], out + used, size - 1 - used);
      CHECK(n >= 0);
      if (!n)
        break;
      used += (size_t)n;
      CHECK(used < size - 1);
    }
  }
  CHECK(tries < 300);
  out[used] = 0;
  close(fds[0]);
  CHECK(waitpid(child, &status, 0) == child);
  if (!WIFEXITED(status) || WEXITSTATUS(status)) {
    fprintf(stderr, "%s failed:\n%s\n", module, out);
    CHECK(0);
  }
}
/* The reference's rnpath manages the blackhole list over the shared-instance
 * RPC: add with duration and reason, list, then lift. */
static void rns_blackhole(const char *python, const char *reference,
                          const char *dir, const char *admin) {
  const char *hash = "22222222222222222222222222222222";
  char out[8192], reply[1024];
  char *add[] = {"--config", (char *)dir, "-B", (char *)hash, "--duration",
                 "1",        "--reason", "oracle", NULL};
  char *list[] = {"--config", (char *)dir, "-b", NULL};
  char *lift[] = {"--config", (char *)dir, "-U", (char *)hash, NULL};
  reference_tool(python, reference, "RNS.Utilities.rnpath", add, out,
                 sizeof(out));
  admin_command(admin, "BLACKHOLES", reply, sizeof(reply));
  CHECK(strstr(reply, hash) && strstr(reply, "reason=oracle") &&
        !strstr(reply, "until=0"));
  reference_tool(python, reference, "RNS.Utilities.rnpath", list, out,
                 sizeof(out));
  if (!strstr(out, "22222222") || !strstr(out, "oracle")) {
    fprintf(stderr, "rnpath -b output:\n%s\n", out);
    CHECK(0);
  }
  reference_tool(python, reference, "RNS.Utilities.rnpath", lift, out,
                 sizeof(out));
  admin_command(admin, "BLACKHOLES", reply, sizeof(reply));
  CHECK(!strncmp(reply, "EMPTY", 5));
}
/* End-to-end remote management: a C client reaches the daemon's
 * rnstransport.remote.management destination over TCP, identifies, and asks
 * for /status. Only allow-listed identities get an answer. */
typedef struct mgmt_client {
  rnc_identity id;
  rnc_node *node;
  rnc_host *host;
  rnc_link *link;
  rnc_service *service;
  unsigned seed;
} mgmt_client;
static rnc_result mgmt_rng(void *context, uint8_t *out, size_t size) {
  unsigned *s = context;
  size_t i;
  for (i = 0; i < size; ++i) {
    *s = *s * 1664525u + 1013904223u;
    out[i] = (uint8_t)(*s >> 24);
  }
  return RNC_OK;
}
/* Returns 1 with the response copied out, 0 if the request timed out. */
static int mgmt_status(unsigned port, const uint8_t daemon_private[64],
                       uint8_t *response, size_t capacity, size_t *size) {
  mgmt_client c = {0};
  rnc_identity daemon_id;
  rnc_host_config tcp = {0};
  rnc_route route;
  rnc_service_event event;
  uint8_t destination[16], link_address[16], request_id[16], name_hash[10];
  const uint8_t include_link_count[2] = {0x91, 0xc3}; /* [true] */
  uint64_t now = 1000, deadline;
  int done = 0, result = 0, path_requested = 0, request_sent = 0;
  c.seed = 42;
  CHECK(rnc_identity_generate(&c.id, mgmt_rng, &c.seed) == RNC_OK);
  CHECK(rnc_identity_from_private(&daemon_id, daemon_private) == RNC_OK);
  CHECK(rnc_destination_hash("rnstransport.remote.management", &daemon_id,
                             name_hash, destination) == RNC_OK);
  c.node = rnc_node_new(&c.id, 0, mgmt_rng, &c.seed);
  c.host = c.node ? rnc_host_new(c.node) : NULL;
  CHECK(c.host);
  tcp.kind = RNC_HOST_TCP_CONNECT;
  tcp.address = "127.0.0.1";
  tcp.port = (uint16_t)port;
  CHECK(rnc_host_add(c.host, 1, &tcp) == RNC_OK);
  deadline = now + 8000;
  while (!done && now < deadline) {
    rnc_host_event he;
    rnc_link_event le;
    now += 10;
    CHECK(rnc_host_step(c.host, 5, (uint64_t)time(NULL), now) == RNC_OK);
    if (!c.link && (!path_requested || now % 500 == 0)) {
      (void)rnc_node_request_path(c.node, destination, now);
      path_requested = 1;
    }
    if (!c.link && rnc_node_lookup(c.node, destination, now, &route) == RNC_OK) {
      c.link = rnc_link_new(mgmt_rng, &c.seed);
      CHECK(c.link && rnc_link_open(c.link, &route.announce, now) == RNC_OK);
      CHECK(rnc_link_address(c.link, link_address) == RNC_OK);
      CHECK(rnc_node_bind_link_on(c.node, link_address, route.interface_id) ==
            RNC_OK);
      c.service = rnc_service_new(c.link, 65536, mgmt_rng, &c.seed);
      CHECK(c.service);
    }
    while (rnc_host_poll(c.host, &he) == RNC_OK)
      if (he.type == RNC_HOST_NODE && he.node.type == RNC_NODE_LOCAL && c.link)
        CHECK(rnc_link_input(c.link, &he.node.packet, now) == RNC_OK);
    if (!c.link)
      continue;
    CHECK(rnc_link_tick(c.link, now) == RNC_OK);
    while (rnc_link_poll(c.link, &le) == RNC_OK) {
      if (le.type == RNC_LINK_SEND)
        CHECK(rnc_node_send(c.node, &le.packet, (uint64_t)time(NULL), now) ==
              RNC_OK);
      else if (le.type == RNC_LINK_PACKET ||
               le.type == RNC_LINK_RESOURCE_PACKET ||
               le.type == RNC_LINK_CLOSED)
        (void)rnc_service_input(c.service, &le, now);
    }
    if (rnc_link_is_active(c.link) && !request_sent) {
      CHECK(rnc_link_identify(c.link, &c.id, now) == RNC_OK);
      CHECK(rnc_service_request(c.service, "/status", include_link_count, 2,
                                (double)time(NULL), now, 3000,
                                request_id) == RNC_OK);
      request_sent = 1;
    }
    (void)rnc_service_pump(c.service, now);
    (void)rnc_service_tick(c.service, now);
    for (;;) {
      size_t got = 0;
      if (rnc_service_poll(c.service, &event, response, capacity, &got) !=
          RNC_OK)
        break;
      if (event.type == RNC_SERVICE_RESPONSE) {
        *size = got;
        result = 1;
        done = 1;
      } else if (event.type == RNC_SERVICE_TIMEOUT)
        done = 1;
    }
  }
  if (c.service)
    rnc_service_free(c.service);
  if (c.link)
    rnc_link_free(c.link);
  rnc_host_free(c.host);
  rnc_node_free(c.node);
  return result;
}
static void management(const char *exe) {
  char dir[] = "/tmp/rnc-node-mgmt-XXXXXX", cfg[256], key[256], admin[256],
       text[1024], id[33];
  unsigned port = unused_port(), seed = 42;
  rnc_identity client;
  uint8_t private_key[64], response[65536];
  char allowed[33];
  size_t size, k, i;
  int fd, keyfd;
  pid_t p;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  /* the client the test will use is the first identity from seed 42 */
  CHECK(rnc_identity_generate(&client, mgmt_rng, &seed) == RNC_OK);
  for (k = 0; k < 16; ++k)
    CHECK(snprintf(allowed + 2 * k, 3, "%02x", client.hash[k]) == 2);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = No\nshare_instance = No\n"
                 "enable_remote_management = Yes\n"
                 "remote_management_allowed = %s\n"
                 "[interfaces]\n[[TCP]]\ntype = TCPServerInterface\n"
                 "listen_ip = 127.0.0.1\nlisten_port = %u\n",
                 allowed, port) > 0);
  config_file(cfg, text);
  p = start(exe, cfg, key, admin, &fd);
  ready_line(fd, id);
  keyfd = open(key, O_RDONLY);
  CHECK(keyfd >= 0 && read(keyfd, private_key, 64) == 64);
  close(keyfd);
  CHECK(mgmt_status(port, private_key, response, sizeof(response), &size));
  /* [ {interfaces: [...], ...}, link_count ] */
  CHECK(size > 20 && response[0] == 0x92 &&
        (response[1] == 0xde || (response[1] & 0xf0) == 0x80));
  {
    int found = 0;
    for (i = 0; i + 10 <= size; ++i)
      if (!memcmp(response + i, "interfaces", 10))
        found = 1;
    CHECK(found);
  }
  stop(p, fd);
  /* a client that is not on the list gets nothing */
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = No\nshare_instance = No\n"
                 "enable_remote_management = Yes\n"
                 "remote_management_allowed = 00000000000000000000000000000001\n"
                 "[interfaces]\n[[TCP]]\ntype = TCPServerInterface\n"
                 "listen_ip = 127.0.0.1\nlisten_port = %u\n",
                 port) > 0);
  config_file(cfg, text);
  p = start(exe, cfg, key, admin, &fd);
  ready_line(fd, id);
  CHECK(!mgmt_status(port, private_key, response, sizeof(response), &size));
  stop(p, fd);
  remove_tree(dir);
  puts("node remote management tests passed");
}
/* Blackhole sources: a daemon subscribed to another daemon's published list
 * picks up its entries, keeps them across a restart, and never lets a source
 * override what it listed itself. */
static void wait_for(const char *admin, const char *command, const char *needle,
                     unsigned seconds, char *reply, size_t size) {
  unsigned waited;
  for (waited = 0; waited < seconds * 10; ++waited) {
    struct timespec t = {0, 100000000};
    admin_command(admin, command, reply, size);
    if (strstr(reply, needle))
      return;
    nanosleep(&t, NULL);
  }
  fprintf(stderr, "never saw \"%s\"; last reply:\n%s\n", needle, reply);
  CHECK(0);
}
static void blackhole_sources(const char *exe) {
  char dir[] = "/tmp/rnc-node-src-XXXXXX", acfg[256], akey[256], aadmin[256],
       bcfg[256], bkey[256], badmin[256], bstate[256], text[1024], aid[33],
       bid[33], reply[2048], source_file[300];
  unsigned port = unused_port();
  int afd, bfd;
  pid_t a, b;
  struct stat st;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(acfg, sizeof(acfg), "%s/a.config", dir) > 0);
  CHECK(snprintf(akey, sizeof(akey), "%s/a.identity", dir) > 0);
  CHECK(snprintf(aadmin, sizeof(aadmin), "%s/a.admin", dir) > 0);
  CHECK(snprintf(bcfg, sizeof(bcfg), "%s/b.config", dir) > 0);
  CHECK(snprintf(bkey, sizeof(bkey), "%s/b.identity", dir) > 0);
  CHECK(snprintf(badmin, sizeof(badmin), "%s/b.admin", dir) > 0);
  CHECK(snprintf(bstate, sizeof(bstate), "%s/b.state", dir) > 0);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = No\nshare_instance = No\n"
                 "publish_blackhole = Yes\n[interfaces]\n[[TCP]]\n"
                 "type = TCPServerInterface\nlisten_ip = 127.0.0.1\n"
                 "listen_port = %u\n",
                 port) > 0);
  config_file(acfg, text);
  a = start(exe, acfg, akey, aadmin, &afd);
  ready_line(afd, aid);
  admin_command(aadmin,
                "BLACKHOLE 55555555555555555555555555555555 0 from source",
                reply, sizeof(reply));
  CHECK(!strncmp(reply, "OK", 2));
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = No\nshare_instance = No\n"
                 "blackhole_sources = %s\nblackhole_initial_wait = 1\n"
                 "[interfaces]\n[[Upstream]]\ntype = TCPClientInterface\n"
                 "target_host = 127.0.0.1\ntarget_port = %u\n"
                 "reconnect_wait = 1\n",
                 aid, port) > 0);
  config_file(bcfg, text);
  b = start_with_state(exe, bcfg, bkey, badmin, bstate, &bfd);
  ready_line(bfd, bid);
  /* B asks for a path to A's list, links, requests it and merges the result */
  admin_command(badmin,
                "BLACKHOLE 66666666666666666666666666666666 0 mine", reply,
                sizeof(reply));
  CHECK(!strncmp(reply, "OK", 2));
  wait_for(badmin, "BLACKHOLES", "55555555555555555555555555555555", 40, reply,
           sizeof(reply));
  CHECK(strstr(reply, "reason=from source"));
  {
    char expected[64];
    CHECK(snprintf(expected, sizeof(expected), "source=%s", aid) > 0);
    CHECK(strstr(reply, expected)); /* attributed to the subscribed source */
  }
  CHECK(snprintf(source_file, sizeof(source_file), "%s.blackhole.%s", bstate,
                 aid) > 0);
  CHECK(!stat(source_file, &st) && (st.st_mode & 0777) == 0600);
  stop(b, bfd);
  stop(a, afd);
  /* with the source gone, a restart still has its entries */
  b = start_with_state(exe, bcfg, bkey, badmin, bstate, &bfd);
  ready_line(bfd, bid);
  admin_command(badmin, "BLACKHOLES", reply, sizeof(reply));
  CHECK(strstr(reply, "55555555555555555555555555555555") &&
        strstr(reply, "66666666666666666666666666666666"));
  stop(b, bfd);
  remove_tree(dir);
  puts("node blackhole source tests passed");
}
/* Probe responder: a C client sends a DATA packet to rnstransport.probe and
 * must get a valid delivery proof back. */
static int probe_delivered(unsigned port, const uint8_t daemon_private[64]) {
  mgmt_client c = {0};
  rnc_identity daemon_id;
  rnc_host_config tcp = {0};
  rnc_route route;
  uint8_t destination[16], name_hash[10], hash[32];
  uint64_t now = 1000, deadline = 9000;
  int sent = 0, result = 0, done = 0;
  c.seed = 7;
  CHECK(rnc_identity_generate(&c.id, mgmt_rng, &c.seed) == RNC_OK);
  CHECK(rnc_identity_from_private(&daemon_id, daemon_private) == RNC_OK);
  CHECK(rnc_destination_hash("rnstransport.probe", &daemon_id, name_hash,
                             destination) == RNC_OK);
  c.node = rnc_node_new(&c.id, 0, mgmt_rng, &c.seed);
  c.host = c.node ? rnc_host_new(c.node) : NULL;
  CHECK(c.host);
  tcp.kind = RNC_HOST_TCP_CONNECT;
  tcp.address = "127.0.0.1";
  tcp.port = (uint16_t)port;
  CHECK(rnc_host_add(c.host, 1, &tcp) == RNC_OK);
  while (!done && now < deadline) {
    rnc_host_event he;
    now += 10;
    CHECK(rnc_host_step(c.host, 5, (uint64_t)time(NULL), now) == RNC_OK);
    if (!sent && now % 500 == 0)
      (void)rnc_node_request_path(c.node, destination, now);
    if (!sent && rnc_node_lookup(c.node, destination, now, &route) == RNC_OK) {
      rnc_packet probe = {0};
      probe.flags = 0; /* SINGLE DATA, header 1 */
      memcpy(probe.destination, destination, 16);
      probe.data_size = 16;
      memset(probe.data, 0x5a, 16);
      /* the payload is encrypted to the destination in real probes; the
       * responder proves any delivered packet, so a raw body suffices here */
      CHECK(rnc_node_send_tracked(c.node, &probe, 5000,
                                  (uint64_t)time(NULL), now, hash) == RNC_OK);
      sent = 1;
    }
    while (rnc_host_poll(c.host, &he) == RNC_OK)
      if (he.type == RNC_HOST_NODE && he.node.type == RNC_NODE_RECEIPT) {
        result = he.node.receipt_status == RNC_RECEIPT_DELIVERED &&
                 !memcmp(he.node.receipt_hash, hash, 32);
        done = 1;
      }
  }
  rnc_host_free(c.host);
  rnc_node_free(c.node);
  return result;
}
static void probe(const char *exe) {
  char dir[] = "/tmp/rnc-node-probe-XXXXXX", cfg[256], key[256], admin[256],
       text[1024], id[33];
  unsigned port = unused_port();
  uint8_t private_key[64];
  int fd, keyfd;
  pid_t p;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = No\nshare_instance = No\n"
                 "respond_to_probes = Yes\n[interfaces]\n[[TCP]]\n"
                 "type = TCPServerInterface\nlisten_ip = 127.0.0.1\n"
                 "listen_port = %u\n",
                 port) > 0);
  config_file(cfg, text);
  p = start(exe, cfg, key, admin, &fd);
  ready_line(fd, id);
  keyfd = open(key, O_RDONLY);
  CHECK(keyfd >= 0 && read(keyfd, private_key, 64) == 64);
  close(keyfd);
  CHECK(probe_delivered(port, private_key));
  stop(p, fd);
  /* disabled by default: no destination, so no proof */
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = No\nshare_instance = No\n"
                 "[interfaces]\n[[TCP]]\ntype = TCPServerInterface\n"
                 "listen_ip = 127.0.0.1\nlisten_port = %u\n",
                 port) > 0);
  config_file(cfg, text);
  p = start(exe, cfg, key, admin, &fd);
  ready_line(fd, id);
  CHECK(!probe_delivered(port, private_key));
  stop(p, fd);
  remove_tree(dir);
  puts("node probe responder tests passed");
}
/* Network identity: loaded from (or created at) the configured path in the
 * reference's 64-byte file format, reported over the admin socket. */
static void network_identity(const char *exe) {
  char dir[] = "/tmp/rnc-node-netid-XXXXXX", cfg[256], key[256], admin[256],
       path[256], text[1024], id[33], reply[256], first[64];
  int fd;
  pid_t p;
  struct stat st;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(path, sizeof(path), "%s/network", dir) > 0);
  /* not configured: nothing to report */
  config_file(cfg, valid);
  p = start(exe, cfg, key, admin, &fd);
  ready_line(fd, id);
  admin_command(admin, "NETWORK", reply, sizeof(reply));
  CHECK(!strncmp(reply, "NONE", 4));
  stop(p, fd);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = No\nshare_instance = No\n"
                 "network_identity = %s\n[interfaces]\n[[TCP]]\n"
                 "type = TCPServerInterface\nlisten_ip = 127.0.0.1\n"
                 "listen_port = 0\n",
                 path) > 0);
  config_file(cfg, text);
  p = start(exe, cfg, key, admin, &fd);
  ready_line(fd, id);
  CHECK(!stat(path, &st) && st.st_size == 64 && (st.st_mode & 0777) == 0600);
  admin_command(admin, "NETWORK", reply, sizeof(reply));
  CHECK(!strncmp(reply, "network identity=", 17) && strlen(reply) >= 49);
  memcpy(first, reply, 49);
  first[49] = 0;
  /* the network identity is distinct from the transport identity */
  CHECK(!strstr(reply, id));
  stop(p, fd);
  p = start(exe, cfg, key, admin, &fd);
  ready_line(fd, id);
  admin_command(admin, "NETWORK", reply, sizeof(reply));
  CHECK(!strncmp(reply, first, 49)); /* stable across restarts */
  stop(p, fd);
  remove_tree(dir);
  puts("node network identity tests passed");
}
/* Interface discovery announces: a daemon with a discoverable interface
 * announces rnstransport.discovery.interface; a C client over TCP receives and
 * validates it. */
static int collect_announce(unsigned port, const uint8_t destination[16],
                            rnc_announce *out, unsigned seconds) {
  mgmt_client c = {0};
  rnc_host_config tcp = {0};
  uint64_t now = 1000, deadline;
  int found = 0;
  c.seed = 11;
  CHECK(rnc_identity_generate(&c.id, mgmt_rng, &c.seed) == RNC_OK);
  c.node = rnc_node_new(&c.id, 0, mgmt_rng, &c.seed);
  c.host = c.node ? rnc_host_new(c.node) : NULL;
  CHECK(c.host);
  tcp.kind = RNC_HOST_TCP_CONNECT;
  tcp.address = "127.0.0.1";
  tcp.port = (uint16_t)port;
  CHECK(rnc_host_add(c.host, 1, &tcp) == RNC_OK);
  deadline = now + seconds * 1000u;
  while (!found && now < deadline) {
    rnc_host_event he;
    now += 10;
    CHECK(rnc_host_step(c.host, 5, (uint64_t)time(NULL), now) == RNC_OK);
    while (rnc_host_poll(c.host, &he) == RNC_OK)
      if (he.type == RNC_HOST_NODE && he.node.type == RNC_NODE_ANNOUNCE &&
          !memcmp(he.node.route.destination, destination, 16)) {
        *out = he.node.route.announce;
        found = 1;
      }
  }
  rnc_host_free(c.host);
  rnc_node_free(c.node);
  return found;
}
static void discovery_announce(const char *exe) {
  char dir[] = "/tmp/rnc-node-disc-XXXXXX", cfg[256], key[256], admin[256],
       netid[256], text[2048], id[33];
  unsigned port = unused_port();
  uint8_t private_key[64], network_key[64], destination[16], name_hash[10],
      stamp[32];
  rnc_identity daemon = {0}, network = {0};
  rnc_announce announce;
  rnc_discovery_info info;
  unsigned value;
  size_t k;
  int fd, keyfd;
  pid_t p;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(netid, sizeof(netid), "%s/network", dir) > 0);
  /* plain announce on the transport identity */
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = Yes\nshare_instance = No\n"
                 "discovery_job_interval = 1\n[interfaces]\n[[Public]]\n"
                 "type = BackboneInterface\nlisten_ip = 127.0.0.1\n"
                 "port = %u\ndiscoverable = yes\ndiscovery_name = "
                 "Test  Node  (EU)\ndiscovery_stamp_value = 8\nreachable_on = "
                 "127.0.0.1\nannounce_interval_seconds = 3600\nlatitude = "
                 "48.8584\nlongitude = 2.2945\nheight = 35\n",
                 port) > 0);
  config_file(cfg, text);
  p = start(exe, cfg, key, admin, &fd);
  ready_line(fd, id);
  keyfd = open(key, O_RDONLY);
  CHECK(keyfd >= 0 && read(keyfd, private_key, 64) == 64);
  close(keyfd);
  CHECK(rnc_identity_from_private(&daemon, private_key) == RNC_OK);
  CHECK(rnc_destination_hash("rnstransport.discovery.interface", &daemon,
                             name_hash, destination) == RNC_OK);
  CHECK(collect_announce(port, destination, &announce, 20));
  CHECK(!memcmp(announce.identity.hash, daemon.hash, 16));
  CHECK(rnc_discovery_parse(announce.app_data, announce.app_size, 8, NULL,
                            &info, stamp, &value) == RNC_OK);
  CHECK(!strcmp(info.type, "BackboneInterface") && info.transport &&
        !memcmp(info.transport_id, daemon.hash, 16) &&
        !strcmp(info.name, "Test Node (EU)") &&
        !strcmp(info.reachable_on, "127.0.0.1") && info.has_port &&
        info.port == port && info.has_latitude && info.latitude == 48.8584 &&
        info.longitude == 2.2945 && info.height == 35.0 && value >= 8);
  stop(p, fd);
  /* encrypted to a network identity, which also owns the destination */
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = No\nshare_instance = No\n"
                 "network_identity = %s\ndiscovery_job_interval = 1\n"
                 "[interfaces]\n[[Public]]\ntype = TCPServerInterface\n"
                 "listen_ip = 127.0.0.1\nlisten_port = %u\ndiscoverable = "
                 "yes\ndiscovery_name = Secret Node\ndiscovery_stamp_value = "
                 "8\ndiscovery_encrypt = yes\nreachable_on = example.org\n",
                 netid, port) > 0);
  config_file(cfg, text);
  p = start(exe, cfg, key, admin, &fd);
  ready_line(fd, id);
  keyfd = open(netid, O_RDONLY);
  CHECK(keyfd >= 0 && read(keyfd, network_key, 64) == 64);
  close(keyfd);
  CHECK(rnc_identity_from_private(&network, network_key) == RNC_OK);
  CHECK(rnc_destination_hash("rnstransport.discovery.interface", &network,
                             name_hash, destination) == RNC_OK);
  CHECK(collect_announce(port, destination, &announce, 20));
  CHECK(!memcmp(announce.identity.hash, network.hash, 16));
  CHECK(announce.app_data[0] == RNC_DISCOVERY_FLAG_ENCRYPTED);
  CHECK(rnc_discovery_parse(announce.app_data, announce.app_size, 8, NULL,
                            &info, stamp, &value) == RNC_STATE);
  CHECK(rnc_discovery_parse(announce.app_data, announce.app_size, 8, &network,
                            &info, stamp, &value) == RNC_OK);
  CHECK(!strcmp(info.type, "TCPServerInterface") && info.port == port &&
        !strcmp(info.reachable_on, "example.org") && !info.transport);
  for (k = 0; k < 1; ++k)
    CHECK(info.name[0]);
  stop(p, fd);
  remove_tree(dir);
  puts("node discovery announce tests passed");
}
/* Discovery listening: B hears A's announce, stores it, and applies source,
 * stamp and encryption rules. */
static void write_config(const char *path, const char *fmt, ...) {
  char text[2048];
  va_list args;
  va_start(args, fmt);
  CHECK(vsnprintf(text, sizeof(text), fmt, args) < (int)sizeof(text));
  va_end(args);
  config_file(path, text);
}
static int listed_within(const char *admin, const char *needle, unsigned seconds) {
  unsigned waited;
  char reply[4096];
  for (waited = 0; waited < seconds * 10; ++waited) {
    struct timespec t = {0, 100000000};
    admin_command(admin, "DISCOVERED", reply, sizeof(reply));
    if (strstr(reply, needle))
      return 1;
    nanosleep(&t, NULL);
  }
  return 0;
}
static void discovery_listen(const char *exe) {
  char dir[] = "/tmp/rnc-node-dl-XXXXXX", acfg[256], akey[256], aadmin[256],
       bcfg[256], bkey[256], badmin[256], bstate[256], netid[256], netcopy[256],
       aid[33], bid[33], reply[4096], store[300];
  unsigned port = unused_port();
  int afd, bfd, k;
  pid_t a, b;
  struct stat st;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(acfg, sizeof(acfg), "%s/a.config", dir) > 0);
  CHECK(snprintf(akey, sizeof(akey), "%s/a.identity", dir) > 0);
  CHECK(snprintf(aadmin, sizeof(aadmin), "%s/a.admin", dir) > 0);
  CHECK(snprintf(bcfg, sizeof(bcfg), "%s/b.config", dir) > 0);
  CHECK(snprintf(bkey, sizeof(bkey), "%s/b.identity", dir) > 0);
  CHECK(snprintf(badmin, sizeof(badmin), "%s/b.admin", dir) > 0);
  CHECK(snprintf(bstate, sizeof(bstate), "%s/b.state", dir) > 0);
  CHECK(snprintf(netid, sizeof(netid), "%s/network", dir) > 0);
  CHECK(snprintf(netcopy, sizeof(netcopy), "%s/network-copy", dir) > 0);
  CHECK(snprintf(store, sizeof(store), "%s.discovery", bstate) > 0);
  write_config(acfg,
               "[reticulum]\nenable_transport = Yes\nshare_instance = No\n"
               "discovery_job_interval = 1\nnetwork_identity = %s\n"
               "[interfaces]\n[[Public]]\ntype = BackboneInterface\n"
               "listen_ip = 127.0.0.1\nport = %u\ndiscoverable = yes\n"
               "discovery_name = Alpha Relay\ndiscovery_stamp_value = 8\n"
               "reachable_on = 198.51.100.4\nannounce_interval_seconds = "
               "2\nlatitude = 10.5\nlongitude = 20.25\nheight = 3\n",
               netid, port);
  a = start(exe, acfg, akey, aadmin, &afd);
  ready_line(afd, aid);
  /* give B the same network identity, so only B-with-key could decrypt */
  {
    uint8_t material[64];
    int in = open(netid, O_RDONLY), out;
    CHECK(in >= 0 && read(in, material, 64) == 64);
    close(in);
    out = open(netcopy, O_WRONLY | O_CREAT | O_EXCL, 0600);
    CHECK(out >= 0 && write(out, material, 64) == 64);
    close(out);
  }
  /* 1. defaults: heard, stored, attributed to the announcing identity */
  write_config(bcfg,
               "[reticulum]\nenable_transport = No\nshare_instance = No\n"
               "discover_interfaces = yes\nrequired_discovery_value = 8\n"
               "network_identity = %s\n[interfaces]\n[[Up]]\n"
               "type = TCPClientInterface\ntarget_host = 127.0.0.1\n"
               "target_port = %u\nreconnect_wait = 1\n",
               netcopy, port);
  b = start_with_state(exe, bcfg, bkey, badmin, bstate, &bfd);
  ready_line(bfd, bid);
  CHECK(listed_within(badmin, "Alpha Relay", 30));
  admin_command(badmin, "DISCOVERED", reply, sizeof(reply));
  CHECK(strstr(reply, "type=BackboneInterface") &&
        strstr(reply, "reachable_on=198.51.100.4") && strstr(reply, "status=available") &&
        strstr(reply, "transport_id=") && strstr(reply, aid));
  CHECK(!stat(store, &st) && S_ISDIR(st.st_mode));
  stop(b, bfd);
  /* a restart still knows it (A need not be running) */
  stop(a, afd);
  b = start_with_state(exe, bcfg, bkey, badmin, bstate, &bfd);
  ready_line(bfd, bid);
  admin_command(badmin, "DISCOVERED", reply, sizeof(reply));
  CHECK(strstr(reply, "Alpha Relay"));
  stop(b, bfd);
  /* 2. rules that must keep it out, each on a fresh store */
  for (k = 0; k < 4; ++k) {
    char rm[400];
    CHECK(snprintf(rm, sizeof(rm), "rm -rf '%s'", store) > 0);
    CHECK(system(rm) == 0);
    if (k >= 2) /* A now encrypts its announces to the network identity */
      write_config(acfg,
                   "[reticulum]\nenable_transport = Yes\nshare_instance = No\n"
                   "discovery_job_interval = 1\nnetwork_identity = %s\n"
                   "[interfaces]\n[[Public]]\ntype = BackboneInterface\n"
                   "listen_ip = 127.0.0.1\nport = %u\ndiscoverable = yes\n"
                   "discovery_name = Alpha Relay\ndiscovery_stamp_value = 8\n"
                   "discovery_encrypt = yes\nreachable_on = 198.51.100.4\n"
                   "announce_interval_seconds = 2\n",
                   netid, port);
    a = start(exe, acfg, akey, aadmin, &afd);
    ready_line(afd, aid);
    if (k != 2)
      write_config(bcfg,
                   "[reticulum]\nenable_transport = No\nshare_instance = No\n"
                   "discover_interfaces = yes\nrequired_discovery_value = %u\n"
                   "%snetwork_identity = %s\n[interfaces]\n[[Up]]\ntype = "
                   "TCPClientInterface\ntarget_host = 127.0.0.1\ntarget_port "
                   "= %u\nreconnect_wait = 1\n",
                   k == 0 ? 30u : 8u,
                   k == 1 ? "interface_discovery_sources = "
                            "00000000000000000000000000000001\n"
                          : "",
                   netcopy, port);
    else
      write_config(bcfg,
                   "[reticulum]\nenable_transport = No\nshare_instance = No\n"
                   "discover_interfaces = yes\nrequired_discovery_value = 8\n"
                   "[interfaces]\n[[Up]]\ntype = TCPClientInterface\n"
                   "target_host = 127.0.0.1\ntarget_port = %u\nreconnect_wait "
                   "= 1\n",
                   port);
    b = start_with_state(exe, bcfg, bkey, badmin, bstate, &bfd);
    ready_line(bfd, bid);
    if (k == 3) /* with the key it decrypts and is listed */
      CHECK(listed_within(badmin, "Alpha Relay", 30));
    else
      CHECK(!listed_within(badmin, "Alpha Relay", 8));
    stop(b, bfd);
    stop(a, afd);
  }
  remove_tree(dir);
  puts("node discovery listening tests passed");
}
/* Auto-connect: a bootstrap link brings the announce of a Backbone interface;
 * the daemon connects to it, drops the bootstrap link once enough auto-connected
 * interfaces are up, and falls back to bootstrap when they all go away. */
static unsigned status_count(const char *admin, const char *needle) {
  char reply[8192];
  const char *at;
  unsigned n = 0;
  admin_command(admin, "STATUS", reply, sizeof(reply));
  for (at = reply; (at = strstr(at, needle)) != NULL; at += strlen(needle))
    n++;
  return n;
}
/* Interfaces listed with an id below `limit`: the configured ones, as opposed
 * to those auto-connected (ids at and above AUTOCONNECT_ID_BASE) or accepted. */
static unsigned status_ids_below(const char *admin, unsigned long limit) {
  char reply[8192];
  const char *at;
  unsigned n = 0;
  admin_command(admin, "STATUS", reply, sizeof(reply));
  for (at = reply; (at = strstr(at, "interface id=")) != NULL; at += 13) {
    unsigned long id = strtoul(at + 13, NULL, 10);
    if (id < limit)
      n++;
  }
  return n;
}
static int configured_wait(const char *admin, unsigned long limit, unsigned want,
                           unsigned seconds) {
  unsigned waited;
  for (waited = 0; waited < seconds * 10; ++waited) {
    struct timespec t = {0, 100000000};
    if (status_ids_below(admin, limit) == want)
      return 1;
    nanosleep(&t, NULL);
  }
  return 0;
}
static int status_wait(const char *admin, const char *needle, unsigned want,
                       unsigned seconds) {
  unsigned waited;
  for (waited = 0; waited < seconds * 10; ++waited) {
    struct timespec t = {0, 100000000};
    if (status_count(admin, needle) == want)
      return 1;
    nanosleep(&t, NULL);
  }
  return 0;
}
static void discovery_autoconnect(const char *exe) {
  char dir[] = "/tmp/rnc-node-ac-XXXXXX", acfg[256], akey[256], aadmin[256],
       bcfg[256], bkey[256], badmin[256], aid[33], bid[33];
  unsigned bootstrap_port = unused_port(), public_port = unused_port();
  int afd, bfd;
  pid_t a, b;
  CHECK(bootstrap_port != public_port && mkdtemp(dir));
  CHECK(snprintf(acfg, sizeof(acfg), "%s/a.config", dir) > 0);
  CHECK(snprintf(akey, sizeof(akey), "%s/a.identity", dir) > 0);
  CHECK(snprintf(aadmin, sizeof(aadmin), "%s/a.admin", dir) > 0);
  CHECK(snprintf(bcfg, sizeof(bcfg), "%s/b.config", dir) > 0);
  CHECK(snprintf(bkey, sizeof(bkey), "%s/b.identity", dir) > 0);
  CHECK(snprintf(badmin, sizeof(badmin), "%s/b.admin", dir) > 0);
  write_config(acfg,
               "[reticulum]\nenable_transport = Yes\nshare_instance = No\n"
               "discovery_job_interval = 1\n[interfaces]\n[[Plain]]\ntype = "
               "TCPServerInterface\nlisten_ip = 127.0.0.1\nlisten_port = %u\n"
               "[[Public]]\ntype = BackboneInterface\nlisten_ip = 127.0.0.1\n"
               "port = %u\ndiscoverable = yes\ndiscovery_name = Beta "
               "Backbone\ndiscovery_stamp_value = 8\nreachable_on = "
               "127.0.0.1\nannounce_interval_seconds = 2\n",
               bootstrap_port, public_port);
  a = start(exe, acfg, akey, aadmin, &afd);
  ready_line(afd, aid);
  write_config(bcfg,
               "[reticulum]\nenable_transport = No\nshare_instance = No\n"
               "discover_interfaces = yes\nrequired_discovery_value = 8\n"
               "autoconnect_discovered_interfaces = 1\n"
               "autoconnect_unverified_implementations = yes\n"
               "autoconnect_allow_local = yes\n"
               "autoconnect_monitor_seconds = 1\nautoconnect_detach_seconds = "
               "2\n[interfaces]\n[[Bootstrap]]\ntype = TCPClientInterface\n"
               "target_host = 127.0.0.1\ntarget_port = %u\nbootstrap_only = "
               "yes\nreconnect_wait = 1\n",
               bootstrap_port);
  b = start(exe, bcfg, bkey, badmin, &bfd);
  ready_line(bfd, bid);
  /* auto-connected interface appears, bootstrap link goes: one TCP client */
  CHECK(status_wait(badmin, "id=2147287040 parent=0 kind=2 online=1", 1, 40));
  CHECK(configured_wait(badmin, 2147287040ul, 0, 10)); /* bootstrap link gone */
  /* the source disappears: the interface is detached, bootstrap returns */
  stop(a, afd);
  CHECK(status_wait(badmin, "id=2147287040", 0, 30));
  CHECK(configured_wait(badmin, 2147287040ul, 1, 30));
  stop(b, bfd);
  remove_tree(dir);
  puts("node discovery auto-connect tests passed");
}
/* The daemon's [logging] section sets the level and destination. */
static int file_contains(const char *path, const char *needle) {
  char buf[65536];
  FILE *f = fopen(path, "r");
  size_t n;
  if (!f)
    return 0;
  n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);
  buf[n] = 0;
  return strstr(buf, needle) != NULL;
}
static void logging_config(const char *exe) {
  char dir[] = "/tmp/rnc-node-log-XXXXXX", cfg[256], key[256], admin[256],
       logfile[256], id[33];
  unsigned port = unused_port(), pass, waited;
  int fd;
  pid_t p;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(logfile, sizeof(logfile), "%s/daemon.log", dir) > 0);
  for (pass = 0; pass < 2; ++pass) {
    int peer;
    (void)unlink(logfile);
    write_config(cfg,
                 "[reticulum]\nenable_transport = No\nshare_instance = No\n"
                 "instance_name = logtest\n[logging]\nloglevel = %u\n"
                 "logdestination = file\nlogfile = %s\n[interfaces]\n[[TCP]]\n"
                 "type = TCPServerInterface\nlisten_ip = 127.0.0.1\n"
                 "listen_port = %u\n",
                 pass ? 3u : 4u, logfile, port);
    p = start(exe, cfg, key, admin, &fd);
    ready_line(fd, id);
    peer = tcp_connect(port); /* an accepted connection is a new interface */
    for (waited = 0; waited < 30; ++waited) {
      struct timespec t = {0, 100000000};
      if (file_contains(logfile, "is up"))
        break;
      nanosleep(&t, NULL);
    }
    close(peer);
    {
      struct timespec t = {0, 300000000};
      nanosleep(&t, NULL);
    }
    stop(p, fd);
    if (pass == 0) {
      /* level 4 (info): the connection is logged, with the RNS-style prefix */
      CHECK(file_contains(logfile, "[Info]"));
      CHECK(file_contains(logfile, "is up"));
    } else
      /* level 3 (notice): info messages are not */
      CHECK(!file_contains(logfile, "is up"));
  }
  /* an invalid level is a configuration error */
  write_config(cfg,
               "[reticulum]\nenable_transport = No\nshare_instance = No\n"
               "[logging]\nloglevel = 12\n[interfaces]\n[[TCP]]\ntype = "
               "TCPServerInterface\nlisten_ip = 127.0.0.1\nlisten_port = 0\n");
  CHECK(run_check(exe, cfg) != 0);
  remove_tree(dir);
  puts("node logging config tests passed");
}
static void shared(const char *exe, const char *reference, const char *python) {
  char dir[] = "/tmp/rnc-node-shared-XXXXXX", cfg[256], keypath[256],
       admin[256], storage[256], text[2048], identity[33];
  unsigned port = unused_port(), control = unused_port(), world;
  pid_t process;
  int fd, keyfd;
  uint8_t private_key[64], key[32];
  rnc_identity id;
  CHECK(port != control && mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(storage, sizeof(storage), "%s/storage", dir) > 0);
  CHECK(!mkdir(storage, 0700));
  CHECK(snprintf(keypath, sizeof(keypath), "%s/transport_identity", storage) >
        0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = No\nshare_instance = "
                 "Yes\nshared_instance_type = tcp\nshared_instance_port = "
                 "%u\ninstance_control_port = %u\n[interfaces]\n[[External "
                 "TCP]]\ntype = TCPServerInterface\nlisten_ip = "
                 "127.0.0.1\nlisten_port = 0\n",
                 port, control) > 0);
  config_file(cfg, text);
  process = start(exe, cfg, keypath, admin, &fd);
  ready_line(fd, identity);
  world = admin_status(admin);
  CHECK(world);
  keyfd = open(keypath, O_RDONLY);
  CHECK(keyfd >= 0 && read(keyfd, private_key, 64) == 64);
  close(keyfd);
  CHECK(rnc_identity_from_private(&id, private_key) == RNC_OK &&
        rnc_rpc_key(&id, key) == RNC_OK);
  rpc_client_test(control, key, 1);
  key[0] ^= 1;
  rpc_client_test(control, key, 0);
  shared_data_test(port, world);
  if (reference) {
    rns_status(python, reference, dir);
    rns_blackhole(python, reference, dir, admin);
  }
  stop(process, fd);
  remove_tree(dir);
  puts(reference ? "unmodified RNS shared-instance test passed"
                 : "native shared-instance tests passed");
}
/* The reference peer: starts RNS from a generated config, prints the hash of a
 * destination it announces once a second, and exits after `seconds`. */
static const char *reference_peer =
    "import RNS, sys, time\n"
    "r = RNS.Reticulum(configdir=sys.argv[1], loglevel=1)\n"
    "i = RNS.Identity()\n"
    "d = RNS.Destination(i, RNS.Destination.IN, RNS.Destination.SINGLE,\n"
    "                    'reticulum_c', 'backbone')\n"
    "print(d.hexhash, flush=True)\n"
    "end = time.time() + float(sys.argv[2])\n"
    "while time.time() < end:\n"
    "    d.announce()\n"
    "    time.sleep(1)\n";
static pid_t start_reference(const char *python, const char *reference,
                             const char *dir, unsigned seconds, int *out,
                             char hash[33]) {
  int fds[2];
  pid_t p;
  char limit[16];
  size_t n = 0;
  unsigned tries;
  CHECK(!pipe(fds));
  CHECK(snprintf(limit, sizeof(limit), "%u", seconds) > 0);
  p = fork();
  CHECK(p >= 0);
  if (!p) {
    close(fds[0]);
    CHECK(dup2(fds[1], STDOUT_FILENO) >= 0 && dup2(fds[1], STDERR_FILENO) >= 0);
    close(fds[1]);
    CHECK(!setenv("PYTHONPATH", reference, 1));
    execl(python, python, "-c", reference_peer, dir, limit, (char *)NULL);
    _exit(127);
  }
  close(fds[1]);
  /* the hash line follows RNS start-up output; read until 32 hex digits end a
   * line */
  for (tries = 0; tries < 200; ++tries) {
    struct pollfd pf = {fds[0], POLLIN, 0};
    char buf[4096];
    char *line;
    CHECK(poll(&pf, 1, 100) >= 0);
    if (pf.revents & POLLIN) {
      ssize_t got = read(fds[0], buf + n, sizeof(buf) - 1 - n);
      CHECK(got >= 0);
      n += (size_t)got;
      buf[n] = 0;
      for (line = strtok(buf, "\n"); line; line = strtok(NULL, "\n")) {
        size_t k;
        if (strlen(line) != 32)
          continue;
        for (k = 0; k < 32 && strchr("0123456789abcdef", line[k]); ++k) {
        }
        if (k == 32) {
          memcpy(hash, line, 32);
          hash[32] = 0;
          *out = fds[0];
          return p;
        }
      }
      CHECK(n < sizeof(buf) - 1);
    }
  }
  fprintf(stderr, "reference peer never printed its destination\n");
  CHECK(0);
  return p;
}
static int admin_has_path(const char *path, const char *hash) {
  struct sockaddr_un addr;
  int fd = socket(AF_UNIX, SOCK_STREAM, 0), found;
  char request[64], buf[512];
  ssize_t n;
  CHECK(fd >= 0);
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, path);
  CHECK(!connect(fd, (struct sockaddr *)&addr, sizeof(addr)));
  CHECK(snprintf(request, sizeof(request), "PATH %s\n", hash) > 0);
  CHECK(write(fd, request, strlen(request)) == (ssize_t)strlen(request));
  n = read(fd, buf, sizeof(buf) - 1);
  CHECK(n > 0);
  buf[n] = 0;
  found = !strncmp(buf, "path destination=", 17);
  close(fd);
  return found;
}
static void stop_reference(pid_t p, int fd) {
  int status;
  (void)kill(p, SIGKILL);
  CHECK(waitpid(p, &status, 0) == p);
  close(fd);
}
/* One direction of the Backbone check: the reference announces over its
 * Backbone interface and our daemon, running the matching Backbone type,
 * must learn the destination. */
static void backbone_direction(const char *exe, const char *reference,
                               const char *python, int reference_listens) {
  char dir[] = "/tmp/rnc-backbone-XXXXXX", rcfg[256], rdir[256], cfg[256],
       key[256], admin[256], text[1024], identity[33], hash[33];
  unsigned port = unused_port(), tries;
  int rfd, dfd, found = 0;
  pid_t peer, daemon;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(rdir, sizeof(rdir), "%s/ref", dir) > 0);
  CHECK(!mkdir(rdir, 0700));
  CHECK(snprintf(rcfg, sizeof(rcfg), "%s/config", rdir) > 0);
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  /* reference side */
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = False\nshare_instance = "
                 "No\n[interfaces]\n[[Backbone]]\ntype = %s\nenabled = yes\n"
                 "%s = 127.0.0.1\n%s = %u\n",
                 reference_listens ? "BackboneInterface"
                                   : "BackboneClientInterface",
                 reference_listens ? "listen_ip" : "target_host",
                 reference_listens ? "listen_port" : "target_port", port) > 0);
  config_file(rcfg, text);
  /* daemon side: the opposite end */
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = No\nshare_instance = "
                 "No\n[interfaces]\n[[Backbone]]\ntype = %s\nenabled = "
                 "Yes\n%s = 127.0.0.1\n%s = %u\n%s",
                 reference_listens ? "BackboneClientInterface"
                                   : "BackboneInterface",
                 reference_listens ? "target_host" : "listen_ip",
                 reference_listens ? "target_port" : "port", port,
                 reference_listens ? "reconnect_wait = 1\n" : "") > 0);
  config_file(cfg, text);
  if (reference_listens) {
    peer = start_reference(python, reference, rdir, 40, &rfd, hash);
    daemon = start(exe, cfg, key, admin, &dfd);
  } else {
    daemon = start(exe, cfg, key, admin, &dfd);
    ready_line(dfd, identity);
    peer = start_reference(python, reference, rdir, 40, &rfd, hash);
  }
  if (reference_listens)
    ready_line(dfd, identity);
  for (tries = 0; tries < 300 && !found; ++tries) {
    struct timespec t = {0, 100000000};
    found = admin_has_path(admin, hash);
    if (!found)
      nanosleep(&t, NULL);
  }
  stop_reference(peer, rfd);
  stop(daemon, dfd);
  if (!found)
    fprintf(stderr, "daemon never learned the reference destination (%s)\n",
            reference_listens ? "reference listens" : "daemon listens");
  CHECK(found);
  remove_tree(dir);
}
static void backbone(const char *exe, const char *reference,
                     const char *python) {
  backbone_direction(exe, reference, python, 0);
  backbone_direction(exe, reference, python, 1);
  puts("unmodified RNS Backbone interop passed in both directions");
}
/* The reference's rnstatus and rnpath manage a remote transport instance over
 * rnstransport.remote.management; the daemon must serve them, to the
 * allow-listed identity only. */
static void remote_management_reference(const char *exe, const char *reference,
                                        const char *python) {
  char dir[] = "/tmp/rnc-mgmt-ref-XXXXXX", rdir[256], rcfg[256], rid[256],
       cfg[256], key[256], admin[256], text[1024], out[16384], daemon[33],
       hash[33], port_text[16];
  unsigned port = unused_port();
  int fd;
  char *c;
  pid_t p;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(rdir, sizeof(rdir), "%s/ref", dir) > 0);
  CHECK(!mkdir(rdir, 0700));
  CHECK(snprintf(rcfg, sizeof(rcfg), "%s/config", rdir) > 0);
  CHECK(snprintf(rid, sizeof(rid), "%s/identity", dir) > 0);
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/node-identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(port_text, sizeof(port_text), "%u", port) > 0);
  {
    char *generate[] = {"-g", rid, NULL};
    reference_tool(python, reference, "RNS.Utilities.rnid", generate, out,
                   sizeof(out));
    c = strchr(out, '<');
    CHECK(c && strlen(c) > 33 && c[33] == '>');
    memcpy(hash, c + 1, 32);
    hash[32] = 0;
  }
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = False\nshare_instance = "
                 "No\n[interfaces]\n[[Daemon]]\ntype = TCPClientInterface\n"
                 "enabled = yes\ntarget_host = 127.0.0.1\ntarget_port = %u\n",
                 port) > 0);
  config_file(rcfg, text);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = No\nshare_instance = No\n"
                 "enable_remote_management = Yes\npublish_blackhole = Yes\n"
                 "remote_management_allowed = %s\n"
                 "[interfaces]\n[[TCP]]\ntype = TCPServerInterface\n"
                 "listen_ip = 127.0.0.1\nlisten_port = %u\n",
                 hash, port) > 0);
  config_file(cfg, text);
  p = start(exe, cfg, key, admin, &fd);
  ready_line(fd, daemon);
  {
    char *status[] = {"--config", rdir, "-R", daemon, "-i", rid,
                      "-w",       "20", NULL};
    char *table[] = {"--config", rdir, "-R", daemon, "-i", rid,
                     "-W",       "20", "-t", NULL};
    int status_ok, table_ok, list_ok;
    char *list[] = {"--config", rdir, "-p", daemon, "-w", "20", NULL};
    char reply[256];
    /* the reference treats an empty table as a failed request, so give the
     * daemon one path: a locally built announce sent over its TCP interface */
    uint8_t seed_key[64] = {9}, raw[RNC_MAX_MTU], framed[RNC_HOST_FRAME_MAX];
    unsigned entropy = 5, waited;
    rnc_identity announcer;
    rnc_packet announce;
    size_t raw_size, framed_size, k;
    char announced[33];
    int feed;
    CHECK(rnc_identity_from_private(&announcer, seed_key) == RNC_OK &&
          rnc_announce_create(&announcer, "reticulum_c.mgmt.table", NULL, 0,
                              (uint64_t)time(NULL), rng, &entropy,
                              &announce) == RNC_OK);
    CHECK(rnc_packet_encode(&announce, raw, sizeof(raw), &raw_size) == RNC_OK &&
          rnc_host_frame_encode(RNC_HOST_HDLC, 0, raw, raw_size, framed,
                                sizeof(framed), &framed_size) == RNC_OK);
    for (k = 0; k < 16; ++k)
      CHECK(snprintf(announced + 2 * k, 3, "%02x", announce.destination[k]) ==
            2);
    feed = tcp_connect(port);
    CHECK(write(feed, framed, framed_size) == (ssize_t)framed_size);
    for (waited = 0; waited < 100 && !admin_has_path(admin, announced); ++waited) {
      struct timespec t = {0, 50000000};
      nanosleep(&t, NULL);
    }
    CHECK(waited < 100);
    reference_tool(python, reference, "RNS.Utilities.rnstatus", status, out,
                   sizeof(out));
    status_ok = strstr(out, "Status    : Up") && strstr(out, " TCP");
    if (!status_ok)
      fprintf(stderr, "rnstatus -R output:\n%s\n", out);
    reference_tool(python, reference, "RNS.Utilities.rnpath", table, out,
                   sizeof(out));
    table_ok = strstr(out, announced) != NULL;
    if (!table_ok)
      fprintf(stderr, "rnpath -R -t output:\n%s\n", out);
    /* the published blackhole list is open to anyone, no identity needed */
    admin_command(admin,
                  "BLACKHOLE 33333333333333333333333333333333 0 published spam",
                  reply, sizeof(reply));
    CHECK(!strncmp(reply, "OK", 2));
    reference_tool(python, reference, "RNS.Utilities.rnpath", list, out,
                   sizeof(out));
    list_ok = strstr(out, "33333333333333333333333333333333") &&
              strstr(out, "blackholed indefinitely") &&
              strstr(out, "published spam");
    if (!list_ok)
      fprintf(stderr, "rnpath -p output:\n%s\n", out);
    close(feed);
    stop(p, fd); /* never leave the daemon holding the test's pipes */
    CHECK(status_ok && table_ok && list_ok);
  }
  remove_tree(dir);
  puts("unmodified RNS rnstatus/rnpath remote management passed");
}
/* The reference as the publishing end: it blackholes an identity and serves its
 * list; the daemon, subscribed to the reference's transport identity, must pick
 * it up. */
static const char *reference_publisher =
    "import RNS, sys, time\n"
    "r = RNS.Reticulum(configdir=sys.argv[1], loglevel=1)\n"
    "RNS.Transport.blackhole_identity(bytes.fromhex(sys.argv[3]),\n"
    "                                 reason='reference list')\n"
    "print('IDENTITY ' + RNS.Transport.identity.hexhash, flush=True)\n"
    "time.sleep(float(sys.argv[2]))\n";
static void blackhole_source_reference(const char *exe, const char *reference,
                                       const char *python) {
  char dir[] = "/tmp/rnc-bh-ref-XXXXXX", rdir[256], rcfg[256], cfg[256],
       key[256], admin[256], text[1024], daemon[33], publisher_id[33],
       out[4096], reply[2048], limit[16], hash[] =
           "77777777777777777777777777777777";
  unsigned port = unused_port(), tries;
  int pfd, dfd, found = 0;
  size_t used = 0;
  pid_t publisher, d;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(rdir, sizeof(rdir), "%s/ref", dir) > 0);
  CHECK(!mkdir(rdir, 0700));
  CHECK(snprintf(rcfg, sizeof(rcfg), "%s/config", rdir) > 0);
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(limit, sizeof(limit), "60") > 0);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = False\nshare_instance = "
                 "No\npublish_blackhole = Yes\n[interfaces]\n[[Server]]\n"
                 "type = TCPServerInterface\nenabled = yes\nlisten_ip = "
                 "127.0.0.1\nlisten_port = %u\n",
                 port) > 0);
  config_file(rcfg, text);
  {
    int fds[2];
    CHECK(!pipe(fds));
    publisher = fork();
    CHECK(publisher >= 0);
    if (!publisher) {
      close(fds[0]);
      CHECK(dup2(fds[1], STDOUT_FILENO) >= 0 &&
            dup2(fds[1], STDERR_FILENO) >= 0);
      close(fds[1]);
      CHECK(!setenv("PYTHONPATH", reference, 1));
      execl(python, python, "-c", reference_publisher, rdir, limit, hash,
            (char *)NULL);
      _exit(127);
    }
    close(fds[1]);
    pfd = fds[0];
  }
  out[0] = 0;
  for (tries = 0; tries < 300 && !strstr(out, "IDENTITY "); ++tries) {
    struct pollfd pf = {pfd, POLLIN, 0};
    CHECK(poll(&pf, 1, 100) >= 0);
    if (pf.revents & POLLIN) {
      ssize_t n = read(pfd, out + used, sizeof(out) - 1 - used);
      CHECK(n >= 0);
      used += (size_t)n;
    }
    out[used] = 0;
  }
  if (!strstr(out, "IDENTITY ")) {
    fprintf(stderr, "reference publisher output:\n%s\n", out);
    (void)kill(publisher, SIGKILL);
    CHECK(0);
  }
  memcpy(publisher_id, strstr(out, "IDENTITY ") + 9, 32);
  publisher_id[32] = 0;
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = No\nshare_instance = No\n"
                 "blackhole_sources = %s\nblackhole_initial_wait = 1\n"
                 "[interfaces]\n[[Upstream]]\ntype = TCPClientInterface\n"
                 "target_host = 127.0.0.1\ntarget_port = %u\n"
                 "reconnect_wait = 1\n",
                 publisher_id, port) > 0);
  config_file(cfg, text);
  d = start(exe, cfg, key, admin, &dfd);
  ready_line(dfd, daemon);
  for (tries = 0; tries < 400 && !found; ++tries) {
    struct timespec t = {0, 100000000};
    admin_command(admin, "BLACKHOLES", reply, sizeof(reply));
    found = strstr(reply, hash) && strstr(reply, "reason=reference list");
    if (!found)
      nanosleep(&t, NULL);
  }
  if (!found)
    fprintf(stderr, "daemon never merged the reference's list:\n%s\n", reply);
  (void)kill(publisher, SIGKILL);
  CHECK(waitpid(publisher, NULL, 0) == publisher);
  close(pfd);
  stop(d, dfd);
  CHECK(found);
  remove_tree(dir);
  puts("unmodified RNS published blackhole list subscribed by the daemon "
       "passed");
}
/* The reference's rnprobe against the daemon's probe responder. */
static void probe_reference(const char *exe, const char *reference,
                            const char *python) {
  char dir[] = "/tmp/rnc-probe-ref-XXXXXX", rdir[256], rcfg[256], cfg[256],
       key[256], admin[256], text[1024], daemon[33], out[8192], hex[33];
  unsigned port = unused_port();
  uint8_t destination[16], name_hash[10];
  rnc_identity identity = {0};
  size_t k;
  int fd, ok;
  pid_t p;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(rdir, sizeof(rdir), "%s/ref", dir) > 0);
  CHECK(!mkdir(rdir, 0700));
  CHECK(snprintf(rcfg, sizeof(rcfg), "%s/config", rdir) > 0);
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = False\nshare_instance = "
                 "No\n[interfaces]\n[[Daemon]]\ntype = TCPClientInterface\n"
                 "enabled = yes\ntarget_host = 127.0.0.1\ntarget_port = %u\n",
                 port) > 0);
  config_file(rcfg, text);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = No\nshare_instance = No\n"
                 "respond_to_probes = Yes\n[interfaces]\n[[TCP]]\n"
                 "type = TCPServerInterface\nlisten_ip = 127.0.0.1\n"
                 "listen_port = %u\n",
                 port) > 0);
  config_file(cfg, text);
  p = start(exe, cfg, key, admin, &fd);
  ready_line(fd, daemon);
  for (k = 0; k < 16; ++k) {
    unsigned v;
    CHECK(sscanf(daemon + 2 * k, "%2x", &v) == 1);
    identity.hash[k] = (uint8_t)v;
  }
  CHECK(rnc_destination_hash("rnstransport.probe", &identity, name_hash,
                             destination) == RNC_OK);
  for (k = 0; k < 16; ++k)
    CHECK(snprintf(hex + 2 * k, 3, "%02x", destination[k]) == 2);
  {
    char *args[] = {"--config", rdir, "-t", "20", "-n", "2", "-w", "1",
                    "rnstransport.probe", hex, NULL};
    reference_tool(python, reference, "RNS.Utilities.rnprobe", args, out,
                   sizeof(out));
  }
  ok = strstr(out, "Valid reply from") != NULL && !strstr(out, "timed out");
  if (!ok)
    fprintf(stderr, "rnprobe output:\n%s\n", out);
  stop(p, fd);
  CHECK(ok);
  remove_tree(dir);
  puts("unmodified RNS rnprobe against the probe responder passed");
}
/* Identity files are interchangeable with the reference in both directions. */
static void network_identity_reference(const char *exe, const char *reference,
                                       const char *python) {
  char dir[] = "/tmp/rnc-netid-ref-XXXXXX", cfg[256], key[256], admin[256],
       theirs[256], ours[256], text[1024], id[33], reply[256], out[4096],
       hash[33];
  char *generate[3], *print[4];
  int fd;
  pid_t p;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(theirs, sizeof(theirs), "%s/reference-identity", dir) > 0);
  CHECK(snprintf(ours, sizeof(ours), "%s/daemon-identity", dir) > 0);
  generate[0] = "-g";
  generate[1] = theirs;
  generate[2] = NULL;
  reference_tool(python, reference, "RNS.Utilities.rnid", generate, out,
                 sizeof(out));
  CHECK(strchr(out, '<') && strlen(strchr(out, '<')) > 33);
  memcpy(hash, strchr(out, '<') + 1, 32);
  hash[32] = 0;
  /* the daemon loads the reference's identity; like its own key file it must
   * not be readable by group or others, which the reference does not ensure */
  CHECK(!chmod(theirs, 0600));
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = No\nshare_instance = No\n"
                 "network_identity = %s\n[interfaces]\n[[TCP]]\n"
                 "type = TCPServerInterface\nlisten_ip = 127.0.0.1\n"
                 "listen_port = 0\n",
                 theirs) > 0);
  config_file(cfg, text);
  p = start(exe, cfg, key, admin, &fd);
  ready_line(fd, id);
  admin_command(admin, "NETWORK", reply, sizeof(reply));
  stop(p, fd);
  CHECK(!strncmp(reply, "network identity=", 17) && !strncmp(reply + 17, hash, 32));
  /* the reference loads the identity the daemon created */
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = No\nshare_instance = No\n"
                 "network_identity = %s\n[interfaces]\n[[TCP]]\n"
                 "type = TCPServerInterface\nlisten_ip = 127.0.0.1\n"
                 "listen_port = 0\n",
                 ours) > 0);
  config_file(cfg, text);
  p = start(exe, cfg, key, admin, &fd);
  ready_line(fd, id);
  admin_command(admin, "NETWORK", reply, sizeof(reply));
  stop(p, fd);
  print[0] = "-i";
  print[1] = ours;
  print[2] = "-p";
  print[3] = NULL;
  reference_tool(python, reference, "RNS.Utilities.rnid", print, out,
                 sizeof(out));
  {
    char want[40];
    CHECK(snprintf(want, sizeof(want), "<%.32s>", reply + 17) > 0);
    CHECK(strstr(out, want));
  }
  remove_tree(dir);
  puts("network identity files interchange with the reference");
}
/* A reference instance with discover_interfaces receives and stores this
 * daemon's discovery announce; its own rnstatus lists it. */
static pid_t start_rnsd(const char *python, const char *reference,
                        const char *config_dir) {
  pid_t p = fork();
  CHECK(p >= 0);
  if (!p) {
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      (void)dup2(devnull, STDOUT_FILENO);
      (void)dup2(devnull, STDERR_FILENO);
    }
    CHECK(!setenv("PYTHONPATH", reference, 1));
    execl(python, python, "-m", "RNS.Utilities.rnsd", "--config", config_dir,
          (char *)NULL);
    _exit(127);
  }
  return p;
}
static void discovery_announce_reference(const char *exe, const char *reference,
                                         const char *python) {
  char dir[] = "/tmp/rnc-disc-ref-XXXXXX", rdir[256], rcfg[256], store[300],
       cfg[256], key[256], admin[256], text[1536], id[33], out[16384];
  unsigned port = unused_port(), waited;
  int fd, found = 0;
  pid_t daemon, rnsd;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(rdir, sizeof(rdir), "%s/ref", dir) > 0);
  CHECK(!mkdir(rdir, 0700));
  CHECK(snprintf(rcfg, sizeof(rcfg), "%s/config", rdir) > 0);
  CHECK(snprintf(store, sizeof(store), "%s/storage/discovery/interfaces", rdir) > 0);
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = No\nshare_instance = No\n"
                 "discover_interfaces = yes\nrequired_discovery_value = 8\n"
                 "[interfaces]\n[[Daemon]]\ntype = TCPClientInterface\n"
                 "enabled = yes\ntarget_host = 127.0.0.1\ntarget_port = %u\n",
                 port) > 0);
  config_file(rcfg, text);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = Yes\nshare_instance = No\n"
                 "discovery_job_interval = 1\n[interfaces]\n[[Public]]\n"
                 "type = BackboneInterface\nlisten_ip = 127.0.0.1\n"
                 "port = %u\ndiscoverable = yes\ndiscovery_name = Oracle "
                 "Listener\ndiscovery_stamp_value = 8\nreachable_on = "
                 "192.0.2.7\nannounce_interval_seconds = 2\nlatitude = "
                 "51.5\nlongitude = -0.12\nheight = 11\n",
                 port) > 0);
  config_file(cfg, text);
  daemon = start(exe, cfg, key, admin, &fd);
  ready_line(fd, id);
  rnsd = start_rnsd(python, reference, rdir);
  for (waited = 0; waited < 300 && !found; ++waited) {
    DIR *d = opendir(store);
    struct dirent *e;
    struct timespec t = {0, 100000000};
    while (d && (e = readdir(d)))
      found |= e->d_name[0] != '.';
    if (d)
      closedir(d);
    if (!found)
      nanosleep(&t, NULL);
  }
  (void)kill(rnsd, SIGTERM);
  CHECK(waitpid(rnsd, NULL, 0) == rnsd);
  stop(daemon, fd);
  CHECK(found);
  {
    char *list[] = {"--config", rdir, "-d", "-D", NULL};
    int ok;
    reference_tool(python, reference, "RNS.Utilities.rnstatus", list, out,
                   sizeof(out));
    ok = strstr(out, "Oracle Listener") && strstr(out, "BackboneInterface") &&
         strstr(out, "192.0.2.7") && strstr(out, "reticulum-c 0.2") &&
         strstr(out, "Enabled");
    if (!ok)
      fprintf(stderr, "rnstatus -d -D output:\n%s\n", out);
    CHECK(ok);
  }
  remove_tree(dir);
  puts("unmodified RNS discovered and listed this daemon's interface");
}
/* The reference as the announcing end: its discoverable interface is heard,
 * validated and listed by this daemon. The reference sends its first discovery
 * announce one job interval (60 s) after start. */
static void discovery_listen_reference(const char *exe, const char *reference,
                                       const char *python) {
  char dir[] = "/tmp/rnc-disc-rl-XXXXXX", rdir[256], rcfg[256], cfg[256],
       key[256], admin[256], text[1536], id[33], reply[4096];
  unsigned port = unused_port();
  int fd, found;
  pid_t daemon, rnsd;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(rdir, sizeof(rdir), "%s/ref", dir) > 0);
  CHECK(!mkdir(rdir, 0700));
  CHECK(snprintf(rcfg, sizeof(rcfg), "%s/config", rdir) > 0);
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = Yes\nshare_instance = No\n"
                 "[interfaces]\n[[Public]]\ntype = BackboneInterface\n"
                 "enabled = yes\nlisten_ip = 127.0.0.1\nport = %u\n"
                 "discoverable = yes\ndiscovery_name = Reference Relay\n"
                 "discovery_stamp_value = 8\nreachable_on = 192.0.2.9\n"
                 "latitude = 52.5\nlongitude = 13.4\nheight = 34\n",
                 port) > 0);
  config_file(rcfg, text);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = No\nshare_instance = No\n"
                 "discover_interfaces = yes\nrequired_discovery_value = 8\n"
                 "[interfaces]\n[[Up]]\ntype = TCPClientInterface\n"
                 "target_host = 127.0.0.1\ntarget_port = %u\nreconnect_wait = "
                 "1\n",
                 port) > 0);
  config_file(cfg, text);
  rnsd = start_rnsd(python, reference, rdir);
  daemon = start(exe, cfg, key, admin, &fd);
  ready_line(fd, id);
  found = listed_within(admin, "Reference Relay", 110);
  admin_command(admin, "DISCOVERED", reply, sizeof(reply));
  (void)kill(rnsd, SIGTERM);
  CHECK(waitpid(rnsd, NULL, 0) == rnsd);
  stop(daemon, fd);
  if (!found)
    fprintf(stderr, "daemon never listed the reference's interface:\n%s\n", reply);
  CHECK(found);
  CHECK(strstr(reply, "type=BackboneInterface") &&
        strstr(reply, "reachable_on=192.0.2.9") && strstr(reply, "value="));
  remove_tree(dir);
  puts("this daemon discovered an unmodified RNS interface announce");
}
int main(int argc, char **argv) {
  CHECK(argc == 3 || argc == 5);
  if (!strcmp(argv[2], "cli"))
    cli(argv[1]);
  else if (!strcmp(argv[2], "network"))
    network(argv[1]);
  else if (!strcmp(argv[2], "logging") && argc == 3)
    logging_config(argv[1]);
  else if (!strcmp(argv[2], "disc_autoconnect") && argc == 3)
    discovery_autoconnect(argv[1]);
  else if (!strcmp(argv[2], "disc_listen") && argc == 3)
    discovery_listen(argv[1]);
  else if (!strcmp(argv[2], "disc_announce") && argc == 3)
    discovery_announce(argv[1]);
  else if (!strcmp(argv[2], "netid") && argc == 3)
    network_identity(argv[1]);
  else if (!strcmp(argv[2], "probe") && argc == 3)
    probe(argv[1]);
  else if (!strcmp(argv[2], "sources") && argc == 3)
    blackhole_sources(argv[1]);
  else if (!strcmp(argv[2], "management") && argc == 3)
    management(argv[1]);
  else if (!strcmp(argv[2], "blackhole") && argc == 3)
    blackhole(argv[1]);
  else if (!strcmp(argv[2], "shared"))
    shared(argv[1], NULL, NULL);
  else if (!strcmp(argv[2], "netid_ref") && argc == 5)
    network_identity_reference(argv[1], argv[3], argv[4]);
  else if (!strcmp(argv[2], "disc_listen_ref") && argc == 5)
    discovery_listen_reference(argv[1], argv[3], argv[4]);
  else if (!strcmp(argv[2], "disc_ref") && argc == 5)
    discovery_announce_reference(argv[1], argv[3], argv[4]);
  else if (!strcmp(argv[2], "probe_ref") && argc == 5)
    probe_reference(argv[1], argv[3], argv[4]);
  else if (!strcmp(argv[2], "source_ref") && argc == 5)
    blackhole_source_reference(argv[1], argv[3], argv[4]);
  else if (!strcmp(argv[2], "remote") && argc == 5)
    remote_management_reference(argv[1], argv[3], argv[4]);
  else if (!strcmp(argv[2], "backbone") && argc == 5)
    backbone(argv[1], argv[3], argv[4]);
  else if (!strcmp(argv[2], "rns") && argc == 5)
    shared(argv[1], argv[3], argv[4]);
  else
    CHECK(0);
  return 0;
}
