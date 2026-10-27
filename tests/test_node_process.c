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
#include <reticulum_c/rnc_ipc.h>
#include <signal.h>
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
int main(int argc, char **argv) {
  CHECK(argc == 3 || argc == 5);
  if (!strcmp(argv[2], "cli"))
    cli(argv[1]);
  else if (!strcmp(argv[2], "network"))
    network(argv[1]);
  else if (!strcmp(argv[2], "blackhole") && argc == 3)
    blackhole(argv[1]);
  else if (!strcmp(argv[2], "shared"))
    shared(argv[1], NULL, NULL);
  else if (!strcmp(argv[2], "backbone") && argc == 5)
    backbone(argv[1], argv[3], argv[4]);
  else if (!strcmp(argv[2], "rns") && argc == 5)
    shared(argv[1], argv[3], argv[4]);
  else
    CHECK(0);
  return 0;
}
