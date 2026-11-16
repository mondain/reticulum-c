#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1 /* wait4, to read a child's peak memory */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include "i2p_vectors.h"
#include <arpa/inet.h>
#include <openssl/sha.h>
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
#include <sys/ioctl.h>
#include <sys/resource.h>
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
/* run exe with arguments, capturing standard output; returns the exit status */
static int run_args(const char *exe, char *const args[], char *out, size_t size) {
  int fds[2], status;
  pid_t p;
  size_t used = 0;
  ssize_t n;
  CHECK(!pipe(fds));
  p = fork();
  CHECK(p >= 0);
  if (!p) {
    int null = open("/dev/null", O_WRONLY);
    close(fds[0]);
    CHECK(null >= 0 && dup2(fds[1], STDOUT_FILENO) >= 0 && dup2(null, STDERR_FILENO) >= 0);
    close(fds[1]);
    execv(exe, args);
    _exit(127);
  }
  close(fds[1]);
  while ((n = read(fds[0], out + used, size - 1 - used)) > 0)
    used += (size_t)n;
  out[used] = 0;
  close(fds[0]);
  CHECK(waitpid(p, &status, 0) == p && WIFEXITED(status));
  return WEXITSTATUS(status);
}
static void cli(const char *exe) {
  char dir[] = "/tmp/rnc-node-cli-XXXXXX", path[256];
  CHECK(mkdtemp(dir));
  {
    /* rnsd's --version, --exampleconfig (a file this daemon accepts) and -i (there is no shell) */
    char out[8192], example[300];
    char *version[] = {(char *)exe, "--version", NULL}, *sample[] = {(char *)exe, "--exampleconfig", NULL},
         *interactive[] = {(char *)exe, "-i", NULL}, *unknown[] = {(char *)exe, "--no-such-option", NULL};
    CHECK(run_args(exe, version, out, sizeof(out)) == 0 && !strncmp(out, "reticulum-c-node ", 17) && strchr(out, '.'));
    CHECK(run_args(exe, sample, out, sizeof(out)) == 0 && strstr(out, "[reticulum]") && strstr(out, "[interfaces]"));
    CHECK(snprintf(example, sizeof(example), "%s/example", dir) > 0);
    config_file(example, out);
    CHECK(run_check(exe, example) == 0);
    CHECK(!unlink(example));
    CHECK(run_args(exe, interactive, out, sizeof(out)) == 2);
    CHECK(run_args(exe, unknown, out, sizeof(out)) == 2);
  }
  CHECK(snprintf(path, sizeof(path), "%s/config", dir) > 0);
  config_file(path, valid);
  CHECK(run_check(exe, path) == 0);
  config_file(
      path,
      "[interfaces]\n[[Broken]]\ntype=TCPServerInterface\nlisten_port=70000\n");
  CHECK(run_check(exe, path) != 0);
  config_file(path, "[reticulum]\nshare_instance=Yes\nshared_instance_type=bogus\n");
  CHECK(run_check(exe, path) != 0);
  config_file(path, "[reticulum]\nshare_instance=Yes\nshared_instance_type=tcp\nshared_instance_port=4242\n"
                    "instance_control_port=4242\n"); /* the two ports must differ */
  CHECK(run_check(exe, path) != 0);
  config_file(path, "[interfaces]\n[[Bad]]\ntype=UnknownInterface\n");
  CHECK(run_check(exe, path) != 0);
  config_file(path,
              "[reticulum]\nuse_implicit_proof = No\npanic_on_interface_error = "
              "No\n[interfaces]\n[[T]]\ntype = TCPServerInterface\n"
              "listen_port = 0\noutgoing = No\n");
  CHECK(run_check(exe, path) == 0);
  config_file(path,
              "[reticulum]\nshare_instance = No\nlink_mtu_discovery = No\n"
              "[interfaces]\n[[T]]\ntype = TCPServerInterface\nlisten_port = 0\n");
  CHECK(run_check(exe, path) == 0);
  config_file(path,
              "[reticulum]\nshare_instance = No\n[interfaces]\n[[WiFi RNode]]\n"
              "type = RNodeInterface\nport = tcp://rnode.local\nfrequency = 868000000\n"
              "bandwidth = 125000\ntxpower = 7\nspreadingfactor = 8\ncodingrate = 5\n");
  CHECK(run_check(exe, path) == 0);
  config_file(path, "[reticulum]\nlink_mtu_discovery = maybe\n");
  CHECK(run_check(exe, path) != 0);
  config_file(path, "[reticulum]\nuse_implicit_proof = maybe\n");
  CHECK(run_check(exe, path) != 0);
  config_file(path, "[reticulum]\npanic_on_interface_error = maybe\n");
  CHECK(run_check(exe, path) != 0);
  config_file(path,
              "[interfaces]\n[[T]]\ntype = TCPServerInterface\n"
              "listen_port = 0\noutgoing = maybe\n");
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
/* a client of the reference's shared instance: the abstract Unix socket "\0rns/<name>" */
static int unix_connect(const char *name) {
  struct sockaddr_storage addr;
  size_t len = rnc_host_abstract_address(name, "", &addr, sizeof(addr));
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  CHECK(fd >= 0 && len);
  CHECK(!connect(fd, (struct sockaddr *)&addr, (socklen_t)len));
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
              contains(event.data, event.size, "rxb") &&
              contains(event.data, event.size, "rssi") &&
              contains(event.data, event.size, "snr"));
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
static void shared_data_fds(int local, int world) {
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
static void shared_data_test(unsigned local_port, unsigned world_port) {
  int world = tcp_connect(world_port), local = tcp_connect(local_port);
  shared_data_fds(local, world);
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
  /* rnsd's -v and -q move the configured level; -s logs to the file beside the configuration and leaves the level */
  {
    static const struct {
      const char *option;
      unsigned level;
      int logs_info;
      int to_service_file;
    } cases[] = {{"-v", 3, 1, 0}, {"-q", 4, 0, 0}, {"-vv", 2, 1, 0}, {"-q", 5, 1, 0}, {"-s", 4, 1, 1}, {"-sv", 3, 0, 1}};
    size_t k;
    char service_log[300];
    CHECK(snprintf(service_log, sizeof(service_log), "%s/logfile", dir) > 0);
    for (k = 0; k < sizeof(cases) / sizeof(*cases); ++k) {
      int peer, out[2];
      pid_t child;
      const char *where = cases[k].to_service_file ? service_log : logfile;
      (void)unlink(logfile);
      (void)unlink(service_log);
      write_config(cfg,
                   "[reticulum]\nenable_transport = No\nshare_instance = No\ninstance_name = logtest\n"
                   "[logging]\nloglevel = %u\n%s%s%s[interfaces]\n[[TCP]]\ntype = TCPServerInterface\n"
                   "listen_ip = 127.0.0.1\nlisten_port = %u\n",
                   cases[k].level, cases[k].to_service_file ? "" : "logdestination = file\nlogfile = ",
                   cases[k].to_service_file ? "" : logfile, cases[k].to_service_file ? "" : "\n", port);
      CHECK(!pipe(out));
      child = fork();
      CHECK(child >= 0);
      if (!child) {
        close(out[0]);
        CHECK(dup2(out[1], STDOUT_FILENO) >= 0);
        close(out[1]);
        execl(exe, exe, "--config", cfg, "--identity", key, "--admin", admin, cases[k].option, (char *)NULL);
        _exit(127);
      }
      close(out[1]);
      ready_line(out[0], id);
      peer = tcp_connect(port);
      for (waited = 0; waited < 30; ++waited) {
        struct timespec t = {0, 100000000};
        if (file_contains(where, "is up") || (!cases[k].logs_info && waited > 10))
          break;
        nanosleep(&t, NULL);
      }
      close(peer);
      {
        struct timespec t = {0, 300000000};
        nanosleep(&t, NULL);
      }
      stop(child, out[0]);
      CHECK(file_contains(where, "is up") == cases[k].logs_info);
      if (cases[k].to_service_file)
        CHECK(file_contains(service_log, "daemon: starting")); /* it did log there */
    }
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

/* ---- Live differential: the same scenario against the unmodified reference as a transport node and against
 * this daemon, with unmodified reference peers around it. Each node under test is a TCP server on a fixed port;
 * peers are reference processes (stdin commands, stdout lines). What the peers observe must agree. ---- */
static const char *live_peer =
    "import RNS, sys, time\n"
    "r = RNS.Reticulum(configdir=sys.argv[1], loglevel=0)\n"
    "t0 = time.time()\n"
    "ms = lambda: int((time.time() - t0) * 1000)\n"
    "d = RNS.Destination(RNS.Identity(), RNS.Destination.IN, RNS.Destination.SINGLE, 'reticulum_c', 'live')\n"
    "print('HASH', d.hexhash, flush=True)\n"
    "class H:\n"
    "    aspect_filter = None\n"
    "    def received_announce(self, destination_hash, announced_identity, app_data):\n"
    "        print('ANN', destination_hash.hex(), RNS.Transport.hops_to(destination_hash), ms(), flush=True)\n"
    "RNS.Transport.register_announce_handler(H())\n"
    "for line in sys.stdin:\n"
    "    p = line.split()\n"
    "    if p[0] == 'announce':\n"
    "        w = time.time()\n"
    "        while not all(i.online for i in RNS.Transport.interfaces) and time.time() - w < 10: time.sleep(0.05)\n"
    "        d.announce()\n"
    "        print('SENT', all(i.online for i in RNS.Transport.interfaces), flush=True)\n"
    "    elif p[0] == 'request':\n"
    "        h = bytes.fromhex(p[1]); s = time.time(); RNS.Transport.request_path(h)\n"
    "        while not RNS.Transport.has_path(h) and time.time() - s < 6: time.sleep(0.005)\n"
    "        print('PATH', p[1], RNS.Transport.hops_to(h) if RNS.Transport.has_path(h) else -1,\n"
    "              int((time.time() - s) * 1000), flush=True)\n"
    "    elif p[0] == 'quit':\n"
    "        break\n";
static const char *live_transport =
    "import RNS, sys\n"
    "r = RNS.Reticulum(configdir=sys.argv[1], loglevel=0)\n"
    "print('READY', flush=True)\n"
    "for line in sys.stdin:\n"
    "    if line.split()[0] == 'dump':\n"
    "        for h, e in list(RNS.Transport.path_table.items()):\n"
    "            print('TPATH', h.hex(), e[2], e[5].name, flush=True)\n"
    "        print('END', flush=True)\n"
    "    elif line.split()[0] == 'quit':\n"
    "        break\n";
typedef struct live_proc {
  pid_t pid;
  int in, out;
  char buf[16384];
  size_t used;
} live_proc;
static void live_spawn_argv(live_proc *p, const char *pythonpath, char *const argv[]) {
  int to[2], from[2];
  CHECK(!pipe(to) && !pipe(from));
  p->pid = fork();
  CHECK(p->pid >= 0);
  if (!p->pid) {
    CHECK(dup2(to[0], STDIN_FILENO) >= 0 && dup2(from[1], STDOUT_FILENO) >= 0 && dup2(from[1], STDERR_FILENO) >= 0);
    close(to[0]); close(to[1]); close(from[0]); close(from[1]);
    CHECK(!setenv("PYTHONPATH", pythonpath, 1));
    execv(argv[0], argv);
    _exit(127);
  }
  close(to[0]);
  close(from[1]);
  p->in = to[1];
  p->out = from[0];
  p->used = 0;
  p->buf[0] = 0;
}
static void live_spawn(live_proc *p, const char *python, const char *reference, const char *script, const char *dir) {
  char *argv[] = {(char *)python, "-c", (char *)script, (char *)dir, NULL};
  live_spawn_argv(p, reference, argv);
}
static void live_send(live_proc *p, const char *line) {
  signal(SIGPIPE, SIG_IGN);
  CHECK(write(p->in, line, strlen(line)) == (ssize_t)strlen(line));
}
/* the first buffered line that starts with `prefix` (consumed into `line`), waiting up to `ms` for it */
static int live_expect(live_proc *p, const char *prefix, unsigned ms, char *line, size_t size) {
  uint64_t end = now_ms() + ms;
  for (;;) {
    char *at = p->buf, *nl;
    while ((nl = strchr(at, '\n'))) {
      *nl = 0;
      if (!strncmp(at, prefix, strlen(prefix))) {
        CHECK(snprintf(line, size, "%s", at) < (int)size);
        memmove(p->buf, nl + 1, strlen(nl + 1) + 1);
        p->used = strlen(p->buf);
        return 1;
      }
      *nl = '\n';
      at = nl + 1;
    }
    {
      uint64_t now = now_ms();
      struct pollfd pf = {p->out, POLLIN, 0};
      if (now >= end)
        return 0;
      CHECK(poll(&pf, 1, (int)(end - now)) >= 0);
      if (pf.revents & POLLIN) {
        ssize_t n = read(p->out, p->buf + p->used, sizeof(p->buf) - 1 - p->used);
        if (n <= 0)
          return 0;
        p->used += (size_t)n;
        p->buf[p->used] = 0;
        CHECK(p->used < sizeof(p->buf) - 1);
      }
    }
  }
}
static void live_end(live_proc *p) {
  int status;
  (void)!write(p->in, "quit\n", 5);
  close(p->in);
  (void)kill(p->pid, SIGTERM);
  CHECK(waitpid(p->pid, &status, 0) == p->pid);
  close(p->out);
}
static void live_sleep(unsigned ms) {
  struct timespec t = {ms / 1000, (long)(ms % 1000) * 1000000L};
  nanosleep(&t, NULL);
}
/* a reference peer's configuration directory: transport off, no shared instance, one client to the node */
static void live_peer_config(char *dir, size_t size, const char *base, const char *name, unsigned port) {
  char path[600], text[600];
  CHECK(snprintf(dir, size, "%s/%s", base, name) < (int)size);
  CHECK(!mkdir(dir, 0700));
  CHECK(snprintf(path, sizeof(path), "%s/config", dir) < (int)sizeof(path));
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = No\nshare_instance = No\n[interfaces]\n[[T]]\n"
                 "type = TCPClientInterface\nenabled = Yes\ntarget_host = 127.0.0.1\ntarget_port = %u\n", port) > 0);
  config_file(path, text);
}
typedef struct live_node {
  int reference;
  pid_t pid;
  int fd;
  live_proc ref;
  char admin[300];
} live_node;
/* the node under test: the reference as a transport node, or this daemon, listening on `port`; `extra` is added
 * to the TCPServerInterface section */
static void live_node_start(live_node *n, int reference, const char *exe, const char *python, const char *ref_dir,
                            const char *base, unsigned port, const char *extra) {
  char dir[400], cfg[500], key[500], text[1024], identity[33];
  memset(n, 0, sizeof(*n));
  n->reference = reference;
  CHECK(snprintf(dir, sizeof(dir), "%s/%s-%u", base, reference ? "ref-node" : "c-node", port) < (int)sizeof(dir));
  CHECK(!mkdir(dir, 0700));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) < (int)sizeof(cfg));
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = Yes\nshare_instance = No\n[interfaces]\n[[Peers]]\n"
                 "type = TCPServerInterface\nenabled = Yes\nlisten_ip = 127.0.0.1\nlisten_port = %u\n%s", port,
                 extra ? extra : "") > 0);
  config_file(cfg, text);
  if (reference) {
    char line[256];
    live_spawn(&n->ref, python, ref_dir, live_transport, dir);
    CHECK(live_expect(&n->ref, "READY", 20000, line, sizeof(line)));
    return;
  }
  CHECK(snprintf(key, sizeof(key), "%s/identity", dir) < (int)sizeof(key));
  CHECK(snprintf(n->admin, sizeof(n->admin), "%s/admin", dir) < (int)sizeof(n->admin));
  n->pid = start(exe, cfg, key, n->admin, &n->fd);
  ready_line(n->fd, identity);
}
static void live_node_stop(live_node *n) {
  if (n->reference)
    live_end(&n->ref);
  else
    stop(n->pid, n->fd);
}
/* Scenario A: a path response from a known path. A peer announces; a second peer joins afterwards and asks for
 * the path; the node answers after PATH_REQUEST_GRACE. Returns the milliseconds the asker waited and its hops. */
static void live_path_response(int reference, const char *exe, const char *python, const char *ref_dir,
                               const char *base, long *wait_ms, long *hops) {
  unsigned port = unused_port();
  live_node node;
  live_proc announcer, asker;
  char dir[500], line[512], hash[40];
  live_node_start(&node, reference, exe, python, ref_dir, base, port, NULL);
  live_peer_config(dir, sizeof(dir), base, reference ? "a1" : "c1", port);
  live_spawn(&announcer, python, ref_dir, live_peer, dir);
  CHECK(live_expect(&announcer, "HASH", 20000, line, sizeof(line)));
  CHECK(snprintf(hash, sizeof(hash), "%s", line + 5) < (int)sizeof(hash));
  live_sleep(1500); /* connected */
  live_send(&announcer, "announce\n");
  live_sleep(2500); /* the node has learned the path and finished its own rebroadcasts */
  live_peer_config(dir, sizeof(dir), base, reference ? "a2" : "c2", port);
  live_spawn(&asker, python, ref_dir, live_peer, dir);
  CHECK(live_expect(&asker, "HASH", 20000, line, sizeof(line)));
  live_sleep(1500);
  CHECK(snprintf(line, sizeof(line), "request %s\n", hash) < (int)sizeof(line));
  live_send(&asker, line);
  CHECK(live_expect(&asker, "PATH", 10000, line, sizeof(line)));
  {
    char h[40];
    long w, hp;
    CHECK(sscanf(line, "PATH %39s %ld %ld", h, &hp, &w) == 3);
    *wait_ms = w;
    *hops = hp;
  }
  live_end(&asker);
  live_end(&announcer);
  live_node_stop(&node);
}
static void hex_of(const uint8_t *data, size_t size, char *out);
/* Scenario B: the hop limit. Announces are injected raw at a given hop count; a reference peer on the node says
 * which of them arrive and with how many hops. results[i] is -1 when announce i never arrived. */
#define LIVE_HOPS 9
static const unsigned live_hop_values[LIVE_HOPS] = {0, 100, 110, 120, 124, 125, 126, 127, 128};
static void live_hop_limit(int reference, const char *exe, const char *python, const char *ref_dir, const char *base,
                           long results[LIVE_HOPS], long learned[LIVE_HOPS]) {
  unsigned port = unused_port();
  live_node node;
  live_proc listener;
  char dir[500], line[512], hashes[LIVE_HOPS][33];
  int raw;
  size_t i;
  live_node_start(&node, reference, exe, python, ref_dir, base, port, NULL);
  live_peer_config(dir, sizeof(dir), base, reference ? "h1" : "h2", port);
  live_spawn(&listener, python, ref_dir, live_peer, dir);
  CHECK(live_expect(&listener, "HASH", 20000, line, sizeof(line)));
  live_sleep(2000);
  raw = tcp_connect(port);
  for (i = 0; i < LIVE_HOPS; ++i) {
    uint8_t key[64] = {0}, wire[RNC_MAX_MTU], framed[RNC_HOST_FRAME_MAX];
    unsigned random = 100u + (unsigned)i;
    rnc_identity id;
    rnc_packet packet;
    size_t n, m;
    key[10] = (uint8_t)(1 + i); /* X25519 clamping would erase differences in the low bits of key[0] */
    key[40] = (uint8_t)(1 + i);
    CHECK(rnc_identity_from_private(&id, key) == RNC_OK &&
          rnc_announce_create(&id, "reticulum_c.live.hops", NULL, 0, (uint64_t)time(NULL), rng, &random, &packet) ==
              RNC_OK);
    packet.hops = 0; /* the encoder refuses 128 and over, so the wire byte is set below */
    hex_of(packet.destination, 16, hashes[i]);
    CHECK(rnc_packet_encode(&packet, wire, sizeof(wire), &n) == RNC_OK);
    wire[1] = (uint8_t)live_hop_values[i];
    CHECK(rnc_host_frame_encode(RNC_HOST_HDLC, 0, wire, n, framed, sizeof(framed), &m) == RNC_OK);
    CHECK(write(raw, framed, m) == (ssize_t)m);
    live_sleep(900); /* slower than a new interface's ingress-control burst frequency */
    results[i] = -1;
  }
  /* collect what arrived, over the rebroadcast window */
  {
    uint64_t end = now_ms() + 6000;
    while (now_ms() < end) {
      char got[40];
      long hp, at;
      if (!live_expect(&listener, "ANN", 300, line, sizeof(line)))
        continue;
      CHECK(sscanf(line, "ANN %39s %ld %ld", got, &hp, &at) == 3);
      if (getenv("LIVE_DEBUG")) fprintf(stderr, "  %s\n", line);
      for (i = 0; i < LIVE_HOPS; ++i)
        if (!strcmp(got, hashes[i]))
          results[i] = hp;
    }
  }
  /* the node's own path table: which announces it learned a path for, and at how many hops */
  for (i = 0; i < LIVE_HOPS; ++i)
    learned[i] = -1;
  if (reference) {
    live_send(&node.ref, "dump\n");
    for (;;) {
      char got[40], iface[64];
      long hp;
      if (!live_expect(&node.ref, "", 3000, line, sizeof(line)) || !strncmp(line, "END", 3))
        break;
      if (strncmp(line, "TPATH ", 6))
        continue;
      CHECK(sscanf(line, "TPATH %39s %ld %63s", got, &hp, iface) >= 2);
      for (i = 0; i < LIVE_HOPS; ++i)
        if (!strcmp(got, hashes[i]))
          learned[i] = hp;
    }
  } else {
    char reply[8192];
    admin_command(node.admin, "ROUTES", reply, sizeof(reply));
    for (i = 0; i < LIVE_HOPS; ++i) {
      char needle[64], *at;
      CHECK(snprintf(needle, sizeof(needle), "destination=%s ", hashes[i]) > 0);
      at = strstr(reply, needle);
      if (at && (at = strstr(at, "hops=")))
        learned[i] = strtol(at + 5, NULL, 10);
    }
  }
  close(raw);
  live_end(&listener);
  live_node_stop(&node);
}
/* Scenario C: announce propagation between interface modes. The node has one interface per entry of `modes`
 * (each with a reference peer on it); every peer announces once; heard[i][j] says whether peer j heard peer i's
 * announce. `extras[i]` adds config lines to interface i. */
#define LIVE_IF_MAX 8
static void live_mode_matrix(int reference, const char *exe, const char *python, const char *ref_dir, const char *base,
                             size_t n, const char *const *modes, const char *const *extras,
                             int heard[LIVE_IF_MAX][LIVE_IF_MAX]) {
  unsigned ports[LIVE_IF_MAX];
  live_node node;
  live_proc peers[LIVE_IF_MAX];
  char hashes[LIVE_IF_MAX][40], extra[4096], dir[500], line[512], name[16];
  size_t i, j, used = 0;
  static unsigned serial;
  CHECK(n <= LIVE_IF_MAX);
  for (i = 0; i < n; ++i)
    ports[i] = unused_port();
  /* interface 0 is the node's first section; the rest follow in `extra` */
  extra[0] = 0;
  used += (size_t)snprintf(extra + used, sizeof(extra) - used, "mode = %s\n%s", modes[0], extras[0] ? extras[0] : "");
  for (i = 1; i < n; ++i) {
    int w = snprintf(extra + used, sizeof(extra) - used,
                     "[[If%zu]]\ntype = TCPServerInterface\nenabled = Yes\nlisten_ip = 127.0.0.1\nlisten_port = %u\n"
                     "mode = %s\n%s",
                     i, ports[i], modes[i], extras[i] ? extras[i] : "");
    CHECK(w > 0 && (size_t)w < sizeof(extra) - used);
    used += (size_t)w;
  }
  if (!reference && getenv("LIVE_LOG")) /* the node's own log, for finding out why a cell differs */
    used += (size_t)snprintf(extra + used, sizeof(extra) - used, "[logging]\nloglevel = %s\n", getenv("LIVE_LOG"));
  live_node_start(&node, reference, exe, python, ref_dir, base, ports[0], extra);
  ++serial;
  for (i = 0; i < n; ++i) {
    CHECK(snprintf(name, sizeof(name), "m%u-%zu", serial, i) > 0);
    live_peer_config(dir, sizeof(dir), base, name, ports[i]);
    live_spawn(&peers[i], python, ref_dir, live_peer, dir);
    CHECK(live_expect(&peers[i], "HASH", 20000, line, sizeof(line)));
    CHECK(snprintf(hashes[i], sizeof(hashes[i]), "%s", line + 5) < (int)sizeof(hashes[i]));
  }
  live_sleep(3000);
  for (i = 0; i < n; ++i) {
    live_send(&peers[i], "announce\n");
    live_sleep(2500); /* far enough apart that no peer's ingress control sees a burst */
  }
  for (i = 0; i < n; ++i)
    for (j = 0; j < n; ++j)
      heard[i][j] = 0;
  live_sleep(4000);
  for (j = 0; j < n; ++j)
    while (live_expect(&peers[j], "ANN", 50, line, sizeof(line))) {
      char got[40];
      long hp, at;
      CHECK(sscanf(line, "ANN %39s %ld %ld", got, &hp, &at) == 3);
      for (i = 0; i < n; ++i)
        if (!strcmp(got, hashes[i]) && i != j)
          heard[i][j] = (int)(at > 0 ? at : 1);
    }
  for (i = 0; i < n; ++i)
    live_end(&peers[i]);
  live_node_stop(&node);
}
static void live_modes(const char *exe, const char *reference, const char *python, const char *base, const char *title,
                       size_t n, const char *const *modes, const char *const *extras) {
  int ref[LIVE_IF_MAX][LIVE_IF_MAX], here[LIVE_IF_MAX][LIVE_IF_MAX];
  size_t i, j;
  live_mode_matrix(1, exe, python, reference, base, n, modes, extras, ref);
  live_mode_matrix(0, exe, python, reference, base, n, modes, extras, here);
  if (getenv("LIVE_REPEAT")) { /* run both again and show them, to see which cells depend on timing */
    int ref2[LIVE_IF_MAX][LIVE_IF_MAX], here2[LIVE_IF_MAX][LIVE_IF_MAX];
    live_mode_matrix(1, exe, python, reference, base, n, modes, extras, ref2);
    live_mode_matrix(0, exe, python, reference, base, n, modes, extras, here2);
    for (i = 0; i < n; ++i) {
      fprintf(stderr, "  %-12s", modes[i]);
      for (j = 0; j < n; ++j)
        fprintf(stderr, " %c%c", i == j ? '.' : ref[i][j] ? 'Y' : 'n', i == j ? ' ' : ref2[i][j] ? 'Y' : 'n');
      fprintf(stderr, "  |");
      for (j = 0; j < n; ++j)
        fprintf(stderr, " %c%c", i == j ? '.' : here[i][j] ? 'Y' : 'n', i == j ? ' ' : here2[i][j] ? 'Y' : 'n');
      fprintf(stderr, "\n");
    }
  }
  fprintf(stderr, "%s: rows announce, columns hear (reference | here)\n", title);
  for (i = 0; i < n; ++i) {
    fprintf(stderr, "  %-10s", modes[i]);
    for (j = 0; j < n; ++j) {
      if (getenv("LIVE_TIMES"))
        fprintf(stderr, " %5d", ref[i][j]);
      else
        fprintf(stderr, " %c", i == j ? '.' : ref[i][j] ? 'Y' : 'n');
    }
    fprintf(stderr, "  |");
    for (j = 0; j < n; ++j) {
      if (getenv("LIVE_TIMES"))
        fprintf(stderr, " %5d", here[i][j]);
      else
        fprintf(stderr, " %c", i == j ? '.' : here[i][j] ? 'Y' : 'n');
    }
    fprintf(stderr, "\n");
  }
  for (i = 0; i < n; ++i)
    for (j = 0; j < n; ++j)
      CHECK(!ref[i][j] == !here[i][j]);
}
/* Scenario D: gravity. Two interfaces, X at gravity 0 and Y at gravity 5. The same announce arrives on both, once
 * X first and once Y first; the path must end up on Y either way (the later copy on a higher gravity takes the
 * path over; a later copy on a lower one does not). learned[k] is 'X', 'Y' or '?' for case k. */
static void live_gravity(int reference, const char *exe, const char *python, const char *ref_dir, const char *base,
                         char learned[2]) {
  unsigned px = unused_port(), py = unused_port();
  live_node node;
  char extra[1024], line[512], hashes[2][33];
  int rx, ry, order, k;
  CHECK(snprintf(extra, sizeof(extra),
                 "gravity = 0\n[[Y]]\ntype = TCPServerInterface\nenabled = Yes\nlisten_ip = 127.0.0.1\n"
                 "listen_port = %u\ngravity = 5\n", py) > 0);
  live_node_start(&node, reference, exe, python, ref_dir, base, px, extra);
  live_sleep(1500);
  rx = tcp_connect(px);
  ry = tcp_connect(py);
  live_sleep(500);
  for (k = 0; k < 2; ++k) {
    uint8_t key[64] = {0}, wire[RNC_MAX_MTU], framed[RNC_HOST_FRAME_MAX];
    unsigned random = 200u + (unsigned)k;
    rnc_identity id;
    rnc_packet packet;
    size_t n, m;
    int first = k ? ry : rx, second = k ? rx : ry;
    key[10] = (uint8_t)(0x21 + k);
    key[40] = (uint8_t)(0x21 + k);
    CHECK(rnc_identity_from_private(&id, key) == RNC_OK &&
          rnc_announce_create(&id, "reticulum_c.live.gravity", NULL, 0, (uint64_t)time(NULL), rng, &random,
                              &packet) == RNC_OK);
    hex_of(packet.destination, 16, hashes[k]);
    CHECK(rnc_packet_encode(&packet, wire, sizeof(wire), &n) == RNC_OK &&
          rnc_host_frame_encode(RNC_HOST_HDLC, 0, wire, n, framed, sizeof(framed), &m) == RNC_OK);
    CHECK(write(first, framed, m) == (ssize_t)m);
    live_sleep(1500);
    CHECK(write(second, framed, m) == (ssize_t)m); /* the very same announce, heard again on the other interface */
    live_sleep(1500);
  }
  (void)order;
  learned[0] = learned[1] = '?';
  if (reference) {
    live_send(&node.ref, "dump\n");
    for (;;) {
      char got[40], iface[128];
      long hp;
      if (!live_expect(&node.ref, "", 3000, line, sizeof(line)) || !strncmp(line, "END", 3))
        break;
      if (strncmp(line, "TPATH ", 6))
        continue;
      CHECK(sscanf(line, "TPATH %39s %ld %127[^\n]", got, &hp, iface) == 3);
      for (k = 0; k < 2; ++k)
        if (!strcmp(got, hashes[k]))
          learned[k] = strstr(iface, "Client on Y") ? 'Y' : strstr(iface, "Client on Peers") ? 'X' : '?';
    }
  } else {
    char reply[8192];
    admin_command(node.admin, "ROUTES", reply, sizeof(reply));
    for (k = 0; k < 2; ++k) {
      char needle[64], *at;
      CHECK(snprintf(needle, sizeof(needle), "destination=%s interface=", hashes[k]) > 0);
      at = strstr(reply, needle);
      if (at) /* children are numbered in accept order: X was connected first */
        learned[k] = strtoul(at + strlen(needle), NULL, 10) == 0x80000000u ? 'X' : 'Y';
    }
  }
  close(rx);
  close(ry);
  live_node_stop(&node);
}
static void live_reference(const char *exe, const char *reference, const char *python) {
  char base[] = "/tmp/rnc-live-XXXXXX";
  long ref_wait, ref_hops, c_wait, c_hops, ref_hop[LIVE_HOPS], c_hop[LIVE_HOPS], ref_path[LIVE_HOPS], c_path[LIVE_HOPS];
  size_t i;
  CHECK(mkdtemp(base));
  live_path_response(1, exe, python, reference, base, &ref_wait, &ref_hops);
  live_path_response(0, exe, python, reference, base, &c_wait, &c_hops);
  fprintf(stderr, "path response: reference %ld ms %ld hops, this daemon %ld ms %ld hops\n", ref_wait, ref_hops,
          c_wait, c_hops);
  CHECK(ref_hops == c_hops && ref_hops > 0);
  /* PATH_REQUEST_GRACE is 0.4 s; both must sit in the same window, and well clear of an immediate answer */
  /* The reference only sweeps its announce table once a second, so its answer comes between 0.4 s and about
   * 1.3 s after the request; this daemon answers at the grace itself. */
  CHECK(ref_wait >= 350 && ref_wait <= 1500);
  CHECK(c_wait >= 350 && c_wait <= 800);
  live_hop_limit(1, exe, python, reference, base, ref_hop, ref_path);
  live_hop_limit(0, exe, python, reference, base, c_hop, c_path);
  for (i = 0; i < LIVE_HOPS; ++i) {
    fprintf(stderr,
            "announce injected at %u hops: forwarded as %ld (reference) / %ld (here); path learned at %ld / %ld\n",
            live_hop_values[i], ref_hop[i], c_hop[i], ref_path[i], c_path[i]);
    CHECK(ref_hop[i] == c_hop[i] && ref_path[i] == c_path[i]);
  }
  {
    const char *plain[] = {"full", "access_point", "roaming", "boundary", "internal", "gateway"};
    const char *none[6] = {NULL, NULL, NULL, NULL, NULL, NULL};
    const char *flags[] = {"announces_from_internal = No\n", NULL, NULL, "announces_to_internal = Yes\n", NULL, NULL};
    const char *mixed[] = {"internal", "full", "boundary", "internal", "roaming", "gateway"};
    live_modes(exe, reference, python, base, "interface modes", 6, plain, none);
    live_modes(exe, reference, python, base, "internal-mode flags", 6, mixed, flags);
  }
  {
    char ref_g[2], here_g[2];
    live_gravity(1, exe, python, reference, base, ref_g);
    live_gravity(0, exe, python, reference, base, here_g);
    fprintf(stderr, "gravity, announce first on X then Y / first on Y then X: reference path on %c %c, here %c %c\n",
            ref_g[0], ref_g[1], here_g[0], here_g[1]);
    CHECK(ref_g[0] == here_g[0] && ref_g[1] == here_g[1] && ref_g[0] != '?' && ref_g[1] != '?');
  }
  remove_tree(base);
  puts("live reference-node comparison passed");
}
/* ---- rnstatus -d / -D: records in the reference's discovery store, listed by ctl and by the reference ---- */
typedef struct disc_spec {
  const char *name, *type, *transport_id, *network_id, *config_entry, *reachable_on, *impl_name, *version, *lxmf,
      *modulation;
  int transport, hops, value, has_location, has_height, port, sf, cr;
  double latitude, longitude, height;
  long long frequency, bandwidth;
  double heard_ago, found_ago;
} disc_spec;
static void disc_write(const char *store, const disc_spec *d, unsigned serial) {
  uint8_t buf[4096];
  rnc_rpc_writer w;
  size_t size, entries;
  char path[600], hash[65];
  double now = (double)time(NULL);
  FILE *f;
  rnc_rpc_writer_init(&w, buf, sizeof(buf));
  entries = 13 + (d->impl_name ? 2 : 0) + (d->reachable_on ? 1 : 0) + (d->port ? 1 : 0) + (d->lxmf ? 1 : 0) +
            (d->frequency ? 2 : 0) + (d->sf ? 2 : 0) + (d->modulation ? 1 : 0);
  CHECK(rnc_rpc_write_map(&w, entries) == RNC_OK);
#define K(name) CHECK(rnc_rpc_write_string(&w, name) == RNC_OK)
#define STR(name, v) do { K(name); CHECK(rnc_rpc_write_string(&w, v) == RNC_OK); } while (0)
#define UINT(name, v) do { K(name); CHECK(rnc_rpc_write_uint(&w, (uint64_t)(v)) == RNC_OK); } while (0)
  STR("name", d->name);
  STR("type", d->type);
  K("transport"); CHECK(rnc_rpc_write_bool(&w, d->transport) == RNC_OK);
  UINT("hops", d->hops);
  UINT("value", d->value);
  STR("transport_id", d->transport_id);
  STR("network_id", d->network_id);
  K("discovered"); CHECK(rnc_rpc_write_real(&w, now - d->found_ago) == RNC_OK);
  K("last_heard"); CHECK(rnc_rpc_write_real(&w, now - d->heard_ago) == RNC_OK);
  K("latitude"); CHECK((d->has_location ? rnc_rpc_write_real(&w, d->latitude) : rnc_rpc_write_nil(&w)) == RNC_OK);
  K("longitude"); CHECK((d->has_location ? rnc_rpc_write_real(&w, d->longitude) : rnc_rpc_write_nil(&w)) == RNC_OK);
  K("height"); CHECK((d->has_height ? rnc_rpc_write_real(&w, d->height) : rnc_rpc_write_nil(&w)) == RNC_OK);
  STR("config_entry", d->config_entry ? d->config_entry : "");
  if (d->impl_name) {
    STR("impl_name", d->impl_name);
    STR("version", d->version);
  }
  if (d->reachable_on) STR("reachable_on", d->reachable_on);
  if (d->port) UINT("port", d->port);
  if (d->lxmf) STR("operator_lxmf_address", d->lxmf);
  if (d->frequency) {
    UINT("frequency", d->frequency);
    UINT("bandwidth", d->bandwidth);
  }
  if (d->sf) {
    UINT("sf", d->sf);
    UINT("cr", d->cr);
  }
  if (d->modulation) STR("modulation", d->modulation);
#undef UINT
#undef STR
#undef K
  CHECK(rnc_rpc_writer_finish(&w, &size) == RNC_OK);
  CHECK(snprintf(hash, sizeof(hash), "%02x%062u", (unsigned)(serial & 0xff), serial) > 0);
  CHECK(snprintf(path, sizeof(path), "%s/%s", store, hash) < (int)sizeof(path));
  f = fopen(path, "wb");
  CHECK(f && fwrite(buf, 1, size, f) == size && !fclose(f));
}
/* five records: a backbone with every field, an RNode of unknown stack, a stale one, an I2P one, and one of a type
 * that is not discoverable (never listed) */
/* ages are chosen so that RNS.prettytime's two-unit form never shows seconds, and the reference, which runs a second
 * or two after ctl, prints the same text */
static void disc_fill(const char *store) {
  static const char tid1[] = "11111111111111111111111111111111", nid1[] = "22222222222222222222222222222222",
                    tid2[] = "33333333333333333333333333333333";
  disc_spec recs[5];
  size_t i;
  memset(recs, 0, sizeof(recs));
  recs[0] = (disc_spec){"Backbone  Alpha  ", "BackboneInterface", tid1, nid1,
                        "[[Backbone Alpha]]\n  type = BackboneInterface\n  enabled = yes\n  remote = host.example\n"
                        "  target_port = 4242",
                        "host.example", "Reticulum", "1.5.5", "aabbccddeeff00112233445566778899", NULL,
                        1, 2, 16, 1, 1, 4242, 0, 0, 59.3293, 18.0686, 12.5, 0, 0, 8130, 444030};
  recs[1] = (disc_spec){"LoRa Hill North", "RNodeInterface", tid2, tid2, "[[LoRa Hill North]]\n  type = RNodeInterface",
                        NULL, NULL, NULL, NULL, NULL, 0, 1, 20, 0, 0, 0, 8, 5, 0, 0, 0, 868000000, 125000, 100000, 174630};
  recs[2] = (disc_spec){"Old Server", "TCPServerInterface", tid1, nid1, "[[Old Server]]\n  type = TCPServerInterface",
                        "192.0.2.7", "Reticulum", "1.4.0", NULL, NULL, 1, 3, 12, 1, 1, 4965, 0, 0, -33.8688, 151.2093, 0,
                        0, 0, 347430, 520230};
  recs[3] = (disc_spec){"An Extremely Long Interface Name That Goes On", "I2PInterface", tid2, nid1,
                        "[[Long]]\n  type = I2PInterface", "abcdefghijklmnop.b32.i2p", "SomeStackWithALongName", "0.9.12", NULL, NULL,
                        0, 4, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5430, 12630};
  recs[4] = (disc_spec){"Not Discoverable", "FooInterface", tid1, nid1, "x", NULL, "Reticulum", "1.5.5", NULL, NULL, 1, 1,
                        10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 60, 60};
  for (i = 0; i < 5; ++i)
    disc_write(store, &recs[i], (unsigned)i + 1u);
}
/* run argv with PYTHONPATH set when given, capturing its standard output */
static void capture_run(char *const argv[], const char *pythonpath, char *out, size_t cap) {
  int pipefd[2], status;
  pid_t child;
  size_t got = 0;
  ssize_t n;
  CHECK(!pipe(pipefd));
  child = fork();
  CHECK(child >= 0);
  if (!child) {
    int null = open("/dev/null", O_WRONLY);
    close(pipefd[0]);
    CHECK(null >= 0 && dup2(pipefd[1], STDOUT_FILENO) >= 0 && dup2(null, STDERR_FILENO) >= 0);
    close(pipefd[1]);
    if (pythonpath)
      CHECK(!setenv("PYTHONPATH", pythonpath, 1));
    execv(argv[0], argv);
    _exit(127);
  }
  close(pipefd[1]);
  while ((n = read(pipefd[0], out + got, cap - 1 - got)) > 0)
    got += (size_t)n;
  out[got] = 0;
  close(pipefd[0]);
  CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
}
static void status_discovered(const char *ctl, const char *reference, const char *python) {
  char dir[] = "/tmp/rnc-disc-XXXXXX", store[400], cfg[400], mine[16384], theirs[16384];
  static const char *const variants[][5] = {{"-d", NULL},
                                            {"-D", NULL},
                                            {"-d", "--show-unknown", NULL},
                                            {"-D", "--show-stale", "--show-unknown", NULL},
                                            {"-d", "lora", "--show-unknown", NULL},
                                            {"-d", "--show-stale", "--show-unknown", NULL}};
  size_t v, q;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  config_file(cfg, "[reticulum]\nenable_transport = No\nshare_instance = No\n[interfaces]\n");
  CHECK(snprintf(store, sizeof(store), "%s/storage", dir) > 0);
  CHECK(!mkdir(store, 0700));
  CHECK(snprintf(store, sizeof(store), "%s/storage/discovery", dir) > 0);
  CHECK(!mkdir(store, 0700));
  CHECK(snprintf(store, sizeof(store), "%s/storage/discovery/interfaces", dir) > 0);
  CHECK(!mkdir(store, 0700));
  disc_fill(store);
  for (v = 0; v < sizeof(variants) / sizeof(*variants); ++v) {
    char *argv[16];
    size_t n = 0;
    argv[n++] = (char *)ctl;
    argv[n++] = "status";
    for (q = 0; variants[v][q]; ++q)
      argv[n++] = (char *)variants[v][q];
    argv[n++] = "--config";
    argv[n++] = dir;
    argv[n] = NULL;
    capture_run(argv, NULL, mine, sizeof(mine));
    if (!v) { /* the default table: the available backbone and I2P entries, not the unknown RNode or the stale one */
      CHECK(strstr(mine, "Name") && strstr(mine, "Backbone Alpha") && strstr(mine, "Reticulum 1.5.5") &&
            strstr(mine, "59.3293, 18.0686") && !strstr(mine, "LoRa Hill") && !strstr(mine, "Old Server") &&
            !strstr(mine, "Not Discoverable"));
    }
    if (v == 1) { /* details of the same entries */
      CHECK(strstr(mine, "Network   ID : 22222222222222222222222222222222") &&
            strstr(mine, "Transport ID : 11111111111111111111111111111111") &&
            strstr(mine, "LXMF address : aabbccddeeff00112233445566778899") && strstr(mine, "Distance     : 2 hops") &&
            strstr(mine, "Port         : 4242") && strstr(mine, "Configuration Entry:\n  [[Backbone Alpha]]"));
    }
    if (reference) {
      char *rv[16];
      n = 0;
      rv[n++] = (char *)python;
      rv[n++] = "-m";
      rv[n++] = "RNS.Utilities.rnstatus";
      rv[n++] = "--config";
      rv[n++] = dir;
      for (q = 0; variants[v][q]; ++q)
        rv[n++] = (char *)variants[v][q];
      rv[n] = NULL;
      capture_run(rv, reference, theirs, sizeof(theirs));
      if (strcmp(mine, theirs)) {
        fprintf(stderr, "variant %zu differs\n--- ctl\n%s\n--- reference\n%s\n", v, mine, theirs);
        CHECK(0);
      }
    }
  }
  remove_tree(dir);
  puts(reference ? "rnstatus -d / -D match the reference" : "rnstatus -d / -D tests passed");
}
/* Echo: this example client against the reference's Echo.py server, and the reference's Echo.py client against
 * this example server, over a daemon that joins them. */
static pid_t spawn_cp(const char *cp, int *out, char *const *args);
static void read_until(int fd, const char *needle, char *buf, size_t size, unsigned seconds);
static int run_cp(const char *cp, char *out, size_t size, char *const *args);
static void stop_cp(pid_t pid, int fd);
static int live_find(live_proc *p, const char *needle, unsigned ms, char *line, size_t size) {
  uint64_t end = now_ms() + ms;
  while (now_ms() < end) {
    if (live_expect(p, "", 200, line, size) && strstr(line, needle))
      return 1;
  }
  return 0;
}
static void echo_reference(const char *exe, const char *echo, const char *reference, const char *python) {
  char base[] = "/tmp/rnc-echo-XXXXXX", cfg[400], key[400], admin[400], text[1024], identity[33], id_file[400],
       id_file2[400], connect[64], dir[500], line[2048], script[500], out[8192], hash[40];
  unsigned port = unused_port();
  pid_t daemon;
  int dfd;
  live_proc ref;
  const char *at;
  CHECK(mkdtemp(base));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", base) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/daemon_id", base) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", base) > 0);
  CHECK(snprintf(id_file, sizeof(id_file), "%s/echo_id", base) > 0);
  CHECK(snprintf(id_file2, sizeof(id_file2), "%s/echo_id2", base) > 0);
  CHECK(snprintf(connect, sizeof(connect), "127.0.0.1:%u", port) > 0);
  CHECK(snprintf(script, sizeof(script), "%s/Examples/Echo.py", reference) > 0);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = Yes\nshare_instance = No\n[interfaces]\n[[TCP]]\n"
                 "type = TCPServerInterface\nenabled = Yes\nlisten_ip = 127.0.0.1\nlisten_port = %u\n", port) > 0);
  config_file(cfg, text);
  daemon = start(exe, cfg, key, admin, &dfd);
  ready_line(dfd, identity);
  /* this client, the reference server */
  {
    char *argv[] = {(char *)python, script, "-s", "--config", dir, NULL};
    char *client[] = {(char *)echo, "--connect", connect, "--identity", id_file, "--count", "3", "client", hash, NULL};
    live_peer_config(dir, sizeof(dir), base, "refserver", port);
    live_spawn_argv(&ref, reference, argv);
    CHECK(live_find(&ref, "Echo server <", 30000, line, sizeof(line)));
    at = strstr(line, "Echo server <");
    CHECK(sscanf(at, "Echo server <%32[0-9a-f]>", hash) == 1);
    live_send(&ref, "\n"); /* the reference server announces on Enter */
    live_sleep(2000);
    memset(out, 0, sizeof(out));
    CHECK(run_cp(echo, out, sizeof(out), client) == 0);
    CHECK(strstr(out, "Valid reply received from") && strstr(out, hash) && strstr(out, "round-trip time is"));
    live_end(&ref);
  }
  /* the reference client, this server */
  {
    int sfd;
    pid_t server;
    char *serve[] = {(char *)echo, "--connect", connect, "--identity", id_file2, "server", NULL};
    server = spawn_cp(echo, &sfd, serve);
    memset(line, 0, sizeof(line));
    read_until(sfd, "Echo server <", line, sizeof(line), 10);
    read_until(sfd, ">", line, sizeof(line), 10);
    at = strstr(line, "Echo server <");
    CHECK(at && sscanf(at, "Echo server <%32[0-9a-f]>", hash) == 1);
    {
      char *argv[] = {(char *)python, script, "--config", dir, "-t", "10", hash, NULL};
      uint64_t end = now_ms() + 40000;
      int replied = 0;
      live_peer_config(dir, sizeof(dir), base, "refclient", port);
      live_spawn_argv(&ref, reference, argv);
      live_sleep(4000);
      while (now_ms() < end && !replied) {
        live_send(&ref, "\n"); /* Enter: request the path, then send once it is known */
        replied = live_find(&ref, "Valid reply received from", 3000, line, sizeof(line));
      }
      CHECK(replied);
      live_end(&ref);
    }
    memset(line, 0, sizeof(line));
    read_until(sfd, "proof sent", line, sizeof(line), 10);
    CHECK(strstr(line, "Received packet from echo client, proof sent"));
    stop_cp(server, sfd);
  }
  stop(daemon, dfd);
  remove_tree(base);
  puts("echo example matches the reference");
}
/* rnid -a: a reference peer on the instance's other interface hears the announce, with the destination rnid printed. */
static int ctl_run(const char *ctl, char *out, size_t size, ...);
static void rnid_announce_reference(const char *exe, const char *ctl, const char *reference, const char *python) {
  char base[] = "/tmp/rnc-rnida-XXXXXX", cfg[400], key[400], admin[400], text[1024], identity[33], idfile[400],
       dir[500], line[1024], out[4096], dest[40], data_arg[16];
  unsigned data = unused_port(), control = unused_port(), world = unused_port();
  pid_t daemon;
  int dfd;
  live_proc peer;
  char *at;
  CHECK(mkdtemp(base));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", base) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/daemon_id", base) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", base) > 0);
  CHECK(snprintf(idfile, sizeof(idfile), "%s/announcer.id", base) > 0);
  CHECK(snprintf(data_arg, sizeof(data_arg), "%u", data) > 0);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = Yes\nshare_instance = Yes\nshared_instance_type = tcp\n"
                 "shared_instance_port = %u\ninstance_control_port = %u\n[interfaces]\n[[World]]\n"
                 "type = TCPServerInterface\nenabled = Yes\nlisten_ip = 127.0.0.1\nlisten_port = %u\n",
                 data, control, world) > 0);
  config_file(cfg, text);
  daemon = start(exe, cfg, key, admin, &dfd);
  ready_line(dfd, identity);
  live_peer_config(dir, sizeof(dir), base, "listener", world);
  live_spawn(&peer, python, reference, live_peer, dir);
  CHECK(live_expect(&peer, "HASH", 20000, line, sizeof(line)));
  live_sleep(2500);
  CHECK(ctl_run(ctl, out, sizeof(out), "id", "-g", idfile, NULL) == 0);
  CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-a", "example.rnid.interop", "--data-port", data_arg, NULL) == 0);
  at = strstr(out, "destination <");
  CHECK(at && sscanf(at, "destination <%32[0-9a-f]>", dest) == 1);
  {
    uint64_t end = now_ms() + 15000;
    int heard = 0;
    while (now_ms() < end && !heard)
      heard = live_expect(&peer, "ANN", 300, line, sizeof(line)) && strstr(line, dest);
    CHECK(heard);
  }
  live_end(&peer);
  stop(daemon, dfd);
  remove_tree(base);
  puts("rnid announce is heard by the reference");
}
/* The shared instance as the reference does it on Linux: no shared_instance_type, so abstract Unix sockets named
 * by instance_name, for both the data port and the RPC port. Clients find it by name (ctl through --config, the
 * unmodified reference through its own config), and a second daemon cannot take the name. */
static int ctl_run(const char *ctl, char *out, size_t size, ...);
/* The reference's directory layout: a daemon started with only the directory (or with HOME and nothing else)
 * keeps its identity in <dir>/storage/transport_identity, the tools find it there, and --config can name the
 * directory for both. */
static void layout_test(const char *exe, const char *ctl, const char *reference, const char *python) {
  char home[] = "/tmp/rnc-home-XXXXXX", dir[256], cfg[256], storage[256], keypath[256], text[1024], out[16384],
       line[512];
  pid_t child;
  int fds[2], status;
  size_t used = 0;
  unsigned tries;
  struct stat sb;
  CHECK(mkdtemp(home));
  CHECK(snprintf(dir, sizeof(dir), "%s/.reticulum", home) > 0);
  CHECK(!mkdir(dir, 0700));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(storage, sizeof(storage), "%s/storage", dir) > 0);
  CHECK(snprintf(keypath, sizeof(keypath), "%s/storage/transport_identity", dir) > 0);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = No\nshare_instance = Yes\ninstance_name = rnc-layout-%d\n"
                 "[interfaces]\n[[T]]\ntype = TCPServerInterface\nlisten_ip = 127.0.0.1\nlisten_port = 0\n",
                 (int)getpid()) > 0);
  config_file(cfg, text);
  out[0] = 0;
  CHECK(!pipe(fds));
  child = fork();
  CHECK(child >= 0);
  if (!child) { /* no --config, no --identity: the search finds $HOME/.reticulum */
    close(fds[0]);
    CHECK(dup2(fds[1], STDOUT_FILENO) >= 0 && dup2(fds[1], STDERR_FILENO) >= 0);
    close(fds[1]);
    CHECK(!setenv("HOME", home, 1));
    execl(exe, exe, (char *)NULL);
    _exit(127);
  }
  close(fds[1]);
  for (tries = 0; tries < 100 && !strstr(out, "Ready"); ++tries) {
    struct pollfd p = {fds[0], POLLIN, 0};
    CHECK(poll(&p, 1, 100) >= 0);
    if (p.revents & POLLIN) {
      ssize_t n = read(fds[0], out + used, sizeof(out) - 1 - used);
      CHECK(n > 0);
      used += (size_t)n;
      out[used] = 0;
    }
  }
  CHECK(tries < 100 && strstr(out, "Ready"));
  CHECK(!stat(storage, &sb) && S_ISDIR(sb.st_mode) && (sb.st_mode & 077) == 0);
  CHECK(!stat(keypath, &sb) && S_ISREG(sb.st_mode) && sb.st_size == 64);
  /* the tool finds the instance by the same search, and by the directory */
  {
    int pipefd[2];
    pid_t tool;
    ssize_t n;
    size_t got = 0;
    CHECK(!pipe(pipefd));
    tool = fork();
    CHECK(tool >= 0);
    if (!tool) {
      close(pipefd[0]);
      CHECK(dup2(pipefd[1], STDOUT_FILENO) >= 0);
      close(pipefd[1]);
      CHECK(!setenv("HOME", home, 1));
      execl(ctl, ctl, "status", (char *)NULL);
      _exit(127);
    }
    close(pipefd[1]);
    while ((n = read(pipefd[0], line + got, sizeof(line) - 1 - got)) > 0)
      got += (size_t)n;
    close(pipefd[0]);
    line[got] = 0;
    CHECK(waitpid(tool, &status, 0) == tool && WIFEXITED(status) && !WEXITSTATUS(status));
    CHECK(strstr(line, "Shared Instance"));
  }
  CHECK(ctl_run(ctl, out, sizeof(out), "status", "--config", dir, NULL) == 0 && strstr(out, "Shared Instance"));
  if (reference)
    rns_status(python, reference, dir);
  CHECK(kill(child, SIGTERM) == 0 && waitpid(child, &status, 0) == child);
  close(fds[0]);
  remove_tree(home);
}
static void shared_unix(const char *exe, const char *ctl, const char *reference, const char *python) {
  char dir[] = "/tmp/rnc-node-unix-XXXXXX", cfg[256], keypath[256], admin[256], other[256], text[2048],
       identity[33], out[16384], name[64], wrong[256];
  unsigned world;
  pid_t process;
  int fd;
  {
    struct sockaddr_storage probe;
    if (!rnc_host_abstract_address("x", "", &probe, sizeof(probe))) { /* abstract sockets are a Linux feature */
      puts("Unix-socket shared-instance test skipped (not Linux)");
      return;
    }
  }
  CHECK(mkdtemp(dir));
  CHECK(snprintf(name, sizeof(name), "rnc-unix-%d", (int)getpid()) > 0);
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(other, sizeof(other), "%s/other", dir) > 0);
  CHECK(snprintf(wrong, sizeof(wrong), "%s/wrong", dir) > 0);
  CHECK(snprintf(keypath, sizeof(keypath), "%s/storage", dir) > 0);
  CHECK(!mkdir(keypath, 0700)); /* the reference reads the RPC key from <config>/storage/transport_identity */
  CHECK(snprintf(keypath, sizeof(keypath), "%s/storage/transport_identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = No\nshare_instance = Yes\ninstance_name = %s\n"
                 "[interfaces]\n[[External TCP]]\ntype = TCPServerInterface\nlisten_ip = 127.0.0.1\n"
                 "listen_port = 0\nmode = gateway\n", name) > 0);
  config_file(cfg, text);
  process = start(exe, cfg, keypath, admin, &fd);
  ready_line(fd, identity);
  world = admin_status(admin);
  CHECK(world);
  /* the data port: a local client announces, the world side hears it */
  shared_data_fds(unix_connect(name), tcp_connect(world));
  /* the RPC port, found through the config's instance_name */
  CHECK(ctl_run(ctl, out, sizeof(out), "status", "--config", cfg, "--identity", keypath, NULL) == 0 &&
        strstr(out, "Shared Instance") && strstr(out, "External"));
  /* another instance name is another (absent) instance */
  CHECK(snprintf(text, sizeof(text), "[reticulum]\ninstance_name = %s-absent\n", name) > 0);
  config_file(wrong, text);
  CHECK(ctl_run(ctl, out, sizeof(out), "status", "--config", wrong, "--identity", keypath, NULL) != 0);
  /* the name is taken: a second daemon on it does not start */
  {
    char second[256], second_key[256], second_admin[256];
    int status;
    pid_t child;
    CHECK(snprintf(second, sizeof(second), "%s/second", dir) > 0);
    CHECK(snprintf(second_key, sizeof(second_key), "%s/second_identity", dir) > 0);
    CHECK(snprintf(second_admin, sizeof(second_admin), "%s/second_admin", dir) > 0);
    CHECK(snprintf(text, sizeof(text),
                   "[reticulum]\nenable_transport = No\nshare_instance = Yes\ninstance_name = %s\n"
                   "[interfaces]\n[[T]]\ntype = TCPServerInterface\nlisten_ip = 127.0.0.1\nlisten_port = 0\n",
                   name) > 0);
    config_file(second, text);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
      CHECK(freopen("/dev/null", "w", stdout) && freopen("/dev/null", "w", stderr));
      execl(exe, exe, "--config", second, "--identity", second_key, "--admin", second_admin, (char *)NULL);
      _exit(127);
    }
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) != 0 && WEXITSTATUS(status) != 127);
  }
  if (reference)
    rns_status(python, reference, dir);
  stop(process, fd);
  remove_tree(dir);
  (void)other;
  layout_test(exe, ctl, reference, python);
  puts(reference ? "unmodified RNS Unix-socket shared-instance test passed"
                 : "native Unix-socket shared-instance test passed");
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


/* Runs the CLI tool with NULL-terminated arguments; returns its exit status
 * and captures stdout and stderr together. */
static int ctl_run(const char *ctl, char *out, size_t size, ...) {
  const char *argv[32];
  int fds[2], status, argc = 1;
  size_t n = 0;
  pid_t p;
  va_list args;
  const char *a;
  argv[0] = ctl;
  va_start(args, size);
  while ((a = va_arg(args, const char *)) != NULL && argc < 31)
    argv[argc++] = a;
  va_end(args);
  argv[argc] = NULL;
  CHECK(!pipe(fds));
  p = fork();
  CHECK(p >= 0);
  if (!p) {
    close(fds[0]);
    CHECK(dup2(fds[1], STDOUT_FILENO) >= 0 && dup2(fds[1], STDERR_FILENO) >= 0);
    close(fds[1]);
    execv(ctl, (char *const *)argv);
    _exit(127);
  }
  close(fds[1]);
  for (;;) {
    ssize_t got = read(fds[0], out + n, size - 1 - n);
    if (got <= 0)
      break;
    n += (size_t)got;
    if (n >= size - 1)
      break;
  }
  out[n] = 0;
  close(fds[0]);
  CHECK(waitpid(p, &status, 0) == p && WIFEXITED(status));
  return WEXITSTATUS(status);
}
static void hex_of(const uint8_t *data, size_t size, char *out) {
  size_t i;
  for (i = 0; i < size; ++i)
    sprintf(out + 2 * i, "%02x", data[i]);
}
static void file_bytes(const char *path, const char *data, size_t size) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  CHECK(fd >= 0 && write(fd, data, size) == (ssize_t)size);
  close(fd);
}
static size_t file_read(const char *path, char *out, size_t size) {
  int fd = open(path, O_RDONLY);
  ssize_t n;
  CHECK(fd >= 0);
  n = read(fd, out, size);
  CHECK(n >= 0);
  close(fd);
  return (size_t)n;
}
static void write_identity(const char *path, uint8_t fill, char hash[33]);
/* Metadata for signed messages, with a spec: nested sections, quoting, comments, lists, a trailing comma, an empty
 * value, defaults (including None and a list), and a section only the spec has. */
static const char meta_fixture[] =
    "# release notes\n"
    "title = Release notes\n"
    "count = 42\n"
    "ratio = 1.5\n"
    "tags = alpha, beta, \"gamma, delta\"\n"
    "flag = yes\n"
    "quoted = \"it's quoted\"   # trailing comment\n"
    "empty =\n"
    "single_list = one,\n"
    "\n"
    "[author]\n"
    "  name = Test User\n"
    "  email = 'test@example.com'\n"
    "  [[address]]\n"
    "    city = Paris\n"
    "[build]\n"
    "number = 7\n";
static const char meta_spec_fixture[] =
    "title = string(max=40)\n"
    "count = \"integer(0, 100)\"\n"
    "ratio = \"float(min=0, max=10)\"\n"
    "tags = \"string_list(min=1, max=5)\"\n"
    "flag = boolean\n"
    "quoted = string\n"
    "empty = string(default=\"x\")\n"
    "single_list = list\n"
    "missing_with_default = integer(default=5)\n"
    "none_default = string(default=None)\n"
    "list_default = \"int_list(default=list(1, 2, 3))\"\n"
    "mode = 'option(\"fast\", \"slow\", default=\"fast\")'\n"
    "[author]\n"
    "name = string\n"
    "email = string\n"
    "[[address]]\n"
    "city = string\n"
    "[build]\n"
    "number = integer\n"
    "[extra]\n"
    "note = string(default=\"n/a\")\n";
/* Awkward values: signs, a long integer, floats Python formats with an exponent, boolean and empty lists, a quoted
 * key and section name, UTF-8, and a value longer than the 64 character display rows. */
static const char meta_edge_fixture[] =
    "long_text = 0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789\n"
    "\"quoted key\" = value\n"
    "neg = -17\n"
    "big = 123456789012\n"
    "small = 1e-5\n"
    "huge = 1e16\n"
    "third = 0.1\n"
    "mid = 12345.678\n"
    "unicode = caf\xc3\xa9 \xe2\x98\x95\n"
    "bools = on, no, 1\n"
    "empty_list = ,\n"
    "[ \"section one\" ]\n"
    "x = 1\n";
static const char meta_edge_spec_fixture[] =
    "neg = integer\n"
    "big = integer\n"
    "small = float\n"
    "huge = float\n"
    "third = float\n"
    "mid = float\n"
    "bools = bool_list\n"
    "empty_list = list\n"
    "[ \"section one\" ]\n"
    "x = integer\n";
static void cli_tools_id(const char *ctl, const char *dir) {
  char out[4096], idfile[300], data[300], sig[320], enc[320], dec[320],
      buf[256], hex[40];
  const char *text = "reticulum-c identity tool test payload";
  rnc_identity id;
  uint8_t private_key[64];
  CHECK(snprintf(idfile, sizeof(idfile), "%s/tool.id", dir) > 0);
  CHECK(snprintf(data, sizeof(data), "%s/payload", dir) > 0);
  CHECK(snprintf(sig, sizeof(sig), "%s.rsg", data) > 0);
  CHECK(snprintf(enc, sizeof(enc), "%s.rfe", data) > 0);
  CHECK(snprintf(dec, sizeof(dec), "%s/decrypted", dir) > 0);
  file_bytes(data, text, strlen(text));
  CHECK(ctl_run(ctl, out, sizeof(out), "id", "-g", idfile, NULL) == 0);
  CHECK(file_read(idfile, buf, sizeof(buf)) == 64);
  CHECK(ctl_run(ctl, out, sizeof(out), "id", "-g", idfile, NULL) != 0);
  memcpy(private_key, buf, 64);
  CHECK(rnc_identity_from_private(&id, private_key) == RNC_OK);
  hex_of(id.hash, 16, hex);
  CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-p", NULL) == 0 &&
        strstr(out, hex) && strstr(out, "Private Key   : Hidden"));
  CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-p", "-P", NULL) ==
            0 &&
        !strstr(out, "Hidden"));
  {
    uint8_t name_hash[10], dest[16];
    char want[40];
    CHECK(rnc_destination_hash("example.aspect", &id, name_hash, dest) ==
          RNC_OK);
    hex_of(dest, 16, want);
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-H",
                  "example.aspect", NULL) == 0 &&
          strstr(out, want));
  }
  CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-s", data, "--raw",
                NULL) == 0);
  CHECK(file_read(sig, buf, sizeof(buf)) == 64 &&
        rnc_identity_verify(&id, text, strlen(text), (uint8_t *)buf) == RNC_OK);
  CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-V", sig, "-r",
                data, "--raw", NULL) == 0);
  file_bytes(data, "tampered", 8);
  CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-V", sig, "-r",
                data, "--raw", NULL) == 10);
  file_bytes(data, text, strlen(text));
  CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-e", data, NULL) ==
        0);
  CHECK(file_read(enc, buf, sizeof(buf)) > strlen(text) + 80);
  CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-d", enc, "-w",
                dec, NULL) == 0);
  CHECK(file_read(dec, buf, sizeof(buf)) == strlen(text) &&
        !memcmp(buf, text, strlen(text)));
  /* flipping a ciphertext byte must fail with the decrypt error code */
  {
    char raw[512];
    size_t n = file_read(enc, raw, sizeof(raw));
    raw[n - 1] ^= 1;
    file_bytes(enc, raw, n);
  }
  CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-d", enc, "-w",
                dec, "-f", NULL) == 12);
  /* signature envelopes: the default (no --raw) form carries the signer, so it validates without -i;
   * -i then names who must have signed it */
  {
    char other[300], other_hash[33];
    char sigbuf[512];
    CHECK(snprintf(other, sizeof(other), "%s/other.id", dir) > 0);
    write_identity(other, 140, other_hash);
    file_bytes(data, text, strlen(text));
    CHECK(!unlink(sig));
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-s", data, NULL) == 0 && strstr(out, "Signed file") &&
          strstr(out, hex));
    CHECK(file_read(sig, sigbuf, sizeof(sigbuf)) > 64 + 60);
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-V", sig, NULL) == 0 && strstr(out, "Signature is valid") &&
          strstr(out, hex));
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-V", sig, NULL) == 0 && strstr(out, "Signature is valid"));
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", other, "-V", sig, NULL) == 10 && strstr(out, "NOT signed by") &&
          strstr(out, other_hash));
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-s", data, NULL) == 11); /* not overwritten */
    file_bytes(data, "changed after signing", 21);
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-V", sig, NULL) == 10 && strstr(out, "Invalid signature"));
    file_bytes(data, text, strlen(text));
    {
      size_t sig_size = file_read(sig, sigbuf, sizeof(sigbuf));
      sigbuf[10] ^= 1; /* a flipped signature byte */
      file_bytes(sig, sigbuf, sig_size);
    }
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-V", sig, NULL) == 10);
    /* a bare (legacy) signature needs the identity */
    CHECK(!unlink(sig));
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-s", data, "--raw", NULL) == 0);
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-V", sig, NULL) == 2);
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-V", sig, "--raw", NULL) == 0);
    CHECK(!unlink(sig));
  }
  /* signed messages (rnid -S): the text travels inside the .rsm, which validates without the original */
  {
    char base[300], rsm[320], msgfile[300], other[300], other_hash[33], bytes[1024];
    size_t size;
    CHECK(snprintf(base, sizeof(base), "%s/note", dir) > 0 && snprintf(rsm, sizeof(rsm), "%s.rsm", base) > 0);
    CHECK(snprintf(msgfile, sizeof(msgfile), "%s/note.txt", dir) > 0 && snprintf(other, sizeof(other), "%s/other2.id", dir) > 0);
    write_identity(other, 141, other_hash);
    (void)unlink(rsm);
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-S", "meet at noon, bring maps", "-w", base, NULL) == 0 &&
          strstr(out, "Message signed with") && strstr(out, hex) && strstr(out, "note.rsm"));
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-V", rsm, NULL) == 0 &&
          strstr(out, "Signature is valid, the following message was signed by") && strstr(out, hex) &&
          strstr(out, "meet at noon, bring maps"));
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-V", rsm, NULL) == 0);
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", other, "-V", rsm, NULL) == 10 && strstr(out, "NOT signed by") &&
          !strstr(out, "meet at noon"));
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-S", "again", "-w", base, NULL) == 11); /* not overwritten */
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-S", "again", "-w", base, "-f", NULL) == 0);
    /* a flipped byte in the stored text no longer matches the signed hash */
    size = file_read(rsm, bytes, sizeof(bytes));
    CHECK(size > 64 + 100);
    bytes[size - 1] ^= 1;
    file_bytes(rsm, bytes, size);
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-V", rsm, NULL) == 10 && strstr(out, "Invalid signature"));
    /* the message from a file; text and file together, or no write path, are refused */
    file_bytes(msgfile, "from a file\nsecond line", 23);
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-S", "-r", msgfile, "-w", base, "-f", NULL) == 0);
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-V", rsm, NULL) == 0 && strstr(out, "from a file\nsecond line"));
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-S", "x", "-r", msgfile, "-w", base, "-f", NULL) == 250);
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-S", "no destination", NULL) == 250);
    CHECK(!unlink(rsm)); /* the text forms print and write nothing, even given a write path */
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-S", "x", "-w", base, "-f", "-b", NULL) == 0 &&
          strstr(out, "#### Start of rsg data ####") && strstr(out, " End of rsg data ####") &&
          strstr(out, "Message signed with <") && access(rsm, F_OK) != 0);
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-S", "x", "-U", NULL) == 0 &&
          strstr(out, "Start of rsg data") && strstr(out, "Message signed with"));
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-S", "x", "-b", "-U", NULL) != 0 &&
          strstr(out, "mutually exclusive"));
    CHECK(!unlink(msgfile));
  }
  /* metadata (rnid -E, --meta-spec, --meta): without a spec every value is text, with one the values are typed
   * and the defaults fill in; --meta lists them, signer and key first, plain values before subsections */
  {
    char base[300], rsm[320], meta[320], spec[330], bad[320];
    CHECK(snprintf(base, sizeof(base), "%s/withmeta", dir) > 0 && snprintf(rsm, sizeof(rsm), "%s.rsm", base) > 0);
    CHECK(snprintf(meta, sizeof(meta), "%s/note.meta", dir) > 0 && snprintf(spec, sizeof(spec), "%s.spec", meta) > 0);
    CHECK(snprintf(bad, sizeof(bad), "%s/bad.meta", dir) > 0);
    file_bytes(meta, meta_fixture, strlen(meta_fixture));
    /* no spec file: strings all the way */
    (void)unlink(spec);
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-S", "hello", "-E", meta, "-w", base, "-f", NULL) == 0 &&
          strstr(out, "Embedding metadata from") && !strstr(out, "using spec"));
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-V", rsm, "--meta", NULL) == 0);
    CHECK(strstr(out, "RSM Metadata\n============\n\nb  signer=") && strstr(out, "\nb  pubkey=") &&
          strstr(out, "\ns  title=Release notes\n") && strstr(out, "\ns  count=42\n") &&
          strstr(out, "\ns  tags=alpha, beta, \"gamma, delta\"") == NULL);
    CHECK(strstr(out, "\nl  tags=['alpha', 'beta', 'gamma, delta']\n") && strstr(out, "\ns  quoted=it's quoted\n") &&
          strstr(out, "\ns  empty=\n") && strstr(out, "\nl  single_list=['one']\n"));
    CHECK(strstr(out, "\nd  author:\ns    name=Test User\ns    email=test@example.com\nd    address:\ns      city=Paris\n") &&
          strstr(out, "\nd  build:\ns    number=7\n"));
    CHECK(strstr(out, "\nValidation\n==========\n\nSignature is valid, the message was signed by <") &&
          strstr(out, ">\n\nMessage\n=======\n\nhello\n"));
    /* with the spec beside it: typed values, defaults, and a section only the spec has */
    file_bytes(spec, meta_spec_fixture, strlen(meta_spec_fixture));
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-S", "hello", "-E", meta, "-w", base, "-f", NULL) == 0 &&
          strstr(out, "using spec from"));
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-V", rsm, "--meta", NULL) == 0);
    CHECK(strstr(out, "\ni  count=42\n") && strstr(out, "\nf  ratio=1.5\n") && strstr(out, "\nu  flag=True\n") &&
          strstr(out, "\ni  missing_with_default=5\n") && strstr(out, "\nN  none_default=None\n") &&
          strstr(out, "\nl  list_default=[1, 2, 3]\n") && strstr(out, "\ns  mode=fast\n") &&
          strstr(out, "\nd  extra:\ns    note=n/a\n"));
    CHECK(strstr(out, "mode=fast\nd  author:") != NULL); /* defaults follow the file's values, then the sections */
    /* a value the spec rejects, and metadata that does not parse, stop the signing */
    /* an unquoted comma in a check: the reference fails on it, so does this */
    file_bytes(bad, "count = integer(0, 100)\n", 24);
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-S", "hello", "-E", meta, "--meta-spec", bad, "-w", base, "-f",
                  NULL) == 254);
    file_bytes(bad, "count = 500\n", 12);
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-S", "hello", "-E", bad, "--meta-spec", spec, "-w", base, "-f",
                  NULL) == 254);
    file_bytes(bad, "key = \"unterminated\n", 20);
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-S", "hello", "-E", bad, "-w", base, "-f", NULL) == 254);
    file_bytes(bad, "a = 1\na = 2\n", 12);
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-S", "hello", "-E", bad, "-w", base, "-f", NULL) == 254);
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-S", "hello", "-E", "/nonexistent/x.meta", "-w", base, "-f",
                  NULL) == 6);
    {
      /* syntax the parser refuses (each would be an error in ConfigObj too), and spec checks that fail */
      static const char *broken[] = {"[[orphan]]\nkey = 1\n",        /* a subsection with no parent */
                                     "[a]\nx = 1\n[a]\ny = 2\n",     /* the same section twice */
                                     "[a]]\nx = 1\n",               /* mismatched brackets */
                                     "just some words\n",           /* neither a section nor key = value */
                                     "k = a,, b\n",                 /* an empty list item */
                                     "k = '''triple'''\n"};         /* unsupported here */
      static const char *spec_cases[][2] = {
          {"mode = slow\n", "mode = 'option(\"fast\", \"on\")'\n"},    /* not one of the options */
          {"x = 1\n", "y = integer\n"},                             /* required, missing, no default */
          {"x = abc\n", "x = integer\n"},                           /* not an integer */
          {"x = 1.5\n", "x = integer\n"},                           /* a float is not an integer */
          {"x = maybe\n", "x = boolean\n"},                         /* not a boolean */
          {"x = single\n", "x = list\n"},                           /* one value is not a list */
          {"x = a, b, c\n", "x = 'list(max=2)'\n"},                 /* too many items */
          {"x = toolong\n", "x = 'string(max=3)'\n"},               /* too long */
          {"[x]\ny = 1\n", "x = integer\n"},                        /* a section where a value belongs */
          {"x = 1\n", "[x]\ny = integer\n"},                        /* a value where a section belongs */
          {"x = 1\n", "x = ip_addr\n"},                             /* a check this port does not cover */
      };
      size_t k;
      for (k = 0; k < sizeof(broken) / sizeof(*broken); ++k) {
        file_bytes(bad, broken[k], strlen(broken[k]));
        CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-S", "hello", "-E", bad, "-w", base, "-f", NULL) == 254);
      }
      for (k = 0; k < sizeof(spec_cases) / sizeof(*spec_cases); ++k) {
        file_bytes(bad, spec_cases[k][0], strlen(spec_cases[k][0]));
        file_bytes(spec, spec_cases[k][1], strlen(spec_cases[k][1]));
        CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-S", "hello", "-E", bad, "--meta-spec", spec, "-w", base,
                      "-f", NULL) == 254);
      }
      /* and the cases that look odd but are fine: an unknown key passes through, bounds are inclusive */
      file_bytes(bad, "x = 100\nextra = whatever\n", 24);
      file_bytes(spec, "x = \"integer(0, 100)\"\n", 21);
      CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-S", "hello", "-E", bad, "--meta-spec", spec, "-w", base,
                    "-f", NULL) == 0);
      CHECK(ctl_run(ctl, out, sizeof(out), "id", "-V", rsm, "--meta", NULL) == 0 && strstr(out, "\ni  x=100\n") &&
            strstr(out, "\ns  extra=whatever\n"));
    }
    CHECK(!unlink(rsm) && !unlink(meta) && !unlink(spec) && !unlink(bad));
  }
  /* base32 and base64 output and import (rnid -B, -b, -m, -M); the private key is the bytes 0..63 so the
   * expected text is fixed */
  {
    static const char *b32 = "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSAIJCEMSCKJRHFAUSUKZMFUXC6MBRGIZTINJWG44DSOR3HQ6T4PY=";
    static const char *b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw==";
    char fixed[300], imported[300], pub_hex[140], cmp[4096];
    unsigned char key[64];
    unsigned k;
    rnc_identity fixed_id;
    for (k = 0; k < 64; ++k)
      key[k] = (unsigned char)k;
    CHECK(snprintf(fixed, sizeof(fixed), "%s/fixed.id", dir) > 0 && snprintf(imported, sizeof(imported), "%s/imported.id", dir) > 0);
    file_bytes(fixed, (const char *)key, 64);
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", fixed, "-X", "-B", NULL) == 0 && strstr(out, b32));
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", fixed, "-X", "-b", NULL) == 0 && strstr(out, b64));
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", fixed, "-p", "-P", "-b", NULL) == 0 && strstr(out, b64));
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", fixed, "-X", "-B", "-b", NULL) != 0); /* one format only */
    /* importing the private key in each format gives the same identity */
    CHECK(rnc_identity_from_private(&fixed_id, key) == RNC_OK);
    hex_of(fixed_id.public_key, 64, pub_hex);
    CHECK(ctl_run(ctl, cmp, sizeof(cmp), "id", "-M", b32, "-x", NULL) == 0 && strstr(cmp, pub_hex) && strstr(cmp, "base32"));
    CHECK(ctl_run(ctl, cmp, sizeof(cmp), "id", "-M", b64, "-x", NULL) == 0 && strstr(cmp, pub_hex) && strstr(cmp, "base64"));
    {
      char hexkey[140];
      hex_of(key, 64, hexkey);
      CHECK(ctl_run(ctl, cmp, sizeof(cmp), "id", "-M", hexkey, "-x", NULL) == 0 && strstr(cmp, pub_hex) && strstr(cmp, "hex"));
    }
    CHECK(ctl_run(ctl, cmp, sizeof(cmp), "id", "-M", fixed, "-x", NULL) == 0 && strstr(cmp, pub_hex));
    CHECK(ctl_run(ctl, cmp, sizeof(cmp), "id", "-M", "not-an-identity", "-x", NULL) == 8);
    /* a public identity imports and exports, and cannot sign */
    CHECK(ctl_run(ctl, cmp, sizeof(cmp), "id", "-m", pub_hex, "-x", NULL) == 0 && strstr(cmp, pub_hex));
    CHECK(ctl_run(ctl, cmp, sizeof(cmp), "id", "-m", pub_hex, "-p", NULL) == 0 && strstr(cmp, "Not available"));
    CHECK(ctl_run(ctl, cmp, sizeof(cmp), "id", "-m", pub_hex, "-s", data, "--raw", NULL) != 0);
    (void)imported;
    rnc_identity_clear(&fixed_id);
  }
  rnc_identity_clear(&id);
}
/* The operator tools talk to a running daemon over its authenticated RPC port
 * and manage identities offline. */
static void cli_tools(const char *exe, const char *ctl) {
  char dir[] = "/tmp/rnc-node-ctl-XXXXXX", cfg[256], keypath[256], admin[256],
       text[2048], identity[33], out[16384], reply[4096], hash[33], port_arg[16],
       control_arg[16], data_arg[16];
  unsigned port = unused_port(), control = unused_port();
  pid_t process;
  int fd, local;
  uint8_t private_key[64] = {9}, raw[RNC_MAX_MTU], framed[RNC_HOST_FRAME_MAX],
          zero_key[65];
  size_t n, m;
  unsigned random = 41;
  rnc_identity id;
  rnc_packet packet;
  CHECK(port != control && mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(keypath, sizeof(keypath), "%s/identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = No\nshare_instance = "
                 "Yes\nshared_instance_type = tcp\nshared_instance_port = "
                 "%u\ninstance_control_port = %u\n[interfaces]\n[[External "
                 "TCP]]\ntype = TCPServerInterface\nlisten_ip = "
                 "127.0.0.1\nlisten_port = 0\nmode = gateway\n",
                 port, control) > 0);
  config_file(cfg, text);
  CHECK(snprintf(port_arg, sizeof(port_arg), "%u", control) > 0);
  CHECK(snprintf(data_arg, sizeof(data_arg), "%u", port) > 0);
  process = start(exe, cfg, keypath, admin, &fd);
  ready_line(fd, identity);

  /* status: text, JSON, and authentication failure */
  CHECK(ctl_run(ctl, out, sizeof(out), "status", "--port", port_arg,
                "--identity", keypath, NULL) == 0);
  CHECK(strstr(out, "Shared Instance") && strstr(out, "Up") &&
        strstr(out, "Traffic") && strstr(out, "Mode      : Gateway") &&
        strstr(out, "Mode      : Internal"));
  CHECK(ctl_run(ctl, out, sizeof(out), "status", "-j", "--port", port_arg,
                "--identity", keypath, NULL) == 0);
  CHECK(out[0] == '{' && strstr(out, "\"interfaces\"") && strstr(out, "\"rxb\"") &&
        strstr(out, "\"hash\": \""));
  /* a name filter, sorting and reversing */
  CHECK(ctl_run(ctl, out, sizeof(out), "status", "External", "--port", port_arg,
                "--identity", keypath, NULL) == 0 &&
        strstr(out, "External") && !strstr(out, "Shared Instance"));
  CHECK(ctl_run(ctl, out, sizeof(out), "status", "no-such-interface", "--port", port_arg,
                "--identity", keypath, NULL) == 0 && !strstr(out, "Status"));
  CHECK(ctl_run(ctl, out, sizeof(out), "status", "-s", "traffic", "--port", port_arg,
                "--identity", keypath, NULL) == 0 && strstr(out, "Shared Instance"));
  CHECK(ctl_run(ctl, out, sizeof(out), "status", "-s", "rate", "-r", "--port", port_arg,
                "--identity", keypath, NULL) == 0 && strstr(out, "External"));
  {
    char first[8192];
    char *a, *b;
    CHECK(ctl_run(ctl, first, sizeof(first), "status", "-s", "rate", "--port", port_arg,
                  "--identity", keypath, NULL) == 0);
    CHECK(ctl_run(ctl, out, sizeof(out), "status", "-s", "rate", "-r", "--port", port_arg,
                  "--identity", keypath, NULL) == 0);
    /* the two interfaces have different rates, so -r puts them the other way round */
    a = strstr(first, "Shared Instance");
    b = strstr(first, "External");
    CHECK(a && b);
    CHECK((a < b) != (strstr(out, "Shared Instance") < strstr(out, "External")));
  }
  CHECK(ctl_run(ctl, out, sizeof(out), "status", "-s", "bogus", "--port", port_arg,
                "--identity", keypath, NULL) != 0);
  memset(zero_key, '0', 64);
  zero_key[64] = 0;
  CHECK(ctl_run(ctl, out, sizeof(out), "status", "--port", port_arg,
                "--rpc-key", (char *)zero_key, NULL) != 0);
  (void)control_arg;

  /* path: feed one announce through the shared instance */
  CHECK(ctl_run(ctl, out, sizeof(out), "path", "-t", "--port", port_arg,
                "--identity", keypath, NULL) == 0 &&
        !strstr(out, "hop"));
  local = tcp_connect(port);
  CHECK(rnc_identity_from_private(&id, private_key) == RNC_OK &&
        rnc_announce_create(&id, "reticulum_c.ctl.test", NULL, 0,
                            (uint64_t)time(NULL), rng, &random,
                            &packet) == RNC_OK);
  hex_of(packet.destination, 16, hash);
  CHECK(rnc_packet_encode(&packet, raw, sizeof(raw), &n) == RNC_OK &&
        rnc_host_frame_encode(RNC_HOST_HDLC, 0, raw, n, framed, sizeof(framed),
                              &m) == RNC_OK);
  CHECK(write(local, framed, m) == (ssize_t)m);
  wait_for(admin, "ROUTES", hash, 5, reply, sizeof(reply));
  CHECK(ctl_run(ctl, out, sizeof(out), "path", "-t", "--port", port_arg,
                "--identity", keypath, NULL) == 0 &&
        strstr(out, hash) && strstr(out, "hop"));
  CHECK(ctl_run(ctl, out, sizeof(out), "path", hash, "--port", port_arg,
                "--identity", keypath, NULL) == 0 &&
        strstr(out, hash) && strstr(out, "hop"));
  CHECK(ctl_run(ctl, out, sizeof(out), "path", "-j", "-t", "--port", port_arg,
                "--identity", keypath, NULL) == 0 &&
        out[0] == '[' && strstr(out, "\"hops\""));
  CHECK(ctl_run(ctl, out, sizeof(out), "path", "-t", "-m", "5", "--port",
                port_arg, "--identity", keypath, NULL) == 0);
  CHECK(ctl_run(ctl, out, sizeof(out), "path",
                "00000000000000000000000000000000", "-w", "1", "--port", port_arg, "--data-port", data_arg,
                "--identity", keypath, NULL) == 1 &&
        strstr(out, "requested") && strstr(out, "Path not found"));
  CHECK(ctl_run(ctl, out, sizeof(out), "path", "nothex", "--port", port_arg,
                "--identity", keypath, NULL) != 0);

  /* rate table, then drop a path, drop everything via a next hop, drop the announce queues */
  CHECK(ctl_run(ctl, out, sizeof(out), "path", "-r", "--port", port_arg,
                "--identity", keypath, NULL) == 0);
  CHECK(ctl_run(ctl, out, sizeof(out), "path", "-d", hash, "--port", port_arg,
                "--identity", keypath, NULL) == 0 && strstr(out, "Dropped path"));
  CHECK(ctl_run(ctl, out, sizeof(out), "path", hash, "-w", "1", "--port", port_arg, "--data-port", data_arg,
                "--identity", keypath, NULL) == 1 && strstr(out, "Path not found"));
  CHECK(ctl_run(ctl, out, sizeof(out), "path", "-d", hash, "--port", port_arg,
                "--identity", keypath, NULL) == 1 && strstr(out, "No path"));
  CHECK(rnc_announce_create(&id, "reticulum_c.ctl.test", NULL, 0,
                            (uint64_t)time(NULL) + 1, rng, &random,
                            &packet) == RNC_OK);
  CHECK(rnc_packet_encode(&packet, raw, sizeof(raw), &n) == RNC_OK &&
        rnc_host_frame_encode(RNC_HOST_HDLC, 0, raw, n, framed, sizeof(framed),
                              &m) == RNC_OK);
  CHECK(write(local, framed, m) == (ssize_t)m);
  wait_for(admin, "ROUTES", hash, 5, reply, sizeof(reply));
  CHECK(ctl_run(ctl, out, sizeof(out), "path", "-x", hash, "--port", port_arg,
                "--identity", keypath, NULL) == 0 && strstr(out, "Dropped 1 path"));
  CHECK(ctl_run(ctl, out, sizeof(out), "path", hash, "-w", "1", "--port", port_arg, "--data-port", data_arg,
                "--identity", keypath, NULL) == 1);
  CHECK(ctl_run(ctl, out, sizeof(out), "path", "-D", "--port", port_arg,
                "--identity", keypath, NULL) == 0 && strstr(out, "announce"));
  CHECK(ctl_run(ctl, out, sizeof(out), "path", "-d", "--port", port_arg,
                "--identity", keypath, NULL) != 0); /* -d needs a destination */

  /* a path request: ctl asks the instance as a local client would, the instance asks its other interfaces, and a
   * peer on one of them answers with the announce */
  {
    int world_fd = tcp_connect(admin_status(admin)), pipefd[2], status, got_request = 0, tries;
    uint8_t other_key[64] = {0}, req_raw[RNC_MAX_MTU], req_framed[RNC_HOST_FRAME_MAX], req_decoded[RNC_MAX_FRAME];
    unsigned other_random = 77;
    rnc_identity other;
    rnc_packet other_packet, request;
    rnc_host_framer framer = {0};
    char other_hash[33], text_out[4096];
    size_t used = 0, cnt, fm;
    pid_t tool;
    other_key[10] = 0x5a;
    other_key[40] = 0x5a;
    CHECK(rnc_identity_from_private(&other, other_key) == RNC_OK &&
          rnc_announce_create(&other, "reticulum_c.ctl.requested", NULL, 0, (uint64_t)time(NULL), rng, &other_random,
                              &other_packet) == RNC_OK);
    hex_of(other_packet.destination, 16, other_hash);
    CHECK(!pipe(pipefd));
    tool = fork();
    CHECK(tool >= 0);
    if (!tool) {
      close(pipefd[0]);
      CHECK(dup2(pipefd[1], STDOUT_FILENO) >= 0);
      close(pipefd[1]);
      execl(ctl, ctl, "path", other_hash, "-w", "8", "--port", port_arg, "--data-port", data_arg, "--identity", keypath,
            (char *)NULL);
      _exit(127);
    }
    close(pipefd[1]);
    for (tries = 0; tries < 80 && !got_request; ++tries) {
      struct pollfd pf = {world_fd, POLLIN, 0};
      CHECK(poll(&pf, 1, 100) >= 0);
      if (pf.revents & POLLIN) {
        ssize_t sz = read(world_fd, req_framed, sizeof(req_framed));
        size_t q;
        uint8_t command;
        CHECK(sz > 0);
        for (q = 0; q < (size_t)sz; ++q)
          if (rnc_host_frame_feed(&framer, RNC_HOST_HDLC, req_framed[q], &command, req_decoded, sizeof(req_decoded),
                                  &cnt) == RNC_OK &&
              rnc_packet_decode(req_decoded, cnt, &request) == RNC_OK && (request.flags & 3u) == RNC_DATA &&
              request.data_size >= 16 && !memcmp(request.data, other_packet.destination, 16))
            got_request = 1;
      }
    }
    CHECK(got_request); /* the instance passed the request on to its other interface */
    CHECK(rnc_packet_encode(&other_packet, req_raw, sizeof(req_raw), &cnt) == RNC_OK &&
          rnc_host_frame_encode(RNC_HOST_HDLC, 0, req_raw, cnt, req_framed, sizeof(req_framed), &fm) == RNC_OK);
    CHECK(write(world_fd, req_framed, fm) == (ssize_t)fm);
    for (;;) {
      ssize_t sz = read(pipefd[0], text_out + used, sizeof(text_out) - 1 - used);
      if (sz <= 0)
        break;
      used += (size_t)sz;
    }
    text_out[used] = 0;
    close(pipefd[0]);
    CHECK(waitpid(tool, &status, 0) == tool && WIFEXITED(status) && !WEXITSTATUS(status));
    CHECK(strstr(text_out, "requested") && strstr(text_out, "Path found, destination") && strstr(text_out, other_hash) &&
          strstr(text_out, "is 1 hop away via"));
    /* the instance counted the request it sent to the world interface */
    CHECK(ctl_run(ctl, out, sizeof(out), "status", "-j", "--port", port_arg, "--identity", keypath, NULL) == 0);
    {
      const char *at;
      int sent_requests = 0;
      for (at = out; (at = strstr(at, "\"ptxc\": ")); at += 8)
        if (at[8] >= '1' && at[8] <= '9')
          sent_requests = 1;
      CHECK(sent_requests);
    }
    close(world_fd);
  }

  /* every sort key of the reference is accepted, and the rates the daemon samples on its own are in the statistics */
  {
    static const char *keys[] = {"rate", "traffic", "rx", "tx", "rxs", "txs", "anns", "arx", "atx", "arxc", "atxc",
                                 "held", "prx", "ptx", "prxc", "ptxc", "pvs", "ivs", "flt", "gravity", "g",
                                 "txdrp", "txdrb", "txbuf", "ANNOUNCES"};
    size_t k;
    for (k = 0; k < sizeof(keys) / sizeof(*keys); ++k)
      CHECK(ctl_run(ctl, out, sizeof(out), "status", "-s", keys[k], "--port", port_arg, "--identity", keypath,
                    NULL) == 0 && strstr(out, "Shared Instance"));
    CHECK(ctl_run(ctl, out, sizeof(out), "status", "-j", "--port", port_arg, "--identity", keypath, NULL) == 0);
    CHECK(strstr(out, "\"incoming_pr_frequency\"") && strstr(out, "\"rxs\""));
    CHECK(ctl_run(ctl, out, sizeof(out), "status", "-s", "bogus", "--port", port_arg, "--identity", keypath, NULL) != 0);
  }

  /* rnid -a: the announce of an identity's destination goes out of the instance's other interfaces */
  {
    char idfile[300], dest_text[40], *at;
    int world_fd = tcp_connect(admin_status(admin)), seen = 0, tries;
    uint8_t raw_in[RNC_MAX_MTU * 2], decoded[RNC_MAX_FRAME];
    rnc_host_framer framer = {0};
    CHECK(snprintf(idfile, sizeof(idfile), "%s/announcer.id", dir) > 0);
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-g", idfile, NULL) == 0);
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-a", "example.rnid.test", "--data-port", data_arg, NULL) == 0);
    at = strstr(out, "Announcing example.rnid.test destination <");
    CHECK(at && sscanf(at, "Announcing example.rnid.test destination <%32[0-9a-f]>", dest_text) == 1);
    for (tries = 0; tries < 60 && !seen; ++tries) {
      struct pollfd pf = {world_fd, POLLIN, 0};
      CHECK(poll(&pf, 1, 100) >= 0);
      if (pf.revents & POLLIN) {
        ssize_t sz = read(world_fd, raw_in, sizeof(raw_in));
        size_t q, cnt;
        uint8_t command;
        CHECK(sz > 0);
        for (q = 0; q < (size_t)sz; ++q)
          if (rnc_host_frame_feed(&framer, RNC_HOST_HDLC, raw_in[q], &command, decoded, sizeof(decoded), &cnt) == RNC_OK) {
            rnc_packet got;
            rnc_announce verified;
            char got_hex[33];
            if (rnc_packet_decode(decoded, cnt, &got) == RNC_OK && (got.flags & 3u) == RNC_ANNOUNCE &&
                rnc_announce_verify(&got, &verified) == RNC_OK) {
              hex_of(got.destination, 16, got_hex);
              if (!strcmp(got_hex, dest_text))
                seen = 1;
            }
          }
      }
    }
    CHECK(seen);
    /* refusals: no dot in the aspects, no private key, no instance there */
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-a", "nodot", "--data-port", data_arg, NULL) == 9 &&
          strstr(out, "Invalid destination aspects"));
    CHECK(ctl_run(ctl, out, sizeof(out), "id", "-i", idfile, "-a", "example.x", "--data-port", "1", NULL) == 254 &&
          strstr(out, "An error ocurred while attempting to send the announce"));
    close(world_fd);
    CHECK(!unlink(idfile));
  }

  /* -l: the link table footer */
  CHECK(ctl_run(ctl, out, sizeof(out), "status", "-l", "--port", port_arg, "--identity", keypath, NULL) == 0 &&
        strstr(out, "in link table"));
  CHECK(ctl_run(ctl, out, sizeof(out), "status", "--port", port_arg, "--identity", keypath, NULL) == 0 &&
        !strstr(out, "in link table"));

  /* -m: monitor mode redraws until it is stopped */
  {
    int pipefd[2], status;
    pid_t tool;
    char text_out[16384];
    size_t used = 0, redraws = 0;
    const char *at;
    uint64_t end;
    CHECK(!pipe(pipefd));
    tool = fork();
    CHECK(tool >= 0);
    if (!tool) {
      close(pipefd[0]);
      CHECK(dup2(pipefd[1], STDOUT_FILENO) >= 0);
      close(pipefd[1]);
      execl(ctl, ctl, "status", "-m", "-I", "0.3", "--port", port_arg, "--identity", keypath, (char *)NULL);
      _exit(127);
    }
    close(pipefd[1]);
    end = now_ms() + 8000;
    while (now_ms() < end && redraws < 3) {
      struct pollfd pf = {pipefd[0], POLLIN, 0};
      CHECK(poll(&pf, 1, 200) >= 0);
      if (pf.revents & POLLIN) {
        ssize_t sz = read(pipefd[0], text_out + used, sizeof(text_out) - 1 - used);
        CHECK(sz > 0);
        used += (size_t)sz;
        text_out[used] = 0;
        redraws = 0;
        for (at = text_out; (at = strstr(at, "\033[H\033[J")); at += 6)
          ++redraws;
      }
    }
    CHECK(kill(tool, SIGTERM) == 0 && waitpid(tool, &status, 0) == tool);
    close(pipefd[0]);
    CHECK(redraws >= 3 && strstr(text_out, "Shared Instance"));
    CHECK(ctl_run(ctl, out, sizeof(out), "status", "-I", "0", "--port", port_arg, "--identity", keypath, NULL) != 0);
  }

  /* blackhole list/add/remove through the RPC */
  CHECK(ctl_run(ctl, out, sizeof(out), "path", "-b", "--port", port_arg,
                "--identity", keypath, NULL) == 0 &&
        !strstr(out, "22222222"));
  CHECK(ctl_run(ctl, out, sizeof(out), "path", "-B",
                "22222222222222222222222222222222", "--reason", "ctl test",
                "--port", port_arg, "--identity", keypath, NULL) == 0);
  admin_command(admin, "BLACKHOLES", reply, sizeof(reply));
  CHECK(strstr(reply, "22222222222222222222222222222222") &&
        strstr(reply, "reason=ctl test"));
  CHECK(ctl_run(ctl, out, sizeof(out), "path", "-b", "--port", port_arg,
                "--identity", keypath, NULL) == 0 &&
        strstr(out, "22222222222222222222222222222222") &&
        strstr(out, "ctl test"));
  CHECK(ctl_run(ctl, out, sizeof(out), "path", "-U",
                "22222222222222222222222222222222", "--port", port_arg,
                "--identity", keypath, NULL) == 0);
  admin_command(admin, "BLACKHOLES", reply, sizeof(reply));
  CHECK(!strncmp(reply, "EMPTY", 5));

  /* usage errors */
  CHECK(ctl_run(ctl, out, sizeof(out), NULL) != 0);
  CHECK(ctl_run(ctl, out, sizeof(out), "frobnicate", NULL) != 0);
  close(local);
  stop(process, fd);
  cli_tools_id(ctl, dir);
  rnc_identity_clear(&id);
  remove_tree(dir);
  puts("cli tool tests passed");
}

/* The identity commands interoperate with the reference rnid: same hashes,
 * our raw signature validates there, and encrypted files cross both ways. */
static void cli_id_reference(const char *ctl, const char *reference,
                             const char *python) {
  char dir[] = "/tmp/rnc-ctl-ref-XXXXXX", cfgdir[300], cfgfile[320], idfile[300],
       data[300], sig[320], enc[320], dec[320], out[8192], ours[8192], buf[256],
       hex[40];
  const char *text = "cross-implementation payload";
  rnc_identity id;
  uint8_t private_key[64];
  char *ref_args[16];
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfgdir, sizeof(cfgdir), "%s/cfg", dir) > 0 && !mkdir(cfgdir, 0700));
  CHECK(snprintf(cfgfile, sizeof(cfgfile), "%s/config", cfgdir) > 0);
  config_file(cfgfile, "[reticulum]\nenable_transport = No\nshare_instance = No\n"
                       "[interfaces]\n");
  CHECK(snprintf(idfile, sizeof(idfile), "%s/tool.id", dir) > 0);
  CHECK(snprintf(data, sizeof(data), "%s/payload", dir) > 0);
  CHECK(snprintf(sig, sizeof(sig), "%s.rsg", data) > 0);
  CHECK(snprintf(enc, sizeof(enc), "%s.rfe", data) > 0);
  CHECK(snprintf(dec, sizeof(dec), "%s/decrypted", dir) > 0);
  file_bytes(data, text, strlen(text));
  CHECK(ctl_run(ctl, ours, sizeof(ours), "id", "-g", idfile, NULL) == 0);
  CHECK(file_read(idfile, buf, sizeof(buf)) == 64);
  memcpy(private_key, buf, 64);
  CHECK(rnc_identity_from_private(&id, private_key) == RNC_OK);
  hex_of(id.hash, 16, hex);
  /* reference reads our identity file and agrees on the hash and aspect hash */
  ref_args[0] = "--config"; ref_args[1] = cfgdir; ref_args[2] = "-i";
  ref_args[3] = idfile; ref_args[4] = "-p"; ref_args[5] = "-H";
  ref_args[6] = "example.aspect"; ref_args[7] = NULL;
  reference_tool(python, reference, "RNS.Utilities.rnid", ref_args, out,
                 sizeof(out));
  CHECK(strstr(out, hex));
  CHECK(ctl_run(ctl, ours, sizeof(ours), "id", "-i", idfile, "-H",
                "example.aspect", NULL) == 0);
  {
    uint8_t name_hash[10], dest[16];
    char want[40];
    CHECK(rnc_destination_hash("example.aspect", &id, name_hash, dest) == RNC_OK);
    hex_of(dest, 16, want);
    CHECK(strstr(out, want) && strstr(ours, want));
  }
  /* reference validates our raw signature */
  CHECK(ctl_run(ctl, ours, sizeof(ours), "id", "-i", idfile, "-s", data, "--raw",
                NULL) == 0);
  ref_args[4] = "-V"; ref_args[5] = sig; ref_args[6] = "-r"; ref_args[7] = data;
  ref_args[8] = "--raw"; ref_args[9] = NULL;
  reference_tool(python, reference, "RNS.Utilities.rnid", ref_args, out,
                 sizeof(out));
  CHECK(strstr(out, "Signature is valid"));
  /* reference signs, ours validates */
  CHECK(!unlink(sig));
  ref_args[4] = "-s"; ref_args[5] = data; ref_args[6] = "--raw"; ref_args[7] = NULL;
  reference_tool(python, reference, "RNS.Utilities.rnid", ref_args, out,
                 sizeof(out));
  CHECK(ctl_run(ctl, ours, sizeof(ours), "id", "-i", idfile, "-V", sig, "-r",
                data, "--raw", NULL) == 0 &&
        strstr(ours, "is valid"));
  /* envelopes: the reference validates ours, and ours validates the reference's */
  CHECK(!unlink(sig));
  CHECK(ctl_run(ctl, ours, sizeof(ours), "id", "-i", idfile, "-s", data, NULL) == 0);
  ref_args[4] = "-V"; ref_args[5] = sig; ref_args[6] = NULL;
  reference_tool(python, reference, "RNS.Utilities.rnid", ref_args, out, sizeof(out));
  CHECK(strstr(out, "Signature is valid") && strstr(out, hex));
  CHECK(!unlink(sig));
  ref_args[4] = "-i"; ref_args[5] = idfile; ref_args[6] = "-s"; ref_args[7] = data; ref_args[8] = NULL;
  reference_tool(python, reference, "RNS.Utilities.rnid", ref_args, out, sizeof(out));
  CHECK(ctl_run(ctl, ours, sizeof(ours), "id", "-V", sig, NULL) == 0 && strstr(ours, "Signature is valid") && strstr(ours, hex));
  CHECK(ctl_run(ctl, ours, sizeof(ours), "id", "-i", idfile, "-V", sig, NULL) == 0);
  CHECK(!unlink(sig));
  ref_args[4] = "-p"; ref_args[5] = "-H"; ref_args[6] = "example.aspect"; ref_args[7] = NULL;
  ref_args[2] = "-i"; ref_args[3] = idfile;
  /* metadata: the same file (with and without its spec) signed by ours and by the reference gives the same
   * bytes, signature included, and --meta prints the same text */
  {
    char meta[320], spec[330], ours_rsm[340], ref_rsm[340], ours_base[330], ref_base[330], a[4096], b[4096];
    size_t pass;
    CHECK(snprintf(meta, sizeof(meta), "%s/diff.meta", dir) > 0 && snprintf(spec, sizeof(spec), "%s.spec", meta) > 0);
    CHECK(snprintf(ours_base, sizeof(ours_base), "%s/diff_ours", dir) > 0 &&
          snprintf(ref_base, sizeof(ref_base), "%s/diff_ref", dir) > 0);
    CHECK(snprintf(ours_rsm, sizeof(ours_rsm), "%s.rsm", ours_base) > 0 && snprintf(ref_rsm, sizeof(ref_rsm), "%s.rsm", ref_base) > 0);
    /* passes: the first fixture without and with its spec, then the awkward one without and with its spec */
    for (pass = 0; pass < 4; ++pass) {
      char ours_bytes[4096], ref_bytes[4096];
      size_t n_ours, n_ref;
      const char *from_ours, *from_ref;
      if (pass == 0 || pass == 2) {
        const char *text = pass == 0 ? meta_fixture : meta_edge_fixture;
        file_bytes(meta, text, strlen(text));
        (void)unlink(spec);
      } else {
        const char *text = pass == 1 ? meta_spec_fixture : meta_edge_spec_fixture;
        file_bytes(spec, text, strlen(text));
      }
      (void)unlink(ours_rsm);
      (void)unlink(ref_rsm);
      CHECK(ctl_run(ctl, ours, sizeof(ours), "id", "-i", idfile, "-S", "hello", "-E", meta, "-w", ours_base, NULL) == 0);
      ref_args[4] = "-S"; ref_args[5] = "hello"; ref_args[6] = "-E"; ref_args[7] = meta;
      ref_args[8] = "-w"; ref_args[9] = ref_base; ref_args[10] = NULL;
      reference_tool(python, reference, "RNS.Utilities.rnid", ref_args, out, sizeof(out));
      n_ours = file_read(ours_rsm, ours_bytes, sizeof(ours_bytes));
      n_ref = file_read(ref_rsm, ref_bytes, sizeof(ref_bytes));
      if (n_ours != n_ref || memcmp(ours_bytes, ref_bytes, n_ours))
        fprintf(stderr, "metadata pass %zu: ours %zu bytes, reference %zu bytes, differ\n", pass, n_ours, n_ref);
      CHECK(n_ours > 100 && n_ours == n_ref && !memcmp(ours_bytes, ref_bytes, n_ours));
      /* the display: ours reads the reference's file and the reference reads ours; same text from "RSM Metadata" */
      CHECK(ctl_run(ctl, ours, sizeof(ours), "id", "-V", ref_rsm, "--meta", NULL) == 0);
      ref_args[4] = "-V"; ref_args[5] = ours_rsm; ref_args[6] = "--meta"; ref_args[7] = NULL;
      reference_tool(python, reference, "RNS.Utilities.rnid", ref_args, out, sizeof(out));
      from_ours = strstr(ours, "RSM Metadata");
      from_ref = strstr(out, "RSM Metadata");
      CHECK(from_ours && from_ref);
      snprintf(a, sizeof(a), "%s", from_ours);
      snprintf(b, sizeof(b), "%s", from_ref);
      if (strcmp(a, b))
        fprintf(stderr, "--meta text differs (pass %zu):\n--- ours\n%s--- reference\n%s\n", pass, a, b);
      CHECK(!strcmp(a, b));
    }
    CHECK(!unlink(meta) && !unlink(spec) && !unlink(ours_rsm) && !unlink(ref_rsm));
  }
  /* the text form of a signature, for each encoding, for a file and for a message: the same bytes as the reference's */
  {
    static const char *const flags[] = {"-F", "-B", "-b", "-U"};
    size_t f;
    char a[8192], b[8192];
    for (f = 0; f < sizeof(flags) / sizeof(*flags); ++f) {
      ref_args[4] = "-s"; ref_args[5] = data; ref_args[6] = (char *)flags[f]; ref_args[7] = NULL;
      CHECK(ctl_run(ctl, ours, sizeof(ours), "id", "-i", idfile, "-s", data, flags[f], NULL) == 0);
      reference_tool(python, reference, "RNS.Utilities.rnid", ref_args, out, sizeof(out));
      snprintf(a, sizeof(a), "%s", ours);
      snprintf(b, sizeof(b), "%s", out);
      if (strcmp(a, b))
        fprintf(stderr, "signature text %s differs\n--- ours\n%s--- reference\n%s\n", flags[f], a, b);
      CHECK(!strcmp(a, b) && strstr(a, "#### Start of rsg data ") && strstr(a, " End of rsg data ####"));
      CHECK(access(sig, F_OK) != 0); /* nothing was written */
      ref_args[4] = "-S"; ref_args[5] = "a message to sign, long enough to need more than one row of text output";
      ref_args[6] = (char *)flags[f]; ref_args[7] = NULL;
      CHECK(ctl_run(ctl, ours, sizeof(ours), "id", "-i", idfile, "-S",
                    "a message to sign, long enough to need more than one row of text output", flags[f], NULL) == 0);
      reference_tool(python, reference, "RNS.Utilities.rnid", ref_args, out, sizeof(out));
      snprintf(a, sizeof(a), "%s", ours);
      snprintf(b, sizeof(b), "%s", out);
      if (strcmp(a, b))
        fprintf(stderr, "message text %s differs\n--- ours\n%s--- reference\n%s\n", flags[f], a, b);
      CHECK(!strcmp(a, b));
    }
    ref_args[4] = "-p"; ref_args[5] = "-H"; ref_args[6] = "example.aspect"; ref_args[7] = NULL;
  }
  /* signed messages: the reference validates ours, and ours validates the reference's */
  {
    char base[320], rsm[340];
    CHECK(snprintf(base, sizeof(base), "%s/refnote", dir) > 0 && snprintf(rsm, sizeof(rsm), "%s.rsm", base) > 0);
    CHECK(ctl_run(ctl, ours, sizeof(ours), "id", "-i", idfile, "-S", "hello from ours", "-w", base, NULL) == 0);
    ref_args[4] = "-V"; ref_args[5] = rsm; ref_args[6] = NULL;
    reference_tool(python, reference, "RNS.Utilities.rnid", ref_args, out, sizeof(out));
    CHECK(strstr(out, "Signature is valid") && strstr(out, hex) && strstr(out, "hello from ours"));
    CHECK(!unlink(rsm));
    ref_args[4] = "-S"; ref_args[5] = "hello from the reference"; ref_args[6] = "-w"; ref_args[7] = base;
    ref_args[8] = NULL;
    reference_tool(python, reference, "RNS.Utilities.rnid", ref_args, out, sizeof(out));
    CHECK(ctl_run(ctl, ours, sizeof(ours), "id", "-V", rsm, NULL) == 0 && strstr(ours, "hello from the reference") &&
          strstr(ours, hex));
    CHECK(!unlink(rsm));
  }
  /* ours encrypts, reference decrypts */
  CHECK(ctl_run(ctl, ours, sizeof(ours), "id", "-i", idfile, "-e", data, NULL) == 0);
  ref_args[4] = "-d"; ref_args[5] = enc; ref_args[6] = "-w"; ref_args[7] = dec;
  ref_args[8] = NULL;
  reference_tool(python, reference, "RNS.Utilities.rnid", ref_args, out,
                 sizeof(out));
  CHECK(file_read(dec, buf, sizeof(buf)) == strlen(text) &&
        !memcmp(buf, text, strlen(text)));
  /* reference encrypts, ours decrypts */
  CHECK(!unlink(enc) && !unlink(dec));
  ref_args[4] = "-e"; ref_args[5] = data; ref_args[6] = NULL;
  reference_tool(python, reference, "RNS.Utilities.rnid", ref_args, out,
                 sizeof(out));
  CHECK(ctl_run(ctl, ours, sizeof(ours), "id", "-i", idfile, "-d", enc, "-w",
                dec, NULL) == 0);
  CHECK(file_read(dec, buf, sizeof(buf)) == strlen(text) &&
        !memcmp(buf, text, strlen(text)));
  rnc_identity_clear(&id);
  remove_tree(dir);
  puts("cli id reference tests passed");
}

/* The reference's TCP client names a tunnel when it connects. After it leaves
 * and comes back (same identity, same interface) this daemon restores the path
 * it had learned, without a new announce. */
static int path_within(const char *admin, const char *hash, unsigned seconds) {
  unsigned w;
  for (w = 0; w < seconds * 10; ++w) {
    struct timespec t = {0, 100000000};
    if (admin_has_path(admin, hash))
      return 1;
    nanosleep(&t, NULL);
  }
  return 0;
}
static const char *reference_tunnel_peer =
    "import RNS, sys, time\n"
    "r = RNS.Reticulum(configdir=sys.argv[1], loglevel=1)\n"
    "if sys.argv[2] == 'announce':\n"
    "    i = RNS.Identity()\n"
    "    d = RNS.Destination(i, RNS.Destination.IN, RNS.Destination.SINGLE,\n"
    "                        'reticulum_c', 'tunnel')\n"
    "    print(d.hexhash, flush=True)\n"
    "    end = time.time() + float(sys.argv[3])\n"
    "    while time.time() < end:\n"
    "        d.announce()\n"
    "        time.sleep(1)\n"
    "else:\n"
    "    print('idle', flush=True)\n"
    "    time.sleep(float(sys.argv[3]))\n";
static void tunnel_reference(const char *exe, const char *reference,
                             const char *python) {
  char dir[] = "/tmp/rnc-tunnel-ref-XXXXXX", rdir[256], rcfg[256], cfg[256],
       key[256], admin[256], text[1024], id[33], hash[33], reply[4096];
  unsigned port = unused_port(), waited;
  int fd, pfd;
  pid_t daemon, peer;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(rdir, sizeof(rdir), "%s/ref", dir) > 0);
  CHECK(!mkdir(rdir, 0700));
  CHECK(snprintf(rcfg, sizeof(rcfg), "%s/config", rdir) > 0);
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  /* a stable transport identity is what makes the tunnel the same one again;
   * the reference only keeps it across runs when transport is enabled */
  write_config(rcfg,
               "[reticulum]\nenable_transport = True\nshare_instance = No\n"
               "[interfaces]\n[[Daemon]]\ntype = TCPClientInterface\n"
               "enabled = yes\ntarget_host = 127.0.0.1\ntarget_port = %u\n",
               port);
  write_config(cfg,
               "[reticulum]\nenable_transport = Yes\nshare_instance = No\n"
               "[interfaces]\n[[TCP]]\ntype = TCPServerInterface\nlisten_ip = "
               "127.0.0.1\nlisten_port = %u\n",
               port);
  daemon = start(exe, cfg, key, admin, &fd);
  ready_line(fd, id);
  /* first visit: announce a destination */
  {
    int fds[2];
    size_t n = 0;
    char out[2048];
    CHECK(!pipe(fds));
    peer = fork();
    CHECK(peer >= 0);
    if (!peer) {
      close(fds[0]);
      CHECK(dup2(fds[1], STDOUT_FILENO) >= 0 && dup2(fds[1], STDERR_FILENO) >= 0);
      close(fds[1]);
      CHECK(!setenv("PYTHONPATH", reference, 1));
      execl(python, python, "-c", reference_tunnel_peer, rdir, "announce", "40",
            (char *)NULL);
      _exit(127);
    }
    close(fds[1]);
    pfd = fds[0];
    out[0] = 0;
    hash[0] = 0;
    for (waited = 0; waited < 300 && !hash[0]; ++waited) {
      struct pollfd pf = {pfd, POLLIN, 0};
      size_t at;
      CHECK(poll(&pf, 1, 100) >= 0);
      if (pf.revents & POLLIN) {
        ssize_t got = read(pfd, out + n, sizeof(out) - 1 - n);
        CHECK(got >= 0);
        n += (size_t)got;
        out[n] = 0;
      }
      /* a line made of exactly 32 hex digits is the destination hash */
      for (at = 0; at + 32 <= n && !hash[0]; ++at) {
        size_t k;
        if (at && out[at - 1] != '\n')
          continue;
        for (k = 0; k < 32 && strchr("0123456789abcdef", out[at + k]); ++k) {
        }
        if (k == 32 && (at + 32 == n || out[at + 32] == '\n')) {
          memcpy(hash, out + at, 32);
          hash[32] = 0;
        }
      }
    }
    CHECK(hash[0]);
  }
  CHECK(path_within(admin, hash, 20));
  admin_command(admin, "TUNNELS", reply, sizeof(reply));
  CHECK(strstr(reply, "tunnel id=") && strstr(reply, "paths=1"));
  /* the peer leaves: the path through its connection goes, the tunnel keeps it */
  (void)kill(peer, SIGKILL);
  CHECK(waitpid(peer, NULL, 0) == peer);
  close(pfd);
  for (waited = 0; waited < 200 && admin_has_path(admin, hash); ++waited) {
    struct timespec t = {0, 100000000};
    nanosleep(&t, NULL);
  }
  CHECK(!admin_has_path(admin, hash));
  admin_command(admin, "TUNNELS", reply, sizeof(reply));
  CHECK(strstr(reply, "interface=0 paths=1"));
  /* second visit, same identity and interface, no announce this time */
  {
    int devnull;
    peer = fork();
    CHECK(peer >= 0);
    if (!peer) {
      devnull = open("/dev/null", O_WRONLY);
      if (devnull >= 0) {
        (void)dup2(devnull, STDOUT_FILENO);
        (void)dup2(devnull, STDERR_FILENO);
      }
      CHECK(!setenv("PYTHONPATH", reference, 1));
      execl(python, python, "-c", reference_tunnel_peer, rdir, "idle", "40",
            (char *)NULL);
      _exit(127);
    }
  }
  for (waited = 0; waited < 300 && !admin_has_path(admin, hash); ++waited) {
    struct timespec t = {0, 100000000};
    nanosleep(&t, NULL);
  }
  CHECK(admin_has_path(admin, hash));
  admin_command(admin, "TUNNELS", reply, sizeof(reply));
  CHECK(!strstr(reply, "interface=0 "));
  (void)kill(peer, SIGKILL);
  CHECK(waitpid(peer, NULL, 0) == peer);
  stop(daemon, fd);
  remove_tree(dir);
  puts("unmodified RNS tunnel restored its path in this daemon");
}
/* The tunnel table is saved with the state and brings a returning peer's path
 * back after a restart of the receiving daemon. */
static void tunnel_persistence(const char *exe) {
  char dir[] = "/tmp/rnc-node-tun-XXXXXX", acfg[256], akey[256], aadmin[256],
       bcfg[256], bkey[256], badmin[256], bstate[256], aid[33], bid[33],
       dest_hex[33], reply[2048], tunnels_file[300];
  unsigned port = unused_port(), k;
  int afd, bfd, keyfd;
  pid_t a, b;
  uint8_t private_key[64], name_hash[10], destination[16];
  rnc_identity a_identity = {0};
  struct stat st;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(acfg, sizeof(acfg), "%s/a.config", dir) > 0);
  CHECK(snprintf(akey, sizeof(akey), "%s/a.identity", dir) > 0);
  CHECK(snprintf(aadmin, sizeof(aadmin), "%s/a.admin", dir) > 0);
  CHECK(snprintf(bcfg, sizeof(bcfg), "%s/b.config", dir) > 0);
  CHECK(snprintf(bkey, sizeof(bkey), "%s/b.identity", dir) > 0);
  CHECK(snprintf(badmin, sizeof(badmin), "%s/b.admin", dir) > 0);
  CHECK(snprintf(bstate, sizeof(bstate), "%s/b.state", dir) > 0);
  CHECK(snprintf(tunnels_file, sizeof(tunnels_file), "%s.tunnels", bstate) > 0);
  write_config(bcfg,
               "[reticulum]\nenable_transport = Yes\nshare_instance = No\n"
               "[interfaces]\n[[TCP]]\ntype = TCPServerInterface\nlisten_ip = "
               "127.0.0.1\nlisten_port = %u\n",
               port);
  /* A connects as a client (so it names a tunnel) and announces on a
   * discoverable interface; its discovery destination is the path we follow */
  write_config(acfg,
               "[reticulum]\nenable_transport = Yes\nshare_instance = No\n"
               "discovery_job_interval = 1\n[interfaces]\n[[Up]]\ntype = "
               "TCPClientInterface\ntarget_host = 127.0.0.1\ntarget_port = %u\n"
               "reconnect_wait = 1\n[[Public]]\ntype = BackboneInterface\n"
               "listen_ip = 127.0.0.1\nport = 0\ndiscoverable = yes\n"
               "discovery_name = Tunnel Source\ndiscovery_stamp_value = 8\n"
               "reachable_on = 127.0.0.1\nannounce_interval_seconds = 2\n",
               port);
  b = start_with_state(exe, bcfg, bkey, badmin, bstate, &bfd);
  ready_line(bfd, bid);
  a = start(exe, acfg, akey, aadmin, &afd);
  ready_line(afd, aid);
  keyfd = open(akey, O_RDONLY);
  CHECK(keyfd >= 0 && read(keyfd, private_key, 64) == 64);
  close(keyfd);
  CHECK(rnc_identity_from_private(&a_identity, private_key) == RNC_OK);
  CHECK(rnc_destination_hash("rnstransport.discovery.interface", &a_identity,
                             name_hash, destination) == RNC_OK);
  for (k = 0; k < 16; ++k)
    CHECK(snprintf(dest_hex + 2 * k, 3, "%02x", destination[k]) == 2);
  CHECK(path_within(badmin, dest_hex, 30));
  admin_command(badmin, "TUNNELS", reply, sizeof(reply));
  CHECK(strstr(reply, "tunnel id=") && strstr(reply, "paths=1"));
  admin_command(badmin, "SAVE", reply, sizeof(reply));
  CHECK(!strncmp(reply, "OK", 2));
  CHECK(!stat(tunnels_file, &st) && (st.st_mode & 0777) == 0600);
  /* B restarts while A is away: the table is back, with no interface */
  stop(a, afd);
  stop(b, bfd);
  b = start_with_state(exe, bcfg, bkey, badmin, bstate, &bfd);
  ready_line(bfd, bid);
  admin_command(badmin, "TUNNELS", reply, sizeof(reply));
  CHECK(strstr(reply, "interface=0 paths=1"));
  CHECK(!admin_has_path(badmin, dest_hex));
  /* A returns (same identity and interface): its path is back before its next
   * announce could have arrived */
  a = start(exe, acfg, akey, aadmin, &afd);
  ready_line(afd, aid);
  CHECK(path_within(badmin, dest_hex, 30));
  stop(a, afd);
  stop(b, bfd);
  remove_tree(dir);
  puts("node tunnel persistence tests passed");
}

/* ---- reticulum-c-cp (rncp compatible file transfer) --------------------- */
static pid_t spawn_cp(const char *cp, int *out, char *const *args) {
  int fds[2];
  pid_t p;
  CHECK(!pipe(fds));
  p = fork();
  CHECK(p >= 0);
  if (!p) {
    close(fds[0]);
    CHECK(dup2(fds[1], STDOUT_FILENO) >= 0 && dup2(fds[1], STDERR_FILENO) >= 0);
    close(fds[1]);
    execv(cp, args);
    _exit(127);
  }
  close(fds[1]);
  *out = fds[0];
  return p;
}
/* Reads from fd until needle shows up in what has accumulated. */
static void read_until(int fd, const char *needle, char *buf, size_t size,
                       unsigned seconds) {
  size_t n = strlen(buf);
  unsigned tries;
  for (tries = 0; tries < seconds * 10; ++tries) {
    struct pollfd p = {fd, POLLIN, 0};
    if (strstr(buf, needle))
      return;
    CHECK(poll(&p, 1, 100) >= 0);
    if (p.revents & POLLIN) {
      ssize_t got = read(fd, buf + n, size - 1 - n);
      CHECK(got > 0);
      n += (size_t)got;
      buf[n] = 0;
    }
  }
  fprintf(stderr, "never saw \"%s\"; output:\n%s\n", needle, buf);
  CHECK(0);
}
/* Runs a short-lived cp command to completion; returns its exit status. */
static int run_cp(const char *cp, char *out, size_t size, char *const *args) {
  int fd, status;
  size_t n = 0;
  pid_t p = spawn_cp(cp, &fd, args);
  unsigned tries;
  for (tries = 0; tries < 900; ++tries) {
    struct pollfd pf = {fd, POLLIN, 0};
    int r = poll(&pf, 1, 100);
    CHECK(r >= 0);
    if (r > 0) {
      ssize_t got = read(fd, out + n, size - 1 - n);
      if (got <= 0)
        break;
      n += (size_t)got;
    }
  }
  CHECK(tries < 900);
  out[n] = 0;
  close(fd);
  CHECK(waitpid(p, &status, 0) == p && WIFEXITED(status));
  return WEXITSTATUS(status);
}
static void stop_cp(pid_t pid, int fd) {
  int status;
  CHECK(!kill(pid, SIGTERM));
  CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status));
  close(fd);
}
static void parse_listening(const char *text, char hash[33]) {
  const char *at = strstr(text, "rncp listening on <");
  CHECK(at);
  memcpy(hash, at + 19, 32);
  hash[32] = 0;
}
static void write_identity(const char *path, uint8_t fill, char hash[33]) {
  uint8_t key[64];
  rnc_identity id;
  size_t i;
  for (i = 0; i < 64; ++i)
    key[i] = (uint8_t)(fill + i * 3u);
  file_bytes(path, (const char *)key, 64);
  CHECK(rnc_identity_from_private(&id, key) == RNC_OK);
  hex_of(id.hash, 16, hash);
  rnc_identity_clear(&id);
}
/* ---- rncp with files far larger than the old 16 MiB memory limit, and a check that they are not held in memory ---- */
static uint8_t big_byte(uint64_t at) {
  uint64_t x = (at + 7) * 0x9e3779b97f4a7c15ull;
  x ^= x >> 29;
  return (uint8_t)(x * 0xbf58476d1ce4e5b9ull >> 56);
}
static void big_file_write(const char *path, uint64_t size) {
  uint8_t chunk[65536];
  uint64_t at = 0;
  FILE *f = fopen(path, "wb");
  CHECK(f);
  while (at < size) {
    size_t n = size - at < sizeof(chunk) ? (size_t)(size - at) : sizeof(chunk), i;
    for (i = 0; i < n; ++i)
      chunk[i] = big_byte(at + i);
    CHECK(fwrite(chunk, 1, n, f) == n);
    at += n;
  }
  CHECK(!fclose(f));
}
/* the file holds the pattern, byte for byte, and is exactly `size` long */
static void big_file_check(const char *path, uint64_t size) {
  uint8_t chunk[65536];
  uint64_t at = 0;
  FILE *f = fopen(path, "rb");
  CHECK(f);
  for (;;) {
    size_t n = fread(chunk, 1, sizeof(chunk), f), i;
    if (!n)
      break;
    for (i = 0; i < n; ++i)
      if (chunk[i] != big_byte(at + i)) {
        fprintf(stderr, "%s differs at byte %llu\n", path, (unsigned long long)(at + i));
        CHECK(0);
      }
    at += n;
  }
  CHECK(!fclose(f) && at == size);
}
/* runs a cp command to completion within `seconds`; returns its exit status, with its peak memory in KiB */
static int run_cp_measured(const char *cp, char *out, size_t size, char *const *args, unsigned seconds, long *maxrss) {
  int fd, status;
  size_t n = 0;
  struct rusage usage;
  pid_t p = spawn_cp(cp, &fd, args);
  uint64_t end = now_ms() + (uint64_t)seconds * 1000u;
  out[0] = 0;
  while (now_ms() < end) {
    struct pollfd pf = {fd, POLLIN, 0};
    int r = poll(&pf, 1, 200);
    CHECK(r >= 0);
    if (r > 0) {
      ssize_t got = read(fd, out + n, size - 1 - n);
      if (got <= 0)
        break;
      n += (size_t)got;
      out[n] = 0;
    }
  }
  CHECK(now_ms() < end); /* finished in time */
  close(fd);
  CHECK(wait4(p, &status, 0, &usage) == p && WIFEXITED(status));
  *maxrss = usage.ru_maxrss;
#ifdef __APPLE__
  *maxrss /= 1024; /* macOS counts bytes, Linux KiB */
#endif
  return WEXITSTATUS(status);
}
static void cp_big(const char *exe, const char *cp) {
  char dir[] = "/tmp/rnc-node-cpbig-XXXXXX", cfg[256], key[256], admin[256], recv[300], fetched[300], idb[300],
       listener_id[300], connect[64], hash_b[33], dest[33], out[8192], listen_out[8192], big[300], path[400], text[1024],
       identity[33];
  const uint64_t size = (uint64_t)20 * 1024 * 1024 + 12345; /* over the old 16 MiB limit */
  long baseline_client = 0, baseline_listener = 0;
  unsigned port = unused_port();
  int dfd, lfd, status;
  pid_t daemon, listener;
  long client_rss, listener_rss;
  struct rusage usage;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/daemon_id", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(recv, sizeof(recv), "%s/recv", dir) > 0 && !mkdir(recv, 0700));
  CHECK(snprintf(fetched, sizeof(fetched), "%s/fetched", dir) > 0 && !mkdir(fetched, 0700));
  CHECK(snprintf(idb, sizeof(idb), "%s/id_b", dir) > 0);
  CHECK(snprintf(listener_id, sizeof(listener_id), "%s/id_l", dir) > 0);
  CHECK(snprintf(connect, sizeof(connect), "127.0.0.1:%u", port) > 0);
  CHECK(snprintf(big, sizeof(big), "%s/big.bin", dir) > 0);
  write_identity(idb, 11, hash_b);
  big_file_write(big, size);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = Yes\nshare_instance = No\n[interfaces]\n[[TCP]]\n"
                 "type = TCPServerInterface\nlisten_ip = 127.0.0.1\nlisten_port = %u\n", port) > 0);
  config_file(cfg, text);
  daemon = start(exe, cfg, key, admin, &dfd);
  ready_line(dfd, identity);
  /* push: 40 MiB to a listener, and the listener's file is byte for byte the original */
  {
    char *listen_args[] = {(char *)cp, "--connect", connect, "--identity", listener_id, "-l", "-n", "-F", "-s", recv,
                           "-b", "0", NULL};
    char *send_args[] = {(char *)cp, "--connect", connect, "--identity", idb, "-S", big, dest, NULL};
    listener = spawn_cp(cp, &lfd, listen_args);
    memset(listen_out, 0, sizeof(listen_out));
    read_until(lfd, "rncp listening on <", listen_out, sizeof(listen_out), 10);
    read_until(lfd, ">\n", listen_out, sizeof(listen_out), 10);
    parse_listening(listen_out, dest);
    /* what these programs need for a small file, to compare the big one with */
    {
      char small[300];
      char *small_args[] = {(char *)cp, "--connect", connect, "--identity", idb, "-S", small, dest, NULL};
      CHECK(snprintf(small, sizeof(small), "%s/small.bin", dir) > 0);
      big_file_write(small, 65536);
      CHECK(run_cp_measured(cp, out, sizeof(out), small_args, 60, &baseline_client) == 0);
      read_until(lfd, "Saved received file to", listen_out, sizeof(listen_out), 20);
      CHECK(!unlink(small));
    }
    CHECK(run_cp_measured(cp, out, sizeof(out), send_args, 240, &client_rss) == 0);
    CHECK(strstr(out, "Transfer complete"));
    read_until(lfd, "Saved received file to", listen_out, sizeof(listen_out), 20);
    CHECK(snprintf(path, sizeof(path), "%s/big.bin", recv) > 0);
    big_file_check(path, size);
    fprintf(stderr, "push of %llu bytes: sender peak %ld KiB\n", (unsigned long long)size, client_rss);
    /* no temporary file is left behind */
    {
      DIR *d = opendir(recv);
      struct dirent *entry;
      unsigned leftovers = 0, files = 0;
      CHECK(d);
      while ((entry = readdir(d))) {
        if (!strncmp(entry->d_name, ".rncp-", 6))
          ++leftovers;
        else if (entry->d_name[0] != '.')
          ++files;
      }
      closedir(d);
      CHECK(!leftovers && files == 2); /* the small file and the big one */
    }
    /* fetch: the same listener serves the file from disk */
    {
      char *fetch_args[] = {(char *)cp, "--connect", connect, "--identity", idb, "-S", "-f", big, "-s", fetched, dest, NULL};
      CHECK(run_cp_measured(cp, out, sizeof(out), fetch_args, 240, &client_rss) == 0);
      CHECK(strstr(out, "Saved fetched file to"));
      CHECK(snprintf(path, sizeof(path), "%s/big.bin", fetched) > 0);
      big_file_check(path, size);
      fprintf(stderr, "fetch of %llu bytes: fetcher peak %ld KiB\n", (unsigned long long)size, client_rss);
    }
    CHECK(!kill(listener, SIGTERM));
    CHECK(wait4(listener, &status, 0, &usage) == listener && WIFEXITED(status));
    listener_rss = usage.ru_maxrss;
#ifdef __APPLE__
    listener_rss /= 1024;
#endif
    close(lfd);
    fprintf(stderr, "listener peak %ld KiB, a small file needs %ld KiB\n", listener_rss, baseline_client);
    /* neither side held the file: against a 64 KiB file the peak grows by a few segments, not by the 20 MiB.
     * (The listener's baseline is taken as the sender's, the programs being alike.) */
    baseline_listener = baseline_client;
    CHECK(listener_rss < baseline_listener + (long)(size / 1024 / 2));
    CHECK(client_rss < baseline_client + (long)(size / 1024 / 2));
  }
  stop(daemon, dfd);
  remove_tree(dir);
  puts("rncp big file tests passed");
}
static void cp_tools(const char *exe, const char *cp) {
  char dir[] = "/tmp/rnc-node-cp-XXXXXX", cfg[256], key[256], admin[256],
       recv[300], jail[300], fetched[300], idb[300], idc[300], listener_id[300],
       connect[64], hash_b[33], hash_c[33], dest[33], out[4096], listen_out[4096],
       payload[300], path[400], jailed[400], outside[300], text[2048],
       identity[33];
  unsigned port = unused_port();
  int dfd, lfd;
  pid_t daemon, listener;
  uint8_t bytes[3000];
  char buf[3000];
  size_t i;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/daemon_id", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(recv, sizeof(recv), "%s/recv", dir) > 0 && !mkdir(recv, 0700));
  CHECK(snprintf(jail, sizeof(jail), "%s/jail", dir) > 0 && !mkdir(jail, 0700));
  CHECK(snprintf(fetched, sizeof(fetched), "%s/fetched", dir) > 0 &&
        !mkdir(fetched, 0700));
  CHECK(snprintf(idb, sizeof(idb), "%s/id_b", dir) > 0);
  CHECK(snprintf(idc, sizeof(idc), "%s/id_c", dir) > 0);
  CHECK(snprintf(listener_id, sizeof(listener_id), "%s/id_l", dir) > 0);
  CHECK(snprintf(connect, sizeof(connect), "127.0.0.1:%u", port) > 0);
  CHECK(snprintf(payload, sizeof(payload), "%s/payload.bin", dir) > 0);
  CHECK(snprintf(jailed, sizeof(jailed), "%s/hello.txt", jail) > 0);
  CHECK(snprintf(outside, sizeof(outside), "%s/outside.txt", dir) > 0);
  write_identity(idb, 11, hash_b);
  write_identity(idc, 99, hash_c);
  for (i = 0; i < sizeof(bytes); ++i)
    bytes[i] = (uint8_t)(i * 13u + 5u);
  file_bytes(payload, (const char *)bytes, sizeof(bytes));
  file_bytes(jailed, "inside the jail", 15);
  file_bytes(outside, "secret", 6);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = Yes\nshare_instance = No\n"
                 "[interfaces]\n[[TCP]]\ntype = TCPServerInterface\n"
                 "listen_ip = 127.0.0.1\nlisten_port = %u\n",
                 port) > 0);
  config_file(cfg, text);
  daemon = start(exe, cfg, key, admin, &dfd);
  ready_line(dfd, identity);

  /* anyone may push: a file arrives, a second copy gets a numeric suffix */
  {
    char *listen_args[] = {(char *)cp, "--connect", connect, "--identity",
                           listener_id, "-l", "-n", "-s", recv, "-b", "0", NULL};
    char *send_args[] = {(char *)cp, "--connect", connect, "--identity", idb,
                         payload, dest, NULL};
    listener = spawn_cp(cp, &lfd, listen_args);
    memset(listen_out, 0, sizeof(listen_out));
    read_until(lfd, "rncp listening on <", listen_out, sizeof(listen_out), 10);
    read_until(lfd, ">\n", listen_out, sizeof(listen_out), 10);
    parse_listening(listen_out, dest);
    CHECK(run_cp(cp, out, sizeof(out), send_args) == 0);
    CHECK(strstr(out, "Transfer complete") && !strstr(out, "physical layer"));
    {
      /* -P adds the rate the interface carried bytes at, next to the data rate */
      char *send_p[] = {(char *)cp, "--connect", connect, "--identity", idb, "-P", payload, dest, NULL};
      CHECK(run_cp(cp, out, sizeof(out), send_p) == 0);
      CHECK(strstr(out, "Transfer complete") && strstr(out, "at physical layer") && strstr(out, "bps"));
    }
    CHECK(snprintf(path, sizeof(path), "%s/payload.bin", recv) > 0);
    CHECK(file_read(path, buf, sizeof(buf)) == sizeof(bytes) &&
          !memcmp(buf, bytes, sizeof(bytes)));
    {
      unsigned k;
      for (k = 0; k < 6; ++k) /* the listener has 4 link slots */
        CHECK(run_cp(cp, out, sizeof(out), send_args) == 0);
    }
    CHECK(snprintf(path, sizeof(path), "%s/payload.bin.1", recv) > 0);
    CHECK(file_read(path, buf, sizeof(buf)) == sizeof(bytes));
    read_until(lfd, "Saved received file to", listen_out, sizeof(listen_out), 5);
    stop_cp(listener, lfd);
  }

  /* allow list: B may push, C is turned away and nothing is saved */
  {
    char *listen_args[] = {(char *)cp, "--connect", connect, "--identity",
                           listener_id, "-l", "-a", hash_b, "-s", jail, "-b",
                           "0", NULL};
    char *send_b[] = {(char *)cp, "--connect", connect, "--identity", idb,
                      outside, dest, NULL};
    char *send_c[] = {(char *)cp, "--connect", connect, "--identity", idc,
                      payload, dest, NULL};
    listener = spawn_cp(cp, &lfd, listen_args);
    memset(listen_out, 0, sizeof(listen_out));
    read_until(lfd, ">\n", listen_out, sizeof(listen_out), 10);
    CHECK(run_cp(cp, out, sizeof(out), send_c) != 0);
    CHECK(snprintf(path, sizeof(path), "%s/payload.bin", jail) > 0);
    CHECK(access(path, F_OK) != 0);
    CHECK(run_cp(cp, out, sizeof(out), send_b) == 0);
    CHECK(snprintf(path, sizeof(path), "%s/outside.txt", jail) > 0);
    CHECK(file_read(path, buf, sizeof(buf)) == 6 && !memcmp(buf, "secret", 6));
    stop_cp(listener, lfd);
    CHECK(!unlink(path));
  }

  /* -p prints the identity and where it listens, without connecting; the allow list may be a file in
   * ~/.rncp/allowed_identities (entries of 32 characters; others are ignored) */
  {
    char home[400], rncp_dir[420], allowed[460], want[64], *saved_home = getenv("HOME");
    char *print_args[] = {(char *)cp, "--identity", idb, "-p", NULL};
    char *listen_args[] = {(char *)cp, "--connect", connect, "--identity", listener_id, "-l", "-s", jail, "-b",
                           "0", NULL};
    char *send_b[] = {(char *)cp, "--connect", connect, "--identity", idb, outside, dest, NULL};
    char *send_c[] = {(char *)cp, "--connect", connect, "--identity", idc, payload, dest, "-S", "-C", NULL};
    uint8_t key_b[64], name_hash[10], dest_b[16];
    char listing[200];
    rnc_identity id_b;
    CHECK(file_read(idb, (char *)key_b, 64) == 64 && rnc_identity_from_private(&id_b, key_b) == RNC_OK);
    CHECK(rnc_destination_hash("rncp.receive", &id_b, name_hash, dest_b) == RNC_OK);
    CHECK(run_cp(cp, out, sizeof(out), print_args) == 0);
    hex_of(dest_b, 16, want);
    CHECK(strstr(out, "Identity     : <") && strstr(out, hash_b) && strstr(out, "Listening on : <") && strstr(out, want));
    rnc_identity_clear(&id_b);
    CHECK(snprintf(home, sizeof(home), "%s/home", dir) > 0 && !mkdir(home, 0700));
    CHECK(snprintf(rncp_dir, sizeof(rncp_dir), "%s/.rncp", home) > 0 && !mkdir(rncp_dir, 0700));
    CHECK(snprintf(allowed, sizeof(allowed), "%s/allowed_identities", rncp_dir) > 0);
    CHECK(snprintf(listing, sizeof(listing), "not a hash\r\n%s\r\n\r\n%s0\r\n", hash_c, hash_b) > 0);
    file_bytes(allowed, listing, strlen(listing));
    CHECK(setenv("HOME", home, 1) == 0);
    listener = spawn_cp(cp, &lfd, listen_args);
    memset(listen_out, 0, sizeof(listen_out));
    read_until(lfd, ">\n", listen_out, sizeof(listen_out), 10);
    CHECK(setenv("HOME", saved_home ? saved_home : "/", 1) == 0);
    CHECK(run_cp(cp, out, sizeof(out), send_b) != 0); /* its 33 character line does not count */
    CHECK(run_cp(cp, out, sizeof(out), send_c) == 0 && strstr(out, "Transfer complete") && !strstr(out, "Progress"));
    CHECK(snprintf(path, sizeof(path), "%s/payload.bin", jail) > 0);
    CHECK(file_read(path, buf, sizeof(buf)) == sizeof(bytes));
    stop_cp(listener, lfd);
    CHECK(!unlink(path));
  }

  /* fetch from a jail: a file inside comes back, escapes and misses do not */
  {
    char *listen_args[] = {(char *)cp, "--connect", connect, "--identity",
                           listener_id, "-l", "-n", "-F", "-j", jail, "-s",
                           recv, "-b", "0", NULL};
    char *fetch_in[] = {(char *)cp, "--connect", connect, "--identity", idb,
                        "-f", "hello.txt", dest, "-s", fetched, NULL};
    char *fetch_up[] = {(char *)cp, "--connect", connect, "--identity", idb,
                        "-f", "../outside.txt", dest, "-s", fetched, NULL};
    char *fetch_none[] = {(char *)cp, "--connect", connect, "--identity", idb,
                          "-f", "nothing.txt", dest, "-s", fetched, NULL};
    listener = spawn_cp(cp, &lfd, listen_args);
    memset(listen_out, 0, sizeof(listen_out));
    read_until(lfd, ">\n", listen_out, sizeof(listen_out), 10);
    CHECK(run_cp(cp, out, sizeof(out), fetch_in) == 0);
    CHECK(snprintf(path, sizeof(path), "%s/hello.txt", fetched) > 0);
    CHECK(file_read(path, buf, sizeof(buf)) == 15 &&
          !memcmp(buf, "inside the jail", 15));
    CHECK(run_cp(cp, out, sizeof(out), fetch_up) != 0 &&
          strstr(out, "not allowed"));
    CHECK(run_cp(cp, out, sizeof(out), fetch_none) != 0 &&
          strstr(out, "does not have"));
    CHECK(snprintf(path, sizeof(path), "%s/outside.txt", fetched) > 0);
    CHECK(access(path, F_OK) != 0);
    stop_cp(listener, lfd);
  }
  stop(daemon, dfd);
  remove_tree(dir);
  puts("cp tool tests passed");
}
/* Both directions of push and fetch against the unmodified reference rncp. */
static void cp_reference(const char *exe, const char *cp, const char *python) {
  char dir[] = "/tmp/rnc-cp-ref-XXXXXX", cfg[256], key[256], admin[256],
       refcfg[300], refconf[320], jail[300], r1[300], r2[300], fetched[300],
       idl[300], ref_l[300], ref_c[300], connect[64], dest[33], out[8192],
       listen_out[8192], payload[300], jailed[300], outside[300], path[400],
       text[2048], identity[33], buf[3000];
  unsigned port = unused_port();
  int dfd, lfd;
  pid_t daemon, listener;
  uint8_t bytes[3000];
  size_t i;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/daemon_id", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(refcfg, sizeof(refcfg), "%s/refcfg", dir) > 0 &&
        !mkdir(refcfg, 0700));
  CHECK(snprintf(refconf, sizeof(refconf), "%s/config", refcfg) > 0);
  CHECK(snprintf(jail, sizeof(jail), "%s/jail", dir) > 0 && !mkdir(jail, 0700));
  CHECK(snprintf(r1, sizeof(r1), "%s/r1", dir) > 0 && !mkdir(r1, 0700));
  CHECK(snprintf(r2, sizeof(r2), "%s/r2", dir) > 0 && !mkdir(r2, 0700));
  CHECK(snprintf(fetched, sizeof(fetched), "%s/fetched", dir) > 0 &&
        !mkdir(fetched, 0700));
  CHECK(snprintf(idl, sizeof(idl), "%s/id_ours", dir) > 0);
  CHECK(snprintf(ref_l, sizeof(ref_l), "%s/id_ref_l", dir) > 0);
  CHECK(snprintf(ref_c, sizeof(ref_c), "%s/id_ref_c", dir) > 0);
  CHECK(snprintf(connect, sizeof(connect), "127.0.0.1:%u", port) > 0);
  CHECK(snprintf(payload, sizeof(payload), "%s/payload.bin", dir) > 0);
  CHECK(snprintf(jailed, sizeof(jailed), "%s/hello.txt", jail) > 0);
  CHECK(snprintf(outside, sizeof(outside), "%s/outside.txt", dir) > 0);
  for (i = 0; i < sizeof(bytes); ++i)
    bytes[i] = (uint8_t)(i * 17u + 3u);
  file_bytes(payload, (const char *)bytes, sizeof(bytes));
  file_bytes(jailed, "inside the jail", 15);
  file_bytes(outside, "secret", 6);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = Yes\nshare_instance = No\n"
                 "[interfaces]\n[[TCP]]\ntype = TCPServerInterface\n"
                 "listen_ip = 127.0.0.1\nlisten_port = %u\n",
                 port) > 0);
  config_file(cfg, text);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = False\nshare_instance = No\n"
                 "[interfaces]\n[[Daemon]]\ntype = TCPClientInterface\n"
                 "enabled = yes\ntarget_host = 127.0.0.1\ntarget_port = %u\n",
                 port) > 0);
  config_file(refconf, text);
  daemon = start(exe, cfg, key, admin, &dfd);
  ready_line(dfd, identity);

  /* reference listens and fetches are served; ours pushes and pulls */
  {
    char *ref_listen[] = {(char *)python, "-u", "-m", "RNS.Utilities.rncp",
                          "--config", refcfg, "-l", "-n", "-F", "-j", jail,
                          "-s", r1, "-b", "0", "-i", ref_l, "-v", NULL};
    char *push[] = {(char *)cp, "--connect", connect, "--identity", idl, payload,
                    dest, "-w", "30", NULL};
    char *pull[] = {(char *)cp, "--connect", connect, "--identity", idl, "-f",
                    "hello.txt", dest, "-s", fetched, "-w", "30", NULL};
    char *pull_up[] = {(char *)cp, "--connect", connect, "--identity", idl, "-f",
                       "../outside.txt", dest, "-s", fetched, "-w", "30", NULL};
    listener = spawn_cp(python, &lfd, ref_listen);
    memset(listen_out, 0, sizeof(listen_out));
    read_until(lfd, "rncp listening on <", listen_out, sizeof(listen_out), 60);
    read_until(lfd, ">", listen_out, sizeof(listen_out), 5);
    parse_listening(listen_out, dest);
    CHECK(run_cp(cp, out, sizeof(out), push) == 0);
    CHECK(snprintf(path, sizeof(path), "%s/payload.bin", r1) > 0);
    CHECK(file_read(path, buf, sizeof(buf)) == sizeof(bytes) &&
          !memcmp(buf, bytes, sizeof(bytes)));
    CHECK(run_cp(cp, out, sizeof(out), pull) == 0);
    CHECK(snprintf(path, sizeof(path), "%s/hello.txt", fetched) > 0);
    CHECK(file_read(path, buf, sizeof(buf)) == 15 &&
          !memcmp(buf, "inside the jail", 15));
    CHECK(run_cp(cp, out, sizeof(out), pull_up) != 0);
    stop_cp(listener, lfd);
  }

  /* ours listens and serves; the reference pushes and pulls */
  {
    char *our_listen[] = {(char *)cp, "--connect", connect, "--identity", idl,
                          "-l", "-n", "-F", "-j", jail, "-s", r2, "-b", "0",
                          NULL};
    char *ref_push[] = {(char *)python, "-u", "-m", "RNS.Utilities.rncp",
                        "--config", refcfg, "-i", ref_c, "-w", "30", payload,
                        dest, NULL};
    char *ref_pull[] = {(char *)python, "-u", "-m", "RNS.Utilities.rncp",
                        "--config", refcfg, "-i", ref_c, "-w", "30", "-f",
                        "hello.txt", dest, "-s", fetched, "-O", NULL};
    listener = spawn_cp(cp, &lfd, our_listen);
    memset(listen_out, 0, sizeof(listen_out));
    read_until(lfd, ">\n", listen_out, sizeof(listen_out), 10);
    parse_listening(listen_out, dest);
    CHECK(unlink(path) == 0);
    CHECK(run_cp(python, out, sizeof(out), ref_push) == 0);
    CHECK(snprintf(path, sizeof(path), "%s/payload.bin", r2) > 0);
    CHECK(file_read(path, buf, sizeof(buf)) == sizeof(bytes) &&
          !memcmp(buf, bytes, sizeof(bytes)));
    CHECK(run_cp(python, out, sizeof(out), ref_pull) == 0);
    CHECK(snprintf(path, sizeof(path), "%s/hello.txt", fetched) > 0);
    CHECK(file_read(path, buf, sizeof(buf)) == 15 &&
          !memcmp(buf, "inside the jail", 15));
    stop_cp(listener, lfd);
  }
  stop(daemon, dfd);
  remove_tree(dir);
  puts("cp reference tests passed");
}

/* ---- reticulum-c-x (rnx compatible remote execution) -------------------- */
static void parse_after(const char *text, const char *needle, char hash[33]) {
  const char *at = strstr(text, needle);
  CHECK(at);
  memcpy(hash, at + strlen(needle), 32);
  hash[32] = 0;
}
static int x_run(const char *x, const char *connect, char *out, size_t size,
                 const char *identity, ...) {
  char *args[32];
  size_t n = 0;
  va_list ap;
  const char *a;
  args[n++] = (char *)x;
  args[n++] = "--connect";
  args[n++] = (char *)connect;
  args[n++] = "--identity";
  args[n++] = (char *)identity;
  va_start(ap, identity);
  while ((a = va_arg(ap, const char *)) != NULL && n < 31)
    args[n++] = (char *)a;
  va_end(ap);
  args[n] = NULL;
  return run_cp(x, out, size, args);
}
static void x_tools(const char *exe, const char *x) {
  char dir[] = "/tmp/rnc-node-x-XXXXXX", cfg[256], key[256], admin[256],
       idb[300], idc[300], idl[300], connect[64], hash_b[33], hash_c[33],
       dest[33], out[8192], listen_out[8192], marker[300], touch[400],
       text[2048], identity[33], cmd[400];
  unsigned port = unused_port();
  int dfd, lfd;
  pid_t daemon, listener;
  time_t started;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/daemon_id", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(idb, sizeof(idb), "%s/id_b", dir) > 0);
  CHECK(snprintf(idc, sizeof(idc), "%s/id_c", dir) > 0);
  CHECK(snprintf(idl, sizeof(idl), "%s/id_l", dir) > 0);
  CHECK(snprintf(connect, sizeof(connect), "127.0.0.1:%u", port) > 0);
  CHECK(snprintf(marker, sizeof(marker), "%s/marker", dir) > 0);
  write_identity(idb, 21, hash_b);
  write_identity(idc, 77, hash_c);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = Yes\nshare_instance = No\n"
                 "[interfaces]\n[[TCP]]\ntype = TCPServerInterface\n"
                 "listen_ip = 127.0.0.1\nlisten_port = %u\n",
                 port) > 0);
  config_file(cfg, text);
  daemon = start(exe, cfg, key, admin, &dfd);
  ready_line(dfd, identity);
  {
    char *listen_args[] = {(char *)x, "--connect", connect, "--identity", idl,
                           "-l", "-a", hash_b, NULL};
    listener = spawn_cp(x, &lfd, listen_args);
    memset(listen_out, 0, sizeof(listen_out));
    read_until(lfd, "rnx listening for commands on <", listen_out,
               sizeof(listen_out), 10);
    read_until(lfd, ">\n", listen_out, sizeof(listen_out), 10);
    parse_after(listen_out, "rnx listening for commands on <", dest);
  }
  /* output comes back; the exit code is only mirrored with -m */
  /* every run closes its link, so far more runs than link slots work */
  {
    unsigned k;
    for (k = 0; k < 12; ++k)
      CHECK(x_run(x, connect, out, sizeof(out), idb, dest, "echo again", NULL) == 0);
  }
  CHECK(x_run(x, connect, out, sizeof(out), idb, dest, "echo hello world", NULL) == 0 && strstr(out, "hello world"));
  CHECK(x_run(x, connect, out, sizeof(out), idb, "-m", dest, "sh -c 'exit 3'", NULL) == 3);
  CHECK(x_run(x, connect, out, sizeof(out), idb, dest, "sh -c 'exit 3'", NULL) == 0);
  CHECK(x_run(x, connect, out, sizeof(out), idb, "--stdin", "abc", dest, "cat", NULL) == 0 && strstr(out, "abc"));
  CHECK(x_run(x, connect, out, sizeof(out), idb, "--stdout", "3", dest, "echo abcdefgh", NULL) == 0 &&
        strstr(out, "abc") && !strstr(out, "abcd") &&
        strstr(out, "stdout truncated to 3 bytes"));
  CHECK(x_run(x, connect, out, sizeof(out), idb, dest, "sh -c 'echo oops 1>&2'", NULL) == 0 && strstr(out, "oops"));
  CHECK(x_run(x, connect, out, sizeof(out), idb, dest, "/no/such/binary", NULL) == 248 &&
        strstr(out, "Remote could not execute command"));
  /* a command that outlives its timeout is stopped */
  started = time(NULL);
  CHECK(x_run(x, connect, out, sizeof(out), idb, "-w", "2", dest, "sleep 30", NULL) == 0);
  CHECK(time(NULL) - started < 15);
  /* an identity that is not allowed cannot run anything */
  CHECK(snprintf(touch, sizeof(touch), "touch %s", marker) > 0);
  CHECK(x_run(x, connect, out, sizeof(out), idc, "-w", "5", dest, touch, NULL) != 0);
  CHECK(access(marker, F_OK) != 0);
  {
    int rc_ = x_run(x, connect, out, sizeof(out), idb, dest, touch, NULL);
    if (rc_)
      fprintf(stderr, "touch as B failed (%d):\n%s\n", rc_, out);
    CHECK(rc_ == 0);
  }
  CHECK(access(marker, F_OK) == 0);
  /* -x: a prompt, one command per line over the same listener, the last exit code shown in the prompt,
   * ending on exit, quit or end of input */
  {
    char script[1024];
    char *args[] = {"/bin/sh", "-c", script, NULL};
    CHECK(snprintf(script, sizeof(script),
                   "printf 'echo first\\nsh -c \"exit 3\"\\necho third\\nclear\\nexit\\necho never\\n' | %s --connect %s "
                   "--identity %s -x %s",
                   x, connect, idb, dest) > 0);
    CHECK(run_cp("/bin/sh", out, sizeof(out), args) == 0);
    CHECK(strstr(out, "first"));
    CHECK(strstr(out, "3> ") && strstr(out, "third") && !strstr(out, "never"));
    CHECK(snprintf(script, sizeof(script), "printf 'echo only\\n' | %s --connect %s --identity %s -x %s", x, connect,
                   idb, dest) > 0);
    CHECK(run_cp("/bin/sh", out, sizeof(out), args) == 0 && strstr(out, "only")); /* end of input ends it too */
    CHECK(x_run(x, connect, out, sizeof(out), idb, "-x", dest, "echo extra", NULL) != 0); /* no command with -x */
  }
  /* -W caps how long the result may take: the command outlasts it and the run ends at once */
  started = time(NULL);
  CHECK(x_run(x, connect, out, sizeof(out), idb, "-w", "30", "-W", "2", dest, "sleep 6", NULL) == 244);
  CHECK(time(NULL) - started < 5);
  /* -p prints the identity and where it listens without connecting; the allow list may be a file in
   * ~/.rnx/allowed_identities (entries of 32 characters, others ignored) */
  {
    char home[400], rnx_dir[420], allowed[460], want[64], listing[200], idl2[300], dest2[33];
    char *saved_home = getenv("HOME");
    char *print_args[] = {(char *)x, "--identity", idb, "-p", NULL};
    char *listen2[] = {(char *)x, "--connect", connect, "--identity", idl2, "-l", NULL};
    uint8_t key_b[64], name_hash[10], dest_b[16];
    rnc_identity id_b;
    pid_t second;
    int sfd;
    CHECK(file_read(idb, (char *)key_b, 64) == 64 && rnc_identity_from_private(&id_b, key_b) == RNC_OK);
    CHECK(rnc_destination_hash("rnx.execute", &id_b, name_hash, dest_b) == RNC_OK);
    CHECK(run_cp(x, out, sizeof(out), print_args) == 0);
    hex_of(dest_b, 16, want);
    CHECK(strstr(out, "Identity     : <") && strstr(out, hash_b) && strstr(out, "Listening on : <") && strstr(out, want));
    rnc_identity_clear(&id_b);
    CHECK(snprintf(idl2, sizeof(idl2), "%s/id_l2", dir) > 0);
    CHECK(snprintf(home, sizeof(home), "%s/home", dir) > 0 && !mkdir(home, 0700));
    CHECK(snprintf(rnx_dir, sizeof(rnx_dir), "%s/.rnx", home) > 0 && !mkdir(rnx_dir, 0700));
    CHECK(snprintf(allowed, sizeof(allowed), "%s/allowed_identities", rnx_dir) > 0);
    CHECK(snprintf(listing, sizeof(listing), "junk\r\n%s\r\n", hash_c) > 0);
    file_bytes(allowed, listing, strlen(listing));
    CHECK(setenv("HOME", home, 1) == 0);
    second = spawn_cp(x, &sfd, listen2);
    memset(listen_out, 0, sizeof(listen_out));
    read_until(sfd, "rnx listening for commands on <", listen_out, sizeof(listen_out), 10);
    read_until(sfd, ">\n", listen_out, sizeof(listen_out), 10);
    CHECK(setenv("HOME", saved_home ? saved_home : "/", 1) == 0);
    parse_after(listen_out, "rnx listening for commands on <", dest2);
    CHECK(x_run(x, connect, out, sizeof(out), idc, dest2, "echo from-file", NULL) == 0 && strstr(out, "from-file"));
    CHECK(x_run(x, connect, out, sizeof(out), idb, "-w", "5", dest2, "echo denied", NULL) != 0);
    stop_cp(second, sfd);
  }
  (void)cmd;
  stop_cp(listener, lfd);
  stop(daemon, dfd);
  remove_tree(dir);
  puts("x tool tests passed");
}
/* rnstatus -R and rnpath -R equivalents: reticulum-c-ctl asks another instance's management destination. */
static void ctl_remote_test(const char *exe, const char *ctl) {
  char dir[] = "/tmp/rnc-node-rem-XXXXXX", cfg[256], key[256], admin[256], idb[300], idc[300], attach[64],
       hash_b[33], hash_c[33], daemon[33], out[16384], text[1024], announced[33];
  unsigned port = unused_port(), entropy = 5, waited;
  uint8_t seed_key[64] = {9}, raw[RNC_MAX_MTU], framed[RNC_HOST_FRAME_MAX];
  rnc_identity announcer;
  rnc_packet announce;
  size_t raw_size, framed_size, k;
  int fd, feed;
  pid_t p;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/node-identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(idb, sizeof(idb), "%s/id_b", dir) > 0);
  CHECK(snprintf(idc, sizeof(idc), "%s/id_c", dir) > 0);
  CHECK(snprintf(attach, sizeof(attach), "127.0.0.1:%u", port) > 0);
  write_identity(idb, 31, hash_b);
  write_identity(idc, 71, hash_c);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = Yes\nshare_instance = No\nenable_remote_management = Yes\n"
                 "remote_management_allowed = %s\n[interfaces]\n[[TCP]]\ntype = TCPServerInterface\n"
                 "listen_ip = 127.0.0.1\nlisten_port = %u\n",
                 hash_b, port) > 0);
  config_file(cfg, text);
  p = start(exe, cfg, key, admin, &fd);
  ready_line(fd, daemon);
  /* give the daemon one path to report */
  CHECK(rnc_identity_from_private(&announcer, seed_key) == RNC_OK &&
        rnc_announce_create(&announcer, "reticulum_c.ctl.remote", NULL, 0, (uint64_t)time(NULL), rng, &entropy,
                            &announce) == RNC_OK);
  CHECK(rnc_packet_encode(&announce, raw, sizeof(raw), &raw_size) == RNC_OK &&
        rnc_host_frame_encode(RNC_HOST_HDLC, 0, raw, raw_size, framed, sizeof(framed), &framed_size) == RNC_OK);
  for (k = 0; k < 16; ++k)
    CHECK(snprintf(announced + 2 * k, 3, "%02x", announce.destination[k]) == 2);
  feed = tcp_connect(port);
  CHECK(write(feed, framed, framed_size) == (ssize_t)framed_size);
  for (waited = 0; waited < 100 && !admin_has_path(admin, announced); ++waited) {
    struct timespec ts = {0, 50000000};
    nanosleep(&ts, NULL);
  }
  CHECK(waited < 100);
  /* the allowed identity gets statistics and the path table; the filter and the hop limit still work */
  CHECK(ctl_run(ctl, out, sizeof(out), "status", "-R", daemon, "--attach", attach, "--mgmt-identity", idb, "-w", "20",
                NULL) == 0 &&
        strstr(out, "Status") && strstr(out, "Transport Instance <"));
  CHECK(ctl_run(ctl, out, sizeof(out), "path", "-t", "-R", daemon, "--attach", attach, "--mgmt-identity", idb, "-w", "20",
                NULL) == 0 &&
        strstr(out, announced));
  CHECK(ctl_run(ctl, out, sizeof(out), "path", "-r", "-R", daemon, "--attach", attach, "--mgmt-identity", idb, "-w", "20",
                NULL) == 0);
  /* an identity that is not on the allow list is refused */
  CHECK(ctl_run(ctl, out, sizeof(out), "status", "-R", daemon, "--attach", attach, "--mgmt-identity", idc, "-w", "8",
                NULL) != 0);
  /* a remote query needs somewhere to attach and an identity */
  CHECK(ctl_run(ctl, out, sizeof(out), "status", "-R", daemon, NULL) != 0);
  close(feed);
  stop(p, fd);
  remove_tree(dir);
  puts("ctl remote tests passed");
}
/* The stand-alone examples (examples/example_announce.c, example_request.c) against the daemon. */
static void examples_test(const char *exe, const char *announce, const char *request, const char *echo) {
  char dir[] = "/tmp/rnc-node-ex-XXXXXX", cfg[256], key[256], admin[256], id_a[300], id_b[300], id_s[300],
       connect[64], dest[33], out[4096], listen_out[4096], text[1024], identity[33], hash[33];
  unsigned port = unused_port();
  int dfd, afd, bfd, sfd;
  pid_t daemon, a, b, server;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/daemon_id", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(id_a, sizeof(id_a), "%s/id_a", dir) > 0);
  CHECK(snprintf(id_b, sizeof(id_b), "%s/id_b", dir) > 0);
  CHECK(snprintf(id_s, sizeof(id_s), "%s/id_s", dir) > 0);
  CHECK(snprintf(connect, sizeof(connect), "127.0.0.1:%u", port) > 0);
  write_identity(id_a, 5, hash);
  write_identity(id_b, 50, hash);
  write_identity(id_s, 95, hash);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = Yes\nshare_instance = No\n[interfaces]\n[[TCP]]\n"
                 "type = TCPServerInterface\nlisten_ip = 127.0.0.1\nlisten_port = %u\n",
                 port) > 0);
  config_file(cfg, text);
  daemon = start(exe, cfg, key, admin, &dfd);
  ready_line(dfd, identity);
  /* A listens for one announce; B announces; A prints B's destination and text */
  {
    char *listen_args[] = {(char *)announce, "--connect", connect, "--identity", id_a, "--app-data", "first",
                           "--count", "1", NULL};
    char *other_args[] = {(char *)announce, "--connect", connect, "--identity", id_b, "--app-data",
                          "second one", NULL};
    int status;
    a = spawn_cp(announce, &afd, listen_args);
    memset(listen_out, 0, sizeof(listen_out));
    read_until(afd, "announcing <", listen_out, sizeof(listen_out), 10);
    read_until(afd, ">\n", listen_out, sizeof(listen_out), 10);
    b = spawn_cp(announce, &bfd, other_args);
    memset(out, 0, sizeof(out));
    read_until(bfd, ">\n", out, sizeof(out), 10);
    read_until(afd, "second one", listen_out, sizeof(listen_out), 20);
    CHECK(strstr(listen_out, "heard <") && strstr(listen_out, " hop"));
    CHECK(waitpid(a, &status, 0) == a && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(afd);
    stop_cp(b, bfd);
  }
  /* a request service: the answer is the text reversed */
  {
    char *serve_args[] = {(char *)request, "--connect", connect, "--identity", id_s, "server", NULL};
    char *call_args[] = {(char *)request, "--connect", connect, "--identity", id_a, "client", dest, "hello world", NULL};
    server = spawn_cp(request, &sfd, serve_args);
    memset(listen_out, 0, sizeof(listen_out));
    read_until(sfd, "serving /reverse on <", listen_out, sizeof(listen_out), 10);
    read_until(sfd, ">\n", listen_out, sizeof(listen_out), 10);
    parse_after(listen_out, "serving /reverse on <", dest);
    CHECK(run_cp(request, out, sizeof(out), call_args) == 0);
    CHECK(strstr(out, "dlrow olleh"));
    stop_cp(server, sfd);
    CHECK(run_cp(request, out, sizeof(out), (char *[]){(char *)request, "--connect", connect, "--identity", id_a, "client", "00000000000000000000000000000000", "x", NULL}) != 0);
  }
  /* echo: the server proves, the client reports the round trip */
  {
    char id_e[300], echo_dest[33];
    char *serve_args[] = {(char *)echo, "--connect", connect, "--identity", id_s, "server", NULL};
    char *ping_args[] = {(char *)echo, "--connect", connect, "--identity", id_a, "--count", "2", "client", echo_dest, NULL};
    (void)id_e;
    server = spawn_cp(echo, &sfd, serve_args);
    memset(listen_out, 0, sizeof(listen_out));
    read_until(sfd, "Echo server <", listen_out, sizeof(listen_out), 10);
    read_until(sfd, ">", listen_out, sizeof(listen_out), 10);
    parse_after(listen_out, "Echo server <", echo_dest);
    CHECK(run_cp(echo, out, sizeof(out), ping_args) == 0);
    CHECK(strstr(out, "Sent echo request to <") && strstr(out, "Valid reply received from <") &&
          strstr(out, "round-trip time is"));
    memset(listen_out, 0, sizeof(listen_out));
    read_until(sfd, "proof sent", listen_out, sizeof(listen_out), 10);
    CHECK(strstr(listen_out, "Received packet from echo client, proof sent"));
    stop_cp(server, sfd);
    /* nobody there: the client reports it and fails */
    CHECK(run_cp(echo, out, sizeof(out), (char *[]){(char *)echo, "--connect", connect, "--identity", id_a, "client",
                                                    "00000000000000000000000000000000", NULL}) != 0);
  }
  stop(daemon, dfd);
  remove_tree(dir);
  puts("example tests passed");
}
/* The reference rnx against ours, both directions. */
static void x_reference(const char *exe, const char *x, const char *python) {
  char dir[] = "/tmp/rnc-x-ref-XXXXXX", cfg[256], key[256], admin[256],
       refcfg[300], refconf[320], idl[300], ref_l[300], ref_c[300], connect[64],
       hash_ref[33], dest[33], out[8192], listen_out[8192], text[2048],
       identity[33];
  unsigned port = unused_port();
  int dfd, lfd;
  pid_t daemon, listener;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/daemon_id", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(refcfg, sizeof(refcfg), "%s/refcfg", dir) > 0 &&
        !mkdir(refcfg, 0700));
  CHECK(snprintf(refconf, sizeof(refconf), "%s/config", refcfg) > 0);
  CHECK(snprintf(idl, sizeof(idl), "%s/id_ours", dir) > 0);
  CHECK(snprintf(ref_l, sizeof(ref_l), "%s/id_ref_l", dir) > 0);
  CHECK(snprintf(ref_c, sizeof(ref_c), "%s/id_ref_c", dir) > 0);
  CHECK(snprintf(connect, sizeof(connect), "127.0.0.1:%u", port) > 0);
  write_identity(ref_c, 33, hash_ref);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = Yes\nshare_instance = No\n"
                 "[interfaces]\n[[TCP]]\ntype = TCPServerInterface\n"
                 "listen_ip = 127.0.0.1\nlisten_port = %u\n",
                 port) > 0);
  config_file(cfg, text);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = False\nshare_instance = No\n"
                 "[interfaces]\n[[Daemon]]\ntype = TCPClientInterface\n"
                 "enabled = yes\ntarget_host = 127.0.0.1\ntarget_port = %u\n",
                 port) > 0);
  config_file(refconf, text);
  daemon = start(exe, cfg, key, admin, &dfd);
  ready_line(dfd, identity);

  /* ours executes for the reference */
  {
    char *our_listen[] = {(char *)x, "--connect", connect, "--identity", idl,
                          "-l", "-a", hash_ref, NULL};
    char *ref_run[] = {(char *)python, "-u", "-m", "RNS.Utilities.rnx",
                       "--config", refcfg, "-i", ref_c, "-w", "30", "-m", dest,
                       "sh -c 'echo from-ours; exit 4'", NULL};
    listener = spawn_cp(x, &lfd, our_listen);
    memset(listen_out, 0, sizeof(listen_out));
    read_until(lfd, ">\n", listen_out, sizeof(listen_out), 10);
    parse_after(listen_out, "rnx listening for commands on <", dest);
    CHECK(run_cp(python, out, sizeof(out), ref_run) == 4 &&
          strstr(out, "from-ours"));
    stop_cp(listener, lfd);
  }
  /* the reference executes for ours */
  {
    char *ref_listen[] = {(char *)python, "-u", "-m", "RNS.Utilities.rnx",
                          "--config", refcfg, "-l", "-n", "-i", ref_l, "-v",
                          NULL};
    char *run[] = {(char *)x, "--connect", connect, "--identity", idl, "-m",
                   "-w", "30", dest, "sh -c 'echo from-ref; exit 5'", NULL};
    listener = spawn_cp(python, &lfd, ref_listen);
    memset(listen_out, 0, sizeof(listen_out));
    read_until(lfd, "rnx listening for commands on <", listen_out,
               sizeof(listen_out), 60);
    read_until(lfd, ">", listen_out, sizeof(listen_out), 5);
    parse_after(listen_out, "rnx listening for commands on <", dest);
    CHECK(run_cp(x, out, sizeof(out), run) == 5 && strstr(out, "from-ref"));
    stop_cp(listener, lfd);
  }
  stop(daemon, dfd);
  remove_tree(dir);
  puts("x reference tests passed");
}

/* ---- reticulum-c-sh (rnsh compatible remote shell) ----------------------- */
/* Like run_cp, but feeds `input` to the command's standard input. */
static int run_cp_input(const char *cp, char *out, size_t size, char *const *args,
                        const char *input) {
  int out_fds[2], in_fds[2], status;
  size_t n = 0;
  pid_t p;
  unsigned tries;
  CHECK(!pipe(out_fds) && !pipe(in_fds));
  p = fork();
  CHECK(p >= 0);
  if (!p) {
    close(out_fds[0]);
    close(in_fds[1]);
    CHECK(dup2(out_fds[1], STDOUT_FILENO) >= 0 &&
          dup2(out_fds[1], STDERR_FILENO) >= 0 && dup2(in_fds[0], STDIN_FILENO) >= 0);
    close(out_fds[1]);
    close(in_fds[0]);
    execv(cp, args);
    _exit(127);
  }
  close(out_fds[1]);
  close(in_fds[0]);
  if (input && *input)
    CHECK(write(in_fds[1], input, strlen(input)) == (ssize_t)strlen(input));
  close(in_fds[1]);
  for (tries = 0; tries < 900; ++tries) {
    struct pollfd pf = {out_fds[0], POLLIN, 0};
    int r = poll(&pf, 1, 100);
    CHECK(r >= 0);
    if (r > 0) {
      ssize_t got = read(out_fds[0], out + n, size - 1 - n);
      if (got <= 0)
        break;
      n += (size_t)got;
      CHECK(n < size - 1);
    }
  }
  CHECK(tries < 900);
  out[n] = 0;
  close(out_fds[0]);
  CHECK(waitpid(p, &status, 0) == p && WIFEXITED(status));
  return WEXITSTATUS(status);
}
/* Runs a command with a real terminal on stdin, stdout and stderr and returns
 * what it wrote to the terminal. */
static int run_in_pty(const char *cp, char *out, size_t size, char *const *args,
                      const char *typed) {
  int master = posix_openpt(O_RDWR | O_NOCTTY), status = 0;
  size_t n = 0;
  pid_t p;
  unsigned tries;
  int reaped = 0;
  CHECK(master >= 0 && grantpt(master) == 0 && unlockpt(master) == 0);
  p = fork();
  CHECK(p >= 0);
  if (!p) {
    int slave = open(ptsname(master), O_RDWR);
    CHECK(slave >= 0);
    CHECK(setsid() >= 0);
    CHECK(ioctl(slave, TIOCSCTTY, 0) == 0);
    CHECK(dup2(slave, 0) >= 0 && dup2(slave, 1) >= 0 && dup2(slave, 2) >= 0);
    close(slave);
    close(master);
    execv(cp, args);
    _exit(127);
  }
  if (typed && *typed) {
    struct timespec t = {1, 0};
    nanosleep(&t, NULL); /* let the client reach raw mode */
    CHECK(write(master, typed, strlen(typed)) == (ssize_t)strlen(typed));
  }
  for (tries = 0; tries < 900 && !reaped; ++tries) {
    struct pollfd pf = {master, POLLIN, 0};
    int r = poll(&pf, 1, 100);
    CHECK(r >= 0);
    if (r > 0) {
      ssize_t got = read(master, out + n, size - 1 - n);
      if (got > 0)
        n += (size_t)got;
    }
    if (waitpid(p, &status, WNOHANG) == p)
      reaped = 1;
  }
  CHECK(reaped);
  /* anything the client wrote just before exiting */
  {
    struct pollfd pf = {master, POLLIN, 0};
    while (poll(&pf, 1, 100) > 0) {
      ssize_t got = read(master, out + n, size - 1 - n);
      if (got <= 0)
        break;
      n += (size_t)got;
    }
  }
  out[n] = 0;
  close(master);
  return WIFEXITED(status) ? WEXITSTATUS(status) : 255;
}
static int sh_run(const char *sh, const char *connect, char *out, size_t size,
                  const char *input, const char *identity, ...) {
  char *args[40];
  size_t n = 0;
  va_list ap;
  const char *a;
  args[n++] = (char *)sh;
  args[n++] = "--connect";
  args[n++] = (char *)connect;
  args[n++] = "--identity";
  args[n++] = (char *)identity;
  va_start(ap, identity);
  while ((a = va_arg(ap, const char *)) != NULL && n < 39)
    args[n++] = (char *)a;
  va_end(ap);
  args[n] = NULL;
  return run_cp_input(sh, out, size, args, input);
}
static void sh_tools(const char *exe, const char *sh) {
  char dir[] = "/tmp/rnc-node-sh-XXXXXX", cfg[256], key[256], admin[256],
       idb[300], idc[300], idl[300], connect[64], hash_b[33], hash_c[33],
       dest[33], out[262144], listen_out[8192], text[2048], identity[33];
  unsigned port = unused_port();
  int dfd, lfd;
  pid_t daemon, listener;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/daemon_id", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(idb, sizeof(idb), "%s/id_b", dir) > 0);
  CHECK(snprintf(idc, sizeof(idc), "%s/id_c", dir) > 0);
  CHECK(snprintf(idl, sizeof(idl), "%s/id_l", dir) > 0);
  CHECK(snprintf(connect, sizeof(connect), "127.0.0.1:%u", port) > 0);
  write_identity(idb, 41, hash_b);
  write_identity(idc, 88, hash_c);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = Yes\nshare_instance = No\n"
                 "[interfaces]\n[[TCP]]\ntype = TCPServerInterface\n"
                 "listen_ip = 127.0.0.1\nlisten_port = %u\n",
                 port) > 0);
  config_file(cfg, text);
  daemon = start(exe, cfg, key, admin, &dfd);
  ready_line(dfd, identity);
  {
    char *listen_args[] = {(char *)sh, "--connect", connect, "--identity", idl,
                           "-l", "-a", hash_b, "-b", "0", NULL};
    listener = spawn_cp(sh, &lfd, listen_args);
    memset(listen_out, 0, sizeof(listen_out));
    read_until(lfd, "rnsh listening for commands on <", listen_out,
               sizeof(listen_out), 10);
    read_until(lfd, ">\n", listen_out, sizeof(listen_out), 10);
    parse_after(listen_out, "rnsh listening for commands on <", dest);
  }
  /* pipes: a command, its exit code, stdin and stderr */
  CHECK(sh_run(sh, connect, out, sizeof(out), "", idb, dest, "--", "echo",
               "hello", "shell", NULL) == 0 && strstr(out, "hello shell"));
  CHECK(sh_run(sh, connect, out, sizeof(out), "", idb, "-m", dest, "--", "sh",
               "-c", "exit 5", NULL) == 5);
  CHECK(sh_run(sh, connect, out, sizeof(out), "", idb, dest, "--", "sh", "-c",
               "exit 5", NULL) == 0);
  CHECK(sh_run(sh, connect, out, sizeof(out), "piped input\n", idb, dest, "--",
               "cat", NULL) == 0 && strstr(out, "piped input"));
  CHECK(sh_run(sh, connect, out, sizeof(out), "", idb, dest, "--", "sh", "-c",
               "echo to-stderr 1>&2", NULL) == 0 && strstr(out, "to-stderr"));
  /* the default program takes commands from stdin; the remote identity is set */
  CHECK(sh_run(sh, connect, out, sizeof(out), "echo id=$RNS_REMOTE_IDENTITY\n",
               idb, dest, NULL) == 0 && strstr(out, hash_b));
  /* a lot of output goes through the channel flow control intact */
  CHECK(sh_run(sh, connect, out, sizeof(out), "", idb, dest, "--", "seq", "1",
               "30000", NULL) == 0 && strstr(out, "\n30000\n") &&
        strstr(out, "\n15000\n"));
  /* a terminal on the initiator gives the command a terminal too */
  {
    char *args[] = {(char *)sh, "--connect", connect, "--identity", idb, dest,
                    "--", "sh", "-c", "tty; echo cols=$(stty size)", NULL};
    CHECK(run_in_pty(sh, out, sizeof(out), args, NULL) == 0);
    CHECK(strstr(out, "/dev/") && strstr(out, "cols="));
  }
  /* typing into the default shell, then leaving with exit */
  {
    char *args[] = {(char *)sh, "--connect", connect, "--identity", idb, "-m",
                    dest, NULL};
    CHECK(run_in_pty(sh, out, sizeof(out), args,
                     "echo typed-$((6*7))\rexit 4\r") == 4);
    CHECK(strstr(out, "typed-42"));
  }
  /* "~." after a newline ends the session even though the command runs on */
  {
    char *args[] = {(char *)sh, "--connect", connect, "--identity", idb, dest,
                    "--", "sleep", "60", NULL};
    time_t t0 = time(NULL);
    CHECK(run_in_pty(sh, out, sizeof(out), args, "\r~.") == 0);
    CHECK(time(NULL) - t0 < 20);
  }
  /* a command that ignores HUP and TERM is still stopped when the session ends */
  {
    char pidfile[300], script[600], pidtext[32];
    char *args[] = {(char *)sh, "--connect", connect, "--identity", idb, dest,
                    "--", "sh", "-c", script, NULL};
    pid_t victim;
    CHECK(snprintf(pidfile, sizeof(pidfile), "%s/victim.pid", dir) > 0);
    CHECK(snprintf(script, sizeof(script),
                   "echo $$ > %s; trap '' HUP TERM; while :; do sleep 1; done",
                   pidfile) > 0);
    CHECK(run_in_pty(sh, out, sizeof(out), args, "\r~.") == 0);
    CHECK(file_read(pidfile, pidtext, sizeof(pidtext) - 1) > 0);
    victim = (pid_t)atoi(pidtext);
    CHECK(victim > 1);
    {
      unsigned w;
      int gone = 0;
      for (w = 0; w < 50 && !gone; ++w) {
        struct timespec t = {0, 100000000};
        gone = kill(victim, 0) != 0;
        if (!gone)
          nanosleep(&t, NULL);
      }
      CHECK(gone);
    }
    /* and the listener is still serving */
    CHECK(sh_run(sh, connect, out, sizeof(out), "", idb, dest, "--", "echo",
                 "still-up", NULL) == 0 && strstr(out, "still-up"));
  }
  /* an unlisted identity is turned away and runs nothing */
  CHECK(sh_run(sh, connect, out, sizeof(out), "", idc, dest, "--", "echo",
               "intruder", NULL) != 0 && !strstr(out, "intruder") &&
        strstr(out, "Identity not allowed"));
  (void)hash_c;
  /* a listener may refuse remote command lines */
  stop_cp(listener, lfd);
  {
    char *listen_args[] = {(char *)sh, "--connect", connect, "--identity", idl,
                           "-l", "-a", hash_b, "-b", "0", "-C", "--", "echo",
                           "fixed program", NULL};
    listener = spawn_cp(sh, &lfd, listen_args);
    memset(listen_out, 0, sizeof(listen_out));
    read_until(lfd, ">\n", listen_out, sizeof(listen_out), 10);
    CHECK(sh_run(sh, connect, out, sizeof(out), "", idb, dest, NULL) == 0 &&
          strstr(out, "fixed program"));
    CHECK(sh_run(sh, connect, out, sizeof(out), "", idb, dest, "--", "echo",
                 "custom", NULL) != 0 &&
          strstr(out, "not allowed by listener"));
    stop_cp(listener, lfd);
  }
  /* -p prints the identity (and with -l where it listens) without connecting; the allowed identities may come
   * from ~/.config/rnsh/allowed_identities or ~/.rnsh/allowed_identities (lines of 32 characters); -T forces
   * pipe mode on the initiator */
  {
    char home[400], rnsh_dir[420], allowed[460], want[64], listing[200];
    char *saved_home = getenv("HOME");
    char *print_id[] = {(char *)sh, "--identity", idb, "-p", NULL};
    char *print_listen[] = {(char *)sh, "--identity", idb, "-l", "-p", NULL};
    char *listen_args[] = {(char *)sh, "--connect", connect, "--identity", idl, "-l", "-b", "0", NULL};
    uint8_t key_b[64], name_hash[10], dest_b[16];
    rnc_identity id_b;
    CHECK(file_read(idb, (char *)key_b, 64) == 64 && rnc_identity_from_private(&id_b, key_b) == RNC_OK);
    CHECK(rnc_destination_hash("rnsh", &id_b, name_hash, dest_b) == RNC_OK);
    hex_of(dest_b, 16, want);
    CHECK(run_cp(sh, out, sizeof(out), print_id) == 0 && strstr(out, "Identity     : <") && strstr(out, hash_b) &&
          !strstr(out, "Listening on"));
    CHECK(run_cp(sh, out, sizeof(out), print_listen) == 0 && strstr(out, "Listening on : <") && strstr(out, want));
    rnc_identity_clear(&id_b);
    CHECK(snprintf(home, sizeof(home), "%s/home", dir) > 0 && !mkdir(home, 0700));
    CHECK(snprintf(rnsh_dir, sizeof(rnsh_dir), "%s/.rnsh", home) > 0 && !mkdir(rnsh_dir, 0700));
    CHECK(snprintf(allowed, sizeof(allowed), "%s/allowed_identities", rnsh_dir) > 0);
    CHECK(snprintf(listing, sizeof(listing), "short\r\n%s\r\n%s0\r\n", hash_c, hash_b) > 0);
    file_bytes(allowed, listing, strlen(listing));
    CHECK(setenv("HOME", home, 1) == 0);
    listener = spawn_cp(sh, &lfd, listen_args);
    memset(listen_out, 0, sizeof(listen_out));
    read_until(lfd, ">\n", listen_out, sizeof(listen_out), 10);
    CHECK(setenv("HOME", saved_home ? saved_home : "/", 1) == 0);
    CHECK(sh_run(sh, connect, out, sizeof(out), "", idc, "-T", dest, "--", "echo", "from file", NULL) == 0 &&
          strstr(out, "from file"));
    CHECK(sh_run(sh, connect, out, sizeof(out), "", idb, dest, "--", "echo", "denied", NULL) != 0 &&
          !strstr(out, "denied\n"));
    stop_cp(listener, lfd);
  }
  stop(daemon, dfd);
  remove_tree(dir);
  puts("sh tool tests passed");
}
/* The reference rnsh against ours, both directions. */
static void sh_reference(const char *exe, const char *sh, const char *python) {
  char dir[] = "/tmp/rnc-sh-ref-XXXXXX", cfg[256], key[256], admin[256],
       refcfg[300], refconf[320], shcfg[300], idl[300], ref_l[300], ref_c[300],
       connect[64], hash_ours[33], hash_ref[33], dest[33], out[16384],
       listen_out[16384], text[2048], identity[33];
  unsigned port = unused_port();
  int dfd, lfd;
  pid_t daemon, listener;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/daemon_id", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(refcfg, sizeof(refcfg), "%s/refcfg", dir) > 0 &&
        !mkdir(refcfg, 0700));
  CHECK(snprintf(refconf, sizeof(refconf), "%s/config", refcfg) > 0);
  CHECK(snprintf(shcfg, sizeof(shcfg), "%s/shcfg", dir) > 0 &&
        !mkdir(shcfg, 0700));
  CHECK(snprintf(idl, sizeof(idl), "%s/id_ours", dir) > 0);
  CHECK(snprintf(ref_l, sizeof(ref_l), "%s/id_ref_l", dir) > 0);
  CHECK(snprintf(ref_c, sizeof(ref_c), "%s/id_ref_c", dir) > 0);
  CHECK(snprintf(connect, sizeof(connect), "127.0.0.1:%u", port) > 0);
  write_identity(idl, 55, hash_ours);
  write_identity(ref_c, 66, hash_ref);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = Yes\nshare_instance = No\n"
                 "[interfaces]\n[[TCP]]\ntype = TCPServerInterface\n"
                 "listen_ip = 127.0.0.1\nlisten_port = %u\n",
                 port) > 0);
  config_file(cfg, text);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = False\nshare_instance = No\n"
                 "[interfaces]\n[[Daemon]]\ntype = TCPClientInterface\n"
                 "enabled = yes\ntarget_host = 127.0.0.1\ntarget_port = %u\n",
                 port) > 0);
  config_file(refconf, text);
  daemon = start(exe, cfg, key, admin, &dfd);
  ready_line(dfd, identity);

  /* ours connects to the reference listener */
  {
    char *ref_listen[] = {(char *)python, "-u", "-m", "RNS.Utilities.rnsh.rnsh",
                          "--config", shcfg, "--rnsconfig", refcfg, "-l", "-a",
                          hash_ours, "-b", "0", "-i", ref_l, "-v", NULL};
    listener = spawn_cp(python, &lfd, ref_listen);
    memset(listen_out, 0, sizeof(listen_out));
    read_until(lfd, "rnsh listening for commands on <", listen_out,
               sizeof(listen_out), 60);
    read_until(lfd, ">", listen_out, sizeof(listen_out), 5);
    parse_after(listen_out, "rnsh listening for commands on <", dest);
    /* the reference listener's pipe mode fails in this setup, so the client
     * runs on a terminal and the command gets a pty on both sides */
    {
      char *args[] = {(char *)sh, "--connect", connect, "--identity", idl, "-w",
                      "30", dest, "--", "echo", "hi-from-ref-listener", NULL};
      CHECK(run_in_pty(sh, out, sizeof(out), args, NULL) == 0 &&
            strstr(out, "hi-from-ref-listener"));
    }
    stop_cp(listener, lfd);
  }
  /* the reference initiator, on a terminal, connects to ours */
  {
    char *our_listen[] = {(char *)sh, "--connect", connect, "--identity", idl,
                          "-l", "-a", hash_ref, "-b", "0", NULL};
    char *ref_run[] = {(char *)python, "-m", "RNS.Utilities.rnsh.rnsh",
                       "--config", shcfg, "--rnsconfig", refcfg, "-i", ref_c,
                       "-w", "30", "-m", dest, "--", "sh", "-c",
                       "echo from-ours; exit 6", NULL};
    listener = spawn_cp(sh, &lfd, our_listen);
    memset(listen_out, 0, sizeof(listen_out));
    read_until(lfd, ">\n", listen_out, sizeof(listen_out), 10);
    parse_after(listen_out, "rnsh listening for commands on <", dest);
    CHECK(run_in_pty(python, out, sizeof(out), ref_run, NULL) == 6);
    CHECK(strstr(out, "from-ours"));
    stop_cp(listener, lfd);
  }
  stop(daemon, dfd);
  remove_tree(dir);
  puts("sh reference tests passed");
}

/* An interface that cannot be opened is skipped (the reference's default) and
 * the rest keep working; panic_on_interface_error makes it fatal. */
static void panic_on_interface(const char *exe) {
  char dir[] = "/tmp/rnc-node-panic-XXXXXX", cfg[256], key[256], admin[256],
       text[2048], identity[33], reply[4096];
  struct sockaddr_in addr;
  socklen_t size = sizeof(addr);
  int hold = socket(AF_INET, SOCK_STREAM, 0), fd, status = 0;
  unsigned busy, tries;
  pid_t p;
  CHECK(hold >= 0 && mkdtemp(dir));
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(!bind(hold, (struct sockaddr *)&addr, sizeof(addr)) &&
        !listen(hold, 4) && !getsockname(hold, (struct sockaddr *)&addr, &size));
  busy = ntohs(addr.sin_port);
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = Yes\nshare_instance = No\n"
                 "[interfaces]\n[[Busy]]\ntype = TCPServerInterface\n"
                 "listen_ip = 127.0.0.1\nlisten_port = %u\n[[Fine]]\n"
                 "type = TCPServerInterface\nlisten_ip = 127.0.0.1\n"
                 "listen_port = 0\n",
                 busy) > 0);
  config_file(cfg, text);
  p = start(exe, cfg, key, admin, &fd);
  ready_line(fd, identity);
  admin_command(admin, "STATUS", reply, sizeof(reply));
  CHECK(strstr(reply, "interface id="));
  stop(p, fd);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = Yes\nshare_instance = No\n"
                 "panic_on_interface_error = Yes\n[interfaces]\n[[Busy]]\n"
                 "type = TCPServerInterface\nlisten_ip = 127.0.0.1\n"
                 "listen_port = %u\n",
                 busy) > 0);
  config_file(cfg, text);
  p = start(exe, cfg, key, admin, &fd);
  for (tries = 0; tries < 100; ++tries) {
    struct timespec t = {0, 100000000};
    if (waitpid(p, &status, WNOHANG) == p)
      break;
    nanosleep(&t, NULL);
  }
  CHECK(tries < 100 && WIFEXITED(status) && WEXITSTATUS(status) != 0);
  close(fd);
  close(hold);
  remove_tree(dir);
  puts("node panic tests passed");
}
/* TCP interfaces take 4096 byte packets unless configured otherwise (the
 * reference sizes them from their bitrate, far above 500), so links across
 * them can use large packets; other kinds keep 500. */
static void interface_mtu(const char *exe) {
  char dir[] = "/tmp/rnc-node-mtu-XXXXXX", cfg[256], key[256], admin[256],
       text[2048], identity[33], reply[4096];
  int fd;
  pid_t p;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = Yes\nshare_instance = No\n"
                 "[interfaces]\n[[Default]]\ntype = TCPServerInterface\n"
                 "listen_ip = 127.0.0.1\nlisten_port = 0\n[[Small]]\n"
                 "type = TCPServerInterface\nlisten_ip = 127.0.0.1\n"
                 "listen_port = 0\nmtu = 1196\n[[Datagram]]\ntype = UDPInterface\n"
                 "listen_ip = 127.0.0.1\nlisten_port = 0\nforward_ip = "
                 "127.0.0.1\nforward_port = 9\n") > 0);
  config_file(cfg, text);
  p = start(exe, cfg, key, admin, &fd);
  ready_line(fd, identity);
  admin_command(admin, "STATUS", reply, sizeof(reply));
  CHECK(strstr(reply, "mtu=4096"));
  CHECK(strstr(reply, "mtu=1196"));
  CHECK(strstr(reply, "mtu=500"));
  stop(p, fd);
  remove_tree(dir);
  puts("node interface MTU tests passed");
}
/* The I2PInterface section against a fake SAM router: the key file is named
 * as the reference names it (the old name wins when such a file exists), the
 * address comes up in STATUS, and each peer gets a dialler. */
/* This test twice timed out at 60 s on CI (sanitizer job only, never reproduced locally in 200 runs, where it takes
 * 0.4 s) without printing anything. The watchdog turns the next occurrence into a message: after 45 s it says
 * which step it was in, kills the two processes the test started, and fails. */
static volatile const char *i2p_stage = "starting";
static volatile pid_t i2p_router_pid, i2p_daemon_pid;
static void i2p_stuck(int sig) {
  static const char head[] = "node I2P test stuck at: ";
  const char *stage = (const char *)i2p_stage;
  size_t n = 0;
  (void)sig;
  while (stage[n])
    ++n;
  (void)!write(2, head, sizeof(head) - 1);
  (void)!write(2, stage, n);
  (void)!write(2, "\n", 1);
  if (i2p_daemon_pid > 0)
    kill(i2p_daemon_pid, SIGKILL);
  if (i2p_router_pid > 0)
    kill(i2p_router_pid, SIGKILL);
  _exit(2);
}
static pid_t start_fake_sam(const char *fake, const char *log, unsigned *port) {
  int fds[2];
  pid_t p;
  char text[16];
  ssize_t got;
  CHECK(!pipe(fds));
  p = fork();
  CHECK(p >= 0);
  if (!p) {
    close(fds[0]);
    CHECK(dup2(fds[1], STDOUT_FILENO) >= 0);
    close(fds[1]);
    execl(fake, fake, log, (char *)NULL);
    _exit(127);
  }
  close(fds[1]);
  i2p_router_pid = p; /* known to the watchdog before the blocking read below */
  got = read(fds[0], text, sizeof(text) - 1);
  CHECK(got > 0);
  text[got] = 0;
  *port = (unsigned)atoi(text);
  close(fds[0]);
  return p;
}
static unsigned count_of(const char *haystack, const char *needle) {
  unsigned n = 0;
  const char *p = haystack;
  while ((p = strstr(p, needle)) != NULL) {
    ++n;
    p += strlen(needle);
  }
  return n;
}
static void i2p_daemon(const char *exe, const char *fake) {
  char dir[] = "/tmp/rnc-node-i2p-XXXXXX", cfg[256], key[256], admin[256],
       state[256], keydir[300], text[2048], identity[33], reply[4096],
       log[300], path[400], hex[65];
  uint8_t name_hash[32], once[32], tail[32], both[64], digest[32],
      id_bytes[16];
  unsigned port, tries, i;
  struct stat sb;
  FILE *f;
  int fd;
  pid_t p, router;
  signal(SIGALRM, i2p_stuck);
  alarm(45);
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(state, sizeof(state), "%s/state", dir) > 0);
  CHECK(snprintf(keydir, sizeof(keydir), "%s.i2p", state) > 0);
  CHECK(snprintf(log, sizeof(log), "%s/sam.log", dir) > 0);
  i2p_stage = "starting the fake SAM router (waiting for its port)";
  router = start_fake_sam(fake, log, &port);
  /* the old-format name, SHA256(SHA256(name)), already holds a key */
  SHA256((const unsigned char *)"I2P", 3, name_hash);
  SHA256(name_hash, 32, once);
  hex_of(once, 32, hex);
  CHECK(mkdir(keydir, 0700) == 0);
  CHECK(snprintf(path, sizeof(path), "%s/%s.i2p", keydir, hex) > 0);
  f = fopen(path, "w");
  CHECK(f && fputs(V0_PRIV, f) >= 0 && !fclose(f));
  CHECK(snprintf(text, sizeof(text),
                 "[reticulum]\nenable_transport = Yes\nshare_instance = No\n"
                 "[interfaces]\n[[I2P]]\ntype = I2PInterface\n"
                 "target_host = 127.0.0.1\ntarget_port = %u\n"
                 "connectable = yes\npeers = %.52s.b32.i2p, %.52s.b32.i2p\n",
                 port,
                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") > 0);
  config_file(cfg, text);
  i2p_stage = "starting the daemon (waiting for its Ready line)";
  p = start_with_state(exe, cfg, key, admin, state, &fd);
  i2p_daemon_pid = p;
  ready_line(fd, identity);
  i2p_stage = "waiting for the I2P address in STATUS";
  for (tries = 0; tries < 100; ++tries) {
    struct timespec t = {0, 100000000};
    admin_command(admin, "STATUS", reply, sizeof(reply));
    if (strstr(reply, "i2p=" V0_B32))
      break;
    nanosleep(&t, NULL);
  }
  CHECK(tries < 100);
  /* the controller and one dialler per peer; the idle acceptor is not a peer */
  CHECK(count_of(reply, "interface id=") == 3);
  /* the stored key was used, and no key of the new name appeared */
  CHECK(count_of(reply, "online=1") >= 1);
  for (i = 0; i < 16; ++i) {
    unsigned v;
    CHECK(sscanf(identity + 2 * i, "%2x", &v) == 1);
    id_bytes[i] = (uint8_t)v;
  }
  SHA256(id_bytes, 16, tail);
  memcpy(both, name_hash, 32);
  memcpy(both + 32, tail, 32);
  SHA256(both, 64, digest);
  hex_of(digest, 32, hex);
  CHECK(snprintf(path, sizeof(path), "%s/%s.i2p", keydir, hex) > 0);
  CHECK(stat(path, &sb) != 0);
  i2p_stage = "stopping the first daemon";
  stop(p, fd);
  i2p_daemon_pid = 0;
  /* with no stored key, one is generated under the new name */
  {
    DIR *d;
    struct dirent *e;
    d = opendir(keydir);
    CHECK(d);
    while ((e = readdir(d)) != NULL) {
      if (e->d_name[0] != '.') {
        char victim[400];
        CHECK(snprintf(victim, sizeof(victim), "%s/%s", keydir, e->d_name) > 0);
        CHECK(unlink(victim) == 0);
      }
    }
    closedir(d);
  }
  i2p_stage = "restarting the daemon (waiting for its Ready line)";
  p = start_with_state(exe, cfg, key, admin, state, &fd);
  i2p_daemon_pid = p;
  ready_line(fd, identity);
  i2p_stage = "waiting for the new key file";
  hex_of(digest, 32, hex);
  CHECK(snprintf(path, sizeof(path), "%s/%s.i2p", keydir, hex) > 0);
  for (tries = 0; tries < 100 && stat(path, &sb) != 0; ++tries) {
    struct timespec t = {0, 100000000};
    nanosleep(&t, NULL);
  }
  CHECK(tries < 100 && (sb.st_mode & 077) == 0);
  i2p_stage = "stopping the second daemon";
  stop(p, fd);
  i2p_daemon_pid = 0;
  alarm(0);
  kill(router, SIGKILL);
  waitpid(router, NULL, 0);
  remove_tree(dir);
  puts("node I2P interface tests passed");
}

static void make_dirs(const char *path) {
  char part[400];
  size_t i;
  CHECK(strlen(path) < sizeof(part));
  for (i = 1; path[i]; ++i)
    if (path[i] == '/') {
      memcpy(part, path, i);
      part[i] = 0;
      (void)mkdir(part, 0700);
    }
  (void)mkdir(path, 0700);
}
/* One direction of I2P interop with the unmodified reference, both ends
 * talking through the fake SAM router: the reference announces a destination
 * and our daemon must learn the path across the I2P stream. */
static void i2p_reference_run(const char *exe, const char *fake,
                              const char *reference, const char *python,
                              int reference_dials) {
  char dir[] = "/tmp/rnc-i2p-ref-XXXXXX", rdir[256], rcfg[256], cfg[256],
       key[256], admin[256], state[256], keydir[300], text[2048], id[33],
       hash[33], log[300], path[500], hex[65], out[256], addr[64];
  uint8_t name_hash[32], once[32];
  unsigned port, waited;
  int fd, pfd, fds[2];
  pid_t daemon, router, peer;
  size_t n = 0;
  FILE *f;
  CHECK(mkdtemp(dir));
  CHECK(snprintf(rdir, sizeof(rdir), "%s/ref", dir) > 0);
  CHECK(!mkdir(rdir, 0700));
  CHECK(snprintf(rcfg, sizeof(rcfg), "%s/config", rdir) > 0);
  CHECK(snprintf(cfg, sizeof(cfg), "%s/config", dir) > 0);
  CHECK(snprintf(key, sizeof(key), "%s/identity", dir) > 0);
  CHECK(snprintf(admin, sizeof(admin), "%s/admin", dir) > 0);
  CHECK(snprintf(state, sizeof(state), "%s/state", dir) > 0);
  CHECK(snprintf(keydir, sizeof(keydir), "%s.i2p", state) > 0);
  CHECK(snprintf(log, sizeof(log), "%s/sam.log", dir) > 0);
  router = start_fake_sam(fake, log, &port);
  SHA256((const unsigned char *)"I2P", 3, name_hash);
  SHA256(name_hash, 32, once);
  hex_of(once, 32, hex);
  CHECK(mkdir(keydir, 0700) == 0);
  if (reference_dials) {
    /* our node is connectable under a key whose address is known */
    CHECK(snprintf(path, sizeof(path), "%s/%s.i2p", keydir, hex) > 0);
    f = fopen(path, "w");
    CHECK(f && fputs(V0_PRIV, f) >= 0 && !fclose(f));
    snprintf(addr, sizeof(addr), "%s", V0_B32);
    CHECK(snprintf(text, sizeof(text),
                   "[reticulum]\nenable_transport = Yes\nshare_instance = "
                   "No\n[interfaces]\n[[I2P]]\ntype = I2PInterface\n"
                   "target_host = 127.0.0.1\ntarget_port = %u\n"
                   "connectable = yes\n",
                   port) > 0);
    config_file(cfg, text);
    write_config(rcfg,
                 "[reticulum]\nenable_transport = No\nshare_instance = No\n"
                 "[interfaces]\n[[I2P]]\ntype = I2PInterface\nenabled = yes\n"
                 "peers = %s.b32.i2p\n",
                 addr);
  } else {
    char rstore[400];
    CHECK(snprintf(rstore, sizeof(rstore), "%s/storage/i2p", rdir) > 0);
    make_dirs(rstore);
    CHECK(snprintf(path, sizeof(path), "%s/%s.i2p", rstore, hex) > 0);
    f = fopen(path, "w");
    CHECK(f && fputs(V1_PRIV, f) >= 0 && !fclose(f));
    snprintf(addr, sizeof(addr), "%s", V1_B32);
    CHECK(snprintf(text, sizeof(text),
                   "[reticulum]\nenable_transport = Yes\nshare_instance = "
                   "No\n[interfaces]\n[[I2P]]\ntype = I2PInterface\n"
                   "target_host = 127.0.0.1\ntarget_port = %u\n"
                   "peers = %s.b32.i2p\n",
                   port, addr) > 0);
    config_file(cfg, text);
    write_config(rcfg,
                 "[reticulum]\nenable_transport = No\nshare_instance = No\n"
                 "[interfaces]\n[[I2P]]\ntype = I2PInterface\nenabled = yes\n"
                 "connectable = yes\n");
  }
  daemon = start_with_state(exe, cfg, key, admin, state, &fd);
  ready_line(fd, id);
  CHECK(!pipe(fds));
  peer = fork();
  CHECK(peer >= 0);
  if (!peer) {
    char sam[32];
    close(fds[0]);
    CHECK(dup2(fds[1], STDOUT_FILENO) >= 0 && dup2(fds[1], STDERR_FILENO) >= 0);
    close(fds[1]);
    CHECK(snprintf(sam, sizeof(sam), "127.0.0.1:%u", port) > 0);
    CHECK(!setenv("PYTHONPATH", reference, 1));
    CHECK(!setenv("I2P_SAM_ADDRESS", sam, 1));
    execl(python, python, "-c", reference_tunnel_peer, rdir, "announce", "150",
          (char *)NULL);
    _exit(127);
  }
  close(fds[1]);
  pfd = fds[0];
  hash[0] = out[0] = 0;
  for (waited = 0; waited < 900 && !hash[0]; ++waited) {
    struct pollfd pf = {pfd, POLLIN, 0};
    size_t at;
    CHECK(poll(&pf, 1, 100) >= 0);
    if (pf.revents & POLLIN) {
      ssize_t got = read(pfd, out + n, sizeof(out) - 1 - n);
      if (got <= 0)
        break;
      n += (size_t)got;
      out[n] = 0;
    }
    for (at = 0; at + 32 <= n && !hash[0]; ++at) {
      size_t k;
      if (at && out[at - 1] != '\n')
        continue;
      for (k = 0; k < 32 && strchr("0123456789abcdef", out[at + k]); ++k) {
      }
      if (k == 32 && (at + 32 == n || out[at + 32] == '\n')) {
        memcpy(hash, out + at, 32);
        hash[32] = 0;
      }
    }
    if (n > sizeof(out) - 64)
      n = 0;
  }
  CHECK(hash[0]);
  if (!path_within(admin, hash, 120)) {
    char reply[4096];
    admin_command(admin, "STATUS", reply, sizeof(reply));
    fprintf(stderr, "no path; status:\n%s\n", reply);
    CHECK(0);
  }
  (void)kill(peer, SIGKILL);
  CHECK(waitpid(peer, NULL, 0) == peer);
  close(pfd);
  stop(daemon, fd);
  kill(router, SIGKILL);
  waitpid(router, NULL, 0);
  remove_tree(dir);
}
static void i2p_reference(const char *exe, const char *fake,
                          const char *reference, const char *python) {
  i2p_reference_run(exe, fake, reference, python, 1);
  i2p_reference_run(exe, fake, reference, python, 0);
  puts("node I2P interface reference tests passed");
}

int main(int argc, char **argv) {
  CHECK(argc == 3 || argc == 4 || argc == 5 || argc == 6);
  if (!strcmp(argv[2], "i2p") && argc == 4)
    i2p_daemon(argv[1], argv[3]);
  else if (!strcmp(argv[2], "i2p_ref") && argc == 6)
    i2p_reference(argv[1], argv[3], argv[4], argv[5]);
  else if (!strcmp(argv[2], "cli"))
    cli(argv[1]);
  else if (!strcmp(argv[2], "network"))
    network(argv[1]);

  else if (!strcmp(argv[2], "sh_ref") && argc == 6)
    sh_reference(argv[1], argv[3], argv[5]);
  else if (!strcmp(argv[2], "x_ref") && argc == 6)
    x_reference(argv[1], argv[3], argv[5]);
  else if (!strcmp(argv[2], "mtu") && argc == 3)
    interface_mtu(argv[1]);
  else if (!strcmp(argv[2], "panic") && argc == 3)
    panic_on_interface(argv[1]);
  else if (!strcmp(argv[2], "sh_tools") && argc == 4)
    sh_tools(argv[1], argv[3]);
  else if (!strcmp(argv[2], "ctl_remote") && argc == 4)
    ctl_remote_test(argv[1], argv[3]);
  else if (!strcmp(argv[2], "examples") && argc == 6)
    examples_test(argv[1], argv[3], argv[4], argv[5]);
  else if (!strcmp(argv[2], "x_tools") && argc == 4)
    x_tools(argv[1], argv[3]);
  else if (!strcmp(argv[2], "cp_ref") && argc == 6)
    cp_reference(argv[1], argv[3], argv[5]);
  else if (!strcmp(argv[2], "cp_tools") && argc == 4)
    cp_tools(argv[1], argv[3]);
  else if (!strcmp(argv[2], "cli_id_ref") && argc == 5)
    cli_id_reference(argv[1], argv[3], argv[4]);
  else if (!strcmp(argv[2], "cli_tools") && argc == 4)
    cli_tools(argv[1], argv[3]);

  else if (!strcmp(argv[2], "tunnel_persist") && argc == 3)
    tunnel_persistence(argv[1]);

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
  else if (!strcmp(argv[2], "live_ref") && argc == 5)
    live_reference(argv[1], argv[3], argv[4]);
  else if (!strcmp(argv[2], "disc_list") && argc == 4)
    status_discovered(argv[3], NULL, NULL);
  else if (!strcmp(argv[2], "disc_list_ref") && argc == 6)
    status_discovered(argv[3], argv[4], argv[5]);
  else if (!strcmp(argv[2], "echo_ref") && argc == 6)
    echo_reference(argv[1], argv[3], argv[4], argv[5]);
  else if (!strcmp(argv[2], "rnid_announce_ref") && argc == 6)
    rnid_announce_reference(argv[1], argv[3], argv[4], argv[5]);
  else if (!strcmp(argv[2], "cp_big") && argc == 4)
    cp_big(argv[1], argv[3]);
  else if (!strcmp(argv[2], "shared_unix") && argc == 4)
    shared_unix(argv[1], argv[3], NULL, NULL);
  else if (!strcmp(argv[2], "shared_unix_ref") && argc == 6)
    shared_unix(argv[1], argv[3], argv[4], argv[5]);
  else if (!strcmp(argv[2], "netid_ref") && argc == 5)
    network_identity_reference(argv[1], argv[3], argv[4]);
  else if (!strcmp(argv[2], "tunnel_ref") && argc == 5)
    tunnel_reference(argv[1], argv[3], argv[4]);
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
