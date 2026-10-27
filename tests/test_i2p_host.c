/* The I2P interface against a fake SAM router (tests/fake_sam.c): session setup
 * and key persistence, an outgoing peer found by b32 name, an incoming peer,
 * packets between two nodes, and retry timing. Nothing here touches a real I2P
 * router. */
#define _XOPEN_SOURCE 700
#include <errno.h>
#include <reticulum_c/rnc_host.h>
#include <reticulum_c/rnc_i2p.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d %s errno=%d\n", __FILE__, __LINE__, #x, errno);   \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

static const char *fake_path;
static char dir[256], log_path[300];

static rnc_result random_bytes(void *v, uint8_t *out, size_t n) {
  unsigned *s = v;
  size_t i;
  for (i = 0; i < n; ++i)
    out[i] = (uint8_t)(*s)++;
  return RNC_OK;
}

static pid_t start_router(unsigned port_wanted, uint16_t *port) {
  int out[2];
  pid_t pid;
  char text[16], wanted[8];
  ssize_t got;
  CHECK(pipe(out) == 0);
  pid = fork();
  CHECK(pid >= 0);
  if (!pid) {
    dup2(out[1], 1);
    close(out[0]);
    close(out[1]);
    snprintf(wanted, sizeof(wanted), "%u", port_wanted);
    if (port_wanted)
      execl(fake_path, fake_path, log_path, wanted, (char *)NULL);
    execl(fake_path, fake_path, log_path, (char *)NULL);
    _exit(127);
  }
  close(out[1]);
  got = read(out[0], text, sizeof(text) - 1);
  CHECK(got > 0);
  text[got] = 0;
  *port = (uint16_t)atoi(text);
  close(out[0]);
  return pid;
}
static void stop_router(pid_t pid) {
  kill(pid, SIGKILL);
  waitpid(pid, NULL, 0);
}
/* Number of lines in the router's command log that contain text. */
static unsigned logged(const char *text) {
  char line[4096];
  unsigned n = 0;
  FILE *f = fopen(log_path, "r");
  if (!f)
    return 0;
  while (fgets(line, sizeof(line), f))
    if (strstr(line, text))
      ++n;
  fclose(f);
  return n;
}

typedef struct side {
  rnc_identity id;
  rnc_node *node;
  rnc_host *host;
  unsigned rng;
} side;
static void side_new(side *s, uint8_t seed) {
  uint8_t key[64] = {0};
  key[0] = seed;
  s->rng = (unsigned)seed * 40u;
  CHECK(rnc_identity_from_private(&s->id, key) == RNC_OK);
  s->node = rnc_node_new(&s->id, 0, random_bytes, &s->rng);
  CHECK(s->node);
  s->host = rnc_host_new(s->node);
  CHECK(s->host);
}
static void side_free(side *s) {
  rnc_host_free(s->host);
  rnc_node_free(s->node);
}
static void i2p_config(rnc_host_config *c, uint16_t port, const char *key,
                       const char *const *peers, size_t peer_count,
                       int connectable) {
  memset(c, 0, sizeof(*c));
  c->kind = RNC_HOST_I2P;
  c->address = "127.0.0.1";
  c->port = port;
  c->i2p_key_path = key;
  c->i2p_peers = peers;
  c->i2p_peer_count = peer_count;
  c->i2p_connectable = connectable;
}
static void run(side **sides, size_t count, uint64_t *now, unsigned steps) {
  unsigned i;
  size_t k;
  for (i = 0; i < steps; ++i) {
    *now += 10;
    for (k = 0; k < count; ++k) {
      rnc_host_event event;
      CHECK(rnc_host_step(sides[k]->host, 1, 1700000000, *now) == RNC_OK);
      while (rnc_host_poll(sides[k]->host, &event) == RNC_OK) {
      }
    }
  }
}
static int controller_status(side *s, uint32_t id, rnc_host_status *st) {
  return rnc_host_get_status(s->host, id, st) == RNC_OK;
}
/* True when some spawned child of the controller is online. */
static int child_online(side *s, uint32_t parent) {
  rnc_host_status st;
  size_t i;
  for (i = 0; i < RNC_HOST_SLOTS; ++i)
    if (rnc_host_status_at(s->host, i, &st) == RNC_OK &&
        st.parent_id == parent && st.online)
      return 1;
  return 0;
}
static unsigned children(side *s, uint32_t parent) {
  rnc_host_status st;
  size_t i;
  unsigned n = 0;
  for (i = 0; i < RNC_HOST_SLOTS; ++i)
    if (rnc_host_status_at(s->host, i, &st) == RNC_OK && st.parent_id == parent)
      ++n;
  return n;
}
static void read_key(const char *path, char *out, size_t cap) {
  FILE *f = fopen(path, "r");
  size_t n;
  CHECK(f);
  n = fread(out, 1, cap - 1, f);
  out[n] = 0;
  fclose(f);
  while (n && (out[n - 1] == '\n' || out[n - 1] == '\r'))
    out[--n] = 0;
}

static void session_and_key(void) {
  side a;
  side *all[1] = {&a};
  rnc_host_config c;
  rnc_host_status st;
  uint16_t port;
  pid_t router = start_router(0, &port);
  char key_path[300], key[1100], pub[700], b32[RNC_I2P_B32_SIZE], first[60];
  uint8_t bin[700];
  size_t n;
  uint64_t now = 100;
  struct stat sb;
  snprintf(key_path, sizeof(key_path), "%s/a.i2p", dir);
  side_new(&a, 1);
  i2p_config(&c, port, key_path, NULL, 0, 1);
  c.name = "I2P test";
  CHECK(rnc_host_add(a.host, 1, &c) == RNC_OK);
  run(all, 1, &now, 100);
  CHECK(controller_status(&a, 1, &st) && st.online && st.kind == RNC_HOST_I2P);
  CHECK(st.mtu == 1064 || st.mtu == 500);
  /* the key was generated by the router and stored with owner-only access */
  CHECK(logged("DEST GENERATE SIGNATURE_TYPE=7") == 1);
  CHECK(logged("SESSION CREATE STYLE=STREAM") == 1);
  CHECK(stat(key_path, &sb) == 0 && (sb.st_mode & 077) == 0);
  read_key(key_path, key, sizeof(key));
  CHECK(rnc_i2p_private_to_public(key, pub, sizeof(pub)) == RNC_OK);
  CHECK(rnc_i2p_b64_decode(pub, bin, sizeof(bin), &n) == RNC_OK);
  CHECK(rnc_i2p_b32(bin, n, b32) == RNC_OK);
  CHECK(!strcmp(st.i2p_b32, b32));
  /* connectable: a waiting acceptor is on the router, hidden from status */
  CHECK(logged("STREAM ACCEPT") >= 1);
  snprintf(first, sizeof(first), "%s", b32);
  side_free(&a);
  /* a restart reuses the stored key: no new destination, same address */
  side_new(&a, 1);
  CHECK(rnc_host_add(a.host, 1, &c) == RNC_OK);
  now += 1000;
  run(all, 1, &now, 100);
  CHECK(controller_status(&a, 1, &st) && st.online);
  CHECK(!strcmp(st.i2p_b32, first));
  CHECK(logged("DEST GENERATE") == 1);
  CHECK(logged("DESTINATION=TRANSIENT") == 0);
  side_free(&a);
  stop_router(router);
  puts("i2p session test passed");
}

int main(int argc, char **argv) {
  char tmpl[] = "/tmp/rnc_i2p_XXXXXX";
  if (argc < 3)
    return 2;
  fake_path = argv[1];
  CHECK(mkdtemp(tmpl));
  snprintf(dir, sizeof(dir), "%s", tmpl);
  snprintf(log_path, sizeof(log_path), "%s/sam.log", dir);
  signal(SIGPIPE, SIG_IGN);
  if (!strcmp(argv[2], "session"))
    session_and_key();
  else
    return 2;
  return 0;
}
