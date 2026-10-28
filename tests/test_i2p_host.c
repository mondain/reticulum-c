/* The I2P interface against a fake SAM router (tests/fake_sam.c): session setup
 * and key persistence, an outgoing peer found by b32 name, an incoming peer,
 * packets between two nodes, and retry timing. Nothing here touches a real I2P
 * router. */
#define _XOPEN_SOURCE 700
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
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

static pid_t routers[8];
static void kill_routers(void) {
  size_t i;
  for (i = 0; i < sizeof(routers) / sizeof(*routers); ++i)
    if (routers[i] > 0) {
      kill(routers[i], SIGKILL);
      waitpid(routers[i], NULL, 0);
      routers[i] = 0;
    }
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
  {
    size_t i;
    for (i = 0; i < sizeof(routers) / sizeof(*routers); ++i)
      if (routers[i] <= 0) {
        routers[i] = pid;
        break;
      }
  }
  return pid;
}
static void stop_router(pid_t pid) {
  size_t i;
  kill(pid, SIGKILL);
  waitpid(pid, NULL, 0);
  for (i = 0; i < sizeof(routers) / sizeof(*routers); ++i)
    if (routers[i] == pid)
      routers[i] = 0;
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

/* Steps until fn is true; fails the test after max steps. */
typedef int (*until_fn)(void *);
static void until(side **sides, size_t count, uint64_t *now, unsigned max,
                  until_fn fn, void *arg) {
  unsigned i;
  for (i = 0; i < max; ++i) {
    run(sides, count, now, 1);
    if (fn(arg))
      return;
  }
  CHECK(!"condition not reached");
}
static int announced(side *from, side *to, const char *name, side **all,
                     size_t count, uint64_t *now) {
  uint8_t dest[16];
  rnc_route route;
  unsigned i;
  CHECK(rnc_node_add_destination(from->node, &from->id, name, NULL, 0, dest) ==
        RNC_OK);
  run(all, count, now, 5);
  CHECK(rnc_node_announce(from->node, dest, 1700000000, *now) == RNC_OK);
  for (i = 0; i < 3000; ++i) {
    run(all, count, now, 1);
    if (rnc_node_lookup(to->node, dest, *now, &route) == RNC_OK)
      return 1;
  }
  return 0;
}
typedef struct online_ctx {
  side *s;
  uint32_t parent;
  int want;
} online_ctx;
static int is_child_online(void *v) {
  online_ctx *c = v;
  return child_online(c->s, c->parent) == c->want;
}
static int is_online(void *v) {
  online_ctx *c = v;
  rnc_host_status st;
  return rnc_host_get_status(c->s->host, c->parent, &st) == RNC_OK &&
         st.online == c->want;
}
static void key_path_for(const char *name, char *out, size_t cap) {
  snprintf(out, cap, "%s/%s.i2p", dir, name);
}

static void peers(void) {
  side a, b;
  side *all[2] = {&a, &b};
  rnc_host_config c;
  rnc_host_status st, ps;
  uint16_t port;
  pid_t router = start_router(0, &port);
  char ak[300], bk[300], name[80];
  const char *list[1];
  uint64_t now = 100;
  online_ctx ca = {&a, 1, 1}, cb = {&b, 2, 1};
  size_t i;
  key_path_for("pa", ak, sizeof(ak));
  key_path_for("pb", bk, sizeof(bk));
  side_new(&a, 1);
  side_new(&b, 2);
  i2p_config(&c, port, ak, NULL, 0, 1);
  CHECK(rnc_host_add(a.host, 1, &c) == RNC_OK);
  until(all, 2, &now, 500, is_online, &ca);
  CHECK(rnc_host_get_status(a.host, 1, &st) == RNC_OK);
  snprintf(name, sizeof(name), "%s.b32.i2p", st.i2p_b32);
  list[0] = name;
  i2p_config(&c, port, bk, list, 1, 0);
  CHECK(rnc_host_add(b.host, 2, &c) == RNC_OK);
  cb.want = 1;
  until(all, 2, &now, 1000, is_child_online, &cb);
  ca.parent = 1;
  until(all, 2, &now, 1000, is_child_online, &ca);
  /* names resolved through the router, then a stream to the destination */
  CHECK(logged("NAMING LOOKUP NAME=") == 1);
  CHECK(logged("STREAM CONNECT ID=rnc00000002 DESTINATION=") == 1);
  /* the acceptor that took the call was replaced by a fresh one */
  run(all, 2, &now, 50);
  CHECK(logged("STREAM ACCEPT ID=rnc00000001") >= 2);
  CHECK(children(&a, 1) == 1 && children(&b, 2) == 1);
  /* both children carry the I2P peer MTU and identify their parent */
  for (i = 0; i < RNC_HOST_SLOTS; ++i)
    if (rnc_host_status_at(a.host, i, &ps) == RNC_OK && ps.parent_id == 1) {
      CHECK(ps.mtu == 1064 && ps.online && ps.kind == RNC_HOST_TCP_CONNECT);
      CHECK(strstr(ps.name, "Connected peer on"));
    }
  /* packets cross in both directions */
  CHECK(announced(&b, &a, "reticulum_c.i2p.test.b", all, 2, &now));
  CHECK(announced(&a, &b, "reticulum_c.i2p.test.a", all, 2, &now));
  /* only B dials */
  CHECK(logged("STREAM CONNECT") == 1);
  side_free(&b);
  side_free(&a);
  stop_router(router);
  puts("i2p peers test passed");
}

/* A bare 52 character b32 address and a full base64 destination both work;
 * the destination needs no lookup. */
static void peer_forms(void) {
  side a, b, d;
  side *all[3] = {&a, &b, &d};
  rnc_host_config c;
  rnc_host_status st;
  uint16_t port;
  pid_t router = start_router(0, &port);
  char ak[300], bk[300], dk[300], pub[700];
  const char *bare[1], *full[1];
  uint64_t now = 100;
  online_ctx ca = {&a, 1, 1}, cb = {&b, 2, 1}, cd = {&d, 3, 1};
  key_path_for("fa", ak, sizeof(ak));
  key_path_for("fb", bk, sizeof(bk));
  key_path_for("fd", dk, sizeof(dk));
  side_new(&a, 1);
  side_new(&b, 2);
  side_new(&d, 3);
  i2p_config(&c, port, ak, NULL, 0, 1);
  CHECK(rnc_host_add(a.host, 1, &c) == RNC_OK);
  until(all, 3, &now, 500, is_online, &ca);
  CHECK(rnc_host_get_status(a.host, 1, &st) == RNC_OK);
  {
    char key[1100];
    read_key(ak, key, sizeof(key));
    CHECK(rnc_i2p_private_to_public(key, pub, sizeof(pub)) == RNC_OK);
  }
  bare[0] = st.i2p_b32;
  CHECK(strlen(bare[0]) == 52);
  i2p_config(&c, port, bk, bare, 1, 0);
  CHECK(rnc_host_add(b.host, 2, &c) == RNC_OK);
  cb.parent = 2;
  until(all, 3, &now, 1000, is_child_online, &cb);
  run(all, 3, &now, 50); /* A's next acceptor is waiting at the router */
  CHECK(logged("NAMING LOOKUP NAME=") == 1);
  CHECK(logged(".b32.i2p.b32.i2p") == 0);
  full[0] = pub;
  i2p_config(&c, port, dk, full, 1, 0);
  CHECK(rnc_host_add(d.host, 3, &c) == RNC_OK);
  cd.parent = 3;
  until(all, 3, &now, 1000, is_child_online, &cd);
  CHECK(logged("NAMING LOOKUP NAME=") == 1); /* none for the destination */
  CHECK(logged("STREAM CONNECT") == 2);
  side_free(&d);
  side_free(&b);
  side_free(&a);
  stop_router(router);
  puts("i2p peer forms test passed");
}

/* A peer that cannot be found is retried after the reference's 15 s. */
static void retry(void) {
  side a, b;
  side *all[2] = {&a, &b};
  rnc_host_config c;
  rnc_host_status st;
  uint16_t port;
  pid_t router = start_router(0, &port);
  char ak[300], bk[300], name[80];
  const char *list[1];
  uint64_t now = 100, failed_at;
  online_ctx ca = {&a, 1, 1}, cb = {&b, 2, 1};
  unsigned lookups;
  key_path_for("ra", ak, sizeof(ak));
  key_path_for("rb", bk, sizeof(bk));
  side_new(&a, 1);
  side_new(&b, 2);
  /* B names a destination nobody has: 52 valid base32 characters */
  snprintf(name, sizeof(name),
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b32.i2p");
  list[0] = name;
  i2p_config(&c, port, bk, list, 1, 0);
  CHECK(rnc_host_add(b.host, 2, &c) == RNC_OK);
  until(all, 2, &now, 500, is_online, &cb);
  run(all, 2, &now, 100);
  CHECK(logged("NAMING LOOKUP") == 1);
  failed_at = now;
  run(all, 2, &now, 1000); /* 10 s later: still waiting */
  CHECK(now - failed_at >= 9000 && logged("NAMING LOOKUP") == 1);
  now += 6000;
  run(all, 2, &now, 100);
  lookups = logged("NAMING LOOKUP");
  CHECK(lookups == 2);
  /* once the peer exists, the next attempt reaches it */
  i2p_config(&c, port, ak, NULL, 0, 1);
  CHECK(rnc_host_add(a.host, 1, &c) == RNC_OK);
  until(all, 2, &now, 500, is_online, &ca);
  CHECK(rnc_host_get_status(a.host, 1, &st) == RNC_OK);
  side_free(&b);
  side_new(&b, 2);
  snprintf(name, sizeof(name), "%s.b32.i2p", st.i2p_b32);
  i2p_config(&c, port, bk, list, 1, 0);
  CHECK(rnc_host_add(b.host, 2, &c) == RNC_OK);
  until(all, 2, &now, 1000, is_child_online, &cb);
  side_free(&b);
  side_free(&a);
  stop_router(router);
  puts("i2p retry test passed");
}

/* The router going away takes the session and its streams with it; when it
 * returns the session is rebuilt on the same key and the peer comes back. */
static void router_restart(void) {
  side a, b;
  side *all[2] = {&a, &b};
  rnc_host_config c;
  rnc_host_status st;
  uint16_t port;
  pid_t router = start_router(0, &port);
  char ak[300], bk[300], name[80], address[64];
  const char *list[1];
  uint64_t now = 100;
  online_ctx ca = {&a, 1, 1}, cb = {&b, 2, 1};
  key_path_for("ma", ak, sizeof(ak));
  key_path_for("mb", bk, sizeof(bk));
  side_new(&a, 1);
  side_new(&b, 2);
  i2p_config(&c, port, ak, NULL, 0, 1);
  CHECK(rnc_host_add(a.host, 1, &c) == RNC_OK);
  until(all, 2, &now, 500, is_online, &ca);
  CHECK(rnc_host_get_status(a.host, 1, &st) == RNC_OK);
  snprintf(address, sizeof(address), "%s", st.i2p_b32);
  snprintf(name, sizeof(name), "%s.b32.i2p", address);
  list[0] = name;
  i2p_config(&c, port, bk, list, 1, 0);
  CHECK(rnc_host_add(b.host, 2, &c) == RNC_OK);
  until(all, 2, &now, 1000, is_child_online, &cb);
  stop_router(router);
  ca.want = 0;
  until(all, 2, &now, 500, is_online, &ca);
  cb.want = 0;
  until(all, 2, &now, 500, is_child_online, &cb);
  CHECK(rnc_host_get_status(a.host, 1, &st) == RNC_OK && !st.i2p_b32[0]);
  /* a router that is back on the same port is found at the next attempt */
  router = start_router(port, &port);
  now += 16000;
  ca.want = 1;
  until(all, 2, &now, 3000, is_online, &ca);
  CHECK(rnc_host_get_status(a.host, 1, &st) == RNC_OK &&
        !strcmp(st.i2p_b32, address));
  cb.want = 1;
  now += 16000;
  until(all, 2, &now, 3000, is_child_online, &cb);
  side_free(&b);
  side_free(&a);
  stop_router(router);
  puts("i2p router restart test passed");
}

/* A key file that is not an I2P key is reported, never replaced. */
static void bad_key(void) {
  side a;
  side *all[1] = {&a};
  rnc_host_config c;
  rnc_host_status st;
  uint16_t port;
  pid_t router = start_router(0, &port);
  char path[300], content[64] = "not a key at all";
  FILE *f;
  uint64_t now = 100;
  key_path_for("bad", path, sizeof(path));
  f = fopen(path, "w");
  CHECK(f && fputs(content, f) >= 0);
  fclose(f);
  side_new(&a, 1);
  i2p_config(&c, port, path, NULL, 0, 0);
  CHECK(rnc_host_add(a.host, 1, &c) == RNC_OK);
  run(all, 1, &now, 200);
  CHECK(rnc_host_get_status(a.host, 1, &st) == RNC_OK && !st.online);
  CHECK(logged("SESSION CREATE") == 0 && logged("DEST GENERATE") == 0);
  {
    char again[64];
    read_key(path, again, sizeof(again));
    CHECK(!strcmp(again, content));
  }
  /* invalid configuration is refused up front */
  i2p_config(&c, port, NULL, NULL, 0, 0);
  CHECK(rnc_host_add(a.host, 2, &c) == RNC_INVALID);
  i2p_config(&c, port, path, NULL, 3, 0);
  CHECK(rnc_host_add(a.host, 2, &c) == RNC_INVALID);
  side_free(&a);
  stop_router(router);
  puts("i2p bad key test passed");
}

/* No data at all for the reference's read timeout drops the stream; the
 * keepalive that arrives in time prevents it. */
static void keepalive(void) {
  side a, b;
  side *all[2] = {&a, &b};
  side *only_b[1] = {&b};
  rnc_host_config c;
  rnc_host_status st;
  uint16_t port;
  pid_t router = start_router(0, &port);
  char ak[300], bk[300], name[80];
  const char *list[1];
  uint64_t now = 100, start;
  online_ctx ca = {&a, 1, 1}, cb = {&b, 2, 1};
  unsigned i;
  key_path_for("ka", ak, sizeof(ak));
  key_path_for("kb", bk, sizeof(bk));
  side_new(&a, 1);
  side_new(&b, 2);
  i2p_config(&c, port, ak, NULL, 0, 1);
  CHECK(rnc_host_add(a.host, 1, &c) == RNC_OK);
  until(all, 2, &now, 500, is_online, &ca);
  CHECK(rnc_host_get_status(a.host, 1, &st) == RNC_OK);
  snprintf(name, sizeof(name), "%s.b32.i2p", st.i2p_b32);
  list[0] = name;
  i2p_config(&c, port, bk, list, 1, 0);
  CHECK(rnc_host_add(b.host, 2, &c) == RNC_OK);
  until(all, 2, &now, 1000, is_child_online, &cb);
  /* a minute of silence in both directions: keepalives hold the stream */
  start = now;
  for (i = 0; i < 70; ++i) {
    now += 1000;
    run(all, 2, &now, 1);
  }
  CHECK(now - start >= 70000 && child_online(&b, 2) && child_online(&a, 1));
  /* A stops answering: B hears nothing and drops the stream after 110 s */
  start = now;
  for (i = 0; i < 100 && child_online(&b, 2); ++i) {
    now += 2000;
    run(only_b, 1, &now, 1);
  }
  CHECK(!child_online(&b, 2));
  /* 110 s after B's last read, which was up to one keepalive interval before A
   * went quiet */
  CHECK(now - start >= 100000 && now - start <= 114000);
  side_free(&b);
  side_free(&a);
  stop_router(router);
  puts("i2p keepalive test passed");
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
  atexit(kill_routers);
  if (!strcmp(argv[2], "session"))
    session_and_key();
  else if (!strcmp(argv[2], "peers"))
    peers();
  else if (!strcmp(argv[2], "peer_forms"))
    peer_forms();
  else if (!strcmp(argv[2], "retry"))
    retry();
  else if (!strcmp(argv[2], "router_restart"))
    router_restart();
  else if (!strcmp(argv[2], "bad_key"))
    bad_key();
  else if (!strcmp(argv[2], "keepalive"))
    keepalive();
  else
    return 2;
  return 0;
}
