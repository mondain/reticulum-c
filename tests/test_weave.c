/* Weave: a Weave switch on a serial line, spoken to with WDCL frames inside
 * HDLC. A pty and a small emulated switch stand in for the hardware. */
#define _XOPEN_SOURCE 700
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <reticulum_c/rnc_host.h>
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

enum {
  T_DISCOVER = 0,
  T_CONNECT = 1,
  T_CMD = 2,
  T_LOG = 3,
  T_ENDPOINT_PKT = 5
};
enum {
  ET_PROTO_WDCL_CONNECTION = 0x3002,
  ET_PROTO_WDCL_HOST_ENDPOINT = 0x3003,
  ET_PROTO_WEAVE_EP_ALIVE = 0x3102,
  ET_PROTO_WEAVE_EP_VIA = 0x3104
};

static rnc_result random_bytes(void *v, uint8_t *out, size_t n) {
  unsigned *s = v;
  size_t i;
  for (i = 0; i < n; ++i)
    out[i] = (uint8_t)(*s)++;
  return RNC_OK;
}

#define SENT_MAX 16
typedef struct sent_packet {
  uint8_t endpoint[8];
  uint8_t data[RNC_MAX_MTU];
  size_t size;
} sent_packet;
typedef struct emu {
  int master;
  rnc_host_framer parser;
  rnc_identity id;
  uint8_t sw[4];       /* the switch's id: the last four bytes of its signing key */
  uint8_t host_sw[4];  /* learnt from the discovery broadcast */
  int answer;          /* answer discovery */
  int connect_ok;      /* send the connection events after a valid handshake */
  int corrupt;         /* sign the discovery reply with the wrong key */
  unsigned discovers, connects, bad_connects, short_frames;
  int connected;
  sent_packet sent[SENT_MAX];
  unsigned sent_count;
  uint8_t last_discover[16];
  size_t last_discover_size;
} emu;

static void emu_frame(emu *e, const uint8_t *dest, uint8_t type,
                      const uint8_t *body, size_t size) {
  uint8_t frame[RNC_MAX_FRAME], out[RNC_HOST_FRAME_MAX];
  size_t n;
  memcpy(frame, dest, 4);
  frame[4] = type;
  memcpy(frame + 5, body, size);
  CHECK(rnc_host_frame_encode(RNC_HOST_HDLC, 0, frame, 5 + size, out,
                              sizeof(out), &n) == RNC_OK);
  CHECK(write(e->master, out, n) == (ssize_t)n);
}
/* A log frame as the reference reads it: two bytes before the timestamp, a
 * four byte time, the level, a two byte event and its data. */
static void emu_event(emu *e, unsigned event, const uint8_t *data,
                      size_t size) {
  uint8_t body[64];
  CHECK(size + 11 < sizeof(body));
  memset(body, 0, 11);
  body[3] = 1; /* timestamp */
  body[6] = 5; /* info */
  body[7] = (uint8_t)(event >> 8);
  body[8] = (uint8_t)event;
  memcpy(body + 9, data, size);
  emu_frame(e, e->host_sw, T_LOG, body, 9 + size);
}
static void emu_alive(emu *e, const uint8_t endpoint[8]) {
  emu_event(e, ET_PROTO_WEAVE_EP_ALIVE, endpoint, 8);
}
static void emu_packet(emu *e, const uint8_t endpoint[8], const uint8_t *data,
                       size_t size) {
  uint8_t body[RNC_MAX_FRAME];
  memcpy(body, data, size);
  memcpy(body + size, endpoint, 8);
  emu_frame(e, e->host_sw, T_ENDPOINT_PKT, body, size + 8);
}
static void emu_handle(emu *e, const uint8_t *f, size_t n) {
  if (n < 5)
    return;
  if (!memcmp(f, "\xff\xff\xff\xff", 4) && f[4] == T_DISCOVER) {
    uint8_t body[96], signature[64];
    ++e->discovers;
    e->last_discover_size = n < sizeof(e->last_discover) ? n : sizeof(e->last_discover);
    memcpy(e->last_discover, f, e->last_discover_size);
    if (n != 9) {
      ++e->short_frames;
      return;
    }
    memcpy(e->host_sw, f + 5, 4);
    if (!e->answer)
      return;
    memcpy(body, e->id.public_key + 32, 32);
    CHECK(rnc_identity_sign(&e->id, e->host_sw, 4,
                            signature) == RNC_OK);
    if (e->corrupt)
      signature[0] ^= 0x55;
    memcpy(body + 32, signature, 64);
    emu_frame(e, e->host_sw, T_DISCOVER, body, 96);
    return;
  }
  if (memcmp(f, e->sw, 4))
    return;
  if (f[4] == T_CONNECT) {
    rnc_identity host;
    uint8_t key[64];
    ++e->connects;
    if (n != 5 + 32 + 64) {
      ++e->bad_connects;
      return;
    }
    memcpy(key, f + 5, 32);
    memcpy(key + 32, f + 5, 32);
    if (rnc_identity_from_public(&host, key) != RNC_OK ||
        rnc_identity_verify(&host, e->sw, 4, f + 5 + 32) != RNC_OK ||
        memcmp(f + 5 + 28, e->host_sw, 4)) {
      ++e->bad_connects;
      return;
    }
    e->connected = 1;
    if (e->connect_ok) {
      static const uint8_t yes = 1, endpoint[8] = {0xe0, 1, 2, 3, 4, 5, 6, 7};
      emu_event(e, ET_PROTO_WDCL_CONNECTION, &yes, 1);
      emu_event(e, ET_PROTO_WDCL_HOST_ENDPOINT, endpoint, 8);
    }
  } else if (f[4] == T_CMD && n >= 5 + 2 + 8 && f[5] == 0 && f[6] == 1 &&
             e->sent_count < SENT_MAX) {
    sent_packet *s = &e->sent[e->sent_count++];
    memcpy(s->endpoint, f + 7, 8);
    s->size = n - 15;
    memcpy(s->data, f + 15, s->size);
  }
}
static void emu_drain(emu *e) {
  uint8_t bytes[1024], data[RNC_MAX_FRAME], command;
  size_t size, k;
  ssize_t n = read(e->master, bytes, sizeof(bytes));
  if (n <= 0)
    return;
  for (k = 0; k < (size_t)n; ++k)
    if (rnc_host_frame_feed(&e->parser, RNC_HOST_HDLC, bytes[k], &command, data,
                            sizeof(data), &size) == RNC_OK)
      emu_handle(e, data, size);
}

typedef struct rig {
  emu e;
  rnc_identity id;
  rnc_node *node;
  rnc_host *host;
  unsigned rng;
  uint64_t now;
} rig;
static void rig_start(rig *r, int answer) {
  uint8_t key[64] = {0};
  memset(r, 0, sizeof(*r));
  r->e.answer = answer;
  r->e.connect_ok = 1;
  r->e.master = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
  CHECK(r->e.master >= 0 && !grantpt(r->e.master) && !unlockpt(r->e.master));
  {
    unsigned seed = 77;
    CHECK(rnc_identity_generate(&r->e.id, random_bytes, &seed) == RNC_OK);
    memcpy(r->e.sw, r->e.id.public_key + 60, 4);
  }
  CHECK(rnc_identity_from_private(&r->id, key) == RNC_OK);
  r->node = rnc_node_new(&r->id, 0, random_bytes, &r->rng);
  r->host = r->node ? rnc_host_new(r->node) : NULL;
  CHECK(r->host);
  r->now = 100;
}
static void rig_stop(rig *r) {
  rnc_host_free(r->host);
  rnc_node_free(r->node);
  close(r->e.master);
}
static void rig_run(rig *r, uint64_t ms) {
  uint64_t end = r->now + ms;
  while (r->now < end) {
    rnc_host_event event;
    CHECK(rnc_host_step(r->host, 0, 1700000000, r->now += 10) == RNC_OK);
    while (rnc_host_poll(r->host, &event) == RNC_OK) {
    }
    emu_drain(&r->e);
  }
}
static rnc_host_config weave_config(const char *path) {
  rnc_host_config c = {0};
  c.kind = RNC_HOST_WEAVE;
  c.name = "Weave";
  c.address = path;
  return c;
}
/* Peers of the device (anything with a parent), in slot order. */
static unsigned peers(rig *r, rnc_host_status *out, unsigned max) {
  rnc_host_status st;
  size_t i;
  unsigned n = 0;
  for (i = 0; i < RNC_HOST_SLOTS; ++i)
    if (rnc_host_status_at(r->host, i, &st) == RNC_OK && st.parent_id == 1 &&
        n < max)
      out[n++] = st;
  return n;
}
static const uint8_t EP_A[8] = {0xa0, 1, 1, 1, 1, 1, 1, 1};
static const uint8_t EP_B[8] = {0xb0, 2, 2, 2, 2, 2, 2, 2};

/* The host broadcasts its id, answers the switch's signed reply with a
 * signature of its own, and is up once the switch reports the connection. */
static void handshake(void) {
  rnc_host_config c;
  rnc_host_status dev;
  rig r;
  rig_start(&r, 1);
  c = weave_config(ptsname(r.e.master));
  CHECK(rnc_host_add(r.host, 1, &c) == RNC_OK);
  rig_run(&r, 1000);
  CHECK(r.e.discovers == 1 && r.e.short_frames == 0);
  CHECK(r.e.connects == 1 && r.e.bad_connects == 0 && r.e.connected);
  CHECK(rnc_host_get_status(r.host, 1, &dev) == RNC_OK && dev.online);
  CHECK(dev.kind == RNC_HOST_WEAVE && dev.mtu == 1024);
  rig_stop(&r);
  puts("weave handshake test passed");
}

/* A switch that does not answer within two seconds is dropped and tried again
 * after five; one whose reply carries a bad signature is never answered. */
static void silent(void) {
  rnc_host_config c;
  rnc_host_status dev;
  rig r;
  rig_start(&r, 0);
  c = weave_config(ptsname(r.e.master));
  CHECK(rnc_host_add(r.host, 1, &c) == RNC_OK);
  rig_run(&r, 1900);
  CHECK(r.e.discovers == 1);
  rig_run(&r, 400);
  CHECK(rnc_host_get_status(r.host, 1, &dev) == RNC_OK && !dev.online);
  rig_run(&r, 5000);
  CHECK(r.e.discovers >= 2 && r.e.connects == 0);
  rig_stop(&r);
  rig_start(&r, 1);
  r.e.corrupt = 1;
  c = weave_config(ptsname(r.e.master));
  CHECK(rnc_host_add(r.host, 1, &c) == RNC_OK);
  rig_run(&r, 1500);
  CHECK(r.e.discovers == 1 && r.e.connects == 0);
  CHECK(rnc_host_get_status(r.host, 1, &dev) == RNC_OK && !dev.online);
  rig_stop(&r);
  puts("weave silent test passed");
}

/* Endpoints the switch reports become interfaces of their own, one each, and
 * go away twenty seconds after they were last heard. */
static void endpoints(void) {
  rnc_host_config c;
  rnc_host_status st[4];
  rig r;
  rig_start(&r, 1);
  c = weave_config(ptsname(r.e.master));
  CHECK(rnc_host_add(r.host, 1, &c) == RNC_OK);
  rig_run(&r, 1000);
  CHECK(peers(&r, st, 4) == 0);
  emu_alive(&r.e, EP_A);
  rig_run(&r, 100);
  CHECK(peers(&r, st, 4) == 1 && st[0].online && st[0].kind == RNC_HOST_WEAVE &&
        st[0].mtu == 1024 && st[0].bitrate == 250000);
  emu_alive(&r.e, EP_A); /* the same endpoint again is not a second peer */
  emu_alive(&r.e, EP_B);
  rig_run(&r, 100);
  CHECK(peers(&r, st, 4) == 2);
  {
    uint8_t via[12];
    memcpy(via, EP_A, 8);
    memcpy(via + 8, "\1\2\3\4", 4);
    emu_event(&r.e, ET_PROTO_WEAVE_EP_VIA, via, 12);
    emu_event(&r.e, 0x1234, via, 3); /* an event of no concern */
    rig_run(&r, 100);
  }
  CHECK(peers(&r, st, 4) == 2);
  /* B keeps announcing itself, A falls silent */
  {
    unsigned i;
    for (i = 0; i < 22; ++i) {
      emu_alive(&r.e, EP_B);
      rig_run(&r, 1000);
    }
  }
  CHECK(peers(&r, st, 4) == 1);
  rig_run(&r, 21000);
  CHECK(peers(&r, st, 4) == 0);
  rig_stop(&r);
  puts("weave endpoints test passed");
}

static size_t make_announce(rig *r, uint8_t seed, uint8_t *raw) {
  uint8_t key[64] = {0};
  rnc_identity other;
  rnc_packet announce;
  size_t n;
  key[0] = seed;
  CHECK(rnc_identity_from_private(&other, key) == RNC_OK);
  CHECK(rnc_announce_create(&other, "weave.test", NULL, 0, 1700000000,
                            random_bytes, &r->rng, &announce) == RNC_OK);
  CHECK(rnc_packet_encode(&announce, raw, RNC_MAX_MTU, &n) == RNC_OK);
  return n;
}
static uint64_t seen(const rnc_host_status *s) {
  return s->rx_packets + s->dropped_packets;
}
/* Packets belong to the endpoint they came from, and an endpoint heard for the
 * first time in a packet is a peer from then on. The same packet arriving from
 * a second endpoint inside three quarters of a second is delivered once. */
static void receive(void) {
  rnc_host_config c;
  rnc_host_status st[4];
  uint8_t raw[RNC_MAX_MTU];
  size_t n;
  rig r;
  rig_start(&r, 1);
  c = weave_config(ptsname(r.e.master));
  CHECK(rnc_host_add(r.host, 1, &c) == RNC_OK);
  rig_run(&r, 1000);
  n = make_announce(&r, 5, raw);
  emu_packet(&r.e, EP_A, raw, n);
  rig_run(&r, 100);
  CHECK(peers(&r, st, 4) == 1 && st[0].rx_packets == 1 &&
        st[0].rx_announces == 1);
  emu_alive(&r.e, EP_B);
  rig_run(&r, 100);
  CHECK(peers(&r, st, 4) == 2);
  emu_packet(&r.e, EP_B, raw, n); /* the same bytes, 0.2 s later */
  rig_run(&r, 100);
  CHECK(peers(&r, st, 4) == 2 && seen(&st[1]) == 0);
  rig_run(&r, 800);
  emu_packet(&r.e, EP_B, raw, n); /* ... and after the window */
  rig_run(&r, 100);
  CHECK(peers(&r, st, 4) == 2 && seen(&st[1]) == 1);
  rig_stop(&r);
  puts("weave receive test passed");
}

/* Every packet the node sends goes to each peer as a command naming the
 * endpoint, and to nobody else. */
static void transmit(void) {
  rnc_host_config c;
  rnc_host_status st[4];
  rnc_packet plain = {0};
  rig r;
  rig_start(&r, 1);
  c = weave_config(ptsname(r.e.master));
  CHECK(rnc_host_add(r.host, 1, &c) == RNC_OK);
  rig_run(&r, 1000);
  emu_alive(&r.e, EP_A);
  emu_alive(&r.e, EP_B);
  rig_run(&r, 200);
  CHECK(peers(&r, st, 4) == 2);
  plain.flags = 8;
  plain.data_size = 1;
  plain.data[0] = 0x11;
  CHECK(rnc_node_send(r.node, &plain, 1700000000, r.now) == RNC_OK);
  rig_run(&r, 500);
  CHECK(r.e.sent_count == 2);
  CHECK(!memcmp(r.e.sent[0].endpoint, EP_A, 8) &&
        !memcmp(r.e.sent[1].endpoint, EP_B, 8));
  CHECK(r.e.sent[0].size == r.e.sent[1].size && r.e.sent[0].size > 1 &&
        r.e.sent[0].data[r.e.sent[0].size - 1] == 0x11);
  CHECK(peers(&r, st, 4) == 2 && st[0].tx_packets == 1 && st[1].tx_packets == 1);
  rig_stop(&r);
  puts("weave transmit test passed");
}

/* Frames that are wrong in some way are ignored and cost nothing. */
static void refusals(void) {
  rnc_host_config c;
  rnc_host_status st[4];
  uint8_t raw[RNC_MAX_MTU], other[4] = {9, 9, 9, 9}, bad[8] = {0};
  size_t n;
  rig r;
  rig_start(&r, 1);
  c = weave_config(ptsname(r.e.master));
  CHECK(rnc_host_add(r.host, 1, &c) == RNC_OK);
  rig_run(&r, 1000);
  n = make_announce(&r, 6, raw);
  {
    uint8_t body[RNC_MAX_FRAME];
    memcpy(body, raw, n);
    memcpy(body + n, EP_A, 8);
    emu_frame(&r.e, other, T_ENDPOINT_PKT, body, n + 8); /* not for us */
  }
  emu_frame(&r.e, r.e.host_sw, T_ENDPOINT_PKT, bad, 3);    /* too short */
  emu_frame(&r.e, r.e.host_sw, T_LOG, bad, 4);             /* too short */
  emu_frame(&r.e, r.e.host_sw, 0x42, bad, 8);              /* unknown type */
  emu_frame(&r.e, r.e.host_sw, T_DISCOVER, bad, 8);        /* wrong length */
  emu_event(&r.e, ET_PROTO_WEAVE_EP_ALIVE, bad, 7);        /* not an endpoint */
  emu_event(&r.e, ET_PROTO_WEAVE_EP_VIA, bad, 8);
  rig_run(&r, 300);
  CHECK(peers(&r, st, 4) == 0);
  CHECK(r.e.discovers == 1 && r.e.connects == 1);
  /* configuration that cannot be right is refused when it is added */
  c = weave_config(ptsname(r.e.master));
  c.mtu = 600;
  CHECK(rnc_host_add(r.host, 2, &c) == RNC_INVALID);
  c = weave_config(NULL);
  CHECK(rnc_host_add(r.host, 2, &c) == RNC_INVALID);
  rig_stop(&r);
  puts("weave refusal tests passed");
}

/* The unmodified reference's WeaveInterface talks to the same emulated switch:
 * it must satisfy the handshake the switch checks, make the endpoint a peer,
 * take a packet from it, and send its own announce to that endpoint. */
static void reference(const char *python, const char *reference_dir) {
  rig r;
  char dir[] = "/tmp/rnc-weave-ref-XXXXXX", path[300], out[300], text[1024],
       line[200] = "";
  uint8_t raw[RNC_MAX_MTU];
  size_t n;
  uint64_t t;
  int sent_ours = 0;
  pid_t child;
  FILE *f;
  rnc_packet decoded;
  unsigned peer_count = 0, rxb = 0;
  rig_start(&r, 1);
  CHECK(mkdtemp(dir));
  snprintf(path, sizeof(path), "%s/config", dir);
  snprintf(out, sizeof(out), "%s/out", dir);
  snprintf(text, sizeof(text),
           "[reticulum]\nenable_transport = No\nshare_instance = No\n"
           "[interfaces]\n  [[Weave]]\n    type = WeaveInterface\n"
           "    enabled = yes\n    port = %s\n",
           ptsname(r.e.master));
  f = fopen(path, "w");
  CHECK(f && fputs(text, f) >= 0 && !fclose(f));
  n = make_announce(&r, 7, raw);
  child = fork();
  CHECK(child >= 0);
  if (!child) {
    int fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    int devnull = open("/dev/null", O_WRONLY);
    if (fd >= 0)
      (void)dup2(fd, STDOUT_FILENO);
    if (devnull >= 0)
      (void)dup2(devnull, STDERR_FILENO);
    CHECK(!setenv("PYTHONPATH", reference_dir, 1));
    execl(python, python, "-c",
          "import RNS,sys,time\n"
          "RNS.Reticulum(configdir=sys.argv[1], loglevel=1)\n"
          "time.sleep(5)\n"
          "i=RNS.Identity()\n"
          "d=RNS.Destination(i,RNS.Destination.IN,RNS.Destination.SINGLE,"
          "'weave','ref')\n"
          "d.announce()\n"
          "time.sleep(2)\n"
          "p=[x for x in RNS.Transport.interfaces if type(x).__name__=="
          "'WeaveInterfacePeer']\n"
          "print('peers',len(p),'rxb',sum(x.rxb for x in p),flush=True)\n"
          "time.sleep(1)\n",
          dir, (char *)NULL);
    _exit(127);
  }
  for (t = 0; t < 12000; t += 10) {
    struct timespec ts = {0, 10000000};
    emu_drain(&r.e);
    if (r.e.connected && !sent_ours && t > 1500) {
      emu_alive(&r.e, EP_A);
      emu_packet(&r.e, EP_A, raw, n);
      sent_ours = 1;
    }
    nanosleep(&ts, NULL);
  }
  kill(child, SIGKILL);
  waitpid(child, NULL, 0);
  f = fopen(out, "r");
  CHECK(f && fgets(line, sizeof(line), f));
  fclose(f);
  CHECK(sscanf(line, "peers %u rxb %u", &peer_count, &rxb) == 2);
  CHECK(r.e.discovers >= 1 && r.e.short_frames == 0 && r.e.connects >= 1 &&
        r.e.bad_connects == 0 && r.e.connected);
  CHECK(peer_count == 1 && rxb == n);
  CHECK(r.e.sent_count >= 1 && !memcmp(r.e.sent[0].endpoint, EP_A, 8));
  CHECK(rnc_packet_decode(r.e.sent[0].data, r.e.sent[0].size, &decoded) ==
            RNC_OK &&
        (decoded.flags & 3u) == RNC_ANNOUNCE);
  rig_stop(&r);
  puts("weave reference test passed");
}

static int check_config(const char *exe, const char *path, const char *text) {
  FILE *f = fopen(path, "w");
  pid_t p;
  int status = 0;
  CHECK(f && fputs(text, f) >= 0 && !fclose(f));
  p = fork();
  CHECK(p >= 0);
  if (!p) {
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      (void)dup2(devnull, STDOUT_FILENO);
      (void)dup2(devnull, STDERR_FILENO);
    }
    execl(exe, exe, "--config", path, "--check", (char *)NULL);
    _exit(127);
  }
  CHECK(waitpid(p, &status, 0) == p && WIFEXITED(status));
  return WEXITSTATUS(status);
}
/* The daemon reads a WeaveInterface section, performs the handshake, and shows
 * the device and its endpoint peers. */
static void daemon_config(const char *exe) {
  char dir[] = "/tmp/rnc-weave-daemon-XXXXXX", cfg[300], key[300], admin[300],
       text[1024], reply[2048];
  rig r;
  pid_t p;
  unsigned i;
  int fd = -1;
  struct sockaddr_un addr;
  ssize_t got;
  CHECK(mkdtemp(dir));
  snprintf(cfg, sizeof(cfg), "%s/config", dir);
  snprintf(key, sizeof(key), "%s/identity", dir);
  snprintf(admin, sizeof(admin), "%s/admin", dir);
  /* the device path is required, and the MTU is fixed */
  CHECK(check_config(exe, cfg,
                     "[reticulum]\nshare_instance = No\n[interfaces]\n"
                     "[[W]]\ntype = WeaveInterface\n") == 2);
  CHECK(check_config(exe, cfg,
                     "[reticulum]\nshare_instance = No\n[interfaces]\n"
                     "[[W]]\ntype = WeaveInterface\nport = /dev/null\n"
                     "mtu = 600\n") == 2);
  CHECK(check_config(exe, cfg,
                     "[reticulum]\nshare_instance = No\n[interfaces]\n"
                     "[[W]]\ntype = WeaveInterface\nport = /dev/null\n"
                     "configured_bitrate = 500000\n") == 0);
  rig_start(&r, 1);
  snprintf(text, sizeof(text),
           "[reticulum]\nenable_transport = No\nshare_instance = No\n"
           "[interfaces]\n[[Weave]]\ntype = WeaveInterface\nport = %s\n"
           "configured_bitrate = 500000\n",
           ptsname(r.e.master));
  {
    FILE *f = fopen(cfg, "w");
    CHECK(f && fputs(text, f) >= 0 && !fclose(f));
  }
  p = fork();
  CHECK(p >= 0);
  if (!p) {
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0)
      (void)dup2(devnull, STDOUT_FILENO);
    execl(exe, exe, "--config", cfg, "--identity", key, "--admin", admin,
          (char *)NULL);
    _exit(127);
  }
  for (i = 0; i < 600 && !r.e.connected; ++i) {
    struct timespec ts = {0, 10000000};
    emu_drain(&r.e);
    nanosleep(&ts, NULL);
  }
  CHECK(r.e.connected);
  for (i = 0; i < 20; ++i) { /* let the daemon take the connection event */
    struct timespec ts = {0, 10000000};
    emu_drain(&r.e);
    nanosleep(&ts, NULL);
  }
  emu_alive(&r.e, EP_A);
  for (i = 0; i < 50 && fd < 0; ++i) {
    struct timespec ts = {0, 100000000};
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(s >= 0);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, admin);
    if (!connect(s, (struct sockaddr *)&addr, sizeof(addr)))
      fd = s;
    else {
      close(s);
      emu_drain(&r.e);
      nanosleep(&ts, NULL);
    }
  }
  CHECK(fd >= 0);
  {
    struct timespec ts = {0, 300000000};
    nanosleep(&ts, NULL);
  }
  CHECK(write(fd, "STATUS\n", 7) == 7);
  got = read(fd, reply, sizeof(reply) - 1);
  CHECK(got > 0);
  reply[got] = 0;
  close(fd);
  {
    unsigned lines = 0;
    const char *at = reply;
    while ((at = strstr(at, "interface id=")) != NULL) {
      ++lines;
      ++at;
    }
    CHECK(lines == 2); /* the switch and its one endpoint */
    CHECK(strstr(reply, "mtu=1024"));
  }
  kill(p, SIGTERM);
  waitpid(p, NULL, 0);
  rig_stop(&r);
  puts("weave daemon test passed");
}

int main(int argc, char **argv) {
  if (argc < 2)
    return 2;
  if (!strcmp(argv[1], "handshake"))
    handshake();
  else if (!strcmp(argv[1], "silent"))
    silent();
  else if (!strcmp(argv[1], "endpoints"))
    endpoints();
  else if (!strcmp(argv[1], "receive"))
    receive();
  else if (!strcmp(argv[1], "transmit"))
    transmit();
  else if (!strcmp(argv[1], "refusals"))
    refusals();
  else if (!strcmp(argv[1], "daemon") && argc == 3)
    daemon_config(argv[2]);
  else if (!strcmp(argv[1], "reference") && argc == 4)
    reference(argv[2], argv[3]);
  else
    return 2;
  return 0;
}
