/* RNode Multi: one serial device carrying several radios, each addressed by a
 * "select interface" frame. A pty stands in for the device. */
#define _XOPEN_SOURCE 700
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
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

static rnc_result random_bytes(void *v, uint8_t *out, size_t n) {
  unsigned *s = v;
  size_t i;
  for (i = 0; i < n; ++i)
    out[i] = (uint8_t)(*s)++;
  return RNC_OK;
}

/* What the emulated device saw, per radio. */
typedef struct radio_seen {
  uint32_t freq, bw;
  uint8_t txp, sf, cr, state;
  unsigned acks, data_frames, st_lock, lt_lock;
  uint8_t last_data[600];
  size_t last_data_size;
} radio_seen;
typedef struct emu {
  int master;
  rnc_host_framer parser;
  uint8_t fw[2];
  int answer; /* 0 silent, 1 answers detect and the rest */
  uint8_t types[4];
  unsigned type_count;
  uint8_t selected;
  int fresh; /* a SEL_INT arrived and has not been used */
  unsigned unselected; /* commands that arrived without a fresh selection */
  unsigned detects, interface_queries;
  radio_seen radio[4];
  char log[8192];
} emu;

static void emu_write(emu *e, uint8_t command, const uint8_t *data,
                      size_t size) {
  uint8_t out[RNC_HOST_FRAME_MAX];
  size_t n;
  CHECK(rnc_host_frame_encode(RNC_HOST_KISS_FRAMING, command, data, size, out,
                              sizeof(out), &n) == RNC_OK);
  CHECK(write(e->master, out, n) == (ssize_t)n);
}
static void emu_select(emu *e, uint8_t index) {
  emu_write(e, 0x1f, &index, 1);
}
/* One token per frame a radio received: "radio:command:data". */
static void emu_log(emu *e, unsigned radio, unsigned command,
                    const uint8_t *data, size_t size) {
  size_t used = strlen(e->log), k;
  int n = snprintf(e->log + used, sizeof(e->log) - used, "%u:%02x:", radio,
                   command);
  if (n < 0 || used + (size_t)n + 2u * size + 2u > sizeof(e->log))
    return;
  used += (size_t)n;
  for (k = 0; k < size && k < 8u; ++k)
    used += (size_t)sprintf(e->log + used, "%02x", data[k]);
  e->log[used++] = ' ';
  e->log[used] = 0;
}
static void emu_drain(emu *e) {
  uint8_t bytes[1024], data[RNC_HOST_FRAME_MAX], command;
  size_t size, k, i;
  ssize_t n = read(e->master, bytes, sizeof(bytes));
  if (n <= 0)
    return;
  for (k = 0; k < (size_t)n; ++k) {
    if (rnc_host_frame_feed(&e->parser, RNC_HOST_KISS_FRAMING, bytes[k],
                            &command, data, sizeof(data), &size) != RNC_OK)
      continue;
    if (command == 0x1f) {
      CHECK(size == 1);
      e->selected = data[0];
      e->fresh = 1;
      continue;
    }
    if (command == 0x08 || command == 0x50 || command == 0x48 ||
        command == 0x49 || command == 0x71) {
      /* device-level queries never need a selection */
      if (command == 0x08) {
        uint8_t resp = 0x46;
        ++e->detects;
        if (e->answer)
          emu_write(e, 0x08, &resp, 1);
      } else if (command == 0x50 && e->answer) {
        emu_write(e, 0x50, e->fw, 2);
      } else if (command == 0x48 && e->answer) {
        uint8_t v = 0x80;
        emu_write(e, 0x48, &v, 1);
      } else if (command == 0x49 && e->answer) {
        uint8_t v = 0x81;
        emu_write(e, 0x49, &v, 1);
      } else if (command == 0x71) {
        ++e->interface_queries;
        for (i = 0; e->answer && i < e->type_count; ++i) {
          uint8_t pair[2] = {(uint8_t)i, e->types[i]};
          emu_write(e, 0x71, pair, 2);
        }
      }
      continue;
    }
    if (!e->fresh)
      ++e->unselected;
    e->fresh = 0;
    if (e->selected >= 4)
      continue;
    {
      radio_seen *r = &e->radio[e->selected];
      if (command != 0x00)
        emu_log(e, e->selected, command, data, size);
      switch (command) {
      case 0x01:
        CHECK(size == 4);
        r->freq = (uint32_t)data[0] << 24 | (uint32_t)data[1] << 16 |
                  (uint32_t)data[2] << 8 | data[3];
        data[3] = (uint8_t)(data[3] + 50u); /* within the register granularity */
        emu_select(e, e->selected);
        emu_write(e, 0x01, data, 4);
        break;
      case 0x02:
        CHECK(size == 4);
        r->bw = (uint32_t)data[0] << 24 | (uint32_t)data[1] << 16 |
                (uint32_t)data[2] << 8 | data[3];
        emu_select(e, e->selected);
        emu_write(e, 0x02, data, 4);
        break;
      case 0x03:
        r->txp = data[0];
        emu_select(e, e->selected);
        emu_write(e, 0x03, data, 1);
        break;
      case 0x04:
        r->sf = data[0];
        emu_select(e, e->selected);
        emu_write(e, 0x04, data, 1);
        break;
      case 0x05:
        r->cr = data[0];
        emu_select(e, e->selected);
        emu_write(e, 0x05, data, 1);
        break;
      case 0x06:
        r->state = data[0];
        emu_select(e, e->selected);
        emu_write(e, 0x06, data, 1);
        break;
      case 0x0b:
        r->st_lock = (unsigned)data[0] << 8 | data[1];
        break;
      case 0x0c:
        r->lt_lock = (unsigned)data[0] << 8 | data[1];
        break;
      case 0x00:
        ++r->data_frames;
        r->last_data_size = size < sizeof(r->last_data) ? size : sizeof(r->last_data);
        memcpy(r->last_data, data, r->last_data_size);
        break;
      default:
        break;
      }
    }
  }
}

typedef struct rig {
  emu e;
  rnc_identity id;
  rnc_node *node;
  rnc_host *host;
  unsigned rng;
  uint64_t now;
} rig;
static void rig_start(rig *r, int answer, uint8_t major, uint8_t minor,
                      const uint8_t *types, unsigned type_count) {
  uint8_t key[64] = {0};
  memset(r, 0, sizeof(*r));
  r->e.answer = answer;
  r->e.fw[0] = major;
  r->e.fw[1] = minor;
  memcpy(r->e.types, types, type_count);
  r->e.type_count = type_count;
  r->e.master = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
  CHECK(r->e.master >= 0 && !grantpt(r->e.master) && !unlockpt(r->e.master));
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
static rnc_host_config multi_config(const char *path,
                                    const rnc_host_subradio *subs,
                                    size_t count) {
  rnc_host_config c = {0};
  c.kind = RNC_HOST_RNODE_MULTI;
  c.name = "Multi";
  c.address = path;
  c.serial_baud = 115200;
  c.subradios = subs;
  c.subradio_count = count;
  return c;
}
static rnc_host_subradio sub(const char *name, unsigned vport, uint32_t freq,
                             uint32_t bw, int txp, unsigned sf, unsigned cr) {
  rnc_host_subradio s = {0};
  s.name = name;
  s.vport = vport;
  s.frequency = freq;
  s.bandwidth = bw;
  s.tx_power = txp;
  s.spreading_factor = sf;
  s.coding_rate = cr;
  return s;
}
/* Children of the device (anything with a parent), in slot order. */
static unsigned children(rig *r, rnc_host_status *out, unsigned max) {
  rnc_host_status st;
  size_t i;
  unsigned n = 0;
  for (i = 0; i < RNC_HOST_SLOTS; ++i)
    if (rnc_host_status_at(r->host, i, &st) == RNC_OK && st.parent_id == 1 &&
        n < max)
      out[n++] = st;
  return n;
}

/* Detection reports two radios (SX127X and SX128X); both are configured, each
 * after a selection frame, and each reports ready on its own. */
static void configure(void) {
  static const uint8_t types[2] = {0x00, 0x20};
  rnc_host_subradio subs[2];
  rnc_host_config c;
  rnc_host_status st[4];
  rig r;
  subs[0] = sub("LoRa", 0, 915000000, 125000, 10, 7, 5);
  subs[1] = sub("2.4", 1, 2400000000u, 812500, 12, 8, 6);
  subs[1].airtime_limit_short = 5.5;
  rig_start(&r, 1, 1, 74, types, 2);
  c = multi_config(ptsname(r.e.master), subs, 2);
  CHECK(rnc_host_add(r.host, 1, &c) == RNC_OK);
  rig_run(&r, 2000);
  CHECK(r.e.detects == 1 && r.e.interface_queries == 1);
  CHECK(children(&r, st, 4) == 2);
  CHECK(st[0].radio_ready && st[1].radio_ready && st[0].online &&
        st[1].online && st[0].kind == RNC_HOST_RNODE);
  CHECK(strstr(st[0].name, "Multi") && strstr(st[0].name, "LoRa"));
  CHECK(strstr(st[1].name, "2.4"));
  CHECK(r.e.unselected == 0);
  CHECK(r.e.radio[0].freq == 915000000 && r.e.radio[0].bw == 125000 &&
        r.e.radio[0].txp == 10 && r.e.radio[0].sf == 7 && r.e.radio[0].cr == 5 &&
        r.e.radio[0].state == 1);
  CHECK(r.e.radio[1].freq == 2400000000u && r.e.radio[1].bw == 812500 &&
        r.e.radio[1].txp == 12 && r.e.radio[1].sf == 8 && r.e.radio[1].cr == 6 &&
        r.e.radio[1].state == 1);
  CHECK(r.e.radio[1].st_lock == 550 && r.e.radio[0].st_lock == 0);
  /* the radios do not share a bitrate: 125 kHz SF7 CR5 against 812.5 kHz SF8 */
  CHECK(st[0].bitrate != st[1].bitrate);
  rig_stop(&r);
  puts("rnode multi configure test passed");
}

/* Packets go out on every outgoing radio, preceded by a selection; a radio
 * set not to transmit stays silent. */
static void transmit(void) {
  static const uint8_t types[2] = {0x00, 0x00};
  rnc_host_subradio subs[2];
  rnc_host_config c;
  rnc_packet plain = {0};
  rig r;
  subs[0] = sub("A", 0, 915000000, 125000, 10, 7, 5);
  subs[1] = sub("B", 1, 868000000, 125000, 10, 7, 5);
  subs[1].no_output = 1;
  rig_start(&r, 1, 1, 74, types, 2);
  c = multi_config(ptsname(r.e.master), subs, 2);
  CHECK(rnc_host_add(r.host, 1, &c) == RNC_OK);
  rig_run(&r, 2000);
  plain.flags = 8;
  plain.data_size = 1;
  plain.data[0] = 0x11;
  CHECK(rnc_node_send(r.node, &plain, 1700000000, r.now) == RNC_OK);
  rig_run(&r, 1000);
  CHECK(r.e.radio[0].data_frames == 1 && r.e.radio[1].data_frames == 0);
  CHECK(r.e.unselected == 0);
  rig_stop(&r);
  puts("rnode multi transmit test passed");
}

/* Frames from the device belong to the radio last selected, with that radio's
 * signal statistics. */
static void receive(void) {
  static const uint8_t types[2] = {0x00, 0x00};
  uint8_t key2[64] = {9}, raw[RNC_MAX_MTU];
  rnc_host_subradio subs[2];
  rnc_host_config c;
  rnc_host_status st[4];
  rnc_identity other;
  rnc_packet announce;
  rnc_host_event event;
  size_t n;
  unsigned i, got = 0;
  uint32_t from = 0;
  uint8_t one = 1, rssi = 100, snr = 13;
  rig r;
  subs[0] = sub("A", 0, 915000000, 125000, 10, 7, 5);
  subs[1] = sub("B", 1, 868000000, 125000, 10, 9, 5);
  rig_start(&r, 1, 1, 74, types, 2);
  c = multi_config(ptsname(r.e.master), subs, 2);
  CHECK(rnc_host_add(r.host, 1, &c) == RNC_OK);
  rig_run(&r, 2000);
  CHECK(rnc_identity_from_private(&other, key2) == RNC_OK);
  CHECK(rnc_announce_create(&other, "multi.test", NULL, 0, 1700000000,
                            random_bytes, &r.rng, &announce) == RNC_OK);
  CHECK(rnc_packet_encode(&announce, raw, sizeof(raw), &n) == RNC_OK);
  emu_select(&r.e, one);
  emu_write(&r.e, 0x23, &rssi, 1);
  emu_write(&r.e, 0x24, &snr, 1);
  emu_write(&r.e, 0x00, raw, n);
  for (i = 0; i < 300 && !got; ++i) {
    CHECK(rnc_host_step(r.host, 0, 1700000000, r.now += 10) == RNC_OK);
    while (rnc_host_poll(r.host, &event) == RNC_OK)
      if (event.type == RNC_HOST_NODE && event.node.type == RNC_NODE_ANNOUNCE) {
        from = event.interface_id;
        CHECK(event.has_signal && event.rssi == -57);
        /* SNR 3.25 dB at SF9 spans -13..6 dB: 85.5 percent (SF7 would give 81.7) */
        CHECK(event.snr > 3.24f && event.snr < 3.26f);
        CHECK(event.quality > 85.4f && event.quality < 85.6f);
        got = 1;
      }
  }
  CHECK(got && children(&r, st, 4) == 2);
  CHECK(from == st[1].interface_id);
  CHECK(!st[0].has_signal && st[1].has_signal && st[1].rx_packets == 1 &&
        st[0].rx_packets == 0);
  rig_stop(&r);
  puts("rnode multi receive test passed");
}

/* Refusals: nothing answering, an old firmware, a vport the device does not
 * have, and a frequency the radio type cannot do. */
static void refusals(void) {
  static const uint8_t types[2] = {0x00, 0x20};
  rnc_host_subradio subs[2];
  rnc_host_config c;
  rnc_host_status st[4], dev;
  rig r;
  subs[0] = sub("A", 0, 915000000, 125000, 10, 7, 5);
  subs[1] = sub("B", 1, 2400000000u, 812500, 10, 7, 5);
  /* silent device: dropped after 5 s, no radio configured */
  rig_start(&r, 0, 1, 74, types, 2);
  c = multi_config(ptsname(r.e.master), subs, 2);
  CHECK(rnc_host_add(r.host, 1, &c) == RNC_OK);
  rig_run(&r, 5700);
  CHECK(r.e.detects >= 1 && children(&r, st, 4) == 0 && r.e.radio[0].sf == 0);
  CHECK(rnc_host_get_status(r.host, 1, &dev) == RNC_OK && !dev.online);
  rig_stop(&r);
  /* firmware 1.73 is below the 1.74 the multi interface needs: not retried */
  rig_start(&r, 1, 1, 73, types, 2);
  c = multi_config(ptsname(r.e.master), subs, 2);
  CHECK(rnc_host_add(r.host, 1, &c) == RNC_OK);
  rig_run(&r, 30000);
  CHECK(r.e.detects == 1 && children(&r, st, 4) == 0);
  rig_stop(&r);
  /* 1.74 and 2.0 are fine */
  rig_start(&r, 1, 2, 0, types, 2);
  c = multi_config(ptsname(r.e.master), subs, 2);
  CHECK(rnc_host_add(r.host, 1, &c) == RNC_OK);
  rig_run(&r, 2000);
  CHECK(children(&r, st, 4) == 2);
  rig_stop(&r);
  /* the device reports one radio but vport 1 is configured: no children, and
   * the device is tried again after 5 s */
  {
    static const uint8_t one[1] = {0x00};
    rig_start(&r, 1, 1, 74, one, 1);
    c = multi_config(ptsname(r.e.master), subs, 2);
    CHECK(rnc_host_add(r.host, 1, &c) == RNC_OK);
    rig_run(&r, 2000);
    CHECK(children(&r, st, 4) == 0);
    rig_run(&r, 6000);
    CHECK(r.e.detects >= 2);
    rig_stop(&r);
  }
  /* 2.4 GHz on an SX127X radio is outside its range */
  {
    static const uint8_t low[2] = {0x00, 0x00};
    rig_start(&r, 1, 1, 74, low, 2);
    c = multi_config(ptsname(r.e.master), subs, 2);
    CHECK(rnc_host_add(r.host, 1, &c) == RNC_OK);
    rig_run(&r, 2000);
    CHECK(children(&r, st, 4) == 0 && r.e.radio[0].sf == 0);
    rig_stop(&r);
  }
  /* configuration errors are rejected when the interface is added */
  {
    rnc_host_subradio bad[2];
    rig_start(&r, 1, 1, 74, types, 2);
    bad[0] = sub("A", 0, 915000000, 125000, 10, 7, 5);
    bad[1] = bad[0];
    c = multi_config(ptsname(r.e.master), bad, 2); /* same vport twice */
    CHECK(rnc_host_add(r.host, 1, &c) == RNC_INVALID);
    bad[1] = sub("B", 1, 915000000, 125000, 10, 13, 5); /* SF 13 */
    c = multi_config(ptsname(r.e.master), bad, 2);
    CHECK(rnc_host_add(r.host, 1, &c) == RNC_INVALID);
    bad[1] = sub("B", 1, 915000000, 7000, 10, 7, 5); /* bandwidth */
    c = multi_config(ptsname(r.e.master), bad, 2);
    CHECK(rnc_host_add(r.host, 1, &c) == RNC_INVALID);
    bad[1] = sub("B", 1, 915000000, 125000, 38, 7, 5); /* TX power */
    c = multi_config(ptsname(r.e.master), bad, 2);
    CHECK(rnc_host_add(r.host, 1, &c) == RNC_INVALID);
    bad[1] = sub("B", 11, 915000000, 125000, 10, 7, 5); /* vport range */
    c = multi_config(ptsname(r.e.master), bad, 2);
    CHECK(rnc_host_add(r.host, 1, &c) == RNC_INVALID);
    c = multi_config(ptsname(r.e.master), bad, 0); /* nothing configured */
    CHECK(rnc_host_add(r.host, 1, &c) == RNC_INVALID);
    rig_stop(&r);
  }
  puts("rnode multi refusal tests passed");
}

static int token_order(const void *a, const void *b) {
  return strcmp(*(char *const *)a, *(char *const *)b);
}
/* The frames a radio received, sorted: the order in which a client sends the
 * parameters of one radio is its own business, the set is the protocol. */
static void sorted_log(const char *log, char *out, size_t cap) {
  char copy[8192], *tokens[512], *at, *save = NULL;
  size_t n = 0, k;
  snprintf(copy, sizeof(copy), "%s", log);
  for (at = strtok_r(copy, " ", &save); at && n < 512;
       at = strtok_r(NULL, " ", &save))
    tokens[n++] = at;
  qsort(tokens, n, sizeof(*tokens), token_order);
  out[0] = 0;
  for (k = 0; k < n; ++k) {
    strncat(out, tokens[k], cap - strlen(out) - 2u);
    strcat(out, " ");
  }
}
/* The unmodified reference's RNodeMultiInterface and this host drive the same
 * emulated device: the commands each radio receives must be identical. */
static void reference(const char *python, const char *reference_dir) {
  static const uint8_t types[2] = {0x00, 0x20};
  rnc_host_subradio subs[2];
  rnc_host_config c;
  rig r;
  char ours[8192], theirs[8192], dir[] = "/tmp/rnc-multi-ref-XXXXXX",
                                  path[300], text[2048];
  uint64_t t;
  pid_t child;
  FILE *f;
  subs[0] = sub("LoRa", 0, 915000000, 125000, 10, 7, 5);
  subs[1] = sub("2.4", 1, 2400000000u, 812500, 12, 8, 6);
  subs[0].airtime_limit_short = 5.5;
  subs[0].airtime_limit_long = 10.0;
  subs[1].flow_control = 1;
  rig_start(&r, 1, 1, 74, types, 2);
  c = multi_config(ptsname(r.e.master), subs, 2);
  CHECK(rnc_host_add(r.host, 1, &c) == RNC_OK);
  rig_run(&r, 2000);
  sorted_log(r.e.log, ours, sizeof(ours));
  rig_stop(&r);
  CHECK(mkdtemp(dir));
  rig_start(&r, 1, 1, 74, types, 2);
  snprintf(path, sizeof(path), "%s/config", dir);
  snprintf(text, sizeof(text),
           "[reticulum]\nenable_transport = No\nshare_instance = No\n"
           "[interfaces]\n  [[Multi]]\n    type = RNodeMultiInterface\n"
           "    enabled = yes\n    port = %s\n"
           "    [[[LoRa]]]\n      vport = 0\n      frequency = 915000000\n"
           "      bandwidth = 125000\n      txpower = 10\n"
           "      spreadingfactor = 7\n      codingrate = 5\n"
           "      airtime_limit_short = 5.5\n      airtime_limit_long = 10\n"
           "    [[[2.4]]]\n      vport = 1\n      frequency = 2400000000\n"
           "      bandwidth = 812500\n      txpower = 12\n"
           "      spreadingfactor = 8\n      codingrate = 6\n"
           "      flow_control = true\n",
           ptsname(r.e.master));
  f = fopen(path, "w");
  CHECK(f && fputs(text, f) >= 0 && !fclose(f));
  child = fork();
  CHECK(child >= 0);
  if (!child) {
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      (void)dup2(devnull, STDOUT_FILENO);
      (void)dup2(devnull, STDERR_FILENO);
    }
    CHECK(!setenv("PYTHONPATH", reference_dir, 1));
    execl(python, python, "-c",
          "import RNS,sys,time\n"
          "RNS.Reticulum(configdir=sys.argv[1], loglevel=1)\n"
          "time.sleep(12)\n",
          dir, (char *)NULL);
    _exit(127);
  }
  for (t = 0; t < 11000; t += 10) {
    emu_drain(&r.e);
    {
      struct timespec ts = {0, 10000000};
      nanosleep(&ts, NULL);
    }
  }
  kill(child, SIGKILL);
  waitpid(child, NULL, 0);
  sorted_log(r.e.log, theirs, sizeof(theirs));
  rig_stop(&r);
  if (strcmp(ours, theirs)) {
    fprintf(stderr, "ours:   %s\nreference: %s\n", ours, theirs);
    CHECK(0);
  }
  CHECK(strstr(ours, "0:01:3689cac0") || strstr(ours, "0:01:"));
  CHECK(strstr(ours, "1:06:01") && strstr(ours, "0:0b:0226"));
  puts("rnode multi reference test passed");
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
/* The daemon reads an RNodeMultiInterface section with [[[radio]]] children,
 * and brings both radios up on the emulated device. */
static void daemon_config(const char *exe) {
  static const uint8_t types[2] = {0x00, 0x20};
  char dir[] = "/tmp/rnc-multi-daemon-XXXXXX", cfg[300], key[300], admin[300],
       text[2048], reply[2048];
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
  /* a radio without a vport, a section under another type, and no radio
   * enabled are all refused */
  CHECK(check_config(exe, cfg,
                     "[reticulum]\nshare_instance = No\n[interfaces]\n"
                     "[[M]]\ntype = RNodeMultiInterface\nenabled = yes\n"
                     "port = /dev/null\n[[[A]]]\nfrequency = 915000000\n"
                     "bandwidth = 125000\ntxpower = 10\nspreadingfactor = 7\n"
                     "codingrate = 5\n") == 2);
  CHECK(check_config(exe, cfg,
                     "[reticulum]\nshare_instance = No\n[interfaces]\n"
                     "[[T]]\ntype = TCPServerInterface\nlisten_ip = "
                     "127.0.0.1\n[[[A]]]\nvport = 0\n") == 2);
  CHECK(check_config(exe, cfg,
                     "[reticulum]\nshare_instance = No\n[interfaces]\n"
                     "[[M]]\ntype = RNodeMultiInterface\nport = /dev/null\n"
                     "[[[A]]]\nvport = 0\nfrequency = 915000000\n"
                     "bandwidth = 125000\ntxpower = 10\nspreadingfactor = 7\n"
                     "codingrate = 5\n") == 2);
  CHECK(check_config(exe, cfg,
                     "[reticulum]\nshare_instance = No\n[interfaces]\n"
                     "[[M]]\ntype = RNodeMultiInterface\nport = /dev/null\n"
                     "[[[A]]]\nvport = 0\ninterface_enabled = yes\n"
                     "frequency = 915000000\nbandwidth = 125000\n"
                     "txpower = 10\nspreadingfactor = 7\ncodingrate = 5\n") == 0);
  rig_start(&r, 1, 1, 74, types, 2);
  snprintf(text, sizeof(text),
           "[reticulum]\nenable_transport = No\nshare_instance = No\n"
           "[interfaces]\n[[Multi]]\ntype = RNodeMultiInterface\n"
           "port = %s\n"
           "[[[LoRa]]]\ninterface_enabled = yes\nvport = 0\n"
           "frequency = 915000000\nbandwidth = 125000\ntxpower = 10\n"
           "spreadingfactor = 7\ncodingrate = 5\n"
           "[[[Off]]]\ninterface_enabled = no\nvport = 1\n"
           "frequency = 868000000\nbandwidth = 125000\ntxpower = 10\n"
           "spreadingfactor = 7\ncodingrate = 5\n"
           "[[[Band]]]\ninterface_enabled = yes\nvport = 1\n"
           "frequency = 2400000000\nbandwidth = 812500\ntxpower = 12\n"
           "spreadingfactor = 8\ncodingrate = 6\noutgoing = no\n",
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
  for (i = 0; i < 600 && !(r.e.radio[0].state && r.e.radio[1].state); ++i) {
    struct timespec ts = {0, 10000000};
    emu_drain(&r.e);
    nanosleep(&ts, NULL);
  }
  CHECK(r.e.radio[0].freq == 915000000 && r.e.radio[1].freq == 2400000000u);
  CHECK(r.e.radio[1].sf == 8 && r.e.unselected == 0);
  /* the disabled section was never configured: nothing reached a third radio
   * and vport 1 carries the enabled section's parameters */
  CHECK(r.e.radio[1].bw == 812500);
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
  CHECK(fd >= 0 && write(fd, "STATUS\n", 7) == 7);
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
    CHECK(lines == 3); /* the device and its two radios */
  }
  kill(p, SIGTERM);
  waitpid(p, NULL, 0);
  rig_stop(&r);
  puts("rnode multi daemon test passed");
}

int main(int argc, char **argv) {
  if (argc < 2)
    return 2;
  if (!strcmp(argv[1], "configure"))
    configure();
  else if (!strcmp(argv[1], "transmit"))
    transmit();
  else if (!strcmp(argv[1], "receive"))
    receive();
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
