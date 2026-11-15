#define _XOPEN_SOURCE 700
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
/* The RNode device side (mcu/radio/rnc_rnode.c) against this project's own host RNode
 * adapter (RNC_HOST_RNODE) over a pseudo terminal, with a simulated LoRa peer on the same
 * channel: the host detects the board, configures the radio, an announce goes out to the
 * peer, and a packet from the peer arrives at the host with its signal figures.
 *
 * LIMIT: simulation (chip models written by the author of the drivers); it checks that the
 * two sides of the protocol agree, not real radio behaviour. */
#include "../radio/rnc_rnode.h"
#include "radio/sim_board.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <reticulum_c/rnc_host.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

typedef struct world {
  int master;
  sim_medium med;
  sim_board board, peer;
  rnc_rnode rn;
  rnc_host *host;
  uint64_t ms;
} world;

/* advances the host, the pty bridge and the simulated channel by 10 ms */
static void tick(world *w) {
  uint8_t buf[512];
  ssize_t n;
  struct pollfd p = {w->master, POLLIN, 0};
  w->ms += 10;
  CHECK(rnc_host_step(w->host, 0, 1700000000u + w->ms / 1000u, w->ms) == RNC_OK);
  while (poll(&p, 1, 0) > 0 && (p.revents & POLLIN) && (n = read(w->master, buf, sizeof(buf))) > 0)
    rnc_rnode_feed(&w->rn, buf, (size_t)n, w->med.now_us);
  w->med.now_us += 10000u;
  sim_medium_advance(&w->med);
  rnc_lora_if_step(&w->peer.li, w->med.now_us);
  rnc_rnode_step(&w->rn, w->med.now_us);
  while ((n = (ssize_t)rnc_rnode_pull(&w->rn, buf, sizeof(buf))) > 0)
    CHECK(write(w->master, buf, (size_t)n) == n);
}

int main(void) {
  static world w;
  uint8_t key[64] = {0}, key2[64] = {1}, dest[16], raw[RNC_MTU], got[508];
  unsigned rng = 0, rng2 = 99;
  size_t n, i;
  rnc_identity id, id2;
  rnc_node *node;
  rnc_host_config cfg = {0};
  rnc_host_status status;
  rnc_packet announce, decoded;
  rnc_announce verified;
  rnc_lora_params p = {0};
  int seen = 0;

  w.master = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
  CHECK(w.master >= 0 && !grantpt(w.master) && !unlockpt(w.master));
  sim_medium_init(&w.med, 81);
  sim_board_init(&w.board, &w.med, 1262, 1, 100);
  sim_board_init(&w.peer, &w.med, 1276, 2, 10000);
  sim_link_all(&w.med, 100);
  p.freq_hz = 915000000u;
  p.bw_hz = 125000u;
  p.sf = 8;
  p.cr = 5;
  p.txp_dbm = 10;
  CHECK(sim_board_start(&w.peer, &p) == 0);
  rnc_rnode_init(&w.rn, &w.board.li, 0x70, 0x71, 0x42);

  CHECK(rnc_identity_from_private(&id, key) == RNC_OK);
  node = rnc_node_new(&id, 0, random_bytes, &rng);
  CHECK(node);
  w.host = rnc_host_new(node);
  CHECK(w.host);
  cfg.kind = RNC_HOST_RNODE;
  cfg.address = ptsname(w.master);
  cfg.serial_baud = 115200;
  cfg.frequency = 915000000;
  cfg.bandwidth = 125000;
  cfg.tx_power = 10;
  cfg.spreading_factor = 8;
  cfg.coding_rate = 5;
  CHECK(rnc_host_add(w.host, 1, &cfg) == RNC_OK);

  /* 1. the host detects the board, accepts its firmware version and configures the radio */
  for (i = 0; i < 1500 && !rnc_rnode_radio_on(&w.rn); i++)
    tick(&w);
  CHECK(rnc_rnode_radio_on(&w.rn));
  for (i = 0; i < 300; i++)
    tick(&w);
  CHECK(rnc_host_get_status(w.host, 1, &status) == RNC_OK);
  CHECK(status.radio_ready);
  CHECK(w.board.li.params.freq_hz == 915000000u && w.board.li.params.sf == 8 &&
        w.board.li.params.txp_dbm == 10);

  /* 2. host to air: an announce of the host's node reaches the peer */
  CHECK(rnc_node_add_destination(node, &id, "reticulum_c.rnode.test", NULL, 0, dest) == RNC_OK);
  CHECK(rnc_node_announce(node, dest, 1700000000u + w.ms / 1000u, w.ms) == RNC_OK);
  for (i = 0; i < 1500 && !seen; i++) {
    tick(&w);
    n = rnc_lora_if_recv(&w.peer.li, got, sizeof(got));
    if (n) {
      CHECK(rnc_packet_decode(got, n, &decoded) == RNC_OK);
      CHECK(rnc_announce_verify(&decoded, &verified) == RNC_OK);
      CHECK(!memcmp(decoded.destination, dest, 16));
      seen = 1;
    }
  }
  CHECK(seen);

  /* 3. air to host: an announce from the peer arrives with signal figures */
  CHECK(rnc_identity_from_private(&id2, key2) == RNC_OK);
  CHECK(rnc_announce_create(&id2, "reticulum_c.rnode.peer", NULL, 0, 1700000000u, random_bytes, &rng2,
                            &announce) == RNC_OK);
  CHECK(rnc_packet_encode(&announce, raw, sizeof(raw), &n) == RNC_OK);
  CHECK(rnc_host_get_status(w.host, 1, &status) == RNC_OK);
  {
    uint64_t before = status.rx_packets;
    CHECK(rnc_lora_if_send(&w.peer.li, raw, n, w.med.now_us) == 0);
    for (i = 0; i < 1500; i++) {
      tick(&w);
      CHECK(rnc_host_get_status(w.host, 1, &status) == RNC_OK);
      if (status.rx_packets > before)
        break;
    }
    CHECK(status.rx_packets > before);
  }
  CHECK(status.has_signal);
  CHECK(status.protocol_violations == 0);
  CHECK(sim_board_violations(&w.board) + sim_board_violations(&w.peer) == 0);

  rnc_host_free(w.host);
  rnc_node_free(node);
  close(w.master);
  puts("rnode host adapter test passed");
  return 0;
}
