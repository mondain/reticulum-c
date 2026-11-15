#define _XOPEN_SOURCE 700
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
/* The RNode device side on a pseudo terminal, in real time, for tests that need a host
 * program on the other end (the reference RNodeInterface, see mcu_rnode_reference.sh).
 * Prints "pty=/dev/pts/N" and then runs until killed: the module drives a simulated SX1262
 * on a simulated channel with one simulated peer, which counts and prints what it hears:
 *
 *   rnode: radio on 915000000 Hz bw 125000 sf 8 cr 5 txp 10
 *   peer: heard 123 bytes
 *
 * Test code: the chip and the channel are models (mcu/tests/radio). */
#include "../radio/rnc_rnode.h"
#include "radio/sim_board.h"
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint64_t real_us(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

int main(void) {
  static sim_medium med;
  static sim_board board, peer;
  static rnc_rnode rn;
  uint8_t buf[512];
  int master, was_on = 0;
  uint64_t start = real_us();
  rnc_lora_params p = {0};

  master = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
  if (master < 0 || grantpt(master) || unlockpt(master)) {
    fprintf(stderr, "no pty\n");
    return 1;
  }
  sim_medium_init(&med, 91);
  sim_board_init(&board, &med, 1262, 1, 100);
  sim_board_init(&peer, &med, 1276, 2, 10000);
  sim_link_all(&med, 100);
  p.freq_hz = 915000000u;
  p.bw_hz = 125000u;
  p.sf = 8;
  p.cr = 5;
  p.txp_dbm = 10;
  if (sim_board_start(&peer, &p) != 0) {
    fprintf(stderr, "peer did not start\n");
    return 1;
  }
  rnc_rnode_init(&rn, &board.li, 0x70, 0x71, 0x42);
  printf("pty=%s\n", ptsname(master));
  fflush(stdout);
  for (;;) {
    struct pollfd pf = {master, POLLIN, 0};
    ssize_t n;
    size_t got;
    med.now_us = real_us() - start;
    sim_medium_advance(&med);
    if (poll(&pf, 1, 2) > 0 && (pf.revents & POLLIN) && (n = read(master, buf, sizeof(buf))) > 0)
      rnc_rnode_feed(&rn, buf, (size_t)n, med.now_us);
    rnc_lora_if_step(&peer.li, med.now_us);
    rnc_rnode_step(&rn, med.now_us);
    while ((n = (ssize_t)rnc_rnode_pull(&rn, buf, sizeof(buf))) > 0)
      if (write(master, buf, (size_t)n) != n)
        break;
    if (rnc_rnode_radio_on(&rn) && !was_on)
      printf("rnode: radio on %u Hz bw %u sf %u cr %u txp %d\n", (unsigned)board.li.params.freq_hz,
             (unsigned)board.li.params.bw_hz, board.li.params.sf, board.li.params.cr,
             board.li.params.txp_dbm);
    was_on = rnc_rnode_radio_on(&rn);
    while ((got = rnc_lora_if_recv(&peer.li, buf, sizeof(buf))) > 0)
      printf("peer: heard %zu bytes\n", got);
    fflush(stdout);
  }
}
