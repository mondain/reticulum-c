#define _GNU_SOURCE
/*
 * reticulum-c-rnode-sx1302: an SX1302 concentrator (Seeed WM1302 Pi HAT and similar) as an
 * RNode on a pseudo terminal. Any RNode host drives it: this project's node with
 * `type = RNodeInterface` (RNC_HOST_RNODE), or the reference rnsd. The host sets the radio;
 * this program never transmits before it has.
 *
 *   sudo reticulum-c-rnode-sx1302 --link /run/rnode-sx1302 \
 *        --freq 915000000 --bw 125000 --sf 8 --cr 5 --txp 17
 *
 * prints "pty=/dev/pts/N" and runs until stopped. --freq/--bw/--sf/--txp are optional: given,
 * the concentrator is started (receive only) at launch with them, so that a host asking for
 * the same setting is answered at once; without them, the first "radio on" from the host
 * blocks for the one to three seconds lgw_start() takes, which some hosts time out on.
 *
 * Uses the portable radio core (mcu/radio: air framing, CSMA, airtime budget, the RNode
 * device protocol) and rnc_sx1302 for the chip. See README.md in this directory.
 */
#include "rnc_rnode.h"
#include "rnc_sx1302.h"
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static void on_signal(int sig) {
  (void)sig;
  stopping = 1;
}

static uint64_t mono_us(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

/* rnc_lora_if needs only the clock from the HAL; the SX1302 is reached through libloragw */
static uint64_t hal_now(void *c) {
  (void)c;
  return mono_us();
}
static void hal_delay(void *c, uint32_t us) {
  (void)c;
  usleep(us);
}
static int hal_spi(void *c, const uint8_t *tx, uint8_t *rx, size_t n) {
  (void)c, (void)tx, (void)rx, (void)n;
  return -1;
}
static void hal_gpio(void *c, rnc_radio_pin p, int l) { (void)c, (void)p, (void)l; }

static uint32_t random32(void *c) {
  uint32_t v = 0;
  (void)c;
  if (getrandom(&v, sizeof(v), 0) != (ssize_t)sizeof(v))
    v = (uint32_t)mono_us() * 2654435761u;
  return v;
}

static int pty_read(void *c, uint8_t *buf, size_t cap) {
  ssize_t n = read(*(int *)c, buf, cap);
  if (n < 0)
    return (errno == EAGAIN || errno == EIO) ? 0 : -1; /* EIO: no host has it open */
  return (int)n;
}

static int pty_write(void *c, const uint8_t *data, size_t size) {
  int fd = *(int *)c;
  size_t done = 0;
  while (done < size) {
    ssize_t n = write(fd, data + done, size - done);
    if (n > 0) {
      done += (size_t)n;
    } else if (n < 0 && errno == EAGAIN) {
      struct pollfd pf = {fd, POLLOUT, 0};
      if (poll(&pf, 1, 50) <= 0)
        break; /* the host is not draining; the rest is dropped and counted */
    } else {
      break;
    }
  }
  return (int)done;
}

static void usage(const char *argv0) {
  fprintf(stderr,
          "usage: %s [options]\n"
          "  --spi PATH          SX1302 SPI device (/dev/spidev0.0)\n"
          "  --gpiochip PATH     GPIO character device (/dev/gpiochip0)\n"
          "  --reset N           SX1302 reset line offset (17, WM1302 Pi HAT)\n"
          "  --power N           SX1302 power enable line offset (18)\n"
          "  --sx1261-reset N    SX1261 reset line offset (5)\n"
          "  --no-reset          do not drive the GPIO lines (reset_lgw.sh was run)\n"
          "  --if-offset HZ      IF of the receive channel; RF chain 0 at freq - HZ (0)\n"
          "  --rssi-offset DB    board RSSI correction (-215.4, WM1302)\n"
          "  --airtime PERCENT   hourly airtime budget (1.0)\n"
          "  --link PATH         create a symlink to the pty at PATH\n"
          "  --freq HZ --bw HZ --sf N --cr N --txp DBM\n"
          "                      start the concentrator at launch (receive only)\n"
          "  -v                  verbose; repeat for statistics every minute\n",
          argv0);
}

int main(int argc, char **argv) {
  static rnc_sx1302 dev;
  static rnc_lora_if li;
  static rnc_rnode rn;
  rnc_sx1302_config cfg;
  rnc_radio_hal hal = {NULL, hal_spi, hal_gpio, NULL, hal_delay, hal_now};
  rnc_lora_params pre;
  rnc_rnode_io io;
  const char *link_path = NULL;
  double airtime = 1.0;
  int master, slave, verbose = 0, was_on = 0, opt;
  uint64_t last_stats = 0;
  struct termios tio;
  struct sigaction sa;
  static const struct option opts[] = {
      {"spi", required_argument, 0, 'S'},       {"gpiochip", required_argument, 0, 'G'},
      {"reset", required_argument, 0, 'R'},     {"power", required_argument, 0, 'P'},
      {"sx1261-reset", required_argument, 0, 'X'}, {"no-reset", no_argument, 0, 'N'},
      {"if-offset", required_argument, 0, 'I'}, {"rssi-offset", required_argument, 0, 'O'},
      {"airtime", required_argument, 0, 'A'},   {"link", required_argument, 0, 'L'},
      {"freq", required_argument, 0, 'f'},      {"bw", required_argument, 0, 'b'},
      {"sf", required_argument, 0, 's'},        {"cr", required_argument, 0, 'c'},
      {"txp", required_argument, 0, 't'},       {"help", no_argument, 0, 'h'},
      {0, 0, 0, 0}};

  memset(&cfg, 0, sizeof(cfg));
  memset(&pre, 0, sizeof(pre));
  cfg.reset_line = 17;
  cfg.power_line = 18;
  cfg.sx1261_reset_line = 5;
  cfg.rssi_offset = -215.4f;
  pre.cr = 5;
  while ((opt = getopt_long(argc, argv, "vh", opts, NULL)) != -1) {
    switch (opt) {
    case 'S': cfg.spi_path = optarg; break;
    case 'G': cfg.gpiochip = optarg; break;
    case 'R': cfg.reset_line = (unsigned)strtoul(optarg, NULL, 0); break;
    case 'P': cfg.power_line = (unsigned)strtoul(optarg, NULL, 0); break;
    case 'X': cfg.sx1261_reset_line = (unsigned)strtoul(optarg, NULL, 0); break;
    case 'N': cfg.no_reset = 1; break;
    case 'I': cfg.if_offset_hz = (int32_t)strtol(optarg, NULL, 0); break;
    case 'O': cfg.rssi_offset = strtof(optarg, NULL); break;
    case 'A': airtime = strtod(optarg, NULL); break;
    case 'L': link_path = optarg; break;
    case 'f': pre.freq_hz = (uint32_t)strtoul(optarg, NULL, 0); break;
    case 'b': pre.bw_hz = (uint32_t)strtoul(optarg, NULL, 0); break;
    case 's': pre.sf = (uint8_t)strtoul(optarg, NULL, 0); break;
    case 'c': pre.cr = (uint8_t)strtoul(optarg, NULL, 0); break;
    case 't': pre.txp_dbm = (int8_t)strtol(optarg, NULL, 0); break;
    case 'v': verbose++; break;
    default: usage(argv[0]); return opt == 'h' ? 0 : 2;
    }
  }
  if (airtime <= 0.0 || airtime > 100.0) {
    fprintf(stderr, "--airtime must be in (0, 100]\n");
    return 2;
  }
  cfg.verbose = verbose;

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_signal;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  signal(SIGPIPE, SIG_IGN);

  master = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
  if (master < 0 || grantpt(master) || unlockpt(master)) {
    perror("pty");
    return 1;
  }
  /* hold the slave open so the master does not report EIO between host sessions */
  slave = open(ptsname(master), O_RDWR | O_NOCTTY);
  if (slave < 0 || tcgetattr(slave, &tio) != 0) {
    perror("pty slave");
    return 1;
  }
  cfmakeraw(&tio);
  tcsetattr(slave, TCSANOW, &tio);
  if (link_path) {
    struct stat st;
    if (lstat(link_path, &st) == 0 && S_ISLNK(st.st_mode))
      unlink(link_path);
    if (symlink(ptsname(master), link_path) != 0) {
      fprintf(stderr, "symlink %s: %s\n", link_path, strerror(errno));
      return 1;
    }
  }

  rnc_sx1302_init(&dev, &cfg);
  rnc_lora_if_init(&li, &dev.modem, &hal, random32, NULL, (uint32_t)(airtime * 100.0 + 0.5));
  rnc_rnode_init(&rn, &li, 0x70, 0x71, 0x42);
  rnc_rnode_set_limits(&rn, 5, 27);

  if (pre.freq_hz || pre.bw_hz || pre.sf || pre.txp_dbm) {
    int r;
    if (!pre.freq_hz || !pre.bw_hz || !pre.sf) {
      fprintf(stderr, "--freq, --bw and --sf go together (and --txp, default 0)\n");
      return 2;
    }
    pre.preamble_symbols = (uint16_t)rnc_lora_default_preamble(pre.bw_hz, pre.sf, pre.cr);
    r = dev.modem.ops->init(&dev.modem, &pre);
    if (r != 0) {
      fprintf(stderr, "concentrator did not start (%d)\n", r);
      rnc_sx1302_close(&dev);
      return 1;
    }
    fprintf(stderr, "concentrator listening on %u Hz bw %u sf %u; waiting for a host\n",
            (unsigned)pre.freq_hz, (unsigned)pre.bw_hz, pre.sf);
  }

  printf("pty=%s\n", ptsname(master));
  fflush(stdout);
  io.read = pty_read;
  io.write = pty_write;
  io.context = &master;

  while (!stopping) {
    struct pollfd pf = {master, POLLIN, 0};
    uint64_t now;
    unsigned wait;
    now = mono_us();
    rnc_rnode_pump(&rn, &io, now);
    wait = rnc_rnode_step(&rn, now);
    rnc_rnode_pump(&rn, &io, now);
    if (rnc_rnode_reset_requested(&rn)) {
      if (verbose)
        fprintf(stderr, "host asked for a reset; settings cleared\n");
      rnc_rnode_reset(&rn);
    }
    if (rnc_rnode_radio_on(&rn) != was_on) {
      was_on = rnc_rnode_radio_on(&rn);
      if (was_on)
        fprintf(stderr, "radio on %u Hz bw %u sf %u cr %u txp %d\n", (unsigned)li.params.freq_hz,
                (unsigned)li.params.bw_hz, li.params.sf, li.params.cr, li.params.txp_dbm);
      else
        fprintf(stderr, "radio off\n");
    }
    if (verbose > 1 && now - last_stats > 60000000u) {
      last_stats = now;
      fprintf(stderr,
              "stats: rx %u pkts/%u frames, crc %u, tx %u pkts/%u frames, fail %u, "
              "budget-deferred %u, dropped q%u s%u, rssi %d snr %.2f, lgw rx-err %u tx-err %u\n",
              (unsigned)li.stats.rx_packets, (unsigned)li.stats.rx_frames,
              (unsigned)li.stats.rx_crc_errors, (unsigned)li.stats.tx_packets,
              (unsigned)li.stats.tx_frames, (unsigned)li.stats.tx_failures,
              (unsigned)li.stats.tx_deferred_budget, (unsigned)li.stats.tx_dropped_queue,
              (unsigned)li.stats.tx_dropped_stale, li.stats.last_rssi_dbm,
              li.stats.last_snr_quarter_db / 4.0, (unsigned)dev.fetch_errors,
              (unsigned)dev.tx_errors);
    }
    if (wait > 5u)
      wait = 5u; /* the concentrator is polled; frames wait in its FIFO meanwhile */
    (void)poll(&pf, 1, (int)wait);
  }

  rnc_lora_if_stop(&li);
  rnc_sx1302_close(&dev);
  if (link_path)
    unlink(link_path);
  close(slave);
  close(master);
  return 0;
}
