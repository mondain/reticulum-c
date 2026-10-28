/* Host build of the MCU example application: the same rnc_mcu_app the firmware
 * runs, with a pty (or stdin/stdout) as the serial transport, /dev/urandom for
 * randomness and files for persistence. It lets CI exercise the firmware logic
 * with no hardware.
 *
 *   reticulum-c-mcu-host [--pty | --stdio | --tcp HOST:PORT] [--state DIR]
 *                        [--announce-ms N] [--board NAME]
 *                        [--lora leaf|gateway [--lora-freq F] [--lora-bw B] [--lora-sf N]
 *                         [--lora-cr N] [--lora-txp DBM] [--lora-airtime PCT]
 *                         [--lora-peers N] [--lora-loss PERMILLE] [--lora-chip sx1262|sx1276]]
 *
 * --pty    (default) creates a pseudo terminal and prints "pty=/dev/pts/N" on
 *          stdout; point a SerialInterface at that path.
 * --stdio  bytes come from stdin and go to stdout (for example under socat).
 * --tcp    the Wi-Fi firmware's transport: a TCP client connected to the
 *          TCPServerInterface of a Reticulum node (HDLC framed, like the serial
 *          interface). Reconnects with exponential backoff when the connection
 *          cannot be made or is lost; the application resets its decoder and
 *          announces again after every reconnect. Logs "tcp: connection failed",
 *          "tcp: connection lost", "transport up" and "transport down".
 * --lora   gives the harness board a SIMULATED LoRa radio (a model of an SX1262 or SX1276 on
 *          a simulated channel, see lora_host.h) in leaf mode (LoRa is the only interface) or
 *          gateway mode (the serial/pty/TCP interface plus LoRa, transport on). The settings
 *          are the firmware's (lora.freq ...): the radio is refused unless frequency,
 *          bandwidth, spreading factor, coding rate and power are all given. --lora-peers
 *          simulated leaf boards (default 1) share the channel; their destinations are
 *          logged ("peer1 destination <hex>").
 * --state  directory for the persisted identity and clock mark (default ".").
 * The process ends on SIGINT or SIGTERM. */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include "lora_host.h"
#include "rnc_mcu_app.h"
#include "rnc_mcu_net.h"
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define TCP_QUEUE_BYTES 4096u
#define TCP_BACKOFF_MIN_MS 250u
#define TCP_BACKOFF_MAX_MS 4000u

typedef struct host {
  int in_fd, out_fd, rng_fd;
  char state[512];
  /* --tcp */
  int tcp;                 /* 1 in TCP client mode */
  char tcp_host[256], tcp_port[8];
  enum { TCP_DOWN, TCP_CONNECTING, TCP_UP } tcp_state;
  uint64_t tcp_retry_ms;   /* when the next attempt may start */
  rnc_mcu_backoff backoff;
  rnc_mcu_txq txq;
  uint8_t txq_storage[TCP_QUEUE_BYTES];
} host;

static volatile sig_atomic_t stopping;
static void on_signal(int sig) {
  (void)sig;
  stopping = 1;
}

static uint64_t host_now_ms(void *context);
static int host_random(void *context, uint8_t *buffer, size_t size);

/* ---- TCP client transport ---------------------------------------------------- */
static void tcp_drop(host *h, const char *why, uint64_t now) {
  uint8_t r[4];
  uint32_t random = 0;
  int was_up = h->tcp_state == TCP_UP;
  if (h->in_fd >= 0)
    close(h->in_fd);
  h->in_fd = h->out_fd = -1;
  h->tcp_state = TCP_DOWN;
  rnc_mcu_txq_clear(&h->txq); /* what was queued belonged to the dead connection */
  if (host_random(h, r, sizeof(r)) == 0)
    random = (uint32_t)r[0] | (uint32_t)r[1] << 8 | (uint32_t)r[2] << 16 | (uint32_t)r[3] << 24;
  h->tcp_retry_ms = now + rnc_mcu_backoff_next(&h->backoff, random);
  fprintf(stderr, "mcu: tcp: %s\n", was_up ? "connection lost" : why);
}
static void tcp_start(host *h, uint64_t now) {
  struct addrinfo hints, *res = NULL, *ai;
  int fd = -1;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(h->tcp_host, h->tcp_port, &hints, &res) != 0 || !res) {
    tcp_drop(h, "connection failed (cannot resolve the host)", now);
    return;
  }
  for (ai = res; ai; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0)
      continue;
    (void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0 || errno == EINPROGRESS)
      break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0) {
    tcp_drop(h, "connection failed", now);
    return;
  }
  h->in_fd = h->out_fd = fd;
  h->tcp_state = TCP_CONNECTING;
}
static void tcp_flush(host *h, uint64_t now) {
  const uint8_t *data;
  size_t n;
  while (h->tcp_state == TCP_UP && (n = rnc_mcu_txq_peek(&h->txq, &data)) > 0) {
    ssize_t sent = send(h->out_fd, data, n, MSG_NOSIGNAL);
    if (sent > 0) {
      rnc_mcu_txq_consume(&h->txq, (size_t)sent);
    } else if (sent < 0 && errno == EINTR) {
      continue;
    } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return;
    } else {
      tcp_drop(h, "connection lost", now);
      return;
    }
  }
}
/* connects, finishes a connect in progress, flushes the output queue */
static void tcp_pump(host *h, uint64_t now) {
  if (h->tcp_state == TCP_DOWN && now >= h->tcp_retry_ms) {
    tcp_start(h, now);
  }
  if (h->tcp_state == TCP_CONNECTING) {
    struct pollfd p = {h->in_fd, POLLOUT, 0};
    if (poll(&p, 1, 0) > 0 && (p.revents & (POLLOUT | POLLERR | POLLHUP))) {
      int err = 0, one = 1;
      socklen_t len = sizeof(err);
      if (getsockopt(h->in_fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) {
        tcp_drop(h, "connection failed", now);
      } else {
        (void)setsockopt(h->in_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        (void)setsockopt(h->in_fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
        h->tcp_state = TCP_UP;
        rnc_mcu_backoff_reset(&h->backoff);
        fprintf(stderr, "mcu: tcp: connected to %s:%s\n", h->tcp_host, h->tcp_port);
      }
    }
  }
  tcp_flush(h, now);
}
static int host_link_up(void *context) {
  host *h = context;
  tcp_pump(h, host_now_ms(h));
  return h->tcp_state == TCP_UP;
}

static size_t host_write(void *context, const uint8_t *data, size_t size) {
  host *h = context;
  size_t done = 0;
  unsigned waits = 0;
  if (h->tcp) {
    /* one HDLC frame: queued whole or refused; a full queue is drained first */
    if (h->tcp_state != TCP_UP)
      return 0;
    if (rnc_mcu_txq_free(&h->txq) < size)
      tcp_flush(h, host_now_ms(h));
    return rnc_mcu_txq_push(&h->txq, data, size) ? size : 0;
  }
  while (done < size) {
    ssize_t n = write(h->out_fd, data + done, size - done);
    if (n > 0) {
      done += (size_t)n;
    } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && waits++ < 50) {
      struct pollfd p = {h->out_fd, POLLOUT, 0};
      (void)poll(&p, 1, 10);
    } else if (n < 0 && errno == EINTR) {
      continue;
    } else {
      break; /* nobody listening (yet): the frame is lost, as on a real wire */
    }
  }
  return done;
}
static size_t host_read(void *context, uint8_t *buffer, size_t capacity) {
  host *h = context;
  struct pollfd p = {h->in_fd, POLLIN, 0};
  ssize_t n;
  if (h->tcp) {
    if (h->tcp_state != TCP_UP)
      return 0;
    n = recv(h->in_fd, buffer, capacity, 0);
    if (n > 0)
      return (size_t)n;
    if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
      tcp_drop(h, "connection lost", host_now_ms(h));
    return 0;
  }
  if (poll(&p, 1, 0) <= 0 || !(p.revents & POLLIN))
    return 0;
  n = read(h->in_fd, buffer, capacity);
  return n > 0 ? (size_t)n : 0;
}
static int host_random(void *context, uint8_t *buffer, size_t size) {
  host *h = context;
  while (size) {
    ssize_t n = read(h->rng_fd, buffer, size);
    if (n <= 0) {
      if (n < 0 && errno == EINTR)
        continue;
      return -1;
    }
    buffer += n;
    size -= (size_t)n;
  }
  return 0;
}
static uint64_t host_now_ms(void *context) {
  struct timespec t;
  (void)context;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
static void host_log(void *context, const char *line) {
  (void)context;
  fprintf(stderr, "mcu: %s\n", line);
}
static void state_path(const host *h, const char *key, char *out, size_t size) {
  (void)snprintf(out, size, "%s/%s.bin", h->state, key);
}
static int host_persist(void *context, const char *key, const void *data, size_t size) {
  host *h = context;
  char path[640];
  FILE *f;
  state_path(h, key, path, sizeof(path));
  f = fopen(path, "wb");
  if (!f)
    return -1;
  if (fwrite(data, 1, size, f) != size) {
    fclose(f);
    return -1;
  }
  (void)chmod(path, 0600);
  return fclose(f) == 0 ? 0 : -1;
}
static int host_load(void *context, const char *key, void *buffer, size_t capacity) {
  host *h = context;
  char path[640];
  FILE *f;
  size_t n;
  state_path(h, key, path, sizeof(path));
  f = fopen(path, "rb");
  if (!f)
    return -1;
  n = fread(buffer, 1, capacity, f);
  fclose(f);
  return (int)n;
}

static int open_pty(host *h) {
  int master = posix_openpt(O_RDWR | O_NOCTTY);
  struct termios t;
  if (master < 0 || grantpt(master) || unlockpt(master))
    return -1;
  /* raw mode, set through the master so the slave starts raw */
  if (tcgetattr(master, &t) == 0) {
    t.c_iflag = 0;
    t.c_oflag = 0;
    t.c_lflag = 0;
    t.c_cflag = (t.c_cflag & ~(tcflag_t)(CSIZE | PARENB)) | CS8 | CREAD | CLOCAL;
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
    (void)tcsetattr(master, TCSANOW, &t);
  }
  (void)fcntl(master, F_SETFL, fcntl(master, F_GETFL, 0) | O_NONBLOCK);
  h->in_fd = h->out_fd = master;
  printf("pty=%s\n", ptsname(master));
  fflush(stdout);
  return 0;
}

int main(int argc, char **argv) {
  host h;
  rnc_mcu_platform platform;
  rnc_mcu_config config;
  rnc_mcu_app *app;
  int use_pty = 1, i;
  char *colon;
  const char *board = "host";
  struct sigaction sa;
  lora_host_options lopt;
  lora_host *lora = NULL;
  int lora_requested = 0;
  memset(&h, 0, sizeof(h));
  memset(&config, 0, sizeof(config));
  memset(&lopt, 0, sizeof(lopt));
  rnc_lora_cfg_init(&lopt.cfg);
  lopt.chip = 1262;
  lopt.peers = 1;
  snprintf(h.state, sizeof(h.state), ".");
  for (i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--pty"))
      use_pty = 1;
    else if (!strcmp(argv[i], "--stdio"))
      use_pty = 0;
    else if (!strcmp(argv[i], "--tcp") && i + 1 < argc) {
      snprintf(h.tcp_host, sizeof(h.tcp_host), "%s", argv[++i]);
      colon = strrchr(h.tcp_host, ':');
      if (!colon || colon == h.tcp_host || !colon[1]) {
        fprintf(stderr, "--tcp needs HOST:PORT\n");
        return 2;
      }
      *colon = 0;
      snprintf(h.tcp_port, sizeof(h.tcp_port), "%s", colon + 1);
      h.tcp = 1;
    } else if (!strcmp(argv[i], "--state") && i + 1 < argc)
      snprintf(h.state, sizeof(h.state), "%s", argv[++i]);
    else if (!strcmp(argv[i], "--announce-ms") && i + 1 < argc)
      config.announce_interval_ms = (uint32_t)strtoul(argv[++i], NULL, 10);
    else if (!strcmp(argv[i], "--board") && i + 1 < argc)
      board = argv[++i];
    else if (!strcmp(argv[i], "--lora") && i + 1 < argc) {
      lora_requested = 1;
      if (rnc_lora_cfg_set(&lopt.cfg, "mode", argv[++i]) != 0) {
        fprintf(stderr, "--lora needs leaf or gateway\n");
        return 2;
      }
    } else if (!strncmp(argv[i], "--lora-", 7) && i + 1 < argc &&
               (!strcmp(argv[i] + 7, "freq") || !strcmp(argv[i] + 7, "bw") ||
                !strcmp(argv[i] + 7, "sf") || !strcmp(argv[i] + 7, "cr") ||
                !strcmp(argv[i] + 7, "txp") || !strcmp(argv[i] + 7, "airtime"))) {
      const char *key = argv[i] + 7;
      if (rnc_lora_cfg_set(&lopt.cfg, key, argv[i + 1]) != 0) {
        fprintf(stderr, "refused value for %s\n", argv[i]);
        return 2;
      }
      i++;
    } else if (!strcmp(argv[i], "--lora-peers") && i + 1 < argc)
      lopt.peers = (unsigned)strtoul(argv[++i], NULL, 10);
    else if (!strcmp(argv[i], "--lora-loss") && i + 1 < argc)
      lopt.loss_permille = (unsigned)strtoul(argv[++i], NULL, 10);
    else if (!strcmp(argv[i], "--lora-chip") && i + 1 < argc) {
      i++;
      lopt.chip = !strcmp(argv[i], "sx1276") ? 1276 : 1262;
    } else {
      fprintf(stderr, "usage: %s [--pty | --stdio | --tcp HOST:PORT] [--state DIR] [--announce-ms N] [--board NAME]\n"
                      "          [--lora leaf|gateway --lora-freq F --lora-bw B --lora-sf N --lora-cr N --lora-txp DBM\n"
                      "           [--lora-airtime PCT] [--lora-peers N] [--lora-loss PERMILLE] [--lora-chip sx1262|sx1276]]\n",
              argv[0]);
      return 2;
    }
  }
  h.rng_fd = open("/dev/urandom", O_RDONLY);
  if (h.rng_fd < 0) {
    perror("/dev/urandom");
    return 1;
  }
  h.in_fd = h.out_fd = -1;
  if (h.tcp) {
    rnc_mcu_backoff_init(&h.backoff, TCP_BACKOFF_MIN_MS, TCP_BACKOFF_MAX_MS);
    rnc_mcu_txq_init(&h.txq, h.txq_storage, sizeof(h.txq_storage));
    h.tcp_state = TCP_DOWN;
  } else if (use_pty) {
    if (open_pty(&h)) {
      perror("pty");
      return 1;
    }
  } else {
    h.in_fd = STDIN_FILENO;
    h.out_fd = STDOUT_FILENO;
  }
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_signal;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  signal(SIGPIPE, SIG_IGN);

  memset(&platform, 0, sizeof(platform));
  platform.context = &h;
  platform.write = host_write;
  platform.read = host_read;
  platform.random = host_random;
  platform.now_ms = host_now_ms;
  platform.log = host_log;
  platform.persist = host_persist;
  platform.load = host_load;
  platform.board = board;
  if (h.tcp)
    platform.link_up = host_link_up;
  if (lora_requested) {
    int status = 0;
    lora = lora_host_new(&lopt, &status);
    if (lora) {
      config.lora = lora_host_interface(lora);
      config.lora_mode = lopt.cfg.mode;
    } else {
      fprintf(stderr, "mcu: continuing without the radio\n");
    }
  }
  /* no unix_seconds hook: the host runs the same build-epoch-plus-uptime policy as a
   * board, which is what the test needs to prove */
  app = rnc_mcu_app_new(&platform, &config);
  if (!app) {
    fprintf(stderr, "mcu: cannot start the application\n");
    return 1;
  }
  {
    uint8_t d[16];
    rnc_mcu_app_destination(app, d);
    fprintf(stderr, "mcu: destination <");
    for (i = 0; i < 16; i++)
      fprintf(stderr, "%02x", d[i]);
    fprintf(stderr, ">\n");
  }
  while (!stopping) {
    unsigned wait;
    if (lora)
      lora_host_step(lora, host_now_ms(&h) * 1000u);
    wait = rnc_mcu_app_step(app, host_now_ms(&h));
    struct pollfd p = {h.in_fd, POLLIN, 0};
    if (h.tcp) {
      tcp_pump(&h, host_now_ms(&h)); /* send what the step queued */
      p.fd = h.tcp_state == TCP_UP ? h.in_fd : -1;
    }
    (void)poll(&p, 1, (int)(wait < 10u ? wait : 10u));
    if (p.revents & (POLLHUP | POLLERR | POLLNVAL)) {
      /* a pty master reports HUP while no slave is open; avoid spinning */
      struct timespec ts = {0, 5 * 1000000L};
      nanosleep(&ts, NULL);
    }
  }
  {
    rnc_mcu_stats st;
    rnc_mcu_app_get_stats(app, &st);
    fprintf(stderr,
            "mcu: stats: announces %u rx %u rx_bad %u tx_dropped %u lora_rx %u lora_rx_bad %u lora_tx %u "
            "lora_tx_dropped %u\n",
            (unsigned)st.announces, (unsigned)st.rx_packets, (unsigned)st.rx_bad,
            (unsigned)st.tx_dropped, (unsigned)st.lora_rx_packets, (unsigned)st.lora_rx_bad,
            (unsigned)st.lora_tx_packets, (unsigned)st.lora_tx_dropped);
  }
  rnc_mcu_app_free(app);
  lora_host_free(lora);
  return 0;
}
