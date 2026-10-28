/* Host build of the MCU example application: the same rnc_mcu_app the firmware
 * runs, with a pty (or stdin/stdout) as the serial transport, /dev/urandom for
 * randomness and files for persistence. It lets CI exercise the firmware logic
 * with no hardware.
 *
 *   reticulum-c-mcu-host [--pty | --stdio] [--state DIR] [--announce-ms N]
 *                        [--board NAME]
 *
 * --pty    (default) creates a pseudo terminal and prints "pty=/dev/pts/N" on
 *          stdout; point a SerialInterface at that path.
 * --stdio  bytes come from stdin and go to stdout (for example under socat).
 * --state  directory for the persisted identity and clock mark (default ".").
 * The process ends on SIGINT or SIGTERM. */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include "rnc_mcu_app.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

typedef struct host {
  int in_fd, out_fd, rng_fd;
  char state[512];
} host;

static volatile sig_atomic_t stopping;
static void on_signal(int sig) {
  (void)sig;
  stopping = 1;
}

static size_t host_write(void *context, const uint8_t *data, size_t size) {
  host *h = context;
  size_t done = 0;
  unsigned waits = 0;
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
  const char *board = "host";
  struct sigaction sa;
  memset(&h, 0, sizeof(h));
  memset(&config, 0, sizeof(config));
  snprintf(h.state, sizeof(h.state), ".");
  for (i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--pty"))
      use_pty = 1;
    else if (!strcmp(argv[i], "--stdio"))
      use_pty = 0;
    else if (!strcmp(argv[i], "--state") && i + 1 < argc)
      snprintf(h.state, sizeof(h.state), "%s", argv[++i]);
    else if (!strcmp(argv[i], "--announce-ms") && i + 1 < argc)
      config.announce_interval_ms = (uint32_t)strtoul(argv[++i], NULL, 10);
    else if (!strcmp(argv[i], "--board") && i + 1 < argc)
      board = argv[++i];
    else {
      fprintf(stderr, "usage: %s [--pty | --stdio] [--state DIR] [--announce-ms N] [--board NAME]\n",
              argv[0]);
      return 2;
    }
  }
  h.rng_fd = open("/dev/urandom", O_RDONLY);
  if (h.rng_fd < 0) {
    perror("/dev/urandom");
    return 1;
  }
  if (use_pty) {
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
    unsigned wait = rnc_mcu_app_step(app, host_now_ms(&h));
    struct pollfd p = {h.in_fd, POLLIN, 0};
    (void)poll(&p, 1, (int)(wait < 10u ? wait : 10u));
    if (p.revents & (POLLHUP | POLLERR | POLLNVAL)) {
      /* a pty master reports HUP while no slave is open; avoid spinning */
      struct timespec ts = {0, 5 * 1000000L};
      nanosleep(&ts, NULL);
    }
  }
  rnc_mcu_app_free(app);
  return 0;
}
