/* reticulum-c-flash --stamp against an emulated setup console (mcu/app/rnc_mcu_net.h) on a pty: the tool reads the
 * board's stamp material, searches a stamp over it, sets and saves it, and restarts the board. */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1 /* cfmakeraw */
#include <fcntl.h>
#include <poll.h>
#include <reticulum_c/rnc_netstamp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                  \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

static int master;
static uint8_t material[90];
static char material_hex[181];
static int refuse_stamp, no_console, identity_missing;
static int entered, got_stamp, saved, stamp_saved, rebooted;
static uint8_t stamp_got[14];

static void say(const char *text) { CHECK(write(master, text, strlen(text)) == (ssize_t)strlen(text)); }
static void line_in(char *line) {
  if (no_console)
    return;
  if (strstr(line, "rnc-config")) {
    if (!entered)
      say("\r\nrnc> ");
    entered = 1;
    return;
  }
  if (!entered)
    return;
  if (!strncmp(line, "get stamp.material", 18)) {
    if (identity_missing)
      say("stamp.material=(not yet: boot once to create the identity)\r\nrnc> ");
    else {
      char out[300];
      snprintf(out, sizeof(out), "stamp.material=%s\r\nrnc> ", material_hex);
      say(out);
    }
  } else if (!strncmp(line, "set stamp ", 10)) {
    uint8_t s[14];
    size_t i;
    int ok = !refuse_stamp && strlen(line + 10) == 28;
    for (i = 0; ok && i < 14; i++) {
      unsigned v;
      ok = sscanf(line + 10 + 2 * i, "%2x", &v) == 1;
      s[i] = (uint8_t)v;
    }
    if (ok && rnc_netstamp_valid(material, sizeof(material), s, 14, 6.0)) {
      memcpy(stamp_got, s, 14);
      got_stamp = 1;
      say("ok (not stored until save)\r\nrnc> ");
    } else {
      say("error: refused (see help)\r\nrnc> ");
    }
  } else if (!strncmp(line, "save", 4)) {
    saved = 1;
    stamp_saved = got_stamp;
    say(got_stamp ? "saving\r\nstored\r\nstamp stored\r\nrnc> " : "saving\r\nstored\r\nrnc> ");
  } else if (!strncmp(line, "reboot", 6)) {
    rebooted = 1;
    say("rebooting\r\n");
  }
}
static int run(const char *tool, char *const extra[], const char *slave, unsigned seconds) {
  char *argv[16];
  size_t k = 0, i, n = 0;
  char line[512];
  pid_t child;
  int status;
  time_t end = time(NULL) + (time_t)seconds;
  argv[k++] = (char *)tool;
  argv[k++] = "--port";
  argv[k++] = (char *)slave;
  for (i = 0; extra[i] && k < 14; ++i)
    argv[k++] = extra[i];
  argv[k] = NULL;
  child = fork();
  CHECK(child >= 0);
  if (!child) {
    int null = open("/dev/null", O_WRONLY);
    dup2(null, 1);
    execv(tool, argv);
    _exit(127);
  }
  for (;;) {
    struct pollfd p = {master, POLLIN, 0};
    pid_t r = waitpid(child, &status, WNOHANG);
    if (r == child)
      return WIFEXITED(status) ? WEXITSTATUS(status) : 255;
    CHECK(time(NULL) < end);
    if (poll(&p, 1, 50) > 0 && (p.revents & POLLIN)) {
      uint8_t c;
      while (read(master, &c, 1) == 1) {
        if (c == '\n' || c == '\r') {
          if (n) {
            line[n] = 0;
            line_in(line);
          }
          n = 0;
        } else if (n + 1 < sizeof(line)) {
          line[n++] = (char)c;
        }
      }
    }
  }
}
static void reset(void) {
  refuse_stamp = no_console = identity_missing = 0;
  entered = got_stamp = saved = stamp_saved = rebooted = 0;
}
int main(int argc, char **argv) {
  char *slave;
  size_t i;
  CHECK(argc == 2);
  for (i = 0; i < sizeof(material); i++)
    material[i] = (uint8_t)(i * 5 + 3);
  for (i = 0; i < sizeof(material); i++)
    sprintf(material_hex + 2 * i, "%02x", material[i]);
  master = posix_openpt(O_RDWR | O_NOCTTY);
  CHECK(master >= 0 && grantpt(master) == 0 && unlockpt(master) == 0);
  slave = ptsname(master);
  CHECK(slave);
  {
    struct termios t;
    int s = open(slave, O_RDWR | O_NOCTTY); /* keep a slave open so the master never sees a hangup */
    CHECK(s >= 0 && tcgetattr(s, &t) == 0);
    cfmakeraw(&t);
    CHECK(tcsetattr(s, TCSANOW, &t) == 0);
  }
  fcntl(master, F_SETFL, O_NONBLOCK);
  {
    char *args[] = {"--stamp", "--stamp-value", "6", "--no-reset", NULL};
    /* the whole flow: material read, a stamp found over it, set, saved, board restarted */
    reset();
    CHECK(run(argv[1], args, slave, 60) == 0);
    CHECK(entered && got_stamp && saved && stamp_saved && rebooted);
    CHECK(rnc_netstamp_valid(material, sizeof(material), stamp_got, 14, 6.0));
    /* a board that refuses the stamp is reported, and nothing is saved as stamped */
    reset();
    refuse_stamp = 1;
    CHECK(run(argv[1], args, slave, 60) != 0 && !stamp_saved);
    /* no identity yet: the tool says so and fails without searching */
    reset();
    identity_missing = 1;
    CHECK(run(argv[1], args, slave, 60) != 0 && !got_stamp);
  }
  {
    char *args[] = {"--stamp", "--stamp-value", "6", "--no-reset", "--stamp-wait", "2", NULL};
    /* a board that never opens the console */
    reset();
    no_console = 1;
    CHECK(run(argv[1], args, slave, 60) != 0 && !got_stamp);
  }
  puts("flash stamp tests passed");
  return 0;
}
