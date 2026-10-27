/* reticulum-c-sh: remote shell compatible with the reference rnsh (protocol 1).
 *
 *   reticulum-c-sh --connect HOST:PORT --identity FILE -l -a HASH... [-b SECS]
 *                  [-C | -A] [-- PROGRAM [ARGS...]]
 *   reticulum-c-sh --connect HOST:PORT --identity FILE [-m] [-N] [-w SECS]
 *                  DESTINATION [-- COMMAND [ARGS...]]
 *
 * The listener runs PROGRAM (default: $SHELL, else /bin/sh) or the command the
 * initiator asks for, on a pty when the initiator is a terminal and on pipes
 * otherwise, for identities on its allow list. There is no "accept anyone"
 * option. The initiator puts a terminal into raw mode, forwards window size
 * changes and understands the "~." escape after a newline. It attaches to a
 * node over TCP, like reticulum-c-cp. */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include "msgpack_tree.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/rand.h>
#include <poll.h>
#include <reticulum_c/rnc_buffer.h>
#include <reticulum_c/rnc_host.h>
#include <reticulum_c/rnc_ipc.h>
#include <reticulum_c/rnc_link.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define APP_NAME "rnsh"
#define SW_VERSION "rnsh-c 0.1"
#define PROTOCOL_VERSION 1
#define MSG(n) ((uint16_t)(0xac00u | (n)))
#define MSG_NOOP MSG(0)
#define MSG_VERSION MSG(5)
#define MSG_WINDOW MSG(2)
#define MSG_EXECUTE MSG(3)
#define MSG_STREAM MSG(4)
#define MSG_ERROR MSG(6)
#define MSG_EXITED MSG(7)
#define STREAM_STDIN 0
#define STREAM_STDOUT 1
#define STREAM_STDERR 2
#define SESSIONS 4
#define BUF_MAX (64u * 1024u)
#define STDIN_MAX (4u * 1024u * 1024u)
#define STATE_TIMEOUT_MS 15000u
#define PIPE_DRAIN_MS 1000u
#define EXIT_WAIT_MS 10000u

static volatile sig_atomic_t stopping, winch;
static void on_signal(int sig) {
  (void)sig;
  stopping = 1;
}
static void on_winch(int sig) {
  (void)sig;
  winch = 1;
}
static rnc_result secure_random(void *context, uint8_t *out, size_t size) {
  (void)context;
  return size <= INT_MAX && RAND_priv_bytes(out, (int)size) == 1 ? RNC_OK
                                                                 : RNC_CRYPTO;
}
static uint64_t monotonic_ms(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
static void print_hex(const uint8_t *data, size_t size) {
  size_t i;
  for (i = 0; i < size; ++i)
    printf("%02x", data[i]);
}
static void hex_string(const uint8_t *data, size_t size, char *out) {
  size_t i;
  for (i = 0; i < size; ++i)
    sprintf(out + 2 * i, "%02x", data[i]);
}
static int hex_decode(const char *text, uint8_t *out, size_t size) {
  size_t i;
  if (strlen(text) != size * 2)
    return 0;
  for (i = 0; i < size; ++i) {
    char pair[3] = {text[2 * i], text[2 * i + 1], 0};
    char *end;
    if (pair[0] == '+' || pair[0] == '-' || pair[0] == ' ')
      return 0;
    out[i] = (uint8_t)strtoul(pair, &end, 16);
    if (*end)
      return 0;
  }
  return 1;
}
static void set_nonblock(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags >= 0)
    (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* ---- options and node setup (as in reticulum-c-x) ------------------------ */
typedef struct options {
  const char *connect, *identity;
  int listen, no_remote_command, remote_args, mirror, no_id;
  long announce; /* -1 = never */
  double timeout;
  uint8_t allowed[32][16];
  size_t allowed_count;
  char **command; /* after -- */
  int command_count;
} options;
static options opt;
typedef struct app {
  rnc_node *node;
  rnc_host *host;
} app;
static int open_node(rnc_identity *id, app *a) {
  rnc_host_config hc;
  char address[256];
  const char *colon = strrchr(opt.connect, ':');
  unsigned long port;
  char *end;
  if (!colon || colon == opt.connect ||
      (size_t)(colon - opt.connect) >= sizeof(address))
    return 0;
  memcpy(address, opt.connect, (size_t)(colon - opt.connect));
  address[colon - opt.connect] = 0;
  port = strtoul(colon + 1, &end, 10);
  if (*end || !port || port > 65535)
    return 0;
  if (rnc_host_identity_load(opt.identity, secure_random, NULL, id) != RNC_OK) {
    fprintf(stderr, "Cannot load or create the identity file %s\n",
            opt.identity);
    return 0;
  }
  a->node = rnc_node_new(id, 0, secure_random, NULL);
  a->host = a->node ? rnc_host_new(a->node) : NULL;
  if (!a->host)
    return 0;
  memset(&hc, 0, sizeof(hc));
  hc.kind = RNC_HOST_TCP_CONNECT;
  hc.name = "rnsh link";
  hc.address = address;
  hc.port = (uint16_t)port;
  hc.mtu = RNC_MAX_MTU;
  hc.bitrate = 1000000000u;
  if (rnc_host_add(a->host, 1, &hc) != RNC_OK) {
    fprintf(stderr, "Cannot connect to %s: %s\n", opt.connect, strerror(errno));
    return 0;
  }
  return 1;
}

/* ---- messages ----------------------------------------------------------- */
static int channel_ready(rnc_link *link) {
  return rnc_link_channel_pending(link) < rnc_link_channel_window(link);
}
static rnc_result send_message(rnc_link *link, uint16_t type, const uint8_t *data,
                               size_t size, uint64_t now) {
  return rnc_link_send(link, type, data, size, now);
}
static rnc_result send_version(rnc_link *link, uint64_t now) {
  uint8_t buf[64];
  rnc_rpc_writer w;
  size_t n;
  rnc_rpc_writer_init(&w, buf, sizeof(buf));
  (void)rnc_rpc_write_array(&w, 2);
  (void)rnc_rpc_write_string(&w, SW_VERSION);
  (void)rnc_rpc_write_uint(&w, PROTOCOL_VERSION);
  if (rnc_rpc_writer_finish(&w, &n) != RNC_OK)
    return RNC_INVALID;
  return send_message(link, MSG_VERSION, buf, n, now);
}
static rnc_result send_error(rnc_link *link, const char *text, int fatal,
                             uint64_t now) {
  uint8_t buf[256];
  rnc_rpc_writer w;
  size_t n;
  rnc_rpc_writer_init(&w, buf, sizeof(buf));
  (void)rnc_rpc_write_array(&w, 3);
  (void)rnc_rpc_write_string(&w, text);
  (void)rnc_rpc_write_bool(&w, fatal);
  (void)rnc_rpc_write_nil(&w);
  if (rnc_rpc_writer_finish(&w, &n) != RNC_OK)
    return RNC_INVALID;
  return send_message(link, MSG_ERROR, buf, n, now);
}
static rnc_result send_exited(rnc_link *link, int code, uint64_t now) {
  uint8_t buf[16];
  rnc_rpc_writer w;
  size_t n;
  rnc_rpc_writer_init(&w, buf, sizeof(buf));
  (void)rnc_rpc_write_int(&w, code);
  if (rnc_rpc_writer_finish(&w, &n) != RNC_OK)
    return RNC_INVALID;
  return send_message(link, MSG_EXITED, buf, n, now);
}
/* Sends up to one channel message of stream data; *consumed bytes were taken. */
static rnc_result send_stream(rnc_link *link, unsigned stream, const uint8_t *data,
                              size_t size, int eof, size_t *consumed,
                              uint64_t now) {
  uint8_t buf[RNC_LINK_MAX_MDU + 16];
  size_t written = 0;
  size_t limit = rnc_link_channel_mdu(link);
  rnc_result r;
  if (limit < 8 || limit > sizeof(buf))
    return RNC_INVALID;
  r = rnc_stream_encode((uint16_t)stream, data, size, eof, 0, buf, limit,
                        &written, consumed);
  if (r != RNC_OK)
    return r;
  return send_message(link, MSG_STREAM, buf, written, now);
}
/* Reads a nil-or-uint value from a tree node. */
static unsigned opt_uint(const val *v) {
  return v->type == V_UINT ? (unsigned)v->u : 0;
}

/* ---- listener ----------------------------------------------------------- */
enum sstate { S_WAIT_IDENT = 1, S_WAIT_VERS, S_WAIT_CMD, S_RUNNING, S_ENDING };
typedef struct session {
  int used;
  enum sstate state;
  rnc_link *link;
  uint8_t id[16], remote[16];
  int identified, authenticated;
  uint64_t state_since, exit_sent_at, end_at;
  /* process */
  pid_t pid;
  int in_fd, out_fd, err_fd, is_pty, exited, exit_code, code_sent;
  uint64_t exited_at;
  uint8_t outbuf[BUF_MAX], errbuf[BUF_MAX];
  size_t out_len, err_len;
  int out_eof, err_eof, out_eof_sent, err_eof_sent;
  uint8_t *stdin_buf;
  size_t stdin_len, stdin_cap;
  int stdin_eof, stdin_closed;
} session;
static session sessions[SESSIONS];

static void set_state(session *s, enum sstate state, uint64_t now) {
  s->state = state;
  s->state_since = now;
}
static void process_close(session *s) {
  if (s->out_fd >= 0)
    close(s->out_fd);
  if (s->err_fd >= 0 && s->err_fd != s->out_fd)
    close(s->err_fd);
  if (s->in_fd >= 0 && s->in_fd != s->out_fd)
    close(s->in_fd);
  s->in_fd = s->out_fd = s->err_fd = -1;
}
static void session_release(app *a, session *s) {
  if (!s->used)
    return;
  if (s->pid > 0 && !s->exited) {
    /* ask politely, then insist: a program may ignore HUP and TERM */
    unsigned waited;
    int reaped = 0;
    (void)kill(s->pid, SIGHUP);
    (void)kill(s->pid, SIGTERM);
    for (waited = 0; waited < 50 && !reaped; waited++) {
      struct timespec nap = {0, 10000000};
      reaped = waitpid(s->pid, NULL, WNOHANG) == s->pid;
      if (!reaped)
        nanosleep(&nap, NULL);
    }
    if (!reaped) {
      (void)kill(s->pid, SIGKILL);
      (void)waitpid(s->pid, NULL, 0);
    }
  }
  process_close(s);
  (void)rnc_node_unbind_link(a->node, s->id);
  rnc_link_free(s->link);
  free(s->stdin_buf);
  memset(s, 0, sizeof(*s));
  s->in_fd = s->out_fd = s->err_fd = -1;
}
static void terminate(session *s, const char *why, uint64_t now) {
  if (s->state == S_ENDING)
    return;
  if (why)
    (void)send_error(s->link, why, 1, now);
  if (s->pid > 0 && !s->exited)
    (void)kill(s->pid, SIGTERM);
  set_state(s, S_ENDING, now);
  s->end_at = now + 1500u; /* let the error reach the initiator */
}
static int is_allowed(const uint8_t hash[16]) {
  size_t i;
  for (i = 0; i < opt.allowed_count; i++)
    if (!memcmp(opt.allowed[i], hash, 16))
      return 1;
  return 0;
}

/* Starts the command. Returns 0 on success. */
static int start_process(session *s, char *const *argv, const char *term,
                         int pipe_in, int pipe_out, int pipe_err,
                         unsigned rows, unsigned cols, unsigned hpix,
                         unsigned vpix) {
  int master = -1, slave = -1, p_in[2] = {-1, -1}, p_out[2] = {-1, -1},
      p_err[2] = {-1, -1};
  int use_pty = !(pipe_in && pipe_out && pipe_err);
  pid_t pid;
  char ident[64] = "<>";
  if (use_pty) {
    master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0 || grantpt(master) < 0 || unlockpt(master) < 0)
      return -1;
    {
      const char *name = ptsname(master);
      if (!name)
        return -1;
      slave = open(name, O_RDWR | O_NOCTTY);
      if (slave < 0)
        return -1;
    }
    if (rows && cols) {
      struct winsize ws;
      memset(&ws, 0, sizeof(ws));
      ws.ws_row = (unsigned short)rows;
      ws.ws_col = (unsigned short)cols;
      ws.ws_xpixel = (unsigned short)hpix;
      ws.ws_ypixel = (unsigned short)vpix;
      (void)ioctl(master, TIOCSWINSZ, &ws);
    }
  }
  if ((pipe_in && pipe(p_in)) || (pipe_out && pipe(p_out)) ||
      (pipe_err && pipe(p_err)))
    return -1;
  if (s->identified) {
    ident[0] = '<';
    hex_string(s->remote, 16, ident + 1);
    strcpy(ident + 33, ">");
  }
  pid = fork();
  if (pid < 0)
    return -1;
  if (!pid) {
    int fd;
    (void)dup2(pipe_in ? p_in[0] : slave, 0);
    (void)dup2(pipe_out ? p_out[1] : slave, 1);
    (void)dup2(pipe_err ? p_err[1] : slave, 2);
    for (fd = 3; fd < 256; fd++)
      close(fd);
    if (use_pty) {
      (void)setsid();
      (void)ioctl(pipe_in ? (pipe_out ? 2 : 1) : 0, TIOCSCTTY, 0);
    }
    (void)setenv("TERM", term && *term ? term : "xterm", 1);
    (void)setenv("RNS_REMOTE_IDENTITY", ident, 1);
    execvp(argv[0], argv);
    fprintf(stderr, "Unable to start %s: %s\n", argv[0], strerror(errno));
    _exit(255);
  }
  s->pid = pid;
  s->is_pty = use_pty;
  if (slave >= 0)
    close(slave);
  if (pipe_in) {
    close(p_in[0]);
    s->in_fd = p_in[1];
  } else
    s->in_fd = master;
  if (pipe_out) {
    close(p_out[1]);
    s->out_fd = p_out[0];
  } else
    s->out_fd = master;
  if (pipe_err) {
    close(p_err[1]);
    s->err_fd = p_err[0];
  } else
    s->err_fd = master; /* same descriptor as stdout on a pty */
  set_nonblock(s->in_fd);
  set_nonblock(s->out_fd);
  set_nonblock(s->err_fd);
  if (s->err_fd == s->out_fd)
    s->err_eof = s->err_eof_sent = 1;
  return 0;
}

static void handle_execute(session *s, const uint8_t *data, size_t size,
                           uint64_t now) {
  val pool[64];
  reader rd = {data, data + size, pool, 0, 64};
  val root;
  char *argv[64], default_buf[1];
  char storage[4096];
  size_t used = 0, argc = 0, i;
  const char *term = NULL;
  char termbuf[128];
  (void)default_buf;
  if (!parse(&rd, &root, 0) || root.type != V_ARR || root.n != 10) {
    terminate(s, "Protocol error (WAIT_CMD)", now);
    return;
  }
  /* base command: the listener's program, else the user's shell */
  if (opt.command_count > 0) {
    for (i = 0; i < (size_t)opt.command_count && argc < 60; i++)
      argv[argc++] = opt.command[i];
  } else {
    const char *shell = getenv("SHELL");
    argv[argc++] = (char *)(shell && *shell ? shell : "/bin/sh");
  }
  if (root.kids[0].type == V_ARR && root.kids[0].n > 0) {
    if (opt.no_remote_command) {
      terminate(s, "Remote command line not allowed by listener", now);
      return;
    }
    if (!opt.remote_args)
      argc = 0;
    for (i = 0; i < root.kids[0].n && argc < 60; i++) {
      const val *w = &root.kids[0].kids[i];
      if ((w->type != V_STR && w->type != V_BIN) || used + w->n + 1 > sizeof(storage)) {
        terminate(s, "Invalid command line", now);
        return;
      }
      memcpy(storage + used, w->p, w->n);
      storage[used + w->n] = 0;
      argv[argc++] = storage + used;
      used += w->n + 1;
    }
  }
  argv[argc] = NULL;
  if (root.kids[5].type == V_STR && root.kids[5].n < sizeof(termbuf)) {
    memcpy(termbuf, root.kids[5].p, root.kids[5].n);
    termbuf[root.kids[5].n] = 0;
    term = termbuf;
  }
  printf("Executing %s", argv[0]);
  if (s->identified) {
    fputs(" for <", stdout);
    print_hex(s->remote, 16);
    putchar('>');
  }
  putchar('\n');
  fflush(stdout);
  set_state(s, S_RUNNING, now);
  if (start_process(s, argv, term, root.kids[1].u != 0 && root.kids[1].type == V_BOOL,
                    root.kids[2].u != 0 && root.kids[2].type == V_BOOL,
                    root.kids[3].u != 0 && root.kids[3].type == V_BOOL,
                    opt_uint(&root.kids[6]), opt_uint(&root.kids[7]),
                    opt_uint(&root.kids[8]), opt_uint(&root.kids[9])) != 0)
    terminate(s, "Unable to start process", now);
}
static void handle_stdin(session *s, const uint8_t *data, size_t size) {
  uint8_t chunk[RNC_LINK_MAX_MDU + 16];
  uint16_t stream = 0;
  int eof = 0;
  size_t n = 0;
  if (rnc_stream_decode(data, size, &stream, &eof, chunk, sizeof(chunk), &n) !=
          RNC_OK ||
      stream != STREAM_STDIN)
    return;
  if (n) {
    if (s->stdin_len + n > s->stdin_cap) {
      size_t cap = s->stdin_cap ? s->stdin_cap : 4096;
      uint8_t *grown;
      while (cap < s->stdin_len + n)
        cap *= 2;
      if (cap > STDIN_MAX)
        return;
      grown = realloc(s->stdin_buf, cap);
      if (!grown)
        return;
      s->stdin_buf = grown;
      s->stdin_cap = cap;
    }
    memcpy(s->stdin_buf + s->stdin_len, chunk, n);
    s->stdin_len += n;
  }
  if (eof)
    s->stdin_eof = 1;
}
static void handle_message(session *s, const rnc_link_event *e, uint64_t now) {
  if (s->state == S_ENDING)
    return;
  if (s->state == S_WAIT_IDENT)
    return; /* ignored until the initiator has identified */
  if (s->state == S_WAIT_VERS) {
    val pool[8];
    reader rd = {e->data, e->data + e->size, pool, 0, 8};
    val root;
    if (e->message_type != MSG_VERSION || !parse(&rd, &root, 0) ||
        root.type != V_ARR || root.n != 2) {
      terminate(s, "Protocol error (WAIT_VERS)", now);
      return;
    }
    if (root.kids[1].type != V_UINT || root.kids[1].u != PROTOCOL_VERSION) {
      terminate(s, "Incompatible protocol", now);
      return;
    }
    (void)send_version(s->link, now);
    set_state(s, S_WAIT_CMD, now);
    return;
  }
  if (s->state == S_WAIT_CMD) {
    if (e->message_type != MSG_EXECUTE) {
      terminate(s, "Protocol error (WAIT_CMD)", now);
      return;
    }
    handle_execute(s, e->data, e->size, now);
    return;
  }
  if (s->state == S_RUNNING) {
    if (e->message_type == MSG_WINDOW) {
      val pool[8];
      reader rd = {e->data, e->data + e->size, pool, 0, 8};
      val root;
      if (parse(&rd, &root, 0) && root.type == V_ARR && root.n == 4 &&
          s->is_pty && s->out_fd >= 0) {
        struct winsize ws;
        memset(&ws, 0, sizeof(ws));
        ws.ws_row = (unsigned short)opt_uint(&root.kids[0]);
        ws.ws_col = (unsigned short)opt_uint(&root.kids[1]);
        ws.ws_xpixel = (unsigned short)opt_uint(&root.kids[2]);
        ws.ws_ypixel = (unsigned short)opt_uint(&root.kids[3]);
        (void)ioctl(s->out_fd, TIOCSWINSZ, &ws);
      }
    } else if (e->message_type == MSG_STREAM)
      handle_stdin(s, e->data, e->size);
    else if (e->message_type == MSG_NOOP)
      (void)send_message(s->link, MSG_NOOP, NULL, 0, now);
  }
}
static void session_io(session *s, uint64_t now) {
  uint8_t buf[4096];
  ssize_t n;
  int status;
  /* stdin to the process */
  if (s->in_fd >= 0 && s->stdin_len) {
    n = write(s->in_fd, s->stdin_buf, s->stdin_len);
    if (n > 0) {
      memmove(s->stdin_buf, s->stdin_buf + n, s->stdin_len - (size_t)n);
      s->stdin_len -= (size_t)n;
    } else if (n < 0 && errno != EAGAIN && errno != EINTR)
      s->stdin_len = 0;
  }
  if (s->stdin_eof && !s->stdin_len && !s->stdin_closed && s->in_fd >= 0) {
    if (s->is_pty && s->in_fd == s->out_fd) {
      uint8_t eot = 0x04;
      (void)!write(s->in_fd, &eot, 1);
    } else {
      close(s->in_fd);
      s->in_fd = -1;
    }
    s->stdin_closed = 1;
  }
  /* output from the process */
  if (s->out_fd >= 0 && !s->out_eof && s->out_len < BUF_MAX - sizeof(buf)) {
    n = read(s->out_fd, buf, sizeof(buf));
    if (n > 0) {
      memcpy(s->outbuf + s->out_len, buf, (size_t)n);
      s->out_len += (size_t)n;
    } else if (n == 0 || (errno != EAGAIN && errno != EINTR))
      s->out_eof = 1;
  }
  if (s->err_fd >= 0 && s->err_fd != s->out_fd && !s->err_eof &&
      s->err_len < BUF_MAX - sizeof(buf)) {
    n = read(s->err_fd, buf, sizeof(buf));
    if (n > 0) {
      memcpy(s->errbuf + s->err_len, buf, (size_t)n);
      s->err_len += (size_t)n;
    } else if (n == 0 || (errno != EAGAIN && errno != EINTR))
      s->err_eof = 1;
  }
  if (!s->exited && s->pid > 0 && waitpid(s->pid, &status, WNOHANG) == s->pid) {
    s->exited = 1;
    s->exited_at = now;
    s->exit_code = WIFSIGNALED(status) ? WTERMSIG(status) : WEXITSTATUS(status);
  }
  /* once the process is gone, give pipes a moment to drain then call it EOF */
  if (s->exited && now > s->exited_at + PIPE_DRAIN_MS) {
    s->out_eof = 1;
    s->err_eof = 1;
  }
}
static void session_output(session *s, uint64_t now) {
  size_t used = 0;
  while (channel_ready(s->link)) {
    rnc_result r;
    if (s->err_len) {
      r = send_stream(s->link, STREAM_STDERR, s->errbuf, s->err_len, 0, &used, now);
      if (r != RNC_OK)
        return;
      memmove(s->errbuf, s->errbuf + used, s->err_len - used);
      s->err_len -= used;
    } else if (s->out_len) {
      r = send_stream(s->link, STREAM_STDOUT, s->outbuf, s->out_len, 0, &used, now);
      if (r != RNC_OK)
        return;
      memmove(s->outbuf, s->outbuf + used, s->out_len - used);
      s->out_len -= used;
    } else if (s->err_eof && !s->err_eof_sent) {
      if (send_stream(s->link, STREAM_STDERR, NULL, 0, 1, &used, now) != RNC_OK)
        return;
      s->err_eof_sent = 1;
    } else if (s->out_eof && !s->out_eof_sent) {
      if (send_stream(s->link, STREAM_STDOUT, NULL, 0, 1, &used, now) != RNC_OK)
        return;
      s->out_eof_sent = 1;
    } else if (s->exited && s->out_eof_sent && s->err_eof_sent && !s->code_sent) {
      if (send_exited(s->link, s->exit_code, now) != RNC_OK)
        return;
      s->code_sent = 1;
      s->exit_sent_at = now;
      return;
    } else
      return;
  }
}
static rnc_result accept_link(app *a, const rnc_identity *id,
                              const uint8_t destination[16],
                              const rnc_node_event *event, uint64_t now) {
  session *s = NULL;
  size_t i;
  rnc_result r;
  for (i = 0; i < SESSIONS; i++)
    if (!sessions[i].used) {
      s = &sessions[i];
      break;
    }
  if (!s)
    return RNC_NO_SPACE;
  memset(s, 0, sizeof(*s));
  s->in_fd = s->out_fd = s->err_fd = -1;
  s->link = rnc_link_new(secure_random, NULL);
  if (!s->link)
    return RNC_NO_SPACE;
  r = rnc_link_accept(s->link, id, destination, &event->packet, now);
  if (r == RNC_OK)
    r = rnc_link_address(s->link, s->id);
  if (r == RNC_OK)
    r = rnc_node_bind_link_on(a->node, s->id, event->interface_id);
  if (r != RNC_OK) {
    rnc_link_free(s->link);
    memset(s, 0, sizeof(*s));
    s->in_fd = s->out_fd = s->err_fd = -1;
    return r;
  }
  s->used = 1;
  set_state(s, S_WAIT_IDENT, now);
  return RNC_OK;
}
static void listener_tick(app *a, uint64_t unix_now, uint64_t now) {
  size_t i;
  for (i = 0; i < SESSIONS; i++) {
    session *s = &sessions[i];
    rnc_link_event le;
    int closed = 0;
    if (!s->used)
      continue;
    (void)rnc_link_tick(s->link, now);
    while (rnc_link_poll(s->link, &le) == RNC_OK) {
      if (le.type == RNC_LINK_SEND)
        (void)rnc_node_send(a->node, &le.packet, unix_now, now);
      else if (le.type == RNC_LINK_IDENTIFIED) {
        s->identified = 1;
        memcpy(s->remote, le.identity_hash, 16);
        if (is_allowed(s->remote)) {
          s->authenticated = 1;
          if (s->state == S_WAIT_IDENT)
            set_state(s, S_WAIT_VERS, now);
        } else {
          printf("Identity <");
          print_hex(s->remote, 16);
          puts("> not allowed");
          fflush(stdout);
          terminate(s, "Identity not allowed", now);
        }
      } else if (le.type == RNC_LINK_MESSAGE)
        handle_message(s, &le, now);
      else if (le.type == RNC_LINK_CLOSED)
        closed = 1;
    }
    if (!closed && s->state == S_RUNNING) {
      session_io(s, now);
      session_output(s, now);
      if (s->code_sent && now > s->exit_sent_at + EXIT_WAIT_MS)
        terminate(s, NULL, now);
    }
    if (!closed && s->state != S_ENDING && s->state != S_RUNNING &&
        now > s->state_since + STATE_TIMEOUT_MS)
      terminate(s, "Protocol timeout error", now);
    /* queued packets leave without waiting for the next tick */
    while (rnc_link_poll(s->link, &le) == RNC_OK) {
      if (le.type == RNC_LINK_SEND)
        (void)rnc_node_send(a->node, &le.packet, unix_now, now);
      else if (le.type == RNC_LINK_CLOSED)
        closed = 1;
    }
    if (s->state == S_ENDING && now >= s->end_at && !closed) {
      (void)rnc_link_close(s->link, now);
      while (rnc_link_poll(s->link, &le) == RNC_OK)
        if (le.type == RNC_LINK_SEND)
          (void)rnc_node_send(a->node, &le.packet, unix_now, now);
      closed = 1;
    }
    if (closed)
      session_release(a, s);
  }
}
static int pump_host(app *a, int listener, uint64_t *unix_out) {
  rnc_host_event event;
  uint64_t unix_now = (uint64_t)time(NULL), now = monotonic_ms();
  (void)listener;
  *unix_out = unix_now;
  if (rnc_host_step(a->host, 10, unix_now, now) != RNC_OK)
    return 0;
  return 1;
  (void)event;
}

static int listen_mode(rnc_identity *id, app *a) {
  uint8_t destination[16];
  uint64_t next_announce = 0;
  int announced = opt.announce < 0;
  size_t i;
  if (rnc_node_add_destination(a->node, id, APP_NAME, NULL, 0, destination) !=
      RNC_OK)
    return 1;
  for (i = 0; i < SESSIONS; i++)
    sessions[i].in_fd = sessions[i].out_fd = sessions[i].err_fd = -1;
  if (!opt.allowed_count)
    fprintf(stderr,
            "Warning: No allowed identities configured, rnsh will not accept "
            "any connections!\n");
  fputs("rnsh listening for commands on <", stdout);
  print_hex(destination, 16);
  puts(">");
  fflush(stdout);
  while (!stopping) {
    rnc_host_event event;
    uint64_t unix_now, now;
    if (!pump_host(a, 1, &unix_now))
      return 1;
    now = monotonic_ms();
    while (rnc_host_poll(a->host, &event) == RNC_OK) {
      const rnc_packet *p;
      if (event.type != RNC_HOST_NODE || event.node.type != RNC_NODE_LOCAL)
        continue;
      p = &event.node.packet;
      if ((p->flags & 3u) == RNC_LINKREQUEST) {
        if (!memcmp(p->destination, destination, 16))
          (void)accept_link(a, id, destination, &event.node, now);
        continue;
      }
      for (i = 0; i < SESSIONS; i++)
        if (sessions[i].used && !memcmp(sessions[i].id, p->destination, 16))
          (void)rnc_link_input(sessions[i].link, p, now);
    }
    listener_tick(a, unix_now, now);
    if (opt.announce >= 0 && now >= next_announce && (!announced || opt.announce > 0)) {
      rnc_host_status st;
      if (rnc_host_get_status(a->host, 1, &st) == RNC_OK && st.online) {
        (void)rnc_node_announce(a->node, destination, unix_now, now);
        announced = 1;
        next_announce = now + (uint64_t)opt.announce * 1000u;
      }
    }
  }
  for (i = 0; i < SESSIONS; i++)
    session_release(a, &sessions[i]);
  return 0;
}

/* ---- initiator ---------------------------------------------------------- */
enum {
  EXIT_NO_PATH = 255,
  EXIT_FAILED = 255,
  EXIT_PROTOCOL = 254,
  EXIT_REMOTE = 200
};
static struct termios saved_tty;
static int tty_saved;
static void tty_restore(void) {
  if (tty_saved) {
    (void)tcsetattr(0, TCSANOW, &saved_tty);
    tty_saved = 0;
  }
}
static size_t encode_execute(uint8_t *out, size_t cap, int tty_in, int tty_out,
                             int tty_err, const struct termios *tio,
                             const struct winsize *ws, int have_ws) {
  rnc_rpc_writer w;
  size_t n = 0;
  int i;
  const char *term = getenv("TERM");
  rnc_rpc_writer_init(&w, out, cap);
  (void)rnc_rpc_write_array(&w, 10);
  if (opt.command_count > 0) {
    (void)rnc_rpc_write_array(&w, (size_t)opt.command_count);
    for (i = 0; i < opt.command_count; i++)
      (void)rnc_rpc_write_string(&w, opt.command[i]);
  } else
    (void)rnc_rpc_write_nil(&w);
  (void)rnc_rpc_write_bool(&w, !tty_in);
  (void)rnc_rpc_write_bool(&w, !tty_out);
  (void)rnc_rpc_write_bool(&w, !tty_err);
  if (tio) { /* [iflag, oflag, cflag, ispeed, lflag, ospeed, [cc...]] as termios.tcgetattr */
    (void)rnc_rpc_write_array(&w, 7);
    (void)rnc_rpc_write_uint(&w, tio->c_iflag);
    (void)rnc_rpc_write_uint(&w, tio->c_oflag);
    (void)rnc_rpc_write_uint(&w, tio->c_cflag);
    (void)rnc_rpc_write_uint(&w, tio->c_lflag);
    (void)rnc_rpc_write_uint(&w, cfgetispeed(tio));
    (void)rnc_rpc_write_uint(&w, cfgetospeed(tio));
    (void)rnc_rpc_write_array(&w, NCCS);
    for (i = 0; i < NCCS; i++)
      (void)rnc_rpc_write_uint(&w, tio->c_cc[i]);
  } else
    (void)rnc_rpc_write_nil(&w);
  if (term)
    (void)rnc_rpc_write_string(&w, term);
  else
    (void)rnc_rpc_write_nil(&w);
  if (have_ws) {
    (void)rnc_rpc_write_uint(&w, ws->ws_row);
    (void)rnc_rpc_write_uint(&w, ws->ws_col);
    (void)rnc_rpc_write_uint(&w, ws->ws_xpixel);
    (void)rnc_rpc_write_uint(&w, ws->ws_ypixel);
  } else
    for (i = 0; i < 4; i++)
      (void)rnc_rpc_write_nil(&w);
  return rnc_rpc_writer_finish(&w, &n) == RNC_OK ? n : 0;
}
static int await_path(app *a, const uint8_t destination[16], double wait) {
  uint64_t start = monotonic_ms(), last_request = 0;
  rnc_route route;
  int requested = 0;
  while (!stopping && monotonic_ms() - start < (uint64_t)(wait * 1000.0)) {
    uint64_t unix_now, now;
    rnc_host_event event;
    if (!pump_host(a, 0, &unix_now))
      return 0;
    now = monotonic_ms();
    while (rnc_host_poll(a->host, &event) == RNC_OK) {
    }
    if (rnc_node_lookup(a->node, destination, now, &route) == RNC_OK)
      return 1;
    if (!requested || now - last_request > 5000u) {
      rnc_host_status s;
      if (rnc_host_get_status(a->host, 1, &s) == RNC_OK && s.online) {
        (void)rnc_node_request_path(a->node, destination, now);
        requested = 1;
        last_request = now;
      }
    }
  }
  return 0;
}
/* Pumps the node and feeds LOCAL packets for this link; returns link events
 * through the callback-free loop in the caller. */
static int initiator_pump(app *a, rnc_link *link, const uint8_t link_id[16],
                          uint64_t *unix_now, uint64_t *now) {
  rnc_host_event event;
  if (!pump_host(a, 0, unix_now))
    return 0;
  *now = monotonic_ms();
  while (rnc_host_poll(a->host, &event) == RNC_OK) {
    if (event.type == RNC_HOST_NODE && event.node.type == RNC_NODE_LOCAL &&
        !memcmp(event.node.packet.destination, link_id, 16))
      (void)rnc_link_input(link, &event.node.packet, *now);
  }
  (void)rnc_link_tick(link, *now);
  return 1;
}
static int run_initiator(rnc_identity *id, app *a, const uint8_t destination[16]) {
  rnc_route route;
  rnc_link *link;
  uint8_t link_id[16];
  rnc_link_event le;
  uint64_t unix_now = (uint64_t)time(NULL), now = monotonic_ms();
  int rc = EXIT_FAILED, have_version = 0, running = 0, stdin_eof = 0,
      sent_eof = 0, tty_in = isatty(0), tty_out = isatty(1), tty_err = isatty(2),
      pre_esc = 1, esc = 0, finished = 0;
  uint8_t exec_buf[1024];
  uint8_t input[1024];
  size_t input_len = 0;
  struct termios tio;
  struct winsize ws;
  int have_tio = 0, have_ws = 0;
  double wait = opt.timeout;
  uint64_t deadline;
  if (!await_path(a, destination, wait)) {
    puts("Path not found");
    return EXIT_NO_PATH;
  }
  if (rnc_node_lookup(a->node, destination, monotonic_ms(), &route) != RNC_OK)
    return EXIT_NO_PATH;
  link = rnc_link_new(secure_random, NULL);
  if (!link || rnc_link_open(link, &route.announce, monotonic_ms()) != RNC_OK ||
      rnc_link_address(link, link_id) != RNC_OK ||
      rnc_node_bind_link_on(a->node, link_id, route.interface_id) != RNC_OK) {
    rnc_link_free(link);
    return EXIT_FAILED;
  }
  deadline = monotonic_ms() + (uint64_t)(wait * 1000.0);
  while (!stopping && !rnc_link_is_active(link) && monotonic_ms() < deadline) {
    if (!initiator_pump(a, link, link_id, &unix_now, &now))
      break;
    while (rnc_link_poll(link, &le) == RNC_OK)
      if (le.type == RNC_LINK_SEND)
        (void)rnc_node_send(a->node, &le.packet, unix_now, now);
  }
  if (!rnc_link_is_active(link)) {
    puts("Could not establish link");
    (void)rnc_node_unbind_link(a->node, link_id);
    rnc_link_free(link);
    return EXIT_FAILED;
  }
  if (!opt.no_id)
    (void)rnc_link_identify(link, id, monotonic_ms());
  (void)send_version(link, monotonic_ms());
  if (tty_in && tcgetattr(0, &tio) == 0) {
    have_tio = 1;
    saved_tty = tio;
  }
  if ((tty_in && ioctl(0, TIOCGWINSZ, &ws) == 0) ||
      (tty_out && ioctl(1, TIOCGWINSZ, &ws) == 0))
    have_ws = 1;
  set_nonblock(0);
  deadline = monotonic_ms() + 10000u;
  while (!stopping && !finished) {
    int progressed = 0;
    now = monotonic_ms();
    unix_now = (uint64_t)time(NULL);
    if (!initiator_pump(a, link, link_id, &unix_now, &now))
      break;
    while (rnc_link_poll(link, &le) == RNC_OK) {
      if (le.type == RNC_LINK_SEND)
        (void)rnc_node_send(a->node, &le.packet, unix_now, now);
      else if (le.type == RNC_LINK_CLOSED) {
        if (!running || rc == EXIT_FAILED)
          rc = EXIT_FAILED;
        finished = 1;
      } else if (le.type == RNC_LINK_MESSAGE) {
        if (le.message_type == MSG_ERROR) {
          val pool[8];
          reader rd = {le.data, le.data + le.size, pool, 0, 8};
          val root;
          if (parse(&rd, &root, 0) && root.type == V_ARR && root.n >= 1 &&
              root.kids[0].type == V_STR) {
            tty_restore();
            fprintf(stderr, "Remote error: %.*s\n", (int)root.kids[0].n,
                    (const char *)root.kids[0].p);
          }
          rc = EXIT_REMOTE;
          finished = 1;
        } else if (le.message_type == MSG_VERSION && !have_version) {
          size_t n = encode_execute(exec_buf, sizeof(exec_buf), tty_in, tty_out,
                                    tty_err, have_tio ? &tio : NULL, &ws, have_ws);
          have_version = 1;
          if (!n) {
            rc = EXIT_FAILED;
            finished = 1;
          } else {
            (void)send_message(link, MSG_EXECUTE, exec_buf, n, now);
            running = 1;
            if (tty_in && have_tio) {
              struct termios raw = tio;
              raw.c_iflag &= ~(tcflag_t)(IGNBRK | BRKINT | PARMRK | ISTRIP |
                                         INLCR | IGNCR | ICRNL | IXON);
              raw.c_oflag &= ~(tcflag_t)OPOST;
              raw.c_lflag &= ~(tcflag_t)(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
              raw.c_cflag &= ~(tcflag_t)(CSIZE | PARENB);
              raw.c_cflag |= CS8;
              raw.c_cc[VMIN] = 1;
              raw.c_cc[VTIME] = 0;
              if (tcsetattr(0, TCSANOW, &raw) == 0)
                tty_saved = 1;
            }
          }
        } else if (le.message_type == MSG_STREAM && running) {
          uint8_t chunk[RNC_LINK_MAX_MDU + 16];
          uint16_t stream = 0;
          int eof = 0;
          size_t n = 0;
          if (rnc_stream_decode(le.data, le.size, &stream, &eof, chunk,
                                sizeof(chunk), &n) == RNC_OK && n) {
            int fd = stream == STREAM_STDERR ? 2 : 1;
            size_t off = 0;
            while (off < n) {
              ssize_t w = write(fd, chunk + off, n - off);
              if (w > 0)
                off += (size_t)w;
              else if (w < 0 && errno != EINTR && errno != EAGAIN)
                break;
              else {
                struct pollfd pf = {fd, POLLOUT, 0};
                (void)poll(&pf, 1, 20);
              }
            }
          }
          progressed = 1;
        } else if (le.message_type == MSG_EXITED && running) {
          val pool[2];
          reader rd = {le.data, le.data + le.size, pool, 0, 2};
          val root;
          rc = 0;
          if (parse(&rd, &root, 0)) {
            long code = root.type == V_INT ? (long)root.i
                        : root.type == V_UINT ? (long)root.u
                                              : 0;
            rc = (int)(code & 0xff);
          }
          finished = 1;
        }
      }
    }
    if (finished)
      break;
    if (!have_version && monotonic_ms() > deadline) {
      puts("Protocol error");
      rc = EXIT_PROTOCOL;
      break;
    }
    if (running) {
      /* keyboard or piped input, with the ~. escape on a terminal */
      if (!stdin_eof && input_len == 0) {
        ssize_t n = read(0, input, sizeof(input) - 1);
        if (n > 0) {
          size_t i, out = 0;
          for (i = 0; i < (size_t)n; i++) {
            uint8_t c = input[i];
            if (!tty_in) {
              input[out++] = c;
              continue;
            }
            if (c == '\r') {
              pre_esc = 1;
              input[out++] = c;
            } else if (pre_esc && c == '~') {
              pre_esc = 0;
              esc = 1;
            } else if (esc) {
              esc = 0;
              if (c == '.') {
                finished = 1;
                rc = 0;
              } else {
                if (c != '~')
                  input[out++] = '~';
                input[out++] = c;
              }
            } else {
              pre_esc = 0;
              input[out++] = c;
            }
          }
          input_len = out;
        } else if (n == 0)
          stdin_eof = 1;
      }
      while (channel_ready(link) && (input_len || (stdin_eof && !sent_eof))) {
        size_t used = 0;
        if (send_stream(link, STREAM_STDIN, input, input_len,
                        stdin_eof && input_len == 0, &used, now) != RNC_OK)
          break;
        if (stdin_eof && input_len == 0)
          sent_eof = 1;
        memmove(input, input + used, input_len - used);
        input_len -= used;
        progressed = 1;
      }
      if (winch && tty_in && channel_ready(link)) {
        winch = 0;
        if (ioctl(0, TIOCGWINSZ, &ws) == 0) {
          uint8_t buf[32];
          rnc_rpc_writer w;
          size_t n;
          rnc_rpc_writer_init(&w, buf, sizeof(buf));
          (void)rnc_rpc_write_array(&w, 4);
          (void)rnc_rpc_write_uint(&w, ws.ws_row);
          (void)rnc_rpc_write_uint(&w, ws.ws_col);
          (void)rnc_rpc_write_uint(&w, ws.ws_xpixel);
          (void)rnc_rpc_write_uint(&w, ws.ws_ypixel);
          if (rnc_rpc_writer_finish(&w, &n) == RNC_OK)
            (void)send_message(link, MSG_WINDOW, buf, n, now);
        }
      }
    }
    (void)progressed;
  }
  tty_restore();
  /* close the link and let the close leave the socket */
  (void)rnc_link_close(link, monotonic_ms());
  {
    uint64_t start = monotonic_ms();
    while (monotonic_ms() - start < 300u) {
      uint64_t u = (uint64_t)time(NULL), n = monotonic_ms();
      if (!pump_host(a, 0, &u))
        break;
      while (rnc_link_poll(link, &le) == RNC_OK)
        if (le.type == RNC_LINK_SEND)
          (void)rnc_node_send(a->node, &le.packet, u, n);
    }
  }
  (void)rnc_node_unbind_link(a->node, link_id);
  rnc_link_free(link);
  return rc;
}

static void usage(void) {
  fputs("usage: reticulum-c-sh --connect HOST:PORT --identity FILE -l -a IDENTITY_HASH... [-b SECONDS] [-C | -A] [-- PROGRAM [ARGS...]]\n"
        "       reticulum-c-sh --connect HOST:PORT --identity FILE [-m] [-N] [-w SECONDS] DESTINATION [-- COMMAND [ARGS...]]\n",
        stderr);
}
int main(int argc, char **argv) {
  int i;
  const char *destination_text = NULL;
  rnc_identity id;
  app a = {0};
  uint8_t destination[16];
  int rc;
  opt.announce = -1;
  opt.timeout = 15.0;
  for (i = 1; i < argc; ++i) {
    const char *arg = argv[i];
#define VALUE (i + 1 < argc ? argv[++i] : (usage(), exit(2), (char *)NULL))
    if (!strcmp(arg, "--")) {
      opt.command = argv + i + 1;
      opt.command_count = argc - i - 1;
      break;
    } else if (!strcmp(arg, "--connect"))
      opt.connect = VALUE;
    else if (!strcmp(arg, "--identity") || !strcmp(arg, "-i"))
      opt.identity = VALUE;
    else if (!strcmp(arg, "-l") || !strcmp(arg, "--listen"))
      opt.listen = 1;
    else if (!strcmp(arg, "-C") || !strcmp(arg, "--no-remote-command"))
      opt.no_remote_command = 1;
    else if (!strcmp(arg, "-A") || !strcmp(arg, "--remote-command-as-args"))
      opt.remote_args = 1;
    else if (!strcmp(arg, "-m") || !strcmp(arg, "--mirror"))
      opt.mirror = 1;
    else if (!strcmp(arg, "-N") || !strcmp(arg, "--no-id"))
      opt.no_id = 1;
    else if (!strcmp(arg, "-b") || !strcmp(arg, "--announce")) {
      char *end;
      opt.announce = strtol(VALUE, &end, 10);
      if (*end || opt.announce < 0)
        return usage(), 2;
    } else if (!strcmp(arg, "-w") || !strcmp(arg, "--timeout")) {
      char *end;
      opt.timeout = strtod(VALUE, &end);
      if (*end || !(opt.timeout > 0) || opt.timeout > 3600)
        return usage(), 2;
    } else if (!strcmp(arg, "-a") || !strcmp(arg, "--allowed")) {
      if (opt.allowed_count >= 32 ||
          !hex_decode(VALUE, opt.allowed[opt.allowed_count], 16)) {
        fprintf(stderr, "Allowed identities are 32 hexadecimal characters\n");
        return 1;
      }
      ++opt.allowed_count;
    } else if (arg[0] != '-' && !destination_text)
      destination_text = arg;
    else
      return usage(), 2;
  }
  if (!opt.connect || !opt.identity)
    return usage(), 2;
  if (opt.listen ? destination_text != NULL : destination_text == NULL)
    return usage(), 2;
  if (opt.no_remote_command && opt.remote_args)
    return usage(), 2;
  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGWINCH, on_winch);
  if (!open_node(&id, &a))
    return 1;
  if (opt.listen)
    rc = listen_mode(&id, &a);
  else if (!hex_decode(destination_text, destination, 16)) {
    fprintf(stderr, "The destination must be 32 hexadecimal characters\n");
    rc = 2;
  } else {
    rc = run_initiator(&id, &a, destination);
    if (!opt.mirror && rc != EXIT_NO_PATH && rc != EXIT_FAILED &&
        rc != EXIT_PROTOCOL && rc != EXIT_REMOTE)
      rc = 0;
  }
  rnc_host_free(a.host);
  rnc_node_free(a.node);
  rnc_identity_clear(&id);
  return rc;
}
