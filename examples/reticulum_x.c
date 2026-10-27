/* reticulum-c-x: remote command execution compatible with the reference rnx.
 *
 *   reticulum-c-x --connect HOST:PORT --identity FILE -l -a IDENTITY_HASH...
 *                 [-b]
 *   reticulum-c-x --connect HOST:PORT --identity FILE [-w SECONDS] [-m] [-d]
 *                 [-N] [--stdin TEXT] [--stdout BYTES] [--stderr BYTES]
 *                 DESTINATION COMMAND
 *
 * The listener runs commands (split like a shell would, but never through a
 * shell) for identities on its allow list, one at a time, and answers with the
 * exit code and captured output. There is deliberately no "accept anyone"
 * option: remote execution without authentication is not offered. DESTINATION
 * is the hash the listener prints. It attaches to a node over TCP, like
 * reticulum-c-cp. A command that runs longer than 25 seconds is stopped: the
 * request must be answered inside the 30 second window the request service
 * keeps. */
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
#include <reticulum_c/rnc_host.h>
#include <reticulum_c/rnc_ipc.h>
#include <reticulum_c/rnc_requester.h>
#include <reticulum_c/rnc_responder.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define APP_NAME "rnx.execute"
#define REQUEST_PATH "command"
#define DEFAULT_TIMEOUT 15.0
#define MAX_RUN_SECONDS 25.0
#define REPLY_GRACE_SECONDS 2.0

static volatile sig_atomic_t stopping;
static void on_signal(int sig) {
  (void)sig;
  stopping = 1;
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
static double wall_seconds(void) {
  struct timespec t;
  clock_gettime(CLOCK_REALTIME, &t);
  return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
static void print_hex(const uint8_t *data, size_t size) {
  size_t i;
  for (i = 0; i < size; ++i)
    printf("%02x", data[i]);
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

/* ---- command line splitting (POSIX shlex rules) -------------------------- */
/* Splits into NUL-separated words in a copy; returns the word count or -1 for
 * an unterminated quote. words[] points into the copy. */
static int split_command(const char *command, char *copy, size_t copy_size,
                         char **words, size_t max_words) {
  size_t count = 0, o = 0;
  const char *p = command;
  while (*p) {
    int in_word = 0;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
      ++p;
    if (!*p)
      break;
    if (count + 1 >= max_words)
      return -1;
    words[count] = copy + o;
    while (*p && !(*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) {
      if (o + 2 >= copy_size)
        return -1;
      if (*p == '\'') {
        ++p;
        while (*p && *p != '\'')
          copy[o++] = *p++;
        if (!*p)
          return -1;
        ++p;
      } else if (*p == '"') {
        ++p;
        while (*p && *p != '"') {
          if (*p == '\\' && (p[1] == '"' || p[1] == '\\'))
            ++p;
          copy[o++] = *p++;
        }
        if (!*p)
          return -1;
        ++p;
      } else if (*p == '\\') {
        if (!p[1])
          return -1;
        copy[o++] = p[1];
        p += 2;
      } else
        copy[o++] = *p++;
      in_word = 1;
    }
    if (in_word) {
      copy[o++] = 0;
      ++count;
    }
  }
  words[count] = NULL;
  return (int)count;
}

/* ---- running a command -------------------------------------------------- */
typedef struct run_result {
  int executed, has_code;
  long code;
  uint8_t *out, *err;
  size_t out_len, err_len, out_kept, err_kept; /* totals and bytes retained */
  double started, concluded;
  int has_concluded;
} run_result;
static void set_nonblock(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags >= 0)
    (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
static void keep(uint8_t *buffer, size_t *kept, size_t *total, size_t keep_max,
                 const uint8_t *data, size_t n) {
  size_t room = keep_max > *kept ? keep_max - *kept : 0, take = n < room ? n : room;
  memcpy(buffer + *kept, data, take);
  *kept += take;
  *total += n;
}
/* Runs words[] with stdin data, stopping it after timeout_s seconds. At most
 * keep_max bytes of each stream are retained; totals still count everything. */
static void run_command(char *const *words, const uint8_t *input,
                        size_t input_size, double timeout_s, size_t keep_max,
                        run_result *r) {
  int in_pipe[2], out_pipe[2], err_pipe[2], exec_pipe[2];
  pid_t child;
  int status = 0, reaped = 0, in_open = 1, out_open = 1, err_open = 1;
  size_t in_done = 0;
  double deadline;
  int terminated = 0;
  double killed_at = 0;
  memset(r, 0, sizeof(*r));
  r->started = wall_seconds();
  r->out = malloc(keep_max + 1);
  r->err = malloc(keep_max + 1);
  if (!r->out || !r->err)
    return;
  if (pipe(in_pipe) || pipe(out_pipe) || pipe(err_pipe) || pipe(exec_pipe))
    return;
  (void)fcntl(exec_pipe[1], F_SETFD, FD_CLOEXEC);
  child = fork();
  if (child < 0)
    return;
  if (!child) {
    int e;
    (void)dup2(in_pipe[0], 0);
    (void)dup2(out_pipe[1], 1);
    (void)dup2(err_pipe[1], 2);
    close(in_pipe[0]);
    close(in_pipe[1]);
    close(out_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[0]);
    close(err_pipe[1]);
    close(exec_pipe[0]);
    execvp(words[0], words);
    e = errno;
    (void)!write(exec_pipe[1], &e, sizeof(e));
    _exit(127);
  }
  close(in_pipe[0]);
  close(out_pipe[1]);
  close(err_pipe[1]);
  close(exec_pipe[1]);
  {
    int e = 0;
    ssize_t got = read(exec_pipe[0], &e, sizeof(e));
    close(exec_pipe[0]);
    if (got > 0) { /* exec failed: nothing ran */
      close(in_pipe[1]);
      close(out_pipe[0]);
      close(err_pipe[0]);
      (void)waitpid(child, NULL, 0);
      return;
    }
  }
  r->executed = 1;
  set_nonblock(in_pipe[1]);
  set_nonblock(out_pipe[0]);
  set_nonblock(err_pipe[0]);
  if (!input_size) {
    close(in_pipe[1]);
    in_open = 0;
  }
  deadline = r->started + timeout_s;
  while (out_open || err_open || !reaped) {
    struct pollfd pf[3];
    nfds_t n = 0;
    int idx_in = -1, idx_out = -1, idx_err = -1;
    uint8_t buf[4096];
    double now = wall_seconds();
    if (!terminated && now > deadline) {
      (void)kill(child, SIGTERM);
      terminated = 1;
      killed_at = now;
    } else if (terminated && now > killed_at + 2.0)
      (void)kill(child, SIGKILL);
    if (in_open) {
      pf[n].fd = in_pipe[1];
      pf[n].events = POLLOUT;
      idx_in = (int)n++;
    }
    if (out_open) {
      pf[n].fd = out_pipe[0];
      pf[n].events = POLLIN;
      idx_out = (int)n++;
    }
    if (err_open) {
      pf[n].fd = err_pipe[0];
      pf[n].events = POLLIN;
      idx_err = (int)n++;
    }
    if (n)
      (void)poll(pf, n, 50);
    else {
      struct timespec nap = {0, 20000000};
      nanosleep(&nap, NULL);
    }
    if (idx_in >= 0 && (pf[idx_in].revents & (POLLOUT | POLLERR | POLLHUP))) {
      ssize_t w = write(in_pipe[1], input + in_done, input_size - in_done);
      if (w > 0)
        in_done += (size_t)w;
      if (w < 0 && errno != EAGAIN && errno != EINTR)
        in_done = input_size;
      if (in_done >= input_size) {
        close(in_pipe[1]);
        in_open = 0;
      }
    }
    if (idx_out >= 0 && (pf[idx_out].revents & (POLLIN | POLLHUP | POLLERR))) {
      ssize_t g = read(out_pipe[0], buf, sizeof(buf));
      if (g > 0)
        keep(r->out, &r->out_kept, &r->out_len, keep_max, buf, (size_t)g);
      else if (g == 0 || (errno != EAGAIN && errno != EINTR)) {
        close(out_pipe[0]);
        out_open = 0;
      }
    }
    if (idx_err >= 0 && (pf[idx_err].revents & (POLLIN | POLLHUP | POLLERR))) {
      ssize_t g = read(err_pipe[0], buf, sizeof(buf));
      if (g > 0)
        keep(r->err, &r->err_kept, &r->err_len, keep_max, buf, (size_t)g);
      else if (g == 0 || (errno != EAGAIN && errno != EINTR)) {
        close(err_pipe[0]);
        err_open = 0;
      }
    }
    if (!reaped && waitpid(child, &status, WNOHANG) == child)
      reaped = 1;
    /* a stopped command may leave grandchildren holding the pipes open */
    if (reaped && terminated && wall_seconds() > killed_at + 3.0)
      break;
  }
  if (in_open)
    close(in_pipe[1]);
  if (out_open)
    close(out_pipe[0]);
  if (err_open)
    close(err_pipe[0]);
  if (!reaped)
    (void)waitpid(child, &status, 0);
  r->concluded = wall_seconds();
  r->has_concluded = !terminated;
  r->has_code = 1;
  r->code = WIFEXITED(status) ? WEXITSTATUS(status)
                              : (WIFSIGNALED(status) ? -(long)WTERMSIG(status) : 0);
}
static void run_free(run_result *r) {
  free(r->out);
  free(r->err);
}

/* ---- listener handler ---------------------------------------------------- */
static rnc_result handle_command(void *context, const char *path,
                                 const uint8_t *request, size_t request_size,
                                 const uint8_t *identity_hash, uint8_t *response,
                                 size_t capacity, size_t *written) {
  val pool[16];
  reader rd = {request, request + request_size, pool, 0, 16};
  val root;
  char command[4096], copy[4096], *words[256];
  const val *cmd, *tmo, *olimit, *elimit, *in;
  double timeout = MAX_RUN_SECONDS;
  size_t keep_max = (capacity > 512 ? capacity - 512 : 0) / 2, out_limit,
         err_limit, input_size = 0;
  const uint8_t *input = NULL;
  run_result r;
  rnc_rpc_writer w;
  int count;
  (void)context;
  (void)path;
  if (!parse(&rd, &root, 0) || root.type != V_ARR || root.n != 5 ||
      rd.p != rd.end)
    return RNC_PROTOCOL;
  cmd = &root.kids[0];
  tmo = &root.kids[1];
  olimit = &root.kids[2];
  elimit = &root.kids[3];
  in = &root.kids[4];
  if ((cmd->type != V_BIN && cmd->type != V_STR) || cmd->n >= sizeof(command))
    return RNC_PROTOCOL;
  memcpy(command, cmd->p, cmd->n);
  command[cmd->n] = 0;
  if (tmo->type == V_UINT || tmo->type == V_INT || tmo->type == V_REAL) {
    double t = as_double(tmo);
    if (t > 0 && t < timeout)
      timeout = t;
  }
  out_limit = olimit->type == V_UINT || olimit->type == V_INT
                  ? (size_t)as_uint(olimit)
                  : keep_max;
  err_limit = elimit->type == V_UINT || elimit->type == V_INT
                  ? (size_t)as_uint(elimit)
                  : keep_max;
  if (in->type == V_BIN || in->type == V_STR) {
    input = in->p;
    input_size = in->n;
  }
  printf("Executing command [%s]", command);
  if (identity_hash) {
    fputs(" for <", stdout);
    print_hex(identity_hash, 16);
    putchar('>');
  }
  putchar('\n');
  fflush(stdout);
  count = split_command(command, copy, sizeof(copy), words, 256);
  if (count > 0)
    run_command(words, input, input_size, timeout, keep_max, &r);
  else
    memset(&r, 0, sizeof(r));
  if (r.out_kept > out_limit)
    r.out_kept = out_limit;
  if (r.err_kept > err_limit)
    r.err_kept = err_limit;
  rnc_rpc_writer_init(&w, response, capacity);
  (void)rnc_rpc_write_array(&w, 8);
  (void)rnc_rpc_write_bool(&w, r.executed);
  if (r.executed && r.has_code)
    (void)rnc_rpc_write_int(&w, r.code);
  else
    (void)rnc_rpc_write_nil(&w);
  if (r.executed) {
    (void)rnc_rpc_write_bin(&w, r.out, r.out_kept);
    (void)rnc_rpc_write_bin(&w, r.err, r.err_kept);
    (void)rnc_rpc_write_uint(&w, r.out_len);
    (void)rnc_rpc_write_uint(&w, r.err_len);
  } else {
    (void)rnc_rpc_write_nil(&w);
    (void)rnc_rpc_write_nil(&w);
    (void)rnc_rpc_write_nil(&w);
    (void)rnc_rpc_write_nil(&w);
  }
  (void)rnc_rpc_write_real(&w, r.started ? r.started : wall_seconds());
  if (r.has_concluded)
    (void)rnc_rpc_write_real(&w, r.concluded);
  else
    (void)rnc_rpc_write_nil(&w);
  run_free(&r);
  return rnc_rpc_writer_finish(&w, written) == RNC_OK ? RNC_OK : RNC_NO_SPACE;
}

/* ---- node setup (as in reticulum-c-cp) ----------------------------------- */
typedef struct options {
  const char *connect, *identity, *stdin_text;
  int listen, no_announce, mirror, detailed, no_id;
  double timeout;
  long stdout_limit, stderr_limit; /* -1 = none */
  uint8_t allowed[8][16];
  size_t allowed_count;
} options;
static options opt;
typedef struct app {
  rnc_node *node;
  rnc_host *host;
  rnc_responder *responder;
  rnc_requester *requester;
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
  hc.name = "rnx link";
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
static int pump(app *a) {
  rnc_host_event event;
  uint64_t unix_now = (uint64_t)time(NULL), now = monotonic_ms();
  if (rnc_host_step(a->host, 10, unix_now, now) != RNC_OK)
    return 0;
  while (rnc_host_poll(a->host, &event) == RNC_OK) {
    if (event.type != RNC_HOST_NODE || event.node.type != RNC_NODE_LOCAL)
      continue;
    if (a->responder)
      (void)rnc_responder_input(a->responder, &event.node, unix_now, now);
    if (a->requester)
      (void)rnc_requester_input(a->requester, &event.node, unix_now, now);
  }
  now = monotonic_ms();
  if (a->responder)
    (void)rnc_responder_tick(a->responder, unix_now, now);
  if (a->requester)
    (void)rnc_requester_tick(a->requester, unix_now, now);
  return 1;
}

static int listen_mode(rnc_identity *id, app *a) {
  uint8_t destination[16];
  int announced = opt.no_announce;
  if (rnc_node_add_destination(a->node, id, APP_NAME, NULL, 0, destination) !=
      RNC_OK)
    return 1;
  a->responder = rnc_responder_new(a->node, RNC_RPC_MESSAGE_MAX, secure_random, NULL);
  if (!a->responder ||
      rnc_responder_add_destination(a->responder, id, destination) != RNC_OK ||
      rnc_responder_register(a->responder, destination, REQUEST_PATH,
                             RNC_SERVICE_ALLOW_LIST,
                             (const uint8_t(*)[16])opt.allowed,
                             opt.allowed_count, handle_command, NULL) != RNC_OK)
    return 1;
  if (!opt.allowed_count)
    fprintf(stderr,
            "Warning: No allowed identities configured, rnx will not accept "
            "any commands!\n");
  fputs("rnx listening for commands on <", stdout);
  print_hex(destination, 16);
  puts(">");
  fflush(stdout);
  while (!stopping) {
    if (!pump(a))
      return 1;
    if (!announced) {
      rnc_host_status s;
      if (rnc_host_get_status(a->host, 1, &s) == RNC_OK && s.online) {
        (void)rnc_node_announce(a->node, destination, (uint64_t)time(NULL),
                                monotonic_ms());
        announced = 1;
      }
    }
  }
  return 0;
}

/* ---- client -------------------------------------------------------------- */
enum {
  EXIT_USAGE = 241,
  EXIT_NO_PATH = 242,
  EXIT_NO_LINK = 243,
  EXIT_NO_REQUEST = 244,
  EXIT_NO_RESULT = 245,
  EXIT_BAD_RESULT = 247,
  EXIT_NOT_EXECUTED = 248,
  EXIT_NO_RESPONSE = 249
};
static int await_path(app *a, const uint8_t destination[16], double wait) {
  uint64_t start = monotonic_ms(), last_request = 0;
  rnc_route route;
  int requested = 0;
  while (!stopping && monotonic_ms() - start < (uint64_t)(wait * 1000.0)) {
    uint64_t now = monotonic_ms();
    if (!pump(a))
      return 0;
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
static size_t encode_request(const char *command, uint8_t *out, size_t cap) {
  rnc_rpc_writer w;
  size_t n = 0;
  rnc_rpc_writer_init(&w, out, cap);
  (void)rnc_rpc_write_array(&w, 5);
  (void)rnc_rpc_write_bin(&w, command, strlen(command));
  if (opt.timeout == (double)(uint64_t)opt.timeout)
    (void)rnc_rpc_write_uint(&w, (uint64_t)opt.timeout);
  else
    (void)rnc_rpc_write_real(&w, opt.timeout);
  if (opt.stdout_limit >= 0)
    (void)rnc_rpc_write_uint(&w, (uint64_t)opt.stdout_limit);
  else
    (void)rnc_rpc_write_nil(&w);
  if (opt.stderr_limit >= 0)
    (void)rnc_rpc_write_uint(&w, (uint64_t)opt.stderr_limit);
  else
    (void)rnc_rpc_write_nil(&w);
  if (opt.stdin_text)
    (void)rnc_rpc_write_bin(&w, opt.stdin_text, strlen(opt.stdin_text));
  else
    (void)rnc_rpc_write_nil(&w);
  return rnc_rpc_writer_finish(&w, &n) == RNC_OK ? n : 0;
}
static int show_result(const uint8_t *data, size_t size) {
  val pool[16];
  reader rd = {data, data + size, pool, 0, 16};
  val root;
  const val *executed, *code, *out, *err, *outlen, *errlen, *started, *concluded;
  size_t out_n, err_n;
  if (!parse(&rd, &root, 0) || root.type != V_ARR || root.n != 8)
    return EXIT_BAD_RESULT;
  executed = &root.kids[0];
  code = &root.kids[1];
  out = &root.kids[2];
  err = &root.kids[3];
  outlen = &root.kids[4];
  errlen = &root.kids[5];
  started = &root.kids[6];
  concluded = &root.kids[7];
  if (executed->type != V_BOOL)
    return EXIT_BAD_RESULT;
  if (!executed->u) {
    puts("Remote could not execute command");
    return EXIT_NOT_EXECUTED;
  }
  out_n = out->type == V_BIN || out->type == V_STR ? out->n : 0;
  err_n = err->type == V_BIN || err->type == V_STR ? err->n : 0;
  if (out_n)
    fwrite(out->p, 1, out_n, stdout);
  if (err_n)
    fwrite(err->p, 1, err_n, stderr);
  if (opt.detailed) {
    fflush(stdout);
    puts("\n--- End of remote output, rnx done ---");
    if (started->type == V_REAL && concluded->type == V_REAL)
      printf("Remote command execution took %.3f seconds\n",
             concluded->d - started->d);
    if (outlen->type == V_UINT)
      printf("Remote wrote %llu bytes to stdout%s\n",
             (unsigned long long)outlen->u,
             out_n < outlen->u ? ", some not displayed" : "");
    if (errlen->type == V_UINT)
      printf("Remote wrote %llu bytes to stderr%s\n",
             (unsigned long long)errlen->u,
             err_n < errlen->u ? ", some not displayed" : "");
  } else if ((opt.stdout_limit != 0 && out_n < as_uint(outlen)) ||
             (opt.stderr_limit != 0 && err_n < as_uint(errlen))) {
    fflush(stdout);
    puts("\nOutput truncated before being returned:");
    if (out_n && out_n < as_uint(outlen))
      printf("  stdout truncated to %zu bytes\n", out_n);
    if (err_n && err_n < as_uint(errlen))
      printf("  stderr truncated to %zu bytes\n", err_n);
  }
  fflush(stdout);
  if (opt.mirror)
    return code->type == V_INT || code->type == V_UINT
               ? (int)((code->type == V_INT ? code->i : (int64_t)code->u) & 0xff)
               : 240;
  return 0;
}
/* Keeps the node running briefly so the link close leaves the socket before
 * the process exits; otherwise the listener keeps the link slot until it
 * times out. */
static void flush_out(app *a) {
  uint64_t start = monotonic_ms();
  while (monotonic_ms() - start < 300u && pump(a)) {
  }
}
static int run_client(rnc_identity *id, app *a, const uint8_t destination[16],
                      const char *command) {
  uint8_t *request, *response;
  size_t request_size, capacity = RNC_RPC_MESSAGE_MAX;
  rnc_requester_result r;
  uint64_t timeout_ms = (uint64_t)((opt.timeout + REPLY_GRACE_SECONDS + 5.0) * 1000.0);
  int rc;
  a->requester = rnc_requester_new(a->node, RNC_RPC_MESSAGE_MAX, secure_random, NULL);
  if (!a->requester)
    return EXIT_NO_REQUEST;
  if (!await_path(a, destination, opt.timeout > 15.0 ? opt.timeout : 15.0)) {
    puts("Path not found");
    return EXIT_NO_PATH;
  }
  request = malloc(RNC_RPC_MESSAGE_MAX);
  if (!request)
    return EXIT_NO_REQUEST;
  request_size = encode_request(command, request, RNC_RPC_MESSAGE_MAX);
  if (!request_size) {
    fprintf(stderr, "The request is too large (at most about 64 kB)\n");
    free(request);
    return EXIT_NO_REQUEST;
  }
  if (rnc_requester_start(a->requester, destination, opt.no_id ? NULL : id,
                          REQUEST_PATH, request, request_size, 1, timeout_ms,
                          (uint64_t)time(NULL), monotonic_ms()) != RNC_OK) {
    puts("Could not request remote execution");
    free(request);
    return EXIT_NO_REQUEST;
  }
  free(request);
  response = malloc(capacity);
  if (!response)
    return EXIT_NO_REQUEST;
  rc = EXIT_NO_RESULT;
  while (!stopping) {
    if (!pump(a))
      break;
    if (rnc_requester_poll(a->requester, &r, response, capacity) == RNC_OK) {
      if (r.status == RNC_REQUESTER_DONE)
        rc = show_result(response, r.size);
      else {
        puts("Could not request remote execution");
        rc = EXIT_NO_REQUEST;
      }
      break;
    }
  }
  flush_out(a);
  free(response);
  return rc;
}

static void usage(void) {
  fputs("usage: reticulum-c-x --connect HOST:PORT --identity FILE -l -a IDENTITY_HASH... [-b]\n"
        "       reticulum-c-x --connect HOST:PORT --identity FILE [-w SECONDS] [-m] [-d] [-N]\n"
        "                     [--stdin TEXT] [--stdout BYTES] [--stderr BYTES] DESTINATION COMMAND\n",
        stderr);
}
static int number_arg(const char *text, long *out) {
  char *end;
  long v = strtol(text, &end, 10);
  if (!*text || *end || v < 0)
    return 0;
  *out = v;
  return 1;
}
int main(int argc, char **argv) {
  int i;
  const char *positional[2] = {NULL, NULL};
  size_t positional_count = 0;
  rnc_identity id;
  app a = {0};
  uint8_t destination[16];
  int rc;
  opt.timeout = DEFAULT_TIMEOUT;
  opt.stdout_limit = opt.stderr_limit = -1;
  for (i = 1; i < argc; ++i) {
    const char *arg = argv[i];
#define VALUE (i + 1 < argc ? argv[++i] : (usage(), exit(EXIT_USAGE), (char *)NULL))
    if (!strcmp(arg, "--connect"))
      opt.connect = VALUE;
    else if (!strcmp(arg, "--identity"))
      opt.identity = VALUE;
    else if (!strcmp(arg, "-l") || !strcmp(arg, "--listen"))
      opt.listen = 1;
    else if (!strcmp(arg, "-b") || !strcmp(arg, "--no-announce"))
      opt.no_announce = 1;
    else if (!strcmp(arg, "-m"))
      opt.mirror = 1;
    else if (!strcmp(arg, "-d") || !strcmp(arg, "--detailed"))
      opt.detailed = 1;
    else if (!strcmp(arg, "-N") || !strcmp(arg, "--noid"))
      opt.no_id = 1;
    else if (!strcmp(arg, "--stdin"))
      opt.stdin_text = VALUE;
    else if (!strcmp(arg, "--stdout")) {
      if (!number_arg(VALUE, &opt.stdout_limit))
        return usage(), EXIT_USAGE;
    } else if (!strcmp(arg, "--stderr")) {
      if (!number_arg(VALUE, &opt.stderr_limit))
        return usage(), EXIT_USAGE;
    } else if (!strcmp(arg, "-w")) {
      char *end;
      opt.timeout = strtod(VALUE, &end);
      if (*end || !(opt.timeout > 0) || opt.timeout > 3600)
        return usage(), EXIT_USAGE;
    } else if (!strcmp(arg, "-a") || !strcmp(arg, "--allowed")) {
      if (opt.allowed_count >= 8 ||
          !hex_decode(VALUE, opt.allowed[opt.allowed_count], 16)) {
        fprintf(stderr,
                "Allowed identities are 32 hexadecimal characters, at most 8\n");
        return 1;
      }
      ++opt.allowed_count;
    } else if (arg[0] != '-' && positional_count < 2)
      positional[positional_count++] = arg;
    else
      return usage(), EXIT_USAGE;
  }
  if (!opt.connect || !opt.identity)
    return usage(), EXIT_USAGE;
  if (opt.listen ? positional_count != 0 : positional_count != 2)
    return usage(), EXIT_USAGE;
  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);
  signal(SIGPIPE, SIG_IGN);
  if (!open_node(&id, &a))
    return 1;
  if (opt.listen)
    rc = listen_mode(&id, &a);
  else if (!hex_decode(positional[0], destination, 16)) {
    fprintf(stderr, "The destination must be 32 hexadecimal characters\n");
    rc = EXIT_USAGE;
  } else
    rc = run_client(&id, &a, destination, positional[1]);
  rnc_responder_free(a.responder);
  rnc_requester_free(a.requester);
  rnc_host_free(a.host);
  rnc_node_free(a.node);
  rnc_identity_clear(&id);
  return rc;
}
