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
 * reticulum-c-cp. Commands run beside each other (8 at once) while the listener
 * keeps serving the network, each for as long as its client asked (-w, at most a
 * day). An answer is at most 16 MiB, the limit of the request service: stdout
 * and stderr share it and what does not fit is reported as truncated. */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include "msgpack_tree.h"
#include "tool_stamps.h"
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
#include <strings.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define APP_NAME "rnx.execute"
#define REQUEST_PATH "command"
#define DEFAULT_TIMEOUT 15.0
#define MAX_RUN_SECONDS 86400.0
#define JOBS 8u
/* the largest request or response the request service carries, and the room an answer's other fields take */
#define VALUE_MAX ((size_t)(16u * 1024u * 1024u - 64u))
#define RESULT_ROOM (VALUE_MAX - 256u)
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
/* ---- MessagePack of any size ---------------------------------------------
 * rnc_rpc_writer stops at the 64 KiB of an RPC message; a command's input and
 * output do not. Small values still go through it, byte strings are written here. */
typedef struct packed {
  uint8_t *data;
  size_t capacity, size;
  int failed;
} packed;
static void pack_raw(packed *p, const void *data, size_t n) {
  if (p->failed || n > p->capacity - p->size) {
    p->failed = 1;
    return;
  }
  if (n)
    memcpy(p->data + p->size, data, n);
  p->size += n;
}
static void pack_bin(packed *p, const void *data, size_t n) {
  uint8_t head[5];
  size_t bytes = n < 256 ? 1 : n < 65536 ? 2 : 4, i;
  head[0] = (uint8_t)(bytes == 1 ? 0xc4 : bytes == 2 ? 0xc5 : 0xc6);
  for (i = 0; i < bytes; ++i)
    head[1 + i] = (uint8_t)((uint64_t)n >> (8u * (bytes - 1u - i)));
  pack_raw(p, head, 1 + bytes);
  pack_raw(p, data, n);
}
/* nil, bool, integer or float: kind is 'n', 'b', 'u', 'i' or 'r'. */
static void pack_small(packed *p, char kind, uint64_t u, int64_t i, double r) {
  uint8_t value[16];
  size_t n = 0;
  rnc_rpc_writer w;
  rnc_rpc_writer_init(&w, value, sizeof(value));
  (void)(kind == 'n'   ? rnc_rpc_write_nil(&w)
         : kind == 'b' ? rnc_rpc_write_bool(&w, u != 0)
         : kind == 'u' ? rnc_rpc_write_uint(&w, u)
         : kind == 'i' ? rnc_rpc_write_int(&w, i)
                       : rnc_rpc_write_real(&w, r));
  if (rnc_rpc_writer_finish(&w, &n) != RNC_OK)
    p->failed = 1;
  else
    pack_raw(p, value, n);
}

static void keep(uint8_t **buffer, size_t *capacity, size_t *kept, size_t *total, const uint8_t *data, size_t n) {
  size_t room = RESULT_ROOM > *kept ? RESULT_ROOM - *kept : 0, take = n < room ? n : room;
  *total += n;
  if (take && *kept + take > *capacity) {
    size_t grown = *capacity ? *capacity * 2u : 65536u;
    uint8_t *bigger;
    while (grown < *kept + take)
      grown *= 2u;
    if (grown > RESULT_ROOM)
      grown = RESULT_ROOM;
    bigger = realloc(*buffer, grown);
    if (!bigger)
      return;
    *buffer = bigger;
    *capacity = grown;
  }
  if (take) {
    memcpy(*buffer + *kept, data, take);
    *kept += take;
  }
}
/* A command that is running. job_step moves its input and output without ever waiting. */
typedef struct job {
  int used, done, in_open, out_open, err_open, reaped, terminated;
  pid_t child;
  int in_fd, out_fd, err_fd, status;
  uint8_t *input;
  size_t input_size, input_done, out_capacity, err_capacity, out_limit, err_limit;
  double deadline, killed_at;
  run_result r;
  rnc_responder_ticket ticket;
} job;
static void job_free(job *j) {
  if (j->used && j->r.executed && !j->reaped) {
    (void)kill(j->child, SIGKILL);
    (void)waitpid(j->child, NULL, 0);
  }
  if (j->in_open)
    close(j->in_fd);
  if (j->out_open)
    close(j->out_fd);
  if (j->err_open)
    close(j->err_fd);
  free(j->input);
  free(j->r.out);
  free(j->r.err);
  memset(j, 0, sizeof(*j));
}
/* Starts words[] with the input as its stdin. False when nothing could be run. */
static int job_start(job *j, char *const *words, const uint8_t *input, size_t input_size, double timeout_s) {
  int in_pipe[2], out_pipe[2], err_pipe[2], exec_pipe[2], e = 0;
  pid_t child;
  ssize_t got;
  j->r.started = wall_seconds();
  if (input_size) {
    j->input = malloc(input_size);
    if (!j->input)
      return 0;
    memcpy(j->input, input, input_size);
    j->input_size = input_size;
  }
  if (pipe(in_pipe) || pipe(out_pipe) || pipe(err_pipe) || pipe(exec_pipe))
    return 0;
  (void)fcntl(exec_pipe[1], F_SETFD, FD_CLOEXEC);
  /* later commands must not inherit this one's pipes, or its end of file would wait for theirs */
  (void)fcntl(in_pipe[1], F_SETFD, FD_CLOEXEC);
  (void)fcntl(out_pipe[0], F_SETFD, FD_CLOEXEC);
  (void)fcntl(err_pipe[0], F_SETFD, FD_CLOEXEC);
  child = fork();
  if (child < 0) {
    close(in_pipe[0]), close(in_pipe[1]), close(out_pipe[0]), close(out_pipe[1]);
    close(err_pipe[0]), close(err_pipe[1]), close(exec_pipe[0]), close(exec_pipe[1]);
    return 0;
  }
  if (!child) {
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
  got = read(exec_pipe[0], &e, sizeof(e));
  close(exec_pipe[0]);
  if (got > 0) { /* exec failed: nothing ran */
    close(in_pipe[1]);
    close(out_pipe[0]);
    close(err_pipe[0]);
    (void)waitpid(child, NULL, 0);
    return 0;
  }
  j->child = child;
  j->r.executed = 1;
  j->in_fd = in_pipe[1];
  j->out_fd = out_pipe[0];
  j->err_fd = err_pipe[0];
  j->in_open = j->out_open = j->err_open = 1;
  set_nonblock(j->in_fd);
  set_nonblock(j->out_fd);
  set_nonblock(j->err_fd);
  if (!input_size) {
    close(j->in_fd);
    j->in_open = 0;
  }
  j->deadline = j->r.started + timeout_s;
  return 1;
}
static void job_read(int fd, int *open, uint8_t **buffer, size_t *capacity, size_t *kept, size_t *total) {
  uint8_t buf[16384];
  int round;
  for (round = 0; *open && round < 32; ++round) {
    ssize_t g = read(fd, buf, sizeof(buf));
    if (g > 0)
      keep(buffer, capacity, kept, total, buf, (size_t)g);
    else {
      if (g == 0 || (errno != EAGAIN && errno != EINTR)) {
        close(fd);
        *open = 0;
      }
      return;
    }
  }
}
static void job_step(job *j) {
  double now = wall_seconds();
  if (j->done)
    return;
  if (!j->terminated && !j->reaped && now > j->deadline) {
    (void)kill(j->child, SIGTERM);
    j->terminated = 1;
    j->killed_at = now;
  } else if (j->terminated && !j->reaped && now > j->killed_at + 2.0)
    (void)kill(j->child, SIGKILL);
  while (j->in_open) {
    ssize_t w = write(j->in_fd, j->input + j->input_done, j->input_size - j->input_done);
    if (w > 0)
      j->input_done += (size_t)w;
    else if (w < 0 && (errno == EAGAIN || errno == EINTR))
      break;
    else
      j->input_done = j->input_size;
    if (j->input_done >= j->input_size) {
      close(j->in_fd);
      j->in_open = 0;
    }
  }
  if (j->out_open)
    job_read(j->out_fd, &j->out_open, &j->r.out, &j->out_capacity, &j->r.out_kept, &j->r.out_len);
  if (j->err_open)
    job_read(j->err_fd, &j->err_open, &j->r.err, &j->err_capacity, &j->r.err_kept, &j->r.err_len);
  if (!j->reaped && waitpid(j->child, &j->status, WNOHANG) == j->child)
    j->reaped = 1;
  /* finished, or stopped and some grandchild still holds the pipes open */
  if (j->reaped && ((!j->out_open && !j->err_open) || (j->terminated && now > j->killed_at + 3.0))) {
    j->done = 1;
    j->r.concluded = now;
    j->r.has_concluded = !j->terminated;
    j->r.has_code = 1;
    j->r.code = WIFEXITED(j->status) ? WEXITSTATUS(j->status)
                                     : (WIFSIGNALED(j->status) ? -(long)WTERMSIG(j->status) : 0);
  }
}
/* The reference's answer: [executed, code, stdout, stderr, stdout length, stderr length, started, concluded] */
static size_t encode_result(job *j, uint8_t *out, size_t cap) {
  run_result *r = &j->r;
  packed w = {out, cap, 0, 0};
  size_t out_n = r->out_kept, err_n = r->err_kept;
  if (out_n > j->out_limit)
    out_n = j->out_limit;
  if (err_n > j->err_limit)
    err_n = j->err_limit;
  if (out_n + err_n > RESULT_ROOM) { /* both are large: each is sure of half */
    size_t spare = RESULT_ROOM - (err_n < RESULT_ROOM / 2u ? err_n : RESULT_ROOM / 2u);
    if (out_n > spare)
      out_n = spare;
    if (err_n > RESULT_ROOM - out_n)
      err_n = RESULT_ROOM - out_n;
  }
  pack_raw(&w, "\x98", 1); /* an array of eight */
  pack_small(&w, 'b', (uint64_t)r->executed, 0, 0);
  if (r->executed && r->has_code)
    pack_small(&w, 'i', 0, r->code, 0);
  else
    pack_small(&w, 'n', 0, 0, 0);
  if (r->executed) {
    pack_bin(&w, r->out, out_n);
    pack_bin(&w, r->err, err_n);
    pack_small(&w, 'u', r->out_len, 0, 0);
    pack_small(&w, 'u', r->err_len, 0, 0);
  } else {
    pack_small(&w, 'n', 0, 0, 0);
    pack_small(&w, 'n', 0, 0, 0);
    pack_small(&w, 'n', 0, 0, 0);
    pack_small(&w, 'n', 0, 0, 0);
  }
  pack_small(&w, 'r', 0, 0, r->started ? r->started : wall_seconds());
  if (r->has_concluded)
    pack_small(&w, 'r', 0, 0, r->concluded);
  else
    pack_small(&w, 'n', 0, 0, 0);
  return w.failed ? 0 : w.size;
}

typedef struct app {
  rnc_node *node;
  rnc_host *host;
  rnc_responder *responder;
  rnc_requester *requester;
} app;
static job jobs[JOBS];

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
  size_t out_limit, err_limit, input_size = 0, i;
  const uint8_t *input = NULL;
  job *j = NULL;
  int count;
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
    timeout = !(t > 0) ? 0.0 : t < MAX_RUN_SECONDS ? t : MAX_RUN_SECONDS;
  }
  out_limit = olimit->type == V_UINT || olimit->type == V_INT
                  ? (size_t)as_uint(olimit)
                  : RESULT_ROOM;
  err_limit = elimit->type == V_UINT || elimit->type == V_INT
                  ? (size_t)as_uint(elimit)
                  : RESULT_ROOM;
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
  for (i = 0; i < JOBS && !j; ++i)
    if (!jobs[i].used)
      j = &jobs[i];
  count = split_command(command, copy, sizeof(copy), words, 256);
  if (!j)
    puts("Too many commands are running, not executing this one");
  else {
    memset(j, 0, sizeof(*j));
    j->used = 1;
    j->out_limit = out_limit;
    j->err_limit = err_limit;
    /* the answer is given when the command ends; the request stays open that long and a little more */
    if (count > 0 &&
        rnc_responder_defer(((app *)context)->responder, &j->ticket, (uint64_t)((timeout + 60.0) * 1000.0)) == RNC_OK &&
        job_start(j, words, input, input_size, timeout))
      return RNC_AGAIN;
    job_free(j);
  }
  { /* nothing is running: say so at once */
    job none;
    memset(&none, 0, sizeof(none));
    *written = encode_result(&none, response, capacity);
  }
  return *written ? RNC_OK : RNC_NO_SPACE;
}
/* Moves the running commands along and answers those that ended. */
static void jobs_step(app *a) {
  static uint8_t *answer;
  size_t i;
  for (i = 0; i < JOBS; ++i) {
    job *j = &jobs[i];
    size_t size;
    rnc_result r;
    if (!j->used)
      continue;
    job_step(j);
    if (!j->done)
      continue;
    if (!answer && !(answer = malloc(VALUE_MAX)))
      return;
    size = encode_result(j, answer, VALUE_MAX);
    r = size ? rnc_responder_reply(a->responder, &j->ticket, answer, size, monotonic_ms()) : RNC_NO_SPACE;
    if (r == RNC_AGAIN)
      continue; /* the link is busy: next round */
    if (r != RNC_OK)
      puts("Could not deliver the result, the link is gone");
    job_free(j);
  }
}

/* ---- node setup (as in reticulum-c-cp) ----------------------------------- */
typedef struct options {
  const char *connect, *identity, *stdin_text;
  int listen, no_announce, mirror, detailed, no_id, print_identity, interactive;
  double timeout, result_timeout; /* result_timeout 0 = none given (-W) */
  double stamp_value;
  long stdout_limit, stderr_limit; /* -1 = none */
  uint8_t allowed[8][16];
  size_t allowed_count;
} options;
static options opt;
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
  tool_stamps_requests(a->node, opt.stamp_value);
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

/* Extra allowed identities from the first of /etc/rnx, ~/.config/rnx and ~/.rnx that has an
 * allowed_identities file, as the reference reads it: one hash per line, other lengths ignored. */
static int load_allowed_file(void) {
  static const char *places[] = {"/etc/rnx/allowed_identities", "~/.config/rnx/allowed_identities",
                                 "~/.rnx/allowed_identities"};
  const char *home = getenv("HOME");
  char path[1024], line[256];
  FILE *f = NULL;
  size_t k;
  for (k = 0; k < sizeof(places) / sizeof(*places) && !f; ++k) {
    if (places[k][0] == '~')
      (void)snprintf(path, sizeof(path), "%s%s", home ? home : "", places[k] + 1);
    else
      (void)snprintf(path, sizeof(path), "%s", places[k]);
    f = fopen(path, "r");
  }
  if (!f)
    return 1;
  while (fgets(line, sizeof(line), f)) {
    size_t n = strcspn(line, "\r\n");
    line[n] = 0;
    if (n != 32)
      continue;
    if (opt.allowed_count >= 8 || !hex_decode(line, opt.allowed[opt.allowed_count], 16)) {
      fprintf(stderr, "Could not apply allowed identity %s from %s\n", line, path);
      fclose(f);
      return 0;
    }
    ++opt.allowed_count;
  }
  fclose(f);
  return 1;
}
static int listen_mode(rnc_identity *id, app *a) {
  uint8_t destination[16];
  int announced = opt.no_announce;
  if (rnc_node_add_destination(a->node, id, APP_NAME, NULL, 0, destination) !=
      RNC_OK)
    return 1;
  a->responder = rnc_responder_new(a->node, VALUE_MAX, secure_random, NULL);
  if (!a->responder ||
      rnc_responder_add_destination(a->responder, id, destination) != RNC_OK ||
      rnc_responder_register(a->responder, destination, REQUEST_PATH,
                             RNC_SERVICE_ALLOW_LIST,
                             (const uint8_t(*)[16])opt.allowed,
                             opt.allowed_count, handle_command, a) != RNC_OK)
    return 1;
  if (!opt.allowed_count)
    fprintf(stderr,
            "Warning: No allowed identities configured, rnx will not accept "
            "any commands!\n");
  fputs("rnx listening for commands on <", stdout);
  print_hex(destination, 16);
  puts(">");
  fflush(stdout);
  tool_stamps_listen(a->node, opt.identity, opt.stamp_value);
  while (!stopping) {
    if (!pump(a))
      break;
    jobs_step(a);
    tool_stamps_step();
    if (!announced && tool_stamps_ready()) {
      rnc_host_status s;
      if (rnc_host_get_status(a->host, 1, &s) == RNC_OK && s.online) {
        (void)rnc_node_announce(a->node, destination, (uint64_t)time(NULL),
                                monotonic_ms());
        announced = 1;
      }
    }
  }
  tool_stamps_stop();
  {
    size_t i;
    for (i = 0; i < JOBS; ++i)
      job_free(&jobs[i]);
  }
  return stopping ? 0 : 1;
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
static int await_callback(void *context, const rnc_host_event *event) {
  app *a = context;
  uint64_t unix_now = (uint64_t)time(NULL), now = monotonic_ms();
  if (event) {
    if (event->type == RNC_HOST_NODE && event->node.type == RNC_NODE_LOCAL) {
      if (a->responder)
        (void)rnc_responder_input(a->responder, &event->node, unix_now, now);
      if (a->requester)
        (void)rnc_requester_input(a->requester, &event->node, unix_now, now);
    }
    return stopping != 0;
  }
  if (a->responder)
    (void)rnc_responder_tick(a->responder, unix_now, now);
  if (a->requester)
    (void)rnc_requester_tick(a->requester, unix_now, now);
  return stopping != 0;
}
static int await_path(app *a, const uint8_t destination[16], double wait) {
  return rnc_host_await_path(a->host, destination, (unsigned)(wait * 1000.0),
                             await_callback, a) == RNC_OK;
}
static size_t encode_request(const char *command, uint8_t *out, size_t cap) {
  packed w = {out, cap, 0, 0};
  pack_raw(&w, "\x95", 1); /* an array of five */
  pack_bin(&w, command, strlen(command));
  if (opt.timeout == (double)(uint64_t)opt.timeout)
    pack_small(&w, 'u', (uint64_t)opt.timeout, 0, 0);
  else
    pack_small(&w, 'r', 0, 0, opt.timeout);
  if (opt.stdout_limit >= 0)
    pack_small(&w, 'u', (uint64_t)opt.stdout_limit, 0, 0);
  else
    pack_small(&w, 'n', 0, 0, 0);
  if (opt.stderr_limit >= 0)
    pack_small(&w, 'u', (uint64_t)opt.stderr_limit, 0, 0);
  else
    pack_small(&w, 'n', 0, 0, 0);
  if (opt.stdin_text)
    pack_bin(&w, opt.stdin_text, strlen(opt.stdin_text));
  else
    pack_small(&w, 'n', 0, 0, 0);
  return w.failed ? 0 : w.size;
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
  size_t request_size, capacity = VALUE_MAX;
  uint64_t give_up;
  rnc_requester_result r;
  uint64_t timeout_ms = (uint64_t)((opt.result_timeout > 0 ? opt.result_timeout
                                                           : opt.timeout + REPLY_GRACE_SECONDS + 5.0) *
                                   1000.0);
  int rc;
  rnc_requester_free(a->requester); /* a second command in interactive mode */
  a->requester = rnc_requester_new(a->node, VALUE_MAX, secure_random, NULL);
  if (!a->requester)
    return EXIT_NO_REQUEST;
  if (!await_path(a, destination, opt.timeout > 15.0 ? opt.timeout : 15.0)) {
    puts("Path not found");
    return EXIT_NO_PATH;
  }
  request = malloc(VALUE_MAX);
  if (!request)
    return EXIT_NO_REQUEST;
  request_size = encode_request(command, request, VALUE_MAX);
  if (!request_size) {
    fprintf(stderr, "The request is too large (at most 16 MiB)\n");
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
  /* the requester lets an answer that is arriving finish; -W also bounds that */
  give_up = opt.result_timeout > 0 ? monotonic_ms() + timeout_ms : 0;
  while (!stopping) {
    if (!pump(a))
      break;
    if (give_up && monotonic_ms() >= give_up) {
      puts("Could not request remote execution");
      rc = EXIT_NO_REQUEST;
      break;
    }
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

/* -x: one command per line. The prompt shows the last remote exit code when it was not zero; "exit",
 * "quit" or the end of input leave, "clear" clears the screen. A failed request is reported and the
 * prompt comes back, as in the reference. */
static int run_interactive(rnc_identity *id, app *a, const uint8_t destination[16]) {
  char line[4096];
  int code = 0;
  size_t n;
  opt.mirror = 1; /* run_client then returns the remote exit code */
  while (!stopping) {
    if (code > 0 && code < 240)
      printf("%d", code);
    fputs("> ", stdout);
    fflush(stdout);
    if (!fgets(line, sizeof(line), stdin))
      break;
    n = strcspn(line, "\r\n");
    line[n] = 0;
    if (!strcasecmp(line, "exit") || !strcasecmp(line, "quit"))
      break;
    if (!strcasecmp(line, "clear")) {
      fputs("\033c", stdout);
      code = 0;
      continue;
    }
    if (!n)
      continue;
    code = run_client(id, a, destination, line);
    if (code >= 240)
      code = 0; /* the request itself failed: no exit code to show */
  }
  putchar('\n');
  return 0;
}
static void usage(void) {
  fputs("usage: reticulum-c-x --connect HOST:PORT --identity FILE -l -a IDENTITY_HASH... [-b] [--stamp-value N]\n"
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
  opt.stamp_value = tool_stamp_default();
  for (i = 1; i < argc; ++i) {
    const char *arg = argv[i];
#define VALUE (i + 1 < argc ? argv[++i] : (usage(), exit(EXIT_USAGE), (char *)NULL))
    if (!strcmp(arg, "--connect"))
      opt.connect = VALUE;
    else if (!strcmp(arg, "--identity"))
      opt.identity = VALUE;
    else if (!strcmp(arg, "-l") || !strcmp(arg, "--listen"))
      opt.listen = 1;
    else if (!strcmp(arg, "--stamp-value")) {
      if (!tool_stamp_parse(VALUE, &opt.stamp_value))
        return usage(), EXIT_USAGE;
    }
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
    } else if (!strcmp(arg, "-W")) {
      char *end;
      opt.result_timeout = strtod(VALUE, &end);
      if (*end || !(opt.result_timeout > 0) || opt.result_timeout > 3600)
        return usage(), EXIT_USAGE;
    } else if (!strcmp(arg, "-p") || !strcmp(arg, "--print-identity"))
      opt.print_identity = 1;
    else if (!strcmp(arg, "-x") || !strcmp(arg, "--interactive"))
      opt.interactive = 1;
    else if (!strcmp(arg, "-a") || !strcmp(arg, "--allowed")) {
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
  if (opt.print_identity) {
    uint8_t name_hash[10];
    char label[33];
    size_t k;
    if (!opt.identity || positional_count)
      return usage(), EXIT_USAGE;
    if (rnc_host_identity_load(opt.identity, secure_random, NULL, &id) != RNC_OK ||
        rnc_destination_hash(APP_NAME, &id, name_hash, destination) != RNC_OK) {
      fprintf(stderr, "Cannot load or create the identity file %s\n", opt.identity);
      return 1;
    }
    for (k = 0; k < 16; ++k)
      (void)snprintf(label + 2 * k, 3, "%02x", id.hash[k]);
    printf("Identity     : <%s>\n", label);
    fputs("Listening on : <", stdout);
    print_hex(destination, 16);
    puts(">");
    rnc_identity_clear(&id);
    return 0;
  }
  if (!opt.connect || !opt.identity)
    return usage(), EXIT_USAGE;
  if (opt.listen ? positional_count != 0 : positional_count != (opt.interactive ? 1u : 2u))
    return usage(), EXIT_USAGE;
  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);
  signal(SIGPIPE, SIG_IGN);
  if (!open_node(&id, &a))
    return 1;
  if (opt.listen && !load_allowed_file())
    return 1;
  if (opt.listen)
    rc = listen_mode(&id, &a);
  else if (!hex_decode(positional[0], destination, 16)) {
    fprintf(stderr, "The destination must be 32 hexadecimal characters\n");
    rc = EXIT_USAGE;
  } else if (opt.interactive)
    rc = run_interactive(&id, &a, destination);
  else
    rc = run_client(&id, &a, destination, positional[1]);
  rnc_responder_free(a.responder);
  rnc_requester_free(a.requester);
  rnc_host_free(a.host);
  rnc_node_free(a.node);
  rnc_identity_clear(&id);
  return rc;
}
