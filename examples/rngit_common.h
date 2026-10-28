#ifndef RETICULUM_C_EXAMPLE_RNGIT_COMMON_H
#define RETICULUM_C_EXAMPLE_RNGIT_COMMON_H
/* Pieces shared by reticulum-c-git (the repository node) and
 * reticulum-c-git-remote (the git remote helper): a node attached over TCP, a
 * MessagePack emitter without the RPC size cap, the reference's ref and SHA
 * sanitising, and a git subprocess runner. Host-only example code. */
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
#include <reticulum_c/rnc_requester.h>
#include <reticulum_c/rnc_responder.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define GIT_APP_NAME "git.repositories"
#define GIT_PATH_LIST "/git/list"
#define GIT_PATH_FETCH "/git/fetch"
#define GIT_PATH_PUSH "/git/push"
#define GIT_PATH_DELETE "/git/delete"
#define GIT_RES_OK 0x00
#define GIT_RES_DISALLOWED 0x01
#define GIT_RES_INVALID_REQ 0x02
#define GIT_RES_NOT_FOUND 0x03
#define GIT_RES_REMOTE_FAIL 0xFF
#define GIT_IDX_REPOSITORY 0
#define GIT_IDX_RESULT_CODE 1

static volatile sig_atomic_t rngit_stopping;
static inline void rngit_on_signal(int sig) {
  (void)sig;
  rngit_stopping = 1;
}
static inline rnc_result rngit_random(void *context, uint8_t *out,
                                      size_t size) {
  (void)context;
  return size <= INT_MAX && RAND_priv_bytes(out, (int)size) == 1 ? RNC_OK
                                                                 : RNC_CRYPTO;
}
static inline uint64_t rngit_monotonic_ms(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
static inline int rngit_hex_decode(const char *text, uint8_t *out,
                                   size_t size) {
  size_t i;
  if (strlen(text) != size * 2)
    return 0;
  for (i = 0; i < size; ++i) {
    unsigned v = 0;
    int k;
    for (k = 0; k < 2; ++k) {
      char c = text[2 * i + (size_t)k];
      unsigned d;
      if (c >= '0' && c <= '9')
        d = (unsigned)(c - '0');
      else if (c >= 'a' && c <= 'f')
        d = (unsigned)(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F')
        d = (unsigned)(c - 'A' + 10);
      else
        return 0;
      v = v << 4 | d;
    }
    out[i] = (uint8_t)v;
  }
  return 1;
}

/* ---- MessagePack emitter: every call returns the new offset, or 0 when the
 * buffer is too small (sticky once failed). ------------------------------- */
typedef struct mp_out {
  uint8_t *p;
  size_t cap, n;
  int failed;
} mp_out;
static inline void mp_put(mp_out *o, const void *data, size_t n) {
  if (o->failed || n > o->cap - o->n) {
    o->failed = 1;
    return;
  }
  if (n)
    memcpy(o->p + o->n, data, n);
  o->n += n;
}
static inline void mp_byte(mp_out *o, uint8_t b) { mp_put(o, &b, 1); }
static inline void mp_map(mp_out *o, size_t pairs) { mp_byte(o, (uint8_t)(0x80 | pairs)); }
static inline void mp_array(mp_out *o, size_t n) {
  if (n < 16)
    mp_byte(o, (uint8_t)(0x90 | n));
  else {
    uint8_t b[3] = {0xdc, (uint8_t)(n >> 8), (uint8_t)n};
    mp_put(o, b, 3);
  }
}
static inline void mp_uint(mp_out *o, uint64_t v) {
  if (v < 128)
    mp_byte(o, (uint8_t)v);
  else {
    uint8_t b[9] = {0xcf};
    int i;
    for (i = 0; i < 8; ++i)
      b[1 + i] = (uint8_t)(v >> (56 - 8 * i));
    mp_put(o, b, 9);
  }
}
static inline void mp_bool(mp_out *o, int v) { mp_byte(o, v ? 0xc3 : 0xc2); }
static inline void mp_str(mp_out *o, const char *s, size_t n) {
  if (n < 32)
    mp_byte(o, (uint8_t)(0xa0 | n));
  else if (n < 256) {
    uint8_t b[2] = {0xd9, (uint8_t)n};
    mp_put(o, b, 2);
  } else {
    uint8_t b[3] = {0xda, (uint8_t)(n >> 8), (uint8_t)n};
    mp_put(o, b, 3);
  }
  mp_put(o, s, n);
}
static inline void mp_cstr(mp_out *o, const char *s) { mp_str(o, s, strlen(s)); }
static inline void mp_bin(mp_out *o, const void *data, size_t n) {
  if (n < 256) {
    uint8_t b[2] = {0xc4, (uint8_t)n};
    mp_put(o, b, 2);
  } else if (n < 65536) {
    uint8_t b[3] = {0xc5, (uint8_t)(n >> 8), (uint8_t)n};
    mp_put(o, b, 3);
  } else {
    uint8_t b[5] = {0xc6, (uint8_t)(n >> 24), (uint8_t)(n >> 16),
                    (uint8_t)(n >> 8), (uint8_t)n};
    mp_put(o, b, 5);
  }
  mp_put(o, data, n);
}
/* A status byte followed by a message, as one binary value: what every
 * non-file reply of the reference is. */
static inline int mp_status(uint8_t *out, size_t cap, size_t *written,
                            uint8_t status, const char *message) {
  mp_out o = {out, cap, 0, 0};
  size_t m = message ? strlen(message) : 0;
  uint8_t head[6];
  size_t h;
  if (m + 1 < 256) {
    head[0] = 0xc4;
    head[1] = (uint8_t)(m + 1);
    h = 2;
  } else {
    head[0] = 0xc5;
    head[1] = (uint8_t)((m + 1) >> 8);
    head[2] = (uint8_t)(m + 1);
    h = 3;
  }
  mp_put(&o, head, h);
  mp_byte(&o, status);
  mp_put(&o, message, m);
  *written = o.n;
  return !o.failed;
}
/* Value of an integer-keyed map entry (the reference's IDX_* keys). */
static inline const val *map_get_int(const val *m, uint64_t key) {
  size_t i;
  if (!m || m->type != V_MAP)
    return NULL;
  for (i = 0; i < m->n; ++i) {
    const val *k = &m->kids[2 * i];
    if (k->type == V_UINT && k->u == key)
      return &m->kids[2 * i + 1];
  }
  return NULL;
}
static inline int val_is_text(const val *v) {
  return v && (v->type == V_STR || v->type == V_BIN);
}

/* ---- ref and SHA sanitising (util.py san_ref / san_sha) ------------------ */
/* Copies a text value into a NUL-terminated buffer; 0 if it has a NUL byte or
 * does not fit. */
static inline int val_copy(const val *v, char *out, size_t cap) {
  if (!val_is_text(v) || v->n >= cap || memchr(v->p, 0, v->n))
    return 0;
  memcpy(out, v->p, v->n);
  out[v->n] = 0;
  return 1;
}
static inline int rngit_san_ref(const char *ref) {
  size_t n = strlen(ref), i, start = 0;
  if (!n || ref[0] == '-' || ref[0] == '/' || ref[n - 1] == '/' ||
      ref[n - 1] == '.')
    return 0;
  if (!strchr(ref, '/') || strstr(ref, "..") || strstr(ref, "/.") ||
      strstr(ref, "//"))
    return 0;
  for (i = 0; i <= n; ++i)
    if (ref[i] == '/' || ref[i] == 0) {
      size_t len = i - start;
      if (len >= 5 && !memcmp(ref + i - 5, ".lock", 5))
        return 0;
      start = i + 1;
    }
  for (i = 0; i < n; ++i) {
    unsigned char c = (unsigned char)ref[i];
    /* the reference rejects every character below code 40, DEL, and these */
    if (c < 40 || c == 0x7f || c == '\\' || c == '~' || c == '^' ||
        c == ':' || c == '?' || c == '*' || c == '[' || c == ' ')
      return 0;
  }
  return 1;
}
static inline int rngit_san_sha(const char *sha) {
  size_t n = strlen(sha), i;
  if (n < 40 || (n & 1u))
    return 0;
  for (i = 0; i < n; ++i)
    if (!((sha[i] >= '0' && sha[i] <= '9') || (sha[i] >= 'a' && sha[i] <= 'f') ||
          (sha[i] >= 'A' && sha[i] <= 'F')))
      return 0;
  return 1;
}

/* ---- git subprocess ------------------------------------------------------ */
typedef struct proc_result {
  int status; /* exit status, or -1 if it could not run or was signalled */
  char err[512];
} proc_result;
/* Runs argv (no shell) in cwd; stdout goes to `out` (up to cap-1 bytes, NUL
 * terminated, *out_size set) when out is non-NULL, otherwise it is discarded.
 * The first bytes of stderr are kept in result->err. */
static inline proc_result rngit_run(const char *cwd, char *const *argv,
                                    char *out, size_t cap, size_t *out_size) {
  proc_result r = {-1, {0}};
  int po[2], pe[2];
  pid_t pid;
  size_t on = 0, en = 0;
  int open_out = 1, open_err = 1;
  if (out_size)
    *out_size = 0;
  if (out && cap)
    out[0] = 0;
  if (pipe(po) || pipe(pe))
    return r;
  pid = fork();
  if (pid < 0) {
    close(po[0]); close(po[1]); close(pe[0]); close(pe[1]);
    return r;
  }
  if (!pid) {
    int dn = open("/dev/null", O_RDWR);
    if (cwd && chdir(cwd))
      _exit(127);
    if (dn >= 0)
      dup2(dn, 0);
    dup2(po[1], 1);
    dup2(pe[1], 2);
    close(po[0]); close(po[1]); close(pe[0]); close(pe[1]);
    execvp(argv[0], argv);
    _exit(127);
  }
  close(po[1]);
  close(pe[1]);
  while (open_out || open_err) {
    struct pollfd p[2];
    char tmp[4096];
    int i, n = 0;
    if (open_out) { p[n].fd = po[0]; p[n].events = POLLIN; ++n; }
    if (open_err) { p[n].fd = pe[0]; p[n].events = POLLIN; ++n; }
    if (poll(p, (nfds_t)n, -1) < 0 && errno != EINTR)
      break;
    for (i = 0; i < n; ++i) {
      ssize_t got;
      if (!(p[i].revents & (POLLIN | POLLHUP | POLLERR)))
        continue;
      got = read(p[i].fd, tmp, sizeof(tmp));
      if (got <= 0) {
        if (p[i].fd == po[0]) open_out = 0; else open_err = 0;
        continue;
      }
      if (p[i].fd == po[0]) {
        if (out && on + 1 < cap) {
          size_t take_n = (size_t)got < cap - 1 - on ? (size_t)got : cap - 1 - on;
          memcpy(out + on, tmp, take_n);
          on += take_n;
          out[on] = 0;
        }
      } else if (en + 1 < sizeof(r.err)) {
        size_t take_n = (size_t)got < sizeof(r.err) - 1 - en ? (size_t)got : sizeof(r.err) - 1 - en;
        memcpy(r.err + en, tmp, take_n);
        en += take_n;
        r.err[en] = 0;
      }
    }
  }
  close(po[0]);
  close(pe[0]);
  {
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {
    }
    r.status = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
  }
  if (out_size)
    *out_size = on;
  return r;
}

/* ---- a node attached over TCP -------------------------------------------- */
typedef struct rngit_node {
  rnc_node *node;
  rnc_host *host;
  rnc_responder *responder;
  rnc_requester *requester;
  rnc_identity id;
  int has_id;
} rngit_node;
static inline int rngit_open_node(rngit_node *a, const char *connect,
                                  const char *identity_path,
                                  const char *name) {
  rnc_host_config hc;
  char address[256];
  const char *colon = strrchr(connect, ':');
  unsigned long port;
  char *end;
  if (!colon || colon == connect || (size_t)(colon - connect) >= sizeof(address))
    return 0;
  memcpy(address, connect, (size_t)(colon - connect));
  address[colon - connect] = 0;
  port = strtoul(colon + 1, &end, 10);
  if (*end || !port || port > 65535)
    return 0;
  if (rnc_host_identity_load(identity_path, rngit_random, NULL, &a->id) !=
      RNC_OK) {
    fprintf(stderr, "Cannot load or create the identity file %s\n",
            identity_path);
    return 0;
  }
  a->has_id = 1;
  a->node = rnc_node_new(&a->id, 0, rngit_random, NULL);
  a->host = a->node ? rnc_host_new(a->node) : NULL;
  if (!a->host)
    return 0;
  memset(&hc, 0, sizeof(hc));
  hc.kind = RNC_HOST_TCP_CONNECT;
  hc.name = name;
  hc.address = address;
  hc.port = (uint16_t)port;
  hc.mtu = RNC_MAX_MTU;
  hc.bitrate = 1000000000u;
  if (rnc_host_add(a->host, 1, &hc) != RNC_OK) {
    fprintf(stderr, "Cannot connect to %s: %s\n", connect, strerror(errno));
    return 0;
  }
  return 1;
}
static inline int rngit_pump(rngit_node *a) {
  rnc_host_event event;
  uint64_t unix_now = (uint64_t)time(NULL), now = rngit_monotonic_ms();
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
  now = rngit_monotonic_ms();
  if (a->responder)
    (void)rnc_responder_tick(a->responder, unix_now, now);
  if (a->requester)
    (void)rnc_requester_tick(a->requester, unix_now, now);
  return 1;
}
static inline void rngit_close_node(rngit_node *a) {
  rnc_responder_free(a->responder);
  rnc_requester_free(a->requester);
  rnc_host_free(a->host);
  rnc_node_free(a->node);
  if (a->has_id)
    rnc_identity_clear(&a->id);
}
#endif
