/* A stand-in for an I2P router's SAM v3 bridge, enough for stream sessions:
 * HELLO, DEST GENERATE, SESSION CREATE, NAMING LOOKUP, STREAM CONNECT and
 * STREAM ACCEPT, with connected streams bridged in memory. Usage:
 *   fake_sam <command log> [port]
 * Prints the port it listens on, then serves until killed. Every command line
 * received is appended to the log. */
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <reticulum_c/rnc_i2p.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_CONN 64
enum { NEW, READY, SESSION, WAITING, BRIDGED };
typedef struct conn {
  int fd, state, peer;
  char line[4096], id[64], priv[1024], pub[640], b32[RNC_I2P_B32_SIZE];
  size_t used;
} conn;
static conn conns[MAX_CONN];
static FILE *log_file;

static void reply(conn *c, const char *text) {
  size_t n = strlen(text), off = 0;
  while (off < n) {
    ssize_t w = write(c->fd, text + off, n - off);
    if (w <= 0)
      return;
    off += (size_t)w;
  }
}
static void drop(int i) {
  conn *c = &conns[i];
  int peer = c->state == BRIDGED ? c->peer : -1;
  if (c->fd >= 0)
    close(c->fd);
  memset(c, 0, sizeof(*c));
  c->fd = -1;
  if (peer >= 0 && conns[peer].fd >= 0)
    drop(peer);
}
static void random_fill(uint8_t *out, size_t n) {
  FILE *f = fopen("/dev/urandom", "rb");
  if (!f || fread(out, 1, n, f) != n)
    exit(2);
  fclose(f);
}
static void generate(char *priv, char *pub, size_t cap) {
  uint8_t key[387 + 7 + 96] = {0};
  size_t dest = 387 + 7;
  random_fill(key, 384);
  key[384] = 5;
  key[385] = 0;
  key[386] = 4;
  key[387] = 0;
  key[388] = 7;
  random_fill(key + dest, 96);
  if (rnc_i2p_b64_encode(key, dest + 96, priv, cap) != RNC_OK ||
      rnc_i2p_b64_encode(key, dest, pub, cap) != RNC_OK)
    exit(2);
}
static const char *word(const char *line, const char *key, char *out,
                        size_t cap) {
  size_t k = strlen(key);
  const char *p = line;
  while ((p = strstr(p, key)) != NULL) {
    if ((p == line || p[-1] == ' ') && p[k] == '=') {
      size_t n = strcspn(p + k + 1, " ");
      if (n >= cap)
        n = cap - 1;
      memcpy(out, p + k + 1, n);
      out[n] = 0;
      return out;
    }
    p += k;
  }
  return NULL;
}
static int find_session_by_pub(const char *pub) {
  int i;
  for (i = 0; i < MAX_CONN; ++i)
    if (conns[i].fd >= 0 && conns[i].state == SESSION &&
        !strcmp(conns[i].pub, pub))
      return i;
  return -1;
}
static int find_session_by_id(const char *id) {
  int i;
  for (i = 0; i < MAX_CONN; ++i)
    if (conns[i].fd >= 0 && conns[i].state == SESSION &&
        !strcmp(conns[i].id, id))
      return i;
  return -1;
}
static void command(int i, char *line) {
  conn *c = &conns[i];
  char value[1024], id[64], out[2048];
  if (log_file) {
    fprintf(log_file, "%s\n", line);
    fflush(log_file);
  }
  if (!strncmp(line, "HELLO VERSION", 13)) {
    reply(c, "HELLO REPLY RESULT=OK VERSION=3.1\n");
    c->state = READY;
  } else if (c->state != READY) {
    reply(c, "HELLO REPLY RESULT=I2P_ERROR MESSAGE=\"hello first\"\n");
  } else if (!strncmp(line, "DEST GENERATE", 13)) {
    char priv[1024], pub[640];
    generate(priv, pub, sizeof(priv));
    snprintf(out, sizeof(out), "DEST REPLY PUB=%s PRIV=%s\n", pub, priv);
    reply(c, out);
  } else if (!strncmp(line, "SESSION CREATE", 14)) {
    if (!word(line, "ID", id, sizeof(id)) ||
        !word(line, "DESTINATION", value, sizeof(value))) {
      reply(c, "SESSION STATUS RESULT=I2P_ERROR\n");
      return;
    }
    if (find_session_by_id(id) >= 0) {
      reply(c, "SESSION STATUS RESULT=DUPLICATED_ID\n");
      return;
    }
    if (!strcmp(value, "TRANSIENT"))
      generate(c->priv, c->pub, sizeof(c->priv));
    else {
      snprintf(c->priv, sizeof(c->priv), "%s", value);
      if (rnc_i2p_private_to_public(value, c->pub, sizeof(c->pub)) !=
          RNC_OK) {
        reply(c, "SESSION STATUS RESULT=INVALID_KEY\n");
        return;
      }
    }
    if (find_session_by_pub(c->pub) >= 0) {
      memset(c->pub, 0, sizeof(c->pub));
      reply(c, "SESSION STATUS RESULT=DUPLICATED_DEST\n");
      return;
    }
    snprintf(c->id, sizeof(c->id), "%s", id);
    {
      uint8_t bin[1024];
      size_t n;
      (void)rnc_i2p_b64_decode(c->pub, bin, sizeof(bin), &n);
      (void)rnc_i2p_b32(bin, n, c->b32);
    }
    c->state = SESSION;
    snprintf(out, sizeof(out), "SESSION STATUS RESULT=OK DESTINATION=%s\n",
             c->priv);
    reply(c, out);
  } else if (!strncmp(line, "NAMING LOOKUP", 13)) {
    int s, k;
    if (!word(line, "NAME", value, sizeof(value))) {
      reply(c, "NAMING REPLY RESULT=I2P_ERROR\n");
      return;
    }
    for (s = -1, k = 0; k < MAX_CONN; ++k) {
      char name[80];
      snprintf(name, sizeof(name), "%s.b32.i2p", conns[k].b32);
      if (conns[k].fd >= 0 && conns[k].state == SESSION &&
          !strcmp(name, value))
        s = k;
    }
    if (s < 0) {
      snprintf(out, sizeof(out), "NAMING REPLY RESULT=KEY_NOT_FOUND NAME=%s\n",
               value);
    } else
      snprintf(out, sizeof(out), "NAMING REPLY RESULT=OK NAME=%s VALUE=%s\n",
               value, conns[s].pub);
    reply(c, out);
  } else if (!strncmp(line, "STREAM ACCEPT", 13)) {
    if (!word(line, "ID", id, sizeof(id)) || find_session_by_id(id) < 0) {
      reply(c, "STREAM STATUS RESULT=INVALID_ID\n");
      return;
    }
    snprintf(c->id, sizeof(c->id), "%s", id);
    c->state = WAITING;
    reply(c, "STREAM STATUS RESULT=OK\n");
  } else if (!strncmp(line, "STREAM CONNECT", 14)) {
    int s, a;
    if (!word(line, "ID", id, sizeof(id)) ||
        (s = find_session_by_id(id)) < 0) {
      reply(c, "STREAM STATUS RESULT=INVALID_ID\n");
      return;
    }
    if (!word(line, "DESTINATION", value, sizeof(value)) ||
        find_session_by_pub(value) < 0) {
      reply(c, "STREAM STATUS RESULT=CANT_REACH_PEER\n");
      return;
    }
    {
      int target = find_session_by_pub(value);
      for (a = -1, s = 0; s < MAX_CONN; ++s)
        if (conns[s].fd >= 0 && conns[s].state == WAITING &&
            !strcmp(conns[s].id, conns[target].id)) {
          a = s;
          break;
        }
    }
    if (a < 0) {
      reply(c, "STREAM STATUS RESULT=CANT_REACH_PEER\n");
      return;
    }
    s = find_session_by_id(id);
    c->state = conns[a].state = BRIDGED;
    c->peer = a;
    conns[a].peer = i;
    reply(c, "STREAM STATUS RESULT=OK\n");
    snprintf(out, sizeof(out), "%s\n", conns[s].pub);
    reply(&conns[a], out);
  } else
    reply(c, "STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"unknown\"\n");
}
static void readable(int i) {
  conn *c = &conns[i];
  char data[4096];
  ssize_t n = read(c->fd, data, c->state == BRIDGED ? sizeof(data)
                                                     : sizeof(c->line) -
                                                           c->used - 1);
  size_t k;
  if (n <= 0) {
    drop(i);
    return;
  }
  if (c->state == BRIDGED) {
    {
      size_t off = 0;
      while (off < (size_t)n) {
        ssize_t w = write(conns[c->peer].fd, data + off, (size_t)n - off);
        if (w <= 0) {
          drop(i);
          return;
        }
        off += (size_t)w;
      }
    }
    return;
  }
  memcpy(c->line + c->used, data, (size_t)n);
  c->used += (size_t)n;
  for (;;) {
    char *nl = memchr(c->line, '\n', c->used);
    if (!nl)
      break;
    *nl = 0;
    k = (size_t)(nl - c->line) + 1u;
    {
      char copy[4096];
      snprintf(copy, sizeof(copy), "%s", c->line);
      memmove(c->line, c->line + k, c->used - k);
      c->used -= k;
      command(i, copy);
    }
    if (c->fd < 0 || c->state == BRIDGED)
      break;
  }
}
int main(int argc, char **argv) {
  int listener = socket(AF_INET, SOCK_STREAM, 0), one = 1, i;
  struct sockaddr_in a = {0};
  socklen_t n = sizeof(a);
  pid_t parent;
  if (argc < 2)
    return 2;
  log_file = fopen(argv[1], "a");
  for (i = 0; i < MAX_CONN; ++i)
    conns[i].fd = -1;
  setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = htons(argc > 2 ? (uint16_t)atoi(argv[2]) : 0);
  if (bind(listener, (struct sockaddr *)&a, sizeof(a)) < 0 ||
      listen(listener, 16) < 0 ||
      getsockname(listener, (struct sockaddr *)&a, &n) < 0)
    return 2;
  parent = getppid();
  printf("%u\n", ntohs(a.sin_port));
  fflush(stdout);
  for (;;) {
    struct pollfd pf[MAX_CONN + 1];
    int idx[MAX_CONN + 1], count = 1;
    pf[0].fd = listener;
    pf[0].events = POLLIN;
    for (i = 0; i < MAX_CONN; ++i)
      if (conns[i].fd >= 0) {
        pf[count].fd = conns[i].fd;
        pf[count].events = POLLIN;
        idx[count++] = i;
      }
    if (poll(pf, (nfds_t)count, 1000) < 0 && errno != EINTR)
      return 2;
    if (getppid() != parent) /* the test that started this is gone */
      return 0;
    if (pf[0].revents & POLLIN) {
      int fd = accept(listener, NULL, NULL);
      for (i = 0; fd >= 0 && i < MAX_CONN; ++i)
        if (conns[i].fd < 0) {
          memset(&conns[i], 0, sizeof(conns[i]));
          conns[i].fd = fd;
          fd = -1;
        }
      if (fd >= 0)
        close(fd);
    }
    for (i = 1; i < count; ++i)
      if ((pf[i].revents & (POLLIN | POLLHUP | POLLERR)) &&
          conns[idx[i]].fd == pf[i].fd)
        readable(idx[i]);
  }
}
