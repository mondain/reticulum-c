/* Boilerplate shared by the stand-alone examples (example_announce.c, example_request.c): a signal
 * flag, secure randomness, a monotonic clock, and a node attached to a running reticulum-c-node
 * (or any Reticulum TCP server interface) over TCP. Everything protocol-related stays in the
 * example files; this header only gets a node and host running. */
#ifndef RETICULUM_C_EXAMPLE_COMMON_H
#define RETICULUM_C_EXAMPLE_COMMON_H
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include <errno.h>
#include <limits.h>
#include <openssl/rand.h>
#include <reticulum_c/rnc_host.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static volatile sig_atomic_t example_stopping;
static void example_on_signal(int sig) {
  (void)sig;
  example_stopping = 1;
}
static rnc_result example_random(void *context, uint8_t *out, size_t size) {
  (void)context;
  return size <= INT_MAX && RAND_priv_bytes(out, (int)size) == 1 ? RNC_OK : RNC_CRYPTO;
}
static uint64_t example_now_ms(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
static void example_print_hex(const uint8_t *data, size_t size) {
  size_t i;
  for (i = 0; i < size; ++i)
    printf("%02x", data[i]);
}
/* Loads (or creates) the identity file, then makes a node and a host with one TCP interface: a client
 * connected to "host:port", or with `listen` a server accepting peers there. Returns 1 on success. */
static inline int example_open_peer(const char *connect, int listen, const char *identity_file, rnc_identity *id,
                             rnc_node **node, rnc_host **host) {
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
  if (rnc_host_identity_load(identity_file, example_random, NULL, id) != RNC_OK) {
    fprintf(stderr, "Cannot load or create the identity file %s\n", identity_file);
    return 0;
  }
  *node = rnc_node_new(id, 0, example_random, NULL);
  *host = *node ? rnc_host_new(*node) : NULL;
  if (!*host)
    return 0;
  memset(&hc, 0, sizeof(hc));
  hc.kind = listen ? RNC_HOST_TCP_LISTEN : RNC_HOST_TCP_CONNECT;
  hc.name = "example link";
  hc.address = address;
  hc.port = (uint16_t)port;
  hc.mtu = RNC_MAX_MTU;
  hc.bitrate = 1000000000u;
  if (rnc_host_add(*host, 1, &hc) != RNC_OK) {
    fprintf(stderr, "Cannot %s %s: %s\n", listen ? "listen on" : "connect to", connect, strerror(errno));
    return 0;
  }
  signal(SIGINT, example_on_signal);
  signal(SIGTERM, example_on_signal);
  signal(SIGPIPE, SIG_IGN);
  return 1;
}
static inline int example_open(const char *connect, const char *identity_file, rnc_identity *id, rnc_node **node,
                               rnc_host **host) {
  return example_open_peer(connect, 0, identity_file, id, node, host);
}
#endif
