/* Test client for the MCU example firmware (mcu/app). It attaches to a node's
 * TCP server like any Reticulum client, waits for the announce of the
 * "reticulum_c.mcu.example" destination, then requests /echo and /info and
 * checks the replies.
 *
 *   echo_client --connect HOST:PORT [--timeout SECONDS]
 *
 * Exit status 0 when both replies are right. Built in the default (OpenSSL)
 * build; it needs nothing from the MCU build except the wire protocol. */
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include <limits.h>
#include <openssl/rand.h>
#include <reticulum_c/rnc_host.h>
#include <reticulum_c/rnc_requester.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define APP_NAME "reticulum_c.mcu.example"
#define FAIL(...)                                                              \
  do {                                                                         \
    fprintf(stderr, "echo_client: " __VA_ARGS__);                              \
    fputc('\n', stderr);                                                       \
    return 1;                                                                  \
  } while (0)

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
static int contains(const uint8_t *hay, size_t n, const char *needle) {
  size_t k = strlen(needle), i;
  for (i = 0; i + k <= n; ++i)
    if (!memcmp(hay + i, needle, k))
      return 1;
  return 0;
}

int main(int argc, char **argv) {
  const char *connect_to = NULL;
  double timeout = 60.0;
  char address[256];
  const char *colon;
  rnc_identity id;
  rnc_node *node;
  rnc_host *host;
  rnc_requester *requester;
  rnc_host_config hc;
  rnc_host_event event;
  uint8_t destination[16], response[1024];
  int have_dest = 0, sent_echo = 0, sent_info = 0, done_echo = 0, done_info = 0;
  /* MessagePack array [1, "mcu", b"\x00\xff"]: arbitrary content must come back intact */
  static const uint8_t echo_value[] = {0x93, 0x01, 0xa3, 'm', 'c', 'u',
                                       0xc4, 0x02, 0x00, 0xff};
  uint64_t deadline, last_start = 0;
  int i;

  for (i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--connect") && i + 1 < argc)
      connect_to = argv[++i];
    else if (!strcmp(argv[i], "--timeout") && i + 1 < argc)
      timeout = atof(argv[++i]);
    else
      FAIL("usage: echo_client --connect HOST:PORT [--timeout SECONDS]");
  }
  if (!connect_to || !(colon = strrchr(connect_to, ':')) ||
      (size_t)(colon - connect_to) >= sizeof(address))
    FAIL("--connect HOST:PORT is required");
  memcpy(address, connect_to, (size_t)(colon - connect_to));
  address[colon - connect_to] = 0;

  if (rnc_identity_generate(&id, secure_random, NULL) != RNC_OK)
    FAIL("identity");
  node = rnc_node_new(&id, 0, secure_random, NULL);
  host = node ? rnc_host_new(node) : NULL;
  requester = node ? rnc_requester_new(node, 4096, secure_random, NULL) : NULL;
  if (!requester)
    FAIL("allocation");
  memset(&hc, 0, sizeof(hc));
  hc.kind = RNC_HOST_TCP_CONNECT;
  hc.name = "echo client";
  hc.address = address;
  hc.port = (uint16_t)atoi(colon + 1);
  hc.mtu = RNC_MAX_MTU;
  hc.bitrate = 1000000000u;
  if (rnc_host_add(host, 1, &hc) != RNC_OK)
    FAIL("cannot connect to %s", connect_to);

  deadline = monotonic_ms() + (uint64_t)(timeout * 1000.0);
  while (monotonic_ms() < deadline && !(done_echo && done_info)) {
    uint64_t unix_now = (uint64_t)time(NULL), now = monotonic_ms();
    rnc_requester_result result;
    if (rnc_host_step(host, 20, unix_now, now) != RNC_OK)
      FAIL("host step");
    while (rnc_host_poll(host, &event) == RNC_OK) {
      if (event.type != RNC_HOST_NODE)
        continue;
      if (event.node.type == RNC_NODE_ANNOUNCE &&
          rnc_announce_matches_aspect(&event.node.route.announce, APP_NAME)) {
        if (!have_dest)
          printf("announce from the MCU destination received\n");
        memcpy(destination, event.node.route.destination, 16);
        have_dest = 1;
      } else if (event.node.type == RNC_NODE_LOCAL)
        (void)rnc_requester_input(requester, &event.node, unix_now, now);
    }
    now = monotonic_ms();
    (void)rnc_requester_tick(requester, unix_now, now);
    if (have_dest && now >= last_start + 100) {
      rnc_result r = RNC_OK;
      if (!sent_echo) {
        r = rnc_requester_start(requester, destination, NULL, "/echo", echo_value,
                                sizeof(echo_value), 1, 20000, unix_now, now);
        sent_echo = r == RNC_OK;
      } else if (!sent_info) {
        const uint8_t none = 0xc0;
        r = rnc_requester_start(requester, destination, NULL, "/info", &none, 1, 2,
                                20000, unix_now, now);
        sent_info = r == RNC_OK;
      }
      last_start = now;
    }
    while (rnc_requester_poll(requester, &result, response, sizeof(response)) ==
           RNC_OK) {
      if (result.status != RNC_REQUESTER_DONE) {
        /* a failed attempt (for example a request sent before the path settled) is retried */
        if (result.tag == 1)
          sent_echo = 0;
        else
          sent_info = 0;
        fprintf(stderr, "echo_client: request %u failed, retrying\n",
                (unsigned)result.tag);
        continue;
      }
      if (result.tag == 1) {
        if (result.size != sizeof(echo_value) ||
            memcmp(response, echo_value, sizeof(echo_value)))
          FAIL("/echo returned %zu bytes that differ from the request",
               result.size);
        printf("/echo ok (%zu bytes)\n", result.size);
        done_echo = 1;
      } else if (result.tag == 2) {
        size_t n = result.size;
        if (n < 2 || (response[0] & 0xf0) != 0x80)
          FAIL("/info is not a MessagePack map");
        if (!contains(response, n, "reticulum-c-mcu") ||
            !contains(response, n, "version") || !contains(response, n, "board") ||
            !contains(response, n, "uptime"))
          FAIL("/info lacks expected fields");
        printf("/info ok (%zu bytes)\n", n);
        done_info = 1;
      }
    }
  }
  rnc_requester_free(requester);
  rnc_host_free(host);
  rnc_node_free(node);
  if (!have_dest)
    FAIL("no announce from the MCU destination before the timeout");
  if (!done_echo || !done_info)
    FAIL("requests incomplete (echo=%d info=%d)", done_echo, done_info);
  puts("mcu echo client: all checks passed");
  return 0;
}
