/* example_announce: announce a destination and print the announces other nodes make.
 *
 *   reticulum-c-example-announce --connect HOST:PORT --identity FILE [--app-data TEXT]
 *                                [--count N]
 *
 * It attaches to a node (reticulum-c-node, or any Reticulum TCP server interface), registers a
 * SINGLE destination "reticulum_c.example.announce" for the identity, announces it once the link is
 * up, then prints every announce that reaches this node: the destination hash, the hops, and the
 * application data as text. --count N exits after N announces have been heard (otherwise it runs
 * until interrupted). This is the library's announce path in about a hundred lines. */
#include "example_common.h"
#include <reticulum_c/rnc_node.h>

#define ASPECTS "reticulum_c.example.announce"

int main(int argc, char **argv) {
  const char *connect = NULL, *identity_file = NULL, *app_data = "hello from reticulum-c";
  unsigned long count = 0, heard = 0;
  int i, announced = 0;
  rnc_identity id;
  rnc_node *node = NULL;
  rnc_host *host = NULL;
  uint8_t destination[16];
  for (i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--connect") && i + 1 < argc)
      connect = argv[++i];
    else if (!strcmp(argv[i], "--identity") && i + 1 < argc)
      identity_file = argv[++i];
    else if (!strcmp(argv[i], "--app-data") && i + 1 < argc)
      app_data = argv[++i];
    else if (!strcmp(argv[i], "--count") && i + 1 < argc)
      count = strtoul(argv[++i], NULL, 10);
    else {
      fprintf(stderr, "usage: %s --connect HOST:PORT --identity FILE [--app-data TEXT] [--count N]\n", argv[0]);
      return 2;
    }
  }
  if (!connect || !identity_file) {
    fprintf(stderr, "--connect and --identity are required\n");
    return 2;
  }
  if (!example_open(connect, identity_file, &id, &node, &host))
    return 1;
  /* The destination is a hash of the aspects and the identity: other nodes learn the identity's
   * public key, and with it how to encrypt to this destination, from the announce. */
  if (rnc_node_add_destination(node, &id, ASPECTS, app_data, strlen(app_data), destination) != RNC_OK) {
    fprintf(stderr, "Cannot register the destination\n");
    return 1;
  }
  fputs("announcing <", stdout);
  example_print_hex(destination, 16);
  puts(">");
  fflush(stdout);
  while (!example_stopping && (!count || heard < count)) {
    rnc_host_event event;
    rnc_host_status status;
    uint64_t unix_now = (uint64_t)time(NULL), now = example_now_ms();
    if (rnc_host_step(host, 50, unix_now, now) != RNC_OK)
      break;
    /* Announce once, as soon as the link to the node is up. */
    if (!announced && rnc_host_get_status(host, 1, &status) == RNC_OK && status.online) {
      if (rnc_node_announce(node, destination, unix_now, now) == RNC_OK)
        announced = 1;
    }
    while (rnc_host_poll(host, &event) == RNC_OK) {
      const rnc_announce *a;
      if (event.type != RNC_HOST_NODE || event.node.type != RNC_NODE_ANNOUNCE)
        continue;
      a = &event.node.route.announce;
      if (!memcmp(a->destination, destination, 16))
        continue; /* our own announce coming back */
      fputs("heard <", stdout);
      example_print_hex(a->destination, 16);
      printf("> %u hop%s: %.*s\n", (unsigned)event.node.route.hops, event.node.route.hops == 1 ? "" : "s",
             (int)a->app_size, (const char *)a->app_data);
      fflush(stdout);
      ++heard;
    }
  }
  rnc_host_free(host);
  rnc_node_free(node);
  rnc_identity_clear(&id);
  return 0;
}
