/* example_echo: the reference's Examples/Echo.py as a C program.
 *
 *   reticulum-c-example-echo --connect HOST:PORT --identity FILE server
 *   reticulum-c-example-echo --connect HOST:PORT --identity FILE [--count N] [--timeout SECONDS] client DESTINATION
 *
 * The server registers the destination "example_utilities.echo.request", sets it to prove every packet it
 * receives, and announces it. The client waits for a path to the destination hash the server printed,
 * sends a packet of random data to it (encrypted to the server, as a reference client does) and waits for
 * the server's proof, which it reports with the round-trip time; with --count it does this N times, one a
 * second. The names, the packet content and the proof are those of the reference example, so a reference
 * Echo.py client can ping this server and this client can ping a reference Echo.py server. */
#include "example_common.h"
#include "example_echo_client.h"

#define APP_ASPECTS "example_utilities.echo.request"

static int run_server(rnc_node *node, rnc_host *host, rnc_identity *id) {
  uint8_t destination[16];
  int announced = 0;
  rnc_host_event event;
  uint64_t last_announce = 0;
  if (rnc_node_add_destination(node, id, APP_ASPECTS, NULL, 0, destination) != RNC_OK ||
      rnc_node_set_proof_strategy(node, destination, RNC_PROVE_ALL) != RNC_OK)
    return 1;
  fputs("Echo server ", stdout);
  print_hash(destination);
  puts(" running (Ctrl-C to quit)");
  fflush(stdout);
  while (!example_stopping) {
    rnc_host_status status;
    uint64_t now = example_now_ms();
    if (rnc_host_step(host, 20, (uint64_t)time(NULL), now) != RNC_OK)
      example_stopping = 1;
    while (rnc_host_poll(host, &event) == RNC_OK) {
      if (event.type == RNC_HOST_NODE && event.node.type == RNC_NODE_LOCAL) {
        /* the proof goes out by itself: the destination's proof strategy is PROVE_ALL */
        char stats[96] = "";
        if (event.has_signal)
          (void)snprintf(stats, sizeof(stats), " [RSSI %d dBm] [SNR %.2f dB]", event.rssi, (double)event.snr);
        printf("Received packet from echo client, proof sent%s\n", stats);
        fflush(stdout);
      }
    }
    /* announce once the interface is up, then every five minutes so clients that start later find us */
    if (rnc_host_get_status(host, 1, &status) == RNC_OK && status.online &&
        (!announced || now - last_announce >= 300000u)) {
      (void)rnc_node_announce(node, destination, (uint64_t)time(NULL), now);
      printf("Sent announce from ");
      print_hash(destination);
      putchar('\n');
      fflush(stdout);
      announced = 1;
      last_announce = now;
    }
  }
  return 0;
}
int main(int argc, char **argv) {
  const char *connect = NULL, *identity_file = NULL, *words[2] = {NULL, NULL};
  size_t word_count = 0;
  unsigned long count = 1;
  double timeout = 0;
  int i, rc;
  rnc_identity id;
  rnc_node *node = NULL;
  rnc_host *host = NULL;
  for (i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--connect") && i + 1 < argc)
      connect = argv[++i];
    else if (!strcmp(argv[i], "--identity") && i + 1 < argc)
      identity_file = argv[++i];
    else if (!strcmp(argv[i], "--count") && i + 1 < argc) {
      char *end;
      count = strtoul(argv[++i], &end, 10);
      if (*end || !count || count > 1000)
        word_count = 9;
    } else if (!strcmp(argv[i], "--timeout") && i + 1 < argc) {
      char *end;
      timeout = strtod(argv[++i], &end);
      if (*end || timeout < 0 || timeout > 3600)
        word_count = 9;
    } else if (word_count < 2)
      words[word_count++] = argv[i];
    else
      word_count = 9;
  }
  if (!connect || !identity_file || !word_count || word_count > 2 ||
      (!strcmp(words[0], "server") ? word_count != 1 : strcmp(words[0], "client") || word_count != 2)) {
    fprintf(stderr,
            "usage: %s --connect HOST:PORT --identity FILE server\n"
            "       %s --connect HOST:PORT --identity FILE [--count N] [--timeout SECONDS] client DESTINATION\n",
            argv[0], argv[0]);
    return 2;
  }
  if (!example_open(connect, identity_file, &id, &node, &host))
    return 1;
  rc = !strcmp(words[0], "server") ? run_server(node, host, &id) : echo_client(node, host, words[1], (unsigned)count, timeout);
  rnc_host_free(host);
  rnc_node_free(node);
  rnc_identity_clear(&id);
  return rc;
}
