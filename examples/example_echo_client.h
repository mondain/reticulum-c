/* The client of the echo examples (Echo.py and Ratchets.py have the same one): wait for a path, send random data
 * to the destination, wait for its proof and report the round-trip time. */
#ifndef RETICULUM_C_EXAMPLE_ECHO_CLIENT_H
#define RETICULUM_C_EXAMPLE_ECHO_CLIENT_H
#include "example_common.h"

static int hex_decode16(const char *text, uint8_t out[16]) {
  size_t i;
  if (strlen(text) != 32)
    return 0;
  for (i = 0; i < 16; ++i) {
    char pair[3] = {text[2 * i], text[2 * i + 1], 0};
    char *end;
    out[i] = (uint8_t)strtoul(pair, &end, 16);
    if (*end)
      return 0;
  }
  return 1;
}
static void print_hash(const uint8_t *hash) {
  fputc('<', stdout);
  example_print_hex(hash, 16);
  fputc('>', stdout);
}
/* Waits for the receipt of `hash`; returns 1 delivered, 0 failed or timed out */
static int wait_receipt(rnc_host *host, const uint8_t hash[32], const uint8_t destination[16], double timeout) {
  uint64_t start = example_now_ms();
  rnc_host_event event;
  while (!example_stopping && example_now_ms() - start < (uint64_t)(timeout * 1000.0) + 2000u) {
    if (rnc_host_step(host, 20, (uint64_t)time(NULL), example_now_ms()) != RNC_OK)
      return 0;
    while (rnc_host_poll(host, &event) == RNC_OK) {
      if (event.type != RNC_HOST_NODE || event.node.type != RNC_NODE_RECEIPT ||
          memcmp(event.node.receipt_hash, hash, 32))
        continue;
      if (event.node.receipt_status == RNC_RECEIPT_DELIVERED) {
        double rtt = (double)event.node.rtt_ms / 1000.0;
        char stats[96] = "";
        if (event.has_signal)
          (void)snprintf(stats, sizeof(stats), " [RSSI %d dBm] [SNR %.2f dB]", event.rssi, (double)event.snr);
        fputs("Valid reply received from ", stdout);
        print_hash(destination);
        if (rtt >= 1.0)
          printf(", round-trip time is %.3f seconds%s\n", rtt, stats);
        else
          printf(", round-trip time is %.3f milliseconds%s\n", rtt * 1000.0, stats);
        return 1;
      }
      fputs("Packet ", stdout);
      print_hash(event.node.receipt_hash); /* the receipt key is 32 bytes; the reference prints it whole */
      puts(" timed out");
      return 0;
    }
  }
  return 0;
}
static int echo_client(rnc_node *node, rnc_host *host, const char *destination_text, unsigned count, double timeout) {
  uint8_t destination[16], data[16], hash[32];
  unsigned i;
  int failed = 0;
  if (!hex_decode16(destination_text, destination)) {
    fprintf(stderr, "Invalid destination entered. Check your input!\n");
    return 2;
  }
  printf("Echo client ready, sending %u echo request%s to %s\n", count, count == 1 ? "" : "s", destination_text);
  if (rnc_host_await_path(host, destination, 15000, NULL, NULL) != RNC_OK) {
    puts("Destination is not yet known. Requesting path...");
    puts("Path not found");
    return 1;
  }
  for (i = 0; i < count && !example_stopping; ++i) {
    rnc_result r;
    if (example_random(NULL, data, sizeof(data)) != RNC_OK)
      return 1;
    r = rnc_node_send_single(node, destination, data, sizeof(data), timeout > 0 ? (uint64_t)(timeout * 1000.0) : 0,
                             (uint64_t)time(NULL), example_now_ms(), hash);
    if (r != RNC_OK) {
      puts("Could not send the echo request");
      return 1;
    }
    fputs("Sent echo request to ", stdout);
    print_hash(destination);
    putchar('\n');
    fflush(stdout);
    if (!wait_receipt(host, hash, destination, timeout > 0 ? timeout : 30.0))
      failed = 1;
    fflush(stdout);
    if (i + 1 < count) { /* one a second */
      uint64_t until = example_now_ms() + 1000u;
      while (!example_stopping && example_now_ms() < until)
        (void)rnc_host_step(host, 20, (uint64_t)time(NULL), example_now_ms());
    }
  }
  return failed;
}
#endif
