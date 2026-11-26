/* The loop shared by the broadcast and group examples: every line typed is sent as one packet to the
 * destination, every packet received for it is printed. Neither kind of packet is routed by transport nodes,
 * so the two ends are directly connected: one listens, the other connects to it. */
#ifndef RETICULUM_C_EXAMPLE_CHAT_H
#define RETICULUM_C_EXAMPLE_CHAT_H
#include "example_common.h"
#include <poll.h>
#include <reticulum_c/rnc_security.h>
#include <unistd.h>

/* One packet from here to the destination: PLAIN as it is, GROUP encrypted with the group's key. */
static int chat_send(rnc_node *node, const uint8_t destination[16], const rnc_group_key *key, const char *text,
                     size_t size) {
  rnc_packet packet;
  memset(&packet, 0, sizeof(packet));
  packet.flags = (uint8_t)((key ? RNC_GROUP : RNC_PLAIN) << 2); /* a broadcast DATA packet */
  memcpy(packet.destination, destination, 16);
  if (size > RNC_GROUP_MDU) {
    puts("That line is too long for one packet");
    return 1;
  }
  if (key) {
    size_t written = 0;
    if (rnc_group_encrypt(key, text, size, example_random, NULL, packet.data, sizeof(packet.data), &written) != RNC_OK)
      return 0;
    packet.data_size = written;
  } else {
    memcpy(packet.data, text, size);
    packet.data_size = size;
  }
  return rnc_node_send(node, &packet, (uint64_t)time(NULL), example_now_ms()) == RNC_OK;
}
static void chat_received(const rnc_packet *packet, const rnc_group_key *key) {
  uint8_t clear[RNC_MAX_MTU];
  const uint8_t *data = packet->data;
  size_t size = packet->data_size;
  if (key) { /* anyone can send to the group's address; only holders of the key can be read */
    size_t written = 0;
    if (rnc_group_decrypt(key, packet->data, packet->data_size, clear, sizeof(clear), &written) != RNC_OK) {
      puts("Dropped a packet that does not match the group key");
      return;
    }
    data = clear;
    size = written;
  }
  printf("Received data: %.*s\n", (int)size, (const char *)data);
}
/* Runs until Ctrl-C or the end of standard input. `title` starts the ready line. */
static int example_chat(rnc_node *node, rnc_host *host, const uint8_t destination[16], const rnc_group_key *key,
                        const char *title) {
  char input[1024];
  size_t used = 0;
  int ready = 0, ended = 0;
  uint64_t end_at = 0;
  setvbuf(stdout, NULL, _IOLBF, 0);
  while (!example_stopping && !(ended && example_now_ms() >= end_at)) {
    rnc_host_event event;
    rnc_host_status status;
    struct pollfd in = {STDIN_FILENO, POLLIN, 0};
    if (rnc_host_step(host, 20, (uint64_t)time(NULL), example_now_ms()) != RNC_OK)
      return 1;
    while (rnc_host_poll(host, &event) == RNC_OK)
      if (event.type == RNC_HOST_NODE && event.node.type == RNC_NODE_LOCAL &&
          !memcmp(event.node.packet.destination, destination, 16) && (event.node.packet.flags & 3u) == RNC_DATA)
        chat_received(&event.node.packet, key);
    if (!ready) { /* wait until the listener is up or the connection made, so nothing typed is lost */
      if (rnc_host_get_status(host, 1, &status) != RNC_OK || !status.online)
        continue;
      printf("%s <", title);
      example_print_hex(destination, 16);
      puts("> running, enter text and hit enter to send (Ctrl-C to quit)");
      ready = 1;
    }
    if (!ended && poll(&in, 1, 0) > 0) {
      ssize_t got = read(STDIN_FILENO, input + used, sizeof(input) - used);
      char *newline;
      if (got <= 0) { /* give the last packet a moment to leave */
        ended = 1;
        end_at = example_now_ms() + 500u;
        continue;
      }
      used += (size_t)got;
      while ((newline = memchr(input, '\n', used))) {
        size_t length = (size_t)(newline - input);
        if (length && !chat_send(node, destination, key, input, length))
          puts("Could not send");
        used -= length + 1u;
        memmove(input, newline + 1, used);
      }
      if (used == sizeof(input))
        used = 0; /* an endless line: drop it */
    }
  }
  return 0;
}
#endif
