/* What it takes to use links from a node and host, shared by the link and identify examples.
 *
 * A link (rnc_link) does no I/O. The program accepts or opens it, binds its address to the interface it uses,
 * feeds it the packets the node delivers for that address, sends the packets it asks to send, and ticks it.
 * example_links_step does one round of all that and hands every other link event to the program. */
#ifndef RETICULUM_C_EXAMPLE_LINK_H
#define RETICULUM_C_EXAMPLE_LINK_H
#include "example_common.h"
#include <poll.h>
#include <reticulum_c/rnc_link.h>
#include <reticulum_c/rnc_node.h>
#include <unistd.h>

#define EXAMPLE_LINKS 8u

typedef struct example_link {
  rnc_link *link; /* NULL: the slot is free */
  uint8_t id[16];
} example_link;
typedef struct example_links {
  rnc_node *node;
  rnc_host *host;
  example_link slot[EXAMPLE_LINKS];
  /* ACTIVE, IDENTIFIED, PACKET and CLOSED events; after CLOSED the slot is freed. */
  void (*on_event)(struct example_links *links, example_link *l, const rnc_link_event *event);
  void *context;
  /* set by a server: link requests for this destination are accepted with this identity */
  const rnc_identity *accept_as;
  uint8_t destination[16];
} example_links;

static void example_link_release(example_links *links, example_link *l) {
  (void)rnc_node_unbind_link(links->node, l->id);
  rnc_link_free(l->link);
  l->link = NULL;
}
static example_link *example_link_free_slot(example_links *links) {
  size_t i;
  for (i = 0; i < EXAMPLE_LINKS; ++i)
    if (!links->slot[i].link)
      return &links->slot[i];
  return NULL;
}
/* Sends what the link wants sent and reports the rest. */
static void example_link_drain(example_links *links, example_link *l) {
  rnc_link_event event;
  while (l->link && rnc_link_poll(l->link, &event) == RNC_OK) {
    if (event.type == RNC_LINK_SEND) {
      (void)rnc_node_send(links->node, &event.packet, (uint64_t)time(NULL), example_now_ms());
      continue;
    }
    links->on_event(links, l, &event);
    if (event.type == RNC_LINK_CLOSED) {
      while (rnc_link_poll(l->link, &event) == RNC_OK)
        if (event.type == RNC_LINK_SEND)
          (void)rnc_node_send(links->node, &event.packet, (uint64_t)time(NULL), example_now_ms());
      example_link_release(links, l);
    }
  }
}
/* Responder: a link request that arrived for our destination. */
static void example_link_accept(example_links *links, const rnc_node_event *request) {
  example_link *l = example_link_free_slot(links);
  if (!l || !(l->link = rnc_link_new(example_random, NULL)))
    return;
  if (rnc_link_configure_mtu(l->link, rnc_node_link_mtu_on(links->node, request->interface_id)) != RNC_OK ||
      rnc_link_accept(l->link, links->accept_as, links->destination, &request->packet, example_now_ms()) != RNC_OK ||
      rnc_link_address(l->link, l->id) != RNC_OK ||
      rnc_node_bind_link_on(links->node, l->id, request->interface_id) != RNC_OK) {
    rnc_link_free(l->link);
    l->link = NULL;
    return;
  }
  example_link_drain(links, l);
}
/* Initiator: a link to a destination whose path is known. NULL on failure. */
static example_link *example_link_open(example_links *links, const uint8_t destination[16]) {
  example_link *l = example_link_free_slot(links);
  rnc_route route;
  uint64_t now = example_now_ms();
  if (!l || rnc_node_lookup(links->node, destination, now, &route) != RNC_OK ||
      !(l->link = rnc_link_new(example_random, NULL)))
    return NULL;
  if (rnc_link_configure_mtu(l->link, rnc_node_link_mtu_to(links->node, destination, now)) != RNC_OK ||
      rnc_node_stamp_link(links->node, l->link, destination) != RNC_OK || /* if it announced a link request cost */
      rnc_link_open(l->link, &route.announce, now) != RNC_OK || rnc_link_address(l->link, l->id) != RNC_OK ||
      rnc_node_bind_link_on(links->node, l->id, route.interface_id) != RNC_OK) {
    rnc_link_free(l->link);
    l->link = NULL;
    return NULL;
  }
  example_link_drain(links, l);
  return l;
}
static void example_link_close(example_links *links, example_link *l) {
  if (l->link) {
    (void)rnc_link_close(l->link, example_now_ms());
    example_link_drain(links, l);
  }
}
/* One round: the network, the packets for our links, their timers. False when the host fails. */
static int example_links_step(example_links *links) {
  rnc_host_event event;
  size_t i;
  if (rnc_host_step(links->host, 20, (uint64_t)time(NULL), example_now_ms()) != RNC_OK)
    return 0;
  while (rnc_host_poll(links->host, &event) == RNC_OK) {
    const rnc_packet *packet = &event.node.packet;
    if (event.type != RNC_HOST_NODE || event.node.type != RNC_NODE_LOCAL)
      continue;
    if (links->accept_as && (packet->flags & 3u) == RNC_LINKREQUEST &&
        !memcmp(packet->destination, links->destination, 16)) {
      example_link_accept(links, &event.node);
      continue;
    }
    for (i = 0; i < EXAMPLE_LINKS; ++i)
      if (links->slot[i].link && !memcmp(packet->destination, links->slot[i].id, 16)) {
        (void)rnc_link_input(links->slot[i].link, packet, example_now_ms());
        example_link_drain(links, &links->slot[i]);
        break;
      }
  }
  for (i = 0; i < EXAMPLE_LINKS; ++i)
    if (links->slot[i].link) {
      (void)rnc_link_tick(links->slot[i].link, example_now_ms());
      example_link_drain(links, &links->slot[i]);
    }
  return 1;
}
/* Closes what is open and gives the close packets a moment to leave. */
static void example_links_shutdown(example_links *links) {
  size_t i;
  uint64_t until = example_now_ms() + 300u;
  for (i = 0; i < EXAMPLE_LINKS; ++i)
    example_link_close(links, &links->slot[i]);
  while (example_now_ms() < until)
    if (!example_links_step(links))
      return;
}
/* A typed line, without waiting: 1 with it in line, 0 when there is none yet, -1 at the end of input. */
static int example_read_line(char *line, size_t capacity) {
  static char buffer[1024];
  static size_t used;
  static int ended;
  char *newline = memchr(buffer, '\n', used);
  struct pollfd in = {STDIN_FILENO, POLLIN, 0};
  if (!newline && !ended && poll(&in, 1, 0) > 0) {
    ssize_t got = read(STDIN_FILENO, buffer + used, sizeof(buffer) - used);
    if (got <= 0)
      ended = 1;
    else
      used += (size_t)got;
    newline = memchr(buffer, '\n', used);
    if (!newline && used == sizeof(buffer))
      used = 0; /* an endless line: drop it */
  }
  if (!newline)
    return ended ? -1 : 0;
  *newline = 0;
  (void)snprintf(line, capacity, "%s", buffer);
  used -= (size_t)(newline - buffer) + 1u;
  memmove(buffer, newline + 1, used);
  return 1;
}
/* Server side: announce the destination once the interface is up, then every five minutes. */
static void example_announce_now_and_then(rnc_node *node, rnc_host *host, const uint8_t destination[16], uint64_t *last) {
  rnc_host_status status;
  uint64_t now = example_now_ms();
  if (rnc_host_get_status(host, 1, &status) != RNC_OK || !status.online || (*last && now - *last < 300000u))
    return;
  (void)rnc_node_announce(node, destination, (uint64_t)time(NULL), now);
  fputs("Sent announce from <", stdout);
  example_print_hex(destination, 16);
  puts(">");
  *last = now;
}
#endif
