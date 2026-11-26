/* The server and client of the link and identify examples: lines typed on the client travel over a link, the
 * server prints them and answers. With `identify` the client then says who it is, and the server reports it. */
#ifndef RETICULUM_C_EXAMPLE_LINK_CHAT_H
#define RETICULUM_C_EXAMPLE_LINK_CHAT_H
#include "example_link.h"

#define EXAMPLE_ALLOWED 16u

typedef struct example_chat_options {
  const char *aspects, *title; /* the destination, and the start of the server's ready line */
  int identify;
  uint8_t allowed[EXAMPLE_ALLOWED][16]; /* server: only these may talk; none means anyone */
  size_t allowed_count;
} example_chat_options;
typedef struct example_chat_state {
  const example_chat_options *options;
  const rnc_identity *identity; /* the client identifies as this */
  int active, closed;
  rnc_link_teardown reason;
} example_chat_state;

static void print_peer(const rnc_link *link) {
  rnc_identity peer;
  if (rnc_link_remote_identity(link, &peer) != RNC_OK) {
    fputs("unidentified peer", stdout);
    return;
  }
  putchar('<');
  example_print_hex(peer.hash, 16);
  putchar('>');
}
static int example_allowed(const example_chat_options *o, const uint8_t hash[16]) {
  size_t i;
  for (i = 0; i < o->allowed_count; ++i)
    if (!memcmp(o->allowed[i], hash, 16))
      return 1;
  return !o->allowed_count;
}
static void server_event(example_links *links, example_link *l, const rnc_link_event *event) {
  const example_chat_options *o = ((example_chat_state *)links->context)->options;
  if (event->type == RNC_LINK_ACTIVE)
    puts("Client connected");
  else if (event->type == RNC_LINK_CLOSED)
    puts("Client disconnected");
  else if (event->type == RNC_LINK_IDENTIFIED) {
    fputs("Remote identified as: ", stdout);
    print_peer(l->link);
    putchar('\n');
    if (!example_allowed(o, event->identity_hash)) {
      puts("Identity not allowed, closing the link");
      (void)rnc_link_close(l->link, example_now_ms());
    }
  } else if (event->type == RNC_LINK_PACKET && event->context == 0) {
    char reply[RNC_LINK_MDU + 1u];
    rnc_identity peer;
    int known = rnc_link_remote_identity(l->link, &peer) == RNC_OK;
    int n;
    if (o->allowed_count && !(known && example_allowed(o, peer.hash)))
      return; /* with an allow list, nothing is read from a peer that has not shown it is on it */
    fputs("Received data", stdout);
    if (o->identify) {
      fputs(" from ", stdout);
      print_peer(l->link);
      printf(": %.*s\n", (int)event->size, (const char *)event->data);
    } else
      printf(" on the link: %.*s\n", (int)event->size, (const char *)event->data);
    n = snprintf(reply, sizeof(reply), "I received \"%.*s\" over the link", (int)event->size, (const char *)event->data);
    if (o->identify && n > 0 && (size_t)n < sizeof(reply)) {
      char hex[33] = "";
      size_t i;
      for (i = 0; known && i < 16; ++i)
        (void)snprintf(hex + 2 * i, 3, "%02x", peer.hash[i]);
      n += snprintf(reply + n, sizeof(reply) - (size_t)n, known ? " from <%s>" : " from unidentified peer%s", hex);
    }
    if (n > 0)
      (void)rnc_link_send_packet(l->link, 0, reply, (size_t)n < sizeof(reply) ? (size_t)n : sizeof(reply) - 1u,
                                 example_now_ms());
  }
  fflush(stdout);
}
static void client_event(example_links *links, example_link *l, const rnc_link_event *event) {
  example_chat_state *state = links->context;
  if (event->type == RNC_LINK_ACTIVE) {
    state->active = 1;
    if (state->options->identify) {
      puts("Link established with server, identifying to remote peer...");
      (void)rnc_link_identify(l->link, state->identity, example_now_ms());
    } else
      puts("Link established with server, enter some text to send, or \"quit\" to quit");
  } else if (event->type == RNC_LINK_PACKET && event->context == 0)
    printf("Received data on the link: %.*s\n", (int)event->size, (const char *)event->data);
  else if (event->type == RNC_LINK_CLOSED) {
    state->closed = 1;
    state->reason = rnc_link_teardown_reason(l->link);
  }
  fflush(stdout);
}
static int chat_server(rnc_node *node, rnc_host *host, const rnc_identity *id, const example_chat_options *options) {
  static example_links links;
  example_chat_state state = {0};
  uint64_t last_announce = 0;
  state.options = options;
  links.node = node;
  links.host = host;
  links.on_event = server_event;
  links.context = &state;
  links.accept_as = id;
  if (rnc_node_add_destination(node, id, options->aspects, NULL, 0, links.destination) != RNC_OK)
    return 1;
  printf("%s <", options->title);
  example_print_hex(links.destination, 16);
  puts("> running, waiting for a connection.");
  fflush(stdout);
  while (!example_stopping && example_links_step(&links)) {
    example_announce_now_and_then(node, host, links.destination, &last_announce);
    fflush(stdout);
  }
  example_links_shutdown(&links);
  return 0;
}
static int chat_client(rnc_node *node, rnc_host *host, const rnc_identity *id, const example_chat_options *options,
                       const uint8_t destination[16]) {
  static example_links links;
  example_chat_state state = {0};
  example_link *l;
  char line[1024];
  state.options = options;
  state.identity = id;
  links.node = node;
  links.host = host;
  links.on_event = client_event;
  links.context = &state;
  setvbuf(stdout, NULL, _IOLBF, 0);
  if (options->identify) {
    fputs("Client identity <", stdout);
    example_print_hex(id->hash, 16);
    puts(">");
  }
  if (rnc_host_await_path(host, destination, 15000, NULL, NULL) != RNC_OK) {
    puts("Path not found");
    return 1;
  }
  puts("Establishing link with server...");
  l = example_link_open(&links, destination);
  if (!l) {
    puts("Could not establish link");
    return 1;
  }
  while (!example_stopping && !state.closed && example_links_step(&links)) {
    int got;
    if (!state.active)
      continue;
    got = example_read_line(line, sizeof(line));
    if (got < 0 || (got > 0 && (!strcmp(line, "quit") || !strcmp(line, "q") || !strcmp(line, "exit"))))
      break;
    if (got > 0 && *line) {
      if (strlen(line) > rnc_link_mdu(l->link))
        printf("Cannot send this packet, it exceeds the link packet MDU of %zu bytes\n", rnc_link_mdu(l->link));
      else if (rnc_link_send_packet(l->link, 0, line, strlen(line), example_now_ms()) != RNC_OK)
        puts("Could not send");
    }
  }
  if (state.closed) {
    puts(state.reason == RNC_TEARDOWN_TIMEOUT              ? "The link timed out, exiting now"
         : state.reason == RNC_TEARDOWN_DESTINATION_CLOSED ? "The link was closed by the server, exiting now"
                                                           : "Link closed, exiting now");
    return state.reason == RNC_TEARDOWN_TIMEOUT;
  }
  example_links_shutdown(&links);
  return 0;
}
/* The command line both examples share. `allow` says whether the server takes --allow. */
static int example_link_main(int argc, char **argv, example_chat_options *options) {
  const char *connect = NULL, *identity_file = NULL, *words[2] = {NULL, NULL};
  size_t word_count = 0, i;
  int a, rc;
  uint8_t destination[16] = {0};
  rnc_identity id;
  rnc_node *node = NULL;
  rnc_host *host = NULL;
  for (a = 1; a < argc; ++a) {
    if (!strcmp(argv[a], "--connect") && a + 1 < argc)
      connect = argv[++a];
    else if (!strcmp(argv[a], "--identity") && a + 1 < argc)
      identity_file = argv[++a];
    else if (!strcmp(argv[a], "--allow") && a + 1 < argc && options->identify) {
      ++a;
      if (options->allowed_count == EXAMPLE_ALLOWED || strlen(argv[a]) != 32)
        word_count = 9;
      else {
        for (i = 0; i < 16; ++i) {
          char pair[3] = {argv[a][2 * i], argv[a][2 * i + 1], 0};
          char *end;
          options->allowed[options->allowed_count][i] = (uint8_t)strtoul(pair, &end, 16);
          if (*end)
            word_count = 9;
        }
        ++options->allowed_count;
      }
    } else if (word_count < 2)
      words[word_count++] = argv[a];
    else
      word_count = 9;
  }
  if (word_count == 2 && !strcmp(words[0], "client") && strlen(words[1]) == 32)
    for (i = 0; i < 16; ++i) {
      char pair[3] = {words[1][2 * i], words[1][2 * i + 1], 0};
      char *end;
      destination[i] = (uint8_t)strtoul(pair, &end, 16);
      if (*end)
        word_count = 9;
    }
  if (!connect || !identity_file || !word_count || word_count > 2 ||
      (!strcmp(words[0], "server") ? word_count != 1
                                   : strcmp(words[0], "client") || word_count != 2 || strlen(words[1]) != 32)) {
    fprintf(stderr,
            "usage: %s --connect HOST:PORT --identity FILE %sserver\n"
            "       %s --connect HOST:PORT --identity FILE client DESTINATION\n",
            argv[0], options->identify ? "[--allow IDENTITY]... " : "", argv[0]);
    return 2;
  }
  if (!example_open(connect, identity_file, &id, &node, &host))
    return 1;
  setvbuf(stdout, NULL, _IOLBF, 0);
  rc = !strcmp(words[0], "server") ? chat_server(node, host, &id, options)
                                   : chat_client(node, host, &id, options, destination);
  rnc_host_free(host);
  rnc_node_free(node);
  rnc_identity_clear(&id);
  return rc;
}
#endif
