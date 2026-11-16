/* example_request: a request/response service and its client.
 *
 *   reticulum-c-example-request --connect HOST:PORT --identity FILE server
 *   reticulum-c-example-request --connect HOST:PORT --identity FILE client DESTINATION TEXT
 *
 * The server registers a destination "reticulum_c.example.request" with one request path, "/reverse".
 * Anyone may call it; it answers with the request text reversed. The client waits for a path to the
 * destination hash the server printed, opens a link, sends TEXT, prints the answer and exits. The
 * request and the response are single MessagePack values (here a binary string), as the reference's
 * Link.request carries them, so a reference RNS peer can call or serve the same path. */
#include "example_common.h"
#include <reticulum_c/rnc_ipc.h>
#include <reticulum_c/rnc_requester.h>
#include <reticulum_c/rnc_responder.h>

#define ASPECTS "reticulum_c.example.request"
#define PATH "/reverse"
#define LIMIT 4096u

/* A binary string as MessagePack: bin8 (0xc4) or bin16 (0xc5). */
static size_t bin_decode(const uint8_t *in, size_t size, const uint8_t **text) {
  if (size >= 2 && in[0] == 0xc4 && size >= 2u + in[1]) {
    *text = in + 2;
    return in[1];
  }
  if (size >= 3 && in[0] == 0xc5) {
    size_t n = ((size_t)in[1] << 8) | in[2];
    if (size >= 3u + n) {
      *text = in + 3;
      return n;
    }
  }
  return (size_t)-1;
}
/* The service: runs when a request for PATH arrives, with the request value and the caller's identity
 * hash (NULL if the caller did not identify). Writes the response value and its size. */
static rnc_result reverse(void *context, const char *path, const uint8_t *request, size_t request_size,
                          const uint8_t *identity_hash, uint8_t *response, size_t capacity, size_t *written) {
  const uint8_t *text;
  uint8_t reversed[LIMIT];
  size_t n = bin_decode(request, request_size, &text), i;
  rnc_rpc_writer w;
  (void)context;
  (void)path;
  (void)identity_hash;
  if (n == (size_t)-1 || n > sizeof(reversed))
    return RNC_AGAIN; /* no response */
  for (i = 0; i < n; ++i)
    reversed[i] = text[n - 1 - i];
  rnc_rpc_writer_init(&w, response, capacity);
  if (rnc_rpc_write_bin(&w, reversed, n) != RNC_OK)
    return RNC_NO_SPACE;
  return rnc_rpc_writer_finish(&w, written);
}
static void pump(rnc_host *host, rnc_responder *responder, rnc_requester *requester) {
  rnc_host_event event;
  uint64_t unix_now = (uint64_t)time(NULL), now = example_now_ms();
  if (rnc_host_step(host, 20, unix_now, now) != RNC_OK)
    example_stopping = 1;
  while (rnc_host_poll(host, &event) == RNC_OK) {
    if (event.type != RNC_HOST_NODE || event.node.type != RNC_NODE_LOCAL)
      continue;
    if (responder)
      (void)rnc_responder_input(responder, &event.node, unix_now, now);
    if (requester)
      (void)rnc_requester_input(requester, &event.node, unix_now, now);
  }
  now = example_now_ms();
  if (responder)
    (void)rnc_responder_tick(responder, unix_now, now);
  if (requester)
    (void)rnc_requester_tick(requester, unix_now, now);
}
static int hex_decode16(const char *text, uint8_t out[16]) {
  size_t i;
  if (strlen(text) != 32)
    return 0;
  for (i = 0; i < 16; ++i) {
    unsigned v;
    char pair[3] = {text[2 * i], text[2 * i + 1], 0};
    char *end;
    v = (unsigned)strtoul(pair, &end, 16);
    if (*end)
      return 0;
    out[i] = (uint8_t)v;
  }
  return 1;
}
static int run_server(rnc_node *node, rnc_host *host, rnc_identity *id) {
  uint8_t destination[16];
  rnc_responder *responder;
  int announced = 0;
  if (rnc_node_add_destination(node, id, ASPECTS, NULL, 0, destination) != RNC_OK)
    return 1;
  responder = rnc_responder_new(node, LIMIT * 2, example_random, NULL);
  if (!responder || rnc_responder_add_destination(responder, id, destination) != RNC_OK ||
      rnc_responder_register(responder, destination, PATH, RNC_SERVICE_ALLOW_ALL, NULL, 0, reverse, NULL) !=
          RNC_OK)
    return 1;
  fputs("serving " PATH " on <", stdout);
  example_print_hex(destination, 16);
  puts(">");
  fflush(stdout);
  while (!example_stopping) {
    rnc_host_status status;
    pump(host, responder, NULL);
    if (!announced && rnc_host_get_status(host, 1, &status) == RNC_OK && status.online) {
      (void)rnc_node_announce(node, destination, (uint64_t)time(NULL), example_now_ms());
      announced = 1;
    }
  }
  rnc_responder_free(responder);
  return 0;
}
static int run_client(rnc_node *node, rnc_host *host, rnc_identity *id, const char *destination_text,
                      const char *text) {
  uint8_t destination[16], request[LIMIT + 8u], answer[LIMIT * 2];
  rnc_rpc_writer w;
  rnc_requester *requester;
  rnc_requester_result result;
  size_t request_size = 0;
  int rc = 1;
  if (!hex_decode16(destination_text, destination)) {
    fprintf(stderr, "The destination is 32 hexadecimal characters\n");
    return 2;
  }
  rnc_rpc_writer_init(&w, request, sizeof(request));
  if (strlen(text) > LIMIT || rnc_rpc_write_bin(&w, text, strlen(text)) != RNC_OK ||
      rnc_rpc_writer_finish(&w, &request_size) != RNC_OK)
    return 2;
  requester = rnc_requester_new(node, LIMIT * 2, example_random, NULL);
  if (!requester)
    return 1;
  /* A request needs a path first: ask the network and wait up to 15 seconds for the announce. */
  if (rnc_host_await_path(host, destination, 15000, NULL, NULL) != RNC_OK) {
    puts("Path not found");
    rnc_requester_free(requester);
    return 1;
  }
  /* The link opens, the request goes out and the answer comes back, all inside this timeout. */
  if (rnc_requester_start(requester, destination, id, PATH, request, request_size, 1, 20000,
                          (uint64_t)time(NULL), example_now_ms()) != RNC_OK) {
    puts("Could not start the request");
    rnc_requester_free(requester);
    return 1;
  }
  while (!example_stopping) {
    pump(host, NULL, requester);
    if (rnc_requester_poll(requester, &result, answer, sizeof(answer)) == RNC_OK) {
      const uint8_t *reply;
      size_t n;
      if (result.status == RNC_REQUESTER_DONE && (n = bin_decode(answer, result.size, &reply)) != (size_t)-1) {
        printf("%.*s\n", (int)n, (const char *)reply);
        rc = 0;
      } else
        puts("The request failed");
      break;
    }
  }
  rnc_requester_free(requester);
  return rc;
}
int main(int argc, char **argv) {
  const char *connect = NULL, *identity_file = NULL, *words[3] = {NULL, NULL, NULL};
  size_t word_count = 0;
  int i, rc;
  rnc_identity id;
  rnc_node *node = NULL;
  rnc_host *host = NULL;
  for (i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--connect") && i + 1 < argc)
      connect = argv[++i];
    else if (!strcmp(argv[i], "--identity") && i + 1 < argc)
      identity_file = argv[++i];
    else if (word_count < 3)
      words[word_count++] = argv[i];
    else
      word_count = 4;
  }
  if (!connect || !identity_file || !word_count || word_count > 3 ||
      (!strcmp(words[0], "server") ? word_count != 1 : strcmp(words[0], "client") || word_count != 3)) {
    fprintf(stderr,
            "usage: %s --connect HOST:PORT --identity FILE server\n"
            "       %s --connect HOST:PORT --identity FILE client DESTINATION TEXT\n",
            argv[0], argv[0]);
    return 2;
  }
  if (!example_open(connect, identity_file, &id, &node, &host))
    return 1;
  rc = !strcmp(words[0], "server") ? run_server(node, host, &id) : run_client(node, host, &id, words[1], words[2]);
  rnc_host_free(host);
  rnc_node_free(node);
  rnc_identity_clear(&id);
  return rc;
}
