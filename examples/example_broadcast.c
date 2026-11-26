/* example_broadcast: the reference's Examples/Broadcast.py as a C program.
 *
 *   reticulum-c-example-broadcast (--listen HOST:PORT | --connect HOST:PORT) --identity FILE [--channel NAME]
 *
 * A PLAIN destination, "example_utilities.broadcast.NAME" (NAME is public_information by default), which holds
 * no keys: what is sent to it is readable by anyone who receives it. Lines typed are broadcast, broadcasts
 * received are printed. The peer may be another of these, or the reference's Broadcast.py on a TCP interface. */
#include "example_chat.h"

int main(int argc, char **argv) {
  const char *connect = NULL, *listen = NULL, *identity_file = NULL, *channel = "public_information";
  char name[128];
  uint8_t destination[16];
  rnc_identity id;
  rnc_node *node = NULL;
  rnc_host *host = NULL;
  int i, rc = 2;
  for (i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--connect") && i + 1 < argc)
      connect = argv[++i];
    else if (!strcmp(argv[i], "--listen") && i + 1 < argc)
      listen = argv[++i];
    else if (!strcmp(argv[i], "--identity") && i + 1 < argc)
      identity_file = argv[++i];
    else if (!strcmp(argv[i], "--channel") && i + 1 < argc)
      channel = argv[++i];
    else
      break;
  }
  if (i < argc || !identity_file || !connect == !listen ||
      snprintf(name, sizeof(name), "example_utilities.broadcast.%s", channel) >= (int)sizeof(name)) {
    fprintf(stderr, "usage: %s (--listen HOST:PORT | --connect HOST:PORT) --identity FILE [--channel NAME]\n", argv[0]);
    return 2;
  }
  if (!example_open_peer(connect ? connect : listen, listen != NULL, identity_file, &id, &node, &host))
    return 1;
  if (rnc_node_add_destination_ex(node, NULL, RNC_PLAIN, name, NULL, 0, destination) == RNC_OK)
    rc = example_chat(node, host, destination, NULL, "Broadcast example");
  rnc_host_free(host);
  rnc_node_free(node);
  rnc_identity_clear(&id);
  return rc;
}
