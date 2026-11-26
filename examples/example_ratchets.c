/* example_ratchets: the reference's Examples/Ratchets.py as a C program, an echo with forward secrecy.
 *
 *   reticulum-c-example-ratchets --connect HOST:PORT --identity FILE [--ratchets FILE] server
 *   reticulum-c-example-ratchets --connect HOST:PORT --identity FILE [--count N] [--timeout SECONDS] client DESTINATION
 *
 * The server's destination "example_utilities.ratchet.echo.request" announces a ratchet, a short-lived
 * encryption key, and replaces it every half hour. Clients encrypt to the ratchet they last heard, so a later
 * theft of the identity does not decrypt what was recorded. The server keeps its ratchet private keys in the
 * ratchets file (the identity file's name with .ratchets by default), in the reference's format, and proves
 * only what one of them decrypts. The client is the echo example's: rnc_node_send_single encrypts to the
 * announced ratchet by itself. */
#include "example_common.h"
#include "example_echo_client.h"
#include <fcntl.h>
#include <reticulum_c/rnc_security.h>
#include <unistd.h>

#define ASPECTS "example_utilities.ratchet.echo.request"
#define KEPT 8u               /* old keys still accepted; the reference keeps 512 */
#define ROTATE_SECONDS 1800u  /* the reference's RATCHET_INTERVAL */
#define FILE_LIMIT 2048u

/* Replaced as a whole, so an interrupted write cannot lose the keys. */
static int save_ratchets(const rnc_ratchets *store, const rnc_identity *id, const char *path) {
  uint8_t record[FILE_LIMIT];
  char temp[1100];
  size_t size = 0;
  int fd, ok = 0;
  if (rnc_ratchets_export_reference(store, id, record, sizeof(record), &size) != RNC_OK ||
      snprintf(temp, sizeof(temp), "%s.new", path) >= (int)sizeof(temp))
    return 0;
  (void)unlink(temp);
  fd = open(temp, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd >= 0) {
    ok = write(fd, record, size) == (ssize_t)size && fsync(fd) == 0;
    ok = close(fd) == 0 && ok && rename(temp, path) == 0;
  }
  OPENSSL_cleanse(record, sizeof(record));
  return ok;
}
static int load_ratchets(rnc_ratchets *store, const rnc_identity *id, const char *path) {
  uint8_t record[FILE_LIMIT];
  FILE *f = fopen(path, "rb");
  size_t size;
  rnc_result r;
  if (!f)
    return errno == ENOENT; /* none yet */
  size = fread(record, 1, sizeof(record), f);
  fclose(f);
  r = rnc_ratchets_import_reference(store, id, record, size, (uint64_t)time(NULL));
  OPENSSL_cleanse(record, sizeof(record));
  return r == RNC_OK;
}
/* A new key when one is due, saved before it is announced, then the announce. */
static int announce(rnc_node *node, rnc_ratchets *store, const rnc_identity *id, const uint8_t destination[16],
                    const char *path) {
  uint8_t public_key[32];
  if (rnc_ratchets_rotate(store, (uint64_t)time(NULL), example_random, NULL) != RNC_OK ||
      !save_ratchets(store, id, path) || rnc_ratchets_public(store, public_key) != RNC_OK ||
      rnc_node_set_ratchet(node, destination, public_key) != RNC_OK)
    return 0;
  return rnc_node_announce(node, destination, (uint64_t)time(NULL), example_now_ms()) == RNC_OK;
}
static int run_server(rnc_node *node, rnc_host *host, const rnc_identity *id, const char *path) {
  rnc_ratchet_key keys[KEPT];
  rnc_ratchets store;
  uint8_t destination[16];
  uint64_t last_announce = 0;
  int announced = 0, rc = 0;
  rnc_host_event event;
  /* no automatic proofs: a packet is proved once it has been decrypted */
  if (rnc_node_add_destination(node, id, ASPECTS, NULL, 0, destination) != RNC_OK ||
      rnc_ratchets_init(&store, id, keys, KEPT, ROTATE_SECONDS) != RNC_OK)
    return 1;
  if (!load_ratchets(&store, id, path)) {
    fprintf(stderr, "Cannot read the ratchets file %s\n", path);
    return 1;
  }
  fputs("Ratcheted echo server ", stdout);
  print_hash(destination);
  puts(" running (Ctrl-C to quit)");
  fflush(stdout);
  while (!example_stopping) {
    rnc_host_status status;
    uint64_t now = example_now_ms();
    if (rnc_host_step(host, 20, (uint64_t)time(NULL), now) != RNC_OK)
      break;
    while (rnc_host_poll(host, &event) == RNC_OK) {
      uint8_t clear[RNC_MAX_MTU], used[10];
      size_t size = 0;
      if (event.type != RNC_HOST_NODE || event.node.type != RNC_NODE_LOCAL ||
          memcmp(event.node.packet.destination, destination, 16) || (event.node.packet.flags & 3u) != RNC_DATA)
        continue;
      /* enforce: only a ratchet decrypts it, not the identity key */
      if (rnc_ratchets_decrypt(&store, id, 1, event.node.packet.data, event.node.packet.data_size, clear,
                               sizeof(clear), &size, used) != RNC_OK) {
        puts("Received a packet no ratchet decrypts, no proof sent");
      } else if (rnc_node_prove(node, destination, &event.node.packet, event.node.interface_id, 1,
                                (uint64_t)time(NULL), now) == RNC_OK)
        puts("Received packet from echo client, proof sent");
      fflush(stdout);
    }
    /* announce once the interface is up, then every five minutes; a due rotation happens with it */
    if (rnc_host_get_status(host, 1, &status) == RNC_OK && status.online &&
        (!announced || now - last_announce >= 300000u)) {
      if (!announce(node, &store, id, destination, path)) {
        fprintf(stderr, "Cannot rotate and announce the ratchet\n");
        rc = 1;
        break;
      }
      fputs("Sent announce from ", stdout);
      print_hash(destination);
      putchar('\n');
      fflush(stdout);
      announced = 1;
      last_announce = now;
    }
  }
  rnc_ratchets_clear(&store);
  return rc;
}
int main(int argc, char **argv) {
  const char *connect = NULL, *identity_file = NULL, *ratchets_file = NULL, *words[2] = {NULL, NULL};
  char default_ratchets[1024];
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
    else if (!strcmp(argv[i], "--ratchets") && i + 1 < argc)
      ratchets_file = argv[++i];
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
      (!strcmp(words[0], "server") ? word_count != 1 : strcmp(words[0], "client") || word_count != 2) ||
      snprintf(default_ratchets, sizeof(default_ratchets), "%s.ratchets", identity_file) >= (int)sizeof(default_ratchets)) {
    fprintf(stderr,
            "usage: %s --connect HOST:PORT --identity FILE [--ratchets FILE] server\n"
            "       %s --connect HOST:PORT --identity FILE [--count N] [--timeout SECONDS] client DESTINATION\n",
            argv[0], argv[0]);
    return 2;
  }
  if (!example_open(connect, identity_file, &id, &node, &host))
    return 1;
  rc = !strcmp(words[0], "server")
           ? run_server(node, host, &id, ratchets_file ? ratchets_file : default_ratchets)
           : echo_client(node, host, words[1], (unsigned)count, timeout);
  rnc_host_free(host);
  rnc_node_free(node);
  rnc_identity_clear(&id);
  return rc;
}
