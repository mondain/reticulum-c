/* example_group: a GROUP destination, "reticulum_c.example.group", shared by everyone holding its key file.
 *
 *   reticulum-c-example-group keygen FILE
 *   reticulum-c-example-group (--listen HOST:PORT | --connect HOST:PORT) --identity FILE --key FILE
 *
 * The key file is what the members share, 128 bytes: the public key of the group's identity, which with the
 * name makes the destination hash, and the 64 byte symmetric key the packets are encrypted with. Give it only
 * to members. Lines typed are sent to the group, packets for the group are printed. The reference has no
 * GROUP example; its Destination of type GROUP with the same name, identity and key interoperates. */
#include "example_chat.h"
#include <fcntl.h>

#define NAME "reticulum_c.example.group"

static int keygen(const char *path) {
  rnc_identity identity;
  rnc_group_key key;
  uint8_t record[128];
  int fd, ok = 0;
  if (rnc_identity_generate(&identity, example_random, NULL) != RNC_OK ||
      rnc_group_generate(&key, example_random, NULL) != RNC_OK)
    return 1;
  memcpy(record, identity.public_key, 64); /* the private half is not needed and not kept */
  memcpy(record + 64, key.bytes, 64);
  fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd >= 0) {
    ok = write(fd, record, sizeof(record)) == (ssize_t)sizeof(record);
    ok = close(fd) == 0 && ok;
  }
  if (!ok)
    fprintf(stderr, "Cannot create %s: %s\n", path, strerror(errno));
  else
    printf("Group key written to %s\n", path);
  rnc_identity_clear(&identity);
  rnc_group_clear(&key);
  OPENSSL_cleanse(record, sizeof(record));
  return ok ? 0 : 1;
}
static int load_key(const char *path, rnc_identity *group, rnc_group_key *key) {
  uint8_t record[129];
  FILE *f = fopen(path, "rb");
  size_t got = f ? fread(record, 1, sizeof(record), f) : 0;
  int ok;
  if (f)
    fclose(f);
  ok = got == 128 && rnc_identity_from_public(group, record) == RNC_OK && rnc_group_import(key, record + 64) == RNC_OK;
  OPENSSL_cleanse(record, sizeof(record));
  return ok;
}
int main(int argc, char **argv) {
  const char *connect = NULL, *listen = NULL, *identity_file = NULL, *key_file = NULL;
  uint8_t destination[16];
  rnc_identity id, group;
  rnc_group_key key;
  rnc_node *node = NULL;
  rnc_host *host = NULL;
  int i, rc = 1;
  if (argc == 3 && !strcmp(argv[1], "keygen"))
    return keygen(argv[2]);
  for (i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--connect") && i + 1 < argc)
      connect = argv[++i];
    else if (!strcmp(argv[i], "--listen") && i + 1 < argc)
      listen = argv[++i];
    else if (!strcmp(argv[i], "--identity") && i + 1 < argc)
      identity_file = argv[++i];
    else if (!strcmp(argv[i], "--key") && i + 1 < argc)
      key_file = argv[++i];
    else
      break;
  }
  if (i < argc || !identity_file || !key_file || !connect == !listen) {
    fprintf(stderr,
            "usage: %s keygen FILE\n"
            "       %s (--listen HOST:PORT | --connect HOST:PORT) --identity FILE --key FILE\n",
            argv[0], argv[0]);
    return 2;
  }
  if (!load_key(key_file, &group, &key)) {
    fprintf(stderr, "Cannot load the group key %s\n", key_file);
    return 1;
  }
  if (!example_open_peer(connect ? connect : listen, listen != NULL, identity_file, &id, &node, &host))
    return 1;
  if (rnc_node_add_destination_ex(node, &group, RNC_GROUP, NAME, NULL, 0, destination) == RNC_OK)
    rc = example_chat(node, host, destination, &key, "Group example");
  rnc_host_free(host);
  rnc_node_free(node);
  rnc_identity_clear(&id);
  rnc_group_clear(&key);
  return rc;
}
