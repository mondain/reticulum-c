#define main rnc_node_daemon_program_main
#include "../examples/node_daemon.c"
#undef main
#include <dirent.h>
#include <sys/resource.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                  \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static rnc_result rng(void *ctx, uint8_t *out, size_t size) {
  size_t i;
  (void)ctx;
  for (i = 0; i < size; ++i)
    out[i] = (uint8_t)i;
  return RNC_OK;
}
static void query(const char *get, rnc_node *node, rnc_host *host,
                  const rnc_identity *id, const config *cfg, uint8_t *out,
                  size_t *size) {
  uint8_t data[128], destination[16] = {1};
  size_t n;
  rnc_rpc_writer w;
  rnc_rpc_writer_init(&w, data, sizeof(data));
  CHECK(rnc_rpc_write_map(&w, !strcmp(get, "next_hop") ? 2 : 1) == RNC_OK &&
        rnc_rpc_write_string(&w, "get") == RNC_OK &&
        rnc_rpc_write_string(&w, get) == RNC_OK);
  if (!strcmp(get, "next_hop"))
    CHECK(rnc_rpc_write_string(&w, "destination_hash") == RNC_OK &&
          rnc_rpc_write_bin(&w, destination, 16) == RNC_OK);
  CHECK(rnc_rpc_writer_finish(&w, &n) == RNC_OK);
  CHECK(rpc_response(out, 4096, size, data, n, host, node, cfg, id, 0, 0));
}
static void config_file(const char *path, const char *text) {
  FILE *f = fopen(path, "w");
  CHECK(f && fputs(text, f) >= 0 && !fclose(f));
}
static void stable_interface_test(void) {
  char dir[] = "/tmp/rnc-config-binding-XXXXXX", path[256];
  config first, reordered, changed;
  static const char *a = "[[A]]\ntype=TCPClientInterface\ntarget_host=127.0.0."
                         "1\ntarget_port=7001\n";
  static const char *b = "[[B]]\ntype=SerialInterface\nport=/dev/null\n";
  char text[2048];
  uint32_t aid, bid;
  rnc_identity owner, remote;
  uint8_t private_key[64] = {2}, record[STATE_MAX];
  size_t size;
  rnc_node *old, *replacement;
  rnc_packet announce;
  rnc_route route;
  CHECK(mkdtemp(dir) && snprintf(path, sizeof(path), "%s/config", dir) > 0);
  CHECK(snprintf(text, sizeof(text), "[interfaces]\n%s%s", a, b) > 0);
  config_file(path, text);
  CHECK(read_config(path, &first));
  aid = first.interfaces[0].interface_id;
  bid = first.interfaces[1].interface_id;
  CHECK(aid && bid && aid != bid);
  CHECK(snprintf(text, sizeof(text), "[interfaces]\n%s%s", b, a) > 0);
  config_file(path, text);
  CHECK(read_config(path, &reordered));
  CHECK(reordered.interfaces[0].interface_id == bid &&
        reordered.interfaces[1].interface_id == aid);
  CHECK(snprintf(text, sizeof(text),
                 "[interfaces]\n[[A]]\ntype=TCPClientInterface\ntarget_host="
                 "127.0.0.1\ntarget_port=7002\n%s",
                 b) > 0);
  config_file(path, text);
  CHECK(read_config(path, &changed));
  CHECK(changed.interfaces[0].interface_id != aid &&
        changed.interfaces[1].interface_id == bid);
  CHECK(rnc_identity_from_private(&owner, private_key) == RNC_OK);
  private_key[0] = 9;
  CHECK(rnc_identity_from_private(&remote, private_key) == RNC_OK);
  old = rnc_node_new(&owner, 0, rng, NULL);
  replacement = rnc_node_new(&owner, 0, rng, NULL);
  CHECK(old && replacement);
  CHECK(rnc_node_add_interface(old, aid, 1000000) == RNC_OK &&
        rnc_node_add_interface(replacement, changed.interfaces[0].interface_id,
                               1000000) == RNC_OK);
  CHECK(rnc_announce_create(&remote, "config.binding", NULL, 0, 1700000000, rng,
                            NULL, &announce) == RNC_OK);
  CHECK(rnc_node_input(old, aid, &announce, 1700000000, 0) == RNC_OK &&
        rnc_node_state_export(old, &owner, 1700000000, 0, record,
                              sizeof(record), &size) == RNC_OK);
  CHECK(rnc_node_state_import(replacement, &owner, 1700000001, 1000, record,
                              size) == RNC_OK);
  CHECK(rnc_node_lookup(replacement, announce.destination, 1000, &route) ==
        RNC_AGAIN);
  rnc_node_free(old);
  rnc_node_free(replacement);
  CHECK(!unlink(path) && !rmdir(dir));
}
static void checkpoint_retry_test(void) {
  char dir[] = "/tmp/rnc-state-retry-XXXXXX", path[256];
  struct rlimit saved, limited;
  rnc_identity id;
  uint8_t key[64] = {8};
  rnc_node *node;
  void (*old_signal)(int);
  CHECK(mkdtemp(dir) && snprintf(path, sizeof(path), "%s/state", dir) > 0);
  CHECK(rnc_identity_from_private(&id, key) == RNC_OK);
  node = rnc_node_new(&id, 0, rng, NULL);
  CHECK(node);
  CHECK(!getrlimit(RLIMIT_FSIZE, &saved));
  limited = saved;
  limited.rlim_cur = 32;
  old_signal = signal(SIGXFSZ, SIG_IGN);
  CHECK(old_signal != SIG_ERR && !setrlimit(RLIMIT_FSIZE, &limited));
  CHECK(!save_state(path, node, &id, 1700000000, 0));
  CHECK(!setrlimit(RLIMIT_FSIZE, &saved));
  (void)signal(SIGXFSZ, old_signal);
  CHECK(save_state(path, node, &id, 1700000000, 0));
  {
    DIR *d = opendir(dir);
    struct dirent *entry;
    unsigned count = 0;
    CHECK(d);
    while ((entry = readdir(d)) != NULL)
      if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
        ++count;
    closedir(d);
    CHECK(count == 1);
  }
  CHECK(!unlink(path) && !rmdir(dir));
  rnc_node_free(node);
}
int main(void) {
  rnc_identity id;
  uint8_t private_key[64] = {1}, out[4096];
  size_t size;
  rnc_node *node;
  rnc_host *host;
  config cfg;
  rnc_host_status status;
  rnc_rpc_writer w;
  memset(&cfg, 0, sizeof(cfg));
  memset(&status, 0, sizeof(status));
  CHECK(rnc_identity_from_private(&id, private_key) == RNC_OK);
  node = rnc_node_new(&id, 0, rng, NULL);
  CHECK(node);
  host = rnc_host_new(node);
  CHECK(host);
  query("interface_stats", node, host, &id, &cfg, out, &size);
  CHECK(size > 20);
  query("path_table", node, host, &id, &cfg, out, &size);
  CHECK(size == 1 && out[0] == 0x90);
  query("next_hop", node, host, &id, &cfg, out, &size);
  CHECK(size == 1 && out[0] == 0xc0);
  query("link_count", node, host, &id, &cfg, out, &size);
  CHECK(size == 1 && out[0] == 0);
  query("active_link_count", node, host, &id, &cfg, out, &size);
  CHECK(size == 1 && out[0] == 0);
  query("unknown", node, host, &id, &cfg, out, &size);
  CHECK(size == 1 && out[0] == 0xc0);
  status.kind = RNC_HOST_SERIAL;
  strcpy(status.name, "SerialInterface[Test]");
  status.online = 1;
  status.mtu = 500;
  status.bitrate = 1200;
  rnc_rpc_writer_init(&w, out, sizeof(out));
  interface_stats(&w, host, &status);
  CHECK(rnc_rpc_writer_finish(&w, &size) == RNC_OK && size > 50);
  rnc_host_free(host);
  rnc_node_free(node);
  checkpoint_retry_test();
  stable_interface_test();
  puts("node RPC response tests passed");
  return 0;
}
