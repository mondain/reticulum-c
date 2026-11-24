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
static int has(const uint8_t *buf, size_t size, const char *text, size_t n);
/* The remote management "rates" query (rnpath -R -r): the same entries as the local rate table, and
 * optionally only those of one destination. */
static void mgmt_rates_test(void) {
  uint8_t key1[64] = {1}, key2[64] = {2}, other[16] = {0x42}, req[64], out[1024];
  rnc_identity id, src;
  rnc_packet a;
  rnc_node *node;
  rnc_host *host;
  rnc_interface_policy policy = {0};
  rnc_rpc_writer w;
  size_t n, size;
  CHECK(rnc_identity_from_private(&id, key1) == RNC_OK && rnc_identity_from_private(&src, key2) == RNC_OK);
  node = rnc_node_new(&id, 1, rng, NULL);
  CHECK(node && rnc_node_add_interface(node, 1, 1000000) == RNC_OK && rnc_node_add_interface(node, 2, 1000000) == RNC_OK);
  policy.announce_rate_target = 60;
  policy.announce_rate_grace = 3;
  policy.announce_rate_penalty = 120;
  CHECK(rnc_node_interface_policy(node, 1, &policy) == RNC_OK);
  CHECK(rnc_announce_create(&src, "rates.remote", NULL, 0, 1000, rng, NULL, &a) == RNC_OK);
  CHECK(rnc_node_input(node, 1, &a, 1000, 0) == RNC_OK);
  host = rnc_host_new(node);
  CHECK(host);
  memset(&mgmt, 0, sizeof(mgmt));
  mgmt.host = host;
  mgmt.node = node;
  rnc_rpc_writer_init(&w, req, sizeof(req));
  CHECK(rnc_rpc_write_array(&w, 2) == RNC_OK && rnc_rpc_write_string(&w, "rates") == RNC_OK && rnc_rpc_write_nil(&w) == RNC_OK &&
        rnc_rpc_writer_finish(&w, &n) == RNC_OK);
  CHECK(mgmt_path(&mgmt, "/path", req, n, id.hash, out, sizeof(out), &size) == RNC_OK);
  CHECK(size > 40 && out[0] == 0x91 && out[1] == 0x85 && has(out, size, "rate_violations", 15));
  rnc_rpc_writer_init(&w, req, sizeof(req));
  CHECK(rnc_rpc_write_array(&w, 2) == RNC_OK && rnc_rpc_write_string(&w, "rates") == RNC_OK &&
        rnc_rpc_write_bin(&w, a.destination, 16) == RNC_OK && rnc_rpc_writer_finish(&w, &n) == RNC_OK);
  CHECK(mgmt_path(&mgmt, "/path", req, n, id.hash, out, sizeof(out), &size) == RNC_OK && out[0] == 0x91);
  rnc_rpc_writer_init(&w, req, sizeof(req));
  CHECK(rnc_rpc_write_array(&w, 2) == RNC_OK && rnc_rpc_write_string(&w, "rates") == RNC_OK &&
        rnc_rpc_write_bin(&w, other, 16) == RNC_OK && rnc_rpc_writer_finish(&w, &n) == RNC_OK);
  CHECK(mgmt_path(&mgmt, "/path", req, n, id.hash, out, sizeof(out), &size) == RNC_OK && size == 1 && out[0] == 0x90);
  memset(&mgmt, 0, sizeof(mgmt));
  rnc_host_free(host);
  rnc_node_free(node);
}
/* The drop calls over the RPC: a known path answers True and is gone, a second drop False, all_via counts. */
static void drop_rpc_test(void) {
  uint8_t private_key[64] = {1}, key2[64] = {2}, out[256], data[128];
  rnc_identity id, src;
  rnc_packet a;
  rnc_node *node;
  rnc_host *host;
  rnc_route route;
  rnc_rpc_writer w;
  config cfg;
  size_t size, n;
  memset(&cfg, 0, sizeof(cfg));
  CHECK(rnc_identity_from_private(&id, private_key) == RNC_OK && rnc_identity_from_private(&src, key2) == RNC_OK);
  node = rnc_node_new(&id, 0, rng, NULL);
  CHECK(node && rnc_node_add_interface(node, 1, 1000000) == RNC_OK);
  host = rnc_host_new(node);
  CHECK(host && rnc_announce_create(&src, "drop.rpc", NULL, 0, 1000, rng, NULL, &a) == RNC_OK);
  CHECK(rnc_node_input(node, 1, &a, 1000, 0) == RNC_OK);
  rnc_rpc_writer_init(&w, data, sizeof(data));
  CHECK(rnc_rpc_write_map(&w, 2) == RNC_OK && rnc_rpc_write_string(&w, "drop") == RNC_OK &&
        rnc_rpc_write_string(&w, "path") == RNC_OK && rnc_rpc_write_string(&w, "destination_hash") == RNC_OK &&
        rnc_rpc_write_bin(&w, a.destination, 16) == RNC_OK && rnc_rpc_writer_finish(&w, &n) == RNC_OK);
  CHECK(rpc_response(out, sizeof(out), &size, data, n, host, node, &cfg, &id, 0, 0));
  CHECK(size == 1 && out[0] == 0xc3 && rnc_node_lookup(node, a.destination, 0, &route) == RNC_AGAIN);
  CHECK(rpc_response(out, sizeof(out), &size, data, n, host, node, &cfg, &id, 0, 0));
  CHECK(size == 1 && out[0] == 0xc2);
  rnc_rpc_writer_init(&w, data, sizeof(data));
  CHECK(rnc_rpc_write_map(&w, 1) == RNC_OK && rnc_rpc_write_string(&w, "drop") == RNC_OK &&
        rnc_rpc_write_string(&w, "announce_queues") == RNC_OK && rnc_rpc_writer_finish(&w, &n) == RNC_OK);
  CHECK(rpc_response(out, sizeof(out), &size, data, n, host, node, &cfg, &id, 0, 0));
  CHECK(size == 1 && out[0] == 0xc0);
  rnc_host_free(host);
  rnc_node_free(node);
}
static void config_file(const char *path, const char *text) {
  FILE *f = fopen(path, "w");
  CHECK(f && fputs(text, f) >= 0 && !fclose(f));
}
static void internal_mode_config_test(void) {
  char dir[] = "/tmp/rnc-config-internal-XXXXXX", path[256];
  config c;
  CHECK(mkdtemp(dir) && snprintf(path, sizeof(path), "%s/config", dir) > 0);
  config_file(path,
              "[interfaces]\n[[A]]\ntype=TCPClientInterface\ntarget_host=127.0.0.1\ntarget_port=7001\n"
              "mode=internal\nannounces_from_internal=No\nannounces_to_internal=Yes\n"
              "[[B]]\ntype=SerialInterface\nport=/dev/null\n");
  CHECK(read_config(path, &c));
  CHECK(c.interfaces[0].host.mode == RNC_MODE_INTERNAL &&
        c.interfaces[0].host.no_announces_from_internal == 1 &&
        c.interfaces[0].host.announces_to_internal == 1);
  CHECK(c.interfaces[1].host.mode == RNC_MODE_FULL && c.interfaces[1].host.no_announces_from_internal == 0 &&
        c.interfaces[1].host.announces_to_internal == 0); /* the reference defaults */
  config_file(path, "[interfaces]\n[[A]]\ntype=SerialInterface\nport=/dev/null\nannounces_to_internal=maybe\n");
  CHECK(!read_config(path, &c));
  CHECK(!unlink(path) && !rmdir(dir));
}
static void gravity_config_test(void) {
  char dir[] = "/tmp/rnc-config-gravity-XXXXXX", path[256];
  config c;
  CHECK(mkdtemp(dir) && snprintf(path, sizeof(path), "%s/config", dir) > 0);
  config_file(path,
              "[reticulum]\ndefault_gravity=3\nautoconnect_interface_gravity=7\n"
              "autoconnect_announces_to_internal=Yes\n"
              "[interfaces]\n[[A]]\ntype=TCPClientInterface\ntarget_host=127.0.0.1\ntarget_port=7001\ngravity=9\n"
              "[[B]]\ntype=SerialInterface\nport=/dev/null\n[[C]]\ntype=SerialInterface\nport=/dev/null\ngravity=-2\n");
  CHECK(read_config(path, &c));
  CHECK(c.interfaces[0].host.gravity == 9 && c.interfaces[1].host.gravity == 3 &&
        c.interfaces[2].host.gravity == -2); /* default_gravity applies where an interface sets none */
  CHECK(c.autoconnect_gravity == 7 && c.autoconnect_announces_to_internal == 1);
  config_file(path, "[reticulum]\nautoconnect_interface_gravity=high\n[interfaces]\n");
  CHECK(!read_config(path, &c));
  config_file(path, "[interfaces]\n[[A]]\ntype=SerialInterface\nport=/dev/null\n");
  CHECK(read_config(path, &c) && c.interfaces[0].host.gravity == 0 && c.autoconnect_gravity == 0 &&
        c.autoconnect_announces_to_internal == 0);
  CHECK(!unlink(path) && !rmdir(dir));
}
/* Discovery announcements for I2P and Weave interfaces (Discovery.py: reachable_on is the b32 of a connectable
 * I2P interface; a Weave interface announces frequency, bandwidth, channel and modulation). */
static void discovery_types_test(void) {
  char dir[] = "/tmp/rnc-config-disctypes-XXXXXX", path[256];
  config c;
  rnc_identity id;
  uint8_t private_key[64] = {5};
  rnc_discovery_info info;
  CHECK(mkdtemp(dir) && snprintf(path, sizeof(path), "%s/config", dir) > 0);
  config_file(path,
              "[interfaces]\n[[W]]\ntype=WeaveInterface\nport=/dev/null\ndiscoverable=Yes\n"
              "discovery_frequency=868000000\ndiscovery_bandwidth=125000\ndiscovery_modulation=2\n"
              "[[I]]\ntype=I2PInterface\nconnectable=Yes\ndiscoverable=Yes\n");
  CHECK(read_config(path, &c));
  CHECK(rnc_identity_from_private(&id, private_key) == RNC_OK);
  mgmt.identity = &id;
  mgmt.settings = c;
  CHECK(discovery_describe(&c.interfaces[0], &info));
  CHECK(!strcmp(info.type, "WeaveInterface") && info.has_frequency && info.frequency == 868000000u &&
        info.has_bandwidth && info.bandwidth == 125000u && info.has_modulation &&
        !strcmp(info.modulation, "2") && !info.has_channel && !info.reachable_on[0]);
  {
    uint8_t packed[512];
    size_t used;
    CHECK(rnc_discovery_pack(&info, packed, sizeof(packed), &used) == RNC_OK && used > 20);
  }
  /* an I2P interface announces its b32 only when it is connectable and has one */
  memset(&info, 0, sizeof(info));
  i2p_publish(&info, 1, "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst");
  CHECK(!strcmp(info.type, "I2PInterface") &&
        !strcmp(info.reachable_on, "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst") && !info.has_port);
  memset(&info, 0, sizeof(info));
  i2p_publish(&info, 0, "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst");
  CHECK(!strcmp(info.type, "I2PInterface") && !info.reachable_on[0]);
  memset(&info, 0, sizeof(info));
  i2p_publish(&info, 1, "");
  CHECK(!strcmp(info.type, "I2PInterface") && !info.reachable_on[0]);
  config_file(path,
              "[interfaces]\n[[W]]\ntype=WeaveInterface\nport=/dev/null\ndiscoverable=Yes\ndiscovery_modulation=fast\n");
  CHECK(!read_config(path, &c)); /* the reference reads it as an integer */
  mgmt.identity = NULL;
  CHECK(!unlink(path) && !rmdir(dir));
}
static void auto_options_test(void) {
  char dir[] = "/tmp/rnc-config-auto-XXXXXX", path[256];
  config c;
  CHECK(mkdtemp(dir) && snprintf(path, sizeof(path), "%s/config", dir) > 0);
  config_file(path,
              "[interfaces]\n[[A]]\ntype=AutoInterface\ndevices=eth0, wlan0\nignored_devices=docker0\n"
              "discovery_scope=Site\nmulticast_address_type=permanent\n[[B]]\ntype=AutoInterface\n");
  CHECK(read_config(path, &c));
  CHECK(!strcmp(c.interfaces[0].host.auto_devices, "eth0, wlan0") &&
        !strcmp(c.interfaces[0].host.auto_ignored_devices, "docker0") &&
        c.interfaces[0].host.auto_scope == RNC_AUTO_SCOPE_SITE && c.interfaces[0].host.auto_permanent == 1);
  CHECK(c.interfaces[1].host.auto_devices == NULL && c.interfaces[1].host.auto_scope == 0 &&
        c.interfaces[1].host.auto_permanent == 0); /* link scope, temporary: the reference defaults */
  /* TCP servers and UDP interfaces may name a device instead of an address */
  config_file(path,
              "[interfaces]\n[[S]]\ntype=TCPServerInterface\ndevice=lo\nlisten_port=4242\n"
              "[[U]]\ntype=UDPInterface\ndevice=lo\nlisten_port=4243\n"
              "[[T]]\ntype=TCPClientInterface\ntarget_host=127.0.0.1\ntarget_port=4244\ni2p_tunneled=Yes\n");
  CHECK(read_config(path, &c) && !strcmp(c.interfaces[0].host.device, "lo") &&
        !strcmp(c.interfaces[1].host.device, "lo") && c.interfaces[1].host.port == 4243 &&
        c.interfaces[2].host.i2p_tunneled == 1);
  config_file(path, "[interfaces]\n[[A]]\ntype=AutoInterface\ndiscovery_scope=nowhere\n");
  CHECK(!read_config(path, &c)); /* the reference never sets a scope here and fails; refuse it */
  config_file(path, "[interfaces]\n[[A]]\ntype=AutoInterface\nmulticast_address_type=odd\n");
  CHECK(read_config(path, &c) && c.interfaces[0].host.auto_permanent == 0); /* unknown: temporary, as the reference */
  CHECK(!unlink(path) && !rmdir(dir));
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
static int has(const uint8_t *buf, size_t size, const char *text, size_t n) {
  size_t i;
  for (i = 0; i + n <= size; i++)
    if (!memcmp(buf + i, text, n))
      return 1;
  return 0;
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
  /* rate_table: empty without entries, then one dict with the reference's five keys */
  query("rate_table", node, host, &id, &cfg, out, &size);
  CHECK(size == 1 && out[0] == 0x90);
  {
    rnc_interface_policy policy = {0};
    rnc_identity src;
    rnc_packet a;
    uint8_t key2[64] = {2};
    rnc_node *n2;
    rnc_host *h2;
    CHECK(rnc_identity_from_private(&src, key2) == RNC_OK);
    n2 = rnc_node_new(&id, 1, rng, NULL);
    CHECK(n2 && rnc_node_add_interface(n2, 1, 1000000) == RNC_OK &&
          rnc_node_add_interface(n2, 2, 1000000) == RNC_OK); /* the table fills when there is somewhere to pass an announce on */
    policy.announce_rate_target = 60;
    policy.announce_rate_grace = 3;
    policy.announce_rate_penalty = 120;
    CHECK(rnc_node_interface_policy(n2, 1, &policy) == RNC_OK);
    CHECK(rnc_announce_create(&src, "rate.rpc", NULL, 0, 1000, rng, NULL, &a) == RNC_OK);
    CHECK(rnc_node_input(n2, 1, &a, 1000, 0) == RNC_OK);
    h2 = rnc_host_new(n2);
    CHECK(h2);
    query("rate_table", n2, h2, &id, &cfg, out, &size);
    CHECK(size > 40 && out[0] == 0x91 && out[1] == 0x85); /* one entry, a map of five */
    CHECK(has(out, size, "hash", 4) && has(out, size, "last", 4) &&
          has(out, size, "rate_violations", 15) && has(out, size, "blocked_until", 13) &&
          has(out, size, "timestamps", 10));
    /* RNS 1.6.1's rnpath reads path state, last use, destination value and link cost from every entry */
    query("path_table", n2, h2, &id, &cfg, out, &size);
    CHECK(out[0] == 0x91 && out[1] == 0x8a); /* one entry, a map of ten */
    CHECK(has(out, size, "state", 5) && has(out, size, "used", 4) && has(out, size, "value", 5) &&
          has(out, size, "lr_cost", 7));
    rnc_host_free(h2);
    rnc_node_free(n2);
  }
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
  interface_stats(&w, host, node, &status);
  CHECK(rnc_rpc_writer_finish(&w, &size) == RNC_OK && size > 50);
  CHECK(has(out, size, "gravity", 7) && has(out, size, "announces_to_internal", 21));
  /* RNS 1.6's rnstatus reads the count of filtered announces of every interface */
  CHECK(has(out, size, "afrxc", 5));
  rnc_host_free(host);
  rnc_node_free(node);
  checkpoint_retry_test();
  stable_interface_test();
  internal_mode_config_test();
  drop_rpc_test();
  mgmt_rates_test();
  gravity_config_test();
  discovery_types_test();
  auto_options_test();
  puts("node RPC response tests passed");
  return 0;
}
