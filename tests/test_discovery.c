#include "discovery_records.h"
#include "discovery_vectors.h"
#include <reticulum_c/rnc_discovery.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                  \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static uint32_t seed = 9;
static rnc_result rng(void *ctx, uint8_t *p, size_t n) {
  size_t i;
  (void)ctx;
  for (i = 0; i < n; i++) {
    seed = seed * 1664525u + 1013904223u;
    p[i] = (uint8_t)(seed >> 24);
  }
  return RNC_OK;
}
static size_t unhex(const char *hex, uint8_t *out) {
  size_t i, n = strlen(hex) / 2;
  for (i = 0; i < n; i++) {
    unsigned v;
    CHECK(sscanf(hex + 2 * i, "%2x", &v) == 1);
    out[i] = (uint8_t)v;
  }
  return n;
}
static void fill_common(rnc_discovery_info *i, const char *type, const char *name) {
  size_t k;
  memset(i, 0, sizeof(*i));
  strcpy(i->type, type);
  strcpy(i->name, name);
  strcpy(i->impl_name, "RNS");
  strcpy(i->version, "1.5.5");
  for (k = 0; k < 16; k++)
    i->transport_id[k] = (uint8_t)k;
}
static void backbone_info(rnc_discovery_info *i) {
  fill_common(i, "BackboneInterface", "My Backbone");
  i->transport = 1;
  i->has_latitude = i->has_longitude = i->has_height = 1;
  i->latitude = 48.8584;
  i->longitude = 2.2945;
  i->height = 35.0;
  strcpy(i->reachable_on, "example.org");
  i->has_port = 1;
  i->port = 4242;
}
static void rnode_info(rnc_discovery_info *i) {
  size_t k;
  fill_common(i, "RNodeInterface", "Hill RNode");
  i->has_operator = 1;
  for (k = 0; k < 16; k++)
    i->operator_address[k] = (uint8_t)(100 + k);
  i->has_frequency = i->has_bandwidth = 1;
  i->frequency = 868000000;
  i->bandwidth = 125000;
  i->spreading_factor = 8;
  i->coding_rate = 5;
  strcpy(i->ifac_netname, "mynet");
  strcpy(i->ifac_netkey, "secret");
}
static void kiss_info(rnc_discovery_info *i) {
  fill_common(i, "KISSInterface", "Packet TNC");
  i->transport = 1;
  i->has_latitude = i->has_longitude = i->has_height = 1;
  i->latitude = 51.5;
  i->longitude = -0.12;
  i->height = 11.0;
  i->has_frequency = i->has_bandwidth = i->has_modulation = 1;
  i->frequency = 433775000;
  i->bandwidth = 25000;
  strcpy(i->modulation, "AFSK1200");
}
/* the map as umsgpack writes it, byte for byte */
static void packing(void) {
  rnc_discovery_info i;
  uint8_t out[512], want[512];
  size_t n, m;
  backbone_info(&i);
  CHECK(rnc_discovery_pack(&i, out, sizeof(out), &n) == RNC_OK);
  m = unhex(vec_backbone_packed, want);
  CHECK(n == m && !memcmp(out, want, n));
  rnode_info(&i);
  CHECK(rnc_discovery_pack(&i, out, sizeof(out), &n) == RNC_OK);
  m = unhex(vec_rnode_packed, want);
  CHECK(n == m && !memcmp(out, want, n));
  kiss_info(&i);
  CHECK(rnc_discovery_pack(&i, out, sizeof(out), &n) == RNC_OK);
  m = unhex(vec_kiss_packed, want);
  CHECK(n == m && !memcmp(out, want, n));
  CHECK(rnc_discovery_pack(&i, out, 10, &n) == RNC_NO_SPACE && n == 0);
}
/* app data the reference produced parses back to the same description */
static size_t app_data(const char *packed_hex, const char *stamp_hex, uint8_t *out) {
  size_t n = 1;
  out[0] = 0;
  n += unhex(packed_hex, out + n);
  n += unhex(stamp_hex, out + n);
  return n;
}
static void parsing(void) {
  uint8_t data[512], stamp[32];
  size_t n;
  unsigned value = 0;
  rnc_discovery_info want, got;
  n = app_data(vec_backbone_packed, vec_backbone_stamp, data);
  backbone_info(&want);
  CHECK(rnc_discovery_parse(data, n, 10, NULL, &got, stamp, &value) == RNC_OK);
  CHECK(value >= 10 && stamp[31] == 0x7b);
  CHECK(!strcmp(got.type, want.type) && got.transport == 1 &&
        !memcmp(got.transport_id, want.transport_id, 16) &&
        !strcmp(got.impl_name, "RNS") && !strcmp(got.version, "1.5.5") &&
        !strcmp(got.name, "My Backbone") && got.has_latitude &&
        got.latitude == 48.8584 && got.longitude == 2.2945 &&
        got.height == 35.0 && !strcmp(got.reachable_on, "example.org") &&
        got.has_port && got.port == 4242 && !got.has_operator);
  /* a higher requirement than the stamp meets */
  CHECK(rnc_discovery_parse(data, n, 30, NULL, &got, stamp, &value) == RNC_AUTH);
  n = app_data(vec_rnode_packed, vec_rnode_stamp, data);
  CHECK(rnc_discovery_parse(data, n, 10, NULL, &got, stamp, &value) == RNC_OK);
  CHECK(!strcmp(got.type, "RNodeInterface") && !got.transport &&
        !got.has_latitude && got.has_operator && got.operator_address[0] == 100 &&
        got.frequency == 868000000 && got.bandwidth == 125000 &&
        got.spreading_factor == 8 && got.coding_rate == 5 &&
        !strcmp(got.ifac_netname, "mynet") && !strcmp(got.ifac_netkey, "secret"));
  n = app_data(vec_kiss_packed, vec_kiss_stamp, data);
  CHECK(rnc_discovery_parse(data, n, 10, NULL, &got, stamp, &value) == RNC_OK);
  CHECK(!strcmp(got.type, "KISSInterface") && got.longitude == -0.12 &&
        got.frequency == 433775000 && !strcmp(got.modulation, "AFSK1200"));
  /* the stamp must belong to the map */
  data[n - 1] ^= 0xff;
  CHECK(rnc_discovery_parse(data, n, 10, NULL, &got, stamp, &value) ==
        RNC_AUTH);
  data[n - 1] ^= 0xff;
  data[20] ^= 0x01; /* altered map bytes */
  CHECK(rnc_discovery_parse(data, n, 10, NULL, &got, stamp, &value) != RNC_OK);
}
/* the reference's encrypted form, and our own in both forms */
static void encryption(void) {
  uint8_t key[64], data[RNC_DISCOVERY_PAYLOAD_MAX], stamp[32], token[512];
  rnc_identity network, public_only;
  rnc_discovery_info info, got;
  size_t i, n, tn;
  unsigned value;
  for (i = 0; i < 64; i++)
    key[i] = (uint8_t)i;
  CHECK(rnc_identity_from_private(&network, key) == RNC_OK);
  tn = unhex(vec_enc_token, token);
  data[0] = RNC_DISCOVERY_FLAG_ENCRYPTED;
  memcpy(data + 1, token, tn);
  CHECK(rnc_discovery_parse(data, 1 + tn, 10, &network, &got, stamp, &value) ==
        RNC_OK);
  CHECK(!strcmp(got.name, "My Backbone"));
  /* no key, or only a public identity, cannot read it */
  CHECK(rnc_discovery_parse(data, 1 + tn, 10, NULL, &got, stamp, &value) ==
        RNC_STATE);
  CHECK(rnc_identity_from_public(&public_only, network.public_key) == RNC_OK);
  CHECK(rnc_discovery_parse(data, 1 + tn, 10, &public_only, &got, stamp,
                            &value) == RNC_STATE);
  /* announce data we build: plain and encrypted, both readable */
  backbone_info(&info);
  CHECK(rnc_discovery_announce_data(&info, 10, NULL, rng, NULL, data,
                                    sizeof(data), &n) == RNC_OK);
  CHECK(data[0] == 0 && rnc_discovery_parse(data, n, 10, NULL, &got, stamp,
                                            &value) == RNC_OK);
  CHECK(value >= 10 && !strcmp(got.reachable_on, "example.org"));
  CHECK(rnc_discovery_announce_data(&info, 10, &network, rng, NULL, data,
                                    sizeof(data), &n) == RNC_OK);
  CHECK(data[0] == RNC_DISCOVERY_FLAG_ENCRYPTED);
  CHECK(rnc_discovery_parse(data, n, 10, &network, &got, stamp, &value) ==
        RNC_OK);
  CHECK(rnc_discovery_announce_data(&info, 10, NULL, rng, NULL, data, 20,
                                    &n) == RNC_NO_SPACE && n == 0);
}
static void helpers(void) {
  char out[64];
  uint8_t hash[32];
  rnc_discovery_info i;
  CHECK(rnc_discovery_is_ip_address("192.168.1.10"));
  CHECK(rnc_discovery_is_ip_address("::1"));
  CHECK(rnc_discovery_is_ip_address("2001:db8::ff00:42:8329"));
  CHECK(rnc_discovery_is_ip_address("::ffff:10.0.0.1"));
  CHECK(!rnc_discovery_is_ip_address("256.1.1.1"));
  CHECK(!rnc_discovery_is_ip_address("1.2.3"));
  CHECK(!rnc_discovery_is_ip_address("example.org"));
  CHECK(!rnc_discovery_is_ip_address("2001:::1"));
  CHECK(!rnc_discovery_is_ip_address(""));
  CHECK(rnc_discovery_is_hostname("example.org"));
  CHECK(rnc_discovery_is_hostname("a-b.example.org."));
  CHECK(rnc_discovery_is_hostname("localhost"));
  CHECK(!rnc_discovery_is_hostname("-bad.example.org"));
  CHECK(!rnc_discovery_is_hostname("bad-.example.org"));
  CHECK(!rnc_discovery_is_hostname("1.2.3.4")); /* an address, not a name */
  CHECK(!rnc_discovery_is_hostname("under_score.org"));
  CHECK(!rnc_discovery_is_hostname(""));
  rnc_discovery_sanitize_name("  --My   Node (EU)--  ", out, sizeof(out));
  CHECK(!strcmp(out, "My Node (EU)"));
  rnc_discovery_sanitize_name("caf\xc3\xa9 Relay", out, sizeof(out));
  CHECK(!strcmp(out, "caf Relay"));
  rnc_discovery_sanitize_name("!!!", out, sizeof(out));
  CHECK(!out[0]);
  backbone_info(&i);
  CHECK(rnc_discovery_hash(&i, hash) == RNC_OK);
  {
    /* sha256 of "000102030405060708090a0b0c0d0e0fMy Backbone" */
    uint8_t expect[32];
    CHECK(rnc_hash("000102030405060708090a0b0c0d0e0fMy Backbone", 43,
                   expect) == RNC_OK && !memcmp(hash, expect, 32));
    CHECK(rnc_discovery_endpoint_hash(&i, hash) == RNC_OK);
    CHECK(rnc_hash("example.org:4242", 16, expect) == RNC_OK &&
          !memcmp(hash, expect, 32));
  }
}
static void record_for(const char *which, rnc_discovery_record *r) {
  size_t k;
  memset(r, 0, sizeof(*r));
  if (!strcmp(which, "backbone")) {
    backbone_info(&r->info);
    strcpy(r->info.ifac_netname, "mynet");
    strcpy(r->info.ifac_netkey, "secret");
  } else if (!strcmp(which, "rnode")) {
    rnode_info(&r->info);
    r->info.ifac_netname[0] = r->info.ifac_netkey[0] = 0;
  } else
    kiss_info(&r->info);
  for (k = 0; k < 32; k++)
    r->stamp[k] = (uint8_t)k;
  for (k = 0; k < 16; k++)
    r->network_id[k] = (uint8_t)(200 + k);
  r->value = 12;
  r->hops = 2;
  r->received = 1700000000.5;
  r->discovered = 1699990000.25;
  r->last_heard = 1700000000.5;
  r->heard_count = 3;
}
static void record_pack(void) {
  static const char *names[] = {"backbone", "rnode", "kiss"};
  const char *vectors[3] = {rec_backbone, rec_rnode, rec_kiss};
  unsigned k;
  for (k = 0; k < 3; k++) {
    rnc_discovery_record r;
    uint8_t out[RNC_DISCOVERY_RECORD_MAX], want[RNC_DISCOVERY_RECORD_MAX];
    size_t n, m;
    record_for(names[k], &r);
    CHECK(rnc_discovery_config_entry(&r.info, 1, r.config_entry,
                                     sizeof(r.config_entry)) == RNC_OK);
    CHECK(rnc_discovery_record_pack(&r, out, sizeof(out), &n) == RNC_OK);
    m = unhex(vectors[k], want);
    if (n != m || memcmp(out, want, n)) {
      size_t i;
      for (i = 0; i < n && i < m && out[i] == want[i]; i++) {
      }
      fprintf(stderr, "%s differs at byte %zu (ours %zu bytes, reference %zu)\n",
              names[k], i, n, m);
      CHECK(0);
    }
    CHECK(rnc_discovery_record_pack(&r, out, 40, &n) == RNC_NO_SPACE && n == 0);
  }
}
static void record_unpack(void) {
  const char *vectors[3] = {rec_backbone, rec_rnode, rec_kiss};
  unsigned k;
  for (k = 0; k < 3; k++) {
    rnc_discovery_record r, again;
    uint8_t data[RNC_DISCOVERY_RECORD_MAX], out[RNC_DISCOVERY_RECORD_MAX];
    size_t n = unhex(vectors[k], data), m;
    CHECK(rnc_discovery_record_unpack(data, n, &r) == RNC_OK);
    CHECK(r.value == 12 && r.hops == 2 && r.heard_count == 3 &&
          r.received == 1700000000.5 && r.discovered == 1699990000.25 &&
          r.last_heard == 1700000000.5 && r.network_id[0] == 200 &&
          r.stamp[31] == 31 && r.config_entry[0] == '[');
    /* re-packing a record read from the reference reproduces it exactly */
    CHECK(rnc_discovery_record_pack(&r, out, sizeof(out), &m) == RNC_OK);
    if (m != n || memcmp(out, data, n)) {
      size_t d;
      for (d = 0; d < n && d < m && out[d] == data[d]; d++) {
      }
      fprintf(stderr, "vector %u: repack differs at byte %zu (%zu vs %zu bytes)\n", k, d, m, n);
      CHECK(0);
    }
    CHECK(rnc_discovery_record_unpack(out, m, &again) == RNC_OK);
    data[0] = 0x92; /* not a map */
    CHECK(rnc_discovery_record_unpack(data, n, &r) == RNC_PROTOCOL);
  }
  {
    rnc_discovery_record r;
    uint8_t data[RNC_DISCOVERY_RECORD_MAX];
    size_t n = unhex(rec_rnode, data);
    CHECK(rnc_discovery_record_unpack(data, n, &r) == RNC_OK);
    CHECK(!strcmp(r.info.type, "RNodeInterface") && r.info.has_operator &&
          r.info.operator_address[0] == 100 && r.info.frequency == 868000000 &&
          r.info.spreading_factor == 8 && !r.info.has_latitude);
  }
}
static void record_status(void) {
  CHECK(rnc_discovery_status(0) == RNC_DISCOVERY_STATUS_AVAILABLE);
  CHECK(rnc_discovery_status(24.0 * 3600) == RNC_DISCOVERY_STATUS_AVAILABLE);
  CHECK(rnc_discovery_status(24.0 * 3600 + 1) == RNC_DISCOVERY_STATUS_UNKNOWN);
  CHECK(rnc_discovery_status(3.0 * 86400) == RNC_DISCOVERY_STATUS_UNKNOWN);
  CHECK(rnc_discovery_status(3.0 * 86400 + 1) == RNC_DISCOVERY_STATUS_STALE);
  CHECK(rnc_discovery_status(7.0 * 86400) == RNC_DISCOVERY_STATUS_STALE);
  CHECK(rnc_discovery_status(7.0 * 86400 + 1) == -1);
}
static void config_entries(void) {
  rnc_discovery_info i;
  char out[768];
  backbone_info(&i);
  CHECK(rnc_discovery_config_entry(&i, 1, out, sizeof(out)) == RNC_OK);
  CHECK(!strncmp(out, "[[My Backbone]]\n  type = BackboneInterface\n  enabled = yes\n  remote = example.org\n  target_port = 4242\n  transport_identity = 000102", 118));
  CHECK(rnc_discovery_config_entry(&i, 0, out, sizeof(out)) == RNC_OK);
  CHECK(strstr(out, "type = TCPClientInterface") &&
        strstr(out, "target_host = example.org"));
  CHECK(rnc_discovery_config_entry(&i, 1, out, 20) == RNC_NO_SPACE);
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  if (!strcmp(argv[1], "packing"))
    packing();
  else if (!strcmp(argv[1], "parsing"))
    parsing();
  else if (!strcmp(argv[1], "encryption"))
    encryption();
  else if (!strcmp(argv[1], "helpers"))
    helpers();
  else if (!strcmp(argv[1], "record_pack"))
    record_pack();
  else if (!strcmp(argv[1], "record_unpack"))
    record_unpack();
  else if (!strcmp(argv[1], "record_status"))
    record_status();
  else if (!strcmp(argv[1], "config_entries"))
    config_entries();
  else
    CHECK(0);
  puts("discovery test passed");
  return 0;
}
