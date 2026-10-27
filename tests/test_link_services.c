#define main rnc_baseline_test_main
#include "test_link.c"
#undef main

static void raw_packet_test(void) {
  pair p;
  rnc_packet packet;
  rnc_link_event event;
  uint8_t data[RNC_LINK_MDU];
  rnc_link snapshot;
  unsigned entropy;
  uint8_t expected[32], hash[32];
  memset(data, 0x71, sizeof(data));
  init(&p);
  establish(&p);
  CHECK(rnc_link_send_packet_hashed(p.client, 9, data, sizeof(data), 110,
                                    hash) == RNC_OK);
  packet = outgoing(p.client);
  CHECK(packet.context == 9);
  CHECK(rnc_packet_hash(&packet, expected) == RNC_OK &&
        !memcmp(hash, expected, 32));
  CHECK(rnc_link_input(p.server, &packet, 111) == RNC_OK);
  CHECK(rnc_link_poll(p.server, &event) == RNC_OK &&
        event.type == RNC_LINK_PACKET);
  CHECK(event.context == 9 && event.size == sizeof(data) &&
        !memcmp(event.data, data, sizeof(data)));
  packet.data[20] ^= 1;
  snapshot = *p.server;
  CHECK(rnc_link_input(p.server, &packet, 112) == RNC_AUTH &&
        !memcmp(&snapshot, p.server, sizeof(snapshot)));
  CHECK(rnc_link_send_packet(p.client, 14, data, 1, 112) == RNC_INVALID);
  CHECK(rnc_link_send_packet(p.client, 1, data, 1, 112) == RNC_INVALID);
  CHECK(rnc_link_send_packet(p.client, 9, data, sizeof(data) + 1, 112) ==
        RNC_INVALID);
  while (p.client->count < RNC_LINK_EVENTS)
    (void)rnc_emit(p.client, RNC_LINK_ACTIVE);
  snapshot = *p.client;
  entropy = p.cr.value;
  CHECK(rnc_link_send_packet(p.client, 0, data, 1, 113) == RNC_AGAIN);
  CHECK(!memcmp(&snapshot, p.client, sizeof(snapshot)) &&
        entropy == p.cr.value);
  finish(&p);
}
static void resource_packet_test(void) {
  pair p;
  rnc_packet packet;
  rnc_link_event event;
  uint8_t data[464];
  uint64_t activity;
  memset(data, 0x32, sizeof(data));
  init(&p);
  establish(&p);
  activity = p.server->activity;
  CHECK(rnc_link_send_resource_packet(p.client, RNC_DATA, 1, data, sizeof(data),
                                      110) == RNC_OK);
  packet = outgoing(p.client);
  CHECK(packet.context == 1 && packet.data_size == sizeof(data));
  CHECK(rnc_link_input(p.server, &packet, 111) == RNC_OK);
  CHECK(rnc_link_poll(p.server, &event) == RNC_OK &&
        event.type == RNC_LINK_RESOURCE_PACKET);
  CHECK(event.packet.data_size == sizeof(data) &&
        !memcmp(event.packet.data, data, sizeof(data)));
  CHECK(p.server->activity == activity);
  CHECK(rnc_link_send_resource_packet(p.client, RNC_PROOF, 5, data, 64, 112) ==
        RNC_OK);
  packet = outgoing(p.client);
  CHECK(rnc_link_input(p.server, &packet, 113) == RNC_OK);
  CHECK(rnc_link_poll(p.server, &event) == RNC_OK &&
        event.type == RNC_LINK_RESOURCE_PACKET);
  CHECK(p.server->activity == activity);
  CHECK(rnc_link_send_resource_packet(p.client, RNC_DATA, 8, data, 32, 114) ==
        RNC_OK);
  packet = outgoing(p.client);
  CHECK(packet.context == 8 && packet.data_size == 32);
  CHECK(rnc_link_input(p.server, &packet, 114) == RNC_OK);
  CHECK(rnc_link_poll(p.server, &event) == RNC_OK &&
        event.type == RNC_LINK_RESOURCE_PACKET);
  CHECK(p.server->activity == activity);
  CHECK(rnc_link_send_resource_packet(p.client, RNC_DATA, 9, data, 10, 114) ==
        RNC_INVALID);
  finish(&p);
}
static void whole_token_test(void) {
  pair p;
  uint8_t data[7000], token[7080], decoded[7000];
  size_t n, m;
  unsigned i;
  init(&p);
  establish(&p);
  for (i = 0; i < sizeof(data); ++i)
    data[i] = (uint8_t)i;
  CHECK(rnc_link_encrypt(p.client, data, sizeof(data), token, sizeof(token),
                         &n) == RNC_OK);
  CHECK(rnc_link_decrypt(p.server, token, n, decoded, sizeof(decoded), &m) ==
        RNC_OK);
  CHECK(m == sizeof(data) && !memcmp(data, decoded, m));
  token[29] ^= 1;
  memset(decoded, 0xa5, sizeof(decoded));
  CHECK(rnc_link_decrypt(p.server, token, n, decoded, sizeof(decoded), &m) ==
            RNC_AUTH &&
        m == 0);
  for (i = 0; i < sizeof(decoded); ++i)
    CHECK(decoded[i] == 0xa5);
  token[29] ^= 1;
  CHECK(rnc_link_decrypt(p.server, token, n, decoded, sizeof(decoded) - 1,
                         &m) == RNC_NO_SPACE &&
        m == 0);
  CHECK(rnc_link_encrypt(p.client, data, sizeof(data), token, sizeof(data),
                         &n) == RNC_NO_SPACE &&
        n == 0);
  finish(&p);
}
static void channel_window_test(void) {
  pair p;
  rnc_packet packet, proof;
  unsigned i;
  size_t window;
  init(&p);
  establish(&p);
  CHECK(rnc_link_channel_window(p.client) == 2);
  CHECK(rnc_link_configure_channel(p.client, 2, 48, 1) == RNC_OK);
  CHECK(rnc_link_configure_channel(p.client, 0, 48, 1) == RNC_INVALID);
  CHECK(rnc_link_configure_channel(p.client, 49, 49, 1) == RNC_INVALID);
  for (i = 0; i < 20; ++i) {
    CHECK(rnc_link_send(p.client, 1, "x", 1, 110 + i * 3) == RNC_OK);
    CHECK(rnc_link_channel_pending(p.client) == 1);
    packet = outgoing(p.client);
    CHECK(rnc_link_input(p.server, &packet, 111 + i * 3) == RNC_OK);
    proof = outgoing(p.server);
    (void)count(p.server, RNC_LINK_MESSAGE);
    CHECK(rnc_link_input(p.client, &proof, 112 + i * 3) == RNC_OK);
    (void)count(p.client, RNC_LINK_DELIVERED);
  }
  window = rnc_link_channel_window(p.client);
  CHECK(window > 5 && window <= 48);
  for (i = 0; i < window; ++i)
    CHECK(rnc_link_send(p.client, 1, "x", 1, 180) == RNC_OK);
  CHECK(rnc_link_send(p.client, 1, "x", 1, 180) == RNC_AGAIN);
  CHECK(rnc_link_configure_channel(p.client, 2, 2, 0) == RNC_STATE);
  (void)count(p.client, RNC_LINK_SEND);
  CHECK(rnc_link_tick(p.client, 1000) == RNC_OK);
  CHECK(rnc_link_channel_window(p.client) < window);
  finish(&p);
}
int main(void) {
  raw_packet_test();
  resource_packet_test();
  whole_token_test();
  channel_window_test();
  puts("link service tests passed");
  return 0;
}
