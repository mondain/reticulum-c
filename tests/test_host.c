#define _XOPEN_SOURCE 700
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <reticulum_c/rnc_host.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d %s errno=%d\n", __FILE__, __LINE__, #x, errno);   \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static rnc_result random_bytes(void *v, uint8_t *out, size_t n) {
  unsigned *s = v;
  size_t i;
  for (i = 0; i < n; ++i)
    out[i] = (uint8_t)(*s)++;
  return RNC_OK;
}
static void codecs(void) {
  uint8_t data[] = {0xc0, 0xdb, 0x7e, 0x7d, 1, 2}, frame[RNC_HOST_FRAME_MAX],
          out[100], command = 0;
  size_t n, m, i;
  unsigned mode;
  rnc_host_framer f = {0};
  for (mode = RNC_HOST_HDLC; mode <= RNC_HOST_KISS_FRAMING; ++mode) {
    memset(&f, 0, sizeof(f));
    CHECK(rnc_host_frame_encode((rnc_host_framing)mode, 0x05, data,
                                sizeof(data), frame, sizeof(frame),
                                &n) == RNC_OK);
    for (i = 0; i < n; ++i) {
      rnc_result r = rnc_host_frame_feed(&f, (rnc_host_framing)mode, frame[i],
                                         &command, out, sizeof(out), &m);
      CHECK(r == (i == n - 1 ? RNC_OK : RNC_AGAIN));
    }
    CHECK(m == sizeof(data) && !memcmp(data, out, m) &&
          command == (mode == RNC_HOST_HDLC ? 0 : 5));
    memset(out, 0xa5, sizeof(out));
    CHECK(rnc_host_frame_encode((rnc_host_framing)mode, 0, data, sizeof(data),
                                out, 1, &n) == RNC_NO_SPACE &&
          n == 0 && out[0] == 0xa5);
  }
  CHECK(rnc_host_auto_group("reticulum", out) == RNC_OK && out[0] == 0xff &&
        out[1] == 0x12 && out[2] == 0 && out[3] == 0);
  CHECK(rnc_host_auto_token("reticulum", "fe80::1", out) == RNC_OK);
  {
    uint8_t expected[32];
    CHECK(rnc_hash("reticulumfe80::1", 16, expected) == RNC_OK &&
          !memcmp(out, expected, 32));
  }
  CHECK(rnc_host_auto_token("reticulum", "garbage", out) == RNC_INVALID);
  puts("host codec tests passed");
}
static void network(void) {
  unsigned ar = 0, br = 90;
  uint8_t key[64] = {0}, dest[16];
  rnc_identity ai, bi;
  rnc_node *a, *b;
  rnc_host *ah, *bh;
  rnc_host_config cfg = {0};
  rnc_host_status st;
  rnc_route route;
  unsigned i;
  int found = 0;
  CHECK(rnc_identity_from_private(&ai, key) == RNC_OK);
  key[0] = 3;
  CHECK(rnc_identity_from_private(&bi, key) == RNC_OK);
  a = rnc_node_new(&ai, 0, random_bytes, &ar);
  b = rnc_node_new(&bi, 0, random_bytes, &br);
  CHECK(a && b);
  ah = rnc_host_new(a);
  bh = rnc_host_new(b);
  CHECK(ah && bh);
  cfg.kind = RNC_HOST_TCP_LISTEN;
  cfg.address = "127.0.0.1";
  CHECK(rnc_host_add(ah, 1, &cfg) == RNC_OK);
  CHECK(rnc_host_get_status(ah, 1, &st) == RNC_OK && st.bound_port);
  cfg.kind = RNC_HOST_TCP_CONNECT;
  cfg.port = st.bound_port;
  CHECK(rnc_host_add(bh, 2, &cfg) == RNC_OK);
  CHECK(rnc_node_add_destination(b, &bi, "reticulum_c.host.test", NULL, 0,
                                 dest) == RNC_OK);
  for (i = 0; i < 1000 && !found; ++i) {
    rnc_host_event event;
    CHECK(rnc_host_step(ah, 0, 1700000000, 100 + i) == RNC_OK);
    CHECK(rnc_host_step(bh, 1, 1700000000, 100 + i) == RNC_OK);
    while (rnc_host_poll(ah, &event) == RNC_OK) {
    }
    while (rnc_host_poll(bh, &event) == RNC_OK) {
    }
    if (i == 5)
      CHECK(rnc_node_announce(b, dest, 1700000000, 105) == RNC_OK);
    found = rnc_node_lookup(a, dest, 100 + i, &route) == RNC_OK;
  }
  CHECK(found && route.interface_id >= 0x80000000u);
  rnc_host_free(bh);
  for (i = 0; i < 20; ++i)
    CHECK(rnc_host_step(ah, 1, 1700000000, 1200 + i) == RNC_OK);
  CHECK(rnc_node_lookup(a, dest, 1300, &route) == RNC_AGAIN);
  rnc_host_free(ah);
  rnc_node_free(a);
  rnc_node_free(b);
  puts("host TCP tests passed");
}
static void udp_test(void) {
  struct sockaddr_in address;
  socklen_t address_size = sizeof(address);
  int receiver;
  unsigned rng = 0, i;
  uint8_t private_key[64] = {0}, destination[16], data[RNC_MAX_FRAME];
  rnc_identity id;
  rnc_node *node;
  rnc_host *host;
  rnc_host_config cfg = {0};
  rnc_host_status status;
  int found = 0;
  receiver = socket(AF_INET, SOCK_DGRAM, 0);
  CHECK(receiver >= 0);
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(!bind(receiver, (struct sockaddr *)&address, sizeof(address)) &&
        !getsockname(receiver, (struct sockaddr *)&address, &address_size));
  close(receiver);
  CHECK(rnc_identity_from_private(&id, private_key) == RNC_OK);
  node = rnc_node_new(&id, 0, random_bytes, &rng);
  CHECK(node);
  host = rnc_host_new(node);
  CHECK(host);
  cfg.kind = RNC_HOST_UDP;
  cfg.address = "127.0.0.1";
  cfg.target = "127.0.0.1";
  cfg.target_port = ntohs(address.sin_port);
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
  CHECK(rnc_node_add_destination(node, &id, "reticulum_c.host.udp", NULL, 0,
                                 destination) == RNC_OK);
  CHECK(rnc_node_announce(node, destination, 1700000000, 100) == RNC_OK);
  for (i = 0; i < 30; ++i)
    CHECK(rnc_host_step(host, 1, 1700000000, 100 + i) == RNC_OK);
  CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK && status.online);
  receiver = socket(AF_INET, SOCK_DGRAM, 0);
  CHECK(receiver >= 0 &&
        !bind(receiver, (struct sockaddr *)&address, sizeof(address)));
  CHECK(rnc_node_announce(node, destination, 1700000001, 300) == RNC_OK);
  for (i = 0; i < 100 && !found; ++i) {
    struct pollfd p = {receiver, POLLIN, 0};
    CHECK(rnc_host_step(host, 1, 1700000001, 300 + i) == RNC_OK);
    CHECK(poll(&p, 1, 1) >= 0);
    if (p.revents & POLLIN) {
      ssize_t size = recv(receiver, data, sizeof(data), 0);
      rnc_packet packet;
      rnc_announce announce;
      CHECK(size > 0 &&
            rnc_packet_decode(data, (size_t)size, &packet) == RNC_OK &&
            rnc_announce_verify(&packet, &announce) == RNC_OK &&
            !memcmp(packet.destination, destination, 16));
      found = 1;
    }
  }
  CHECK(found && rnc_host_get_status(host, 1, &status) == RNC_OK &&
        status.online);
  rnc_host_free(host);
  rnc_node_free(node);
  close(receiver);
  puts("host UDP recovery tests passed");
}
static void serial_test(void) {
  int master;
  char *device;
  unsigned rng = 0, i;
  uint8_t key[64] = {0}, dest[16], raw[RNC_MTU], frame[RNC_HOST_FRAME_MAX];
  size_t n, m;
  rnc_identity id;
  rnc_packet announce;
  rnc_node *node;
  rnc_host *host;
  rnc_host_config cfg = {0};
  rnc_route route;
  master = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
  CHECK(master >= 0);
  CHECK(!grantpt(master) && !unlockpt(master));
  device = ptsname(master);
  CHECK(device);
  CHECK(rnc_identity_from_private(&id, key) == RNC_OK);
  node = rnc_node_new(&id, 0, random_bytes, &rng);
  CHECK(node);
  host = rnc_host_new(node);
  CHECK(host);
  cfg.kind = RNC_HOST_SERIAL;
  cfg.address = device;
  cfg.serial_baud = 115200;
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
  CHECK(rnc_announce_create(&id, "reticulum_c.host.serial", NULL, 0, 1700000000,
                            random_bytes, &rng, &announce) == RNC_OK);
  memcpy(dest, announce.destination, 16);
  CHECK(rnc_packet_encode(&announce, raw, sizeof(raw), &n) == RNC_OK);
  CHECK(rnc_host_frame_encode(RNC_HOST_HDLC, 0, raw, n, frame, sizeof(frame),
                              &m) == RNC_OK);
  { /* An unroutable transit packet cannot block a following announce. */
    rnc_packet unknown = {0};
    uint8_t raw_unknown[RNC_MAX_MTU], framed_unknown[RNC_HOST_FRAME_MAX];
    size_t un, uf;
    unknown.flags = 0x50;
    unknown.data_size = 1;
    unknown.data[0] = 1;
    memset(unknown.destination, 0x55, 16);
    memcpy(unknown.transport_id, id.hash, 16);
    CHECK(rnc_packet_encode(&unknown, raw_unknown, sizeof(raw_unknown), &un) ==
          RNC_OK);
    CHECK(rnc_host_frame_encode(RNC_HOST_HDLC, 0, raw_unknown, un,
                                framed_unknown, sizeof(framed_unknown),
                                &uf) == RNC_OK);
    CHECK(write(master, framed_unknown, uf) == (ssize_t)uf);
  }
  CHECK(write(master, frame, m) == (ssize_t)m);
  for (i = 0; i < 20; ++i) {
    rnc_host_event event;
    CHECK(rnc_host_step(host, 1, 1700000000, 100 + i) == RNC_OK);
    while (rnc_host_poll(host, &event) == RNC_OK) {
    }
  }
  CHECK(rnc_node_lookup(node, dest, 120, &route) == RNC_OK &&
        route.interface_id == 1);
  rnc_host_free(host);
  rnc_node_free(node);
  close(master);
  puts("host PTY tests passed");
}
static void serial_pressure_test(void) {
  int master;
  char *device;
  unsigned rng = 0, i, expected = 0;
  uint8_t key[64] = {0}, raw[RNC_MAX_MTU], framed[RNC_HOST_FRAME_MAX], last[16];
  rnc_identity id;
  rnc_node *node;
  rnc_host *host;
  rnc_host_config cfg = {0};
  rnc_host_status status;
  rnc_route route;
  master = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
  CHECK(master >= 0);
  CHECK(!grantpt(master) && !unlockpt(master));
  device = ptsname(master);
  CHECK(device);
  CHECK(rnc_identity_from_private(&id, key) == RNC_OK);
  node = rnc_node_new(&id, 0, random_bytes, &rng);
  CHECK(node);
  host = rnc_host_new(node);
  CHECK(host);
  cfg.kind = RNC_HOST_SERIAL;
  cfg.ingress.disabled = 1; /* exercise queue backpressure, not burst holds */
  cfg.address = device;
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
  for (i = 0; i < 125; ++i) {
    rnc_packet announce;
    char name[64];
    size_t n, m;
    CHECK(snprintf(name, sizeof(name), "reticulum_c.pressure.%u", i) > 0);
    CHECK(rnc_announce_create(&id, name, NULL, 0, 1700000000, random_bytes,
                              &rng, &announce) == RNC_OK);
    memcpy(last, announce.destination, 16);
    CHECK(rnc_packet_encode(&announce, raw, sizeof(raw), &n) == RNC_OK);
    CHECK(rnc_host_frame_encode(RNC_HOST_HDLC, 0, raw, n, framed,
                                sizeof(framed), &m) == RNC_OK);
    CHECK(write(master, framed, m) == (ssize_t)m);
    CHECK(rnc_host_step(host, 1, 1700000000, 100 + i) == RNC_OK);
    CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK);
    expected = i + 1;
    if (status.rx_packets < expected)
      break;
  }
  CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK && status.online &&
        status.rx_packets < expected);
  for (i = 0; i < 10; ++i) {
    rnc_host_event event;
    while (rnc_host_poll(host, &event) == RNC_OK) {
    }
    CHECK(rnc_host_step(host, 1, 1700000000, 300 + i) == RNC_OK);
    CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK && status.online);
  }
  CHECK(status.rx_packets == expected &&
        rnc_node_lookup(node, last, 320, &route) == RNC_OK);
  rnc_host_free(host);
  rnc_node_free(node);
  close(master);
  puts("host PTY backpressure tests passed");
}
static void radio_test(void) {
  int master;
  char *device;
  unsigned rng = 0, i, commands = 0;
  uint8_t key[64] = {0}, bytes[256], decoded[RNC_IFAC_FRAME_MAX], command;
  size_t size;
  rnc_host_framer parser = {0};
  rnc_identity id;
  rnc_node *node;
  rnc_host *host;
  rnc_host_config cfg = {0};
  const uint8_t expected_commands[] = {1, 2, 3, 4, 5, 6};
  master = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
  CHECK(master >= 0);
  CHECK(!grantpt(master) && !unlockpt(master));
  device = ptsname(master);
  CHECK(device);
  CHECK(rnc_identity_from_private(&id, key) == RNC_OK);
  node = rnc_node_new(&id, 0, random_bytes, &rng);
  CHECK(node);
  host = rnc_host_new(node);
  CHECK(host);
  cfg.kind = RNC_HOST_RNODE;
  cfg.address = device;
  cfg.serial_baud = 115200;
  cfg.frequency = 915000000;
  cfg.bandwidth = 125000;
  cfg.tx_power = 10;
  cfg.spreading_factor = 7;
  cfg.coding_rate = 5;
  cfg.flow_control = 1;
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
  for (i = 0; i < 1000 && commands < 6; ++i) {
    ssize_t n;
    size_t k;
    CHECK(rnc_host_step(host, 0, 1700000000, 100 + i) == RNC_OK);
    n = read(master, bytes, sizeof(bytes));
    if (n < 0) {
      CHECK(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR);
      continue;
    }
    for (k = 0; k < (size_t)n; ++k)
      if (rnc_host_frame_feed(&parser, RNC_HOST_KISS_FRAMING, bytes[k],
                              &command, decoded, sizeof(decoded),
                              &size) == RNC_OK) {
        CHECK(commands < 6 && command == expected_commands[commands]);
        if (command == 1) {
          uint8_t expected[] = {0x36, 0x89, 0xca, 0xc0};
          CHECK(size == 4 && !memcmp(decoded, expected, 4));
        } else if (command == 2) {
          uint8_t expected[] = {0, 1, 0xe8, 0x48};
          CHECK(size == 4 && !memcmp(decoded, expected, 4));
        } else
          CHECK(size == 1 && decoded[0] == (command == 3   ? 10
                                            : command == 4 ? 7
                                            : command == 5 ? 5
                                                           : 1));
        {
          uint8_t ack[RNC_HOST_FRAME_MAX];
          size_t ack_size;
          if (command == 1)
            decoded[3] =
                (uint8_t)(decoded[3] + 50u); /* normal PLL quantisation */
          CHECK(rnc_host_frame_encode(RNC_HOST_KISS_FRAMING, command, decoded,
                                      size, ack, sizeof(ack),
                                      &ack_size) == RNC_OK);
          CHECK(write(master, ack, ack_size) == (ssize_t)ack_size);
        }
        ++commands;
      }
  }
  CHECK(commands == 6);
  {
    uint8_t destination[16];
    rnc_host_status status;
    uint8_t ready[] = {0xc0, 0x0f, 1, 0xc0};
    CHECK(rnc_node_add_destination(node, &id, "reticulum_c.host.radio", NULL, 0,
                                   destination) == RNC_OK);
    CHECK(rnc_node_announce(node, destination, 1700000000, 1200) == RNC_OK);
    for (i = 0; i < 20; ++i) {
      CHECK(rnc_host_step(host, 1, 1700000000, 1200 + i) == RNC_OK);
      CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK);
      if (status.radio_ready && !status.queued_frames)
        break;
    }
    CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK &&
          status.radio_ready && status.queued_frames == 0 &&
          status.tx_packets == 1);
    {
      rnc_packet plain = {0};
      plain.flags = 8;
      plain.data_size = 1;
      plain.data[0] = 0x11;
      CHECK(rnc_node_send(node, &plain, 1700000001, 4000) == RNC_OK);
    }
    CHECK(rnc_host_step(host, 0, 1700000001, 4000) == RNC_OK);
    CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK &&
          status.queued_frames == 1);
    CHECK(write(master, ready, sizeof(ready)) == (ssize_t)sizeof(ready));
    for (i = 0; i < 10; ++i)
      CHECK(rnc_host_step(host, 1, 1700000001, 4001 + i) == RNC_OK);
    CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK &&
          status.queued_frames == 0 && status.tx_packets == 2);
  }
  rnc_host_free(host);
  rnc_node_free(node);
  close(master);
  puts("host RNode PTY tests passed");
}
static void keys(void) {
  char directory[] = "/tmp/rnc-host-key-XXXXXX", path[256], linkpath[256],
       fifopath[256];
  rnc_identity first, second, snapshot;
  struct stat st;
  unsigned rng = 2;
  CHECK(mkdtemp(directory));
  CHECK(snprintf(path, sizeof(path), "%s/key", directory) > 0);
  CHECK(snprintf(linkpath, sizeof(linkpath), "%s/link", directory) > 0);
  CHECK(snprintf(fifopath, sizeof(fifopath), "%s/fifo", directory) > 0);
  CHECK(rnc_host_identity_load(path, random_bytes, &rng, &first) == RNC_OK);
  CHECK(!stat(path, &st) && st.st_size == 64 && (st.st_mode & 0777) == 0600);
  CHECK(rnc_host_identity_load(path, random_bytes, &rng, &second) == RNC_OK);
  CHECK(!memcmp(first.private_key, second.private_key, 64));
  snapshot = second;
  CHECK(!chmod(path, 0644));
  CHECK(rnc_host_identity_load(path, random_bytes, &rng, &second) == RNC_AUTH &&
        !memcmp(&snapshot, &second, sizeof(second)));
  CHECK(!chmod(path, 0600) && !symlink(path, linkpath) &&
        !mkfifo(fifopath, 0600));
  CHECK(rnc_host_identity_load(linkpath, random_bytes, &rng, &second) !=
        RNC_OK);
  CHECK(rnc_host_identity_load(fifopath, random_bytes, &rng, &second) ==
        RNC_AUTH);
  CHECK(!unlink(linkpath) && !unlink(fifopath) && !unlink(path) &&
        !rmdir(directory));
  rnc_identity_clear(&first);
  rnc_identity_clear(&second);
  puts("host identity tests passed");
}
static void policy_test(void) {
  uint8_t private_key[64] = {0};
  unsigned rng = 0;
  rnc_identity id;
  rnc_node *node;
  rnc_host *host;
  rnc_host_config cfg = {0};
  rnc_host_status status;
  CHECK(rnc_identity_from_private(&id, private_key) == RNC_OK);
  node = rnc_node_new(&id, 1, random_bytes, &rng);
  CHECK(node);
  host = rnc_host_new(node);
  CHECK(host);
  cfg.kind = RNC_HOST_UDP;
  cfg.address = "127.0.0.1";
  cfg.mode = RNC_MODE_ROAMING;
  cfg.announce_cap_permille = 50;
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
  CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK);
  CHECK(status.mode == RNC_MODE_ROAMING && status.announce_cap_permille == 50);
  cfg.mode = (rnc_interface_mode)77;
  CHECK(rnc_host_add(host, 2, &cfg) == RNC_INVALID);
  cfg.mode = RNC_MODE_FULL;
  cfg.announce_cap_permille = 2000;
  CHECK(rnc_host_add(host, 3, &cfg) == RNC_INVALID);
  rnc_host_free(host);
  rnc_node_free(node);
  puts("host interface policy tests passed");
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  if (!strcmp(argv[1], "codecs"))
    codecs();
  else if (!strcmp(argv[1], "network"))
    network();
  else if (!strcmp(argv[1], "serial"))
    serial_test();
  else if (!strcmp(argv[1], "keys"))
    keys();
  else if (!strcmp(argv[1], "rnode"))
    radio_test();
  else if (!strcmp(argv[1], "pressure"))
    serial_pressure_test();
  else if (!strcmp(argv[1], "udp"))
    udp_test();
  else if (!strcmp(argv[1], "policy"))
    policy_test();
  else
    CHECK(0);
  return 0;
}
