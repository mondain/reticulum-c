#define _XOPEN_SOURCE 700
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <time.h>
#include <reticulum_c/rnc_host.h>
#include <reticulum_c/rnc_log.h>
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
  {
    rnc_host_status radio_status;
    /* reference: sf * (4/cr) / (2^sf / bw) = 5468.75 bit/s at SF7 BW125 CR5 */
    CHECK(rnc_host_get_status(host, 1, &radio_status) == RNC_OK);
    CHECK(radio_status.bitrate == 5469u);
  }
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
        if (command == 0x08 || command == 0x50 || command == 0x48 ||
            command == 0x49) { /* detection: answer detect and firmware */
          uint8_t reply[2] = {command == 0x08 ? 0x46 : 1, 74}, out[32];
          size_t out_size;
          if (command == 0x08 || command == 0x50) {
            CHECK(rnc_host_frame_encode(RNC_HOST_KISS_FRAMING, command, reply,
                                        command == 0x08 ? 1 : 2, out,
                                        sizeof(out), &out_size) == RNC_OK);
            CHECK(write(master, out, out_size) == (ssize_t)out_size);
          }
          continue;
        }
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
/* Identity.to_file and pub_to_file: raw keys, the private one at mode 0600. */
static void identity_files(void) {
  char directory[] = "/tmp/rnc-host-idsave-XXXXXX", path[256], pub[256];
  rnc_identity id, loaded, public_only;
  uint8_t key[64], bytes[64];
  struct stat st;
  unsigned rng = 5;
  size_t i;
  int fd;
  for (i = 0; i < 64; ++i)
    key[i] = (uint8_t)(i * 3u + 1u);
  CHECK(rnc_identity_from_private(&id, key) == RNC_OK);
  CHECK(rnc_identity_from_public(&public_only, id.public_key) == RNC_OK);
  CHECK(mkdtemp(directory));
  CHECK(snprintf(path, sizeof(path), "%s/key", directory) > 0);
  CHECK(snprintf(pub, sizeof(pub), "%s/key.pub", directory) > 0);
  CHECK(rnc_host_identity_save(path, &id, 0, 0) == RNC_OK);
  CHECK(!stat(path, &st) && st.st_size == 64 && (st.st_mode & 0777) == 0600);
  CHECK(rnc_host_identity_load(path, random_bytes, &rng, &loaded) == RNC_OK &&
        !memcmp(loaded.private_key, id.private_key, 64) &&
        !memcmp(loaded.hash, id.hash, 16));
  /* an existing file is only replaced on request */
  CHECK(rnc_host_identity_save(path, &id, 0, 0) == RNC_STATE);
  CHECK(rnc_host_identity_save(path, &id, 0, 1) == RNC_OK);
  CHECK(!stat(path, &st) && (st.st_mode & 0777) == 0600);
  /* public key file */
  CHECK(rnc_host_identity_save(pub, &id, 1, 0) == RNC_OK);
  CHECK(!stat(pub, &st) && st.st_size == 64 && (st.st_mode & 0777) == 0644);
  fd = open(pub, O_RDONLY);
  CHECK(fd >= 0 && read(fd, bytes, 64) == 64 && !memcmp(bytes, id.public_key, 64));
  close(fd);
  /* an identity without a private key can only save its public half */
  CHECK(rnc_host_identity_save(path, &public_only, 0, 1) == RNC_INVALID);
  CHECK(rnc_host_identity_save(pub, &public_only, 1, 1) == RNC_OK);
  CHECK(rnc_host_identity_save(NULL, &id, 0, 0) == RNC_INVALID &&
        rnc_host_identity_save(path, NULL, 0, 0) == RNC_INVALID);
  CHECK(!unlink(path) && !unlink(pub) && !rmdir(directory));
  puts("host identity file tests passed");
}
/* Transport.await_path: asks the network for a path and waits for it. The
 * callback runs for every host event and once per loop pass, which is how the
 * peer in this test is kept alive while the waiter blocks. */
typedef struct await_peer {
  rnc_host *host;
  rnc_node *node;
  uint8_t destination[16];
  rnc_identity identity;
  uint64_t announce_at, started;
  int announced, stop;
  unsigned events, idles;
} await_peer;
static uint64_t wall_ms(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
static int await_step(void *context, const rnc_host_event *event) {
  await_peer *p = context;
  rnc_host_event drop;
  if (event) {
    ++p->events;
    return 0;
  }
  ++p->idles;
  CHECK(rnc_host_step(p->host, 5, (uint64_t)time(NULL), wall_ms()) == RNC_OK);
  while (rnc_host_poll(p->host, &drop) == RNC_OK) {
  }
  if (!p->announced && p->announce_at && wall_ms() >= p->announce_at) {
    uint8_t made[16];
    p->announced = 1;
    /* the destination only comes into being now, so earlier path requests
     * go unanswered */
    CHECK(rnc_node_add_destination(p->node, &p->identity, "await.test", NULL, 0,
                                   made) == RNC_OK &&
          !memcmp(made, p->destination, 16));
    CHECK(rnc_node_announce(p->node, p->destination, (uint64_t)time(NULL),
                            wall_ms()) == RNC_OK);
  }
  return p->stop;
}
static void await_path_test(void) {
  uint8_t key_a[64] = {1}, key_b[64] = {2}, unknown[16] = {0x77};
  unsigned rng = 0;
  rnc_identity ida, idb;
  rnc_node *na, *nb;
  rnc_host *ha, *hb;
  rnc_host_config cfg = {0};
  rnc_host_status status;
  await_peer peer = {0};
  uint64_t t0;
  CHECK(rnc_identity_from_private(&ida, key_a) == RNC_OK &&
        rnc_identity_from_private(&idb, key_b) == RNC_OK);
  na = rnc_node_new(&ida, 0, random_bytes, &rng);
  nb = rnc_node_new(&idb, 0, random_bytes, &rng);
  CHECK(na && nb);
  hb = rnc_host_new(nb);
  ha = rnc_host_new(na);
  CHECK(ha && hb);
  cfg.kind = RNC_HOST_TCP_LISTEN;
  cfg.address = "127.0.0.1";
  CHECK(rnc_host_add(hb, 1, &cfg) == RNC_OK &&
        rnc_host_get_status(hb, 1, &status) == RNC_OK && status.bound_port);
  memset(&cfg, 0, sizeof(cfg));
  cfg.kind = RNC_HOST_TCP_CONNECT;
  cfg.address = "127.0.0.1";
  cfg.port = status.bound_port;
  CHECK(rnc_host_add(ha, 1, &cfg) == RNC_OK);
  {
    uint8_t name_hash[10];
    CHECK(rnc_destination_hash("await.test", &idb, name_hash,
                               peer.destination) == RNC_OK);
  }
  peer.identity = idb;
  peer.host = hb;
  peer.node = nb;
  peer.announce_at = wall_ms() + 400;
  /* the peer announces 400 ms in; the waiter returns once the path exists */
  t0 = wall_ms();
  CHECK(rnc_host_await_path(ha, peer.destination, 10000, await_step, &peer) ==
        RNC_OK);
  CHECK(wall_ms() - t0 >= 300 && wall_ms() - t0 < 6000 && peer.events > 0 &&
        peer.idles > 0);
  /* a path already known returns at once */
  t0 = wall_ms();
  CHECK(rnc_host_await_path(ha, peer.destination, 10000, NULL, NULL) == RNC_OK);
  CHECK(wall_ms() - t0 < 200);
  /* nobody knows this one */
  t0 = wall_ms();
  CHECK(rnc_host_await_path(ha, unknown, 600, await_step, &peer) == RNC_TIMEOUT);
  CHECK(wall_ms() - t0 >= 600 && wall_ms() - t0 < 3000);
  /* a callback can interrupt the wait */
  peer.stop = 1;
  t0 = wall_ms();
  CHECK(rnc_host_await_path(ha, unknown, 10000, await_step, &peer) == RNC_AGAIN);
  CHECK(wall_ms() - t0 < 1000);
  peer.stop = 0;
  CHECK(rnc_host_await_path(ha, unknown, 0, NULL, NULL) == RNC_INVALID &&
        rnc_host_await_path(NULL, unknown, 10, NULL, NULL) == RNC_INVALID);
  rnc_host_free(ha);
  rnc_host_free(hb);
  rnc_node_free(na);
  rnc_node_free(nb);
  puts("host await path test passed");
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

/* Reads whatever the radio side of the PTY received and counts KISS frames by
 * command; data frames (command 0) are compared against the callsign. */
typedef struct radio_tap {
  int master;
  rnc_host_framer parser;
  unsigned data_frames, beacons, saw_st, saw_lt;
  uint8_t st[2], lt[2];
} radio_tap;
static void radio_drain(radio_tap *t) {
  uint8_t bytes[256], decoded[RNC_IFAC_FRAME_MAX], command;
  size_t size, k;
  ssize_t n = read(t->master, bytes, sizeof(bytes));
  if (n <= 0)
    return;
  for (k = 0; k < (size_t)n; ++k)
    if (rnc_host_frame_feed(&t->parser, RNC_HOST_KISS_FRAMING, bytes[k],
                            &command, decoded, sizeof(decoded),
                            &size) == RNC_OK) {
      uint8_t ack[RNC_HOST_FRAME_MAX];
      size_t ack_size;
      if (command == 0x08 || command == 0x50) { /* detect, firmware version */
        uint8_t reply[2] = {command == 0x08 ? 0x46 : 1, 74};
        CHECK(rnc_host_frame_encode(RNC_HOST_KISS_FRAMING, command, reply,
                                    command == 0x08 ? 1 : 2, ack, sizeof(ack),
                                    &ack_size) == RNC_OK);
        CHECK(write(t->master, ack, ack_size) == (ssize_t)ack_size);
      } else if (command == 0) {
        if (size == 6 && !memcmp(decoded, "N0CALL", 6))
          ++t->beacons;
        else
          ++t->data_frames;
      } else if (command == 0x0b && size == 2) {
        t->saw_st = 1;
        memcpy(t->st, decoded, 2);
      } else if (command == 0x0c && size == 2) {
        t->saw_lt = 1;
        memcpy(t->lt, decoded, 2);
      } else if (command >= 1 && command <= 6) {
        if (command == 1)
          decoded[3] = (uint8_t)(decoded[3] + 50u);
        CHECK(rnc_host_frame_encode(RNC_HOST_KISS_FRAMING, command, decoded,
                                    size, ack, sizeof(ack),
                                    &ack_size) == RNC_OK);
        CHECK(write(t->master, ack, ack_size) == (ssize_t)ack_size);
      }
    }
}
/* The reference detects the RNode and checks its firmware (at least 1.52)
 * before configuring the radio. */
typedef struct detect_tap {
  int master, mode; /* 0 silent, 1 answers detect, 2 also the firmware version */
  uint8_t fw[2];
  rnc_host_framer parser;
  unsigned detects, versions, platforms, mcus, config_frames;
} detect_tap;
static void detect_drain(detect_tap *t) {
  uint8_t bytes[256], decoded[RNC_IFAC_FRAME_MAX], command, out[64];
  size_t size, k, out_size;
  ssize_t n = read(t->master, bytes, sizeof(bytes));
  if (n <= 0)
    return;
  for (k = 0; k < (size_t)n; ++k)
    if (rnc_host_frame_feed(&t->parser, RNC_HOST_KISS_FRAMING, bytes[k],
                            &command, decoded, sizeof(decoded),
                            &size) == RNC_OK) {
      if (command == 0x08) {
        CHECK(size == 1 && decoded[0] == 0x73);
        ++t->detects;
        if (t->mode >= 1) {
          uint8_t resp = 0x46;
          CHECK(rnc_host_frame_encode(RNC_HOST_KISS_FRAMING, 0x08, &resp, 1,
                                      out, sizeof(out), &out_size) == RNC_OK);
          CHECK(write(t->master, out, out_size) == (ssize_t)out_size);
        }
      } else if (command == 0x50) {
        ++t->versions;
        if (t->mode >= 2) {
          CHECK(rnc_host_frame_encode(RNC_HOST_KISS_FRAMING, 0x50, t->fw, 2,
                                      out, sizeof(out), &out_size) == RNC_OK);
          CHECK(write(t->master, out, out_size) == (ssize_t)out_size);
        }
      } else if (command == 0x48) {
        ++t->platforms;
      } else if (command == 0x49) {
        ++t->mcus;
      } else if (command >= 1 && command <= 6) {
        ++t->config_frames;
        if (command == 1)
          decoded[3] = (uint8_t)(decoded[3] + 50u);
        CHECK(rnc_host_frame_encode(RNC_HOST_KISS_FRAMING, command, decoded,
                                    size, out, sizeof(out),
                                    &out_size) == RNC_OK);
        CHECK(write(t->master, out, out_size) == (ssize_t)out_size);
      }
    }
}
static void rnode_detect_run(int mode, uint8_t major, uint8_t minor,
                             uint64_t duration, detect_tap *tap,
                             rnc_host_status *status) {
  uint8_t key[64] = {0};
  unsigned rng = 0;
  uint64_t now = 100;
  rnc_identity id;
  rnc_node *node;
  rnc_host *host;
  rnc_host_config cfg = {0};
  memset(tap, 0, sizeof(*tap));
  tap->mode = mode;
  tap->fw[0] = major;
  tap->fw[1] = minor;
  tap->master = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
  CHECK(tap->master >= 0 && !grantpt(tap->master) && !unlockpt(tap->master));
  CHECK(rnc_identity_from_private(&id, key) == RNC_OK);
  node = rnc_node_new(&id, 0, random_bytes, &rng);
  host = node ? rnc_host_new(node) : NULL;
  CHECK(host);
  cfg.kind = RNC_HOST_RNODE;
  cfg.address = ptsname(tap->master);
  cfg.serial_baud = 115200;
  cfg.frequency = 915000000;
  cfg.bandwidth = 125000;
  cfg.tx_power = 10;
  cfg.spreading_factor = 7;
  cfg.coding_rate = 5;
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
  while (now < 100 + duration) {
    CHECK(rnc_host_step(host, 0, 1700000000, now += 10) == RNC_OK);
    detect_drain(tap);
  }
  CHECK(rnc_host_get_status(host, 1, status) == RNC_OK);
  rnc_host_free(host);
  rnc_node_free(node);
  close(tap->master);
}
static void rnode_detect_test(void) {
  detect_tap tap;
  rnc_host_status status;
  /* detected, firmware 1.74: the radio is configured */
  rnode_detect_run(2, 1, 74, 3000, &tap, &status);
  CHECK(tap.detects == 1 && tap.versions == 1 && tap.platforms == 1 &&
        tap.mcus == 1 && tap.config_frames >= 6 && status.radio_ready);
  /* the oldest firmware accepted, and a newer major version */
  rnode_detect_run(2, 1, 52, 3000, &tap, &status);
  CHECK(status.radio_ready);
  rnode_detect_run(2, 2, 0, 3000, &tap, &status);
  CHECK(status.radio_ready);
  /* nothing answers: the radio is never configured and the interface drops */
  rnode_detect_run(0, 0, 0, 5700, &tap, &status); /* dropped at 5 s, not yet retried */
  CHECK(tap.detects >= 1 && tap.config_frames == 0 && !status.radio_ready &&
        !status.online);
  /* firmware too old: refused, and not retried */
  rnode_detect_run(2, 1, 51, 70000, &tap, &status);
  CHECK(!status.radio_ready && !status.online && status.reconnects == 0 &&
        tap.detects == 1);
  rnode_detect_run(2, 0, 99, 20000, &tap, &status);
  CHECK(!status.radio_ready && !status.online);
  puts("host RNode detection tests passed");
}
/* RSSI, SNR and link quality: an RNode reports them just before each received
 * frame, and they travel with the host event for that packet. */
static void rnode_signal_run(unsigned sf, uint8_t rssi_byte, uint8_t snr_byte,
                             int want_rssi, double want_snr, double want_q) {
  uint8_t key[64] = {0}, key2[64] = {9}, raw[RNC_MAX_MTU], wire[RNC_HOST_FRAME_MAX],
          stats[8];
  unsigned rng = 0, i;
  uint64_t now = 100;
  size_t n, m;
  detect_tap tap;
  rnc_identity id, other;
  rnc_node *node;
  rnc_host *host;
  rnc_host_config cfg = {0};
  rnc_host_status status;
  rnc_host_event event;
  rnc_packet announce;
  int found = 0;
  memset(&tap, 0, sizeof(tap));
  tap.mode = 2;
  tap.fw[0] = 1;
  tap.fw[1] = 74;
  tap.master = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
  CHECK(tap.master >= 0 && !grantpt(tap.master) && !unlockpt(tap.master));
  CHECK(rnc_identity_from_private(&id, key) == RNC_OK &&
        rnc_identity_from_private(&other, key2) == RNC_OK);
  node = rnc_node_new(&id, 0, random_bytes, &rng);
  host = node ? rnc_host_new(node) : NULL;
  CHECK(host);
  cfg.kind = RNC_HOST_RNODE;
  cfg.address = ptsname(tap.master);
  cfg.serial_baud = 115200;
  cfg.frequency = 915000000;
  cfg.bandwidth = 125000;
  cfg.tx_power = 10;
  cfg.spreading_factor = sf;
  cfg.coding_rate = 5;
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
  for (i = 0; i < 1000; ++i) {
    CHECK(rnc_host_step(host, 0, 1700000000, now += 10) == RNC_OK);
    detect_drain(&tap);
    CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK);
    if (status.radio_ready)
      break;
  }
  CHECK(status.radio_ready && !status.has_signal);
  /* the statistics, then an announce from another node */
  CHECK(rnc_announce_create(&other, "signal.test", NULL, 0, 1700000000, random_bytes,
                            &rng, &announce) == RNC_OK);
  CHECK(rnc_packet_encode(&announce, raw, sizeof(raw), &n) == RNC_OK);
  stats[0] = 0xc0, stats[1] = 0x23, stats[2] = rssi_byte, stats[3] = 0xc0;
  stats[4] = 0xc0, stats[5] = 0x24, stats[6] = snr_byte, stats[7] = 0xc0;
  CHECK(write(tap.master, stats, sizeof(stats)) == (ssize_t)sizeof(stats));
  CHECK(rnc_host_frame_encode(RNC_HOST_KISS_FRAMING, 0, raw, n, wire,
                              sizeof(wire), &m) == RNC_OK);
  CHECK(write(tap.master, wire, m) == (ssize_t)m);
  for (i = 0; i < 200 && !found; ++i) {
    CHECK(rnc_host_step(host, 0, 1700000000, now += 10) == RNC_OK);
    while (rnc_host_poll(host, &event) == RNC_OK)
      if (event.type == RNC_HOST_NODE && event.node.type == RNC_NODE_ANNOUNCE) {
        CHECK(event.has_signal && event.rssi == want_rssi);
        CHECK(event.snr > want_snr - 0.001f && event.snr < want_snr + 0.001f);
        CHECK(event.quality > want_q - 0.01f && event.quality < want_q + 0.01f);
        found = 1;
      }
  }
  CHECK(found);
  CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK && status.has_signal &&
        status.rssi == want_rssi);
  rnc_host_free(host);
  rnc_node_free(node);
  close(tap.master);
}
static void rnode_signal_test(void) {
  /* SF7: quality spans -9 to 6 dB; RSSI is the byte less 157 */
  rnode_signal_run(7, 100, 13, -57, 3.25, 81.7);
  /* SF9 shifts the lower end by 4 dB to -13; negative SNR is a signed byte */
  rnode_signal_run(9, 140, 0xf0, -17, -4.0, 47.4);
  /* clamped at both ends */
  rnode_signal_run(7, 157, 0x7f, 0, 31.75, 100.0);
  rnode_signal_run(12, 20, 0x80, -137, -32.0, 0.0);
  puts("host RNode signal tests passed");
}
static void radio_extras_test(void) {
  radio_tap tap = {0};
  uint8_t key[64] = {0};
  unsigned rng = 0, i;
  rnc_identity id;
  rnc_node *node;
  rnc_host *host;
  rnc_host_config cfg = {0};
  rnc_host_status status;
  rnc_packet plain = {0};
  uint64_t now = 100;
  tap.master = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
  CHECK(tap.master >= 0);
  CHECK(!grantpt(tap.master) && !unlockpt(tap.master));
  CHECK(rnc_identity_from_private(&id, key) == RNC_OK);
  node = rnc_node_new(&id, 0, random_bytes, &rng);
  CHECK(node);
  host = rnc_host_new(node);
  CHECK(host);
  cfg.kind = RNC_HOST_RNODE;
  cfg.address = ptsname(tap.master);
  cfg.serial_baud = 115200;
  cfg.frequency = 915000000;
  cfg.bandwidth = 125000;
  cfg.tx_power = 10;
  cfg.spreading_factor = 7;
  cfg.coding_rate = 5;
  cfg.airtime_limit_short = 25.5;
  cfg.airtime_limit_long = 10.0;
  cfg.id_callsign = "N0CALL";
  cfg.id_interval = 10;
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
  for (i = 0; i < 1000; ++i) {
    CHECK(rnc_host_step(host, 0, 1700000000, ++now) == RNC_OK);
    radio_drain(&tap);
    CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK);
    if (status.radio_ready && tap.saw_st && tap.saw_lt)
      break;
  }
  CHECK(status.radio_ready && tap.saw_st && tap.saw_lt);
  CHECK(tap.st[0] == 0x09 && tap.st[1] == 0xf6); /* 25.5% in hundredths */
  CHECK(tap.lt[0] == 0x03 && tap.lt[1] == 0xe8); /* 10.0% */
  plain.flags = 8;
  plain.data_size = 1;
  plain.data[0] = 0x11;
  now = 5000;
  CHECK(rnc_node_send(node, &plain, 1700000001, now) == RNC_OK);
  for (i = 0; i < 20; ++i) {
    CHECK(rnc_host_step(host, 0, 1700000001, ++now) == RNC_OK);
    radio_drain(&tap);
  }
  CHECK(tap.data_frames == 1 && tap.beacons == 0);
  /* first transmission at ~5000 ms starts the ID clock; 10 s later we ID */
  CHECK(rnc_host_step(host, 0, 1700000010, 14000) == RNC_OK);
  radio_drain(&tap);
  CHECK(tap.beacons == 0);
  CHECK(rnc_host_step(host, 0, 1700000011, 15100) == RNC_OK);
  CHECK(rnc_host_step(host, 0, 1700000011, 15200) == RNC_OK);
  radio_drain(&tap);
  CHECK(tap.beacons == 1);
  /* the beacon itself does not restart the clock: nothing until new traffic */
  CHECK(rnc_host_step(host, 0, 1700000040, 40000) == RNC_OK);
  radio_drain(&tap);
  CHECK(tap.beacons == 1);
  CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK &&
        status.tx_packets == 1);
  rnc_host_free(host);
  rnc_node_free(node);
  close(tap.master);
  puts("host RNode airtime and beacon tests passed");
}
static void pipe_test(void) {
  uint8_t key[64] = {0};
  unsigned rng = 0, i;
  rnc_identity id;
  rnc_node *node;
  rnc_host *host;
  rnc_host_config cfg = {0};
  rnc_host_status status;
  rnc_packet plain = {0};
  CHECK(rnc_identity_from_private(&id, key) == RNC_OK);
  node = rnc_node_new(&id, 0, random_bytes, &rng);
  CHECK(node);
  host = rnc_host_new(node);
  CHECK(host);
  cfg.kind = RNC_HOST_PIPE;
  cfg.address = "";
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_INVALID);
  cfg.address = "cat";
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
  plain.flags = 8;
  plain.data_size = 1;
  plain.data[0] = 0x11;
  CHECK(rnc_node_send(node, &plain, 1700000000, 100) == RNC_OK);
  for (i = 0; i < 300; ++i) {
    CHECK(rnc_host_step(host, 10, 1700000000, 100 + i) == RNC_OK);
    CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK);
    if (status.rx_packets)
      break;
  }
  /* cat echoes the HDLC frame back, so it arrives as input */
  CHECK(status.online && status.kind == RNC_HOST_PIPE);
  CHECK(status.tx_packets == 1 && status.rx_packets == 1);
  CHECK(status.bitrate == 1000000u);
  rnc_host_free(host);
  /* a command that exits is restarted after respawn_delay_ms */
  host = rnc_host_new(node);
  CHECK(host);
  cfg.address = "true";
  cfg.respawn_delay_ms = 50;
  CHECK(rnc_host_add(host, 2, &cfg) == RNC_OK);
  for (i = 0; i < 400; ++i) {
    CHECK(rnc_host_step(host, 10, 1700000001, 1000 + 10u * i) == RNC_OK);
    CHECK(rnc_host_get_status(host, 2, &status) == RNC_OK);
    if (status.reconnects)
      break;
  }
  CHECK(status.reconnects >= 1);
  CHECK(i < 60); /* respawn_delay_ms honoured, not the 1 s default */
  rnc_host_free(host);
  rnc_node_free(node);
  puts("host pipe tests passed");
}
typedef struct tnc_frame {
  uint8_t command, data[RNC_HOST_FRAME_MAX];
  size_t size;
} tnc_frame;
static size_t tnc_read(int master, rnc_host_framer *parser, tnc_frame *out,
                       size_t count, size_t max) {
  uint8_t bytes[512];
  ssize_t n = read(master, bytes, sizeof(bytes));
  size_t k;
  for (k = 0; n > 0 && k < (size_t)n && count < max; ++k) {
    uint8_t decoded[RNC_IFAC_FRAME_MAX], command;
    size_t size;
    if (rnc_host_frame_feed(parser, RNC_HOST_KISS_FRAMING, bytes[k], &command,
                            decoded, sizeof(decoded), &size) == RNC_OK) {
      out[count].command = command;
      out[count].size = size;
      memcpy(out[count].data, decoded, size);
      ++count;
    }
  }
  return count;
}
static void ax25_test(void) {
  int master = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
  uint8_t key[64] = {0}, ready[RNC_HOST_FRAME_MAX], header[16];
  unsigned rng = 0, i;
  size_t count = 0, ready_size, k;
  tnc_frame frames[16];
  rnc_host_framer parser = {0};
  rnc_identity id;
  rnc_node *node;
  rnc_host *host;
  rnc_host_config cfg = {0};
  rnc_host_status status;
  rnc_packet plain = {0};
  const uint8_t setup[][2] = {{0x01, 35}, {0x04, 2}, {0x02, 64},
                              {0x03, 2},  {0x0f, 1}};
  const char dst[] = "APZRNS", src[] = "N0CALL";
  CHECK(master >= 0 && !grantpt(master) && !unlockpt(master));
  CHECK(rnc_identity_from_private(&id, key) == RNC_OK);
  node = rnc_node_new(&id, 0, random_bytes, &rng);
  CHECK(node);
  host = rnc_host_new(node);
  CHECK(host);
  cfg.kind = RNC_HOST_AX25;
  cfg.address = ptsname(master);
  cfg.serial_baud = 115200;
  cfg.callsign = "ab";
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_INVALID);
  cfg.callsign = "n0call";
  cfg.ssid = 16;
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_INVALID);
  cfg.ssid = 3;
  cfg.flow_control = 1;
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
  plain.flags = 8;
  plain.data_size = 1;
  plain.data[0] = 0x11;
  CHECK(rnc_node_send(node, &plain, 1700000000, 100) == RNC_OK);
  for (i = 0; i < 100 && count < 6; ++i) {
    CHECK(rnc_host_step(host, 0, 1700000000, 100 + 100u * i) == RNC_OK);
    count = tnc_read(master, &parser, frames, count, 16);
  }
  CHECK(count == 6);
  for (k = 0; k < 5; ++k)
    CHECK(frames[k].command == setup[k][0] && frames[k].size == 1 &&
          frames[k].data[0] == setup[k][1]);
  CHECK(frames[5].command == 0 && frames[5].size > 16);
  for (k = 0; k < 6; ++k) {
    header[k] = (uint8_t)(dst[k] << 1);
    header[7 + k] = (uint8_t)(src[k] << 1);
  }
  header[6] = 0x60;
  header[13] = 0x60 | (3 << 1) | 1;
  header[14] = 0x03;
  header[15] = 0xf0;
  CHECK(!memcmp(frames[5].data, header, 16));
  /* with flow control, the next packet waits for the TNC's ready frame */
  CHECK(rnc_node_send(node, &plain, 1700000001, 1000) == RNC_OK);
  for (i = 0; i < 20; ++i) {
    CHECK(rnc_host_step(host, 0, 1700000001, 1000 + 100u * i) == RNC_OK);
    count = tnc_read(master, &parser, frames, count, 16);
  }
  CHECK(count == 6);
  CHECK(rnc_host_frame_encode(RNC_HOST_KISS_FRAMING, 0x0f,
                              (const uint8_t[]){1}, 1, ready,
                              sizeof(ready), &ready_size) == RNC_OK);
  CHECK(write(master, ready, ready_size) == (ssize_t)ready_size);
  for (i = 0; i < 20; ++i) {
    CHECK(rnc_host_step(host, 0, 1700000001, 3000 + 100u * i) == RNC_OK);
    count = tnc_read(master, &parser, frames, count, 16);
  }
  CHECK(count == 7 && frames[6].command == 0);
  /* a frame arriving from the TNC has its AX.25 header stripped */
  {
    uint8_t echo[RNC_HOST_FRAME_MAX];
    size_t echo_size;
    CHECK(rnc_host_frame_encode(RNC_HOST_KISS_FRAMING, 0, frames[6].data,
                                frames[6].size, echo, sizeof(echo),
                                &echo_size) == RNC_OK);
    CHECK(write(master, echo, echo_size) == (ssize_t)echo_size);
  }
  for (i = 0; i < 20; ++i)
    CHECK(rnc_host_step(host, 0, 1700000001, 5000 + 100u * i) == RNC_OK);
  CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK);
  CHECK(status.kind == RNC_HOST_AX25 && status.rx_packets == 1 &&
        status.tx_packets == 2);
  rnc_host_free(host);
  rnc_node_free(node);
  close(master);
  puts("host AX.25 KISS tests passed");
}
static int flap_connect(uint16_t port) {
  struct sockaddr_in a = {0};
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  CHECK(fd >= 0);
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0);
  CHECK(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
  return fd;
}
static void fast_flap_test(void) {
  uint8_t key[64] = {0};
  unsigned rng = 0, i, round;
  uint64_t now = 100;
  rnc_identity id;
  rnc_node *node;
  rnc_host *host;
  rnc_host_config cfg = {0};
  rnc_host_status status;
  CHECK(rnc_identity_from_private(&id, key) == RNC_OK);
  node = rnc_node_new(&id, 0, random_bytes, &rng);
  CHECK(node);
  host = rnc_host_new(node);
  CHECK(host);
  cfg.kind = RNC_HOST_TCP_LISTEN;
  cfg.address = "127.0.0.1";
  cfg.fast_flap.enabled = 1;
  cfg.fast_flap.grace = 2;
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
  CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK && status.bound_port);
  /* three short-lived connections exceed a grace of two */
  for (round = 0; round < 3; ++round) {
    int fd = flap_connect(status.bound_port);
    uint8_t byte;
    for (i = 0; i < 10; ++i)
      CHECK(rnc_host_step(host, 5, 1700000000, now += 10) == RNC_OK);
    CHECK(recv(fd, &byte, 1, 0) < 0 && errno == EAGAIN); /* accepted, open */
    close(fd);
    for (i = 0; i < 10; ++i)
      CHECK(rnc_host_step(host, 5, 1700000000, now += 10) == RNC_OK);
  }
  CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK &&
        status.blocked_ips == 1);
  {
    int fd = flap_connect(status.bound_port);
    uint8_t byte;
    ssize_t got = -1;
    for (i = 0; i < 20 && got < 0; ++i) {
      CHECK(rnc_host_step(host, 5, 1700000000, now += 10) == RNC_OK);
      got = recv(fd, &byte, 1, 0);
    }
    CHECK(got == 0); /* refused: closed without service */
    close(fd);
  }
  /* the block lapses 12 h after the last flap */
  CHECK(rnc_host_step(host, 0, 1700000000, now + 12u * 3600u * 1000u + 1000u) ==
        RNC_OK);
  CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK &&
        status.blocked_ips == 0);
  rnc_host_free(host);
  rnc_node_free(node);
  puts("host fast-flap tests passed");
}
static int tcp_listener(int family, uint16_t *port) {
  struct sockaddr_storage a = {0};
  socklen_t n = sizeof(a);
  int fd = socket(family, SOCK_STREAM, 0), one = 1;
  CHECK(fd >= 0);
  (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  if (family == AF_INET) {
    struct sockaddr_in *v4 = (struct sockaddr_in *)&a;
    v4->sin_family = AF_INET;
    v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    v4->sin_port = htons(*port);
  } else {
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&a;
    v6->sin6_family = AF_INET6;
    v6->sin6_addr = in6addr_loopback;
    v6->sin6_port = htons(*port);
  }
  if (bind(fd, (struct sockaddr *)&a, family == AF_INET
                                          ? sizeof(struct sockaddr_in)
                                          : sizeof(struct sockaddr_in6)) < 0) {
    close(fd);
    return -1;
  }
  CHECK(listen(fd, 4) == 0);
  CHECK(getsockname(fd, (struct sockaddr *)&a, &n) == 0);
  *port = ntohs(family == AF_INET ? ((struct sockaddr_in *)&a)->sin_port
                                  : ((struct sockaddr_in6 *)&a)->sin6_port);
  CHECK(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
  return fd;
}
static int accept_within(rnc_host *host, int listener, uint64_t *now,
                         unsigned steps) {
  unsigned i;
  for (i = 0; i < steps; ++i) {
    int fd;
    CHECK(rnc_host_step(host, 5, 1700000000, *now += 10) == RNC_OK);
    fd = accept(listener, NULL, NULL);
    if (fd >= 0)
      return fd;
  }
  return -1;
}
/* A client added before the first step, on a clock far from zero (a real
 * monotonic clock), must connect at once, not after a reconnect wait. */
static void connect_late_clock_test(void) {
  uint8_t key[64] = {0};
  unsigned rng = 0, i;
  uint64_t now = 3000000;
  uint16_t port = 0;
  int listener, accepted;
  rnc_identity id;
  rnc_node *node;
  rnc_host *host;
  rnc_host_config cfg = {0};
  rnc_host_status status;
  CHECK(rnc_identity_from_private(&id, key) == RNC_OK);
  node = rnc_node_new(&id, 0, random_bytes, &rng);
  host = node ? rnc_host_new(node) : NULL;
  listener = tcp_listener(AF_INET, &port);
  CHECK(host && listener >= 0);
  cfg.kind = RNC_HOST_TCP_CONNECT;
  cfg.address = "127.0.0.1";
  cfg.port = port;
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
  accepted = accept_within(host, listener, &now, 50);
  CHECK(accepted >= 0);
  for (i = 0; i < 20; ++i)
    CHECK(rnc_host_step(host, 5, 1700000000, now += 10) == RNC_OK);
  CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK && status.online &&
        status.last_errno == 0);
  close(accepted);
  close(listener);
  rnc_host_free(host);
  rnc_node_free(node);
  puts("host late clock connect test passed");
}
/* outgoing = No: the interface still receives, but nothing is sent on it,
 * including on the connections a listener accepts. */
static void no_output_test(void) {
  uint8_t key[64] = {0};
  unsigned rng = 0, i;
  uint64_t now = 100;
  uint16_t port = 0;
  int listener, accepted, client;
  rnc_identity id;
  rnc_node *node;
  rnc_host *host;
  rnc_host_config cfg = {0};
  rnc_packet plain = {0};
  uint8_t bytes[64];
  ssize_t got = -1;
  CHECK(rnc_identity_from_private(&id, key) == RNC_OK);
  node = rnc_node_new(&id, 0, random_bytes, &rng);
  CHECK(node);
  plain.flags = 8;
  plain.data_size = 1;
  plain.data[0] = 0x11;
  /* client interface */
  host = rnc_host_new(node);
  listener = tcp_listener(AF_INET, &port);
  CHECK(host && listener >= 0);
  cfg.kind = RNC_HOST_TCP_CONNECT;
  cfg.address = "127.0.0.1";
  cfg.port = port;
  cfg.no_output = 1;
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
  accepted = accept_within(host, listener, &now, 50);
  CHECK(accepted >= 0);
  CHECK(rnc_node_send(node, &plain, 1700000000, now) == RNC_OK);
  for (i = 0; i < 50; ++i) {
    CHECK(rnc_host_step(host, 5, 1700000000, now += 10) == RNC_OK);
    got = recv(accepted, bytes, sizeof(bytes), MSG_DONTWAIT);
    CHECK(got <= 0 && (got == 0 || errno == EAGAIN || errno == EWOULDBLOCK));
  }
  close(accepted);
  close(listener);
  rnc_host_free(host);
  /* the same interface with output enabled does send */
  host = rnc_host_new(node);
  listener = tcp_listener(AF_INET, &port);
  CHECK(host && listener >= 0);
  cfg.port = port;
  cfg.no_output = 0;
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
  accepted = accept_within(host, listener, &now, 50);
  CHECK(accepted >= 0);
  CHECK(rnc_node_send(node, &plain, 1700000000, now) == RNC_OK);
  got = -1;
  for (i = 0; i < 50 && got <= 0; ++i) {
    CHECK(rnc_host_step(host, 5, 1700000000, now += 10) == RNC_OK);
    got = recv(accepted, bytes, sizeof(bytes), MSG_DONTWAIT);
  }
  CHECK(got > 0);
  close(accepted);
  close(listener);
  rnc_host_free(host);
  /* accepted connections of a listener inherit it */
  host = rnc_host_new(node);
  CHECK(host);
  memset(&cfg, 0, sizeof(cfg));
  cfg.kind = RNC_HOST_TCP_LISTEN;
  cfg.address = "127.0.0.1";
  cfg.no_output = 1;
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
  {
    rnc_host_status status;
    struct sockaddr_in addr;
    CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK && status.bound_port);
    client = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(client >= 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(status.bound_port);
    CHECK(connect(client, (struct sockaddr *)&addr, sizeof(addr)) == 0);
  }
  for (i = 0; i < 20; ++i)
    CHECK(rnc_host_step(host, 5, 1700000000, now += 10) == RNC_OK);
  CHECK(rnc_node_send(node, &plain, 1700000000, now) == RNC_OK);
  for (i = 0; i < 50; ++i) {
    CHECK(rnc_host_step(host, 5, 1700000000, now += 10) == RNC_OK);
    got = recv(client, bytes, sizeof(bytes), MSG_DONTWAIT);
    CHECK(got <= 0 && (got == 0 || errno == EAGAIN || errno == EWOULDBLOCK));
  }
  close(client);
  rnc_host_free(host);
  rnc_node_free(node);
  puts("host no output test passed");
}
static void tcp_options_test(void) {
  uint8_t key[64] = {0};
  unsigned rng = 0, i;
  uint64_t now = 100;
  uint16_t port = 0, free_port = 0;
  int listener, accepted, one = 1, value;
  socklen_t n;
  rnc_identity id;
  rnc_node *node;
  rnc_host *host;
  rnc_host_config cfg = {0};
  rnc_host_status status;
  rnc_packet plain = {0};
  CHECK(rnc_identity_from_private(&id, key) == RNC_OK);
  node = rnc_node_new(&id, 0, random_bytes, &rng);
  CHECK(node);
  plain.flags = 8;
  plain.data_size = 1;
  plain.data[0] = 0x11;
  (void)one;
  /* keepalive and user timeout on the host's connected socket */
  host = rnc_host_new(node);
  CHECK(host);
  listener = tcp_listener(AF_INET, &port);
  CHECK(listener >= 0);
  cfg.kind = RNC_HOST_TCP_CONNECT;
  cfg.address = "127.0.0.1";
  cfg.port = port;
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
  accepted = accept_within(host, listener, &now, 50);
  CHECK(accepted >= 0);
  {
    int fd, found = 0;
    for (fd = 3; fd < 256; ++fd) {
      struct sockaddr_in peer;
      socklen_t peer_size = sizeof(peer);
      if (fd == listener || fd == accepted ||
          getpeername(fd, (struct sockaddr *)&peer, &peer_size) != 0 ||
          peer.sin_family != AF_INET || ntohs(peer.sin_port) != port)
        continue;
      found = 1;
      n = sizeof(value);
      /* BSD kernels report boolean options as their flag bit, not 1 */
      CHECK(getsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &value, &n) == 0 &&
            value != 0);
#ifdef __linux__
      CHECK(getsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &value, &n) == 0 &&
            value == 5);
      CHECK(getsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &value, &n) == 0 &&
            value == 2);
      CHECK(getsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &value, &n) == 0 &&
            value == 12);
      CHECK(getsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &value, &n) == 0 &&
            value == 24000);
#endif
    }
    CHECK(found);
  }
  close(accepted);
  rnc_host_free(host);
  /* kiss_framing: data frames are FEND 0x00 ... FEND instead of HDLC */
  host = rnc_host_new(node);
  CHECK(host);
  cfg.kiss_framing = 1;
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
  accepted = accept_within(host, listener, &now, 50);
  CHECK(accepted >= 0);
  CHECK(rnc_node_send(node, &plain, 1700000000, now) == RNC_OK);
  {
    uint8_t bytes[64];
    ssize_t got = -1;
    for (i = 0; i < 50 && got <= 0; ++i) {
      CHECK(rnc_host_step(host, 5, 1700000000, now += 10) == RNC_OK);
      got = recv(accepted, bytes, sizeof(bytes), MSG_DONTWAIT);
    }
    CHECK(got > 3 && bytes[0] == 0xc0 && bytes[1] == 0x00 &&
          bytes[got - 1] == 0xc0);
  }
  close(accepted);
  rnc_host_free(host);
  close(listener);
  /* max_reconnect_tries stops retrying; reconnect_wait_ms paces attempts */
  listener = tcp_listener(AF_INET, &free_port);
  CHECK(listener >= 0);
  close(listener); /* nothing listens on free_port now */
  host = rnc_host_new(node);
  CHECK(host);
  cfg.kiss_framing = 0;
  cfg.port = free_port;
  cfg.reconnect_wait_ms = 50;
  cfg.max_reconnect_tries = 2;
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
  for (i = 0; i < 100; ++i)
    CHECK(rnc_host_step(host, 1, 1700000000, now += 10) == RNC_OK);
  listener = tcp_listener(AF_INET, &free_port);
  CHECK(listener >= 0);
  CHECK(accept_within(host, listener, &now, 100) < 0);
  CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK && !status.online);
  close(listener);
  rnc_host_free(host);
  /* without a limit, the same client connects once the listener appears */
  host = rnc_host_new(node);
  CHECK(host);
  cfg.max_reconnect_tries = 0;
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
  for (i = 0; i < 20; ++i)
    CHECK(rnc_host_step(host, 1, 1700000000, now += 10) == RNC_OK);
  listener = tcp_listener(AF_INET, &free_port);
  CHECK(listener >= 0);
  accepted = accept_within(host, listener, &now, 100);
  CHECK(accepted >= 0);
  close(accepted);
  close(listener);
  rnc_host_free(host);
  /* prefer_ipv6 picks the IPv6 address of a name that has both */
  {
    struct addrinfo hints = {0}, *res = NULL;
    uint16_t port6 = 0;
    int listener6;
    int v4 = 0, v6 = 0;
    struct addrinfo *entry;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo("localhost", "1", &hints, &res) == 0)
      for (entry = res; entry; entry = entry->ai_next) {
        v4 |= entry->ai_family == AF_INET;
        v6 |= entry->ai_family == AF_INET6;
      }
    if (res)
      freeaddrinfo(res);
    /* needs a dual-stack "localhost"; skipped where the resolver has no ::1 */
    listener6 = v4 && v6 ? tcp_listener(AF_INET6, &port6) : -1;
    if (listener6 < 0)
      puts("prefer_ipv6 check skipped: localhost is not dual-stack here");
    if (listener6 >= 0) {
      host = rnc_host_new(node);
      CHECK(host);
      cfg.address = "localhost";
      cfg.port = port6;
      cfg.reconnect_wait_ms = 50;
      cfg.prefer_ipv6 = 1;
      CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
      accepted = accept_within(host, listener6, &now, 100);
      CHECK(accepted >= 0);
      close(accepted);
      close(listener6);
      rnc_host_free(host);
    }
  }
  /* a connect that never completes is abandoned after connect_timeout_ms. The
   * saturated accept queue that stalls the handshake is Linux behaviour; other
   * kernels complete or refuse the connection instead. */
#ifdef __linux__
  {
    uint16_t stuck_port = 0;
    int stuck = tcp_listener(AF_INET, &stuck_port), fillers[8], k;
    struct sockaddr_in a = {0};
    CHECK(stuck >= 0);
    CHECK(listen(stuck, 0) == 0);
    a.sin_family = AF_INET;
    a.sin_port = htons(stuck_port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    for (k = 0; k < 8; ++k) { /* saturate the accept queue so SYNs are dropped */
      fillers[k] = socket(AF_INET, SOCK_STREAM, 0);
      CHECK(fcntl(fillers[k], F_SETFL, O_NONBLOCK) == 0);
      (void)connect(fillers[k], (struct sockaddr *)&a, sizeof(a));
    }
    host = rnc_host_new(node);
    CHECK(host);
    cfg.address = "127.0.0.1";
    cfg.port = stuck_port;
    cfg.prefer_ipv6 = 0;
    cfg.connect_timeout_ms = 200;
    cfg.reconnect_wait_ms = 100000;
    CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
    CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK && !status.online);
    CHECK(rnc_host_step(host, 0, 1700000000, now += 100) == RNC_OK);
    CHECK(rnc_host_step(host, 0, 1700000000, now += 250) == RNC_OK);
    CHECK(rnc_host_get_status(host, 1, &status) == RNC_OK &&
          status.last_errno == ETIMEDOUT);
    rnc_host_free(host);
    for (k = 0; k < 8; ++k)
      close(fillers[k]);
    close(stuck);
  }
#endif
  rnc_node_free(node);
  puts("host TCP option tests passed");
}
static void serial_params_test(void) {
  unsigned rng = 0;
  uint8_t key[64] = {0};
  rnc_identity id;
  CHECK(rnc_identity_from_private(&id, key) == RNC_OK);
  {
    int master = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
    rnc_node *node = rnc_node_new(&id, 0, random_bytes, &rng);
    rnc_host *host = rnc_host_new(node);
    rnc_host_config cfg = {0};
    CHECK(master >= 0 && !grantpt(master) && !unlockpt(master));
    cfg.kind = RNC_HOST_SERIAL;
    cfg.address = ptsname(master);
    cfg.serial_baud = 115200;
    cfg.serial_databits = 9;
    CHECK(rnc_host_add(host, 1, &cfg) == RNC_INVALID);
    cfg.serial_databits = 8;
    cfg.serial_parity = 'X';
    CHECK(rnc_host_add(host, 1, &cfg) == RNC_INVALID);
    cfg.serial_parity = 'N';
    cfg.serial_stopbits = 3;
    CHECK(rnc_host_add(host, 1, &cfg) == RNC_INVALID);
    cfg.serial_databits = 7;
    cfg.serial_parity = 'E';
    cfg.serial_stopbits = 2;
    CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
    rnc_host_free(host);
    rnc_node_free(node);
    close(master);
  }
  puts("host serial parameter tests passed");
}
static void kiss_test(void) {
  int master = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
  uint8_t key[64] = {0}, ready[RNC_HOST_FRAME_MAX];
  unsigned rng = 0, i;
  size_t count = 0, ready_size, k;
  tnc_frame frames[16];
  rnc_host_framer parser = {0};
  rnc_identity id;
  rnc_node *node;
  rnc_host *host;
  rnc_host_config cfg = {0};
  rnc_packet plain = {0};
  const uint8_t setup[][2] = {{0x01, 10}, {0x04, 2}, {0x02, 64},
                              {0x03, 2},  {0x0f, 1}};
  CHECK(master >= 0 && !grantpt(master) && !unlockpt(master));
  CHECK(rnc_identity_from_private(&id, key) == RNC_OK);
  node = rnc_node_new(&id, 0, random_bytes, &rng);
  CHECK(node);
  host = rnc_host_new(node);
  CHECK(host);
  cfg.kind = RNC_HOST_KISS;
  cfg.address = ptsname(master);
  cfg.serial_baud = 115200;
  cfg.preamble_ms = 100;
  cfg.flow_control = 1;
  cfg.id_callsign = "N0CALL";
  cfg.id_interval = 10;
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
  plain.flags = 8;
  plain.data_size = 1;
  plain.data[0] = 0x11;
  CHECK(rnc_node_send(node, &plain, 1700000000, 100) == RNC_OK);
  for (i = 0; i < 100 && count < 6; ++i) {
    CHECK(rnc_host_step(host, 0, 1700000000, 100 + 100u * i) == RNC_OK);
    count = tnc_read(master, &parser, frames, count, 16);
  }
  CHECK(count == 6);
  for (k = 0; k < 5; ++k)
    CHECK(frames[k].command == setup[k][0] && frames[k].size == 1 &&
          frames[k].data[0] == setup[k][1]);
  /* plain KISS carries the packet itself, with no AX.25 header */
  CHECK(frames[5].command == 0 && frames[5].size < 30 &&
        frames[5].data[0] == 0x08);
  CHECK(rnc_host_frame_encode(RNC_HOST_KISS_FRAMING, 0x0f,
                              (const uint8_t[]){1}, 1, ready, sizeof(ready),
                              &ready_size) == RNC_OK);
  CHECK(write(master, ready, ready_size) == (ssize_t)ready_size);
  for (i = 0; i < 5; ++i) {
    CHECK(rnc_host_step(host, 0, 1700000001, 11000 + 100u * i) == RNC_OK);
    count = tnc_read(master, &parser, frames, count, 16);
  }
  CHECK(count == 7 && frames[6].command == 0 && frames[6].size == 6 &&
        !memcmp(frames[6].data, "N0CALL", 6)); /* station ID after 10 s */
  rnc_host_free(host);
  rnc_node_free(node);
  close(master);
  puts("host KISS tests passed");
}
typedef struct host_journal {
  unsigned count;
  int level[16];
  char text[16][160];
} host_journal;
static void host_record(void *context, int level, const char *module,
                        const char *message) {
  host_journal *j = context;
  if (j->count < 16) {
    j->level[j->count] = level;
    snprintf(j->text[j->count], sizeof(j->text[0]), "%s: %s", module, message);
  }
  j->count++;
}
/* interface lifecycle shows up in the log */
static void log_test(void) {
  uint8_t key[64] = {0};
  unsigned rng = 0, i;
  host_journal j = {0};
  rnc_identity id;
  rnc_node *node;
  rnc_host *host;
  rnc_host_config cfg = {0};
  int up = -1, down = -1;
  CHECK(rnc_identity_from_private(&id, key) == RNC_OK);
  node = rnc_node_new(&id, 0, random_bytes, &rng);
  host = rnc_host_new(node);
  CHECK(node && host);
  rnc_log_set_handler(host_record, &j);
  rnc_log_set_level(RNC_LOG_INFO);
  cfg.kind = RNC_HOST_UDP;
  cfg.name = "Log Probe";
  cfg.address = "127.0.0.1";
  CHECK(rnc_host_add(host, 1, &cfg) == RNC_OK);
  CHECK(rnc_host_remove(host, 1) == RNC_OK);
  for (i = 0; i < j.count && i < 16; ++i) {
    if (strstr(j.text[i], "host:") && strstr(j.text[i], "Log Probe") &&
        strstr(j.text[i], " up"))
      up = j.level[i];
    if (strstr(j.text[i], "host:") && strstr(j.text[i], "Log Probe") &&
        strstr(j.text[i], " down"))
      down = j.level[i];
  }
  CHECK(up == RNC_LOG_INFO && down == RNC_LOG_INFO);
  rnc_log_set_handler(NULL, NULL);
  rnc_log_set_level(RNC_LOG_NOTICE);
  rnc_host_free(host);
  rnc_node_free(node);
  puts("host log tests passed");
}
/* A TCP client announces a tunnel when it connects; the server's node learns it. */
static void tunnel_test(void) {
  uint8_t key_a[64] = {1}, key_b[64] = {2};
  unsigned ra = 0, rb = 0, i;
  rnc_identity ia, ib;
  rnc_node *a, *b;
  rnc_host *ah, *bh;
  rnc_host_config cfg = {0};
  rnc_host_status st;
  rnc_tunnel_info t;
  uint8_t material[96], expected[32];
  CHECK(rnc_identity_from_private(&ia, key_a) == RNC_OK);
  CHECK(rnc_identity_from_private(&ib, key_b) == RNC_OK);
  a = rnc_node_new(&ia, 1, random_bytes, &ra);
  b = rnc_node_new(&ib, 0, random_bytes, &rb);
  ah = rnc_host_new(a);
  bh = rnc_host_new(b);
  CHECK(a && b && ah && bh);
  cfg.kind = RNC_HOST_TCP_LISTEN;
  cfg.address = "127.0.0.1";
  CHECK(rnc_host_add(ah, 1, &cfg) == RNC_OK);
  CHECK(rnc_host_get_status(ah, 1, &st) == RNC_OK && st.bound_port);
  cfg.kind = RNC_HOST_TCP_CONNECT;
  cfg.port = st.bound_port;
  CHECK(rnc_host_add(bh, 2, &cfg) == RNC_OK);
  CHECK(rnc_host_get_status(bh, 2, &st) == RNC_OK);
  memcpy(material, ib.public_key, 64);
  memcpy(material + 64, st.hash, 32); /* the interface hash is its name hash */
  CHECK(rnc_hash(material, 96, expected) == RNC_OK);
  for (i = 0; i < 500 && !rnc_node_tunnel_count(a); ++i) {
    rnc_host_event e;
    CHECK(rnc_host_step(ah, 0, 1700000000, 100 + i) == RNC_OK);
    CHECK(rnc_host_step(bh, 1, 1700000000, 100 + i) == RNC_OK);
    while (rnc_host_poll(ah, &e) == RNC_OK) {
    }
    while (rnc_host_poll(bh, &e) == RNC_OK) {
    }
  }
  CHECK(rnc_node_tunnel_count(a) == 1);
  CHECK(rnc_node_tunnel_at(a, 0, &t) == RNC_OK && !memcmp(t.id, expected, 32));
  rnc_host_free(ah);
  rnc_host_free(bh);
  rnc_node_free(a);
  rnc_node_free(b);
  puts("host tunnel tests passed");
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
  else if (!strcmp(argv[1], "rnode_detect"))
    rnode_detect_test();
  else if (!strcmp(argv[1], "rnode_signal"))
    rnode_signal_test();
  else if (!strcmp(argv[1], "rnode_extras"))
    radio_extras_test();
  else if (!strcmp(argv[1], "pipe"))
    pipe_test();
  else if (!strcmp(argv[1], "ax25"))
    ax25_test();
  else if (!strcmp(argv[1], "fast_flap"))
    fast_flap_test();
  else if (!strcmp(argv[1], "connect_late_clock"))
    connect_late_clock_test();
  else if (!strcmp(argv[1], "await_path"))
    await_path_test();
  else if (!strcmp(argv[1], "identity_files"))
    identity_files();
  else if (!strcmp(argv[1], "no_output"))
    no_output_test();
  else if (!strcmp(argv[1], "tcp_options"))
    tcp_options_test();
  else if (!strcmp(argv[1], "serial_params"))
    serial_params_test();
  else if (!strcmp(argv[1], "kiss"))
    kiss_test();
  else if (!strcmp(argv[1], "log"))
    log_test();
  else if (!strcmp(argv[1], "tunnel"))
    tunnel_test();
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
