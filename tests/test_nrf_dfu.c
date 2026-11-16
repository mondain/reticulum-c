/* reticulum-c-flash --nrf-dfu against an emulated Adafruit nRF52 serial DFU bootloader on a pseudo terminal.
 * The emulator checks what the tool sends the way the bootloader does (header checksum, CRC16, sequence
 * number, the order start / init / data / stop), acknowledges each packet with the next sequence number,
 * answers a repeated packet with the acknowledgement but does not write it twice, and rebuilds the image
 * so the test can compare it with the package. Nothing here touches a real board. */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1 /* cfmakeraw */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1 /* mkdtemp, cfmakeraw */
#endif
#include "../examples/nrf_dfu.h"
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x)                                                                                                       \
  do {                                                                                                                 \
    if (!(x)) {                                                                                                        \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                                                          \
      exit(1);                                                                                                         \
    }                                                                                                                  \
  } while (0)

static int master;
static uint8_t image[8192], init_seen[64];
static size_t image_size, init_size, expected_size;
static unsigned packets, duplicates, state; /* 0 start, 1 init, 2 data, 3 stopped */
static int last_seq = -1, drop_ack_of_packet, dropped, silent, bad_packets;

static void send_frame(const uint8_t *data, size_t n) {
  uint8_t out[64];
  size_t o = 0, i;
  out[o++] = 0xc0;
  for (i = 0; i < n; ++i)
    out[o++] = data[i]; /* acknowledgements have no byte that needs escaping */
  out[o++] = 0xc0;
  CHECK(write(master, out, o) == (ssize_t)o);
}
/* The bootloader's pure acknowledgement: header only, the acknowledged number in the ack field. */
static void acknowledge(unsigned ack) {
  uint8_t h[4];
  h[0] = (uint8_t)(ack << 3);
  h[1] = 0;
  h[2] = 0;
  h[3] = (uint8_t)(-(h[0] + h[1] + h[2]));
  send_frame(h, 4);
}
static void handle(const uint8_t *p, size_t n) {
  size_t length;
  unsigned seq, ack;
  uint32_t word;
  const uint8_t *payload;
  CHECK(n >= 6);
  CHECK((uint8_t)(p[0] + p[1] + p[2] + p[3]) == 0);                  /* header checksum */
  CHECK((p[0] & 0xc0) == 0xc0);                                      /* reliable, with a CRC */
  length = (size_t)(p[1] >> 4) | ((size_t)p[2] << 4);
  CHECK((p[1] & 15) == 14);                                          /* DFU payload type */
  CHECK(n == 4 + length + 2);
  CHECK(dfu_crc16(p, n - 2, 0xffff) == (uint16_t)(p[n - 2] | (p[n - 1] << 8)));
  seq = p[0] & 7u;
  ack = (p[0] >> 3) & 7u;
  CHECK(ack == ((seq + 1) & 7u));
  payload = p + 4;
  ++packets;
  if (silent)
    return;
  if (last_seq == (int)seq) { /* a packet sent again: acknowledge it, write nothing */
    ++duplicates;
    acknowledge((seq + 1) & 7u);
    return;
  }
  CHECK(last_seq < 0 || (int)seq == (last_seq + 1) % 8); /* sequence numbers advance by one */
  CHECK(length >= 4);
  word = dfu_le32(payload);
  switch (state) {
  case 0: /* START: type, application mode, no SoftDevice, no bootloader, application size */
    CHECK(word == DFU_START_PACKET && length == 20 && dfu_le32(payload + 4) == DFU_MODE_APPLICATION);
    CHECK(dfu_le32(payload + 8) == 0 && dfu_le32(payload + 12) == 0);
    expected_size = dfu_le32(payload + 16);
    state = 1;
    break;
  case 1: /* INIT: the init packet then two zero bytes */
    CHECK(word == DFU_INIT_PACKET && length >= 6 && length - 6 <= sizeof(init_seen));
    CHECK(payload[length - 1] == 0 && payload[length - 2] == 0);
    init_size = length - 6;
    memcpy(init_seen, payload + 4, init_size);
    state = 2;
    break;
  case 2:
    if (word == DFU_DATA_PACKET) {
      CHECK(length >= 5 && length - 4 <= DFU_CHUNK && image_size + length - 4 <= sizeof(image));
      memcpy(image + image_size, payload + 4, length - 4);
      image_size += length - 4;
    } else {
      CHECK(word == DFU_STOP_DATA_PACKET && length == 4 && image_size == expected_size);
      state = 3;
    }
    break;
  default:
    CHECK(0);
  }
  last_seq = (int)seq;
  if (drop_ack_of_packet && packets == (unsigned)drop_ack_of_packet && !dropped) {
    dropped = 1; /* the acknowledgement is lost; the tool must send the packet again */
    return;
  }
  acknowledge((seq + 1) & 7u);
}
static int serve(pid_t child, unsigned seconds) {
  uint8_t frame[4200];
  size_t n = 0;
  int in = 0, esc = 0, status;
  time_t end = time(NULL) + (time_t)seconds;
  time_t quiet_since = time(NULL);
  for (;;) {
    struct pollfd p = {master, POLLIN, 0};
    pid_t r = child > 0 ? waitpid(child, &status, WNOHANG) : 0;
    if (r == child && child > 0)
      return WIFEXITED(status) ? WEXITSTATUS(status) : 255;
    /* child == 0: serve a client we did not start (--serve) until the image is complete and it goes quiet */
    if (child == 0 && state == 3 && time(NULL) - quiet_since > 2)
      return 0;
    CHECK(time(NULL) < end);
    if (poll(&p, 1, 50) > 0 && (p.revents & POLLIN)) {
      uint8_t c;
      while (read(master, &c, 1) == 1) {
        quiet_since = time(NULL);
        if (c == 0xc0) {
          if (in && n)
            handle(frame, n);
          in = 1;
          n = 0;
          esc = 0;
        } else if (in) {
          if (esc) {
            CHECK(c == 0xdc || c == 0xdd);
            c = c == 0xdc ? 0xc0 : 0xdb;
            esc = 0;
          } else if (c == 0xdb) {
            esc = 1;
            continue;
          }
          CHECK(n < sizeof(frame));
          frame[n++] = c;
        }
      }
    }
  }
}
static void reset_state(void) {
  image_size = init_size = expected_size = 0;
  packets = duplicates = state = 0;
  last_seq = -1;
  drop_ack_of_packet = dropped = silent = bad_packets = 0;
  memset(image, 0, sizeof(image));
}

/* ---- a stored zip, built by hand ------------------------------------------ */
static void le16(uint8_t *p, unsigned v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
}
static void le32(uint8_t *p, uint32_t v) {
  le16(p, v & 0xffff);
  le16(p + 2, v >> 16);
}
typedef struct zname {
  const char *name;
  const uint8_t *data;
  size_t size;
  unsigned method;
  int bad_crc;
} zname;
static size_t make_zip(uint8_t *out, const zname *files, size_t count) {
  size_t o = 0, central, i;
  size_t offsets[8];
  for (i = 0; i < count; ++i) {
    size_t nl = strlen(files[i].name);
    offsets[i] = o;
    le32(out + o, 0x04034b50u);
    le16(out + o + 4, 20);
    le16(out + o + 6, 0);
    le16(out + o + 8, files[i].method);
    le16(out + o + 10, 0);
    le16(out + o + 12, 0x21);
    le32(out + o + 14, dfu_crc32(files[i].data, files[i].size) ^ (files[i].bad_crc ? 1u : 0u));
    le32(out + o + 18, (uint32_t)files[i].size);
    le32(out + o + 22, (uint32_t)files[i].size);
    le16(out + o + 26, (unsigned)nl);
    le16(out + o + 28, 0);
    memcpy(out + o + 30, files[i].name, nl);
    memcpy(out + o + 30 + nl, files[i].data, files[i].size);
    o += 30 + nl + files[i].size;
  }
  central = o;
  for (i = 0; i < count; ++i) {
    size_t nl = strlen(files[i].name);
    le32(out + o, 0x02014b50u);
    le16(out + o + 4, 20);
    le16(out + o + 6, 20);
    le16(out + o + 8, 0);
    le16(out + o + 10, files[i].method);
    le16(out + o + 12, 0);
    le16(out + o + 14, 0x21);
    le32(out + o + 16, dfu_crc32(files[i].data, files[i].size) ^ (files[i].bad_crc ? 1u : 0u));
    le32(out + o + 20, (uint32_t)files[i].size);
    le32(out + o + 24, (uint32_t)files[i].size);
    le16(out + o + 28, (unsigned)nl);
    memset(out + o + 30, 0, 12);
    le32(out + o + 42, (uint32_t)offsets[i]);
    memcpy(out + o + 46, files[i].name, nl);
    o += 46 + nl;
  }
  le32(out + o, 0x06054b50u);
  memset(out + o + 4, 0, 4);
  le16(out + o + 8, (unsigned)count);
  le16(out + o + 10, (unsigned)count);
  le32(out + o + 12, (uint32_t)(o - central));
  le32(out + o + 16, (uint32_t)central);
  le16(out + o + 20, 0);
  return o + 22;
}
static void write_file(const char *path, const uint8_t *data, size_t n) {
  FILE *f = fopen(path, "wb");
  CHECK(f && fwrite(data, 1, n, f) == n && !fclose(f));
}
static int run_tool(const char *tool, const char *slave, const char *zip) {
  char *argv[8];
  pid_t child;
  argv[0] = (char *)tool;
  argv[1] = "--port";
  argv[2] = (char *)slave;
  argv[3] = "--nrf-dfu";
  argv[4] = (char *)zip;
  argv[5] = NULL;
  child = fork();
  CHECK(child >= 0);
  if (!child) {
    int null = open("/dev/null", O_WRONLY);
    dup2(null, 1);
    dup2(null, 2);
    execv(tool, argv);
    _exit(127);
  }
  return serve(child, 60);
}
static const char *manifest_ok =
    "{\"manifest\": {\"application\": {\"bin_file\": \"firmware.bin\", \"dat_file\": \"firmware.dat\", "
    "\"init_packet_data\": {\"device_type\": 82, \"softdevice_req\": [182]}}, \"dfu_version\": 0.5}}";

int main(int argc, char **argv) {
  char dir[] = "/tmp/rnc-nrfdfu-XXXXXX", zip_path[300], *slave;
  uint8_t firmware[1300], dat[14], zip[8192];
  size_t i, zip_size;
  zname files[3];
  CHECK(argc == 2);
  CHECK(mkdtemp(dir));
  if (!strcmp(argv[1], "--serve")) { /* by hand: let a real tool (adafruit-nrfutil) flash this bootloader */
    char path[300];
    master = posix_openpt(O_RDWR | O_NOCTTY);
    CHECK(master >= 0 && grantpt(master) == 0 && unlockpt(master) == 0);
    {
      int s = open(ptsname(master), O_RDWR | O_NOCTTY);
      struct termios t;
      CHECK(s >= 0 && tcgetattr(s, &t) == 0);
      cfmakeraw(&t);
      CHECK(tcsetattr(s, TCSANOW, &t) == 0);
    }
    fcntl(master, F_SETFL, O_NONBLOCK);
    snprintf(path, sizeof(path), "%s", ptsname(master));
    printf("%s\n", path);
    fflush(stdout);
    reset_state();
    CHECK(serve(0, 300) == 0);
    printf("image %zu bytes, init %zu bytes, %u packets, %u repeats\n", image_size, init_size, packets, duplicates);
    return 0;
  }
  snprintf(zip_path, sizeof(zip_path), "%s/dfu.zip", dir);
  master = posix_openpt(O_RDWR | O_NOCTTY);
  CHECK(master >= 0 && grantpt(master) == 0 && unlockpt(master) == 0);
  slave = ptsname(master);
  CHECK(slave);
  {
    struct termios t;
    int s = open(slave, O_RDWR | O_NOCTTY); /* keep a slave open so the master never sees a hangup */
    CHECK(s >= 0 && tcgetattr(s, &t) == 0);
    cfmakeraw(&t);
    CHECK(tcsetattr(s, TCSANOW, &t) == 0);
  }
  fcntl(master, F_SETFL, O_NONBLOCK);
  for (i = 0; i < sizeof(firmware); ++i)
    firmware[i] = (uint8_t)(i * 5u + (i >> 7));
  firmware[3] = 0xc0; /* bytes that SLIP must escape, in the image and in the CRC range */
  firmware[4] = 0xdb;
  firmware[600] = 0xc0;
  for (i = 0; i < sizeof(dat); ++i)
    dat[i] = (uint8_t)(0xff - i);
  files[0] = (zname){"firmware.dat", dat, sizeof(dat), 0, 0};
  files[1] = (zname){"manifest.json", (const uint8_t *)manifest_ok, strlen(manifest_ok), 0, 0};
  files[2] = (zname){"firmware.bin", firmware, sizeof(firmware), 0, 0};

  /* the CRC16 and the frame, against the values the upstream adafruit-nrfutil produces (its calc_crc16 and
   * HciPacket, run on 2026-11-16 with sequence number 3): the escaped bytes, the header checksum, the CRC */
  {
    static const uint8_t expected[] = {0xc0, 0xe3, 0x4e, 0x00, 0xcf, 0xdb, 0xdc, 0xdb, 0xdd,
                                       0x01, 0x02, 0xe5, 0x05, 0xc0};
    uint8_t probe[4] = {0xc0, 0xdb, 0x01, 0x02}, out[64], plain[16] = {0};
    size_t n = dfu_frame(probe, sizeof(probe), 3, out);
    CHECK(dfu_crc16((const uint8_t *)"123456789", 9, 0xffff) == 0x29b1);
    CHECK(dfu_crc16(probe, sizeof(probe), 0xffff) == 0xb172);
    CHECK(n == sizeof(expected) && !memcmp(out, expected, n));
    CHECK(dfu_frame(plain, DFU_MAX_PAYLOAD + 1, 1, out) == 0);
  }

  /* a good package: the image and the init packet arrive intact, in order */
  reset_state();
  zip_size = make_zip(zip, files, 3);
  write_file(zip_path, zip, zip_size);
  CHECK(run_tool(argv[1], slave, zip_path) == 0);
  CHECK(state == 3 && image_size == sizeof(firmware) && !memcmp(image, firmware, sizeof(firmware)));
  CHECK(init_size == sizeof(dat) && !memcmp(init_seen, dat, sizeof(dat)));
  CHECK(packets == 1 + 1 + 3 + 1 && duplicates == 0); /* start, init, 3 chunks (512+512+276), stop */

  /* a lost acknowledgement: the packet is sent again, answered, and not written twice */
  reset_state();
  drop_ack_of_packet = 3; /* the first data chunk */
  CHECK(run_tool(argv[1], slave, zip_path) == 0);
  CHECK(dropped && duplicates == 1 && state == 3 && image_size == sizeof(firmware) &&
        !memcmp(image, firmware, sizeof(firmware)));

  /* a bootloader that never answers: the tool gives up and fails */
  reset_state();
  silent = 1;
  CHECK(run_tool(argv[1], slave, zip_path) != 0);

  /* packages that are refused before a single byte is sent */
  {
    zname bad[4];
    static const char *with_bootloader =
        "{\"manifest\": {\"bootloader\": {\"bin_file\": \"firmware.bin\", \"dat_file\": \"firmware.dat\"}, "
        "\"application\": {\"bin_file\": \"firmware.bin\", \"dat_file\": \"firmware.dat\"}, \"dfu_version\": 0.5}}";
    static const char *missing_file =
        "{\"manifest\": {\"application\": {\"bin_file\": \"other.bin\", \"dat_file\": \"firmware.dat\"}}}";
    memcpy(bad, files, sizeof(files));
    bad[1].data = (const uint8_t *)with_bootloader;
    bad[1].size = strlen(with_bootloader);
    reset_state();
    write_file(zip_path, zip, make_zip(zip, bad, 3));
    CHECK(run_tool(argv[1], slave, zip_path) != 0 && packets == 0); /* a bootloader section */
    memcpy(bad, files, sizeof(files));
    bad[1].data = (const uint8_t *)missing_file;
    bad[1].size = strlen(missing_file);
    write_file(zip_path, zip, make_zip(zip, bad, 3));
    CHECK(run_tool(argv[1], slave, zip_path) != 0 && packets == 0); /* the manifest names a missing file */
    memcpy(bad, files, sizeof(files));
    bad[2].method = 8; /* claims to be deflated */
    write_file(zip_path, zip, make_zip(zip, bad, 3));
    CHECK(run_tool(argv[1], slave, zip_path) != 0 && packets == 0);
    memcpy(bad, files, sizeof(files));
    bad[2].bad_crc = 1; /* a damaged entry */
    write_file(zip_path, zip, make_zip(zip, bad, 3));
    CHECK(run_tool(argv[1], slave, zip_path) != 0 && packets == 0);
    write_file(zip_path, zip, make_zip(zip, files, 2)); /* only two entries */
    CHECK(run_tool(argv[1], slave, zip_path) != 0 && packets == 0);
    write_file(zip_path, (const uint8_t *)"not a zip at all", 16);
    CHECK(run_tool(argv[1], slave, zip_path) != 0 && packets == 0);
    CHECK(run_tool(argv[1], slave, "/nonexistent/dfu.zip") != 0 && packets == 0);
  }
  unlink(zip_path);
  rmdir(dir);
  puts("nrf dfu tool tests passed");
  return 0;
}
