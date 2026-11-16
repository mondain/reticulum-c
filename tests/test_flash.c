/* reticulum-c-flash against an emulated ESP ROM loader on a pseudo terminal. The emulator answers the way
 * the ROM loader does (SLIP frames, status bytes after the data, XOR checksums, an 8 MB flash that reads 0xff
 * until written) and checks what the tool sends: SYNC first, the SPI setup, FLASH_BEGIN with the right size
 * and offset, blocks in sequence with correct checksums, the MD5 request. Nothing here touches a real chip. */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1 /* cfmakeraw */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1 /* mkdtemp, cfmakeraw */
#endif
#include <fcntl.h>
#include <openssl/evp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#define FLASH_BYTES (8u << 20)
static uint8_t *flash;
static int master;
static unsigned syncs, blocks_seen, bad_checksums, md5_requests, begins;
static int corrupt_write, refuse_first_block, refuse_all, silent;
static uint32_t begin_offset, begin_blocks, next_seq;
static int refused;

static uint32_t get32(const uint8_t *p) {
  return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static void put32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}
static void send_frame(const uint8_t *data, size_t n) {
  uint8_t out[4096];
  size_t o = 0, i;
  out[o++] = 0xc0;
  for (i = 0; i < n; ++i) {
    if (data[i] == 0xc0) {
      out[o++] = 0xdb;
      out[o++] = 0xdc;
    } else if (data[i] == 0xdb) {
      out[o++] = 0xdb;
      out[o++] = 0xdd;
    } else
      out[o++] = data[i];
  }
  out[o++] = 0xc0;
  CHECK(write(master, out, o) == (ssize_t)o);
}
/* ROM loader responses: direction 1, opcode, data size, value, then data followed by FOUR status bytes
 * (status, error, 0, 0), as an ESP32-S3 sends them (seen on hardware; the RAM stub sends two). */
static void respond(uint8_t op, uint32_t value, const uint8_t *data, size_t n, uint8_t status, uint8_t error) {
  uint8_t out[256];
  CHECK(n + 12 <= sizeof(out));
  out[0] = 1;
  out[1] = op;
  out[2] = (uint8_t)(n + 4);
  out[3] = (uint8_t)((n + 4) >> 8);
  put32(out + 4, value);
  if (n)
    memcpy(out + 8, data, n);
  out[8 + n] = status;
  out[9 + n] = error;
  out[10 + n] = 0;
  out[11 + n] = 0;
  send_frame(out, n + 12);
}
static void handle(const uint8_t *pkt, size_t n) {
  uint8_t op, d[16];
  uint32_t size, chk;
  const uint8_t *data;
  CHECK(n >= 8 && pkt[0] == 0);
  op = pkt[1];
  size = (uint32_t)pkt[2] | (uint32_t)pkt[3] << 8;
  chk = get32(pkt + 4);
  data = pkt + 8;
  CHECK(n == 8 + size);
  if (silent)
    return;
  switch (op) {
  case 0x08: /* SYNC */
    CHECK(size == 36 && data[0] == 0x07 && data[1] == 0x07 && data[2] == 0x12 && data[3] == 0x20 && data[4] == 0x55);
    ++syncs;
    respond(op, 0x7c3f55aa, NULL, 0, 0, 0);
    break;
  case 0x0d: /* SPI_ATTACH */
    CHECK(syncs && size == 8);
    respond(op, 0, NULL, 0, 0, 0);
    break;
  case 0x0b: /* SPI_SET_PARAMS */
    CHECK(size == 24 && get32(data + 4) == FLASH_BYTES);
    respond(op, 0, NULL, 0, 0, 0);
    break;
  case 0x02: /* FLASH_BEGIN: erase size, blocks, block size, offset, encrypted flag */
    CHECK(size == 20 && get32(data + 8) == 0x400 && get32(data + 16) == 0);
    CHECK(get32(data) == get32(data + 4) * 0x400 || get32(data) <= get32(data + 4) * 0x400);
    begin_blocks = get32(data + 4);
    begin_offset = get32(data + 12);
    CHECK(begin_offset + begin_blocks * 0x400 <= FLASH_BYTES);
    next_seq = 0;
    ++begins;
    respond(op, 0, NULL, 0, 0, 0);
    break;
  case 0x03: { /* FLASH_DATA: length, sequence, 0, 0, then the block */
    uint32_t len = get32(data), seq = get32(data + 4), x = 0;
    size_t i;
    CHECK(size == 16 + len && len == 0x400 && get32(data + 8) == 0 && get32(data + 12) == 0);
    for (i = 0; i < len; ++i)
      x ^= data[16 + i];
    if ((x ^ 0xef) != chk) {
      ++bad_checksums;
      respond(op, 0, NULL, 0, 1, 0x07);
      break;
    }
    if (refuse_all) { /* a permanent failure: the tool must stop and say so */
      respond(op, 0, NULL, 0, 1, 0x09);
      break;
    }
    if (refuse_first_block && !refused) { /* a transient failure the tool must retry */
      refused = 1;
      respond(op, 0, NULL, 0, 1, 0x05);
      break;
    }
    CHECK(seq == next_seq && seq < begin_blocks);
    memcpy(flash + begin_offset + (size_t)seq * 0x400, data + 16, len);
    if (corrupt_write && seq == 0)
      flash[begin_offset] ^= 1;
    ++next_seq;
    ++blocks_seen;
    respond(op, 0, NULL, 0, 0, 0);
    break;
  }
  case 0x04: /* FLASH_END */
    CHECK(size == 4);
    respond(op, 0, NULL, 0, 0, 0);
    break;
  case 0x13: { /* SPI_FLASH_MD5: the digest as 32 hex characters, then status */
    uint32_t addr = get32(data), len = get32(data + 4);
    uint8_t digest[16];
    unsigned dl = 0, i;
    char hex[33];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    CHECK(size == 16 && addr + len <= FLASH_BYTES);
    CHECK(ctx && EVP_DigestInit_ex(ctx, EVP_md5(), NULL) == 1 && EVP_DigestUpdate(ctx, flash + addr, len) == 1 &&
          EVP_DigestFinal_ex(ctx, digest, &dl) == 1);
    EVP_MD_CTX_free(ctx);
    for (i = 0; i < 16; ++i)
      snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    ++md5_requests;
    memcpy(d, hex, 0);
    {
      uint8_t out[64];
      memcpy(out, hex, 32);
      respond(op, 0, out, 32, 0, 0);
    }
    break;
  }
  default:
    respond(op, 0, NULL, 0, 1, 0x05);
  }
}
/* Serves the tool until it exits; returns its exit status. */
static int serve(pid_t child, unsigned seconds) {
  uint8_t frame[4096];
  size_t n = 0;
  int in = 0, esc = 0, status;
  time_t end = time(NULL) + (time_t)seconds;
  for (;;) {
    struct pollfd p = {master, POLLIN, 0};
    pid_t r = waitpid(child, &status, WNOHANG);
    if (r == child)
      return WIFEXITED(status) ? WEXITSTATUS(status) : 255;
    CHECK(time(NULL) < end);
    if (poll(&p, 1, 50) > 0 && (p.revents & POLLIN)) {
      uint8_t c;
      while (read(master, &c, 1) == 1) {
        if (c == 0xc0) {
          if (in && n)
            handle(frame, n);
          in = 1;
          n = 0;
          esc = 0;
        } else if (in) {
          if (esc) {
            c = c == 0xdc ? 0xc0 : c == 0xdd ? 0xdb : c;
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
static void write_file(const char *path, const uint8_t *data, size_t n) {
  FILE *f = fopen(path, "wb");
  CHECK(f && fwrite(data, 1, n, f) == n && !fclose(f));
}
static int run_tool(const char *tool, char *const extra[], const char *slave) {
  char *argv[24];
  size_t k = 0, i;
  pid_t child;
  argv[k++] = (char *)tool;
  argv[k++] = "--port";
  argv[k++] = (char *)slave;
  argv[k++] = "--flash-size";
  argv[k++] = "8MB";
  argv[k++] = "--no-usb";
  for (i = 0; extra[i] && k < 22; ++i)
    argv[k++] = extra[i];
  argv[k] = NULL;
  child = fork();
  CHECK(child >= 0);
  if (!child) {
    int null = open("/dev/null", O_WRONLY);
    dup2(null, 1);
    execv(tool, argv);
    _exit(127);
  }
  return serve(child, 60);
}
static void reset_counts(void) {
  syncs = blocks_seen = bad_checksums = md5_requests = begins = 0;
  corrupt_write = refuse_first_block = refuse_all = silent = refused = 0;
  memset(flash, 0xff, FLASH_BYTES);
}
int main(int argc, char **argv) {
  char dir[] = "/tmp/rnc-flash-XXXXXX", a[300], b[300], *slave;
  uint8_t img_a[3000], img_b[1500];
  size_t i;
  CHECK(argc == 2);
  flash = malloc(FLASH_BYTES);
  CHECK(flash && mkdtemp(dir));
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
  for (i = 0; i < sizeof(img_a); ++i)
    img_a[i] = (uint8_t)(i * 7u + (i >> 8)); /* includes 0xc0 and 0xdb bytes, which SLIP must escape */
  for (i = 0; i < sizeof(img_b); ++i)
    img_b[i] = (uint8_t)(255u - i);
  img_a[10] = 0xc0;
  img_a[11] = 0xdb;
  snprintf(a, sizeof(a), "%s/a.bin", dir);
  snprintf(b, sizeof(b), "%s/b.bin", dir);
  write_file(a, img_a, sizeof(img_a));
  write_file(b, img_b, sizeof(img_b));

  /* two images at two offsets: both land, with the tail of each padded by erased flash */
  reset_counts();
  {
    char *args[] = {"0x0", a, "0x10000", b, NULL};
    CHECK(run_tool(argv[1], args, slave) == 0);
  }
  CHECK(syncs >= 1 && begins == 2 && bad_checksums == 0 && md5_requests == 2);
  CHECK(blocks_seen == 3 + 2); /* 3000 bytes = 3 blocks, 1500 bytes = 2 */
  CHECK(!memcmp(flash, img_a, sizeof(img_a)) && !memcmp(flash + 0x10000, img_b, sizeof(img_b)));
  CHECK(flash[3000] == 0xff && flash[0x10000 + 1500] == 0xff && flash[0xffff] == 0xff);

  /* a block the loader refuses once is sent again */
  reset_counts();
  refuse_first_block = 1;
  {
    char *args[] = {"0x20000", b, NULL};
    CHECK(run_tool(argv[1], args, slave) == 0);
  }
  CHECK(refused && !memcmp(flash + 0x20000, img_b, sizeof(img_b)));

  /* a block the loader always refuses ends the run with an error and no MD5 request */
  reset_counts();
  refuse_all = 1;
  {
    char *args[] = {"0x0", b, NULL};
    CHECK(run_tool(argv[1], args, slave) != 0);
  }
  CHECK(blocks_seen == 0 && md5_requests == 0);

  /* flash that does not read back as written fails the MD5 check and the tool says so */
  reset_counts();
  corrupt_write = 1;
  {
    char *args[] = {"0x0", b, NULL};
    CHECK(run_tool(argv[1], args, slave) != 0);
  }
  CHECK(md5_requests == 1);
  /* ... unless verification is switched off */
  reset_counts();
  corrupt_write = 1;
  {
    char *args[] = {"--no-verify", "0x0", b, NULL};
    CHECK(run_tool(argv[1], args, slave) == 0 && md5_requests == 0);
  }

  /* an image past the end of the flash is refused before anything is sent */
  reset_counts();
  {
    char *args[] = {"0x7fffff", b, NULL};
    CHECK(run_tool(argv[1], args, slave) != 0 && syncs == 0);
  }
  /* no loader answering: the tool gives up */
  reset_counts();
  silent = 1;
  {
    char *args[] = {"0x0", b, NULL};
    CHECK(run_tool(argv[1], args, slave) != 0);
  }
  /* --verify-only compares without writing: it passes on what was flashed and fails on anything else */
  reset_counts();
  {
    char *write_args[] = {"0x0", b, NULL};
    char *check_args[] = {"--verify-only", "0x0", b, NULL};
    char *other_args[] = {"--verify-only", "0x0", a, NULL};
    CHECK(run_tool(argv[1], write_args, slave) == 0);
    blocks_seen = begins = 0;
    CHECK(run_tool(argv[1], check_args, slave) == 0 && begins == 0 && blocks_seen == 0 && md5_requests == 2);
    CHECK(run_tool(argv[1], other_args, slave) != 0 && begins == 0);
  }
  /* --reset-only restarts the chip without talking to the loader */
  reset_counts();
  {
    char *args[] = {"--reset-only", NULL};
    CHECK(run_tool(argv[1], args, slave) == 0 && syncs == 0);
  }
  free(flash);
  unlink(a);
  unlink(b);
  rmdir(dir);
  puts("flash tool tests passed");
  return 0;
}
