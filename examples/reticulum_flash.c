/* reticulum-c-flash: write images to an ESP32-family board through the chip's ROM serial loader, the
 * way `esptool write_flash` does without its RAM stub.
 *
 *   reticulum-c-flash --port DEVICE [--flash-size 4MB] [--no-reset] [--no-verify] [-v]
 *                     OFFSET FILE [OFFSET FILE ...]
 *
 * It resets the chip into its download mode (the USB-Serial/JTAG reset sequence when the port is a
 * native USB one, which is what the ESP32-S3 boards here use, otherwise the usual DTR/RTS pair), syncs
 * with the loader, attaches the SPI flash, writes every file at its offset in 1 KiB blocks, checks the
 * result with the loader's MD5 command and resets the chip so it runs the new image. The protocol is
 * SLIP framed commands with an XOR checksum; the command numbers and layouts follow esptool's loader
 * (SYNC 0x08, SPI_SET_PARAMS 0x0B, SPI_ATTACH 0x0D, FLASH_BEGIN 0x02, FLASH_DATA 0x03, FLASH_END 0x04,
 * SPI_FLASH_MD5 0x13).
 *
 * This writes flash. A wrong offset overwrites whatever lives there; a merged image written at 0x0
 * replaces the bootloader, partition table, application and NVS (identity and settings). */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1 /* cfmakeraw */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define SLIP_END 0xc0
#define SLIP_ESC 0xdb
#define BLOCK 0x400u /* the ROM loader's write size */
#define CHECKSUM_MAGIC 0xef
enum { OP_FLASH_BEGIN = 0x02, OP_FLASH_DATA = 0x03, OP_FLASH_END = 0x04, OP_SYNC = 0x08, OP_SPI_SET_PARAMS = 0x0b,
       OP_SPI_ATTACH = 0x0d, OP_SPI_FLASH_MD5 = 0x13 };

static int verbose;
static int fd = -1;

static void sleep_ms(unsigned ms) {
  struct timespec t = {(time_t)(ms / 1000u), (long)(ms % 1000u) * 1000000L};
  nanosleep(&t, NULL);
}
static uint64_t now_ms(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
static void put32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}
static uint32_t get32(const uint8_t *p) {
  return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/* ---- the port ------------------------------------------------------------ */
static int open_port(const char *path) {
  struct termios t;
  fd = open(path, O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (fd < 0) {
    fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
    return 0;
  }
  if (tcgetattr(fd, &t) == 0) { /* a pty or a plain file need not accept this */
    cfmakeraw(&t);
    cfsetispeed(&t, B115200);
    cfsetospeed(&t, B115200);
    t.c_cflag |= CLOCAL | CREAD;
    t.c_cc[VMIN] = 0;
    t.c_cc[VTIME] = 0;
    (void)tcsetattr(fd, TCSANOW, &t);
  }
  return 1;
}
static void modem(int bit, int on) {
  int flag = bit;
  (void)ioctl(fd, on ? TIOCMBIS : TIOCMBIC, &flag); /* best effort: not every port has the lines */
}
static void set_dtr(int on) { modem(TIOCM_DTR, on); }
static void set_rts(int on) { modem(TIOCM_RTS, on); }
static int write_all(const uint8_t *data, size_t size) {
  size_t sent = 0;
  while (sent < size) {
    ssize_t n = write(fd, data + sent, size - sent);
    if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
      struct pollfd p = {fd, POLLOUT, 0};
      (void)poll(&p, 1, 100);
      continue;
    }
    if (n <= 0)
      return 0;
    sent += (size_t)n;
  }
  return 1;
}

/* ---- SLIP frames --------------------------------------------------------- */
/* One frame into out (at most cap bytes); returns its length, or -1 on timeout. Bytes outside frames are
 * ignored, which is what the chip's boot messages look like. */
static int read_frame(uint8_t *out, size_t cap, unsigned timeout_ms) {
  uint64_t end = now_ms() + timeout_ms;
  size_t n = 0;
  int in_frame = 0, escaped = 0;
  for (;;) {
    uint8_t c;
    uint64_t now = now_ms();
    struct pollfd p = {fd, POLLIN, 0};
    ssize_t got;
    if (now >= end)
      return -1;
    if (poll(&p, 1, (int)(end - now)) <= 0)
      return -1;
    got = read(fd, &c, 1);
    if (got <= 0)
      continue;
    if (c == SLIP_END) {
      if (in_frame && n)
        return (int)n;
      in_frame = 1;
      n = 0;
      escaped = 0;
      continue;
    }
    if (!in_frame)
      continue;
    if (escaped) {
      c = c == 0xdc ? SLIP_END : c == 0xdd ? SLIP_ESC : c;
      escaped = 0;
    } else if (c == SLIP_ESC) {
      escaped = 1;
      continue;
    }
    if (n < cap)
      out[n++] = c;
  }
}
static int write_frame(const uint8_t *packet, size_t size) {
  uint8_t *buf = malloc(size * 2 + 2);
  size_t n = 0, i;
  int ok;
  if (!buf)
    return 0;
  buf[n++] = SLIP_END;
  for (i = 0; i < size; ++i) {
    if (packet[i] == SLIP_END) {
      buf[n++] = SLIP_ESC;
      buf[n++] = 0xdc;
    } else if (packet[i] == SLIP_ESC) {
      buf[n++] = SLIP_ESC;
      buf[n++] = 0xdd;
    } else
      buf[n++] = packet[i];
  }
  buf[n++] = SLIP_END;
  ok = write_all(buf, n);
  free(buf);
  return ok;
}

/* ---- commands ------------------------------------------------------------ */
/* Sends a command and waits for its response: direction 1, same opcode. *value is the header's value field;
 * the response data (status bytes included) is copied to reply. Returns the data length or -1. */
static int command(uint8_t op, const uint8_t *data, size_t size, uint32_t checksum, unsigned timeout_ms,
                   uint32_t *value, uint8_t *reply, size_t reply_cap) {
  uint8_t *packet = malloc(8 + size), frame[2048];
  int tries;
  if (!packet)
    return -1;
  packet[0] = 0;
  packet[1] = op;
  packet[2] = (uint8_t)size;
  packet[3] = (uint8_t)(size >> 8);
  put32(packet + 4, checksum);
  if (size)
    memcpy(packet + 8, data, size);
  if (verbose)
    fprintf(stderr, "command 0x%02x, %zu bytes\n", op, size);
  if (!write_frame(packet, 8 + size)) {
    free(packet);
    return -1;
  }
  free(packet);
  for (tries = 0; tries < 100; ++tries) {
    int n = read_frame(frame, sizeof(frame), timeout_ms);
    size_t len;
    if (n < 0)
      return -1;
    if (n < 8 || frame[0] != 1 || frame[1] != op)
      continue;
    len = (size_t)n - 8;
    if (value)
      *value = get32(frame + 4);
    if (reply && len <= reply_cap)
      memcpy(reply, frame + 8, len);
    return (int)len;
  }
  return -1;
}
/* The ROM loader ends every response with four status bytes (status, error, two zeros); esptool's RAM stub
 * uses two, but this tool never loads the stub. Found on an ESP32-S3 on 2026-11-15: an MD5 answer was 32
 * characters plus these four. */
#define STATUS_BYTES 4
/* A command whose response must carry status 0 in the first status byte. Returns the number of payload bytes
 * before the status (copied to reply), or -1. */
static int check_command(const char *what, uint8_t op, const uint8_t *data, size_t size, uint32_t checksum,
                         unsigned timeout_ms, uint8_t *reply, size_t reply_cap) {
  uint8_t buf[256] = {0};
  int n = command(op, data, size, checksum, timeout_ms, NULL, buf, sizeof(buf));
  if (n > (int)sizeof(buf)) { /* command() copies nothing from a reply this long */
    fprintf(stderr, "Failed to %s: the loader's answer is too long (%d bytes)\n", what, n);
    return -1;
  }
  if (n < STATUS_BYTES) {
    fprintf(stderr, "Failed to %s: %s\n", what, n < 0 ? "no answer from the loader" : "a short answer");
    return -1;
  }
  if (buf[n - STATUS_BYTES] != 0) {
    fprintf(stderr, "Failed to %s: loader status 0x%02x, error 0x%02x\n", what, buf[n - STATUS_BYTES],
            buf[n - STATUS_BYTES + 1]);
    return -1;
  }
  if (reply && (size_t)(n - STATUS_BYTES) <= reply_cap)
    memcpy(reply, buf, (size_t)(n - STATUS_BYTES));
  return n - STATUS_BYTES;
}
static uint32_t checksum_of(const uint8_t *data, size_t size) {
  uint32_t s = CHECKSUM_MAGIC;
  size_t i;
  for (i = 0; i < size; ++i)
    s ^= data[i];
  return s;
}
static unsigned erase_timeout_ms(size_t bytes) {
  double seconds = 30.0 * (double)bytes / 1e6;
  return (unsigned)((seconds < 3.0 ? 3.0 : seconds) * 1000.0);
}

/* ---- entering the loader ------------------------------------------------- */
/* The USB-Serial/JTAG reset into download mode (esptool's USBJTAGSerialReset), or the classic pair. */
static void enter_bootloader(int usb) {
  if (usb) {
    set_rts(0);
    set_dtr(0);
    sleep_ms(100);
    set_dtr(1); /* IO0 low */
    set_rts(0);
    sleep_ms(100);
    set_rts(1); /* reset */
    set_dtr(0);
    set_rts(1);
    sleep_ms(100);
    set_dtr(0);
    set_rts(0); /* out of reset, into the loader */
  } else {
    set_dtr(0);
    set_rts(1);
    sleep_ms(100);
    set_dtr(1);
    set_rts(0);
    sleep_ms(350);
    set_dtr(0);
  }
}
static void hard_reset(int usb) {
  set_rts(1); /* EN low */
  sleep_ms(usb ? 200 : 100);
  set_rts(0);
  if (usb)
    sleep_ms(200);
}
static int sync_loader(void) {
  uint8_t data[36];
  int i;
  memset(data, 0x55, sizeof(data));
  data[0] = 0x07;
  data[1] = 0x07;
  data[2] = 0x12;
  data[3] = 0x20;
  for (i = 0; i < 10; ++i) {
    uint32_t value = 0;
    if (command(OP_SYNC, data, sizeof(data), 0, 100, &value, NULL, 0) >= 0) {
      /* the loader answers a SYNC several times; drain the extras so they are not taken for answers */
      uint8_t junk[64];
      while (read_frame(junk, sizeof(junk), 100) >= 0) {
      }
      return 1;
    }
  }
  return 0;
}

/* ---- writing ------------------------------------------------------------- */
static int write_image(uint32_t offset, const uint8_t *image, size_t size) {
  size_t blocks = (size + BLOCK - 1) / BLOCK, b;
  uint8_t begin[20], *packet = malloc(16 + BLOCK);
  if (!packet)
    return 0;
  put32(begin, (uint32_t)size);   /* erase size */
  put32(begin + 4, (uint32_t)blocks);
  put32(begin + 8, BLOCK);
  put32(begin + 12, offset);
  put32(begin + 16, 0); /* not an encrypted write */
  if (check_command("enter flash download mode", OP_FLASH_BEGIN, begin, sizeof(begin), 0, erase_timeout_ms(size),
                    NULL, 0) < 0) {
    free(packet);
    return 0;
  }
  for (b = 0; b < blocks; ++b) {
    size_t at = b * BLOCK, n = size - at < BLOCK ? size - at : BLOCK;
    uint8_t *payload = packet + 16;
    int attempt, ok = 0;
    memset(payload, 0xff, BLOCK); /* the last block is padded with erased flash */
    memcpy(payload, image + at, n);
    put32(packet, BLOCK);
    put32(packet + 4, (uint32_t)b);
    put32(packet + 8, 0);
    put32(packet + 12, 0);
    for (attempt = 0; attempt < 3 && !ok; ++attempt)
      ok = check_command("write a block", OP_FLASH_DATA, packet, 16 + BLOCK, checksum_of(payload, BLOCK), 3000,
                         NULL, 0) >= 0;
    if (!ok) {
      free(packet);
      return 0;
    }
    if (b % 64 == 0 || b + 1 == blocks) {
      printf("\r0x%06x: %3zu%%", offset, (b + 1) * 100 / blocks);
      fflush(stdout);
    }
  }
  free(packet);
  printf("\n");
  return 1;
}
static int verify_image(uint32_t offset, const uint8_t *image, size_t size) {
  uint8_t request[16], reply[64], digest[16];
  char want[33];
  unsigned dlen = 0, i;
  int n;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx || EVP_DigestInit_ex(ctx, EVP_md5(), NULL) != 1 || EVP_DigestUpdate(ctx, image, size) != 1 ||
      EVP_DigestFinal_ex(ctx, digest, &dlen) != 1) {
    EVP_MD_CTX_free(ctx);
    return 0;
  }
  EVP_MD_CTX_free(ctx);
  for (i = 0; i < 16; ++i)
    (void)snprintf(want + 2 * i, 3, "%02x", digest[i]);
  put32(request, offset);
  put32(request + 4, (uint32_t)size);
  put32(request + 8, 0);
  put32(request + 12, 0);
  n = check_command("calculate the MD5", OP_SPI_FLASH_MD5, request, sizeof(request), 0,
                    (unsigned)(8000.0 * (double)size / 1e6 + 3000.0), reply, sizeof(reply));
  if (verbose) {
    int k;
    fprintf(stderr, "MD5 reply: %d bytes:", n);
    for (k = 0; k < n && k < 40; ++k)
      fprintf(stderr, " %02x", reply[k]);
    fputc('\n', stderr);
  }
  if (n == 32 && !memcmp(reply, want, 32)) {
    printf("0x%06x: MD5 %s verified\n", offset, want);
    return 1;
  }
  if (n == 16 && !memcmp(reply, digest, 16)) {
    printf("0x%06x: MD5 %s verified\n", offset, want);
    return 1;
  }
  fprintf(stderr, "0x%06x: the flash does not match the image (expected MD5 %s)\n", offset, want);
  return 0;
}
static int read_file(const char *path, uint8_t **data, size_t *size) {
  FILE *f = fopen(path, "rb");
  long n;
  uint8_t *buf;
  if (!f)
    return 0;
  if (fseek(f, 0, SEEK_END) || (n = ftell(f)) <= 0 || fseek(f, 0, SEEK_SET)) {
    fclose(f);
    return 0;
  }
  buf = malloc((size_t)n + 4);
  if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) {
    free(buf);
    fclose(f);
    return 0;
  }
  fclose(f);
  *size = (size_t)n;
  while (*size % 4) /* the loader writes whole words */
    buf[(*size)++] = 0xff;
  *data = buf;
  return 1;
}
static int parse_size(const char *text, size_t *out) {
  char *end;
  unsigned long v = strtoul(text, &end, 10);
  if (end == text || (strcasecmp(end, "MB") && strcasecmp(end, "M")) || !v || v > 64)
    return 0;
  *out = (size_t)v << 20;
  return 1;
}
static void usage(void) {
  fputs("usage: reticulum-c-flash --port DEVICE [--flash-size 4MB] [--no-reset] [--no-verify] [--usb | --no-usb] "
        "[-v] OFFSET FILE [OFFSET FILE ...]\n"
        "       reticulum-c-flash --port DEVICE --verify-only [--flash-size 4MB] OFFSET FILE [...]\n"
        "       reticulum-c-flash --port DEVICE --reset-only\n"
        "  --usb / --no-usb: the port is the chip's native USB Serial/JTAG (default when the device name is\n"
        "  /dev/ttyACM*) or an external UART bridge\n",
        stderr);
}
int main(int argc, char **argv) {
  const char *port = NULL;
  struct {
    uint32_t offset;
    const char *path;
  } jobs[16];
  size_t job_count = 0, flash_size = 4u << 20, i;
  int no_reset = 0, no_verify = 0, usb = -1, rc = 1, attached = 0, k, reset_only = 0, verify_only = 0;
  uint32_t pending_offset = 0;
  int have_offset = 0;
  for (i = 1; i < (size_t)argc; ++i) {
    const char *a = argv[i];
    if ((!strcmp(a, "--port") || !strcmp(a, "-p")) && i + 1 < (size_t)argc)
      port = argv[++i];
    else if (!strcmp(a, "--flash-size") && i + 1 < (size_t)argc) {
      if (!parse_size(argv[++i], &flash_size))
        return usage(), 2;
    } else if (!strcmp(a, "--no-reset"))
      no_reset = 1;
    else if (!strcmp(a, "--reset-only"))
      reset_only = 1;
    else if (!strcmp(a, "--verify-only"))
      verify_only = 1;
    else if (!strcmp(a, "--no-verify"))
      no_verify = 1;
    else if (!strcmp(a, "--usb"))
      usb = 1;
    else if (!strcmp(a, "--no-usb"))
      usb = 0;
    else if (!strcmp(a, "-v"))
      verbose = 1;
    else if (a[0] != '-') {
      if (!have_offset) {
        char *end;
        unsigned long v = strtoul(a, &end, 0);
        if (*end || v > 0xffffffffu)
          return usage(), 2;
        pending_offset = (uint32_t)v;
        have_offset = 1;
      } else {
        if (job_count >= sizeof(jobs) / sizeof(*jobs))
          return usage(), 2;
        jobs[job_count].offset = pending_offset;
        jobs[job_count++].path = a;
        have_offset = 0;
      }
    } else
      return usage(), 2;
  }
  if (!port || have_offset || (reset_only ? job_count : !job_count))
    return usage(), 2;
  if (usb < 0)
    usb = strstr(port, "ttyACM") != NULL;
  if (reset_only) { /* restart the chip so it runs what is in flash */
    if (!open_port(port))
      return 1;
    hard_reset(usb);
    close(fd);
    return 0;
  }
  /* read every image before touching the chip */
  {
    uint8_t *images[16];
    size_t sizes[16];
    for (i = 0; i < job_count; ++i) {
      if (!read_file(jobs[i].path, &images[i], &sizes[i])) {
        fprintf(stderr, "Cannot read %s\n", jobs[i].path);
        return 1;
      }
      if ((size_t)jobs[i].offset + sizes[i] > flash_size) {
        fprintf(stderr, "%s does not fit: it ends at 0x%zx, past the %zu MB flash\n", jobs[i].path,
                (size_t)jobs[i].offset + sizes[i], flash_size >> 20);
        return 1;
      }
    }
    if (!open_port(port))
      return 1;
    for (k = 0; k < 5 && !attached; ++k) {
      enter_bootloader(usb);
      attached = sync_loader();
    }
    if (!attached) {
      fprintf(stderr, "The chip did not answer. Hold BOOT, tap RESET, release BOOT and try again.\n");
      goto done;
    }
    puts("Synced with the ROM loader");
    {
      uint8_t attach[8] = {0}, params[24];
      if (check_command("attach the SPI flash", OP_SPI_ATTACH, attach, sizeof(attach), 0, 3000, NULL, 0) < 0)
        goto done;
      put32(params, 0);                    /* flash id */
      put32(params + 4, (uint32_t)flash_size);
      put32(params + 8, 64u * 1024u);      /* block size */
      put32(params + 12, 4u * 1024u);      /* sector size */
      put32(params + 16, 256);             /* page size */
      put32(params + 20, 0xffff);          /* status mask */
      if (check_command("set the SPI flash parameters", OP_SPI_SET_PARAMS, params, sizeof(params), 0, 3000, NULL,
                        0) < 0)
        goto done;
    }
    for (i = 0; i < job_count; ++i) {
      if (verify_only)
        printf("Checking %s (%zu bytes) at 0x%x\n", jobs[i].path, sizes[i], jobs[i].offset);
      else {
        printf("Writing %s (%zu bytes) at 0x%x\n", jobs[i].path, sizes[i], jobs[i].offset);
        if (!write_image(jobs[i].offset, images[i], sizes[i]))
          goto done;
      }
      if ((verify_only || !no_verify) && !verify_image(jobs[i].offset, images[i], sizes[i]))
        goto done;
    }
    /* No FLASH_END: esptool skips it for the ROM loader too, and an ESP32-S3 answers it with an error after a
     * plain (uncompressed) write. The reset below is what leaves the loader. */
    if (!no_reset) {
      hard_reset(usb);
      puts("Reset: the chip runs the new image");
    }
    rc = 0;
  done:
    for (i = 0; i < job_count; ++i)
      free(images[i]);
  }
  if (fd >= 0)
    close(fd);
  return rc;
}
