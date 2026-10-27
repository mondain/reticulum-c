/* reticulum-c-rnodeconf against an emulated RNode on a pty: the emulator speaks
 * the device side of the KISS protocol the reference rnodeconf uses (detect,
 * firmware, platform, ROM and config reads, the setters), keeps its state
 * between runs and logs every frame it receives. The differential case points
 * the unmodified reference rnodeconf at the same emulator. */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d %s errno=%d\n", __FILE__, __LINE__, #x, errno);   \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
#define FEND 0xC0
#define FESC 0xDB
#define TFEND 0xDC
#define TFESC 0xDD

/* ---- the emulated device ------------------------------------------------- */
typedef struct device {
  uint8_t eeprom[296], cfg[200];
  uint8_t pending_conf[4 + 4 + 1 + 1 + 1]; /* freq, bw, txp, sf, cr */
  unsigned char board, platform, mcu, fw_major, fw_minor;
  int provisioned;
} device;
static void put_be32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}
static void md5(const uint8_t *data, size_t n, uint8_t out[16]) {
  unsigned len = 16;
  CHECK(EVP_Digest(data, n, out, &len, EVP_md5(), NULL) == 1);
}
/* A provisioned device. `signature` is 128 bytes over the checksum or NULL. */
static void device_init(device *d, const uint8_t *signature) {
  uint8_t info[11], sum[16];
  memset(d, 0xff, sizeof(*d));
  memset(d->eeprom, 0xff, sizeof(d->eeprom));
  memset(d->cfg, 0xff, sizeof(d->cfg));
  d->board = 0x37;
  d->platform = 0x80;
  d->mcu = 0x81;
  d->fw_major = 1;
  d->fw_minor = 74;
  d->provisioned = 1;
  info[0] = 0xc1; /* Heltec LoRa32 v3 */
  info[1] = 0xca; /* 850 - 950 MHz, SX1262, 22 dBm */
  info[2] = 3;
  info[3] = 0, info[4] = 0, info[5] = 0, info[6] = 5; /* serial */
  put_be32(info + 7, 1700000000u);                     /* manufactured */
  md5(info, sizeof(info), sum);
  memcpy(d->eeprom, info, 3);
  memcpy(d->eeprom + 3, info + 3, 4);
  memcpy(d->eeprom + 7, info + 7, 4);
  memcpy(d->eeprom + 0x0b, sum, 16);
  if (signature)
    memcpy(d->eeprom + 0x1b, signature, 128);
  else
    memset(d->eeprom + 0x1b, 0, 128);
  d->eeprom[0x9b] = 0x73; /* info lock */
  d->eeprom[0xa7] = 0xff; /* not configured: normal mode */
  d->eeprom[0xb0] = 0x00; /* bluetooth off */
  d->eeprom[0xb2] = 0x80; /* display brightness */
  d->eeprom[0xb3] = 0xff; /* display address default */
  d->eeprom[0xb4] = 0x00;
  d->eeprom[0xb7] = 0xff;
  d->eeprom[0xb9] = 0x00; /* interference avoidance enabled */
  d->eeprom[0xba] = 0x00; /* wifi off */
  d->eeprom[0xbb] = 0x01;
}
static size_t unescape_into(const uint8_t *in, size_t n, uint8_t *out) {
  size_t i, o = 0;
  int esc = 0;
  for (i = 0; i < n; i++) {
    uint8_t b = in[i];
    if (b == FESC) {
      esc = 1;
      continue;
    }
    if (esc) {
      b = b == TFEND ? FEND : (b == TFESC ? FESC : b);
      esc = 0;
    }
    out[o++] = b;
  }
  return o;
}
static void emit(int fd, uint8_t cmd, const uint8_t *data, size_t n) {
  uint8_t out[1200];
  size_t o = 0, i;
  out[o++] = FEND;
  out[o++] = cmd;
  for (i = 0; i < n; i++) {
    if (data[i] == FEND) {
      out[o++] = FESC;
      out[o++] = TFEND;
    } else if (data[i] == FESC) {
      out[o++] = FESC;
      out[o++] = TFESC;
    } else
      out[o++] = data[i];
  }
  out[o++] = FEND;
  CHECK(write(fd, out, o) == (ssize_t)o);
}
static void handle_frame(device *d, int fd, FILE *log, uint8_t cmd,
                         const uint8_t *data, size_t n) {
  uint8_t byte[1], two[2], hash[33];
  size_t i;
  if (log) {
    fprintf(log, "%02x:", cmd);
    for (i = 0; i < n; i++)
      fprintf(log, "%02x", data[i]);
    fputc('\n', log);
    fflush(log);
  }
  switch (cmd) {
  case 0x08:
    byte[0] = 0x46;
    emit(fd, 0x08, byte, 1);
    break;
  case 0x50:
    two[0] = d->fw_major;
    two[1] = d->fw_minor;
    emit(fd, 0x50, two, 2);
    break;
  case 0x48:
    emit(fd, 0x48, &d->platform, 1);
    break;
  case 0x49:
    emit(fd, 0x49, &d->mcu, 1);
    break;
  case 0x47:
    emit(fd, 0x47, &d->board, 1);
    break;
  case 0x56:
    memset(hash, 0xd1, 32);
    emit(fd, 0x56, hash, 32);
    break;
  case 0x60:
    hash[0] = n ? data[0] : 1;
    memset(hash + 1, hash[0] == 1 ? 0xf1 : 0xf2, 32);
    emit(fd, 0x60, hash, 33);
    break;
  case 0x51:
    emit(fd, 0x51, d->eeprom, sizeof(d->eeprom));
    break;
  case 0x6d:
    emit(fd, 0x6d, d->cfg, sizeof(d->cfg));
    break;
  case 0x46: /* bluetooth */
    if (n) {
      d->eeprom[0xb0] = data[0] == 0x01 ? 0x73 : 0x00;
    }
    break;
  case 0x45: /* display intensity */
    if (n)
      d->eeprom[0xb2] = data[0];
    break;
  case 0x64: /* display blanking */
    if (n) {
      d->eeprom[0xb4] = data[0];
      d->eeprom[0xb7] = 0x73;
    }
    break;
  case 0x67:
    if (n)
      d->eeprom[0xb8] = data[0];
    break;
  case 0x63:
    if (n)
      d->eeprom[0xb3] = data[0];
    break;
  case 0x65: /* NeoPixel intensity, which also marks it as set */
    if (n) {
      d->eeprom[0xb6] = data[0];
      d->eeprom[0xb5] = 0x73;
    }
    break;
  case 0x69: /* interference avoidance disable */
    if (n)
      d->eeprom[0xb9] = data[0];
    break;
  case 0x6a: /* wifi mode */
    if (n)
      d->eeprom[0xba] = data[0];
    break;
  case 0x6e:
    if (n)
      d->eeprom[0xbb] = data[0];
    break;
  case 0x6b: /* ssid, NUL terminated */
    memset(d->cfg + 0x00, 0xff, 0x21);
    memcpy(d->cfg + 0x00, data, n > 33 ? 33 : n);
    break;
  case 0x6c:
    memset(d->cfg + 0x21, 0xff, 0x21);
    memcpy(d->cfg + 0x21, data, n > 33 ? 33 : n);
    break;
  case 0x84:
    if (n == 4)
      memcpy(d->cfg + 0x42, data, 4);
    break;
  case 0x85:
    if (n == 4)
      memcpy(d->cfg + 0x46, data, 4);
    break;
  case 0x01: /* radio parameters, remembered for CONF_SAVE */
    if (n == 4)
      memcpy(d->pending_conf, data, 4);
    break;
  case 0x02:
    if (n == 4)
      memcpy(d->pending_conf + 4, data, 4);
    break;
  case 0x03:
    if (n)
      d->pending_conf[8] = data[0];
    break;
  case 0x04:
    if (n)
      d->pending_conf[9] = data[0];
    break;
  case 0x05:
    if (n)
      d->pending_conf[10] = data[0];
    break;
  case 0x53: /* save: TNC mode */
    d->eeprom[0xa7] = 0x73;
    memcpy(d->eeprom + 0xa3, d->pending_conf, 4);       /* frequency */
    memcpy(d->eeprom + 0x9f, d->pending_conf + 4, 4);   /* bandwidth */
    d->eeprom[0x9e] = d->pending_conf[8];
    d->eeprom[0x9c] = d->pending_conf[9];
    d->eeprom[0x9d] = d->pending_conf[10];
    break;
  case 0x54: /* delete: normal mode */
    d->eeprom[0xa7] = 0xff;
    break;
  default:
    break;
  }
}
/* Runs until killed. Frames are FEND cmd data FEND, adjacent frames sharing a
 * FEND, data escaped. */
static void emulate(int master, device *d, const char *log_path) {
  FILE *log = log_path ? fopen(log_path, "a") : NULL;
  uint8_t buf[2048], frame[2048], data[2048];
  size_t flen = 0;
  int in_frame = 0;
  for (;;) {
    struct pollfd p = {master, POLLIN, 0};
    ssize_t n, i;
    if (poll(&p, 1, 200) <= 0)
      continue;
    n = read(master, buf, sizeof(buf));
    if (n <= 0)
      continue;
    for (i = 0; i < n; i++) {
      if (buf[i] == FEND) {
        if (in_frame && flen >= 1) {
          size_t dn = unescape_into(frame + 1, flen - 1, data);
          handle_frame(d, master, log, frame[0], data, dn);
        }
        in_frame = 1;
        flen = 0;
      } else if (in_frame && flen < sizeof(frame))
        frame[flen++] = buf[i];
    }
  }
}
typedef struct emu {
  pid_t pid;
  int master;
  char port[128], log[256];
} emu;
static void emu_start_with(emu *e, const char *dir, const uint8_t *signature,
                           int configured, void (*tweak)(device *)) {
  device d;
  e->master = posix_openpt(O_RDWR | O_NOCTTY);
  CHECK(e->master >= 0 && grantpt(e->master) == 0 && unlockpt(e->master) == 0);
  CHECK(snprintf(e->port, sizeof(e->port), "%s", ptsname(e->master)) > 0);
  CHECK(snprintf(e->log, sizeof(e->log), "%s/frames.log", dir) > 0);
  device_init(&d, signature);
  if (configured) {
    d.eeprom[0xa7] = 0x73;
    put_be32(d.eeprom + 0xa3, 868000000u);
    put_be32(d.eeprom + 0x9f, 125000u);
    d.eeprom[0x9e] = 14;
    d.eeprom[0x9c] = 8;
    d.eeprom[0x9d] = 5;
  }
  if (tweak)
    tweak(&d);
  /* keep the slave open so the pty does not hang up between tool runs */
  (void)open(e->port, O_RDWR | O_NOCTTY);
  e->pid = fork();
  CHECK(e->pid >= 0);
  if (!e->pid) {
    /* never keep a test runner's pipes open if the test dies */
    int null = open("/dev/null", O_RDWR);
    if (null >= 0) {
      (void)dup2(null, 0);
      (void)dup2(null, 1);
      (void)dup2(null, 2);
    }
    emulate(e->master, &d, e->log);
    _exit(0);
  }
}
static void emu_start(emu *e, const char *dir, const uint8_t *signature,
                      int configured) {
  emu_start_with(e, dir, signature, configured, NULL);
}
static void emu_stop(emu *e) {
  kill(e->pid, SIGKILL);
  (void)waitpid(e->pid, NULL, 0);
  close(e->master);
}
static int slurp(const char *path, char *out, size_t size) {
  FILE *f = fopen(path, "r");
  size_t n;
  if (!f) {
    out[0] = 0;
    return 0;
  }
  n = fread(out, 1, size - 1, f);
  out[n] = 0;
  fclose(f);
  return (int)n;
}

/* ---- running programs ---------------------------------------------------- */
static int run(char *out, size_t size, char *const *argv) {
  int fds[2], status;
  size_t n = 0;
  pid_t p;
  unsigned tries;
  CHECK(!pipe(fds));
  p = fork();
  CHECK(p >= 0);
  if (!p) {
    close(fds[0]);
    CHECK(dup2(fds[1], 1) >= 0 && dup2(fds[1], 2) >= 0);
    close(fds[1]);
    execv(argv[0], argv);
    _exit(127);
  }
  close(fds[1]);
  for (tries = 0; tries < 1200; ++tries) {
    struct pollfd pf = {fds[0], POLLIN, 0};
    int r = poll(&pf, 1, 100);
    CHECK(r >= 0);
    if (r > 0) {
      ssize_t got = read(fds[0], out + n, size - 1 - n);
      if (got <= 0)
        break;
      n += (size_t)got;
      CHECK(n < size - 1);
    }
  }
  CHECK(tries < 1200);
  out[n] = 0;
  close(fds[0]);
  CHECK(waitpid(p, &status, 0) == p && WIFEXITED(status));
  return WEXITSTATUS(status);
}
static int tool(const char *exe, char *out, size_t size, ...) {
  char *args[40];
  size_t n = 0;
  va_list ap;
  const char *a;
  args[n++] = (char *)exe;
  va_start(ap, size);
  while ((a = va_arg(ap, const char *)) != NULL && n < 39)
    args[n++] = (char *)a;
  va_end(ap);
  args[n] = NULL;
  return run(out, size, args);
}
static void make_dir(char *dir, size_t size) {
  char tmpl[] = "/tmp/rnc-rnodeconf-XXXXXX";
  CHECK(mkdtemp(tmpl));
  CHECK(snprintf(dir, size, "%s", tmpl) > 0);
}
static void remove_dir(const char *dir) {
  char cmd[512];
  CHECK(snprintf(cmd, sizeof(cmd), "rm -rf %s", dir) > 0);
  CHECK(system(cmd) == 0);
}

/* ---- cases --------------------------------------------------------------- */
static void info(const char *exe) {
  char dir[64], out[8192];
  emu e;
  time_t made = 1700000000;
  struct tm tm;
  char stamp[64], expect[128];
  make_dir(dir, sizeof(dir));
  emu_start(&e, dir, NULL, 0);
  CHECK(tool(exe, out, sizeof(out), "-i", e.port, NULL) == 0);
  CHECK(strstr(out, "Product            : Heltec LoRa32 v3 850 - 950 MHz (c1:ca:37)"));
  CHECK(strstr(out, "Device signature   : Unverified"));
  CHECK(strstr(out, "Firmware version   : 1.74"));
  CHECK(strstr(out, "Hardware revision  : 3"));
  CHECK(strstr(out, "Serial number      : 00:00:00:05"));
  CHECK(strstr(out, "Modem chip         : SX1262"));
  CHECK(strstr(out, "Frequency range    : 850.0 MHz - 950.0 MHz"));
  CHECK(strstr(out, "Max TX power       : 22 dBm"));
  CHECK(localtime_r(&made, &tm) && strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tm));
  CHECK(snprintf(expect, sizeof(expect), "Manufactured       : %s", stamp) > 0 && strstr(out, expect));
  CHECK(strstr(out, "Device mode        : Normal (host-controlled)"));
  emu_stop(&e);
  /* a device in TNC mode shows its stored radio settings */
  emu_start(&e, dir, NULL, 1);
  CHECK(tool(exe, out, sizeof(out), "-i", e.port, NULL) == 0);
  CHECK(strstr(out, "Device mode        : TNC"));
  CHECK(strstr(out, "Frequency        : 868.0 MHz"));
  CHECK(strstr(out, "Bandwidth        : 125.0 KHz"));
  CHECK(strstr(out, "TX power         : 14 dBm (25.119 mW)"));
  CHECK(strstr(out, "Spreading factor : 8"));
  CHECK(strstr(out, "Coding rate      : 5"));
  CHECK(strstr(out, "On-air bitrate   : 3.12 kbps"));
  emu_stop(&e);
  remove_dir(dir);
  puts("rnodeconf info tests passed");
}
static void bad_device(const char *exe) {
  char dir[64], out[4096];
  emu e;
  int fd;
  make_dir(dir, sizeof(dir));
  /* silence: nothing answers on the port */
  e.master = posix_openpt(O_RDWR | O_NOCTTY);
  CHECK(e.master >= 0 && grantpt(e.master) == 0 && unlockpt(e.master) == 0);
  CHECK(snprintf(e.port, sizeof(e.port), "%s", ptsname(e.master)) > 0);
  fd = open(e.port, O_RDWR | O_NOCTTY);
  CHECK(fd >= 0);
  CHECK(tool(exe, out, sizeof(out), "-i", e.port, NULL) != 0);
  CHECK(strstr(out, "invalid response while detecting"));
  close(fd);
  close(e.master);
  CHECK(tool(exe, out, sizeof(out), "-i", "/no/such/port", NULL) != 0);
  CHECK(tool(exe, out, sizeof(out), NULL) != 0);
  remove_dir(dir);
  puts("rnodeconf bad device tests passed");
}
static int log_has(const emu *e, const char *line) {
  char text[16384];
  size_t n = strlen(line);
  const char *p;
  slurp(e->log, text, sizeof(text));
  for (p = text; (p = strstr(p, line)) != NULL; p += n)
    if ((p == text || p[-1] == '\n') && p[n] == '\n')
      return 1;
  return 0;
}
/* The bytes each setting puts on the wire. */
static void settings(const char *exe) {
  char dir[64], out[8192];
  emu e;
  make_dir(dir, sizeof(dir));
  emu_start(&e, dir, NULL, 0);
  CHECK(tool(exe, out, sizeof(out), "-b", "-D", "999", "-t", "15", "-R", "1",
             "--np", "77", "-X", "--channel", "6", "--ssid", "MyNet", "--psk",
             "secretpass", "--ip", "192.168.1.9", "--nm", "255.255.255.0", "-w",
             "station", e.port, NULL) == 0);
  CHECK(strstr(out, "Enabling Bluetooth...") &&
        strstr(out, "Setting display intensity to 255") &&
        strstr(out, "Setting display timeout to 15") &&
        strstr(out, "Setting display rotation to 1") &&
        strstr(out, "Setting NeoPixel intensity to 77") &&
        strstr(out, "Disabling interference avoidance") &&
        strstr(out, "Setting WiFi channel to 6") &&
        strstr(out, "Setting WiFi SSID to: MyNet") &&
        strstr(out, "Setting WiFi static IP to: 192.168.1.9") &&
        strstr(out, "Setting WiFi to station mode"));
  CHECK(log_has(&e, "46:01") && log_has(&e, "45:ff") && log_has(&e, "64:0f") &&
        log_has(&e, "67:01") && log_has(&e, "65:4d") && log_has(&e, "69:01") &&
        log_has(&e, "6e:06") && log_has(&e, "6b:4d794e657400") &&
        log_has(&e, "6c:736563726574706173730") == 0 &&
        log_has(&e, "6c:73656372657470617373" "00") &&
        log_has(&e, "84:c0a80109") && log_has(&e, "85:ffffff00") &&
        log_has(&e, "6a:01") && log_has(&e, "0a:ff"));
  CHECK(tool(exe, out, sizeof(out), "-B", "-x", "-w", "off", "--ssid", "none",
             "--ip", "none", "-D", "0", "-t", "0", e.port, NULL) == 0);
  CHECK(strstr(out, "Disabling Bluetooth...") && strstr(out, "Enabling interference avoidance") &&
        strstr(out, "Disabling WiFi...") && strstr(out, "Deleting WiFi SSID") &&
        strstr(out, "Setting WiFi IP to DHCP...") && strstr(out, "Disabling display blanking"));
  CHECK(log_has(&e, "46:00") && log_has(&e, "69:00") && log_has(&e, "6a:00") &&
        log_has(&e, "6b:00") && log_has(&e, "84:00000000") && log_has(&e, "64:00"));
  /* radio parameters, then save as TNC mode, then back to normal */
  CHECK(tool(exe, out, sizeof(out), "-T", "--freq", "433775000", "--bw", "125000",
             "--txp", "7", "--sf", "10", "--cr", "5", e.port, NULL) == 0);
  CHECK(strstr(out, "Device set to TNC operating mode"));
  CHECK(log_has(&e, "01:19dae198") && log_has(&e, "02:0001e848") &&
        log_has(&e, "03:07") && log_has(&e, "04:0a") && log_has(&e, "05:05") &&
        log_has(&e, "06:01") && log_has(&e, "53:00"));
  CHECK(tool(exe, out, sizeof(out), "-N", e.port, NULL) == 0 &&
        strstr(out, "Device set to normal (host-controlled) operating mode") &&
        log_has(&e, "54:00"));
  emu_stop(&e);
  remove_dir(dir);
  puts("rnodeconf settings tests passed");
}
/* Bad values are refused before anything is sent. */
static void refusals(const char *exe) {
  char dir[64], out[4096];
  emu e;
  make_dir(dir, sizeof(dir));
  emu_start(&e, dir, NULL, 0);
  CHECK(tool(exe, out, sizeof(out), "--channel", "99", e.port, NULL) != 0 &&
        strstr(out, "Invalid WiFi channel") && !log_has(&e, "6e:63"));
  CHECK(tool(exe, out, sizeof(out), "--psk", "short", e.port, NULL) != 0 &&
        strstr(out, "Invalid psk length"));
  CHECK(tool(exe, out, sizeof(out), "--ip", "300.1.1.1", e.port, NULL) != 0 &&
        strstr(out, "Invalid IP address"));
  CHECK(tool(exe, out, sizeof(out), "--ssid", "an-ssid-that-is-far-too-long-for-the-device", e.port, NULL) != 0 &&
        strstr(out, "Invalid SSID length"));
  CHECK(tool(exe, out, sizeof(out), "-T", "--freq", "868000000", e.port, NULL) != 0 &&
        strstr(out, "TNC mode needs"));
  CHECK(tool(exe, out, sizeof(out), "-T", "--freq", "868000000", "--bw", "125000",
             "--txp", "10", "--sf", "3", "--cr", "5", e.port, NULL) != 0 &&
        strstr(out, "Invalid radio parameters") && !log_has(&e, "53:00"));
  CHECK(tool(exe, out, sizeof(out), "--display-addr", "zz", e.port, NULL) == 0 &&
        strstr(out, "Invalid display address specified") && !log_has(&e, "63:00"));
  CHECK(tool(exe, out, sizeof(out), "--frobnicate", e.port, NULL) != 0);
  CHECK(tool(exe, out, sizeof(out), e.port, NULL) != 0); /* nothing to do */
  emu_stop(&e);
  remove_dir(dir);
  puts("rnodeconf refusal tests passed");
}
static void unprovisioned(device *d) {
  d->eeprom[0x9b] = 0xff;
}
static void corrupt(device *d) {
  d->eeprom[0x0b] ^= 0x01; /* the checksum no longer matches */
}
static void signature_checks(const char *exe) {
  char dir[64], out[8192], hex[2048];
  emu e;
  EVP_PKEY *key = NULL;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  uint8_t info[11], sum[16], digest[32], signature[128], *der = NULL;
  unsigned len = 16;
  size_t siglen = sizeof(signature), i;
  int derlen;
  /* a signing key of our own, trusted with --trust-key */
  CHECK(ctx && EVP_PKEY_keygen_init(ctx) == 1 &&
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024) == 1 &&
        EVP_PKEY_keygen(ctx, &key) == 1);
  EVP_PKEY_CTX_free(ctx);
  derlen = i2d_PUBKEY(key, &der);
  CHECK(derlen > 0 && (size_t)derlen * 2 < sizeof(hex));
  for (i = 0; i < (size_t)derlen; i++)
    sprintf(hex + 2 * i, "%02x", der[i]);
  info[0] = 0xc1;
  info[1] = 0xca;
  info[2] = 3;
  info[3] = 0, info[4] = 0, info[5] = 0, info[6] = 5;
  put_be32(info + 7, 1700000000u);
  CHECK(EVP_Digest(info, sizeof(info), sum, &len, EVP_md5(), NULL) == 1);
  {
    unsigned dl = 32;
    CHECK(EVP_Digest(sum, 16, digest, &dl, EVP_sha256(), NULL) == 1);
  }
  ctx = EVP_PKEY_CTX_new(key, NULL);
  CHECK(ctx && EVP_PKEY_sign_init(ctx) == 1 &&
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) == 1 &&
        EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) == 1 &&
        EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, RSA_PSS_SALTLEN_MAX) == 1 &&
        EVP_PKEY_sign(ctx, signature, &siglen, digest, 32) == 1 && siglen == 128);
  EVP_PKEY_CTX_free(ctx);
  make_dir(dir, sizeof(dir));
  emu_start(&e, dir, signature, 0);
  CHECK(tool(exe, out, sizeof(out), "-i", e.port, NULL) == 0 &&
        strstr(out, "Device signature   : Unverified"));
  CHECK(tool(exe, out, sizeof(out), "-i", "--trust-key", hex, e.port, NULL) == 0 &&
        strstr(out, "Device signature   : Validated - Local signature"));
  CHECK(tool(exe, out, sizeof(out), "-i", "--trust-key", "00ff", e.port, NULL) == 0 &&
        strstr(out, "Unverified"));
  emu_stop(&e);
  /* a device that was never provisioned, and one with a damaged EEPROM */
  emu_start_with(&e, dir, NULL, 0, unprovisioned);
  CHECK(tool(exe, out, sizeof(out), "-i", e.port, NULL) == 0 &&
        strstr(out, "EEPROM is invalid, no further information available"));
  CHECK(tool(exe, out, sizeof(out), "-T", "--freq", "868000000", "--bw", "125000",
             "--txp", "10", "--sf", "8", "--cr", "5", e.port, NULL) != 0 &&
        !log_has(&e, "53:00"));
  emu_stop(&e);
  emu_start_with(&e, dir, NULL, 0, corrupt);
  CHECK(tool(exe, out, sizeof(out), "-i", e.port, NULL) != 0 &&
        strstr(out, "EEPROM checksum mismatch"));
  emu_stop(&e);
  OPENSSL_free(der);
  EVP_PKEY_free(key);
  remove_dir(dir);
  puts("rnodeconf signature tests passed");
}
/* Lines of a block of output, trimmed and with the reference's log prefix
 * ("[time] [Level]   ") removed. */
static size_t normalise(const char *text, char lines[][160], size_t max) {
  size_t n = 0;
  const char *p = text;
  while (*p && n < max) {
    const char *eol = strchr(p, '\n');
    size_t len = eol ? (size_t)(eol - p) : strlen(p);
    char line[512], *q = line;
    if (len >= sizeof(line))
      len = sizeof(line) - 1;
    memcpy(line, p, len);
    line[len] = 0;
    if (line[0] == '[') { /* the reference's "[time] " log prefix */
      char *close = strchr(line, ']');
      if (close)
        q = close + 1;
    }
    while (*q == ' ' || *q == '\t')
      ++q;
    {
      size_t l = strlen(q);
      while (l && (q[l - 1] == ' ' || q[l - 1] == '\r'))
        q[--l] = 0;
    }
    if (*q) {
      snprintf(lines[n], 160, "%.159s", q);
      ++n;
    }
    p = eol ? eol + 1 : p + len;
  }
  return n;
}
static int has_line(char lines[][160], size_t n, const char *prefix) {
  size_t i;
  for (i = 0; i < n; i++)
    if (!strncmp(lines[i], prefix, strlen(prefix)))
      return 1;
  return 0;
}
/* Every line that starts with prefix in a is also in b (exact text). */
static void same_line(char a[][160], size_t an, char b[][160], size_t bn,
                      const char *prefix) {
  size_t i, j;
  int found = 0;
  for (i = 0; i < an; i++)
    if (!strncmp(a[i], prefix, strlen(prefix))) {
      int match = 0;
      for (j = 0; j < bn; j++)
        if (!strcmp(a[i], b[j]))
          match = 1;
      if (!match)
        fprintf(stderr, "no match for \"%s\" in the other output\n", a[i]);
      CHECK(match);
      found = 1;
    }
  if (!found)
    fprintf(stderr, "no line starting \"%s\"\n", prefix);
  CHECK(found);
}
static int reference(const char *python, char *out, size_t size, ...) {
  char *args[40];
  size_t n = 0;
  va_list ap;
  const char *a;
  args[n++] = (char *)python;
  args[n++] = "-u";
  args[n++] = "-m";
  args[n++] = "RNS.Utilities.rnodeconf";
  va_start(ap, size);
  while ((a = va_arg(ap, const char *)) != NULL && n < 39)
    args[n++] = (char *)a;
  va_end(ap);
  args[n] = NULL;
  return run(out, size, args);
}
/* The unmodified reference rnodeconf and this tool, on the same emulated
 * device: the same information, and each reads what the other wrote. */
static void differential(const char *exe, const char *python) {
  char dir[64], ours[16384], theirs[16384], lines_a[80][160], lines_b[80][160];
  size_t an, bn;
  emu e;
  const char *info_keys[] = {"Product", "Device signature", "Firmware version",
                             "Hardware revision", "Serial number", "Modem chip",
                             "Frequency range", "Max TX power", "Manufactured",
                             "Device mode"};
  size_t k;
  make_dir(dir, sizeof(dir));
  CHECK(setenv("HOME", dir, 1) == 0);
  emu_start(&e, dir, NULL, 0);
  CHECK(tool(exe, ours, sizeof(ours), "-i", e.port, NULL) == 0);
  CHECK(reference(python, theirs, sizeof(theirs), "-i", e.port, NULL) == 0);
  an = normalise(ours, lines_a, 80);
  bn = normalise(theirs, lines_b, 80);
  for (k = 0; k < sizeof(info_keys) / sizeof(*info_keys); k++)
    same_line(lines_a, an, lines_b, bn, info_keys[k]);
  /* ours writes, the reference reads */
  CHECK(tool(exe, ours, sizeof(ours), "-b", "-D", "200", "-t", "15", "-R", "1",
             "--np", "77", "-X", "--channel", "6", "--ssid", "MyNet", "--psk",
             "secretpass", "-w", "ap", e.port, NULL) == 0);
  CHECK(reference(python, theirs, sizeof(theirs), "-c", "--show-psk", e.port,
                  NULL) == 0);
  CHECK(strstr(theirs, "Bluetooth              : Enabled"));
  CHECK(strstr(theirs, "WiFi                   : Enabled (AP)"));
  CHECK(strstr(theirs, "Channel              : 6"));
  CHECK(strstr(theirs, "SSID                 : MyNet"));
  CHECK(strstr(theirs, "PSK                  : secretpass"));
  CHECK(strstr(theirs, "Interference avoidance : Disabled"));
  CHECK(strstr(theirs, "Display brightness     : 200"));
  CHECK(strstr(theirs, "Display blanking       : 15s"));
  CHECK(strstr(theirs, "Display rotation       : Portrait"));
  CHECK(strstr(theirs, "Neopixel Intensity     : 77"));
  CHECK(tool(exe, ours, sizeof(ours), "-c", "--show-psk", e.port, NULL) == 0);
  an = normalise(ours, lines_a, 80);
  bn = normalise(theirs, lines_b, 80);
  for (k = 0; k < an; k++) { /* every configuration line is the same text */
    size_t j;
    int match = 0;
    for (j = 0; j < bn; j++)
      match |= !strcmp(lines_a[k], lines_b[j]);
    if (!match)
      fprintf(stderr, "reference output lacks \"%s\"\n", lines_a[k]);
    CHECK(match);
  }
  CHECK(has_line(lines_a, an, "Bluetooth"));
  /* the reference writes, ours reads */
  CHECK(reference(python, theirs, sizeof(theirs), "-B", "-D", "50", "-x", "-w",
                  "station", "--ssid", "OtherNet", "--ip", "192.168.1.9", "--nm",
                  "255.255.255.0", e.port, NULL) == 0);
  CHECK(tool(exe, ours, sizeof(ours), "-c", "--show-psk", e.port, NULL) == 0);
  CHECK(strstr(ours, "Bluetooth              : Disabled"));
  CHECK(strstr(ours, "WiFi                   : Enabled (Station)"));
  CHECK(strstr(ours, "SSID                 : OtherNet"));
  CHECK(strstr(ours, "IP Address           : 192.168.1.9"));
  CHECK(strstr(ours, "Network Mask         : 255.255.255.0"));
  CHECK(strstr(ours, "Interference avoidance : Enabled"));
  CHECK(strstr(ours, "Display brightness     : 50"));
  /* TNC mode set by the reference, read by ours, then back to normal by ours */
  CHECK(reference(python, theirs, sizeof(theirs), "-T", "--freq", "915000000",
                  "--bw", "250000", "--txp", "10", "--sf", "9", "--cr", "6",
                  e.port, NULL) == 0);
  CHECK(tool(exe, ours, sizeof(ours), "-i", e.port, NULL) == 0);
  CHECK(strstr(ours, "Device mode        : TNC") &&
        strstr(ours, "Frequency        : 915.0 MHz") &&
        strstr(ours, "Bandwidth        : 250.0 KHz") &&
        strstr(ours, "TX power         : 10 dBm (10.0 mW)") &&
        strstr(ours, "Spreading factor : 9") && strstr(ours, "Coding rate      : 6"));
  CHECK(reference(python, theirs, sizeof(theirs), "-i", e.port, NULL) == 0);
  an = normalise(ours, lines_a, 80);
  bn = normalise(theirs, lines_b, 80);
  same_line(lines_a, an, lines_b, bn, "On-air bitrate");
  same_line(lines_a, an, lines_b, bn, "TX power");
  CHECK(tool(exe, ours, sizeof(ours), "-N", e.port, NULL) == 0);
  CHECK(tool(exe, ours, sizeof(ours), "-i", e.port, NULL) == 0 &&
        strstr(ours, "Normal (host-controlled)"));
  /* and ours sets TNC mode, the reference reads it */
  CHECK(tool(exe, ours, sizeof(ours), "-T", "--freq", "433775000", "--bw",
             "125000", "--txp", "7", "--sf", "10", "--cr", "5", e.port, NULL) == 0);
  CHECK(reference(python, theirs, sizeof(theirs), "-i", e.port, NULL) == 0);
  CHECK(strstr(theirs, "Frequency        : 433.775 MHz") &&
        strstr(theirs, "Spreading factor : 10"));
  emu_stop(&e);
  remove_dir(dir);
  puts("rnodeconf reference tests passed");
}
int main(int argc, char **argv) {
  CHECK(argc >= 3);
  signal(SIGPIPE, SIG_IGN);
  if (!strcmp(argv[2], "info") && argc == 3)
    info(argv[1]);
  else if (!strcmp(argv[2], "settings") && argc == 3)
    settings(argv[1]);
  else if (!strcmp(argv[2], "refusals") && argc == 3)
    refusals(argv[1]);
  else if (!strcmp(argv[2], "signature") && argc == 3)
    signature_checks(argv[1]);
  else if (!strcmp(argv[2], "ref") && argc == 5)
    differential(argv[1], argv[4]);
  else if (!strcmp(argv[2], "emulator") && argc == 3) {
    /* for manual use: print the port and serve until killed */
    char dir[64];
    emu e;
    make_dir(dir, sizeof(dir));
    emu_start(&e, dir, NULL, 0);
    printf("%s %s\n", e.port, e.log);
    fflush(stdout);
    pause();
  } else if (!strcmp(argv[2], "bad") && argc == 3)
    bad_device(argv[1]);
  else
    CHECK(0);
  return 0;
}
