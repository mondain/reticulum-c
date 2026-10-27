/* reticulum-c-rnodeconf: configure an RNode from the host, the part of the
 * reference rnodeconf that talks to a running device.
 *
 *   reticulum-c-rnodeconf [OPTIONS] PORT
 *
 *   -i            show device information (product, signature, firmware, modem)
 *   -c [--show-psk]   show the stored configuration (Bluetooth, WiFi, display)
 *   -T [--freq HZ --bw HZ --txp DBM --sf N --cr N]   store TNC mode
 *   -N            return to normal (host-controlled) mode
 *   -b | -B | -p  Bluetooth on, off, pairing
 *   -D N, -t SECONDS, -R 0..3, --display-addr HEX, --recondition-display,
 *   --np N        display and NeoPixel settings
 *   -x | -X       interference avoidance on, off
 *   -w off|ap|station, --channel N, --ssid S|none, --psk S|none, --ip A|none,
 *   --nm A|none   WiFi settings
 *   --trust-key HEX   also accept this DER public key for device signatures
 *
 * Firmware download, flashing, update and extraction, EEPROM provisioning,
 * signing and recovery are not part of this tool: they need the vendor
 * toolchain and the hardware, and nothing here can test them. */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define FEND 0xC0
#define FESC 0xDB
#define TFEND 0xDC
#define TFESC 0xDD
enum {
  CMD_FREQUENCY = 0x01,
  CMD_BANDWIDTH = 0x02,
  CMD_TXPOWER = 0x03,
  CMD_SF = 0x04,
  CMD_CR = 0x05,
  CMD_RADIO_STATE = 0x06,
  CMD_DETECT = 0x08,
  CMD_LEAVE = 0x0A,
  CMD_DISP_INT = 0x45,
  CMD_BT_CTRL = 0x46,
  CMD_BOARD = 0x47,
  CMD_PLATFORM = 0x48,
  CMD_MCU = 0x49,
  CMD_FW_VERSION = 0x50,
  CMD_ROM_READ = 0x51,
  CMD_CONF_SAVE = 0x53,
  CMD_CONF_DELETE = 0x54,
  CMD_DEV_HASH = 0x56,
  CMD_HASHES = 0x60,
  CMD_DISP_ADR = 0x63,
  CMD_DISP_BLNK = 0x64,
  CMD_NP_INT = 0x65,
  CMD_DISP_ROT = 0x67,
  CMD_DISP_RCND = 0x68,
  CMD_DIS_IA = 0x69,
  CMD_WIFI_MODE = 0x6A,
  CMD_WIFI_SSID = 0x6B,
  CMD_WIFI_PSK = 0x6C,
  CMD_CFG_READ = 0x6D,
  CMD_WIFI_CHN = 0x6E,
  CMD_WIFI_IP = 0x84,
  CMD_WIFI_NM = 0x85,
  DETECT_REQ = 0x73,
  DETECT_RESP = 0x46
};
/* EEPROM layout */
enum {
  ADDR_PRODUCT = 0x00,
  ADDR_MODEL = 0x01,
  ADDR_HW_REV = 0x02,
  ADDR_SERIAL = 0x03,
  ADDR_MADE = 0x07,
  ADDR_CHKSUM = 0x0B,
  ADDR_SIGNATURE = 0x1B,
  ADDR_INFO_LOCK = 0x9B,
  ADDR_CONF_SF = 0x9C,
  ADDR_CONF_CR = 0x9D,
  ADDR_CONF_TXP = 0x9E,
  ADDR_CONF_BW = 0x9F,
  ADDR_CONF_FREQ = 0xA3,
  ADDR_CONF_OK = 0xA7,
  ADDR_CONF_BT = 0xB0,
  ADDR_CONF_DINT = 0xB2,
  ADDR_CONF_DADR = 0xB3,
  ADDR_CONF_DBLK = 0xB4,
  ADDR_CONF_PSET = 0xB5,
  ADDR_CONF_PINT = 0xB6,
  ADDR_CONF_BSET = 0xB7,
  ADDR_CONF_DROT = 0xB8,
  ADDR_CONF_DIA = 0xB9,
  ADDR_CONF_WIFI = 0xBA,
  ADDR_CONF_WCHN = 0xBB,
  CFG_SSID = 0x00,
  CFG_PSK = 0x21,
  CFG_IP = 0x42,
  CFG_NM = 0x46,
  INFO_LOCK_BYTE = 0x73,
  CONF_OK_BYTE = 0x73,
  PLATFORM_AVR = 0x90,
  PLATFORM_ESP32 = 0x80,
  PLATFORM_NRF52 = 0x70,
  MCU_1284P = 0x91
};
typedef struct model {
  uint8_t code;
  uint32_t min_freq, max_freq;
  int max_output;
  const char *band, *chip;
} model;
static const model models[] = {
    {0xA4, 410000000u, 525000000u, 14, "410 - 525 MHz", "SX1278"},
    {0xA9, 820000000u, 1020000000u, 17, "820 - 1020 MHz", "SX1276"},
    {0xA1, 410000000u, 525000000u, 22, "410 - 525 MHz", "SX1268"},
    {0xA6, 820000000u, 1020000000u, 22, "820 - 960 MHz", "SX1262"},
    {0xA5, 410000000u, 525000000u, 17, "410 - 525 MHz", "SX1278"},
    {0xAA, 820000000u, 1020000000u, 17, "820 - 960 MHz", "SX1276"},
    {0xAC, 2400000000u, 2500000000u, 20, "2.4 - 2.5 GHz", "SX1280"},
    {0xA2, 410000000u, 525000000u, 17, "410 - 525 MHz", "SX1278"},
    {0xA7, 820000000u, 1020000000u, 17, "820 - 1020 MHz", "SX1276"},
    {0xA3, 410000000u, 525000000u, 17, "410 - 525 MHz", "SX1278"},
    {0xA8, 820000000u, 1020000000u, 17, "820 - 1020 MHz", "SX1276"},
    {0xB3, 420000000u, 520000000u, 17, "420 - 520 MHz", "SX1278"},
    {0xB8, 850000000u, 950000000u, 17, "850 - 950 MHz", "SX1276"},
    {0xB4, 420000000u, 520000000u, 17, "420 - 520 MHz", "SX1278"},
    {0xB9, 850000000u, 950000000u, 17, "850 - 950 MHz", "SX1276"},
    {0x04, 420000000u, 520000000u, 17, "420 - 520 MHz", "SX1278"},
    {0x09, 850000000u, 950000000u, 17, "850 - 950 MHz", "SX1276"},
    {0xBA, 420000000u, 520000000u, 17, "420 - 520 MHz", "SX1278"},
    {0xBB, 850000000u, 950000000u, 17, "850 - 950 MHz", "SX1276"},
    {0xC4, 420000000u, 520000000u, 17, "420 - 520 MHz", "SX1278"},
    {0xC9, 850000000u, 950000000u, 17, "850 - 950 MHz", "SX1276"},
    {0xC5, 420000000u, 520000000u, 22, "420 - 520 MHz", "SX1268"},
    {0xCA, 850000000u, 950000000u, 22, "850 - 950 MHz", "SX1262"},
    {0xC8, 860000000u, 930000000u, 28, "850 - 950 MHz", "SX1262"},
    {0xC6, 420000000u, 520000000u, 22, "420 - 520 MHz", "SX1268"},
    {0xC7, 850000000u, 950000000u, 22, "850 - 950 MHz", "SX1262"},
    {0xE4, 420000000u, 520000000u, 17, "420 - 520 MHz", "SX1278"},
    {0xE9, 850000000u, 950000000u, 17, "850 - 950 MHz", "SX1276"},
    {0xD4, 420000000u, 520000000u, 22, "420 - 520 MHz", "SX1268"},
    {0xD9, 850000000u, 950000000u, 22, "850 - 950 MHz", "SX1262"},
    {0xDB, 420000000u, 520000000u, 22, "420 - 520 MHz", "SX1268"},
    {0xDC, 850000000u, 950000000u, 22, "850 - 950 MHz", "SX1262"},
    {0xE3, 420000000u, 520000000u, 22, "420 - 520 MHz", "SX1268"},
    {0xE8, 850000000u, 950000000u, 22, "850 - 950 MHz", "SX1262"},
    {0x11, 430000000u, 510000000u, 22, "430 - 510 MHz", "SX1262"},
    {0x12, 779000000u, 928000000u, 22, "779 - 928 MHz", "SX1262"},
    {0x13, 430000000u, 510000000u, 22, "430 - 510 MHz", "SX1262 + SX1280"},
    {0x14, 779000000u, 928000000u, 22, "779 - 928 MHz", "SX1262 + SX1280"},
    {0x16, 779000000u, 928000000u, 22, "430 - 510 Mhz", "SX1262"},
    {0x17, 779000000u, 928000000u, 22, "779 - 928 Mhz", "SX1262"},
    {0x21, 820000000u, 960000000u, 22, "820 - 960 MHz", "SX1262 + SX1280"},
    {0xDE, 420000000u, 520000000u, 22, "420 - 520 MHz", "SX1262"},
    {0xDD, 850000000u, 950000000u, 22, "850 - 950 MHz", "SX1262"},
    {0xFE, 100000000u, 1100000000u, 17, "(Band capabilities unknown)", "Unknown"},
    {0xFF, 100000000u, 1100000000u, 14, "(Band capabilities unknown)", "Unknown"},
};
typedef struct product {
  uint8_t code;
  const char *name;
} product;
static const product products[] = {
    {0x03, "RNode"},
    {0xF0, "Hombrew RNode"},
    {0xE0, "LilyGO T-Beam"},
    {0xEA, "LilyGO T-Beam Supreme"},
    {0xD0, "LilyGO T-Deck"},
    {0xB2, "LilyGO LoRa32 v1.0"},
    {0xB0, "LilyGO LoRa32 v2.0"},
    {0xB1, "LilyGO LoRa32 v2.1"},
    {0xC0, "Heltec LoRa32 v2"},
    {0xC1, "Heltec LoRa32 v3"},
    {0xC3, "Heltec LoRa32 v4"},
    {0x15, "LilyGO T-Echo"},
    {0x10, "RAK4631"},
    {0x20, "openCom XL"},
    {0xC2, "Heltec Mesh Node T114"},
    {0xEB, "Seeed XIAO ESP32S3 Wio-SX1262"}};
/* DER public keys of the vendor whose devices are recognised as genuine */
static const char *vendor_keys[] = {
    "30819f300d06092a864886f70d010101050003818d0030818902818100bf831ebd99f43b477caf1a094bec829389da40653e8f1f83fc14bf1b98a3e1cc70e759c213a43f71e5a47eb56a9ca487f241335b3e6ff7cdde0ee0a1c75c698574aeba0485726b6a9dfc046b4188e3520271ee8555a8f405cf21f81f2575771d0b0887adea5dd53c1f594f72c66b5f14904ffc2e72206a6698a490d51ba1105b0203010001",
    "30819f300d06092a864886f70d010101050003818d0030818902818100e5d46084e445595376bf7efd9c6ccf19d39abbc59afdb763207e4ff68b8d00ebffb63847aa2fe6dd10783d3ea63b55ac66f71ad885c20e223709f0d51ed5c6c0d0b093be9e1d165bb8a483a548b67a3f7a1e4580f50e75b306593fa6067ae259d3e297717bd7ff8c8f5b07f2bed89929a9a0321026cf3699524db98e2d18fb2d020300ff39",
};
#define VENDOR "unsigned.io"

static const model *find_model(uint8_t code) {
  size_t i;
  for (i = 0; i < sizeof(models) / sizeof(*models); ++i)
    if (models[i].code == code)
      return &models[i];
  return NULL;
}
static const char *find_product(uint8_t code) {
  size_t i;
  for (i = 0; i < sizeof(products) / sizeof(*products); ++i)
    if (products[i].code == code)
      return products[i].name;
  return NULL;
}
/* Python's repr for the floats rnodeconf prints: shortest form with at least
 * one decimal. */
static void pyfloat(double v, char *out, size_t size) {
  char text[64];
  int decimals;
  for (decimals = 1; decimals <= 15; ++decimals) {
    snprintf(text, sizeof(text), "%.*f", decimals, v);
    if (strtod(text, NULL) == v)
      break;
  }
  snprintf(out, size, "%s", text);
}
/* round(v, places) printed as Python does */
static void pyround(double v, int places, char *out, size_t size) {
  char text[64];
  snprintf(text, sizeof(text), "%.*f", places, v);
  pyfloat(strtod(text, NULL), out, size);
}

/* ---- the serial line and KISS ------------------------------------------- */
typedef struct rnode {
  int fd;
  int detected, have_fw, have_platform, have_mcu, have_board;
  unsigned fw_major, fw_minor;
  uint8_t platform, mcu, board;
  uint8_t *eeprom, *cfg;
  size_t eeprom_size, cfg_size;
  int provisioned, signature_valid, locally_signed;
  /* parsed */
  uint8_t product, model, hw_rev, serial[4], made[4], checksum[16];
  int configured;
  unsigned conf_sf, conf_cr, conf_txp;
  uint32_t conf_freq, conf_bw;
  /* frame parser */
  uint8_t frame[2048];
  size_t frame_len;
  int in_frame;
  const char *extra_keys[8];
  size_t extra_key_count;
} rnode;

static int open_port(const char *path) {
  struct termios t;
  int fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
  if (fd < 0)
    return -1;
  if (tcgetattr(fd, &t) == 0) {
    t.c_iflag = 0;
    t.c_oflag = 0;
    t.c_lflag = 0;
    t.c_cflag &= (tcflag_t) ~(CSIZE | PARENB | CSTOPB);
    t.c_cflag |= CS8 | CLOCAL | CREAD;
    t.c_cc[VMIN] = 0;
    t.c_cc[VTIME] = 0;
    (void)cfsetispeed(&t, B115200);
    (void)cfsetospeed(&t, B115200);
    (void)tcsetattr(fd, TCSANOW, &t);
  }
  return fd;
}
static int send_frame(rnode *r, uint8_t cmd, const uint8_t *data, size_t n) {
  uint8_t out[600];
  size_t o = 0, i;
  out[o++] = FEND;
  out[o++] = cmd;
  for (i = 0; i < n && o + 3 < sizeof(out); i++) {
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
  for (i = 0; i < o;) {
    ssize_t w = write(r->fd, out + i, o - i);
    if (w > 0)
      i += (size_t)w;
    else if (w < 0 && (errno == EAGAIN || errno == EINTR)) {
      struct pollfd p = {r->fd, POLLOUT, 0};
      (void)poll(&p, 1, 100);
    } else
      return 0;
  }
  return 1;
}
static int send_byte(rnode *r, uint8_t cmd, uint8_t value) {
  return send_frame(r, cmd, &value, 1);
}
static void handle_frame(rnode *r, uint8_t cmd, const uint8_t *d, size_t n) {
  switch (cmd) {
  case CMD_DETECT:
    if (n >= 1 && d[0] == DETECT_RESP)
      r->detected = 1;
    break;
  case CMD_FW_VERSION:
    if (n >= 2) {
      r->fw_major = d[0];
      r->fw_minor = d[1];
      r->have_fw = 1;
    }
    break;
  case CMD_PLATFORM:
    if (n >= 1) {
      r->platform = d[0];
      r->have_platform = 1;
    }
    break;
  case CMD_MCU:
    if (n >= 1) {
      r->mcu = d[0];
      r->have_mcu = 1;
    }
    break;
  case CMD_BOARD:
    if (n >= 1) {
      r->board = d[0];
      r->have_board = 1;
    }
    break;
  case CMD_ROM_READ:
    free(r->eeprom);
    r->eeprom = malloc(n ? n : 1);
    if (r->eeprom) {
      memcpy(r->eeprom, d, n);
      r->eeprom_size = n;
    }
    break;
  case CMD_CFG_READ:
    free(r->cfg);
    r->cfg = malloc(n ? n : 1);
    if (r->cfg) {
      memcpy(r->cfg, d, n);
      r->cfg_size = n;
    }
    break;
  default:
    break;
  }
}
/* Feeds received bytes through the unescaping frame parser. */
static void feed(rnode *r, const uint8_t *in, size_t n) {
  size_t i;
  static int escape;
  for (i = 0; i < n; i++) {
    uint8_t b = in[i];
    if (b == FEND) {
      if (r->in_frame && r->frame_len >= 1)
        handle_frame(r, r->frame[0], r->frame + 1, r->frame_len - 1);
      r->in_frame = 1;
      r->frame_len = 0;
      escape = 0;
    } else if (r->in_frame) {
      if (b == FESC) {
        escape = 1;
        continue;
      }
      if (escape) {
        b = b == TFEND ? FEND : (b == TFESC ? FESC : b);
        escape = 0;
      }
      if (r->frame_len < sizeof(r->frame))
        r->frame[r->frame_len++] = b;
    }
  }
}
/* Reads for up to timeout_ms, or until done() says so after a quiet spell. */
static void listen_for(rnode *r, unsigned timeout_ms, int (*done)(rnode *)) {
  struct timespec start, now;
  clock_gettime(CLOCK_MONOTONIC, &start);
  for (;;) {
    struct pollfd p = {r->fd, POLLIN, 0};
    uint8_t buf[512];
    ssize_t n;
    long elapsed;
    if (poll(&p, 1, 50) > 0 && (n = read(r->fd, buf, sizeof(buf))) > 0)
      feed(r, buf, (size_t)n);
    if (done && done(r))
      return;
    clock_gettime(CLOCK_MONOTONIC, &now);
    elapsed = (now.tv_sec - start.tv_sec) * 1000 +
              (now.tv_nsec - start.tv_nsec) / 1000000;
    if (elapsed >= (long)timeout_ms)
      return;
  }
}
static int detect_done(rnode *r) {
  return r->detected && r->have_fw && r->have_platform && r->have_mcu &&
         r->have_board;
}
static int eeprom_done(rnode *r) { return r->eeprom != NULL; }
static int cfg_done(rnode *r) { return r->cfg != NULL; }

static int probe(rnode *r) {
  static const uint8_t detect = DETECT_REQ, zero = 0, one = 1, two = 2;
  if (!send_frame(r, CMD_DETECT, &detect, 1) ||
      !send_frame(r, CMD_FW_VERSION, &zero, 1) ||
      !send_frame(r, CMD_PLATFORM, &zero, 1) || !send_frame(r, CMD_MCU, &zero, 1) ||
      !send_frame(r, CMD_BOARD, &zero, 1) || !send_frame(r, CMD_DEV_HASH, &one, 1) ||
      !send_frame(r, CMD_HASHES, &one, 1) || !send_frame(r, CMD_HASHES, &two, 1))
    return 0;
  listen_for(r, 4000, detect_done);
  if (!r->detected)
    return 0;
  if (!r->have_platform || !r->have_mcu) {
    r->platform = PLATFORM_AVR;
    r->mcu = MCU_1284P;
  }
  return 1;
}

/* ---- the EEPROM --------------------------------------------------------- */
static int verify_signature(const rnode *r, const char *hex) {
  size_t len = strlen(hex) / 2, i;
  uint8_t *der = malloc(len ? len : 1);
  const uint8_t *p;
  EVP_PKEY *key = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  uint8_t digest[32];
  unsigned digest_len = sizeof(digest);
  int ok = 0;
  if (!der)
    return 0;
  for (i = 0; i < len; i++) {
    unsigned v;
    if (sscanf(hex + 2 * i, "%2x", &v) != 1) {
      free(der);
      return 0;
    }
    der[i] = (uint8_t)v;
  }
  p = der;
  key = d2i_PUBKEY(NULL, &p, (long)len);
  /* the signature is over SHA-256 of the 16 byte checksum, as the reference
   * verifies it with a SHA-256 PSS signature over the checksum as the message */
  if (key && EVP_Digest(r->checksum, 16, digest, &digest_len, EVP_sha256(), NULL) == 1 &&
      (ctx = EVP_PKEY_CTX_new(key, NULL)) != NULL &&
      EVP_PKEY_verify_init(ctx) == 1 &&
      EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) == 1 &&
      EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) == 1 &&
      EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, RSA_PSS_SALTLEN_AUTO) == 1)
    ok = EVP_PKEY_verify(ctx, r->eeprom + ADDR_SIGNATURE, 128, digest,
                         digest_len) == 1;
  ERR_clear_error();
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(key);
  free(der);
  return ok;
}
/* Fills the parsed fields. Returns 1 if the EEPROM is provisioned and intact,
 * 0 if it is not provisioned, -1 on a checksum mismatch. */
static int parse_eeprom(rnode *r) {
  uint8_t info[11], sum[16];
  unsigned len = 16;
  size_t i;
  if (!r->eeprom || r->eeprom_size <= ADDR_CONF_WCHN)
    return 0;
  if (r->eeprom[ADDR_INFO_LOCK] != INFO_LOCK_BYTE)
    return 0;
  r->provisioned = 1;
  r->product = r->eeprom[ADDR_PRODUCT];
  r->model = r->eeprom[ADDR_MODEL];
  r->hw_rev = r->eeprom[ADDR_HW_REV];
  memcpy(r->serial, r->eeprom + ADDR_SERIAL, 4);
  memcpy(r->made, r->eeprom + ADDR_MADE, 4);
  memcpy(r->checksum, r->eeprom + ADDR_CHKSUM, 16);
  info[0] = r->product;
  info[1] = r->model;
  info[2] = r->hw_rev;
  memcpy(info + 3, r->serial, 4);
  memcpy(info + 7, r->made, 4);
  if (EVP_Digest(info, sizeof(info), sum, &len, EVP_md5(), NULL) != 1 ||
      memcmp(sum, r->checksum, 16)) {
    r->provisioned = 0;
    return -1;
  }
  for (i = 0; i < sizeof(vendor_keys) / sizeof(*vendor_keys) &&
              !r->signature_valid;
       i++)
    if (verify_signature(r, vendor_keys[i]))
      r->signature_valid = 1;
  for (i = 0; i < r->extra_key_count && !r->signature_valid; i++)
    if (verify_signature(r, r->extra_keys[i])) {
      r->signature_valid = 1;
      r->locally_signed = 1;
    }
  if (r->eeprom[ADDR_CONF_OK] == CONF_OK_BYTE) {
    r->configured = 1;
    r->conf_sf = r->eeprom[ADDR_CONF_SF];
    r->conf_cr = r->eeprom[ADDR_CONF_CR];
    r->conf_txp = r->eeprom[ADDR_CONF_TXP];
    r->conf_freq = (uint32_t)r->eeprom[ADDR_CONF_FREQ] << 24 |
                   (uint32_t)r->eeprom[ADDR_CONF_FREQ + 1] << 16 |
                   (uint32_t)r->eeprom[ADDR_CONF_FREQ + 2] << 8 |
                   r->eeprom[ADDR_CONF_FREQ + 3];
    r->conf_bw = (uint32_t)r->eeprom[ADDR_CONF_BW] << 24 |
                 (uint32_t)r->eeprom[ADDR_CONF_BW + 1] << 16 |
                 (uint32_t)r->eeprom[ADDR_CONF_BW + 2] << 8 |
                 r->eeprom[ADDR_CONF_BW + 3];
  }
  return 1;
}
static int download_eeprom(rnode *r) {
  free(r->eeprom);
  r->eeprom = NULL;
  if (!send_byte(r, CMD_ROM_READ, 0x00))
    return 0;
  listen_for(r, 3000, eeprom_done);
  return r->eeprom != NULL;
}

/* ---- commands ----------------------------------------------------------- */
static void show_info(rnode *r) {
  struct tm tm;
  time_t made;
  char stamp[64], a[48], b[48], c[48];
  const model *m = find_model(r->model);
  const char *name = find_product(r->product);
  const char *sig = "Unverified";
  char vendor[96];
  if (r->signature_valid) {
    if (r->locally_signed)
      sig = "Validated - Local signature";
    else {
      snprintf(vendor, sizeof(vendor), "Genuine board, vendor is %s", VENDOR);
      sig = vendor;
    }
  }
  made = (time_t)((uint32_t)r->made[0] << 24 | (uint32_t)r->made[1] << 16 |
                  (uint32_t)r->made[2] << 8 | r->made[3]);
  if (!localtime_r(&made, &tm) ||
      !strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tm))
    snprintf(stamp, sizeof(stamp), "unknown");
  putchar('\n');
  puts("Device info:");
  if (r->have_board)
    snprintf(a, sizeof(a), ":%02x", r->board);
  else
    a[0] = 0;
  printf("\tProduct            : %s %s (%02x:%02x%s)\n",
         name ? name : "Unknown product", m ? m->band : "(unknown model)",
         r->product, r->model, a);
  printf("\tDevice signature   : %s\n", sig);
  printf("\tFirmware version   : %u.%02u\n", r->fw_major, r->fw_minor);
  printf("\tHardware revision  : %u\n", r->hw_rev);
  printf("\tSerial number      : %02x:%02x:%02x:%02x\n", r->serial[0], r->serial[1],
         r->serial[2], r->serial[3]);
  printf("\tModem chip         : %s\n", m ? m->chip : "Unknown");
  pyfloat(m ? m->min_freq / 1e6 : 0, a, sizeof(a));
  pyfloat(m ? m->max_freq / 1e6 : 0, b, sizeof(b));
  printf("\tFrequency range    : %s MHz - %s MHz\n", a, b);
  printf("\tMax TX power       : %d dBm\n", m ? m->max_output : 0);
  printf("\tManufactured       : %s\n", stamp);
  if (r->configured) {
    double bitrate =
        r->conf_sf * ((4.0 / r->conf_cr) / (pow(2, r->conf_sf) / (r->conf_bw / 1000.0))) * 1000.0;
    putchar('\n');
    puts("\tDevice mode        : TNC");
    pyfloat(r->conf_freq / 1000000.0, a, sizeof(a));
    printf("\t  Frequency        : %s MHz\n", a);
    pyfloat(r->conf_bw / 1000.0, a, sizeof(a));
    printf("\t  Bandwidth        : %s KHz\n", a);
    pyround(pow(10, r->conf_txp / 10.0), 3, b, sizeof(b));
    printf("\t  TX power         : %u dBm (%s mW)\n", r->conf_txp, b);
    printf("\t  Spreading factor : %u\n", r->conf_sf);
    printf("\t  Coding rate      : %u\n", r->conf_cr);
    pyround(bitrate / 1000.0, 2, c, sizeof(c));
    printf("\t  On-air bitrate   : %s kbps\n", c);
  } else
    puts("\tDevice mode        : Normal (host-controlled)");
  putchar('\n');
}
static void show_config(rnode *r, int show_psk) {
  uint8_t bt = r->eeprom[ADDR_CONF_BT], dint = r->eeprom[ADDR_CONF_DINT],
          dadr = r->eeprom[ADDR_CONF_DADR], dblk = r->eeprom[ADDR_CONF_DBLK],
          drot = r->eeprom[ADDR_CONF_DROT], pset = r->eeprom[ADDR_CONF_PSET],
          pint = r->eeprom[ADDR_CONF_PINT], bset = r->eeprom[ADDR_CONF_BSET],
          dia = r->eeprom[ADDR_CONF_DIA], wifi = r->eeprom[ADDR_CONF_WIFI],
          wchn = r->eeprom[ADDR_CONF_WCHN];
  char ssid[40] = "", psk[40] = "", ip[24] = "", nm[24] = "";
  size_t i, n;
  if (wchn < 1 || wchn > 14)
    wchn = 1;
  if (r->cfg && r->cfg_size >= CFG_NM + 4) {
    for (n = 0, i = 0; i < 32; i++) {
      uint8_t byte = r->cfg[CFG_SSID + i];
      if (byte == 0xff || byte == 0x00)
        break;
      ssid[n++] = (char)byte;
    }
    ssid[n] = 0;
    for (n = 0, i = 0; i < 32; i++) {
      uint8_t byte = r->cfg[CFG_PSK + i];
      if (byte == 0xff || byte == 0x00)
        break;
      psk[n++] = show_psk ? (char)byte : '*';
    }
    psk[n] = 0;
    snprintf(ip, sizeof(ip), "%u.%u.%u.%u", r->cfg[CFG_IP], r->cfg[CFG_IP + 1],
             r->cfg[CFG_IP + 2], r->cfg[CFG_IP + 3]);
    snprintf(nm, sizeof(nm), "%u.%u.%u.%u", r->cfg[CFG_NM], r->cfg[CFG_NM + 1],
             r->cfg[CFG_NM + 2], r->cfg[CFG_NM + 3]);
    if (!strcmp(ip, "255.255.255.255") || !strcmp(ip, "0.0.0.0"))
      ip[0] = 0;
    if (!strcmp(nm, "255.255.255.255") || !strcmp(nm, "0.0.0.0"))
      nm[0] = 0;
    if (wifi == 0x02) {
      strcpy(ip, "10.0.0.1");
      strcpy(nm, "255.255.255.0");
    }
  }
  puts("\nDevice configuration:");
  printf("  Bluetooth              : %s\n", bt == 0x73 ? "Enabled" : "Disabled");
  if (wifi == 0x01)
    puts("  WiFi                   : Enabled (Station)");
  else if (wifi == 0x02)
    puts("  WiFi                   : Enabled (AP)");
  else
    puts("  WiFi                   : Disabled");
  if (wifi == 0x01 || wifi == 0x02) {
    printf("    Channel              : %u\n", wchn);
    printf("    SSID                 : %s\n", ssid[0] ? ssid : "Not set");
    printf("    PSK                  : %s\n", psk[0] ? psk : "Not set");
    printf("    IP Address           : %s\n", ip[0] ? ip : "DHCP");
    if (ip[0] && nm[0])
      printf("    Network Mask         : %s\n", nm);
  }
  printf("  Interference avoidance : %s\n", dia == 0x00 ? "Enabled" : "Disabled");
  printf("  Display brightness     : %u\n", dint);
  if (dadr == 0xff)
    puts("  Display address        : Default");
  else
    printf("  Display address        : %02x\n", dadr);
  if (bset == 0x73 && dblk != 0x00)
    printf("  Display blanking       : %us\n", dblk);
  else
    puts("  Display blanking       : Disabled");
  if (drot != 0xff) {
    static const char *names[] = {"Landscape", "Portrait", "Landscape 180",
                                  "Portrait 180"};
    printf("  Display rotation       : %s\n", drot < 4 ? names[drot] : "");
  } else
    puts("  Display rotation       : Default");
  if (pset == 0x73)
    printf("  Neopixel Intensity     : %u\n", pint);
  putchar('\n');
}

typedef struct options {
  const char *port, *ssid, *psk, *ip, *nm, *wifi, *display_addr, *trust_key;
  int info, config, show_psk, tnc, normal, bt_on, bt_off, bt_pair, recondition,
      ia_enable, ia_disable;
  long freq, bw, txp, sf, cr, display, timeout, rotation, np, channel;
} options;
static options opt;

static int octets(const char *text, uint8_t out[4]) {
  int a, b, c, d;
  char tail;
  if (sscanf(text, "%d.%d.%d.%d%c", &a, &b, &c, &d, &tail) != 4 || a < 0 ||
      a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255)
    return 0;
  out[0] = (uint8_t)a;
  out[1] = (uint8_t)b;
  out[2] = (uint8_t)c;
  out[3] = (uint8_t)d;
  return 1;
}
static long clamp(long v, long lo, long hi) { return v < lo ? lo : v > hi ? hi : v; }
static void be32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}
static void leave(rnode *r) {
  (void)send_byte(r, CMD_LEAVE, 0xff);
  /* give the device time to take it in before the line closes */
  {
    struct timespec t = {0, 300000000};
    nanosleep(&t, NULL);
  }
}
/* the settings, in the reference's order */
static int apply_settings(rnode *r) {
  if (opt.display >= 0) {
    long v = clamp(opt.display, 0, 255);
    printf("Setting display intensity to %ld\n", v);
    (void)send_byte(r, CMD_DISP_INT, (uint8_t)v);
  }
  if (opt.timeout >= 0) {
    long v = clamp(opt.timeout, 0, 255);
    if (v == 0)
      puts("Disabling display blanking");
    else
      printf("Setting display timeout to %ld\n", v);
    (void)send_byte(r, CMD_DISP_BLNK, (uint8_t)v);
  }
  if (opt.rotation >= 0) {
    long v = clamp(opt.rotation, 0, 3);
    printf("Setting display rotation to %ld\n", v);
    (void)send_byte(r, CMD_DISP_ROT, (uint8_t)v);
  }
  if (opt.recondition) {
    puts("Starting display reconditioning");
    (void)send_byte(r, CMD_DISP_RCND, 0x01);
  }
  if (opt.ia_enable) {
    puts("Enabling interference avoidance");
    (void)send_byte(r, CMD_DIS_IA, 0x00);
  }
  if (opt.ia_disable) {
    puts("Disabling interference avoidance");
    (void)send_byte(r, CMD_DIS_IA, 0x01);
  }
  if (opt.np >= 0) {
    long v = clamp(opt.np, 0, 255);
    printf("Setting NeoPixel intensity to %ld\n", v);
    (void)send_byte(r, CMD_NP_INT, (uint8_t)v);
  }
  if (opt.display_addr) {
    const char *h = opt.display_addr;
    unsigned v;
    char tail;
    if (!strncmp(h, "0x", 2))
      h += 2;
    if (strlen(h) == 2 && sscanf(h, "%2x%c", &v, &tail) == 1) {
      printf("Setting display address to %02x\n", v);
      (void)send_byte(r, CMD_DISP_ADR, (uint8_t)v);
      (void)send_byte(r, 0x55, 0xf8); /* reset so the address takes effect */
      return 1;
    }
    puts("Invalid display address specified");
  }
  if (opt.bt_on) {
    puts("Enabling Bluetooth...");
    (void)send_byte(r, CMD_BT_CTRL, 0x01);
    leave(r);
  }
  if (opt.bt_off) {
    puts("Disabling Bluetooth...");
    (void)send_byte(r, CMD_BT_CTRL, 0x00);
    leave(r);
  }
  if (opt.bt_pair) {
    puts("Putting device into Bluetooth pairing mode.");
    (void)send_byte(r, CMD_BT_CTRL, 0x02);
    leave(r);
  }
  if (opt.channel >= 0) {
    if (opt.channel < 1 || opt.channel > 14) {
      puts("Could not set WiFi channel: Invalid WiFi channel");
      return 1;
    }
    printf("Setting WiFi channel to %ld\n", opt.channel);
    (void)send_byte(r, CMD_WIFI_CHN, (uint8_t)opt.channel);
  }
  if (opt.ssid) {
    uint8_t data[40];
    size_t n;
    if (!strcasecmp(opt.ssid, "none")) {
      puts("Deleting WiFi SSID");
      data[0] = 0;
      n = 1;
    } else {
      n = strlen(opt.ssid);
      if (n + 1 > 33) {
        puts("Could not set WiFi SSID: Invalid SSID length");
        return 1;
      }
      printf("Setting WiFi SSID to: %s\n", opt.ssid);
      memcpy(data, opt.ssid, n + 1);
      n += 1;
    }
    (void)send_frame(r, CMD_WIFI_SSID, data, n);
  }
  if (opt.psk) {
    uint8_t data[40];
    size_t n;
    if (!strcasecmp(opt.psk, "none")) {
      puts("Deleting WiFi PSK");
      data[0] = 0;
      n = 1;
    } else {
      n = strlen(opt.psk) + 1;
      if (n < 8 || n > 33) {
        puts("Could not set WiFi PSK: Invalid psk length");
        return 1;
      }
      puts("Setting WiFi PSK");
      memcpy(data, opt.psk, n);
    }
    (void)send_frame(r, CMD_WIFI_PSK, data, n);
  }
  if (opt.ip || opt.nm) {
    const char *texts[2] = {opt.ip, opt.nm};
    uint8_t cmds[2] = {CMD_WIFI_IP, CMD_WIFI_NM};
    const char *what[2] = {"IP", "netmask"};
    int k;
    for (k = 0; k < 2; k++) {
      uint8_t v[4] = {0, 0, 0, 0};
      if (!texts[k])
        continue;
      if (!strcasecmp(texts[k], "none")) {
        printf(k ? "Deleting WiFi static netmask configuration...\n"
                 : "Setting WiFi IP to DHCP...\n");
      } else if (octets(texts[k], v)) {
        printf(k ? "Setting WiFi static netmask to: %s\n"
                 : "Setting WiFi static IP to: %s\n",
               texts[k]);
      } else {
        printf("Could not set WiFi %s: Invalid IP address\n", what[k]);
        return 1;
      }
      (void)send_frame(r, cmds[k], v, 4);
    }
  }
  if (opt.wifi) {
    uint8_t mode = 0;
    if (!strncasecmp(opt.wifi, "sta", 3))
      mode = 1;
    else if (!strncasecmp(opt.wifi, "ap", 2))
      mode = 2;
    puts(mode == 0 ? "Disabling WiFi..."
                   : mode == 1 ? "Setting WiFi to station mode"
                               : "Setting WiFi to AP mode");
    (void)send_byte(r, CMD_WIFI_MODE, mode);
  }
  return 0;
}

static void usage(void) {
  fputs("usage: reticulum-c-rnodeconf [-i] [-c [--show-psk]] [-N | -T --freq HZ --bw HZ --txp DBM --sf N --cr N]\n"
        "         [-b | -B | -p] [-D N] [-t S] [-R 0-3] [--display-addr HEX] [--recondition-display] [--np N]\n"
        "         [-x | -X] [-w off|ap|station] [--channel N] [--ssid S] [--psk S] [--ip A] [--nm A]\n"
        "         [--trust-key HEX] PORT\n",
        stderr);
}
static int number(const char *text, long *out) {
  char *end;
  long v = strtol(text, &end, 10);
  if (!*text || *end)
    return 0;
  *out = v;
  return 1;
}
int main(int argc, char **argv) {
  int i, rc = 0;
  rnode r;
  memset(&r, 0, sizeof(r));
  opt.display = opt.timeout = opt.rotation = opt.np = opt.channel = -1;
  opt.freq = opt.bw = opt.txp = opt.sf = opt.cr = -1;
  for (i = 1; i < argc; ++i) {
    const char *a = argv[i];
#define VALUE (i + 1 < argc ? argv[++i] : (usage(), exit(2), (char *)NULL))
#define NUM(field)                                                             \
  do {                                                                         \
    if (!number(VALUE, &(field)))                                              \
      return usage(), 2;                                                       \
  } while (0)
    if (!strcmp(a, "-i") || !strcmp(a, "--info"))
      opt.info = 1;
    else if (!strcmp(a, "-c") || !strcmp(a, "--config"))
      opt.config = 1;
    else if (!strcmp(a, "--show-psk"))
      opt.show_psk = 1;
    else if (!strcmp(a, "-T") || !strcmp(a, "--tnc"))
      opt.tnc = 1;
    else if (!strcmp(a, "-N") || !strcmp(a, "--normal"))
      opt.normal = 1;
    else if (!strcmp(a, "-b") || !strcmp(a, "--bluetooth-on"))
      opt.bt_on = 1;
    else if (!strcmp(a, "-B") || !strcmp(a, "--bluetooth-off"))
      opt.bt_off = 1;
    else if (!strcmp(a, "-p") || !strcmp(a, "--bluetooth-pair"))
      opt.bt_pair = 1;
    else if (!strcmp(a, "-x") || !strcmp(a, "--ia-enable"))
      opt.ia_enable = 1;
    else if (!strcmp(a, "-X") || !strcmp(a, "--ia-disable"))
      opt.ia_disable = 1;
    else if (!strcmp(a, "--recondition-display"))
      opt.recondition = 1;
    else if (!strcmp(a, "--freq"))
      NUM(opt.freq);
    else if (!strcmp(a, "--bw"))
      NUM(opt.bw);
    else if (!strcmp(a, "--txp"))
      NUM(opt.txp);
    else if (!strcmp(a, "--sf"))
      NUM(opt.sf);
    else if (!strcmp(a, "--cr"))
      NUM(opt.cr);
    else if (!strcmp(a, "-D") || !strcmp(a, "--display"))
      NUM(opt.display);
    else if (!strcmp(a, "-t") || !strcmp(a, "--timeout"))
      NUM(opt.timeout);
    else if (!strcmp(a, "-R") || !strcmp(a, "--rotation"))
      NUM(opt.rotation);
    else if (!strcmp(a, "--np"))
      NUM(opt.np);
    else if (!strcmp(a, "--channel"))
      NUM(opt.channel);
    else if (!strcmp(a, "--display-addr"))
      opt.display_addr = VALUE;
    else if (!strcmp(a, "-w") || !strcmp(a, "--wifi"))
      opt.wifi = VALUE;
    else if (!strcmp(a, "--ssid"))
      opt.ssid = VALUE;
    else if (!strcmp(a, "--psk"))
      opt.psk = VALUE;
    else if (!strcmp(a, "--ip"))
      opt.ip = VALUE;
    else if (!strcmp(a, "--nm"))
      opt.nm = VALUE;
    else if (!strcmp(a, "--trust-key")) {
      if (r.extra_key_count < 8)
        r.extra_keys[r.extra_key_count++] = VALUE;
      else
        return usage(), 2;
    } else if (a[0] != '-' && !opt.port)
      opt.port = a;
    else
      return usage(), 2;
  }
  if (!opt.port)
    return usage(), 2;
  if (!(opt.info || opt.config || opt.tnc || opt.normal || opt.bt_on ||
        opt.bt_off || opt.bt_pair || opt.recondition || opt.ia_enable ||
        opt.ia_disable || opt.display >= 0 || opt.timeout >= 0 ||
        opt.rotation >= 0 || opt.np >= 0 || opt.channel >= 0 ||
        opt.display_addr || opt.wifi || opt.ssid || opt.psk || opt.ip || opt.nm))
    return usage(), 2;
  r.fd = open_port(opt.port);
  if (r.fd < 0) {
    fprintf(stderr, "Could not open the serial port %s: %s\n", opt.port,
            strerror(errno));
    return 1;
  }
  if (!probe(&r)) {
    puts("Serial port opened, but RNode did not respond. Is a valid firmware installed?");
    puts("Got invalid response while detecting device");
    close(r.fd);
    return 1;
  }
  if (!download_eeprom(&r)) {
    puts("Could not download EEPROM from device. Is a valid firmware installed?");
    close(r.fd);
    return 1;
  }
  {
    int parsed = parse_eeprom(&r);
    if (parsed < 0) {
      puts("EEPROM checksum mismatch");
      close(r.fd);
      return 1;
    }
  }
  if (opt.config) {
    (void)send_byte(&r, CMD_CFG_READ, 0x00);
    listen_for(&r, 3000, cfg_done);
    show_config(&r, opt.show_psk);
    leave(&r);
  }
  if (apply_settings(&r))
    rc = 1;
  if (opt.info) {
    if (r.provisioned)
      show_info(&r);
    else
      puts("EEPROM is invalid, no further information available");
  }
  if (r.provisioned && !rc) {
    if (opt.normal) {
      (void)send_byte(&r, CMD_CONF_DELETE, 0x00);
      puts("Device set to normal (host-controlled) operating mode");
    } else if (opt.tnc) {
      if (opt.freq < 0 || opt.bw < 0 || opt.txp < 0 || opt.sf < 0 || opt.cr < 0) {
        puts("TNC mode needs --freq, --bw, --txp, --sf and --cr");
        rc = 2;
      } else if (opt.txp > 255 || opt.sf < 5 || opt.sf > 12 || opt.cr < 5 ||
                 opt.cr > 8) {
        puts("Invalid radio parameters");
        rc = 2;
      } else {
        uint8_t v[4];
        be32(v, (uint32_t)opt.freq);
        (void)send_frame(&r, CMD_FREQUENCY, v, 4);
        be32(v, (uint32_t)opt.bw);
        (void)send_frame(&r, CMD_BANDWIDTH, v, 4);
        (void)send_byte(&r, CMD_TXPOWER, (uint8_t)opt.txp);
        (void)send_byte(&r, CMD_SF, (uint8_t)opt.sf);
        (void)send_byte(&r, CMD_CR, (uint8_t)opt.cr);
        (void)send_byte(&r, CMD_RADIO_STATE, 0x01);
        {
          struct timespec t = {0, 500000000};
          nanosleep(&t, NULL);
        }
        (void)send_byte(&r, CMD_CONF_SAVE, 0x00);
        puts("Device set to TNC operating mode");
        {
          struct timespec t = {1, 0};
          nanosleep(&t, NULL);
        }
      }
    }
  } else if (!r.provisioned && (opt.tnc || opt.normal)) {
    puts("This device contains a valid firmware, but EEPROM is invalid.");
    rc = 1;
  }
  free(r.eeprom);
  free(r.cfg);
  close(r.fd);
  return rc;
}
