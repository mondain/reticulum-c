#ifndef RNC_MCU_NET_H
#define RNC_MCU_NET_H
/*
 * Portable helpers of the Wi-Fi TCP transport, shared by the ESP-IDF firmware, the
 * Arduino/PlatformIO sketch and the host harness (--tcp). Header only, C and C++,
 * no platform headers and no sockets, so the logic can be unit tested on the host
 * (mcu/tests/test_net.c).
 *
 *   rnc_mcu_backoff   reconnect delays: exponential with a little jitter, capped
 *   rnc_mcu_txq       bounded output byte queue; a frame is queued whole or refused
 *   rnc_mcu_cfg       the provisioning settings (mode, ssid, password, host, port) and
 *                     the LoRa radio settings (lora.mode, lora.freq, lora.bw, lora.sf,
 *                     lora.cr, lora.txp, lora.airtime: rnc_lora_cfg.h)
 *   rnc_mcu_console   the line console that edits them: help, get, set, clear, save,
 *                     reboot
 *
 * SECURITY: the settings include a Wi-Fi password. The console never prints it.
 * Where the settings are stored (NVS, Preferences) is up to the port.
 */
#include "rnc_lora_cfg.h"
#include "rnc_mcu_app.h"
#include <reticulum_c/rnc_netstamp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- reconnect backoff ---------------------------------------------------- */
typedef struct rnc_mcu_backoff {
  uint32_t min_ms, max_ms, step_ms;
} rnc_mcu_backoff;

static inline void rnc_mcu_backoff_init(rnc_mcu_backoff *b, uint32_t min_ms, uint32_t max_ms) {
  if (min_ms == 0)
    min_ms = 1;
  if (max_ms < min_ms)
    max_ms = min_ms;
  b->min_ms = min_ms;
  b->max_ms = max_ms;
  b->step_ms = min_ms;
}
/* Call after a successful connection. */
static inline void rnc_mcu_backoff_reset(rnc_mcu_backoff *b) { b->step_ms = b->min_ms; }
/* The delay before the next attempt, then doubles the step up to the cap. `random` is
 * any 32 bit value (a hardware random number): the delay is the step minus up to a
 * quarter of it, so that many boards that lost the same server do not retry in step. */
static inline uint32_t rnc_mcu_backoff_next(rnc_mcu_backoff *b, uint32_t random) {
  uint32_t step = b->step_ms, delay = step - (step / 4u ? random % (step / 4u + 1u) : 0u);
  b->step_ms = step > b->max_ms / 2u ? b->max_ms : step * 2u;
  return delay;
}

/* ---- bounded output queue ------------------------------------------------- */
typedef struct rnc_mcu_txq {
  uint8_t *buffer; /* caller supplied storage */
  size_t capacity, head, size;
  uint32_t dropped; /* frames refused because they did not fit */
} rnc_mcu_txq;

static inline void rnc_mcu_txq_init(rnc_mcu_txq *q, uint8_t *storage, size_t capacity) {
  q->buffer = storage;
  q->capacity = capacity;
  q->head = q->size = 0;
  q->dropped = 0;
}
static inline size_t rnc_mcu_txq_free(const rnc_mcu_txq *q) { return q->capacity - q->size; }
/* Queues all `size` bytes (one HDLC frame) or none: a half frame in the stream would
 * cost the peer two frames. Returns 1 if queued, 0 if refused (counted in `dropped`). */
static inline int rnc_mcu_txq_push(rnc_mcu_txq *q, const uint8_t *data, size_t size) {
  size_t tail, first;
  if (size > rnc_mcu_txq_free(q)) {
    q->dropped++;
    return 0;
  }
  tail = (q->head + q->size) % q->capacity;
  first = q->capacity - tail;
  if (first > size)
    first = size;
  memcpy(q->buffer + tail, data, first);
  if (size > first)
    memcpy(q->buffer, data + first, size - first);
  q->size += size;
  return 1;
}
/* The longest contiguous run at the head, for send(); 0 when empty. */
static inline size_t rnc_mcu_txq_peek(const rnc_mcu_txq *q, const uint8_t **data) {
  size_t run = q->capacity - q->head;
  *data = q->buffer + q->head;
  return run < q->size ? run : q->size;
}
static inline void rnc_mcu_txq_consume(rnc_mcu_txq *q, size_t size) {
  if (size > q->size)
    size = q->size;
  q->head = (q->head + size) % q->capacity;
  q->size -= size;
  if (!q->size)
    q->head = 0;
}
/* A lost connection takes the queued bytes with it. */
static inline void rnc_mcu_txq_clear(rnc_mcu_txq *q) { q->head = q->size = 0; }

/* ---- provisioning settings ------------------------------------------------ */
#define RNC_MCU_MODE_SERIAL "serial"
#define RNC_MCU_MODE_WIFI "wifi"
#define RNC_MCU_MODE_RNODE "rnode" /* a LoRa modem for a host (mcu/radio/rnc_rnode.h) */
#define RNC_MCU_DEFAULT_PORT 4242 /* the Reticulum TCPServerInterface default */

typedef struct rnc_mcu_cfg {
  char mode[8];       /* "serial" (the default), "wifi" or "rnode" */
  char ssid[33];      /* 1..32 bytes */
  char password[65];  /* empty (open network) or 8..63 characters */
  char host[64];      /* the node's name or address */
  char ble_pin[7];    /* RNode mode over Bluetooth: six digits, or empty (Bluetooth off) */
  uint16_t port;
  rnc_lora_cfg lora;  /* the radio: off until explicitly configured (rnc_lora_cfg.h) */
  /* The destination stamp (RNS 1.6). A stamp depends only on the board's public data, so it is searched elsewhere
   * (reticulum-c-flash, the web flasher) and loaded here: `get stamp.material` shows what to stamp, `set stamp HEX`
   * takes 14 bytes that meet `stamp_value` over it. The runtime fields are filled in by the port before the console
   * runs (rnc_mcu_stamp_prepare) and are not stored with the other settings; a new stamp is stored by the port on
   * save under RNC_MCU_KEY_STAMP. */
  double stamp_value;       /* the value a stamp must have; 25.0, the reference's default */
  char stamp_material[181]; /* hex of destination || public key || name hash, empty before the identity exists */
  char stamp_status[8];     /* "none", "valid" or "stale" (a stored stamp that does not fit this identity) */
  uint8_t stamp_new[14];    /* set by "set stamp": all zero means remove the stored stamp */
  int stamp_new_set;
} rnc_mcu_cfg;

static inline void rnc_mcu_cfg_init(rnc_mcu_cfg *c) {
  memset(c, 0, sizeof(*c));
  memcpy(c->mode, RNC_MCU_MODE_SERIAL, sizeof(RNC_MCU_MODE_SERIAL));
  c->port = RNC_MCU_DEFAULT_PORT;
  rnc_lora_cfg_init(&c->lora);
  c->stamp_value = 25.0;
}
static inline int rnc_mcu_cfg_wifi_mode(const rnc_mcu_cfg *c) {
  return !strcmp(c->mode, RNC_MCU_MODE_WIFI);
}
/* 1 when a Bluetooth PIN is set: there is no default PIN and Bluetooth stays off without one. */
static inline int rnc_mcu_cfg_ble_ready(const rnc_mcu_cfg *c) { return strlen(c->ble_pin) == 6u; }
static inline int rnc_mcu_cfg_rnode_mode(const rnc_mcu_cfg *c) {
  return !strcmp(c->mode, RNC_MCU_MODE_RNODE);
}
/* 1 when the settings can start a Wi-Fi connection (the mode is not looked at). */
static inline int rnc_mcu_cfg_wifi_ready(const rnc_mcu_cfg *c) {
  size_t p = strlen(c->password);
  return c->ssid[0] != 0 && c->host[0] != 0 && c->port != 0 && (p == 0 || (p >= 8 && p <= 63));
}

static inline int rnc_mcu_hex_byte(const char *p) {
  int v = 0, i;
  for (i = 0; i < 2; i++) {
    char ch = p[i];
    v <<= 4;
    if (ch >= '0' && ch <= '9')
      v |= ch - '0';
    else if (ch >= 'a' && ch <= 'f')
      v |= ch - 'a' + 10;
    else if (ch >= 'A' && ch <= 'F')
      v |= ch - 'A' + 10;
    else
      return -1;
  }
  return v;
}
/* "set stamp": 28 hex digits that meet the stamp value over the board's own material, or "clear". */
static inline int rnc_mcu_cfg_set_stamp(rnc_mcu_cfg *c, const char *value) {
  uint8_t stamp[14], material[90];
  size_t i;
  if (!strcmp(value, "clear")) {
    memset(c->stamp_new, 0, sizeof(c->stamp_new));
    c->stamp_new_set = 1;
    return 0;
  }
  if (strlen(value) != 28u || strlen(c->stamp_material) != 180u)
    return -1;
  for (i = 0; i < sizeof(stamp); i++) {
    int v = rnc_mcu_hex_byte(value + 2 * i);
    if (v < 0)
      return -1;
    stamp[i] = (uint8_t)v;
  }
  for (i = 0; i < sizeof(material); i++) {
    int v = rnc_mcu_hex_byte(c->stamp_material + 2 * i);
    if (v < 0)
      return -1;
    material[i] = (uint8_t)v;
  }
  if (!rnc_netstamp_valid(material, sizeof(material), stamp, sizeof(stamp), c->stamp_value))
    return -1;
  memcpy(c->stamp_new, stamp, sizeof(stamp));
  c->stamp_new_set = 1;
  return 0;
}
static inline int rnc_mcu_cfg_set(rnc_mcu_cfg *c, const char *key, const char *value) {
  size_t n = strlen(value);
  if (!strcmp(key, "stamp"))
    return rnc_mcu_cfg_set_stamp(c, value);
  if (!strncmp(key, "lora.", 5)) {
    if (rnc_lora_cfg_set(&c->lora, key + 5, value) != 0)
      return -1;
    return 0;
  }
  if (!strcmp(key, "ble.pin")) {
    size_t i;
    if (n != 0u && n != 6u)
      return -1;
    for (i = 0; i < n; i++)
      if (value[i] < '0' || value[i] > '9')
        return -1;
    memset(c->ble_pin, 0, sizeof(c->ble_pin));
    memcpy(c->ble_pin, value, n);
    return 0;
  }
  if (!strcmp(key, "mode")) {
    if (strcmp(value, RNC_MCU_MODE_SERIAL) && strcmp(value, RNC_MCU_MODE_WIFI) &&
        strcmp(value, RNC_MCU_MODE_RNODE))
      return -1;
    memset(c->mode, 0, sizeof(c->mode));
    memcpy(c->mode, value, n);
  } else if (!strcmp(key, "ssid")) {
    if (n == 0 || n > 32)
      return -1;
    memset(c->ssid, 0, sizeof(c->ssid));
    memcpy(c->ssid, value, n);
  } else if (!strcmp(key, "password")) {
    if (n != 0 && (n < 8 || n > 63))
      return -1;
    memset(c->password, 0, sizeof(c->password));
    memcpy(c->password, value, n);
  } else if (!strcmp(key, "host")) {
    size_t i;
    if (n == 0 || n > 63)
      return -1;
    for (i = 0; i < n; i++) /* a name or an address: no spaces or control characters */
      if ((unsigned char)value[i] <= ' ' || (unsigned char)value[i] >= 127)
        return -1;
    memset(c->host, 0, sizeof(c->host));
    memcpy(c->host, value, n);
  } else if (!strcmp(key, "port")) {
    unsigned long v = 0;
    size_t i;
    if (n == 0 || n > 5)
      return -1;
    for (i = 0; i < n; i++) {
      if (value[i] < '0' || value[i] > '9')
        return -1;
      v = v * 10u + (unsigned long)(value[i] - '0');
    }
    if (v == 0 || v > 65535ul)
      return -1;
    c->port = (uint16_t)v;
  } else {
    return -1;
  }
  return 0;
}

/* ---- the destination stamp: what the console shows, and where the stamp is kept ------------------------ */
/* Fills the runtime stamp fields of `cfg` from the persisted identity and stamp, before the console runs. Without
 * an identity (the very first boot, which creates it) the material stays empty. */
static inline void rnc_mcu_stamp_prepare(rnc_mcu_cfg *cfg, const rnc_mcu_platform *platform) {
  uint8_t key[64], name_hash[10], address[16], material[90], stamp[14];
  rnc_identity id;
  size_t i;
  int n;
  memset(cfg->stamp_material, 0, sizeof(cfg->stamp_material));
  memcpy(cfg->stamp_status, "none", 5);
  if (!platform || !platform->load)
    return;
  n = platform->load(platform->context, RNC_MCU_KEY_IDENTITY, key, sizeof(key));
  if (n != (int)sizeof(key) || rnc_identity_from_private(&id, key) != RNC_OK ||
      rnc_destination_hash(RNC_MCU_APP_NAME, &id, name_hash, address) != RNC_OK) {
    {
      volatile uint8_t *k = key;
      for (i = 0; i < sizeof(key); i++)
        k[i] = 0;
    }
    return;
  }
  rnc_netstamp_announce_material(address, id.public_key, name_hash, material);
  { /* the private key was only needed to learn the public one */
    volatile uint8_t *k = key;
    for (i = 0; i < sizeof(key); i++)
      k[i] = 0;
    rnc_identity_clear(&id);
  }
  for (i = 0; i < sizeof(material); i++)
    (void)snprintf(cfg->stamp_material + 2 * i, 3, "%02x", material[i]);
  n = platform->load(platform->context, RNC_MCU_KEY_STAMP, stamp, sizeof(stamp));
  if (n == (int)sizeof(stamp)) {
    uint8_t any = 0;
    for (i = 0; i < sizeof(stamp); i++)
      any |= stamp[i];
    if (any)
      memcpy(cfg->stamp_status,
             rnc_netstamp_valid(material, sizeof(material), stamp, sizeof(stamp), cfg->stamp_value) ? "valid" : "stale",
             6);
  }
}
/* After the port stored the stamp that "set stamp" took: the status the console reports follows at once. */
static inline void rnc_mcu_stamp_stored(rnc_mcu_cfg *cfg) {
  size_t i;
  uint8_t any = 0;
  for (i = 0; i < sizeof(cfg->stamp_new); i++)
    any |= cfg->stamp_new[i];
  memcpy(cfg->stamp_status, any ? "valid" : "none", any ? 6 : 5);
  cfg->stamp_new_set = 0;
}
/* Stores a stamp taken by "set stamp" (all zero removes it); 0 on success. */
static inline int rnc_mcu_stamp_store(const rnc_mcu_platform *platform, const uint8_t stamp[14]) {
  if (!platform || !platform->persist)
    return -1;
  return platform->persist(platform->context, RNC_MCU_KEY_STAMP, stamp, 14);
}

/* ---- the line console ------------------------------------------------------ */
#define RNC_MCU_CONSOLE_LINE 160u
#define RNC_MCU_CONSOLE_SAVE 1u   /* returned by _feed: store the settings now */
#define RNC_MCU_CONSOLE_REBOOT 2u /* returned by _feed: restart the board */

typedef struct rnc_mcu_console {
  char line[RNC_MCU_CONSOLE_LINE];
  size_t length;
  int overflow;
} rnc_mcu_console;

static inline void rnc_mcu_console_init(rnc_mcu_console *c) { memset(c, 0, sizeof(*c)); }

static inline void rnc_mcu_console_get(const rnc_mcu_cfg *cfg, const char *key, char *out,
                                       size_t size) {
  char tmp[160], lora[256];
  tmp[0] = 0;
  if (key && !strncmp(key, "lora.", 5)) {
    rnc_lora_cfg_get(&cfg->lora, key + 5, out, size);
    return;
  }
  if (!key || !*key) {
    rnc_lora_cfg_get(&cfg->lora, NULL, lora, sizeof(lora));
    (void)snprintf(tmp, sizeof(tmp), "mode=%s\nssid=%s\npassword=%s\nhost=%s\nport=%u", cfg->mode,
                   cfg->ssid, cfg->password[0] ? "(set)" : "(empty)", cfg->host,
                   (unsigned)cfg->port);
    (void)snprintf(out, size, "%s\nble.pin=%s\n%s", tmp, cfg->ble_pin[0] ? "(set)" : "(empty)", lora);
    return;
  } else if (!strcmp(key, "mode")) {
    (void)snprintf(tmp, sizeof(tmp), "mode=%s", cfg->mode);
  } else if (!strcmp(key, "ssid")) {
    (void)snprintf(tmp, sizeof(tmp), "ssid=%s", cfg->ssid);
  } else if (!strcmp(key, "stamp.material")) {
    (void)snprintf(out, size, "stamp.material=%s",
                   cfg->stamp_material[0] ? cfg->stamp_material : "(not yet: boot once to create the identity)");
    return;
  } else if (!strcmp(key, "stamp.status") || !strcmp(key, "stamp")) {
    (void)snprintf(tmp, sizeof(tmp), "stamp.status=%s", cfg->stamp_status[0] ? cfg->stamp_status : "none");
  } else if (!strcmp(key, "ble.pin")) { /* never the value */
    (void)snprintf(tmp, sizeof(tmp), "ble.pin=%s", cfg->ble_pin[0] ? "(set)" : "(empty)");
  } else if (!strcmp(key, "password")) { /* never the value */
    (void)snprintf(tmp, sizeof(tmp), "password=%s", cfg->password[0] ? "(set)" : "(empty)");
  } else if (!strcmp(key, "host")) {
    (void)snprintf(tmp, sizeof(tmp), "host=%s", cfg->host);
  } else if (!strcmp(key, "port")) {
    (void)snprintf(tmp, sizeof(tmp), "port=%u", (unsigned)cfg->port);
  } else {
    (void)snprintf(tmp, sizeof(tmp), "error: unknown key");
  }
  (void)snprintf(out, size, "%s", tmp);
}

/* Handles one finished line; returns RNC_MCU_CONSOLE_* actions. */
static inline unsigned rnc_mcu_console_line(rnc_mcu_console *c, rnc_mcu_cfg *cfg, char *reply,
                                            size_t reply_size) {
  char *cmd = c->line, *arg;
  unsigned actions = 0;
  while (*cmd == ' ' || *cmd == '\t')
    cmd++;
  arg = cmd;
  while (*arg && *arg != ' ' && *arg != '\t')
    arg++;
  if (*arg) {
    *arg++ = 0;
    while (*arg == ' ' || *arg == '\t')
      arg++;
  }
  if (!*cmd) {
    reply[0] = 0;
  } else if (!strcmp(cmd, "help")) {
    (void)snprintf(reply, reply_size,
                   "commands: get [key] | set key value | clear | save | reboot\n"
                   "keys: mode (serial|wifi|rnode) ssid password host port ble.pin (six digits)\n"
                   "LoRa: lora.mode (off|leaf|gateway) lora.freq lora.bw lora.sf lora.cr lora.txp\n"
                   "lora.airtime; the radio stays off until mode, freq, bw, sf, cr and txp are set\n"
                   "stamp.material (read) and stamp (set HEX|clear): the RNS 1.6 destination stamp\n"
                   "set mode wifi, fill in the rest, then save and reboot");
  } else if (!strcmp(cmd, "get")) {
    rnc_mcu_console_get(cfg, arg, reply, reply_size);
  } else if (!strcmp(cmd, "set")) {
    char *value = arg;
    while (*value && *value != ' ' && *value != '\t')
      value++;
    if (*value) {
      *value++ = 0;
      while (*value == ' ' || *value == '\t')
        value++;
    }
    if (!*arg || rnc_mcu_cfg_set(cfg, arg, value) != 0)
      (void)snprintf(reply, reply_size, "error: refused (see help)");
    else
      (void)snprintf(reply, reply_size, "ok (not stored until save)");
  } else if (!strcmp(cmd, "clear")) {
    char material[sizeof(cfg->stamp_material)], status[sizeof(cfg->stamp_status)];
    memcpy(material, cfg->stamp_material, sizeof(material)); /* what the port learned about the identity stays */
    memcpy(status, cfg->stamp_status, sizeof(status));
    rnc_mcu_cfg_init(cfg);
    memcpy(cfg->stamp_material, material, sizeof(material));
    memcpy(cfg->stamp_status, status, sizeof(status));
    (void)snprintf(reply, reply_size, "ok: defaults restored (not stored until save)");
  } else if (!strcmp(cmd, "save")) {
    actions = RNC_MCU_CONSOLE_SAVE;
    (void)snprintf(reply, reply_size, "saving");
  } else if (!strcmp(cmd, "reboot")) {
    actions = RNC_MCU_CONSOLE_REBOOT;
    (void)snprintf(reply, reply_size, "rebooting");
  } else {
    (void)snprintf(reply, reply_size, "error: unknown command (try help)");
  }
  return actions;
}

/* Feeds one input byte. A line ends with LF or CR (CRLF terminals work: the empty
 * line after CR is ignored). Returns RNC_MCU_CONSOLE_* actions for the finished line,
 * 0 otherwise; `reply` (no trailing newline) is written when a line finished and the
 * reply is not empty. */
static inline unsigned rnc_mcu_console_feed(rnc_mcu_console *c, rnc_mcu_cfg *cfg, uint8_t byte,
                                            char *reply, size_t reply_size) {
  unsigned actions;
  if (byte == '\r' || byte == '\n') {
    if (c->overflow) {
      (void)snprintf(reply, reply_size, "error: line too long");
      actions = 0;
    } else if (c->length == 0) {
      return 0; /* the LF of a CRLF, or an empty line: nothing to answer */
    } else {
      c->line[c->length] = 0;
      actions = rnc_mcu_console_line(c, cfg, reply, reply_size);
    }
    c->length = 0;
    c->overflow = 0;
    return actions;
  }
  if (byte < ' ' || byte == 127) /* ignore control characters, backspace excepted */
  {
    if ((byte == 8 || byte == 127) && c->length && !c->overflow)
      c->length--;
    return 0;
  }
  if (c->length + 1 < sizeof(c->line))
    c->line[c->length++] = (char)byte;
  else
    c->overflow = 1;
  return 0;
}

#ifdef __cplusplus
}
#endif
#endif
