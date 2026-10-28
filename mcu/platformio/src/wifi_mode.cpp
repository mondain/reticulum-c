#include "wifi_mode.h"

#if defined(ARDUINO_ARCH_ESP32)
#include <Arduino.h>
#include <Preferences.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <errno.h>
#include <esp_random.h>
#include <lwip/sockets.h>
#include <string.h>

#define NET_NAMESPACE "rnc_net"
#define QUEUE_BYTES 4096u
#define BACKOFF_MIN_MS 500u
#define BACKOFF_MAX_MS 30000u
#define CONNECT_TIMEOUT_MS 3000u // WiFiClient::connect blocks the Reticulum task this long
#define WIFI_TIMEOUT_MS 30000u

// ---- settings -------------------------------------------------------------
static void copy_string(char *out, size_t size, const String &value) {
  if (value.length() > 0 && value.length() < size) {
    memset(out, 0, size);
    memcpy(out, value.c_str(), value.length());
  }
}

bool rnc_settings_load(rnc_mcu_cfg *cfg) {
  Preferences prefs;
  bool stored = false;
  rnc_mcu_cfg_init(cfg);
  // read-only open fails while the namespace does not exist yet: the defaults apply
  if (prefs.begin(NET_NAMESPACE, true)) {
    String mode = prefs.getString("mode", "");
    if (mode.length() > 0) {
      stored = true;
      (void)rnc_mcu_cfg_set(cfg, "mode", mode.c_str());
    }
    copy_string(cfg->ssid, sizeof(cfg->ssid), prefs.getString("ssid", ""));
    copy_string(cfg->password, sizeof(cfg->password), prefs.getString("password", ""));
    copy_string(cfg->host, sizeof(cfg->host), prefs.getString("host", ""));
    uint16_t port = prefs.getUShort("port", 0);
    if (port != 0)
      cfg->port = port;
    // the radio: nothing is assumed; a transmit setting counts only if it was stored with its
    // "set" bit, and it passes the same checks as at the console
    {
      char text[16];
      String lmode = prefs.getString("lora_mode", "");
      if (lmode.length() > 0)
        (void)rnc_lora_cfg_set(&cfg->lora, "mode", lmode.c_str());
      uint8_t set = prefs.getUChar("lora_set", 0);
      if (set & RNC_LORA_SET_FREQ) {
        snprintf(text, sizeof(text), "%lu", (unsigned long)prefs.getULong("lora_freq", 0));
        (void)rnc_lora_cfg_set(&cfg->lora, "freq", text);
      }
      if (set & RNC_LORA_SET_BW) {
        snprintf(text, sizeof(text), "%lu", (unsigned long)prefs.getULong("lora_bw", 0));
        (void)rnc_lora_cfg_set(&cfg->lora, "bw", text);
      }
      if (set & RNC_LORA_SET_SF) {
        snprintf(text, sizeof(text), "%u", (unsigned)prefs.getUChar("lora_sf", 0));
        (void)rnc_lora_cfg_set(&cfg->lora, "sf", text);
      }
      if (set & RNC_LORA_SET_CR) {
        snprintf(text, sizeof(text), "%u", (unsigned)prefs.getUChar("lora_cr", 0));
        (void)rnc_lora_cfg_set(&cfg->lora, "cr", text);
      }
      if (set & RNC_LORA_SET_TXP) {
        snprintf(text, sizeof(text), "%d", (int)prefs.getChar("lora_txp", 0));
        (void)rnc_lora_cfg_set(&cfg->lora, "txp", text);
      }
      uint16_t air = prefs.getUShort("lora_air", 0);
      if (air >= 1 && air <= 10000)
        cfg->lora.airtime = air;
    }
    prefs.end();
  }
#if defined(RNC_MCU_DEV_WIFI_SSID)
  if (!stored) { // DEVELOPER BUILD ONLY: the credentials are inside the firmware image
    (void)rnc_mcu_cfg_set(cfg, "mode", "wifi");
    (void)rnc_mcu_cfg_set(cfg, "ssid", RNC_MCU_DEV_WIFI_SSID);
#if defined(RNC_MCU_DEV_WIFI_PASSWORD)
    (void)rnc_mcu_cfg_set(cfg, "password", RNC_MCU_DEV_WIFI_PASSWORD);
#endif
#if defined(RNC_MCU_DEV_WIFI_HOST)
    (void)rnc_mcu_cfg_set(cfg, "host", RNC_MCU_DEV_WIFI_HOST);
#endif
#if defined(RNC_MCU_DEV_WIFI_PORT)
    cfg->port = RNC_MCU_DEV_WIFI_PORT;
#endif
    return true;
  }
#endif
  (void)stored;
  return false;
}

bool rnc_settings_save(const rnc_mcu_cfg *cfg) {
  Preferences prefs;
  if (!prefs.begin(NET_NAMESPACE, false))
    return false;
  bool ok = prefs.putString("mode", cfg->mode) > 0;
  ok = (prefs.putString("ssid", cfg->ssid) > 0 || !cfg->ssid[0]) && ok;
  ok = (prefs.putString("password", cfg->password) > 0 || !cfg->password[0]) && ok;
  ok = (prefs.putString("host", cfg->host) > 0 || !cfg->host[0]) && ok;
  ok = prefs.putUShort("port", cfg->port) == 2 && ok;
  ok = prefs.putString("lora_mode", cfg->lora.mode == RNC_LORA_MODE_LEAF      ? "leaf"
                                    : cfg->lora.mode == RNC_LORA_MODE_GATEWAY ? "gateway"
                                                                               : "off") > 0 && ok;
  ok = prefs.putUChar("lora_set", cfg->lora.set) == 1 && ok;
  if (cfg->lora.set & RNC_LORA_SET_FREQ)
    ok = prefs.putULong("lora_freq", cfg->lora.freq_hz) == 4 && ok;
  if (cfg->lora.set & RNC_LORA_SET_BW)
    ok = prefs.putULong("lora_bw", cfg->lora.bw_hz) == 4 && ok;
  if (cfg->lora.set & RNC_LORA_SET_SF)
    ok = prefs.putUChar("lora_sf", cfg->lora.sf) == 1 && ok;
  if (cfg->lora.set & RNC_LORA_SET_CR)
    ok = prefs.putUChar("lora_cr", cfg->lora.cr) == 1 && ok;
  if (cfg->lora.set & RNC_LORA_SET_TXP)
    ok = prefs.putChar("lora_txp", cfg->lora.txp_dbm) == 1 && ok;
  ok = prefs.putUShort("lora_air", cfg->lora.airtime) == 2 && ok;
  prefs.end();
  return ok;
}

// ---- provisioning -----------------------------------------------------------
bool rnc_provision_requested(unsigned window_ms) {
  static const char entry[] = "rnc-config";
  char line[24];
  size_t length = 0;
  unsigned low_ms = 0;
  if (window_ms == 0)
    return false;
#if RNC_MCU_BOOT_PIN >= 0
  pinMode(RNC_MCU_BOOT_PIN, INPUT_PULLUP);
#endif
  for (unsigned elapsed = 0; elapsed < window_ms; elapsed += 10) {
    while (Serial.available() > 0) {
      int c = Serial.read();
      if (c == '\r' || c == '\n') {
        line[length] = 0;
        if (length == sizeof(entry) - 1 && !memcmp(line, entry, length))
          return true;
        length = 0;
      } else if (c >= 0 && length + 1 < sizeof(line)) {
        line[length++] = (char)c;
      } else {
        length = 0;
      }
    }
#if RNC_MCU_BOOT_PIN >= 0
    low_ms = digitalRead(RNC_MCU_BOOT_PIN) == LOW ? low_ms + 10 : 0;
    if (low_ms >= 300)
      return true;
#endif
    delay(10);
  }
  (void)low_ms;
  return false;
}

static void print(const char *text) {
  for (; *text; text++) {
    if (*text == '\n')
      Serial.write('\r');
    Serial.write((uint8_t)*text);
  }
}

void rnc_provision_console(rnc_mcu_cfg *cfg, const char *reason) {
  rnc_mcu_console con;
  char reply[512];
  rnc_mcu_console_init(&con);
  print("\n\nreticulum-c provisioning console\n");
  print(reason);
  print("\nThe Reticulum node is not running. Type help. Settings are stored with save, and "
        "used after reboot.\n");
  rnc_mcu_console_get(cfg, NULL, reply, sizeof(reply));
  print(reply);
  print("\nrnc> ");
  for (;;) {
    if (Serial.available() <= 0) {
      delay(10);
      continue;
    }
    uint8_t byte = (uint8_t)Serial.read();
    if (byte == '\r' || byte == '\n') {
      size_t had = con.length;
      reply[0] = 0;
      unsigned actions = rnc_mcu_console_feed(&con, cfg, byte, reply, sizeof(reply));
      if (had || reply[0]) {
        print("\n");
        if (reply[0]) {
          print(reply);
          print("\n");
        }
      }
      if (actions & RNC_MCU_CONSOLE_SAVE)
        print(rnc_settings_save(cfg) ? "stored\n" : "error: cannot store\n");
      if (actions & RNC_MCU_CONSOLE_REBOOT) {
        delay(100);
        ESP.restart();
      }
      if (had)
        print("rnc> ");
    } else {
      size_t before = con.length;
      bool hide = con.length >= 12 && !strncmp(con.line, "set password", 12);
      reply[0] = 0;
      (void)rnc_mcu_console_feed(&con, cfg, byte, reply, sizeof(reply));
      if (con.length > before) // accepted: echo it (the password as *)
        Serial.write(hide ? (uint8_t)'*' : byte);
      else if (con.length < before)
        print("\b \b");
    }
  }
}

// ---- the transport ----------------------------------------------------------
static rnc_mcu_cfg s_cfg;
static WiFiClient s_client;
static bool s_tcp_up = false;
static bool s_began = false;
static uint64_t s_wifi_started_ms = 0, s_wifi_retry_ms = 0, s_tcp_retry_ms = 0;
static rnc_mcu_backoff s_wifi_backoff, s_tcp_backoff;
static rnc_mcu_txq s_txq;
static uint8_t s_txq_storage[QUEUE_BYTES];

static uint64_t now_ms() { return millis(); } // the pump runs far more often than once per wrap

static void tcp_drop() {
  s_client.stop();
  s_tcp_up = false;
  rnc_mcu_txq_clear(&s_txq); // what was queued belonged to the dead connection
  s_tcp_retry_ms = now_ms() + rnc_mcu_backoff_next(&s_tcp_backoff, esp_random());
}

static void wifi_begin() {
  WiFi.disconnect(false, false);
  WiFi.begin(s_cfg.ssid, s_cfg.password[0] ? s_cfg.password : NULL);
  s_wifi_started_ms = now_ms();
}

bool rnc_wifi_start(const rnc_mcu_cfg *cfg) {
  s_cfg = *cfg;
  rnc_mcu_txq_init(&s_txq, s_txq_storage, sizeof(s_txq_storage));
  rnc_mcu_backoff_init(&s_wifi_backoff, BACKOFF_MIN_MS, BACKOFF_MAX_MS);
  rnc_mcu_backoff_init(&s_tcp_backoff, BACKOFF_MIN_MS, BACKOFF_MAX_MS);
  WiFi.persistent(false); // the credentials stay in the settings namespace only
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  wifi_begin();
  s_began = true;
  return true;
}

static void tcp_flush() {
  const uint8_t *data;
  size_t n;
  int fd = s_client.fd();
  while (s_tcp_up && (n = rnc_mcu_txq_peek(&s_txq, &data)) > 0) {
    int sent = send(fd, data, n, MSG_DONTWAIT);
    if (sent > 0) {
      rnc_mcu_txq_consume(&s_txq, (size_t)sent);
    } else if (sent < 0 && errno == EINTR) {
      continue;
    } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return;
    } else {
      tcp_drop();
      return;
    }
  }
}

int rnc_wifi_link_up(void *) {
  if (!s_began)
    return 0;
  uint64_t now = now_ms();
  if (WiFi.status() != WL_CONNECTED) {
    if (s_tcp_up || s_client.connected())
      tcp_drop();
    // the driver retries by itself (auto reconnect); an attempt that gets nowhere for a
    // long time is restarted, with backoff
    if (now - s_wifi_started_ms > WIFI_TIMEOUT_MS && now >= s_wifi_retry_ms) {
      s_wifi_retry_ms = now + rnc_mcu_backoff_next(&s_wifi_backoff, esp_random());
      wifi_begin();
    }
    return 0;
  }
  rnc_mcu_backoff_reset(&s_wifi_backoff);
  s_wifi_started_ms = now;
  if (!s_tcp_up) {
    if (now < s_tcp_retry_ms)
      return 0;
    // blocking: name resolution and connect, at most CONNECT_TIMEOUT_MS
    if (s_client.connect(s_cfg.host, s_cfg.port, CONNECT_TIMEOUT_MS)) {
      int fd = s_client.fd(), one = 1, idle = 30, interval = 10, count = 3;
      (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
      (void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
      (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
      (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
      (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
      s_tcp_up = true;
      rnc_mcu_backoff_reset(&s_tcp_backoff);
    } else {
      tcp_drop();
      return 0;
    }
  }
  tcp_flush();
  return s_tcp_up ? 1 : 0;
}

size_t rnc_wifi_write(void *, const uint8_t *data, size_t size) {
  if (!s_tcp_up)
    return 0;
  // one HDLC frame: queued whole or refused (backpressure); a full queue is drained first
  if (rnc_mcu_txq_free(&s_txq) < size)
    tcp_flush();
  return rnc_mcu_txq_push(&s_txq, data, size) ? size : 0;
}

size_t rnc_wifi_read(void *, uint8_t *buffer, size_t capacity) {
  if (!s_tcp_up)
    return 0;
  int n = recv(s_client.fd(), buffer, capacity, MSG_DONTWAIT);
  if (n > 0)
    return (size_t)n;
  if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
    tcp_drop();
  return 0;
}
#endif
