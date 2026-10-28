// Runtime provisioning for the nRF52840 environments (RAK4631, Heltec T114, LilyGo T-Echo):
// the LoRa radio settings in the internal flash file system and the same line console as the
// ESP32 firmware (help, get, set, clear, save, reboot), on the USB serial port. Compiles to
// nothing on the ESP32 environments (wifi_mode.cpp has theirs).
//
// The console runs only on request: the line "rnc-config" on Serial within a short window
// after boot. The nRF52 boards have no Wi-Fi, so the other keys (mode, ssid, ...) are accepted
// by the console but unused. NOT RUN ON HARDWARE: compiled only.
#include "wifi_mode.h"

#if defined(NRF52840_XXAA) || defined(ARDUINO_ARCH_NRF52)
#include <Adafruit_LittleFS.h>
#include <Arduino.h>
#include <InternalFileSystem.h>
#include <string.h>

using namespace Adafruit_LittleFS_Namespace;

#define SETTINGS_FILE "/rnc_lora"
#define SETTINGS_TEMP "/rnc_lora.tmp"
#define SETTINGS_MAGIC 0x524E4301u // "RNC" 1

static void put32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}
static uint32_t get32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

bool rnc_settings_load(rnc_mcu_cfg *cfg) {
  uint8_t b[20];
  rnc_mcu_cfg_init(cfg);
  File file(InternalFS);
  if (!file.open(SETTINGS_FILE, FILE_O_READ))
    return false;
  int n = file.read(b, sizeof(b));
  file.close();
  if (n != (int)sizeof(b) || get32(b) != SETTINGS_MAGIC)
    return false;
  // every value goes through the same checks as at the console; a transmit setting counts only
  // if it was stored with its "set" bit
  char text[16];
  uint8_t mode = b[4], set = b[5];
  (void)rnc_lora_cfg_set(&cfg->lora, "mode",
                         mode == RNC_LORA_MODE_LEAF ? "leaf" : mode == RNC_LORA_MODE_GATEWAY ? "gateway" : "off");
  if (set & RNC_LORA_SET_FREQ) {
    snprintf(text, sizeof(text), "%lu", (unsigned long)get32(b + 12));
    (void)rnc_lora_cfg_set(&cfg->lora, "freq", text);
  }
  if (set & RNC_LORA_SET_BW) {
    snprintf(text, sizeof(text), "%lu", (unsigned long)get32(b + 16));
    (void)rnc_lora_cfg_set(&cfg->lora, "bw", text);
  }
  if (set & RNC_LORA_SET_SF) {
    snprintf(text, sizeof(text), "%u", (unsigned)b[6]);
    (void)rnc_lora_cfg_set(&cfg->lora, "sf", text);
  }
  if (set & RNC_LORA_SET_CR) {
    snprintf(text, sizeof(text), "%u", (unsigned)b[7]);
    (void)rnc_lora_cfg_set(&cfg->lora, "cr", text);
  }
  if (set & RNC_LORA_SET_TXP) {
    snprintf(text, sizeof(text), "%d", (int)(int8_t)b[8]);
    (void)rnc_lora_cfg_set(&cfg->lora, "txp", text);
  }
  uint16_t air = (uint16_t)((b[9] << 8) | b[10]);
  if (air >= 1 && air <= 10000)
    cfg->lora.airtime = air;
  return false; // never from compiled-in defaults
}

// Written to a temporary file and renamed over the old one (atomic in LittleFS)
bool rnc_settings_save(const rnc_mcu_cfg *cfg) {
  uint8_t b[20];
  memset(b, 0, sizeof(b));
  put32(b, SETTINGS_MAGIC);
  b[4] = cfg->lora.mode;
  b[5] = cfg->lora.set;
  b[6] = cfg->lora.sf;
  b[7] = cfg->lora.cr;
  b[8] = (uint8_t)cfg->lora.txp_dbm;
  b[9] = (uint8_t)(cfg->lora.airtime >> 8);
  b[10] = (uint8_t)cfg->lora.airtime;
  put32(b + 12, cfg->lora.freq_hz);
  put32(b + 16, cfg->lora.bw_hz);
  InternalFS.remove(SETTINGS_TEMP);
  File file(InternalFS);
  if (!file.open(SETTINGS_TEMP, FILE_O_WRITE))
    return false;
  size_t w = file.write(b, sizeof(b));
  file.close();
  if (w != sizeof(b)) {
    InternalFS.remove(SETTINGS_TEMP);
    return false;
  }
  return InternalFS.rename(SETTINGS_TEMP, SETTINGS_FILE);
}

bool rnc_provision_requested(unsigned window_ms) {
  static const char entry[] = "rnc-config";
  char line[24];
  size_t length = 0;
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
    delay(10);
  }
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
        "used after reboot. Only the lora.* keys matter on this board.\n");
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
        NVIC_SystemReset();
      }
      if (had)
        print("rnc> ");
    } else {
      size_t before = con.length;
      reply[0] = 0;
      (void)rnc_mcu_console_feed(&con, cfg, byte, reply, sizeof(reply));
      if (con.length > before)
        Serial.write(byte);
      else if (con.length < before)
        print("\b \b");
    }
  }
}
#endif
