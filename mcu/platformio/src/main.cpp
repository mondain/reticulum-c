// Arduino port of the portable reticulum-c MCU example application (mcu/app).
//
// Fills the rnc_mcu_platform table (mcu/app/rnc_mcu_platform.h) for
//   - ESP32 / ESP32-S3 (arduino-esp32): hardware RNG, Preferences (NVS) for state
//   - nRF52840 (Adafruit nRF52 core):   RNG peripheral, InternalFileSystem for state
// and runs rnc_mcu_app_step from its own FreeRTOS task with a 16 KB stack.
//
// In serial mode (the default; the only mode of the nRF52 boards) the serial port
// ("Serial": a UART behind the board's USB bridge, or the native USB CDC port) carries
// ONLY the HDLC byte stream of the Reticulum SerialInterface: the application's log hook
// is not wired, and framework logging is switched off, so no log text is ever mixed
// into the stream. On ESP32 / ESP32-S3 the board can instead be provisioned (at runtime,
// no credentials in the firmware) to run the HDLC stream over Wi-Fi and a TCP connection
// to a Reticulum node: see wifi_mode.h and README.txt in this directory.
//
// Optionally a LoRa radio (mcu/radio) on the board selected by the build environment. Its
// settings (lora.mode, lora.freq, lora.bw, lora.sf, lora.cr, lora.txp, lora.airtime) are
// provisioned at runtime like the Wi-Fi ones and the radio stays OFF until every transmit
// setting has been given: no frequency, bandwidth, spreading factor, coding rate or power
// is compiled into any image (REGULATORY, see mcu/radio/README.txt). lora.mode leaf makes
// LoRa the only interface (Serial is then free for status text); gateway keeps the serial
// or Wi-Fi interface and adds LoRa with Reticulum transport on.
#include <Arduino.h>
#include <string.h>

#include "radio_hal.h"
#include "rnc_mcu_app.h"
#include "rnc_radio.h"
#include "wifi_mode.h"

#ifndef RNC_MCU_FIRMWARE_BOARD
#define RNC_MCU_FIRMWARE_BOARD "arduino"
#endif
#ifndef RNC_MCU_STACK_BYTES
#define RNC_MCU_STACK_BYTES 16384
#endif
#ifndef RNC_MCU_BAUD
#define RNC_MCU_BAUD 115200 // UART boards; USB CDC ignores it
#endif

#if defined(ARDUINO_ARCH_ESP32)
// ---------------------------------------------------------------- ESP32 ----
#include <Preferences.h>
#include <esp_log.h>
#include <esp_system.h>
extern "C" {
#include <bootloader_random.h>
}
#define RNC_TRANSPORT_USB_CDC (ARDUINO_USB_CDC_ON_BOOT + 0)

static Preferences prefs;

static int platform_random(void *, uint8_t *buffer, size_t size) {
  esp_fill_random(buffer, size);
  return 0;
}
static int platform_persist(void *, const char *key, const void *data, size_t size) {
  if (!prefs.begin("reticulum", false))
    return -1;
  size_t n = prefs.putBytes(key, data, size);
  prefs.end();
  return n == size ? 0 : -1;
}
static int platform_load(void *, const char *key, void *buffer, size_t capacity) {
  if (!prefs.begin("reticulum", true))
    return -1;
  size_t length = prefs.getBytesLength(key);
  int result = -1;
  if (length > 0 && length <= capacity && prefs.getBytes(key, buffer, length) == length)
    result = (int)length;
  prefs.end();
  return result;
}
static size_t platform_free_heap(void *) { return ESP.getFreeHeap(); }
static bool g_wifi_mode = false; // the transport is the Wi-Fi TCP connection
static void hardware_init(void) {
  esp_log_level_set("*", ESP_LOG_NONE); // nothing but HDLC (or the console) on the serial port
}
// Wi-Fi mode logs status text to Serial (it is free for people there); serial mode wires
// no log hook at all
static void platform_log(void *, const char *line) {
  Serial.println(line);
}
#define STACK_DEPTH(bytes) (bytes) // FreeRTOS in ESP-IDF counts bytes

#elif defined(NRF52840_XXAA) || defined(ARDUINO_ARCH_NRF52)
// --------------------------------------------------------------- nRF52 ----
#include <Adafruit_LittleFS.h>
#include <InternalFileSystem.h>
#include <nrf_sdm.h>
#include <nrf_soc.h>
extern "C" {
#include "utility/debug.h" // dbgHeapFree
}
using namespace Adafruit_LittleFS_Namespace;
#define RNC_TRANSPORT_USB_CDC 1

// Random bytes: the SoftDevice's pool when it is enabled (the SoftDevice owns the RNG
// peripheral then), otherwise the RNG peripheral itself with bias correction.
static int platform_random(void *, uint8_t *buffer, size_t size) {
  uint8_t softdevice = 0;
  (void)sd_softdevice_is_enabled(&softdevice);
  if (softdevice) {
    size_t done = 0;
    uint32_t started = millis();
    while (done < size) {
      uint8_t available = 0;
      (void)sd_rand_application_bytes_available_get(&available);
      if (available) {
        uint8_t take = (uint8_t)((size - done) < available ? (size - done) : available);
        if (sd_rand_application_vector_get(buffer + done, take) == NRF_SUCCESS)
          done += take;
      } else {
        if (millis() - started > 2000)
          return -1;
        delay(1);
      }
    }
    return 0;
  }
  NRF_RNG->CONFIG = RNG_CONFIG_DERCEN_Enabled << RNG_CONFIG_DERCEN_Pos;
  NRF_RNG->EVENTS_VALRDY = 0;
  NRF_RNG->TASKS_START = 1;
  for (size_t i = 0; i < size; i++) {
    uint32_t started = millis();
    while (!NRF_RNG->EVENTS_VALRDY) {
      if (millis() - started > 100) {
        NRF_RNG->TASKS_STOP = 1;
        return -1;
      }
    }
    buffer[i] = (uint8_t)NRF_RNG->VALUE;
    NRF_RNG->EVENTS_VALRDY = 0;
  }
  NRF_RNG->TASKS_STOP = 1;
  return 0;
}
static void state_path(char *path, size_t size, const char *key, const char *suffix) {
  snprintf(path, size, "/rnc_%s%s", key, suffix);
}
// Write a temporary file, then rename it over the old one: the rename is atomic in
// LittleFS, so a power cut leaves either the old or the new content, never neither.
static int platform_persist(void *, const char *key, const void *data, size_t size) {
  char path[40], temp[48];
  state_path(path, sizeof(path), key, "");
  state_path(temp, sizeof(temp), key, ".tmp");
  InternalFS.remove(temp);
  File file(InternalFS);
  if (!file.open(temp, FILE_O_WRITE))
    return -1;
  size_t n = file.write((const uint8_t *)data, size);
  file.close();
  if (n != size) {
    InternalFS.remove(temp);
    return -1;
  }
  return InternalFS.rename(temp, path) ? 0 : -1;
}
static int platform_load(void *, const char *key, void *buffer, size_t capacity) {
  char path[40];
  state_path(path, sizeof(path), key, "");
  File file(InternalFS);
  if (!file.open(path, FILE_O_READ))
    return -1;
  size_t length = file.size();
  int result = -1;
  if (length > 0 && length <= capacity && file.read((uint8_t *)buffer, length) == (int)length)
    result = (int)length;
  file.close();
  return result;
}
static size_t platform_free_heap(void *) {
  int free_bytes = dbgHeapFree();
  return free_bytes > 0 ? (size_t)free_bytes : 0;
}
static void hardware_init(void) { InternalFS.begin(); }
static void platform_log(void *, const char *line) { Serial.println(line); }
#define STACK_DEPTH(bytes) ((bytes) / 4) // vanilla FreeRTOS counts words

#else
#error "reticulum-c example: unsupported architecture (ESP32 or nRF52840 only)"
#endif

// ----------------------------------------------------------- the radio -------
static rnc_radio g_radio; // drivers and interface, about 3 KB
static rnc_radio_hal g_radio_hal;
static rnc_lora_cfg g_lora;
static bool g_lora_active = false; // the LoRa interface is handed to the application

static uint32_t radio_random32(void *) {
  uint32_t v = 0;
  if (platform_random(NULL, (uint8_t *)&v, sizeof(v)) != 0)
    v = micros();
  return v;
}

// Starts the radio if, and only if, the settings allow it. rnc_radio_setup is the gate: with the
// mode off or any transmit setting missing the chip is not even spoken to.
static int lora_start(const rnc_mcu_cfg *cfg) {
  const rnc_board *board = rnc_board_find(RNC_MCU_FIRMWARE_BOARD);
  int status;
  g_lora = cfg->lora;
  if (cfg->lora.mode == RNC_LORA_MODE_OFF || !rnc_lora_cfg_ready(&cfg->lora) || !board ||
      !board->supported) {
    status = rnc_radio_setup(&g_radio, board, NULL, &cfg->lora, radio_random32, NULL);
  } else if (rnc_radio_hal_init(board, &g_radio_hal) != 0) {
    status = RNC_RADIO_BOARD_UNSUPPORTED;
  } else {
    status = rnc_radio_setup(&g_radio, board, &g_radio_hal, &cfg->lora, radio_random32, NULL);
  }
  g_lora_active = status == RNC_RADIO_OK || status == RNC_RADIO_CHIP_FAILED;
  return status;
}

// ----------------------------------------------------------- transport -------
static size_t transport_write(void *, const uint8_t *data, size_t size) {
  return Serial.write(data, size);
}
static size_t transport_read(void *, uint8_t *buffer, size_t capacity) {
  size_t n = 0;
  while (n < capacity && Serial.available() > 0) {
    int c = Serial.read();
    if (c < 0)
      break;
    buffer[n++] = (uint8_t)c;
  }
  return n;
}

// Monotonic 64-bit milliseconds from the 32-bit millis() (wraps after 49 days);
// called only from the Reticulum task, far more often than once per wrap.
static uint64_t platform_now_ms(void *) {
  static uint32_t last = 0;
  static uint64_t high = 0;
  uint32_t now = millis();
  if (now < last)
    high += (uint64_t)1 << 32;
  last = now;
  return high + now;
}

static void reticulum_task(void *) {
  rnc_mcu_platform platform;
  rnc_mcu_config config;
  memset(&platform, 0, sizeof(platform));
  platform.write = transport_write;
  platform.read = transport_read;
  platform.random = platform_random;
  platform.now_ms = platform_now_ms;
  platform.persist = platform_persist;
  platform.load = platform_load;
  platform.free_heap = platform_free_heap;
  platform.log = NULL; // the serial port is the HDLC stream: no log text on it
  platform.board = RNC_MCU_FIRMWARE_BOARD;
  // no unix_seconds hook: build epoch plus uptime plus the persisted mark (rnc_mcu_app.h)
  memset(&config, 0, sizeof(config));
#if RNC_TRANSPORT_USB_CDC
  config.bitrate = 1000000u;
#else
  config.bitrate = RNC_MCU_BAUD;
#endif
#if defined(ARDUINO_ARCH_ESP32)
  if (g_wifi_mode) {
    platform.write = rnc_wifi_write;
    platform.read = rnc_wifi_read;
    platform.link_up = rnc_wifi_link_up;
    platform.log = platform_log;
    config.bitrate = 10000000u; // a TCP interface, like Reticulum's TCPClientInterface
  }
#endif
  if (g_lora_active) {
    config.lora = &g_radio.li;
    config.lora_mode = g_lora.mode;
    if (g_lora.mode == RNC_LORA_MODE_LEAF)
      platform.log = platform_log; // Serial is free for status text
  }
  rnc_mcu_app *app = rnc_mcu_app_new(&platform, &config);
  if (!app) { // out of memory or no usable random source: nothing to run
    for (;;)
      vTaskDelay(pdMS_TO_TICKS(1000));
  }
  for (;;) {
    unsigned wait = rnc_mcu_app_step(app, platform_now_ms(NULL));
    TickType_t ticks = pdMS_TO_TICKS(wait > 5u ? 5u : wait);
    vTaskDelay(ticks ? ticks : 1);
  }
}

void setup() {
  hardware_init();
#if defined(ARDUINO_ARCH_ESP32)
  Serial.setRxBufferSize(2048);
#endif
  Serial.begin(RNC_MCU_BAUD);
  // Runtime provisioning (wifi_mode.h, nrf_mode.cpp): the console runs when Wi-Fi mode has no
  // usable settings, or on request in a short window after boot.
  rnc_mcu_cfg cfg;
  bool compiled_in = rnc_settings_load(&cfg);
  bool lora_leaf = cfg.lora.mode == RNC_LORA_MODE_LEAF && rnc_lora_cfg_ready(&cfg.lora);
#if defined(ARDUINO_ARCH_ESP32)
  if (rnc_mcu_cfg_wifi_mode(&cfg) && !rnc_mcu_cfg_wifi_ready(&cfg) && !lora_leaf)
    rnc_provision_console(&cfg, "Wi-Fi mode is selected but ssid, password or host are missing or invalid.");
#endif
  if (rnc_provision_requested(RNC_MCU_PROVISION_WINDOW_MS))
    rnc_provision_console(&cfg, "Requested at boot.");
  // the radio, if the settings allow it; with it off or incomplete the board is the serial or
  // Wi-Fi leaf it always was
  (void)lora_start(&cfg);
  lora_leaf = g_lora_active && g_lora.mode == RNC_LORA_MODE_LEAF;
#if defined(ARDUINO_ARCH_ESP32)
  if (!lora_leaf && rnc_mcu_cfg_wifi_mode(&cfg)) {
    g_wifi_mode = true;
    if (compiled_in)
      Serial.println("WARNING: developer build, Wi-Fi credentials are compiled into this image");
    Serial.printf("Wi-Fi mode: joining \"%s\", then connecting to %s:%u\r\n", cfg.ssid, cfg.host,
                  (unsigned)cfg.port);
    rnc_wifi_start(&cfg);
    memset(cfg.password, 0, sizeof(cfg.password)); // the driver has its own copy
    // the radio is the entropy source for esp_fill_random now
  } else {
    // esp_fill_random is a true random source only while the RF subsystem or the SAR
    // ADC entropy source runs; this mode uses no Wi-Fi or Bluetooth.
    bootloader_random_enable();
  }
#else
  (void)compiled_in;
#endif
  xTaskCreate(reticulum_task, "reticulum", STACK_DEPTH(RNC_MCU_STACK_BYTES), NULL, 2, NULL);
}

void loop() { vTaskDelay(pdMS_TO_TICKS(1000)); }
