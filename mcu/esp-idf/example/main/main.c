/* ESP-IDF port of the portable MCU example application (mcu/app).
 *
 * Wires rnc_mcu_app to the hardware RNG, esp_timer, NVS (identity and clock mark) and
 * one of two transports, chosen at runtime from the settings in the "rnccfg" NVS
 * partition (mcu/README.txt):
 *
 *   serial (default)  HDLC on a UART or the built-in USB Serial/JTAG; the host sees
 *                     the board as a serial port, for a reticulum-c-node or
 *                     Reticulum SerialInterface.
 *   wifi              HDLC on a TCP connection (station mode) to the
 *                     TCPServerInterface of a Reticulum node.
 *
 * The settings (ssid, password, host, port) are provisioned at runtime and are never
 * compiled into a release image.
 *
 * Optionally a LoRa radio (mcu/radio), on the board selected in Kconfig. Its settings
 * (lora.mode, lora.freq, lora.bw, lora.sf, lora.cr, lora.txp, lora.airtime) are provisioned
 * the same way; the radio stays off until every transmit setting has been given
 * (REGULATORY: nothing is compiled in). lora.mode leaf makes LoRa the node's only interface;
 * gateway keeps the serial or Wi-Fi interface and adds LoRa with transport on. */
#include "bootloader_random.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "net_settings.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "provision.h"
#include "radio_hal_idf.h"
#include "rnc_mcu_app.h"
#include "rnc_radio.h"
#include "sdkconfig.h"
#include "serial_port.h"
#include "wifi_transport.h"
#include <stdio.h>
#include <string.h>

static const char *TAG = "reticulum";
#define NVS_NAMESPACE "reticulum"

static int s_wifi_mode; /* 1 when the transport is the Wi-Fi TCP connection */
static int s_text_log;  /* 1 when the serial port is free for text (Wi-Fi mode, LoRa only) */
static rnc_radio s_radio;          /* the LoRa radio: drivers and interface, ~3 KB */
static rnc_radio_hal s_radio_hal;
static rnc_lora_cfg s_lora;        /* the settings the radio was started with */
static int s_lora_active;          /* the LoRa interface is handed to the application */

/* ---- the rest of the platform --------------------------------------------- */
static int platform_random(void *context, uint8_t *buffer, size_t size) {
  (void)context;
  esp_fill_random(buffer, size);
  return 0;
}
static uint64_t platform_now_ms(void *context) {
  (void)context;
  return (uint64_t)(esp_timer_get_time() / 1000);
}
static void platform_log(void *context, const char *line) {
  (void)context;
  if (s_text_log) { /* the serial port is free for people in Wi-Fi mode and in LoRa only mode */
    serial_port_print(line);
    serial_port_print("\n");
  } else {
    ESP_LOGI(TAG, "%s", line);
  }
}
static size_t platform_free_heap(void *context) {
  (void)context;
  return esp_get_free_heap_size();
}
static int platform_persist(void *context, const char *key, const void *data, size_t size) {
  nvs_handle_t h;
  esp_err_t err;
  (void)context;
  if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK)
    return -1;
  err = nvs_set_blob(h, key, data, size);
  if (err == ESP_OK)
    err = nvs_commit(h);
  nvs_close(h);
  return err == ESP_OK ? 0 : -1;
}
static int platform_load(void *context, const char *key, void *buffer, size_t capacity) {
  nvs_handle_t h;
  size_t size = capacity;
  esp_err_t err;
  (void)context;
  if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK)
    return -1;
  err = nvs_get_blob(h, key, buffer, &size);
  nvs_close(h);
  return err == ESP_OK ? (int)size : -1;
}

/* in LoRa only mode the serial hooks are never used, but the table needs them */
static size_t leaf_write(void *context, const uint8_t *data, size_t size) {
  (void)context;
  (void)data;
  return size;
}
static size_t leaf_read(void *context, uint8_t *buffer, size_t capacity) {
  (void)context;
  (void)buffer;
  (void)capacity;
  return 0;
}

static uint32_t radio_random32(void *context) {
  (void)context;
  return esp_random();
}

/* Starts the radio if, and only if, the settings allow it (rnc_radio_setup is the gate:
 * with anything missing the chip is not even spoken to). Returns the RNC_RADIO_* status. */
static int lora_start(const rnc_mcu_cfg *cfg) {
  const char *id = CONFIG_RETICULUM_MCU_LORA_BOARD_ID;
  const rnc_board *board = id[0] ? rnc_board_find(id) : NULL;
  int status;
  s_lora = cfg->lora;
  if (cfg->lora.mode == RNC_LORA_MODE_OFF || !rnc_lora_cfg_ready(&cfg->lora) || !board ||
      !board->supported) {
    status = rnc_radio_setup(&s_radio, board, NULL, &cfg->lora, radio_random32, NULL);
  } else if (radio_hal_idf_init(board, &s_radio_hal) != 0) {
    status = RNC_RADIO_BOARD_UNSUPPORTED;
  } else {
    status = rnc_radio_setup(&s_radio, board, &s_radio_hal, &cfg->lora, radio_random32, NULL);
  }
  s_lora_active = status == RNC_RADIO_OK || status == RNC_RADIO_CHIP_FAILED;
  return status;
}

static void reticulum_task(void *arg) {
  rnc_mcu_platform platform;
  rnc_mcu_config config;
  rnc_mcu_app *app;
  (void)arg;
  memset(&platform, 0, sizeof(platform));
  if (s_lora_active && s_lora.mode == RNC_LORA_MODE_LEAF) {
    /* LoRa is the only interface: the application never touches the serial hooks */
    platform.write = leaf_write;
    platform.read = leaf_read;
  } else if (s_wifi_mode) {
    platform.write = wifi_transport_write;
    platform.read = wifi_transport_read;
    platform.link_up = wifi_transport_link_up;
  } else {
    platform.write = serial_port_write;
    platform.read = serial_port_read;
  }
  platform.random = platform_random;
  platform.now_ms = platform_now_ms;
  platform.log = platform_log;
  platform.persist = platform_persist;
  platform.load = platform_load;
  platform.free_heap = platform_free_heap;
  platform.board = CONFIG_RETICULUM_MCU_BOARD;
  /* no unix_seconds hook: build epoch plus uptime plus the persisted mark (rnc_mcu_app.h) */
  memset(&config, 0, sizeof(config));
  config.announce_interval_ms = CONFIG_RETICULUM_MCU_ANNOUNCE_SECONDS * 1000u;
  if (s_wifi_mode)
    config.bitrate = 10000000u; /* a TCP interface, like Reticulum's TCPClientInterface */
  else
#if defined(CONFIG_RETICULUM_MCU_TRANSPORT_UART)
    config.bitrate = CONFIG_RETICULUM_MCU_UART_BAUD;
#else
    config.bitrate = 1000000u;
#endif
  if (s_lora_active) {
    config.lora = &s_radio.li;
    config.lora_mode = s_lora.mode;
  }
  app = rnc_mcu_app_new(&platform, &config);
  if (!app) {
    ESP_LOGE(TAG, "cannot start the application (out of memory?)");
    vTaskDelete(NULL);
    return;
  }
  ESP_LOGI(TAG, "running, free heap %u bytes; %s", (unsigned)esp_get_free_heap_size(),
           rnc_radio_status_text(s_radio.status));
  for (;;) {
    unsigned wait = rnc_mcu_app_step(app, platform_now_ms(NULL));
    TickType_t ticks = pdMS_TO_TICKS(wait > 5u ? 5u : wait);
    vTaskDelay(ticks ? ticks : 1);
  }
}

void app_main(void) {
  rnc_mcu_cfg cfg;
  int compiled_in;
  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    err = nvs_flash_init();
  }
  ESP_ERROR_CHECK(err);
  ESP_ERROR_CHECK(serial_port_init());
  compiled_in = net_settings_load(&cfg);

  /* Provisioning console: Wi-Fi mode without usable settings, or on request during the
   * window after boot. In serial mode the window costs CONFIG_RETICULUM_MCU_PROVISION_WINDOW_MS
   * of start-up time. */
  if (rnc_mcu_cfg_wifi_mode(&cfg) && !rnc_mcu_cfg_wifi_ready(&cfg) &&
      !(cfg.lora.mode == RNC_LORA_MODE_LEAF && rnc_lora_cfg_ready(&cfg.lora))) /* LoRa only needs no Wi-Fi */
    provision_console(&cfg, "Wi-Fi mode is selected but ssid, password or host are missing or invalid.");
  if (provision_requested(CONFIG_RETICULUM_MCU_PROVISION_WINDOW_MS,
                          CONFIG_RETICULUM_MCU_PROVISION_BOOT_GPIO))
    provision_console(&cfg, "Requested at boot.");

  /* the radio, if the settings allow it; with it off or incomplete the board is the serial or
   * Wi-Fi leaf it always was */
  (void)lora_start(&cfg);
  if (s_lora_active && s_lora.mode == RNC_LORA_MODE_LEAF) {
    /* LoRa only: no serial stream, no Wi-Fi; the entropy source below is still needed */
    s_text_log = 1;
    bootloader_random_enable();
  } else if (rnc_mcu_cfg_wifi_mode(&cfg)) {
    char text[160];
    s_wifi_mode = 1;
    s_text_log = 1;
    if (compiled_in)
      serial_port_print("WARNING: developer build, Wi-Fi credentials are compiled into this image\n");
    (void)snprintf(text, sizeof(text), "Wi-Fi mode: joining \"%s\", then connecting to %s:%u\n",
                   cfg.ssid, cfg.host, (unsigned)cfg.port);
    serial_port_print(text);
    err = wifi_transport_start(&cfg);
    memset(&cfg.password, 0, sizeof(cfg.password)); /* the driver has its own copy */
    if (err != ESP_OK) {
      serial_port_print("cannot start Wi-Fi, falling back to the console\n");
      provision_console(&cfg, "Wi-Fi could not be started.");
    }
    /* the radio is running: it is the entropy source for esp_fill_random */
  } else {
    /* esp_fill_random is a true random source only while the RF subsystem or this
     * entropy source runs; serial mode does not use Wi-Fi or Bluetooth */
    bootloader_random_enable();
  }
  if (xTaskCreate(reticulum_task, "reticulum", CONFIG_RETICULUM_MCU_TASK_STACK, NULL, 5, NULL) !=
      pdPASS)
    ESP_LOGE(TAG, "cannot create the Reticulum task");
}
