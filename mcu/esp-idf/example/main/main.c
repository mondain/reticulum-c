/* ESP-IDF port of the portable MCU example application (mcu/app).
 *
 * Wires rnc_mcu_app to: a UART (or the built-in USB Serial/JTAG) as the serial
 * transport, the hardware RNG, esp_timer, and NVS for the identity and the clock
 * mark. The host sees the board as a serial port; point a reticulum-c-node or
 * Reticulum SerialInterface at it (see mcu/README.txt). */
#include "bootloader_random.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "rnc_mcu_app.h"
#include "sdkconfig.h"
#include <string.h>

#if defined(CONFIG_RETICULUM_MCU_TRANSPORT_USB_SERIAL_JTAG)
#include "driver/usb_serial_jtag.h"
#else
#include "driver/uart.h"
#endif

static const char *TAG = "reticulum";
#define NVS_NAMESPACE "reticulum"

/* ---- serial transport ------------------------------------------------------ */
#if defined(CONFIG_RETICULUM_MCU_TRANSPORT_USB_SERIAL_JTAG)
static esp_err_t transport_init(void) {
  usb_serial_jtag_driver_config_t cfg = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
  cfg.rx_buffer_size = 1024;
  cfg.tx_buffer_size = 1024;
  return usb_serial_jtag_driver_install(&cfg);
}
static size_t transport_write(void *context, const uint8_t *data, size_t size) {
  int n = usb_serial_jtag_write_bytes(data, size, pdMS_TO_TICKS(50));
  (void)context;
  return n > 0 ? (size_t)n : 0;
}
static size_t transport_read(void *context, uint8_t *buffer, size_t capacity) {
  int n = usb_serial_jtag_read_bytes(buffer, capacity, 0);
  (void)context;
  return n > 0 ? (size_t)n : 0;
}
#else
#define UART_PORT ((uart_port_t)CONFIG_RETICULUM_MCU_UART_NUM)
static esp_err_t transport_init(void) {
  uart_config_t cfg = {
      .baud_rate = CONFIG_RETICULUM_MCU_UART_BAUD,
      .data_bits = UART_DATA_8_BITS,
      .parity = UART_PARITY_DISABLE,
      .stop_bits = UART_STOP_BITS_1,
      .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
      .source_clk = UART_SCLK_DEFAULT,
  };
  esp_err_t err = uart_driver_install(UART_PORT, 2048, 0, 0, NULL, 0);
  if (err != ESP_OK)
    return err;
  err = uart_param_config(UART_PORT, &cfg);
  if (err != ESP_OK)
    return err;
  return uart_set_pin(UART_PORT,
                      CONFIG_RETICULUM_MCU_UART_TX_GPIO < 0 ? UART_PIN_NO_CHANGE
                                                            : CONFIG_RETICULUM_MCU_UART_TX_GPIO,
                      CONFIG_RETICULUM_MCU_UART_RX_GPIO < 0 ? UART_PIN_NO_CHANGE
                                                            : CONFIG_RETICULUM_MCU_UART_RX_GPIO,
                      UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
}
static size_t transport_write(void *context, const uint8_t *data, size_t size) {
  int n = uart_write_bytes(UART_PORT, data, size); /* blocks until queued to the FIFO */
  (void)context;
  return n > 0 ? (size_t)n : 0;
}
static size_t transport_read(void *context, uint8_t *buffer, size_t capacity) {
  int n = uart_read_bytes(UART_PORT, buffer, capacity, 0);
  (void)context;
  return n > 0 ? (size_t)n : 0;
}
#endif

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
  ESP_LOGI(TAG, "%s", line);
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

static void reticulum_task(void *arg) {
  rnc_mcu_platform platform;
  rnc_mcu_config config;
  rnc_mcu_app *app;
  (void)arg;
  memset(&platform, 0, sizeof(platform));
  platform.write = transport_write;
  platform.read = transport_read;
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
#if defined(CONFIG_RETICULUM_MCU_TRANSPORT_UART)
  config.bitrate = CONFIG_RETICULUM_MCU_UART_BAUD;
#else
  config.bitrate = 1000000u;
#endif
  app = rnc_mcu_app_new(&platform, &config);
  if (!app) {
    ESP_LOGE(TAG, "cannot start the application (out of memory?)");
    vTaskDelete(NULL);
    return;
  }
  ESP_LOGI(TAG, "running, free heap %u bytes", (unsigned)esp_get_free_heap_size());
  for (;;) {
    unsigned wait = rnc_mcu_app_step(app, platform_now_ms(NULL));
    TickType_t ticks = pdMS_TO_TICKS(wait > 5u ? 5u : wait);
    vTaskDelay(ticks ? ticks : 1);
  }
}

void app_main(void) {
  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    err = nvs_flash_init();
  }
  ESP_ERROR_CHECK(err);
  /* esp_fill_random is a true random source only while the RF subsystem or this
   * entropy source runs; this firmware does not use Wi-Fi or Bluetooth */
  bootloader_random_enable();
  ESP_ERROR_CHECK(transport_init());
  if (xTaskCreate(reticulum_task, "reticulum", CONFIG_RETICULUM_MCU_TASK_STACK, NULL, 5, NULL) !=
      pdPASS)
    ESP_LOGE(TAG, "cannot create the Reticulum task");
}
