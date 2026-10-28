#include "net_settings.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdkconfig.h"
#include <string.h>

static void get_str(nvs_handle_t h, const char *key, char *out, size_t size) {
  char tmp[96];
  size_t n = sizeof(tmp);
  if (nvs_get_str(h, key, tmp, &n) == ESP_OK && n <= size) {
    memset(out, 0, size);
    memcpy(out, tmp, n); /* n counts the terminating zero */
  }
  memset(tmp, 0, sizeof(tmp));
}

int net_settings_load(rnc_mcu_cfg *cfg) {
  nvs_handle_t h;
  uint16_t port;
  int stored = 0;
  rnc_mcu_cfg_init(cfg);
  if (nvs_flash_init_partition(NET_SETTINGS_PARTITION) == ESP_OK &&
      nvs_open_from_partition(NET_SETTINGS_PARTITION, NET_SETTINGS_NAMESPACE, NVS_READONLY, &h) ==
          ESP_OK) {
    char mode[8];
    size_t n = sizeof(mode);
    if (nvs_get_str(h, "mode", mode, &n) == ESP_OK) {
      stored = 1;
      /* a stored value that is not one of the two modes is ignored: serial */
      (void)rnc_mcu_cfg_set(cfg, "mode", mode);
    }
    get_str(h, "ssid", cfg->ssid, sizeof(cfg->ssid));
    get_str(h, "password", cfg->password, sizeof(cfg->password));
    get_str(h, "host", cfg->host, sizeof(cfg->host));
    if (nvs_get_u16(h, "port", &port) == ESP_OK && port != 0)
      cfg->port = port;
    nvs_close(h);
  }
#if defined(CONFIG_RETICULUM_MCU_DEV_WIFI_DEFAULTS)
  if (!stored) {
    /* DEVELOPER BUILD ONLY: credentials are inside the firmware image */
    (void)rnc_mcu_cfg_set(cfg, "mode", "wifi");
    (void)rnc_mcu_cfg_set(cfg, "ssid", CONFIG_RETICULUM_MCU_DEV_WIFI_SSID);
    (void)rnc_mcu_cfg_set(cfg, "password", CONFIG_RETICULUM_MCU_DEV_WIFI_PASSWORD);
    (void)rnc_mcu_cfg_set(cfg, "host", CONFIG_RETICULUM_MCU_DEV_SERVER_HOST);
    cfg->port = CONFIG_RETICULUM_MCU_DEV_SERVER_PORT;
    return 1;
  }
#else
  (void)stored;
#endif
  return 0;
}

esp_err_t net_settings_save(const rnc_mcu_cfg *cfg) {
  nvs_handle_t h;
  esp_err_t err = nvs_flash_init_partition(NET_SETTINGS_PARTITION);
  if (err != ESP_OK)
    return err;
  err = nvs_open_from_partition(NET_SETTINGS_PARTITION, NET_SETTINGS_NAMESPACE, NVS_READWRITE, &h);
  if (err != ESP_OK)
    return err;
  err = nvs_set_str(h, "mode", cfg->mode);
  if (err == ESP_OK)
    err = nvs_set_str(h, "ssid", cfg->ssid);
  if (err == ESP_OK)
    err = nvs_set_str(h, "password", cfg->password);
  if (err == ESP_OK)
    err = nvs_set_str(h, "host", cfg->host);
  if (err == ESP_OK)
    err = nvs_set_u16(h, "port", cfg->port);
  if (err == ESP_OK)
    err = nvs_commit(h);
  nvs_close(h);
  return err;
}
