#include "net_settings.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdkconfig.h"
#include <stdio.h>
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
    {
      /* the radio: nothing is assumed. Every transmit setting counts as set only if it was
       * stored together with its "set" bit, and passes the same checks as at the console. */
      char text[16];
      uint32_t u32;
      uint8_t u8, set = 0;
      int8_t i8;
      uint16_t u16;
      size_t n = sizeof(text);
      if (nvs_get_str(h, "lora_mode", text, &n) == ESP_OK)
        (void)rnc_lora_cfg_set(&cfg->lora, "mode", text);
      if (nvs_get_u8(h, "lora_set", &set) != ESP_OK)
        set = 0;
      if ((set & RNC_LORA_SET_FREQ) && nvs_get_u32(h, "lora_freq", &u32) == ESP_OK) {
        snprintf(text, sizeof(text), "%lu", (unsigned long)u32);
        (void)rnc_lora_cfg_set(&cfg->lora, "freq", text);
      }
      if ((set & RNC_LORA_SET_BW) && nvs_get_u32(h, "lora_bw", &u32) == ESP_OK) {
        snprintf(text, sizeof(text), "%lu", (unsigned long)u32);
        (void)rnc_lora_cfg_set(&cfg->lora, "bw", text);
      }
      if ((set & RNC_LORA_SET_SF) && nvs_get_u8(h, "lora_sf", &u8) == ESP_OK) {
        snprintf(text, sizeof(text), "%u", (unsigned)u8);
        (void)rnc_lora_cfg_set(&cfg->lora, "sf", text);
      }
      if ((set & RNC_LORA_SET_CR) && nvs_get_u8(h, "lora_cr", &u8) == ESP_OK) {
        snprintf(text, sizeof(text), "%u", (unsigned)u8);
        (void)rnc_lora_cfg_set(&cfg->lora, "cr", text);
      }
      if ((set & RNC_LORA_SET_TXP) && nvs_get_i8(h, "lora_txp", &i8) == ESP_OK) {
        snprintf(text, sizeof(text), "%d", (int)i8);
        (void)rnc_lora_cfg_set(&cfg->lora, "txp", text);
      }
      if (nvs_get_u16(h, "lora_air", &u16) == ESP_OK && u16 >= 1 && u16 <= 10000)
        cfg->lora.airtime = u16;
    }
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
  /* the radio settings; a value that was never set is not stored (it stays "not set") */
  if (err == ESP_OK)
    err = nvs_set_str(h, "lora_mode",
                      cfg->lora.mode == RNC_LORA_MODE_LEAF      ? "leaf"
                      : cfg->lora.mode == RNC_LORA_MODE_GATEWAY ? "gateway"
                                                                 : "off");
  if (err == ESP_OK)
    err = nvs_set_u8(h, "lora_set", cfg->lora.set);
  if (err == ESP_OK && (cfg->lora.set & RNC_LORA_SET_FREQ))
    err = nvs_set_u32(h, "lora_freq", cfg->lora.freq_hz);
  if (err == ESP_OK && (cfg->lora.set & RNC_LORA_SET_BW))
    err = nvs_set_u32(h, "lora_bw", cfg->lora.bw_hz);
  if (err == ESP_OK && (cfg->lora.set & RNC_LORA_SET_SF))
    err = nvs_set_u8(h, "lora_sf", cfg->lora.sf);
  if (err == ESP_OK && (cfg->lora.set & RNC_LORA_SET_CR))
    err = nvs_set_u8(h, "lora_cr", cfg->lora.cr);
  if (err == ESP_OK && (cfg->lora.set & RNC_LORA_SET_TXP))
    err = nvs_set_i8(h, "lora_txp", cfg->lora.txp_dbm);
  if (err == ESP_OK)
    err = nvs_set_u16(h, "lora_air", cfg->lora.airtime);
  if (err == ESP_OK)
    err = nvs_commit(h);
  nvs_close(h);
  return err;
}
