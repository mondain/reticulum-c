#ifndef NET_SETTINGS_H
#define NET_SETTINGS_H
/* The provisioning settings (mode, Wi-Fi credentials, server) in the dedicated
 * NVS partition "rnccfg", separate from the identity in the default NVS partition,
 * so that provisioning never touches the node's identity. Namespace "rnc_net";
 * keys: mode, ssid, password, host (strings) and port (u16). The same layout is
 * produced by mcu/tools/wifi-config.sh. */
#include "esp_err.h"
#include "rnc_mcu_net.h"

#define NET_SETTINGS_PARTITION "rnccfg"
#define NET_SETTINGS_NAMESPACE "rnc_net"

/* Loads the settings; defaults (serial mode) when nothing is stored. With the
 * developer Kconfig option RETICULUM_MCU_DEV_WIFI_DEFAULTS the compiled-in values
 * are used when the partition holds no mode key. Returns 1 if the values came from
 * the compiled-in developer defaults. */
int net_settings_load(rnc_mcu_cfg *cfg);
esp_err_t net_settings_save(const rnc_mcu_cfg *cfg);
#endif
