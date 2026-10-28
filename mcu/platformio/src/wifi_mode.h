// Wi-Fi TCP transport and runtime provisioning for the ESP32 / ESP32-S3 environments
// (Arduino framework). Compiles to nothing on the nRF52 environments.
//
// The same concept as the ESP-IDF firmware (mcu/README.txt):
//   - settings (mode, ssid, password, host, port) in Preferences, namespace "rnc_net";
//   - mode "serial" (the default) keeps the HDLC stream on Serial as before;
//   - mode "wifi" runs the HDLC stream over a TCP client connection to a Reticulum
//     node's TCPServerInterface, and Serial carries the console and status text;
//   - a line console (help, get, set, clear, save, reboot) that runs only when Wi-Fi mode
//     has no usable settings, or on request in a short window after boot (the line
//     "rnc-config" on Serial, or the BOOT button held for 300 ms).
// Credentials are never compiled into a release build. For developers only, the build
// flags RNC_MCU_DEV_WIFI_SSID / _PASSWORD / _HOST / _PORT (string literals) compile
// defaults in; they apply only while no mode is stored.
#pragma once
#include <stddef.h>
#include <stdint.h>

#include "rnc_mcu_net.h"

#ifndef RNC_MCU_PROVISION_WINDOW_MS
#define RNC_MCU_PROVISION_WINDOW_MS 2000
#endif
#ifndef RNC_MCU_BOOT_PIN
#define RNC_MCU_BOOT_PIN 0 // GPIO0, the BOOT button of the supported boards; -1 disables
#endif

// Loads the settings; returns true if they came from the compiled-in developer defaults.
bool rnc_settings_load(rnc_mcu_cfg *cfg);
bool rnc_settings_save(const rnc_mcu_cfg *cfg);

// Waits up to window_ms for "rnc-config" on Serial or the BOOT button.
bool rnc_provision_requested(unsigned window_ms);
// Runs the console until reboot; does not return.
void rnc_provision_console(rnc_mcu_cfg *cfg, const char *reason);

#if defined(ARDUINO_ARCH_ESP32)
// The transport: call rnc_wifi_start once, then plug the three functions into the
// platform table (all are called from the Reticulum task only).
bool rnc_wifi_start(const rnc_mcu_cfg *cfg);
int rnc_wifi_link_up(void *context);
size_t rnc_wifi_write(void *context, const uint8_t *data, size_t size);
size_t rnc_wifi_read(void *context, uint8_t *buffer, size_t capacity);
#endif
