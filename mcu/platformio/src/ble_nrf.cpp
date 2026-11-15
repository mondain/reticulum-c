// Bluetooth LE Nordic UART transport on nRF52840 (Adafruit Bluefruit stack, the SoftDevice that
// the Adafruit bootloader keeps in place). See ble_mode.h.
#include "ble_mode.h"

#if RNC_HAVE_BLE
#include <Arduino.h>
#include <bluefruit.h>

static BLEUart g_uart;

static int ble_read(void *, uint8_t *buffer, size_t capacity) {
  int n;
  if (!Bluefruit.connected())
    return 0;
  n = g_uart.available();
  if (n <= 0)
    return 0;
  if ((size_t)n > capacity)
    n = (int)capacity;
  return g_uart.read(buffer, (size_t)n);
}

// Takes what the central can receive; the rest is dropped and counted by the module.
static int ble_write(void *, const uint8_t *data, size_t size) {
  if (!Bluefruit.connected() || !g_uart.notifyEnabled())
    return 0;
  return (int)g_uart.write(data, size);
}

const rnc_rnode_io rnc_ble_io = {ble_read, ble_write, NULL};

int rnc_ble_available(void) { return Bluefruit.connected() ? g_uart.available() : 0; }

bool rnc_ble_start(const rnc_mcu_cfg *cfg) {
  char name[16];
  if (!rnc_mcu_cfg_ble_ready(cfg))
    return false; // no PIN: Bluetooth stays off
  Bluefruit.autoConnLed(false);
  Bluefruit.configPrphBandwidth(BANDWIDTH_MAX);
  if (!Bluefruit.begin())
    return false;
  snprintf(name, sizeof(name), "RNode %04X", (unsigned)(NRF_FICR->DEVICEADDR[0] & 0xFFFFu));
  Bluefruit.setName(name);
  // a static passkey: this device displays it (it is the operator's PIN), the central types it
  Bluefruit.Security.setPIN(cfg->ble_pin);
  g_uart.setPermission(SECMODE_ENC_WITH_MITM, SECMODE_ENC_WITH_MITM); // nothing without pairing
  if (g_uart.begin() != ERROR_NONE)
    return false;
  Bluefruit.Advertising.addFlags(BLE_GAP_ADV_FLAGS_LE_ONLY_GENERAL_DISC_MODE);
  Bluefruit.Advertising.addTxPower();
  Bluefruit.Advertising.addService(g_uart);
  Bluefruit.ScanResponse.addName();
  Bluefruit.Advertising.restartOnDisconnect(true);
  Bluefruit.Advertising.setInterval(32, 244); // units of 0.625 ms
  Bluefruit.Advertising.setFastTimeout(30);
  Bluefruit.Advertising.start(0); // advertise until connected, again after a disconnect
  return true;
}
#endif
