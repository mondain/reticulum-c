// Bluetooth LE transport for the RNode mode (docs/rnode-mode-design.txt 6.6): one Nordic UART
// service, device name "RNode XXXX", passkey pairing with the operator's PIN (set ble.pin).
// Bluetooth stays off, and does not advertise, until a PIN is set. nRF52840 boards use the
// Adafruit Bluefruit stack (ble_nrf.cpp); ESP32 boards have no Bluetooth transport yet.
#pragma once
#include <stddef.h>
#include <stdint.h>

#include "rnc_mcu_net.h"
#include "rnc_rnode_io.h"

#if defined(ARDUINO_ARCH_NRF52) || defined(NRF52840_XXAA)
#define RNC_HAVE_BLE 1
// Starts the service when a PIN is set; returns true when Bluetooth is on.
bool rnc_ble_start(const rnc_mcu_cfg *cfg);
// The byte transport of the connected central (reads nothing, writes nothing when none).
extern const rnc_rnode_io rnc_ble_io;
// Bytes waiting from the central.
int rnc_ble_available(void);
#else
#define RNC_HAVE_BLE 0
static inline bool rnc_ble_start(const rnc_mcu_cfg *) { return false; }
static inline int rnc_ble_available(void) { return 0; }
static const rnc_rnode_io rnc_ble_io = {NULL, NULL, NULL}; // never used: no Bluetooth here
#endif
