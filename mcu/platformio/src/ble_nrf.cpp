// Bluetooth LE Nordic UART transport on nRF52840 (Adafruit Bluefruit stack, the SoftDevice that
// the Adafruit bootloader keeps in place). See ble_mode.h.
#include "ble_mode.h"

#if RNC_HAVE_BLE && (defined(ARDUINO_ARCH_NRF52) || defined(NRF52840_XXAA))
#include <Arduino.h>
#include <bluefruit.h>

// BLEUart creates its characteristics open (its source says "TODO enable encryption"), so a
// PIN would protect nothing. This copy of its begin() asks for an encrypted, authenticated
// (MITM, here the static passkey) link before the characteristics can be used: the CCCD write
// (turning notifications on) takes the TX characteristic's read permission, and the RX
// characteristic can only be written when paired.
class RncUart : public BLEUart {
public:
  err_t begin(void) {
    err_t r;
    _rx_fifo = new Adafruit_FIFO(1);
    _rx_fifo->begin(_rx_fifo_depth);
    r = BLEService::begin();
    if (r != ERROR_NONE)
      return r;
    uint16_t max_mtu = Bluefruit.getMaxMtu(BLE_GAP_ROLE_PERIPH);
    _txd.setProperties(CHR_PROPS_NOTIFY);
    _txd.setPermission(SECMODE_ENC_WITH_MITM, SECMODE_NO_ACCESS);
    _txd.setMaxLen(max_mtu);
    _txd.setUserDescriptor("TXD");
    r = _txd.begin();
    if (r != ERROR_NONE)
      return r;
    _rxd.setProperties(CHR_PROPS_WRITE | CHR_PROPS_WRITE_WO_RESP);
    _rxd.setWriteCallback(BLEUart::bleuart_rxd_cb, true);
    _rxd.setPermission(SECMODE_NO_ACCESS, SECMODE_ENC_WITH_MITM);
    _rxd.setMaxLen(max_mtu);
    _rxd.setUserDescriptor("RXD");
    return _rxd.begin();
  }
};
static RncUart g_uart;

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
