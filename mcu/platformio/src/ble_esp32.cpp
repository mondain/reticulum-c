// Bluetooth LE Nordic UART transport on ESP32 / ESP32-S3 (NimBLE-Arduino). See ble_mode.h.
// Nothing the host sends is accepted, and nothing is sent, until the link is encrypted and
// authenticated with the operator's PIN (static passkey, MITM).
#include "ble_mode.h"

#if RNC_HAVE_BLE && defined(ARDUINO_ARCH_ESP32)
#include <Arduino.h>
#include <NimBLEDevice.h>

#define NUS_SERVICE "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
#define NUS_RX "6E400002-B5A3-F393-E0A9-E50E24DCCA9E" // the central writes here
#define NUS_TX "6E400003-B5A3-F393-E0A9-E50E24DCCA9E" // notifications to the central

static NimBLECharacteristic *g_tx = NULL;
static volatile bool g_connected = false;
static volatile bool g_secure = false; // encrypted and authenticated (the PIN was used)
static uint8_t g_ring[1024];
static volatile uint16_t g_head = 0, g_tail = 0; // written by the NimBLE task, read by ours
static portMUX_TYPE g_mux = portMUX_INITIALIZER_UNLOCKED;

static void ring_push(const uint8_t *data, size_t size) {
  portENTER_CRITICAL(&g_mux);
  for (size_t i = 0; i < size; i++) {
    uint16_t next = (uint16_t)((g_head + 1u) % sizeof(g_ring));
    if (next == g_tail)
      break; // full: the rest is dropped (the host retries or times out)
    g_ring[g_head] = data[i];
    g_head = next;
  }
  portEXIT_CRITICAL(&g_mux);
}

class RxCallbacks : public NimBLECharacteristicCallbacks {
  void onWrite(NimBLECharacteristic *characteristic) override {
    if (!g_secure)
      return; // not paired: ignored (the characteristic also requires authentication)
    std::string value = characteristic->getValue();
    ring_push((const uint8_t *)value.data(), value.size());
  }
};

class ServerCallbacks : public NimBLEServerCallbacks {
  void onConnect(NimBLEServer *, ble_gap_conn_desc *desc) override {
    g_connected = true;
    g_secure = false;
    NimBLEDevice::startSecurity(desc->conn_handle); // ask for pairing at once
  }
  void onDisconnect(NimBLEServer *) override {
    g_connected = false;
    g_secure = false;
    portENTER_CRITICAL(&g_mux);
    g_head = g_tail = 0; // nothing of the old connection is left for the next one
    portEXIT_CRITICAL(&g_mux);
    NimBLEDevice::startAdvertising();
  }
  void onAuthenticationComplete(ble_gap_conn_desc *desc) override {
    g_secure = desc->sec_state.encrypted && desc->sec_state.authenticated;
    if (!g_secure)
      NimBLEDevice::getServer()->disconnect(desc->conn_handle);
  }
};

static int ble_read(void *, uint8_t *buffer, size_t capacity) {
  size_t n = 0;
  portENTER_CRITICAL(&g_mux);
  while (n < capacity && g_tail != g_head) {
    buffer[n++] = g_ring[g_tail];
    g_tail = (uint16_t)((g_tail + 1u) % sizeof(g_ring));
  }
  portEXIT_CRITICAL(&g_mux);
  return (int)n;
}

// Notifications are limited by the negotiated MTU; larger writes go out in chunks.
static int ble_write(void *, const uint8_t *data, size_t size) {
  size_t done = 0;
  if (!g_tx || !g_connected || !g_secure)
    return 0;
  size_t chunk = NimBLEDevice::getMTU() > 23 ? (size_t)(NimBLEDevice::getMTU() - 3) : 20u;
  while (done < size && g_connected) {
    size_t n = size - done < chunk ? size - done : chunk;
    g_tx->setValue(data + done, n);
    g_tx->notify(); // NimBLE-Arduino 1.4 returns nothing; a lost link ends the loop below
    done += n;
    delay(2); // give the stack time to send before the next chunk
  }
  return (int)done;
}

const rnc_rnode_io rnc_ble_io = {ble_read, ble_write, NULL};

int rnc_ble_available(void) {
  int n;
  if (!g_connected || !g_secure)
    return 0;
  portENTER_CRITICAL(&g_mux);
  n = (int)((g_head + sizeof(g_ring) - g_tail) % sizeof(g_ring));
  portEXIT_CRITICAL(&g_mux);
  return n;
}

bool rnc_ble_start(const rnc_mcu_cfg *cfg) {
  char name[16];
  if (!rnc_mcu_cfg_ble_ready(cfg))
    return false; // no PIN: Bluetooth stays off
  snprintf(name, sizeof(name), "RNode %04X", (unsigned)((ESP.getEfuseMac() >> 32) & 0xFFFFu));
  NimBLEDevice::init(name);
  NimBLEDevice::setMTU(247);
  NimBLEDevice::setSecurityAuth(true, true, true);              // bonding, MITM, secure connections
  NimBLEDevice::setSecurityIOCap(BLE_HS_IO_DISPLAY_ONLY);      // the PIN is the operator's, shown elsewhere
  NimBLEDevice::setSecurityPasskey((uint32_t)atol(cfg->ble_pin));
  NimBLEServer *server = NimBLEDevice::createServer();
  server->setCallbacks(new ServerCallbacks());
  NimBLEService *service = server->createService(NUS_SERVICE);
  g_tx = service->createCharacteristic(NUS_TX, NIMBLE_PROPERTY::NOTIFY);
  NimBLECharacteristic *rx = service->createCharacteristic(
      NUS_RX, NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR | NIMBLE_PROPERTY::WRITE_ENC |
                  NIMBLE_PROPERTY::WRITE_AUTHEN);
  rx->setCallbacks(new RxCallbacks());
  service->start();
  NimBLEAdvertising *advertising = NimBLEDevice::getAdvertising();
  advertising->addServiceUUID(NUS_SERVICE);
  advertising->setScanResponse(true);
  advertising->start();
  return true;
}
#endif
