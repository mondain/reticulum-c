#include "radio_hal.h"

#include <Arduino.h>
#include <SPI.h>
#include <string.h>

#if defined(ARDUINO_ARCH_ESP32)
#include <Wire.h>
#endif

#define RADIO_SPI_HZ 4000000u

static struct {
  int8_t pin[RNC_PIN_COUNT];
  int8_t cs;
  bool ready;
  uint32_t last_micros;
  uint64_t high;
} s_hal;

#if defined(ARDUINO_ARCH_ESP32)
#if defined(CONFIG_IDF_TARGET_ESP32)
static SPIClass s_spi(VSPI); // the original ESP32: the general purpose SPI host
#else
static SPIClass s_spi(FSPI); // ESP32-S3: SPI2
#endif
#else
static SPIClass s_spi(NRF_SPIM2, 0, 0, 0); // pins are replaced in rnc_radio_hal_init
#endif

static int hal_spi(void *, const uint8_t *tx, uint8_t *rx, size_t len) {
  if (!s_hal.ready || len == 0 || len > 260)
    return -1;
  uint8_t zeros[260];
  if (!tx) {
    memset(zeros, 0, len);
    tx = zeros;
  }
  s_spi.beginTransaction(SPISettings(RADIO_SPI_HZ, MSBFIRST, SPI_MODE0));
  digitalWrite(s_hal.cs, LOW);
#if defined(ARDUINO_ARCH_ESP32)
  uint8_t scratch[260];
  s_spi.transferBytes(tx, rx ? rx : scratch, len);
#else
  uint8_t scratch[260];
  s_spi.transfer(tx, rx ? rx : scratch, len);
#endif
  digitalWrite(s_hal.cs, HIGH);
  s_spi.endTransaction();
  return 0;
}

static void hal_write(void *, rnc_radio_pin pin, int level) {
  if (pin < RNC_PIN_COUNT && s_hal.pin[pin] >= 0)
    digitalWrite(s_hal.pin[pin], level ? HIGH : LOW);
}

static int hal_read(void *, rnc_radio_pin pin) {
  if (pin >= RNC_PIN_COUNT || s_hal.pin[pin] < 0)
    return -1;
  return digitalRead(s_hal.pin[pin]) == HIGH ? 1 : 0;
}

static void hal_delay(void *, uint32_t us) {
  if (us >= 2000u)
    delay((us + 999u) / 1000u); // yields to the other tasks
  else
    delayMicroseconds(us);
}

// 64-bit microseconds from the 32-bit micros() (wraps every 71 minutes): called far more
// often than once per wrap, from the Reticulum task only
static uint64_t hal_now(void *) {
  uint32_t now = micros();
  if (now < s_hal.last_micros)
    s_hal.high += (uint64_t)1 << 32;
  s_hal.last_micros = now;
  return s_hal.high + now;
}

#if defined(ARDUINO_ARCH_ESP32)
// The T-Beam v1.0/v1.1 power the LoRa module from LDO2 of the AXP192: set 3.3 V and switch
// it on over I2C (address 0x34; register 0x28 holds the LDO2 voltage in its high nibble,
// register 0x12 the output enables, bit 2 is LDO2). UNTESTED.
static int axp192_enable_lora(int sda, int scl) {
  Wire.begin(sda, scl, 100000);
  Wire.beginTransmission(0x34);
  Wire.write(0x28);
  if (Wire.endTransmission(false) != 0)
    return -1;
  if (Wire.requestFrom(0x34, 1) != 1)
    return -1;
  uint8_t v = Wire.read();
  Wire.beginTransmission(0x34);
  Wire.write(0x28);
  Wire.write((uint8_t)((v & 0x0F) | 0xF0));
  if (Wire.endTransmission() != 0)
    return -1;
  Wire.beginTransmission(0x34);
  Wire.write(0x12);
  if (Wire.endTransmission(false) != 0)
    return -1;
  if (Wire.requestFrom(0x34, 1) != 1)
    return -1;
  v = Wire.read();
  Wire.beginTransmission(0x34);
  Wire.write(0x12);
  Wire.write((uint8_t)(v | 0x04));
  if (Wire.endTransmission() != 0)
    return -1;
  delay(20);
  Wire.end();
  return 0;
}
#endif

int rnc_radio_hal_init(const rnc_board *board, rnc_radio_hal *hal) {
  if (!board || !board->supported)
    return -1;
  memset(&s_hal, 0, sizeof(s_hal));
  memset(s_hal.pin, -1, sizeof(s_hal.pin));
  s_hal.pin[RNC_PIN_RESET] = board->reset;
  s_hal.pin[RNC_PIN_BUSY] = board->busy;
  s_hal.pin[RNC_PIN_DIO] = board->dio;
  s_hal.pin[RNC_PIN_RXEN] = board->rxen;
  s_hal.pin[RNC_PIN_TXEN] = board->txen;
  s_hal.cs = board->cs;
  if (board->power_pin >= 0) {
    pinMode(board->power_pin, OUTPUT);
    digitalWrite(board->power_pin, HIGH);
  }
#if defined(ARDUINO_ARCH_ESP32)
  if (board->pmu == RNC_BOARD_PMU_AXP192 && axp192_enable_lora(board->i2c_sda, board->i2c_scl) != 0)
    return -2;
#endif
  if (board->pmu == RNC_BOARD_PMU_AXP2101)
    return -3; // not implemented
  pinMode(board->cs, OUTPUT);
  digitalWrite(board->cs, HIGH);
  pinMode(board->reset, OUTPUT);
  digitalWrite(board->reset, HIGH);
  if (board->rxen >= 0) {
    pinMode(board->rxen, OUTPUT);
    digitalWrite(board->rxen, LOW);
  }
  if (board->txen >= 0) {
    pinMode(board->txen, OUTPUT);
    digitalWrite(board->txen, LOW);
  }
  if (board->busy >= 0)
    pinMode(board->busy, INPUT);
  if (board->dio >= 0)
    pinMode(board->dio, INPUT);
#if defined(ARDUINO_ARCH_ESP32)
  s_spi.begin(board->sck, board->miso, board->mosi, -1); // chip select is driven by hal_spi
#else
  s_spi = SPIClass(NRF_SPIM2, (uint8_t)board->miso, (uint8_t)board->sck, (uint8_t)board->mosi);
  s_spi.begin();
#endif
  s_hal.ready = true;
  memset(hal, 0, sizeof(*hal));
  hal->spi_transfer = hal_spi;
  hal->gpio_write = hal_write;
  hal->gpio_read = hal_read;
  hal->delay_us = hal_delay;
  hal->now_us = hal_now;
  return 0;
}
