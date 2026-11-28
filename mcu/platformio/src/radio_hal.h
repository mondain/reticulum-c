// Arduino implementation of the radio HAL (mcu/radio/rnc_radio_hal.h) for ESP32 (arduino-esp32
// SPIClass) and nRF52840 (Adafruit nRF52 core SPIClass on SPIM2 with an identity pin map,
// variants/rnc_nrf52840). Bench-tested on T-Echo and Supreme SX1262; other boards remain unverified.
#pragma once
#include "rnc_boards.h"
#include "rnc_radio_hal.h"

// Brings up the SPI bus, the control pins and, where the board needs it, the power
// management chip's radio rail. Returns 0, or a negative value. `hal` is filled.
int rnc_radio_hal_init(const rnc_board *board, rnc_radio_hal *hal);

// The chip's temperature in degrees Celsius, and the battery's state (RNode protocol) and charge. 0, or a negative
// value where this board has nothing to say.
int rnc_board_temperature(int *celsius);
int rnc_board_battery(const rnc_board *board, unsigned *state, unsigned *percent);
