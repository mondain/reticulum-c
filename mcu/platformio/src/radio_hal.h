// Arduino implementation of the radio HAL (mcu/radio/rnc_radio_hal.h) for ESP32 (arduino-esp32
// SPIClass) and nRF52840 (Adafruit nRF52 core SPIClass on SPIM2 with an identity pin map,
// variants/rnc_nrf52840). NOT RUN ON HARDWARE: compiled only.
#pragma once
#include "rnc_boards.h"
#include "rnc_radio_hal.h"

// Brings up the SPI bus, the control pins and, where the board needs it, the power
// management chip's radio rail. Returns 0, or a negative value. `hal` is filled.
int rnc_radio_hal_init(const rnc_board *board, rnc_radio_hal *hal);
