#ifndef RADIO_HAL_IDF_H
#define RADIO_HAL_IDF_H
/* ESP-IDF implementation of the radio HAL (mcu/radio/rnc_radio_hal.h): spi_master for the
 * chip, gpio for the control lines, esp_timer and esp_rom_delay_us for time. The pins come
 * from the board table entry selected by Kconfig (RETICULUM_MCU_LORA_BOARD_*). */
#include "rnc_boards.h"
#include "rnc_radio_hal.h"

/* Brings up the SPI bus, the control pins and, for boards that need it, the power
 * management chip's radio rail. Returns 0 or a negative value. `hal` is filled. */
int radio_hal_idf_init(const rnc_board *board, rnc_radio_hal *hal);
#endif
