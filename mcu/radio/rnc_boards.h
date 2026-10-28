#ifndef RNC_BOARDS_H
#define RNC_BOARDS_H
/*
 * The boards the firmware knows: chip variant, SPI and control pins and the radio's
 * board-level properties (TCXO, antenna switch, regulator, PA path). Portable data, no
 * platform headers; the ESP-IDF and Arduino ports select one entry at build time (Kconfig
 * choice, PlatformIO build flag) and feed it to their HAL.
 *
 * Pin numbers are the chip's own GPIO numbers (ESP32: GPIO n; nRF52: port * 32 + pin).
 * Where they come from and how sure each entry is: mcu/radio/README.txt. A pin of -1 is
 * not present on the board.
 *
 * REGULATORY: nothing here sets a frequency or a power. See rnc_lora_cfg.h.
 */
#include "rnc_sx126x.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum rnc_board_chip {
  RNC_BOARD_SX1262 = 1262,
  RNC_BOARD_SX1276 = 1276
} rnc_board_chip;

#define RNC_BOARD_PMU_NONE 0
#define RNC_BOARD_PMU_AXP192 1 /* the radio rail (LDO2) must be switched on over I2C first */
#define RNC_BOARD_PMU_AXP2101 2 /* ... (ALDO3) likewise; not implemented */

typedef struct rnc_board {
  const char *id;       /* the PlatformIO environment / Kconfig name */
  const char *name;     /* what the board is called */
  rnc_board_chip chip;
  rnc_sx126x_board sx126x; /* SX1262 boards */
  uint8_t pa_boost;        /* SX1276 boards: antenna on PA_BOOST */
  int8_t sck, miso, mosi, cs, reset, busy, dio, rxen, txen;
  int8_t power_pin;     /* output driven high before the radio is used, -1 none */
  uint8_t pmu;          /* RNC_BOARD_PMU_* */
  int8_t i2c_sda, i2c_scl;
  uint8_t supported;    /* 1: the firmware drives this board; 0: listed, not usable (see the notes) */
  int8_t max_txp_dbm;   /* highest chip output power the firmware accepts here */
  const char *notes;
} rnc_board;

unsigned rnc_board_count(void);
const rnc_board *rnc_board_at(unsigned index);
/* by id; NULL when unknown */
const rnc_board *rnc_board_find(const char *id);

#ifdef __cplusplus
}
#endif
#endif
