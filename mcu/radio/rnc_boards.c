/* Board table; see rnc_boards.h. Pin maps and chip variants are facts about the hardware
 * (taken from the public board definitions of the RNode firmware project and checked against
 * manufacturer documentation where I know it; see README.txt for the confidence of each
 * entry). */
#include "rnc_boards.h"
#include <string.h>

#define N (-1)

static const rnc_board BOARDS[] = {
    {"heltec_wifi_lora_32_V3", "Heltec WiFi LoRa 32 V3 (ESP32-S3, SX1262)", RNC_BOARD_SX1262,
     {1262, RNC_SX126X_TCXO_3V3, 5000, 1, 0, 0x28}, 0,
     /* sck miso mosi cs reset busy dio rxen txen */
     9, 11, 10, 8, 12, 13, 14, N, N, N, RNC_BOARD_PMU_NONE, N, N, 1, 22,
     "TCXO voltage from the RNode firmware (3.3 V); the Heltec documentation was not checked"},
    {"heltec_wifi_lora_32_V2", "Heltec WiFi LoRa 32 V2 (ESP32, SX1276)", RNC_BOARD_SX1276,
     {0, 0, 0, 0, 0, 0}, 1, 5, 19, 27, 18, 14, N, 26, N, N, N, RNC_BOARD_PMU_NONE, N, N, 1, 20,
     "SPI pins SCK 5, MISO 19, MOSI 27 are the common ESP32 LoRa board wiring"},
    {"ttgo_t_beam", "LilyGo T-Beam v1.0/v1.1 (ESP32, SX1276, AXP192)", RNC_BOARD_SX1276,
     {0, 0, 0, 0, 0, 0}, 1, 5, 19, 27, 18, 23, N, 26, N, N, N, RNC_BOARD_PMU_AXP192, 21, 22, 1, 20,
     "the radio rail is switched by the AXP192 (LDO2, 3.3 V): the port enables it over I2C; the v1.2 "
     "with an AXP2101 is not supported"},
    {"lilygo_t_beam_supreme", "LilyGo T-Beam Supreme (ESP32-S3, SX1262, AXP2101)", RNC_BOARD_SX1262,
     {1262, RNC_SX126X_TCXO_1V8, 5000, 1, 0, 0x28}, 0, 12, 13, 11, 10, 5, 4, 1, N, N, N,
     RNC_BOARD_PMU_AXP2101, 42, 41, 0, 22,
     "pin map known, but the radio rail needs the AXP2101 PMU initialised and that is not "
     "implemented: NOT SUPPORTED"},
    {"lilygo_t3_s3", "LilyGo T3-S3 V1.x (ESP32-S3, SX1262)", RNC_BOARD_SX1262,
     {1262, RNC_SX126X_TCXO_1V8, 5000, 1, 0, 0x28}, 0, 5, 3, 6, 7, 8, 34, 33, N, N, N,
     RNC_BOARD_PMU_NONE, N, N, 1, 22,
     "the SX1262 variant of the T3-S3 (there are SX1276, SX1280 and LR1121 variants of the board that "
     "this table does not describe)"},
    {"wiscore_rak4631", "RAKwireless WisCore RAK4631 (nRF52840, SX1262)", RNC_BOARD_SX1262,
     {1262, RNC_SX126X_TCXO_3V3, 5000, 1, 0, 0x28}, 0, 43, 45, 44, 42, 38, 46, 47, 37, N, N,
     RNC_BOARD_PMU_NONE, N, N, 1, 22,
     "RXEN (pin 37) powers the antenna switch and is held high; TCXO voltage from the RNode firmware"},
    {"heltec_t114", "Heltec Mesh Node T114 (nRF52840, SX1262)", RNC_BOARD_SX1262,
     {1262, RNC_SX126X_TCXO_1V8, 5000, 1, 0, 0x28}, 0, 19, 23, 22, 24, 25, 17, 20, N, N, N,
     RNC_BOARD_PMU_NONE, N, N, 1, 22, ""},
    {"lilygo_t_echo", "LilyGo T-Echo (nRF52840, SX1262)", RNC_BOARD_SX1262,
     {1262, RNC_SX126X_TCXO_1V8, 5000, 1, 0, 0x28}, 0, 19, 23, 22, 24, 25, 17, 20, N, N, 12,
     RNC_BOARD_PMU_NONE, N, N, 1, 22,
     "pin 12 (VEXT) is driven high before the radio, as the RNode firmware does; the RNode "
     "firmware does not enable DIO2 as the antenna switch control here, this table does"},
};

unsigned rnc_board_count(void) { return (unsigned)(sizeof(BOARDS) / sizeof(BOARDS[0])); }
const rnc_board *rnc_board_at(unsigned index) {
  return index < rnc_board_count() ? &BOARDS[index] : NULL;
}
const rnc_board *rnc_board_find(const char *id) {
  unsigned i;
  for (i = 0; i < rnc_board_count(); i++)
    if (id && !strcmp(BOARDS[i].id, id))
      return &BOARDS[i];
  return NULL;
}
