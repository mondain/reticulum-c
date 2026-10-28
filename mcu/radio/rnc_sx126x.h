#ifndef RNC_SX126X_H
#define RNC_SX126X_H
/*
 * Driver for the Semtech SX1261 / SX1262 / SX1268 (LoRa only), written from the public
 * datasheet (SX1261-2 data sheet, command set and application notes). Implements
 * rnc_modem. Polling; the DIO1 line is optional (when the HAL has it, the status is
 * only read over SPI while it is high).
 *
 * Board specifics are in rnc_sx126x_board: chip variant (power amplifier path), TCXO
 * on DIO3, DIO2 as the RF switch control, DC-DC regulator, external RF switch pins.
 */
#include "rnc_modem.h"
#include "rnc_radio_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rnc_sx126x_board {
  uint16_t chip;       /* 1262 (SX1262 and SX1268, high power path, -9..+22 dBm) or 1261
                        * (low power path, -17..+15 dBm) */
  uint8_t tcxo_code;   /* 0 = crystal; else 1 + the DIO3 TCXO voltage code of the datasheet:
                        * 1 -> 1.6 V, 2 -> 1.7, 3 -> 1.8, 4 -> 2.2, 5 -> 2.4, 6 -> 2.7,
                        * 7 -> 3.0, 8 -> 3.3 */
  uint16_t tcxo_start_us; /* TCXO start time allowed, 0 = 5000 */
  uint8_t dio2_rf_switch; /* DIO2 controls the antenna switch (high while transmitting) */
  uint8_t dcdc;        /* use the DC-DC regulator (the board has its inductor) */
  uint8_t ocp;         /* over-current protection register value (0x08E7), 0 = chip default */
} rnc_sx126x_board;

#define RNC_SX126X_TCXO_1V6 1u
#define RNC_SX126X_TCXO_1V7 2u
#define RNC_SX126X_TCXO_1V8 3u
#define RNC_SX126X_TCXO_2V2 4u
#define RNC_SX126X_TCXO_2V4 5u
#define RNC_SX126X_TCXO_2V7 6u
#define RNC_SX126X_TCXO_3V0 7u
#define RNC_SX126X_TCXO_3V3 8u

typedef struct rnc_sx126x {
  rnc_modem base; /* first member */
  const rnc_radio_hal *hal;
  rnc_sx126x_board board;
  rnc_lora_params params;
  uint8_t mode; /* 0 unconfigured, 1 standby, 2 rx, 3 tx, 4 cad */
  uint64_t tx_deadline_us;
  uint64_t carrier_until_us;
  uint32_t symbol_us;
  uint32_t busy_timeouts; /* BUSY stuck high */
} rnc_sx126x;

/* Prepares the driver object (no hardware access). */
void rnc_sx126x_attach(rnc_sx126x *d, const rnc_radio_hal *hal, const rnc_sx126x_board *board);

/* Pure helpers, exposed for tests. */
/* The 32 bit RfFrequency register value for a carrier: freq * 2^25 / 32 MHz. */
uint32_t rnc_sx126x_frf(uint32_t freq_hz);
/* The BW code of SetModulationParams for a nominal bandwidth, or -1. */
int rnc_sx126x_bw_code(uint32_t bw_hz);
/* SetPaConfig parameters {paDutyCycle, hpMax, deviceSel, paLut} and the SetTxParams power
 * for a requested output power; returns 0, or -1 when the power is out of range. */
int rnc_sx126x_pa(unsigned chip, int dbm, uint8_t pa[4], int8_t *tx_power);
/* CalibrateImage bytes for the band of a frequency; 0 on success. */
int rnc_sx126x_image_band(uint32_t freq_hz, uint8_t out[2]);

#ifdef __cplusplus
}
#endif
#endif
