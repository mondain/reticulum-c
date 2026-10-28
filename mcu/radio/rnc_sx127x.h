#ifndef RNC_SX127X_H
#define RNC_SX127X_H
/*
 * Driver for the Semtech SX1276 / SX1277 / SX1278 / SX1279 in LoRa mode, written from
 * the public SX1276/77/78/79 data sheet (register map, LoRa modem chapter, errata
 * notes). Implements rnc_modem. Register level and polling; DIO0 is optional (mapped
 * to RxDone in receive and TxDone in transmit, used as a shortcut for the status read).
 */
#include "rnc_modem.h"
#include "rnc_radio_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rnc_sx127x_board {
  uint8_t pa_boost; /* 1: antenna on the PA_BOOST pin (2..17 dBm, up to 20 with the PA DAC);
                     * 0: on the RFO pin (0..14 dBm) */
} rnc_sx127x_board;

typedef struct rnc_sx127x {
  rnc_modem base; /* first member */
  const rnc_radio_hal *hal;
  rnc_sx127x_board board;
  rnc_lora_params params;
  uint8_t mode; /* 0 unconfigured, 1 standby, 2 rx, 3 tx, 4 cad */
  uint8_t low_band; /* carrier below 525 MHz (LowFrequencyModeOn, RSSI offset) */
  uint64_t tx_deadline_us;
} rnc_sx127x;

void rnc_sx127x_attach(rnc_sx127x *d, const rnc_radio_hal *hal, const rnc_sx127x_board *board);

/* Pure helpers, exposed for tests. */
/* RegFrf value: freq * 2^19 / 32 MHz, truncated. */
uint32_t rnc_sx127x_frf(uint32_t freq_hz);
/* RegModemConfig1 bandwidth field (0..9) for a nominal bandwidth, or -1. */
int rnc_sx127x_bw_code(uint32_t bw_hz);
/* RegPaConfig, RegPaDac and RegOcp for a requested power; 0, or -1 out of range. */
int rnc_sx127x_pa(int pa_boost, int dbm, uint8_t *pa_config, uint8_t *pa_dac, uint8_t *ocp);

/* Switches the modem between explicit header (default) and implicit header with a fixed
 * payload length. Not used by the Reticulum interface (the air format has explicit
 * headers) but required for SF6, which only exists with implicit headers. */
int rnc_sx127x_set_header_mode(rnc_sx127x *d, int implicit, unsigned payload_length);

#ifdef __cplusplus
}
#endif
#endif
