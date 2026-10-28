#ifndef SX127X_MODEL_H
#define SX127X_MODEL_H
/*
 * Software model of an SX1276/77/78/79 in LoRa mode at register level, written from the
 * public datasheet for the host tests. It enforces the datasheet's rules the drivers
 * depend on: the LoRa bit of RegOpMode changes only in sleep, the modem registers are not
 * written while transmitting or receiving, the FIFO is written only in standby, a
 * transmission needs a payload length, SF6 needs implicit header mode, the PA DAC and PA
 * configuration must agree, the 500 kHz receiver optimisation registers follow the errata.
 * Violations are counted with a message. Written by the author of the driver it checks, so
 * a misreading of the datasheet could be present in both.
 */
#include "../../radio/rnc_radio_hal.h"
#include "lora_sim.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sx127x_model {
  sim_medium *medium;
  int id;
  rnc_radio_hal hal;
  int has_dio0;           /* DIO0 is wired (the HAL reports its level) */
  uint8_t regs[0x80];
  uint8_t fifo[256];
  int mode;               /* 0 sleep, 1 stdby, 3 tx, 5 rxcont, 7 cad (RegOpMode bits 2..0) */
  uint64_t rx_since_us, tx_end_us, cad_end_us;
  unsigned violations;
  char first_violation[120];
  unsigned frames_sent, frames_received, crc_errors, bw500_degraded, writes, reads;
  uint8_t pending_payload_len;
} sx127x_model;

void sx127x_model_init(sx127x_model *m, sim_medium *medium, int has_dio0);
double sx127x_model_freq_hz(const sx127x_model *m);

#ifdef __cplusplus
}
#endif
#endif
