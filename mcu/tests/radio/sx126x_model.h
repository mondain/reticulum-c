#ifndef SX126X_MODEL_H
#define SX126X_MODEL_H
/*
 * Software model of an SX1261/SX1262 at the SPI command level, written from the public
 * datasheet for the host tests. It is deliberately strict: a command that the datasheet
 * does not allow in the current state, that has the wrong length, that arrives while BUSY
 * is high, or that depends on an earlier command that was never sent (packet type before
 * frequency, PA configuration before TX parameters, TCXO control before the oscillator is
 * used on a board that has a TCXO ...) is counted as a violation with a message. It
 * tracks the chip mode (sleep, STDBY_RC, STDBY_XOSC, FS, RX, TX, CAD), the packet type,
 * modulation and packet parameters, the IRQ mask and flags, the data buffer and the
 * registers the drivers use, and it behaves like silicon would for two silent failure
 * modes of the datasheet's errata (IQ polarity register, 500 kHz modulation quality).
 *
 * It was written by the author of the driver it checks, so a misreading of the datasheet
 * could be present in both.
 */
#include "../../radio/rnc_radio_hal.h"
#include "lora_sim.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sx126x_model {
  sim_medium *medium;
  int id;
  rnc_radio_hal hal;
  /* what the board is */
  unsigned variant;       /* 1261 or 1262 */
  int tcxo_present;       /* the board has a TCXO on DIO3: it must be configured before use */
  int absent;             /* the chip does not answer (tests of init failure and retry) */
  int dio2_switch;        /* the antenna switch is controlled by DIO2: must be enabled */
  /* chip state */
  int mode;               /* 0 sleep, 2 stdby rc, 3 stdby xosc, 4 fs, 5 rx, 6 tx, 7 cad */
  int packet_type;        /* -1 not set, 0 GFSK, 1 LoRa */
  uint32_t frf;           /* RfFrequency register */
  int have_freq, have_mod, have_pkt, have_pa, have_txp, have_buffer_base, have_irq_params;
  uint8_t pa[4];
  int8_t tx_power;
  uint8_t ramp;
  uint8_t sf, bw, cr, ldro;
  uint16_t preamble;
  uint8_t header_type, payload_len, crc_type, invert_iq;
  uint8_t tx_base, rx_base;
  uint16_t irq_mask, dio1_mask, irq_status;
  uint8_t tcxo_ctrl_set, tcxo_voltage;
  uint32_t tcxo_delay;
  uint8_t dio2_rf, regulator, fallback;
  uint8_t calibration, image_cal[2];
  uint16_t device_errors;
  uint8_t cad[7];
  int have_cad;
  uint8_t regs[0x1000];
  uint8_t buffer[256];
  /* reception */
  uint64_t rx_since_us;
  uint8_t rx_len, rx_start;
  uint8_t rx_rssi_raw;
  int8_t rx_snr_raw;
  /* transmission */
  uint64_t tx_end_us, cad_end_us, busy_until_us, last_pre_start, last_hdr_start;
  uint8_t tx_frame_len;
  /* diagnostics */
  unsigned violations;
  char first_violation[120];
  unsigned commands, frames_sent, frames_received, crc_errors, iq_misses, antenna_misses,
      bw500_degraded;
  uint8_t last_opcode;
} sx126x_model;

/* `variant`: 1261 or 1262. `tcxo_present`/`dio2_switch`: board properties the driver must
 * respect. Registers the model with the medium and fills m->hal. */
void sx126x_model_init(sx126x_model *m, sim_medium *medium, unsigned variant, int tcxo_present,
                       int dio2_switch);
/* The carrier frequency the model is tuned to, in Hz. */
double sx126x_model_freq_hz(const sx126x_model *m);

#ifdef __cplusplus
}
#endif
#endif
