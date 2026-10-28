#ifndef LORA_SIM_H
#define LORA_SIM_H
/*
 * Shared radio medium for the host tests of the LoRa support: joins several modelled
 * radios (SX126x and SX127x models) on one simulated channel, with a virtual clock.
 *
 *   - propagation: a loss matrix in dB (no entry = out of range, which is how a hidden
 *     node is built) and an optional random frame loss in permille per link;
 *   - a frame is received by a radio that was in continuous receive before the
 *     preamble ended, is not itself transmitting, has the same frequency, bandwidth,
 *     spreading factor, low data rate setting and sync word class, and hears it above
 *     its sensitivity;
 *   - collisions: transmissions that overlap in time on the same channel destroy each
 *     other at a receiver unless one is stronger by `capture_db` (the capture effect);
 *     a destroyed frame is delivered with a CRC error to the radio that was locked on it;
 *   - carrier sensing for the radio models (preamble detect, modem status, RSSI).
 *
 * The models and this medium are written by the same author as the drivers, so they share
 * any misreading of the datasheets; they check the drivers' consistency with a careful
 * reading of them, not the behaviour of real silicon.
 */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SIM_MAX_RADIOS 6
#define SIM_MAX_TX 160
#define SIM_NO_LINK 9999

typedef struct sim_phy {
  uint32_t freq_hz, bw_hz;
  uint8_t sf, cr, ldro;
  uint8_t net; /* sync word class: 0 private (0x12 / 0x1424), 1 public (0x34 / 0x3444), 2 other */
  uint16_t preamble;
  int8_t txp_dbm;
} sim_phy;

typedef struct sim_radio_ops {
  /* 1 when the radio is in continuous receive; fills `phy` and the time it entered */
  int (*rx_state)(void *radio, sim_phy *phy, uint64_t *since_us);
  void (*deliver)(void *radio, const uint8_t *frame, size_t len, int crc_ok, int rssi_dbm,
                  int snr_quarter_db);
} sim_radio_ops;

typedef struct sim_tx {
  int radio;
  uint8_t frame[255];
  size_t len;
  uint64_t start_us, end_us;
  sim_phy phy;
  int done;
} sim_tx;

typedef struct sim_medium {
  uint64_t now_us;
  int count;
  void *radio[SIM_MAX_RADIOS];
  const sim_radio_ops *ops[SIM_MAX_RADIOS];
  int loss_db[SIM_MAX_RADIOS][SIM_MAX_RADIOS];       /* SIM_NO_LINK: not heard */
  uint16_t drop_permille[SIM_MAX_RADIOS][SIM_MAX_RADIOS];
  int capture_db;      /* 6 by default; 1000 disables capture */
  int noise_floor_dbm; /* -110 by default */
  sim_tx tx[SIM_MAX_TX];
  uint32_t seed;
  /* statistics */
  uint32_t frames_sent, frames_delivered, lost_collision, lost_random, lost_unheard,
      lost_not_listening, lost_phy_mismatch, max_frame;
  uint64_t air_us[SIM_MAX_RADIOS]; /* total time on air per radio */
  uint32_t log_count;
  uint8_t log_first[256]; /* header byte of the first 256 frames on the air */
  uint16_t log_len[256];
  uint8_t log_radio[256];
} sim_medium;

void sim_medium_init(sim_medium *m, uint32_t seed);
/* Adds a radio; returns its index. Links default to none; use sim_link. */
int sim_medium_add(sim_medium *m, void *radio, const sim_radio_ops *ops);
/* Symmetric link with a path loss in dB. */
void sim_link(sim_medium *m, int a, int b, int loss_db);
void sim_link_drop(sim_medium *m, int a, int b, unsigned permille);
/* Links everything to everything with this loss. */
void sim_link_all(sim_medium *m, int loss_db);
/* Delivers every transmission that has ended by `m->now_us`. */
void sim_medium_advance(sim_medium *m);
/* A radio starts transmitting a frame lasting `duration_us`. */
void sim_medium_tx(sim_medium *m, int radio, const uint8_t *frame, size_t len, const sim_phy *phy,
                   uint64_t duration_us);
/* 1 when the radio is transmitting at m->now_us. */
int sim_transmitting(const sim_medium *m, int radio);
/* Carrier sensing at `radio` (which listens with `phy`): 1 when a heard transmission with
 * the same channel parameters has been on air for at least `detect_us`; `start_us` gets its
 * start time. */
int sim_sense(const sim_medium *m, int radio, const sim_phy *phy, uint64_t detect_us,
              uint64_t *start_us);
/* Instantaneous RSSI at the radio: the strongest co-channel transmission or the noise floor. */
int sim_rssi(const sim_medium *m, int radio, const sim_phy *phy);
/* Receiver sensitivity (dBm) for a bandwidth and spreading factor. */
double sim_sensitivity_dbm(uint32_t bw_hz, unsigned sf);
/* Time on air in microseconds by the Semtech formula, written separately from the driver's
 * (floating point, straight from the formula as printed in the datasheets). */
double sim_toa_us(uint32_t bw_hz, unsigned sf, unsigned cr_denominator, unsigned preamble,
                  unsigned payload, int ldro);
/* The nominal bandwidth in exact Hz. */
double sim_bw_exact(uint32_t bw_nominal);

#ifdef __cplusplus
}
#endif
#endif
