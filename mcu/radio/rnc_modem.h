#ifndef RNC_MODEM_H
#define RNC_MODEM_H
/*
 * The interface the LoRa interface adapter (rnc_lora_if.h) uses to drive a radio chip.
 * rnc_sx126x (SX1261/SX1262/SX1268) and rnc_sx127x (SX1276/77/78/79) implement it.
 * Everything is polling and non-blocking after init (init itself waits for the chip:
 * reset, calibration), so one task can run the whole interface.
 */
#include "rnc_lora_phy.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* the most a frame can carry */
#define RNC_MODEM_FRAME_MAX 255u

typedef struct rnc_modem_rx_info {
  int16_t rssi_dbm;   /* packet RSSI */
  int16_t snr_quarter_db; /* signal to noise ratio in quarter dB */
} rnc_modem_rx_info;

typedef struct rnc_modem rnc_modem;
typedef struct rnc_modem_ops {
  /* Resets the chip and configures it with `p` (frequency, bandwidth, spreading
   * factor, coding rate, power, preamble; explicit header, CRC on, standard IQ, the
   * private network sync word). Leaves it in standby. Returns 0, or a negative value
   * (chip absent, unsupported parameters). Waits for the chip, so it may take up to
   * about 100 ms. */
  int (*init)(rnc_modem *m, const rnc_lora_params *p);
  /* Enters continuous receive. */
  int (*start_rx)(rnc_modem *m);
  /* Non-blocking. Returns the frame size (1..255) when a frame with a good CRC was
   * received into `buf`, 0 when there is none, -1 when a frame was received and
   * dropped (CRC error). The chip stays in receive. */
  int (*poll_rx)(rnc_modem *m, uint8_t *buf, size_t capacity, rnc_modem_rx_info *info);
  /* Starts sending one frame of 1..255 bytes (leaves receive). */
  int (*start_tx)(rnc_modem *m, const uint8_t *frame, size_t size);
  /* 1 when the frame went out (the chip is back in standby), 0 while on air, -1 when
   * the transmission did not finish in time (the chip was reset to standby). */
  int (*poll_tx)(rnc_modem *m);
  /* 1 while a LoRa preamble or header is being received (the channel is taken), else
   * 0; only meaningful in receive. */
  int (*carrier)(rnc_modem *m);
  /* Instantaneous RSSI of the channel in dBm (receive mode); 0 on success. */
  int (*rssi)(rnc_modem *m, int *dbm);
  /* Channel activity detection: start_cad begins a CAD cycle (leaves receive);
   * poll_cad returns 0 while running, 1 when finished with the channel free, 2 when
   * activity was detected. The adapter returns to receive afterwards. */
  int (*start_cad)(rnc_modem *m);
  int (*poll_cad)(rnc_modem *m);
  /* Standby / sleep (lowest power, configuration lost on some chips: init again). */
  void (*standby)(rnc_modem *m);
  void (*sleep)(rnc_modem *m);
} rnc_modem_ops;

struct rnc_modem {
  const rnc_modem_ops *ops;
};

#ifdef __cplusplus
}
#endif
#endif
