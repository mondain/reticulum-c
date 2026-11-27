#ifndef RNC_SX1302_H
#define RNC_SX1302_H
/*
 * An rnc_modem (mcu/radio/rnc_modem.h) on a Semtech SX1302 concentrator with SX1250
 * radios, driven through Semtech's libloragw (sx1302_hal 2.1.0), on Linux. Written for the
 * Seeed WM1302 SPI module on the WM1302 Pi HAT; other SX1302/SX1250 CoreCell boards work
 * with their own GPIO lines, SPI path and gain table.
 *
 * The concentrator is used as a single-channel RNode-style radio: RF chain 0 is centred on
 * the configured frequency (plus `if_offset_hz`) and only the "LoRa service" IF chain
 * (IF 8) is enabled, with the exact bandwidth and spreading factor of the setting. That is
 * the one SX1302 demodulator that takes 125, 250 and 500 kHz at a fixed SF, which is what a
 * stock RNode peer uses. The eight multi-SF demodulators (125 kHz only) are left off, so a
 * frame is never received twice. The board uses the private LoRa sync word (0x12), CRC on,
 * explicit header and standard IQ, like an RNode.
 *
 * Differences from the SX126x/SX127x drivers, all reported, none hidden:
 *   - carrier(): libloragw exposes no preamble/header detection, so it always reports a
 *     free channel and rnc_lora_if's CSMA becomes a random backoff without carrier sense.
 *   - rssi() and CAD are not supported (they return -1).
 *   - init() calls lgw_start(), which loads the concentrator firmware and calibrates the
 *     radios: about one to three seconds, blocking. A setting that only changes the coding
 *     rate or preamble does not restart it; one that changes the frequency, bandwidth,
 *     spreading factor or transmit power does. standby() therefore does not stop the
 *     concentrator (it ends a transmission and drops received frames); sleep() does.
 *   - Transmit power: below the calibrated range (12..27 dBm on the WM1302 US915 table)
 *     the SX1250 power index is extrapolated and NOT calibrated; init() prints a warning.
 *   - lgw_start() needs the board's I2C temperature sensor (enable I2C on the Pi).
 *
 * Linux only; this file is not part of the portable radio core.
 */
#include "rnc_modem.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rnc_sx1302_config {
  const char *spi_path;  /* default "/dev/spidev0.0" */
  const char *gpiochip;  /* default "/dev/gpiochip0"; NULL with no_reset */
  /* GPIO line offsets on gpiochip (not sysfs numbers). WM1302 Pi HAT: 17, 18, 5. */
  unsigned reset_line, power_line, sx1261_reset_line;
  int no_reset;          /* nonzero: the caller ran reset_lgw.sh itself */
  int32_t if_offset_hz;  /* IF of the service channel; RF chain 0 sits at freq - this */
  float rssi_offset;     /* board RSSI correction; WM1302 SX1250: -215.4 */
  int verbose;
} rnc_sx1302_config;

typedef struct rnc_sx1302 {
  rnc_modem modem; /* first, so an rnc_sx1302 * is an rnc_modem * */
  rnc_sx1302_config cfg;
  int gpio_fd;     /* the GPIO line request, held open so the lines stay driven */
  int started;
  rnc_lora_params running; /* the setting the concentrator was started with */
  /* received frames not yet handed out */
  struct {
    uint8_t data[256];
    uint16_t size;
    uint8_t crc_ok;
    int16_t rssi, snr_q;
  } rxq[16];
  unsigned rx_head, rx_count;
  uint64_t last_fetch_us;
  /* transmission in flight */
  uint64_t tx_start_us, tx_toa_us;
  int tx_active;
  uint32_t fetch_errors, tx_errors;
} rnc_sx1302;

/* Prepares the modem; touches no hardware. */
void rnc_sx1302_init(rnc_sx1302 *d, const rnc_sx1302_config *cfg);
/* Stops the concentrator, powers it down and releases the GPIO lines. */
void rnc_sx1302_close(rnc_sx1302 *d);
/* Drops received frames still waiting in the concentrator and in the local queue. */
void rnc_sx1302_flush(rnc_sx1302 *d);

#ifdef __cplusplus
}
#endif
#endif
