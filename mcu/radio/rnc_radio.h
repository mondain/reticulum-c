#ifndef RNC_RADIO_H
#define RNC_RADIO_H
/*
 * Glue between the settings, the board table and the radio drivers: builds the right driver
 * for a board, checks the settings against the board and starts the LoRa interface. This is
 * the one place that decides whether the radio may run, so the regulatory rule lives here:
 *
 *   the radio is not touched (no SPI traffic, no transmission, no reception) unless the
 *   mode is leaf or gateway and frequency, bandwidth, spreading factor, coding rate and
 *   transmit power have all been set explicitly (rnc_lora_cfg.h).
 *
 * Portable C; the port supplies the HAL (SPI, GPIO, timing).
 */
#include "rnc_boards.h"
#include "rnc_lora_cfg.h"
#include "rnc_lora_if.h"
#include "rnc_sx126x.h"
#include "rnc_sx127x.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rnc_radio {
  rnc_sx126x d126;
  rnc_sx127x d127;
  rnc_lora_if li;
  const rnc_board *board;
  rnc_lora_cfg cfg;
  int status; /* RNC_RADIO_* */
} rnc_radio;

#define RNC_RADIO_OK 0
#define RNC_RADIO_OFF 1            /* mode off: nothing to do */
#define RNC_RADIO_NOT_CONFIGURED 2 /* mode set, but a transmit setting is missing: radio disabled */
#define RNC_RADIO_BOARD_UNSUPPORTED 3
#define RNC_RADIO_BAD_SETTINGS 4   /* rejected for this board (power, spreading factor, band) */
#define RNC_RADIO_CHIP_FAILED 5    /* the chip did not start (retried every ten seconds) */

/* Prepares `r` and starts the radio if the settings allow it. Returns RNC_RADIO_OK when the
 * interface is up, RNC_RADIO_CHIP_FAILED when it is prepared but the chip did not answer
 * (the interface retries), or another RNC_RADIO_* code when the radio was not started and no
 * hardware access was made. `random32` supplies random bits for the backoff. */
int rnc_radio_setup(rnc_radio *r, const rnc_board *board, const rnc_radio_hal *hal,
                    const rnc_lora_cfg *cfg, uint32_t (*random32)(void *context), void *context);
/* One line saying why the radio is in the state it is in. */
const char *rnc_radio_status_text(int status);

#ifdef __cplusplus
}
#endif
#endif
