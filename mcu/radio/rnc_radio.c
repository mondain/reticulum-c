/* Radio start-up glue; see rnc_radio.h. */
#include "rnc_radio.h"
#include <string.h>

const char *rnc_radio_status_text(int status) {
  switch (status) {
  case RNC_RADIO_OK: return "radio running";
  case RNC_RADIO_OFF: return "radio off (lora.mode is off)";
  case RNC_RADIO_NOT_CONFIGURED:
    return "radio DISABLED: lora.freq, lora.bw, lora.sf, lora.cr and lora.txp must all be set";
  case RNC_RADIO_BOARD_UNSUPPORTED: return "radio disabled: this board is not supported";
  case RNC_RADIO_BAD_SETTINGS: return "radio disabled: settings not valid for this board";
  case RNC_RADIO_CHIP_FAILED: return "radio chip did not start (will retry)";
  default: return "radio state unknown";
  }
}

int rnc_radio_setup(rnc_radio *r, const rnc_board *board, const rnc_radio_hal *hal,
                    const rnc_lora_cfg *cfg, uint32_t (*random32)(void *context), void *context) {
  rnc_lora_params p;
  memset(r, 0, sizeof(*r));
  r->board = board;
  r->cfg = *cfg;
  if (cfg->mode == RNC_LORA_MODE_OFF)
    return r->status = RNC_RADIO_OFF;
  if (!rnc_lora_cfg_ready(cfg))
    return r->status = RNC_RADIO_NOT_CONFIGURED;
  if (!board || !board->supported || !hal)
    return r->status = RNC_RADIO_BOARD_UNSUPPORTED;
  rnc_lora_cfg_params(cfg, &p);
  if (rnc_lora_params_check(&p, board->chip == RNC_BOARD_SX1276 ? 7u : 5u) != 0 ||
      p.txp_dbm > board->max_txp_dbm)
    return r->status = RNC_RADIO_BAD_SETTINGS;
  if (board->chip == RNC_BOARD_SX1276) {
    rnc_sx127x_board b;
    b.pa_boost = board->pa_boost;
    rnc_sx127x_attach(&r->d127, hal, &b);
    rnc_lora_if_init(&r->li, &r->d127.base, hal, random32, context, cfg->airtime);
  } else {
    rnc_sx126x_attach(&r->d126, hal, &board->sx126x);
    rnc_lora_if_init(&r->li, &r->d126.base, hal, random32, context, cfg->airtime);
  }
  /* the driver also checks the power and band against the chip; a refusal there leaves the
   * interface down and is reported the same way */
  {
    int rc = rnc_lora_if_start(&r->li, &p);
    if (rc == -2 || rc == -3) { /* settings the chip cannot do: no retry will help */
      r->li.retry_us = 0;
      return r->status = RNC_RADIO_BAD_SETTINGS;
    }
    if (rc != 0)
      return r->status = RNC_RADIO_CHIP_FAILED;
  }
  return r->status = RNC_RADIO_OK;
}
