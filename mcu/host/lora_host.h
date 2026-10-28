#ifndef LORA_HOST_H
#define LORA_HOST_H
/*
 * Simulated LoRa segment for the host harness (reticulum-c-mcu-host --lora ...): the board
 * the harness runs gets a modelled radio chip on a simulated shared channel, started through
 * the same rnc_radio_setup() gate as the firmware, and N more simulated boards ("peers",
 * each a full instance of the portable application in leaf mode) sit on the same channel.
 * Used by the gateway test: a Reticulum node reaches the peers through the harness.
 *
 * Test and harness code only. The channel and the chips are models (mcu/tests/radio): they
 * check the logic, not real radio behaviour.
 */
#include "rnc_lora_cfg.h"
#include "rnc_lora_if.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lora_host lora_host;

typedef struct lora_host_options {
  rnc_lora_cfg cfg;       /* the radio settings (the harness refuses to start the radio unless complete) */
  int chip;               /* 1262 (default) or 1276 for the harness board; peers use the other family */
  unsigned peers;         /* simulated boards behind the channel (default 1) */
  unsigned loss_permille; /* random frame loss on every link */
  int verbose;
} lora_host_options;

/* Creates the segment. Returns NULL if the radio did not start (the reason is printed to
 * stderr); *status gets the RNC_RADIO_* code. */
lora_host *lora_host_new(const lora_host_options *options, int *status);
void lora_host_free(lora_host *h);
/* The harness board's interface and mode, to hand to rnc_mcu_config. */
rnc_lora_if *lora_host_interface(lora_host *h);
/* Advances the channel to the wall clock and steps the peers. Call every loop pass, before
 * stepping the harness application. */
void lora_host_step(lora_host *h, uint64_t real_now_us);

#ifdef __cplusplus
}
#endif
#endif
