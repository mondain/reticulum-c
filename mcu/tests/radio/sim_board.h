#ifndef SIM_BOARD_H
#define SIM_BOARD_H
/*
 * A simulated board for the host tests and the host harness: a modelled radio chip (SX1262,
 * SX1261 or SX1276 model) on a shared medium, the real driver for it, and the LoRa
 * interface adapter on top. Test and harness code only; the drivers and the interface are
 * the code that runs on the boards.
 */
#include "../../radio/rnc_lora_if.h"
#include "../../radio/rnc_sx126x.h"
#include "../../radio/rnc_sx127x.h"
#include "lora_sim.h"
#include "sx126x_model.h"
#include "sx127x_model.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sim_board {
  int chip; /* 1262, 1261 or 1276 */
  sx126x_model m126;
  sx127x_model m127;
  rnc_sx126x d126;
  rnc_sx127x d127;
  rnc_lora_if li;
  uint32_t seed;
  int radio_id; /* index in the medium */
  int fixed_random; /* when set, random32 returns this value (to force coinciding backoffs) */
  int use_fixed;
} sim_board;

/* `chip` 1262/1261 (SX126x models) or 1276 (SX127x model with PA_BOOST). The board's
 * interface is prepared with the airtime budget `airtime_hundredths`. */
void sim_board_init(sim_board *b, sim_medium *medium, int chip, uint32_t seed,
                    uint32_t airtime_hundredths);
/* Starts the radio (driver init, receive); returns the driver's result. */
int sim_board_start(sim_board *b, const rnc_lora_params *params);
/* The model's violation count and first message, whichever chip it is. */
unsigned sim_board_violations(const sim_board *b);
const char *sim_board_violation_text(const sim_board *b);

#ifdef __cplusplus
}
#endif
#endif
