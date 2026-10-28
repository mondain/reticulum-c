/* Simulated board; see sim_board.h. */
#include "sim_board.h"
#include <string.h>

static uint32_t board_random(void *context) {
  sim_board *b = context;
  if (b->use_fixed)
    return (uint32_t)b->fixed_random;
  b->seed = b->seed * 1664525u + 1013904223u;
  return b->seed ^ (b->seed >> 13);
}

void sim_board_init(sim_board *b, sim_medium *medium, int chip, uint32_t seed,
                    uint32_t airtime_hundredths) {
  memset(b, 0, sizeof(*b));
  b->chip = chip;
  b->seed = seed;
  if (chip == 1276) {
    rnc_sx127x_board bd;
    bd.pa_boost = 1;
    sx127x_model_init(&b->m127, medium, 1);
    rnc_sx127x_attach(&b->d127, &b->m127.hal, &bd);
    b->radio_id = b->m127.id;
    rnc_lora_if_init(&b->li, &b->d127.base, &b->m127.hal, board_random, b, airtime_hundredths);
  } else {
    rnc_sx126x_board bd;
    memset(&bd, 0, sizeof(bd));
    bd.chip = (uint16_t)chip;
    bd.tcxo_code = RNC_SX126X_TCXO_1V8;
    bd.dio2_rf_switch = 1;
    bd.ocp = 0x28;
    sx126x_model_init(&b->m126, medium, (unsigned)chip, 1, 1);
    rnc_sx126x_attach(&b->d126, &b->m126.hal, &bd);
    b->radio_id = b->m126.id;
    rnc_lora_if_init(&b->li, &b->d126.base, &b->m126.hal, board_random, b, airtime_hundredths);
  }
}

int sim_board_start(sim_board *b, const rnc_lora_params *params) {
  return rnc_lora_if_start(&b->li, params);
}

unsigned sim_board_violations(const sim_board *b) {
  return b->chip == 1276 ? b->m127.violations : b->m126.violations;
}
const char *sim_board_violation_text(const sim_board *b) {
  return b->chip == 1276 ? b->m127.first_violation : b->m126.first_violation;
}
