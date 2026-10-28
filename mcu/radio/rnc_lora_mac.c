/* Airtime budget and CSMA; see rnc_lora_mac.h. */
#include "rnc_lora_mac.h"
#include <string.h>

/* ---- airtime ------------------------------------------------------------------ */
void rnc_airtime_init(rnc_airtime *a, uint32_t percent_hundredths) {
  uint64_t ms;
  memset(a, 0, sizeof(*a));
  if (percent_hundredths == 0u)
    percent_hundredths = 1u;
  if (percent_hundredths > 10000u)
    percent_hundredths = 10000u;
  /* window ms * percent / 100 / 100, rounded down: never more than the budget */
  ms = (uint64_t)RNC_AIRTIME_WINDOW_MS * percent_hundredths / 10000u;
  a->budget_ms = (uint32_t)ms;
}

uint32_t rnc_airtime_used(const rnc_airtime *a, uint64_t now_ms) {
  uint64_t minute = now_ms / RNC_AIRTIME_BIN_MS, sum = 0;
  unsigned i;
  for (i = 0; i < RNC_AIRTIME_BINS; i++) {
    uint64_t bin_minute = a->bin_minute[i];
    if (a->bin_ms[i] && bin_minute + RNC_AIRTIME_BINS > minute && bin_minute <= minute)
      sum += a->bin_ms[i];
  }
  return sum > 0xFFFFFFFFu ? 0xFFFFFFFFu : (uint32_t)sum;
}

int rnc_airtime_allows(const rnc_airtime *a, uint64_t now_ms, uint32_t toa_ms) {
  uint64_t after;
  if (toa_ms > a->budget_ms)
    return 2;
  after = (uint64_t)rnc_airtime_used(a, now_ms) + toa_ms;
  return after <= a->budget_ms;
}

void rnc_airtime_book(rnc_airtime *a, uint64_t now_ms, uint32_t toa_ms) {
  uint64_t minute = now_ms / RNC_AIRTIME_BIN_MS;
  unsigned i = (unsigned)(minute % RNC_AIRTIME_BINS);
  if (a->bin_minute[i] != (uint32_t)minute || !a->bin_ms[i]) {
    a->bin_ms[i] = 0;
    a->bin_minute[i] = (uint32_t)minute;
  }
  a->bin_ms[i] += toa_ms;
  a->total_ms += toa_ms;
}

/* ---- CSMA --------------------------------------------------------------------- */
#define CSMA_SLOT_MAX_MS 100u
#define CSMA_SLOT_MIN_MS 24u
#define CSMA_SLOT_MIN_FAST_MS 6u
#define CSMA_SLOT_SYMBOLS 12u
#define CSMA_CW_BASE 15u
#define CSMA_UNSET UINT64_MAX

void rnc_csma_init(rnc_csma *c, uint32_t symbol_us, int fast_rate) {
  uint32_t slot = (uint32_t)(((uint64_t)symbol_us * CSMA_SLOT_SYMBOLS) / 1000u);
  uint32_t min_slot = fast_rate ? CSMA_SLOT_MIN_FAST_MS : CSMA_SLOT_MIN_MS;
  memset(c, 0, sizeof(*c));
  if (slot > CSMA_SLOT_MAX_MS)
    slot = CSMA_SLOT_MAX_MS;
  if (slot < CSMA_SLOT_MIN_MS)
    slot = min_slot;
  c->slot_ms = slot;
  c->difs_ms = 2u * slot;
  c->since_ms = CSMA_UNSET;
  c->cw_target_ms = CSMA_UNSET;
}

void rnc_csma_begin(rnc_csma *c) {
  c->state = 1;
  c->attempts = 0;
  c->since_ms = CSMA_UNSET;
  c->cw_target_ms = CSMA_UNSET;
  c->cw_done_ms = 0;
  c->last_busy = 0;
}

int rnc_csma_step(rnc_csma *c, uint64_t now_ms, int busy, uint32_t random) {
  if (c->state == 0)
    return 1;
  if (busy) {
    if (!c->last_busy) {
      c->deferrals++;
      if (c->attempts < 3u)
        c->attempts++;
    }
    c->last_busy = 1;
    c->state = 1; /* the DIFS starts over when the channel frees up */
    c->since_ms = CSMA_UNSET;
    return 0;
  }
  c->last_busy = 0;
  if (c->state == 1) {
    if (c->since_ms == CSMA_UNSET)
      c->since_ms = now_ms;
    if (now_ms - c->since_ms < c->difs_ms)
      return 0;
    c->state = 2;
    c->last_ms = now_ms;
    if (c->cw_target_ms == CSMA_UNSET) {
      /* window: 0..14 slots, doubling after each busy interruption */
      uint32_t window = CSMA_CW_BASE << (c->attempts > 3u ? 3u : c->attempts);
      c->cw_target_ms = (uint64_t)(random % window) * c->slot_ms;
      c->cw_done_ms = 0;
    }
  } else {
    c->cw_done_ms += now_ms - c->last_ms;
    c->last_ms = now_ms;
  }
  if (c->cw_done_ms >= c->cw_target_ms) {
    c->state = 0;
    return 1;
  }
  return 0;
}
