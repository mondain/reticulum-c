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

void rnc_airtime_set_limit(rnc_airtime *a, uint32_t percent_hundredths) {
  rnc_airtime fresh;
  rnc_airtime_init(&fresh, percent_hundredths);
  a->budget_ms = fresh.budget_ms;
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

void rnc_channel_init(rnc_channel *c) { memset(c, 0, sizeof(*c)); }

void rnc_channel_sample(rnc_channel *c, uint64_t now_ms, int sending, int carrier, int rssi_valid, int rssi_dbm) {
  const uint32_t second = (uint32_t)(now_ms / 1000u), minute = (uint32_t)(now_ms / 60000u);
  const unsigned s = second % RNC_CHANNEL_SECONDS, m = minute % RNC_CHANNEL_MINUTES;
  if (c->second[s] != second || !c->looks[s]) {
    c->second[s] = second;
    c->looks[s] = c->sending[s] = c->taken[s] = 0;
  }
  if (c->minute[m] != minute || !c->minute_looks[m]) {
    c->minute[m] = minute;
    c->minute_looks[m] = c->minute_taken[m] = 0;
  }
  ++c->looks[s];
  ++c->minute_looks[m];
  if (sending)
    ++c->sending[s];
  if (sending || carrier) {
    ++c->taken[s];
    ++c->minute_taken[m];
  }
  if (!rssi_valid || sending)
    return;
  c->rssi_dbm = (int16_t)rssi_dbm;
  if (carrier) { /* a signal being received says nothing about the noise */
    c->interfered = 0;
    return;
  }
  if (!c->have_floor) {
    c->floor_q8 = rssi_dbm * 256;
    c->have_floor = 1;
  }
  c->interfered = rssi_dbm * 256 >= c->floor_q8 + RNC_CHANNEL_INTERFERENCE_DB * 256;
  if (c->interfered) {
    c->interference_dbm = (int16_t)rssi_dbm;
    c->floor_q8 += (rssi_dbm * 256 - c->floor_q8) / 256; /* slowly: a louder place is a new floor in time */
  } else {
    c->floor_q8 += (rssi_dbm * 256 - c->floor_q8) / 16;
  }
}

static uint16_t hundredths_of(uint32_t part, uint32_t whole) {
  return whole ? (uint16_t)((part * 10000u + whole / 2u) / whole) : 0u;
}

void rnc_channel_read(const rnc_channel *c, uint64_t now_ms, rnc_channel_report *out) {
  const uint32_t second = (uint32_t)(now_ms / 1000u), minute = (uint32_t)(now_ms / 60000u);
  uint32_t looks = 0, sending = 0, taken = 0, long_looks = 0, long_taken = 0;
  unsigned i;
  memset(out, 0, sizeof(*out));
  for (i = 0; i < RNC_CHANNEL_SECONDS; ++i)
    if (c->looks[i] && second - c->second[i] < RNC_CHANNEL_SECONDS) {
      looks += c->looks[i];
      sending += c->sending[i];
      taken += c->taken[i];
    }
  for (i = 0; i < RNC_CHANNEL_MINUTES; ++i)
    if (c->minute_looks[i] && minute - c->minute[i] < RNC_CHANNEL_MINUTES) {
      long_looks += c->minute_looks[i];
      long_taken += c->minute_taken[i];
    }
  out->airtime_short = hundredths_of(sending, looks);
  out->load_short = hundredths_of(taken, looks);
  /* the hour's load is of the whole hour, so that it compares with the hour's airtime: time not yet watched
   * counts as quiet */
  {
    const uint32_t hour_looks = RNC_CHANNEL_MINUTES * (60000u / RNC_CHANNEL_LOOK_MS);
    out->load_long = hundredths_of(long_taken, long_looks > hour_looks ? long_looks : hour_looks);
  }
  out->rssi_dbm = c->rssi_dbm;
  out->have_floor = c->have_floor;
  out->noise_floor_dbm = (int16_t)((c->floor_q8 - 128) / 256);
  out->has_interference = c->interfered;
  out->interference_dbm = c->interference_dbm;
}
