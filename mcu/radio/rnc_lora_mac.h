#ifndef RNC_LORA_MAC_H
#define RNC_LORA_MAC_H
/*
 * Channel access for the LoRa interface: an airtime budget and a CSMA style
 * listen-before-talk with random backoff. Pure state machines driven by the caller's
 * clock and randomness (no hardware access), so they are unit tested directly.
 *
 * AIRTIME BUDGET. A sliding one hour window kept in one minute bins. A packet
 * may be sent only if its whole time on air fits under `percent` of an hour on top of
 * what was sent in the window; the check is made before every transmission, for the
 * packet as a whole (both frames of a split packet are accounted together, so a packet
 * is never half sent). The time is booked in the bin in which the transmission starts
 * and stays booked for at least an hour (never less), so the budget errs on the
 * side of sending less.
 *
 * CSMA. Before transmitting, the channel must be free for a DIFS of two slots; then a
 * random number of further free slots is waited (the contention window), and the
 * count is frozen while the channel is busy. After a busy period the window grows
 * (binary exponential, four steps). The slot is twelve symbols long, between 24 and
 * 100 ms (6 ms minimum above 30 kbit/s), the numbers of the stock RNode firmware.
 */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RNC_AIRTIME_BINS 61u /* 60 minutes plus the one being filled */
#define RNC_AIRTIME_BIN_MS 60000u
#define RNC_AIRTIME_WINDOW_MS 3600000u

typedef struct rnc_airtime {
  uint32_t bin_ms[RNC_AIRTIME_BINS];   /* milliseconds sent in each bin */
  uint32_t bin_minute[RNC_AIRTIME_BINS];   /* which minute (ms / 60000) the bin holds */
  uint32_t budget_ms;                  /* allowed per window */
  uint32_t denied;                     /* transmissions refused by the budget */
  uint64_t total_ms;                   /* ever sent */
} rnc_airtime;

/* `percent_hundredths`: 100 = 1.00 %. Values of 0 are treated as the minimum 1 (0.01 %),
 * never as "unlimited". */
void rnc_airtime_init(rnc_airtime *a, uint32_t percent_hundredths);
/* Changes the budget (same rules as _init) and keeps what was already booked. */
void rnc_airtime_set_limit(rnc_airtime *a, uint32_t percent_hundredths);
/* Airtime booked in the window ending at now_ms, in milliseconds. */
uint32_t rnc_airtime_used(const rnc_airtime *a, uint64_t now_ms);
/* 1 when `toa_ms` more fits in the budget now. A packet longer than the whole budget
 * can never be sent and is reported as 2. */
int rnc_airtime_allows(const rnc_airtime *a, uint64_t now_ms, uint32_t toa_ms);
/* Books a transmission. */
void rnc_airtime_book(rnc_airtime *a, uint64_t now_ms, uint32_t toa_ms);

/* ---- what the channel has been like, for the reports a host asks of an RNode -------------------------------- */
#define RNC_CHANNEL_SECONDS 15u
#define RNC_CHANNEL_MINUTES 60u
#define RNC_CHANNEL_LOOK_MS 100u        /* how often the owner looks */
#define RNC_CHANNEL_INTERFERENCE_DB 11  /* this far over the noise floor with no LoRa signal is interference */

typedef struct rnc_channel {
  uint32_t second[RNC_CHANNEL_SECONDS];
  uint16_t looks[RNC_CHANNEL_SECONDS], sending[RNC_CHANNEL_SECONDS], taken[RNC_CHANNEL_SECONDS];
  uint32_t minute[RNC_CHANNEL_MINUTES];
  uint16_t minute_looks[RNC_CHANNEL_MINUTES], minute_taken[RNC_CHANNEL_MINUTES];
  int32_t floor_q8; /* the noise floor in 1/256 dB, a running average of quiet looks */
  int16_t rssi_dbm, interference_dbm;
  uint8_t have_floor, interfered;
} rnc_channel;

typedef struct rnc_channel_report {
  /* hundredths of a percent */
  uint16_t airtime_short, load_short, load_long;
  int16_t rssi_dbm, noise_floor_dbm, interference_dbm;
  uint8_t have_floor, has_interference;
} rnc_channel_report;

void rnc_channel_init(rnc_channel *c);
/* One look at the channel: whether we are sending, whether a LoRa signal is being received, and the signal level
 * when it could be read (`rssi_valid`). */
void rnc_channel_sample(rnc_channel *c, uint64_t now_ms, int sending, int carrier, int rssi_valid, int rssi_dbm);
void rnc_channel_read(const rnc_channel *c, uint64_t now_ms, rnc_channel_report *out);

typedef struct rnc_csma {
  uint32_t slot_ms, difs_ms;
  uint8_t state;              /* 0 idle, 1 waiting for DIFS, 2 counting slots */
  uint8_t attempts;           /* busy interruptions of this packet */
  uint64_t since_ms;          /* start of the current free period */
  uint64_t cw_target_ms;      /* how long the slot countdown needs in total */
  uint64_t cw_done_ms;        /* counted so far */
  uint64_t last_ms;
  int last_busy;
  uint32_t deferrals;         /* times a busy channel interrupted the wait */
} rnc_csma;

void rnc_csma_init(rnc_csma *c, uint32_t symbol_us, int fast_rate);
/* Starts waiting to transmit a new packet. */
void rnc_csma_begin(rnc_csma *c);
/* Advances the wait. `busy` is the channel state now, `random` any 32 bit random value
 * (used when the countdown starts). Returns 1 when the packet may be transmitted now. */
int rnc_csma_step(rnc_csma *c, uint64_t now_ms, int busy, uint32_t random);

#ifdef __cplusplus
}
#endif
#endif
