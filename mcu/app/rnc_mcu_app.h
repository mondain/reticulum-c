#ifndef RNC_MCU_APP_H
#define RNC_MCU_APP_H
/*
 * Portable example application for microcontrollers: a Reticulum node with one
 * HDLC-framed serial interface (the framing of the Reticulum SerialInterface),
 * one destination `reticulum_c.mcu.example`, and the request paths
 *
 *   /echo   returns the request value unchanged
 *   /info   returns a MessagePack map {name, version, board, uptime[, heap][, unix]}
 *
 * It must be built with the mcu capacity profile (RNC_PROFILE_MCU defined for the
 * library AND for this file) and the portable crypto backend, and it contains no
 * platform headers: a port supplies an rnc_mcu_platform (rnc_mcu_platform.h) and
 * calls rnc_mcu_app_step from its loop or task. It needs a task stack of at least
 * 12 KB and about 90 KB of heap (see tests/footprint.c for the figures).
 *
 * UNIX TIME POLICY. Devices usually have no clock, but announces carry a unix
 * timestamp: a peer drops one whose time is more than 300 seconds in the future,
 * and the reference stack ignores an announce whose time is not newer than the one
 * behind its stored path. So the application keeps a clock that never goes
 * backwards and is never ahead of real time by more than a few minutes:
 *   1. If the platform's unix_seconds hook returns a non-zero value (RTC, SNTP,
 *      GPS) that value is used (never moving the clock backwards).
 *   2. Otherwise the clock is build-time epoch plus uptime, raised to a persisted
 *      high-water mark. The mark is stored under RNC_MCU_KEY_TIME every
 *      RNC_MCU_TIME_PERSIST_S seconds, and on boot the clock starts at the stored
 *      mark plus RNC_MCU_TIME_PERSIST_S + 1, which is at least as late as any
 *      announce sent before the reboot, so paths on the other side keep updating.
 *      The build epoch is RNC_MCU_BUILD_EPOCH (set by the build system, else a
 *      constant) and is always in the past, so the clock is only ever late.
 *   3. rnc_mcu_app_set_unix lets a port move the clock forward when a host or
 *      user tells it the real time; going backwards is refused.
 */
#include "rnc_mcu_platform.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RNC_MCU_APP_NAME "reticulum_c.mcu.example"
#ifndef RNC_MCU_FIRMWARE_NAME
#define RNC_MCU_FIRMWARE_NAME "reticulum-c-mcu"
#endif
#ifndef RNC_MCU_VERSION
#define RNC_MCU_VERSION "0.2.0"
#endif
#ifndef RNC_MCU_BUILD_EPOCH
#define RNC_MCU_BUILD_EPOCH 1767225600u /* 2026-01-01: used when the build supplies none */
#endif
#ifndef RNC_MCU_TIME_PERSIST_S
#define RNC_MCU_TIME_PERSIST_S 120u
#endif
#ifndef RNC_MCU_LINK_UP_DELAY_MS
#define RNC_MCU_LINK_UP_DELAY_MS 500u /* announce this long after the transport comes up */
#endif
#ifndef RNC_MCU_ANNOUNCE_MS
#define RNC_MCU_ANNOUNCE_MS 600000u /* 10 minutes */
#endif

typedef struct rnc_mcu_config {
  uint32_t announce_interval_ms; /* 0 = RNC_MCU_ANNOUNCE_MS */
  uint32_t bitrate;              /* bits per second of the transport, 0 = 115200 */
} rnc_mcu_config;

typedef struct rnc_mcu_app rnc_mcu_app;

/* Creates the node, loads or creates the persistent identity (platform persist/
 * load), registers the destination and the request paths. NULL on failure
 * (missing hooks, out of memory). `config` may be NULL. The platform table is
 * copied. */
rnc_mcu_app *rnc_mcu_app_new(const rnc_mcu_platform *platform,
                             const rnc_mcu_config *config);
void rnc_mcu_app_free(rnc_mcu_app *app);

/* One pass of the loop: reads available bytes, feeds the node, runs timers and the
 * responder, writes outgoing frames, announces when due (at the first step, again
 * a few seconds later, then every interval). Never blocks beyond the platform
 * hooks. Call it at least every 20 ms or so (more often at higher baud rates);
 * `now_ms` is the monotonic time from the platform. Returns the number of
 * milliseconds after which the next call is wanted at the latest. */
unsigned rnc_mcu_app_step(rnc_mcu_app *app, uint64_t now_ms);

/* Counters since start, for tests and diagnostics. */
typedef struct rnc_mcu_stats {
  uint32_t link_ups;     /* transitions of the transport to up (the first one included) */
  uint32_t link_downs;   /* transitions to down */
  uint32_t announces;    /* announces handed to the transport */
  uint32_t rx_packets;   /* frames that decoded as Reticulum packets */
  uint32_t rx_bad;       /* HDLC frames that did not decode as a packet */
  uint32_t tx_dropped;   /* outgoing packets discarded because the link was down */
} rnc_mcu_stats;
void rnc_mcu_app_get_stats(const rnc_mcu_app *app, rnc_mcu_stats *stats);

/* The 16 byte destination hash; 0 on success. */
int rnc_mcu_app_destination(const rnc_mcu_app *app, uint8_t hash[16]);
/* Current unix seconds according to the policy above. */
uint64_t rnc_mcu_app_unix(rnc_mcu_app *app, uint64_t now_ms);
/* Moves the clock forward to `unix_seconds`; returns 0 if applied, -1 if it was
 * not later than the current time. */
int rnc_mcu_app_set_unix(rnc_mcu_app *app, uint64_t now_ms, uint64_t unix_seconds);

#ifdef __cplusplus
}
#endif
#endif
