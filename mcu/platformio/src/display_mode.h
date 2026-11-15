// The status screens of the T-Echo (e-paper) and the T-Beam Supreme (OLED); see
// docs/display-status-design.txt. Only the environments that set RNC_DISPLAY_OLED or
// RNC_DISPLAY_EPAPER build any of it; everywhere else these are empty stubs. RNC_DISPLAY_NULL
// builds the same code with a driver that draws nothing (a compile check on any board).
#pragma once
#include <stddef.h>
#include <stdint.h>

#include "rnc_mcu_app.h"
#include "rnc_mcu_net.h"
#include "rnc_radio.h"
#include "rnc_rnode.h"
#include "rnc_status.h"

#if defined(RNC_DISPLAY_OLED) || defined(RNC_DISPLAY_EPAPER) || defined(RNC_DISPLAY_NULL)
#define RNC_HAVE_DISPLAY 1

// What the status page is built from (read only, from the display task). The pointers must stay
// valid; the configuration is copied.
void rnc_status_sources(const rnc_lora_if *li, const rnc_rnode *rn, const rnc_mcu_cfg *cfg);
void rnc_status_set_phase(rnc_status_phase phase);
void rnc_status_set_link(rnc_status_link link);
// Fills `out` from the sources, the Bluetooth state and the phase. The PIN digits are copied
// only when the PIN rule says they may be shown, and are empty otherwise.
void rnc_status_fill(rnc_status *out, uint64_t now_ms);

// Starts the low-priority task that draws the status page; false when no screen is built in.
bool rnc_display_start(void);

// The driver of the board's screen (display_oled.cpp or display_epaper.cpp).
bool display_init(void);
void display_draw(const char lines[][RNC_STATUS_MAX_COLS + 1], unsigned rows, rnc_refresh_action action);
extern const rnc_status_profile display_profile;
extern const unsigned display_min_interval_ms, display_pin_interval_ms, display_full_interval_ms;
#else
#define RNC_HAVE_DISPLAY 0
static inline void rnc_status_sources(const rnc_lora_if *, const rnc_rnode *, const rnc_mcu_cfg *) {}
static inline void rnc_status_set_phase(rnc_status_phase) {}
static inline void rnc_status_set_link(rnc_status_link) {}
static inline bool rnc_display_start(void) { return false; }
#endif
