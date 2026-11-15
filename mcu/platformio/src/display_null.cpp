// A display driver that draws nothing: builds the status task and filler on any board
// (-DRNC_DISPLAY_NULL), to check that they compile and that a board runs with them.
#include "display_mode.h"

#if defined(RNC_DISPLAY_NULL)
const rnc_status_profile display_profile = {21u, 8u};
const unsigned display_min_interval_ms = 1000u, display_pin_interval_ms = 1000u, display_full_interval_ms = 0u;
bool display_init(void) { return true; }
void display_draw(const char[][RNC_STATUS_MAX_COLS + 1], unsigned, rnc_refresh_action) {}
#endif
