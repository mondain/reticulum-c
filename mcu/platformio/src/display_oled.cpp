// The status screen of the T-Beam Supreme: a 128 x 64 SH1106 OLED on I2C (address 0x3C, SDA 17,
// SCL 18). The AXP2101 power chip is on the other bus (Wire1 on 42/41, radio_hal.cpp), so the
// two do not share a bus. See display_mode.h and docs/display-status-design.md.
#include "display_mode.h"

#if defined(RNC_DISPLAY_OLED)
#include <Adafruit_GFX.h>
#include <Adafruit_SH110X.h>
#include <Wire.h>

const rnc_status_profile display_profile = {21u, 8u}; // 6 x 8 font on 128 x 64
const unsigned display_min_interval_ms = 1000u, display_pin_interval_ms = 1000u, display_full_interval_ms = 0u;

static Adafruit_SH1106G g_display(128, 64, &Wire, -1);

bool display_init(void) {
  Wire.begin(17, 18);
  if (!g_display.begin(0x3C, true))
    return false;
  g_display.clearDisplay();
  g_display.setTextSize(1);
  g_display.setTextColor(SH110X_WHITE);
  g_display.setTextWrap(false);
  g_display.display();
  return true;
}

void display_draw(const char lines[][RNC_STATUS_MAX_COLS + 1], unsigned rows, rnc_refresh_action) {
  g_display.clearDisplay();
  for (unsigned r = 0; r < rows && r < 8u; r++) {
    g_display.setCursor(0, (int16_t)(r * 8u));
    g_display.print(lines[r]);
  }
  g_display.display();
}
#endif
