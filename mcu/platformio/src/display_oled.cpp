// The status screen of the 128 x 64 OLED boards, both at I2C address 0x3C on SDA 17, SCL 18:
//   T-Beam Supreme (RNC_DISPLAY_OLED): SH1106. The AXP2101 power chip is on the other bus (Wire1
//     on 42/41, radio_hal.cpp), so the two do not share a bus.
//   Heltec WiFi LoRa 32 V3 (RNC_DISPLAY_SSD1306): SSD1306, powered from Vext (GPIO36, on when
//     low) and reset on GPIO21.
// See display_mode.h and docs/display-status-design.md.
#include "display_mode.h"

#if defined(RNC_DISPLAY_OLED) || defined(RNC_DISPLAY_SSD1306)
#include <Adafruit_GFX.h>
#include <Wire.h>
#if defined(RNC_DISPLAY_SSD1306)
#include <Adafruit_SSD1306.h>
#define OLED_WHITE SSD1306_WHITE
#else
#include <Adafruit_SH110X.h>
#define OLED_WHITE SH110X_WHITE
#endif

const rnc_status_profile display_profile = {21u, 8u}; // 6 x 8 font on 128 x 64
const unsigned display_min_interval_ms = 1000u, display_pin_interval_ms = 1000u, display_full_interval_ms = 0u;

#if defined(RNC_DISPLAY_SSD1306)
#define OLED_VEXT 36
#define OLED_RESET_PIN 21

static Adafruit_SSD1306 g_display(128, 64, &Wire, OLED_RESET_PIN);

static bool panel_begin(void) {
  pinMode(OLED_VEXT, OUTPUT);
  digitalWrite(OLED_VEXT, LOW); // powers the panel
  delay(50);
  Wire.begin(17, 18);
  // resets the panel; false only when the frame buffer cannot be allocated. periphBegin is
  // false so the library does not set up Wire again on the board's default pins.
  if (!g_display.begin(SSD1306_SWITCHCAPVCC, 0x3C, true, false))
    return false;
  Wire.beginTransmission(0x3C); // begin() does not notice a missing panel
  return Wire.endTransmission() == 0;
}
#else
static Adafruit_SH1106G g_display(128, 64, &Wire, -1);

static bool panel_begin(void) {
  Wire.begin(17, 18);
  return g_display.begin(0x3C, true);
}
#endif

bool display_init(void) {
  if (!panel_begin())
    return false;
  g_display.clearDisplay();
  g_display.setTextSize(1);
  g_display.setTextColor(OLED_WHITE);
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
