// The status screen of the T-Echo: a 1.54 inch e-paper (GxEPD2_154_D67) on SPIM3, with CS 30, DC 28,
// RESET 2, BUSY 3, SCK 31 and MOSI 29. The radio uses SPIM2; SPIM0 and SPIM1 are disabled in the
// Adafruit nRF52 core (they serve as I2C), and a driver on one of them hangs at its first transfer. See display_mode.h and
// docs/display-status-design.txt. E-paper refreshes take seconds: this runs in the display task
// only, and the refresh policy (rnc_refresh) keeps them rare.
#include "display_mode.h"

#if defined(RNC_DISPLAY_EPAPER)
#include <Arduino.h>
#include <GxEPD2_BW.h>
#include <SPI.h>

const rnc_status_profile display_profile = {16u, 12u}; // text size 2 (12 x 16) on 200 x 200
const unsigned display_min_interval_ms = 15000u, display_pin_interval_ms = 2000u,
               display_full_interval_ms = 300000u;

#define EPD_VEXT 12 // the rail that powers the radio and the screen
#define EPD_CS 30
#define EPD_DC 28
#define EPD_RESET 2
#define EPD_BUSY 3
#define EPD_SCK 31
#define EPD_MOSI 29
// The panel has no MISO line, but the Adafruit nRF52 core maps every pin through a table of 48
// entries, so it needs a valid number: the radio's MISO (23) is only ever read, by both.
#define EPD_MISO_UNUSED 23

static SPIClass g_spi(NRF_SPIM3, EPD_MISO_UNUSED, EPD_SCK, EPD_MOSI);
static GxEPD2_BW<GxEPD2_154_D67, GxEPD2_154_D67::HEIGHT> g_display(GxEPD2_154_D67(EPD_CS, EPD_DC, EPD_RESET, EPD_BUSY));

bool display_init(void) {
  pinMode(EPD_VEXT, OUTPUT);
  digitalWrite(EPD_VEXT, HIGH);
  delay(50);
  g_display.init(0, true, 10, false, g_spi, SPISettings(4000000, MSBFIRST, SPI_MODE0));
  g_display.setRotation(0);
  g_display.setTextColor(GxEPD_BLACK);
  g_display.setTextSize(2);
  g_display.setTextWrap(false);
  return true; // GxEPD2 reports no failure: a missing panel just never gets busy
}

void display_draw(const char lines[][RNC_STATUS_MAX_COLS + 1], unsigned rows, rnc_refresh_action action) {
  if (action == RNC_REFRESH_FULL)
    g_display.setFullWindow();
  else
    g_display.setPartialWindow(0, 0, g_display.width(), g_display.height());
  g_display.firstPage();
  do {
    g_display.fillScreen(GxEPD_WHITE);
    for (unsigned r = 0; r < rows && r < 12u; r++) {
      g_display.setCursor(0, (int16_t)(r * 16u));
      g_display.print(lines[r]);
    }
  } while (g_display.nextPage());
}
#endif
