// The task that draws the status page (display_mode.h). It runs below the radio and Reticulum
// tasks, only reads shared state, and ends silently if the screen does not start, so a screen
// problem can never cost the board its radio, USB or Bluetooth.
#include "display_mode.h"

#if RNC_HAVE_DISPLAY
#include <Arduino.h>

#if defined(ARDUINO_ARCH_ESP32)
#define DISPLAY_STACK(bytes) (bytes) // FreeRTOS in ESP-IDF counts bytes
#else
#define DISPLAY_STACK(bytes) ((bytes) / 4) // vanilla FreeRTOS counts words
#endif

static void display_task(void *) {
  static rnc_refresh refresh;
  static rnc_display_state state;
  static rnc_status status;
  static char lines[RNC_STATUS_MAX_ROWS][RNC_STATUS_MAX_COLS + 1];
  unsigned rows = 0;
  uint32_t last = 0;
  uint64_t high = 0;
  bool ok = display_init();
  rnc_refresh_init(&refresh, display_min_interval_ms, display_pin_interval_ms, display_full_interval_ms);
  if (!ok) { // the screen did not start: the task has nothing to do
    (void)rnc_display_step(&refresh, &state, &status, display_profile, 0, 0, lines, &rows);
    vTaskDelete(NULL);
  }
  for (;;) {
    uint32_t now = millis();
    if (now < last)
      high += (uint64_t)1 << 32; // 49 days
    last = now;
    uint64_t now_ms = high + now;
    rnc_status_fill(&status, now_ms);
    rnc_refresh_action action = rnc_display_step(&refresh, &state, &status, display_profile, 1, now_ms, lines, &rows);
    if (action != RNC_REFRESH_NONE)
      display_draw(lines, rows, action);
    vTaskDelay(pdMS_TO_TICKS(200));
  }
}

bool rnc_display_start(void) {
  xTaskCreate(display_task, "display", DISPLAY_STACK(6144), NULL, 1, NULL);
  return true;
}
#endif
