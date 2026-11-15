/* Tests of the status record, its text layout and the PIN rule (mcu/app/rnc_status.h): what
 * the screens of the T-Echo and the T-Beam Supreme show. Host only; no screen involved. */
#include "rnc_status.h"
#include <stdio.h>
#include <string.h>

static int failures;
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #x);    \
      failures++;                                                              \
    }                                                                          \
  } while (0)
#define CHECK_LINE(lines, n, text)                                             \
  do {                                                                         \
    if (strcmp((lines)[n], (text)) != 0) {                                     \
      fprintf(stderr, "%s:%d: line %d is \"%s\", expected \"%s\"\n", __FILE__, __LINE__, n, (lines)[n], text); \
      failures++;                                                              \
    }                                                                          \
  } while (0)

typedef char screen[RNC_STATUS_MAX_ROWS][RNC_STATUS_MAX_COLS + 1];

static rnc_status sample(void) {
  rnc_status s;
  memset(&s, 0, sizeof(s));
  s.phase = RNC_PHASE_RUNNING;
  strcpy(s.mode, "RNode");
  s.radio_on = 1;
  s.radio_set = 1;
  s.freq_hz = 915000000u;
  s.bw_hz = 125000u;
  s.sf = 8;
  s.cr = 5;
  s.txp_dbm = 0;
  s.has_signal = 1;
  s.rssi_dbm = -31;
  s.snr_quarter_db = 51;
  s.rx_packets = 12;
  s.tx_packets = 3;
  s.airtime_permille = 4;
  s.link = RNC_LINK_USB;
  s.ble = RNC_BLE_OFF;
  strcpy(s.version, "0.2.1");
  return s;
}

static void test_pin_rule(void) {
  CHECK(rnc_status_pin_visible(RNC_BLE_ADVERTISING, 1));
  CHECK(rnc_status_pin_visible(RNC_BLE_CONNECTED, 1));
  CHECK(!rnc_status_pin_visible(RNC_BLE_OFF, 1));
  CHECK(!rnc_status_pin_visible(RNC_BLE_SECURE, 1));
  CHECK(!rnc_status_pin_visible(RNC_BLE_ADVERTISING, 0));
  CHECK(!rnc_status_pin_visible(RNC_BLE_CONNECTED, 0));
  CHECK(!rnc_status_pin_visible(RNC_BLE_OFF, 0));
  CHECK(!rnc_status_pin_visible(RNC_BLE_SECURE, 0));
}

static void test_running_page_oled(void) {
  rnc_status s = sample();
  screen l;
  unsigned n = rnc_status_layout(&s, RNC_PROFILE_OLED, l);
  CHECK(n == 7);
  CHECK_LINE(l, 0, "reticulum-c 0.2.1");
  CHECK_LINE(l, 1, "RNode Radio ON");
  CHECK_LINE(l, 2, "915.000MHz 0dBm");
  CHECK_LINE(l, 3, "BW125k SF8 CR4/5");
  CHECK_LINE(l, 4, "RSSI -31 SNR 12.8");
  CHECK_LINE(l, 5, "RX 12 TX 3 Air 0.4%");
  CHECK_LINE(l, 6, "Link USB");
}

/* the PIN is on its own last row, only when the rule says so, and is never printed otherwise */
static void test_pin_row(void) {
  rnc_status s = sample();
  screen l;
  unsigned n, i;
  s.ble = RNC_BLE_ADVERTISING;
  strcpy(s.pin, "246810");
  n = rnc_status_layout(&s, RNC_PROFILE_OLED, l);
  CHECK(n == 8);
  CHECK_LINE(l, 6, "Link USB");
  CHECK_LINE(l, 7, "BLE PIN 246810");
  s.ble = RNC_BLE_CONNECTED; /* a phone is pairing: still shown */
  n = rnc_status_layout(&s, RNC_PROFILE_OLED, l);
  CHECK(n == 8 && !strcmp(l[7], "BLE PIN 246810"));
  /* paired and connected, or Bluetooth off: the digits are in the record but never on screen */
  for (i = 0; i < 2; i++) {
    s.ble = i ? RNC_BLE_OFF : RNC_BLE_SECURE;
    n = rnc_status_layout(&s, RNC_PROFILE_OLED, l);
    for (unsigned r = 0; r < n; r++)
      CHECK(strstr(l[r], "246810") == NULL && strstr(l[r], "PIN") == NULL);
  }
  s.ble = RNC_BLE_ADVERTISING;
  s.pin[0] = 0; /* no PIN set */
  n = rnc_status_layout(&s, RNC_PROFILE_OLED, l);
  for (unsigned r = 0; r < n; r++)
    CHECK(strstr(l[r], "PIN") == NULL);
}

static void test_no_signal_and_off(void) {
  rnc_status s = sample();
  screen l;
  unsigned n, r;
  s.has_signal = 0;
  n = rnc_status_layout(&s, RNC_PROFILE_OLED, l);
  CHECK_LINE(l, 4, "No signal yet");
  CHECK(n == 7);
  s = sample();
  s.radio_on = 0;
  s.radio_set = 0;
  s.has_signal = 0;
  n = rnc_status_layout(&s, RNC_PROFILE_OLED, l);
  CHECK_LINE(l, 1, "RNode Radio not set");
  for (r = 0; r < n; r++)
    CHECK(strstr(l[r], "MHz") == NULL && strstr(l[r], "BW") == NULL);
  s = sample();
  s.radio_on = 0; /* settings made, radio off */
  n = rnc_status_layout(&s, RNC_PROFILE_OLED, l);
  CHECK_LINE(l, 1, "RNode Radio OFF");
  CHECK_LINE(l, 2, "915.000MHz 0dBm");
}

static void test_epaper_profile(void) {
  rnc_status s = sample();
  screen l;
  rnc_status_profile tiny = {21, 4};
  unsigned n, r;
  s.ble = RNC_BLE_ADVERTISING;
  strcpy(s.pin, "246810");
  n = rnc_status_layout(&s, RNC_PROFILE_EPAPER, l);
  CHECK(n <= 12);
  for (r = 0; r < n; r++)
    CHECK(strlen(l[r]) <= 16);
  CHECK(n > 0 && !strcmp(l[n - 1], "BLE PIN 246810"));
  CHECK_LINE(l, 0, "reticulum-c");
  CHECK_LINE(l, 1, "0.2.1");
  /* too few rows: lower-priority rows go first, the PIN stays */
  n = rnc_status_layout(&s, tiny, l);
  CHECK(n == 4);
  CHECK_LINE(l, 0, "reticulum-c 0.2.1");
  CHECK_LINE(l, 3, "BLE PIN 246810");
}

static void test_extremes(void) {
  rnc_status s = sample();
  screen l;
  unsigned n, r, k;
  s.freq_hz = 1020000000u;
  s.rx_packets = 4294967295u;
  s.tx_packets = 4294967295u;
  s.airtime_permille = 1000;
  strcpy(s.mode, "12345678901234567890123");
  s.ble = RNC_BLE_CONNECTED;
  strcpy(s.pin, "000000");
  for (k = 0; k < 8; k++) {
    s.rssi_dbm = (int16_t)((k & 1) ? -157 : 0);
    s.snr_quarter_db = (int16_t)((k & 2) ? -128 : 127);
    s.bw_hz = (k & 4) ? 7800u : 500000u;
    for (r = 0; r < 2; r++) {
      rnc_status_profile p = r ? RNC_PROFILE_EPAPER : RNC_PROFILE_OLED;
      unsigned i;
      n = rnc_status_layout(&s, p, l);
      CHECK(n <= p.rows);
      for (i = 0; i < n; i++)
        CHECK(strlen(l[i]) <= p.cols);
    }
  }
  s.rssi_dbm = -157;
  s.snr_quarter_db = -128;
  s.bw_hz = 7800u;
  n = rnc_status_layout(&s, RNC_PROFILE_OLED, l);
  CHECK(n >= 5);
  CHECK_LINE(l, 1, "123456789012345678901"); /* the 23 character mode text is cut to the row */
  CHECK_LINE(l, 2, "Radio ON");
  CHECK_LINE(l, 3, "1020.000MHz 0dBm");
  CHECK_LINE(l, 4, "BW7.8k SF8 CR4/5");
  CHECK_LINE(l, 5, "RSSI -157 SNR -32.0");
}

static void test_phases(void) {
  rnc_status s = sample();
  screen l;
  unsigned n;
  s.phase = RNC_PHASE_STARTING;
  n = rnc_status_layout(&s, RNC_PROFILE_OLED, l);
  CHECK(n == 2);
  CHECK_LINE(l, 0, "reticulum-c 0.2.1");
  CHECK_LINE(l, 1, "starting");
  s.phase = RNC_PHASE_SETUP;
  n = rnc_status_layout(&s, RNC_PROFILE_OLED, l);
  CHECK(n == 3);
  CHECK_LINE(l, 1, "Setup mode");
  CHECK_LINE(l, 2, "rnc-config console");
  n = rnc_status_layout(&s, RNC_PROFILE_EPAPER, l);
  CHECK(n == 5); /* the title and the console line wrap on the narrower profile */
}

int main(void) {
  test_pin_rule();
  test_running_page_oled();
  test_pin_row();
  test_no_signal_and_off();
  test_epaper_profile();
  test_extremes();
  test_phases();
  if (failures) {
    fprintf(stderr, "test_status: %d failure(s)\n", failures);
    return 1;
  }
  puts("test_status: all checks passed");
  return 0;
}
