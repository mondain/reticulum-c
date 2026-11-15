#ifndef RNC_STATUS_H
#define RNC_STATUS_H
/*
 * What the screens of the T-Echo (e-paper) and the T-Beam Supreme (OLED) show: one status
 * record that the firmware fills in, and one text layout of it, in portable C so the words
 * and the PIN rule are tested on the host (docs/display-status-design.txt).
 *
 * The Bluetooth PIN appears only while it is needed: Bluetooth is on (a PIN is set) and no
 * authenticated link exists. The layout checks the rule itself, so the digits are never
 * printed otherwise even if a caller leaves them in the record.
 */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { RNC_PHASE_STARTING = 0, RNC_PHASE_SETUP, RNC_PHASE_RUNNING } rnc_status_phase;
typedef enum { RNC_LINK_NONE = 0, RNC_LINK_USB, RNC_LINK_BLE, RNC_LINK_WIFI } rnc_status_link;
typedef enum {
  RNC_BLE_OFF = 0,     /* no PIN set: the service is not started */
  RNC_BLE_ADVERTISING, /* waiting for a central */
  RNC_BLE_CONNECTED,   /* a central is connected but the link is not authenticated yet */
  RNC_BLE_SECURE       /* encrypted and authenticated with the PIN (or a bonded key) */
} rnc_ble_state_t;

typedef struct rnc_status {
  rnc_status_phase phase;
  char mode[24];             /* "RNode", "USB leaf", "WiFi gateway", ... */
  int radio_on;              /* the radio is running */
  int radio_set;             /* every transmit setting has been made */
  uint32_t freq_hz, bw_hz;
  uint8_t sf, cr;            /* cr: denominator 5..8 */
  int8_t txp_dbm;
  int has_signal;            /* a packet has been received since boot */
  int16_t rssi_dbm;
  int16_t snr_quarter_db;
  uint32_t rx_packets, tx_packets;
  uint16_t airtime_permille; /* airtime used, thousandths of the hourly budget */
  rnc_status_link link;
  rnc_ble_state_t ble;
  char pin[7];               /* the six digits; the filler leaves it empty unless it may be shown */
  char version[12];
} rnc_status;

/* 1 when the PIN may be shown: Bluetooth is advertising or has an unauthenticated central,
 * and a PIN is set. */
int rnc_status_pin_visible(rnc_ble_state_t ble, int pin_set);

#define RNC_STATUS_MAX_COLS 21u
#define RNC_STATUS_MAX_ROWS 12u

typedef struct rnc_status_profile {
  unsigned cols, rows;
} rnc_status_profile;
extern const rnc_status_profile rnc_profile_oled;   /* 21 columns x 8 rows (6 x 8 font on 128 x 64) */
extern const rnc_status_profile rnc_profile_epaper; /* 16 columns x 12 rows (text size 2 on 200 x 200) */
#define RNC_PROFILE_OLED rnc_profile_oled
#define RNC_PROFILE_EPAPER rnc_profile_epaper

/* Lays the status out as text: returns the rows used (at most p.rows); every row is NUL
 * terminated and at most p.cols characters. Fields are packed greedily onto rows; when the
 * rows run out the lowest-priority rows (the end of the page) go first and the PIN row, when
 * it is shown, is always kept as the last row. No allocation. */
unsigned rnc_status_layout(const rnc_status *s, rnc_status_profile p,
                           char lines[RNC_STATUS_MAX_ROWS][RNC_STATUS_MAX_COLS + 1]);

#ifdef __cplusplus
}
#endif
#endif
