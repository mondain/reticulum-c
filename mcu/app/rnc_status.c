#include "rnc_status.h"
#include <stdio.h>
#include <string.h>

const rnc_status_profile rnc_profile_oled = {21u, 8u};
const rnc_status_profile rnc_profile_epaper = {16u, 12u};

int rnc_status_pin_visible(rnc_ble_state_t ble, int pin_set) {
  return pin_set && (ble == RNC_BLE_ADVERTISING || ble == RNC_BLE_CONNECTED);
}

#define MAX_CANDIDATES 24u

typedef struct layout {
  char row[MAX_CANDIDATES][RNC_STATUS_MAX_COLS + 1];
  unsigned count, cols;
} layout;

static void push_row(layout *l, const char *text) {
  if (l->count >= MAX_CANDIDATES)
    return;
  strncpy(l->row[l->count], text, RNC_STATUS_MAX_COLS);
  l->row[l->count][RNC_STATUS_MAX_COLS] = 0;
  l->row[l->count][l->cols] = 0;
  l->count++;
}

/* packs fields onto rows with a space between them; a field wider than a row is cut */
static void add_group(layout *l, const char *const *fields, unsigned n) {
  char cur[RNC_STATUS_MAX_COLS + 1];
  unsigned i;
  cur[0] = 0;
  for (i = 0; i < n; i++) {
    char field[RNC_STATUS_MAX_COLS + 1];
    size_t flen, clen;
    if (!fields[i] || !fields[i][0])
      continue;
    strncpy(field, fields[i], l->cols);
    field[l->cols] = 0;
    flen = strlen(field);
    clen = strlen(cur);
    if (clen == 0u) {
      memcpy(cur, field, flen + 1u);
    } else if (clen + 1u + flen <= l->cols) {
      cur[clen] = ' ';
      memcpy(cur + clen + 1u, field, flen + 1u);
    } else {
      push_row(l, cur);
      memcpy(cur, field, flen + 1u);
    }
  }
  if (cur[0])
    push_row(l, cur);
}

unsigned rnc_status_layout(const rnc_status *s, rnc_status_profile p,
                           char lines[RNC_STATUS_MAX_ROWS][RNC_STATUS_MAX_COLS + 1]) {
  layout l;
  char f[8][24];
  const char *g[8];
  unsigned i, rows = 0;
  int pin = 0, pin_rows;
  if (p.cols > RNC_STATUS_MAX_COLS)
    p.cols = RNC_STATUS_MAX_COLS;
  if (p.rows > RNC_STATUS_MAX_ROWS)
    p.rows = RNC_STATUS_MAX_ROWS;
  if (p.rows == 0u || p.cols == 0u)
    return 0u;
  memset(&l, 0, sizeof(l));
  l.cols = p.cols;

  g[0] = "reticulum-c";
  g[1] = s->version;
  add_group(&l, g, 2);
  if (s->phase == RNC_PHASE_STARTING) {
    g[0] = "starting";
    add_group(&l, g, 1);
  } else if (s->phase == RNC_PHASE_SETUP) {
    g[0] = "Setup mode";
    add_group(&l, g, 1);
    g[0] = "rnc-config";
    g[1] = "console";
    add_group(&l, g, 2);
  } else {
    unsigned whole, frac;
    int tenths, v;
    /* the mode and whether the radio runs */
    g[0] = s->mode;
    g[1] = s->radio_on ? "Radio ON" : s->radio_set ? "Radio OFF" : "Radio not set";
    add_group(&l, g, 2);
    if (s->radio_set) {
      snprintf(f[0], sizeof(f[0]), "%lu.%03luMHz", (unsigned long)(s->freq_hz / 1000000u),
               (unsigned long)((s->freq_hz / 1000u) % 1000u));
      snprintf(f[1], sizeof(f[1]), "%ddBm", (int)s->txp_dbm);
      g[0] = f[0];
      g[1] = f[1];
      add_group(&l, g, 2);
      whole = s->bw_hz / 1000u;
      frac = (s->bw_hz % 1000u) / 10u; /* hundredths of a kHz */
      if (frac == 0u)
        snprintf(f[0], sizeof(f[0]), "BW%uk", whole);
      else if (frac % 10u == 0u)
        snprintf(f[0], sizeof(f[0]), "BW%u.%uk", whole, frac / 10u);
      else
        snprintf(f[0], sizeof(f[0]), "BW%u.%02uk", whole, frac);
      snprintf(f[1], sizeof(f[1]), "SF%u", (unsigned)s->sf);
      snprintf(f[2], sizeof(f[2]), "CR4/%u", (unsigned)s->cr);
      g[0] = f[0];
      g[1] = f[1];
      g[2] = f[2];
      add_group(&l, g, 3);
    }
    if (s->has_signal) {
      snprintf(f[0], sizeof(f[0]), "RSSI %d", (int)s->rssi_dbm);
      v = (int)s->snr_quarter_db * 25; /* hundredths of a dB */
      tenths = (v + (v >= 0 ? 5 : -5)) / 10;
      snprintf(f[1], sizeof(f[1]), "SNR %s%d.%d", tenths < 0 ? "-" : "", tenths < 0 ? -tenths / 10 : tenths / 10,
               tenths < 0 ? -tenths % 10 : tenths % 10);
      g[0] = f[0];
      g[1] = f[1];
      add_group(&l, g, 2);
    } else {
      g[0] = "No signal yet";
      add_group(&l, g, 1);
    }
    snprintf(f[0], sizeof(f[0]), "RX %lu", (unsigned long)s->rx_packets);
    snprintf(f[1], sizeof(f[1]), "TX %lu", (unsigned long)s->tx_packets);
    snprintf(f[2], sizeof(f[2]), "Air %u.%u%%", (unsigned)(s->airtime_permille / 10u),
             (unsigned)(s->airtime_permille % 10u));
    g[0] = f[0];
    g[1] = f[1];
    g[2] = f[2];
    add_group(&l, g, 3);
    g[0] = s->link == RNC_LINK_USB    ? "Link USB"
           : s->link == RNC_LINK_BLE  ? "Link BLE"
           : s->link == RNC_LINK_WIFI ? "Link WiFi"
                                      : "Link none";
    add_group(&l, g, 1);
  }

  /* the PIN: its own last row, only when the rule says so, never dropped */
  pin = rnc_status_pin_visible(s->ble, s->pin[0] != 0);
  pin_rows = pin ? 1 : 0;
  while (l.count + (unsigned)pin_rows > p.rows && l.count > 0u)
    l.count--; /* lowest priority (the end of the page) first */
  for (i = 0; i < l.count; i++) {
    strcpy(lines[rows], l.row[i]);
    rows++;
  }
  if (pin && rows < p.rows) {
    char text[RNC_STATUS_MAX_COLS + 1];
    snprintf(text, sizeof(text), "BLE PIN %s", s->pin);
    text[p.cols] = 0;
    strcpy(lines[rows], text);
    rows++;
  }
  return rows;
}

void rnc_refresh_init(rnc_refresh *r, unsigned min_ms, unsigned pin_ms, unsigned full_ms) {
  memset(r, 0, sizeof(*r));
  r->min_interval_ms = min_ms;
  r->pin_interval_ms = pin_ms;
  r->full_interval_ms = full_ms;
}

rnc_refresh_action rnc_refresh_decide(rnc_refresh *r, int layout_changed, int pin_visible, uint64_t now_ms) {
  rnc_refresh_action action;
  int pin_changed = pin_visible != r->last_pin_visible;
  if (!r->drawn_once) {
    action = RNC_REFRESH_FULL;
  } else {
    uint64_t since = now_ms - r->last_ms;
    if (pin_changed ? since < r->pin_interval_ms : (!layout_changed || since < r->min_interval_ms))
      return RNC_REFRESH_NONE;
    action = r->full_interval_ms != 0u && now_ms - r->last_full_ms >= r->full_interval_ms ? RNC_REFRESH_FULL
                                                                                          : RNC_REFRESH_PARTIAL;
  }
  r->drawn_once = 1;
  r->last_ms = now_ms;
  r->last_pin_visible = pin_visible;
  if (action == RNC_REFRESH_FULL)
    r->last_full_ms = now_ms;
  return action;
}

rnc_refresh_action rnc_display_step(rnc_refresh *r, rnc_display_state *st, const rnc_status *s,
                                    rnc_status_profile p, int init_ok, uint64_t now_ms,
                                    char out[RNC_STATUS_MAX_ROWS][RNC_STATUS_MAX_COLS + 1],
                                    unsigned *rows) {
  unsigned n, i;
  int changed;
  rnc_refresh_action action;
  if (!init_ok)
    return RNC_REFRESH_NONE;
  n = rnc_status_layout(s, p, out);
  changed = n != st->prev_rows;
  for (i = 0; !changed && i < n; i++)
    changed = strcmp(out[i], st->prev[i]) != 0;
  action = rnc_refresh_decide(r, changed, rnc_status_pin_visible(s->ble, s->pin[0] != 0), now_ms);
  if (action != RNC_REFRESH_NONE) {
    for (i = 0; i < n; i++)
      strcpy(st->prev[i], out[i]);
    st->prev_rows = n;
    *rows = n;
  }
  return action;
}
