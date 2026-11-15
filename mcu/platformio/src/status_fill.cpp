// Fills the status record for the screens (display_mode.h). Everything here only reads: the
// display task runs beside the radio and Reticulum tasks and must never change their state.
// The values are aligned words, so a snapshot that mixes two instants is acceptable.
#include "display_mode.h"

#if RNC_HAVE_DISPLAY
#include <Arduino.h>

#include "ble_mode.h"

static const rnc_lora_if *g_li = NULL;
static const rnc_rnode *g_rn = NULL;
static rnc_mcu_cfg g_cfg;
static volatile rnc_status_phase g_phase = RNC_PHASE_STARTING;
static volatile rnc_status_link g_link = RNC_LINK_NONE;

void rnc_status_sources(const rnc_lora_if *li, const rnc_rnode *rn, const rnc_mcu_cfg *cfg) {
  g_cfg = *cfg;
  memset(g_cfg.password, 0, sizeof g_cfg.password); // the screen never needs the Wi-Fi secrets
  memset(g_cfg.ssid, 0, sizeof g_cfg.ssid);
  g_li = li;
  g_rn = rn;
}
void rnc_status_set_phase(rnc_status_phase phase) { g_phase = phase; }
void rnc_status_set_link(rnc_status_link link) { g_link = link; }

void rnc_status_fill(rnc_status *out, uint64_t now_ms) {
  memset(out, 0, sizeof(*out));
  out->phase = g_phase;
  out->link = g_link;
  snprintf(out->version, sizeof(out->version), "%s", RNC_MCU_VERSION);
  bool rnode = rnc_mcu_cfg_rnode_mode(&g_cfg);
  if (rnode) {
    snprintf(out->mode, sizeof(out->mode), "RNode");
    if (g_rn) {
      out->radio_on = rnc_rnode_radio_on(g_rn);
      out->radio_set = (g_rn->set & 0x1Fu) == 0x1Fu; // frequency, bandwidth, power, SF and CR made
      out->freq_hz = g_rn->p.freq_hz;
      out->bw_hz = g_rn->p.bw_hz;
      out->sf = g_rn->p.sf;
      out->cr = g_rn->p.cr;
      out->txp_dbm = g_rn->p.txp_dbm;
    }
  } else {
    const char *transport = rnc_mcu_cfg_wifi_mode(&g_cfg) ? "WiFi" : "USB";
    const char *lora = g_cfg.lora.mode == RNC_LORA_MODE_LEAF      ? " leaf"
                       : g_cfg.lora.mode == RNC_LORA_MODE_GATEWAY ? " gateway"
                                                                  : "";
    snprintf(out->mode, sizeof(out->mode), "%s%s", transport, lora);
    out->radio_on = g_li && rnc_lora_if_up(g_li);
    out->radio_set = rnc_lora_cfg_ready(&g_cfg.lora);
    out->freq_hz = g_cfg.lora.freq_hz;
    out->bw_hz = g_cfg.lora.bw_hz;
    out->sf = g_cfg.lora.sf;
    out->cr = g_cfg.lora.cr;
    out->txp_dbm = g_cfg.lora.txp_dbm;
  }
  if (g_li) {
    out->rx_packets = g_li->stats.rx_packets;
    out->tx_packets = g_li->stats.tx_packets;
    out->has_signal = g_li->stats.rx_packets > 0u; // a packet has been received since boot
    out->rssi_dbm = g_li->stats.last_rssi_dbm;
    out->snr_quarter_db = g_li->stats.last_snr_quarter_db;
    if (g_li->budget.budget_ms > 0u) {
      uint64_t used = rnc_airtime_used(&g_li->budget, now_ms);
      uint64_t permille = used * 1000u / g_li->budget.budget_ms;
      out->airtime_permille = (uint16_t)(permille > 1000u ? 1000u : permille);
    }
  }
  // Bluetooth runs only in RNode mode; the PIN is copied only while the rule allows showing it
  out->ble = rnode ? rnc_ble_state() : RNC_BLE_OFF;
  if (rnc_status_pin_visible(out->ble, g_cfg.ble_pin[0] != 0))
    memcpy(out->pin, g_cfg.ble_pin, sizeof(out->pin));
}
#endif
