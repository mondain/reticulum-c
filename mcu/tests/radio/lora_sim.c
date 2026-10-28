/* Shared radio medium for the LoRa host tests; see lora_sim.h. */
#include "lora_sim.h"
#include <math.h>
#include <string.h>

double sim_bw_exact(uint32_t n) {
  switch (n) {
  case 7800: return 7812.5;
  case 10400: return 10416.666666667;
  case 15600: return 15625.0;
  case 20800: return 20833.333333333;
  case 31250: return 31250.0;
  case 41700: return 41666.666666667;
  default: return (double)n;
  }
}

double sim_toa_us(uint32_t bw_hz, unsigned sf, unsigned cr, unsigned preamble, unsigned payload,
                  int ldro) {
  double bw = sim_bw_exact(bw_hz), tsym = pow(2.0, sf) / bw * 1e6;
  double tpre = (preamble + (sf < 7 ? 6.25 : 4.25)) * tsym;
  double num = 8.0 * payload - 4.0 * sf + (sf < 7 ? 20.0 : 28.0) + 16.0;
  double den = 4.0 * (sf - 2.0 * (ldro ? 1 : 0));
  double blocks = ceil(num / den);
  if (blocks < 0)
    blocks = 0;
  return tpre + (8.0 + blocks * cr) * tsym;
}

double sim_sensitivity_dbm(uint32_t bw_hz, unsigned sf) {
  /* thermal noise + noise figure 6 dB + the demodulator SNR limit */
  double snr = -7.5 - 2.5 * ((double)sf - 7.0);
  return -174.0 + 10.0 * log10(sim_bw_exact(bw_hz)) + 6.0 + snr;
}

void sim_medium_init(sim_medium *m, uint32_t seed) {
  int i, j;
  memset(m, 0, sizeof(*m));
  m->seed = seed ? seed : 1u;
  m->capture_db = 6;
  m->noise_floor_dbm = -110;
  for (i = 0; i < SIM_MAX_RADIOS; i++)
    for (j = 0; j < SIM_MAX_RADIOS; j++)
      m->loss_db[i][j] = SIM_NO_LINK;
}
static uint32_t rnd(sim_medium *m) {
  m->seed = m->seed * 1664525u + 1013904223u;
  return m->seed >> 8;
}
int sim_medium_add(sim_medium *m, void *radio, const sim_radio_ops *ops) {
  int i = m->count++;
  m->radio[i] = radio;
  m->ops[i] = ops;
  return i;
}
void sim_link(sim_medium *m, int a, int b, int loss_db) {
  m->loss_db[a][b] = m->loss_db[b][a] = loss_db;
}
void sim_link_drop(sim_medium *m, int a, int b, unsigned permille) {
  m->drop_permille[a][b] = m->drop_permille[b][a] = (uint16_t)permille;
}
void sim_link_all(sim_medium *m, int loss_db) {
  int i, j;
  for (i = 0; i < m->count; i++)
    for (j = 0; j < m->count; j++)
      if (i != j)
        m->loss_db[i][j] = loss_db;
}

int sim_transmitting(const sim_medium *m, int radio) {
  int k;
  for (k = 0; k < SIM_MAX_TX; k++)
    if (m->tx[k].len && m->tx[k].radio == radio && m->tx[k].start_us <= m->now_us &&
        m->now_us < m->tx[k].end_us)
      return 1;
  return 0;
}

void sim_medium_tx(sim_medium *m, int radio, const uint8_t *frame, size_t len, const sim_phy *phy,
                   uint64_t duration_us) {
  int k, slot = -1;
  for (k = 0; k < SIM_MAX_TX; k++)
    if (!m->tx[k].len || (m->tx[k].done && m->tx[k].end_us + 15000000u < m->now_us)) {
      slot = k;
      break;
    }
  if (slot < 0)
    return;
  m->tx[slot].radio = radio;
  memcpy(m->tx[slot].frame, frame, len);
  m->tx[slot].len = len;
  m->tx[slot].start_us = m->now_us;
  m->tx[slot].end_us = m->now_us + duration_us;
  m->tx[slot].phy = *phy;
  m->tx[slot].done = 0;
  m->frames_sent++;
  m->air_us[radio] += duration_us;
  if (len > m->max_frame)
    m->max_frame = (uint32_t)len;
  if (m->log_count < 256u) {
    m->log_first[m->log_count] = frame[0];
    m->log_len[m->log_count] = (uint16_t)len;
    m->log_radio[m->log_count] = (uint8_t)radio;
  }
  m->log_count++;
}

static int same_channel(const sim_phy *a, const sim_phy *b) {
  double d = (double)a->freq_hz - (double)b->freq_hz;
  return fabs(d) <= sim_bw_exact(a->bw_hz) / 4.0 && a->bw_hz == b->bw_hz && a->sf == b->sf;
}
static double power_at(const sim_medium *m, const sim_tx *t, int j) {
  int loss = m->loss_db[t->radio][j];
  return loss == SIM_NO_LINK ? -1000.0 : (double)t->phy.txp_dbm - (double)loss;
}

void sim_medium_advance(sim_medium *m) {
  int k, j, q;
  for (k = 0; k < SIM_MAX_TX; k++) {
    sim_tx *t = &m->tx[k];
    if (!t->len || t->done || t->end_us > m->now_us)
      continue;
    for (j = 0; j < m->count; j++) {
      sim_phy rp;
      uint64_t since;
      double p, sens;
      int crc_ok = 1;
      if (j == t->radio)
        continue;
      p = power_at(m, t, j);
      sens = sim_sensitivity_dbm(t->phy.bw_hz, t->phy.sf);
      if (p < sens) {
        m->lost_unheard++;
        continue;
      }
      if (!m->ops[j]->rx_state(m->radio[j], &rp, &since)) {
        m->lost_not_listening++;
        continue;
      }
      if (!same_channel(&rp, &t->phy) || rp.ldro != t->phy.ldro || rp.net != t->phy.net) {
        m->lost_phy_mismatch++;
        continue;
      }
      /* it must have been listening before the preamble ran out (a few symbols are enough to
       * lock; we ask for the first half of the preamble) */
      {
        double tsym = pow(2.0, t->phy.sf) / sim_bw_exact(t->phy.bw_hz) * 1e6;
        if ((double)since > (double)t->start_us + (t->phy.preamble / 2.0) * tsym) {
          m->lost_not_listening++;
          continue;
        }
      }
      /* transmitting itself at any time during the frame: deaf */
      {
        int deaf = 0;
        for (q = 0; q < SIM_MAX_TX; q++) {
          const sim_tx *o = &m->tx[q];
          if (o->len && o != t && o->radio == j && o->start_us < t->end_us && o->end_us > t->start_us)
            deaf = 1;
        }
        if (deaf) {
          m->lost_not_listening++;
          continue;
        }
      }
      for (q = 0; q < SIM_MAX_TX; q++) {
        const sim_tx *o = &m->tx[q];
        if (!o->len || o == t || o->radio == t->radio)
          continue;
        if (o->start_us < t->end_us && o->end_us > t->start_us && same_channel(&o->phy, &t->phy)) {
          double po = power_at(m, o, j);
          if (po >= sim_sensitivity_dbm(o->phy.bw_hz, o->phy.sf) - 6.0 && po + m->capture_db > p)
            crc_ok = 0;
        }
      }
      if (m->drop_permille[t->radio][j] && rnd(m) % 1000u < m->drop_permille[t->radio][j]) {
        m->lost_random++;
        continue;
      }
      if (!crc_ok)
        m->lost_collision++;
      else
        m->frames_delivered++;
      m->ops[j]->deliver(m->radio[j], t->frame, t->len, crc_ok, (int)(p + 0.5),
                         (int)((p - m->noise_floor_dbm) * 4.0 > 40.0 ? 40.0 : (p - m->noise_floor_dbm) * 4.0));
    }
    t->done = 1;
  }
}

int sim_sense(const sim_medium *m, int radio, const sim_phy *phy, uint64_t detect_us,
              uint64_t *start_us) {
  int k;
  for (k = 0; k < SIM_MAX_TX; k++) {
    const sim_tx *t = &m->tx[k];
    if (!t->len || t->done || t->radio == radio || t->end_us <= m->now_us ||
        t->start_us + detect_us > m->now_us)
      continue;
    if (!same_channel(&t->phy, phy))
      continue;
    if (power_at(m, t, radio) < sim_sensitivity_dbm(t->phy.bw_hz, t->phy.sf))
      continue;
    if (start_us)
      *start_us = t->start_us;
    return 1;
  }
  return 0;
}

int sim_rssi(const sim_medium *m, int radio, const sim_phy *phy) {
  int k;
  double best = m->noise_floor_dbm;
  for (k = 0; k < SIM_MAX_TX; k++) {
    const sim_tx *t = &m->tx[k];
    double p;
    if (!t->len || t->done || t->radio == radio || t->end_us <= m->now_us ||
        t->start_us > m->now_us)
      continue;
    if (fabs((double)t->phy.freq_hz - (double)phy->freq_hz) > sim_bw_exact(phy->bw_hz))
      continue;
    p = power_at(m, t, radio);
    if (p > best)
      best = p;
  }
  return (int)floor(best + 0.5);
}
