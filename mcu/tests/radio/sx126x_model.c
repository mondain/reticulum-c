/* Software model of the SX1261/SX1262 at command level; see sx126x_model.h. */
#include "sx126x_model.h"
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

enum { M_SLEEP = 0, M_RC = 2, M_XOSC = 3, M_FS = 4, M_RX = 5, M_TX = 6, M_CAD = 7 };
enum {
  IRQ_TXDONE = 1, IRQ_RXDONE = 2, IRQ_PREAMBLE = 4, IRQ_SYNC = 8, IRQ_HEADER = 0x10,
  IRQ_HDRERR = 0x20, IRQ_CRCERR = 0x40, IRQ_CADDONE = 0x80, IRQ_CADDET = 0x100
};

static void violate(sx126x_model *m, const char *fmt, ...) {
  va_list ap;
  m->violations++;
  if (m->violations == 1) {
    va_start(ap, fmt);
    vsnprintf(m->first_violation, sizeof(m->first_violation), fmt, ap);
    va_end(ap);
  }
}

static double bw_exact_from_code(int code) {
  switch (code) {
  case 0: return 7812.5;
  case 8: return 10416.666666667;
  case 1: return 15625.0;
  case 9: return 20833.333333333;
  case 2: return 31250.0;
  case 10: return 41666.666666667;
  case 3: return 62500.0;
  case 4: return 125000.0;
  case 5: return 250000.0;
  case 6: return 500000.0;
  default: return 0;
  }
}
static uint32_t bw_nominal_from_code(int code) {
  switch (code) {
  case 0: return 7800;
  case 8: return 10400;
  case 1: return 15600;
  case 9: return 20800;
  case 2: return 31250;
  case 10: return 41700;
  case 3: return 62500;
  case 4: return 125000;
  case 5: return 250000;
  case 6: return 500000;
  default: return 0;
  }
}
double sx126x_model_freq_hz(const sx126x_model *m) {
  return (double)m->frf * 32000000.0 / 33554432.0;
}

static void phy_of(const sx126x_model *m, sim_phy *p) {
  uint16_t sw = (uint16_t)((m->regs[0x0740] << 8) | m->regs[0x0741]);
  memset(p, 0, sizeof(*p));
  p->freq_hz = (uint32_t)(sx126x_model_freq_hz(m) + 0.5);
  p->bw_hz = bw_nominal_from_code(m->bw);
  p->sf = m->sf;
  p->cr = (uint8_t)(m->cr + 4u);
  p->ldro = m->ldro;
  p->net = sw == 0x1424 ? 0 : sw == 0x3444 ? 1 : 2;
  p->preamble = m->preamble;
  p->txp_dbm = m->tx_power;
}

static double tsym_us(const sx126x_model *m) {
  return pow(2.0, m->sf) / bw_exact_from_code(m->bw) * 1e6;
}

/* brings the model up to the medium's clock */
static void sync(sx126x_model *m) {
  uint64_t now = m->medium->now_us;
  sim_phy phy;
  if (m->mode == M_TX && now >= m->tx_end_us) {
    m->irq_status |= IRQ_TXDONE;
    m->mode = m->fallback == 0x40 ? M_FS : m->fallback == 0x20 ? M_RC : M_XOSC;
    m->frames_sent++;
  }
  if (m->mode == M_CAD && now >= m->cad_end_us) {
    uint64_t start;
    phy_of(m, &phy);
    m->irq_status |= IRQ_CADDONE;
    if (sim_sense(m->medium, m->id, &phy, 0, &start))
      m->irq_status |= IRQ_CADDET;
    m->mode = M_RC; /* CAD_ONLY exit mode: standby RC */
  }
  if (m->mode == M_RX && m->packet_type == 1) {
    uint64_t start;
    double ts = tsym_us(m);
    phy_of(m, &phy);
    if (sim_sense(m->medium, m->id, &phy, (uint64_t)(4.0 * ts), &start)) {
      if (start != m->last_pre_start) {
        m->last_pre_start = start;
        m->irq_status |= IRQ_PREAMBLE;
      }
      if (now >= start + (uint64_t)((m->preamble + 4.25 + 2.0) * ts) && start != m->last_hdr_start) {
        m->last_hdr_start = start;
        m->irq_status |= IRQ_SYNC | IRQ_HEADER;
      }
    }
  }
}

static int busy(sx126x_model *m) { return m->medium->now_us < m->busy_until_us; }
static void set_busy(sx126x_model *m, uint64_t us) {
  m->busy_until_us = m->medium->now_us + us;
}

/* ---- reception from the medium ----------------------------------------------------- */
static int rx_state(void *r, sim_phy *phy, uint64_t *since) {
  sx126x_model *m = r;
  sync(m);
  if (m->mode != M_RX || m->packet_type != 1)
    return 0;
  if (!(m->regs[0x0736] & 0x04) && m->invert_iq == 0) {
    m->iq_misses++; /* errata: standard IQ needs bit 2 of 0x0736 set; demodulation fails */
    return 0;
  }
  if (m->bw == 6 && (m->regs[0x0889] & 0x04)) {
    /* errata: with 500 kHz the bit must be cleared; with it set the modulation quality
     * suffers. Frames are still decoded, but flagged for the test. */
    m->bw500_degraded++;
  }
  phy_of(m, phy);
  *since = m->rx_since_us;
  return 1;
}
static void deliver(void *r, const uint8_t *frame, size_t len, int crc_ok, int rssi, int snr) {
  sx126x_model *m = r;
  m->irq_status |= IRQ_PREAMBLE | IRQ_SYNC | IRQ_HEADER;
  memcpy(m->buffer + m->rx_base, frame, len);
  m->rx_len = (uint8_t)len;
  m->rx_start = m->rx_base;
  m->rx_rssi_raw = (uint8_t)(-2 * rssi > 255 ? 255 : (-2 * rssi < 0 ? 0 : -2 * rssi));
  m->rx_snr_raw = (int8_t)snr;
  m->irq_status |= IRQ_RXDONE;
  if (!crc_ok) {
    m->irq_status |= IRQ_CRCERR;
    m->crc_errors++;
  } else {
    m->frames_received++;
  }
}
static const sim_radio_ops OPS = {rx_state, deliver};

/* ---- commands ------------------------------------------------------------------------- */
static int in_standby(const sx126x_model *m) { return m->mode == M_RC || m->mode == M_XOSC; }
static int in_standby_fs(const sx126x_model *m) { return in_standby(m) || m->mode == M_FS; }

static void need_len(sx126x_model *m, const char *name, size_t got, size_t want) {
  if (got != want)
    violate(m, "%s: length %zu, expected %zu", name, got, want);
}

static void start_xosc(sx126x_model *m, int to_mode) {
  if (m->tcxo_present && !m->tcxo_ctrl_set) {
    /* a board with a TCXO on DIO3: the oscillator never starts unless DIO3 is configured */
    m->device_errors |= 0x0020;
    violate(m, "oscillator started on a board with a TCXO without SetDIO3AsTCXOCtrl");
    return;
  }
  m->mode = to_mode;
}

static void tx_start(sx126x_model *m) {
  sim_phy phy;
  double toa;
  int ok = 1;
  if (m->packet_type != 1 || !m->have_freq || !m->have_mod || !m->have_pkt || !m->have_pa ||
      !m->have_txp) {
    violate(m, "SetTx before the LoRa configuration is complete");
    return;
  }
  if (m->payload_len == 0) {
    violate(m, "SetTx with payload length 0");
    return;
  }
  if (m->dio2_switch && !m->dio2_rf)
    ok = 0, m->antenna_misses++;
  phy_of(m, &phy);
  toa = sim_toa_us(phy.bw_hz, phy.sf, phy.cr, phy.preamble, m->payload_len, phy.ldro);
  start_xosc(m, M_TX);
  if (m->mode != M_TX)
    return;
  m->tx_end_us = m->medium->now_us + (uint64_t)toa;
  m->tx_frame_len = m->payload_len;
  if (ok)
    sim_medium_tx(m->medium, m->id, m->buffer + m->tx_base, m->payload_len, &phy, (uint64_t)toa);
}

static void execute(sx126x_model *m, const uint8_t *tx, uint8_t *rx, size_t n) {
  uint8_t op = tx[0];
  const uint8_t *a = tx + 1;
  size_t na = n - 1;
  uint8_t status = (uint8_t)(m->mode << 4);
  size_t i;
  m->last_opcode = op;
  m->commands++;
  if (rx)
    memset(rx, 0, n);
  if (rx && n > 1)
    rx[1] = status; /* every read command returns the status as its first answer byte */
  switch (op) {
  case 0x80: /* SetStandby */
    need_len(m, "SetStandby", na, 1);
    if (na == 1 && a[0] > 1)
      violate(m, "SetStandby: bad mode %u", a[0]);
    if (na == 1 && m->mode != M_SLEEP) {
      if (a[0] == 1)
        start_xosc(m, M_XOSC);
      else
        m->mode = M_RC;
      if (a[0] == 1 && m->tcxo_present)
        set_busy(m, (uint64_t)(m->tcxo_delay * 15.625));
    }
    break;
  case 0x84: /* SetSleep */
    need_len(m, "SetSleep", na, 1);
    m->mode = M_SLEEP;
    break;
  case 0xC1: /* SetFs */
    need_len(m, "SetFs", na, 0);
    if (!in_standby(m))
      violate(m, "SetFs outside standby");
    else
      start_xosc(m, M_FS);
    break;
  case 0x83: /* SetTx */
    need_len(m, "SetTx", na, 3);
    if (!in_standby_fs(m))
      violate(m, "SetTx from mode %d", m->mode);
    else
      tx_start(m);
    break;
  case 0x82: /* SetRx */
    need_len(m, "SetRx", na, 3);
    if (!in_standby_fs(m)) {
      violate(m, "SetRx from mode %d", m->mode);
    } else if (m->packet_type != 1 || !m->have_freq || !m->have_mod || !m->have_pkt) {
      violate(m, "SetRx before the LoRa configuration is complete");
    } else {
      start_xosc(m, M_RX);
      if (m->mode == M_RX)
        m->rx_since_us = m->medium->now_us;
    }
    break;
  case 0xC5: /* SetCad */
    need_len(m, "SetCad", na, 0);
    if (!in_standby_fs(m) || m->packet_type != 1 || !m->have_mod) {
      violate(m, "SetCad in the wrong state");
    } else {
      start_xosc(m, M_CAD);
      if (m->mode == M_CAD)
        m->cad_end_us = m->medium->now_us + (uint64_t)(2.0 * tsym_us(m) + 1000.0);
    }
    break;
  case 0x8A: /* SetPacketType */
    need_len(m, "SetPacketType", na, 1);
    if (!in_standby(m))
      violate(m, "SetPacketType outside standby");
    else if (na == 1 && a[0] > 1)
      violate(m, "SetPacketType: bad type");
    else if (na == 1)
      m->packet_type = a[0];
    break;
  case 0x86: /* SetRfFrequency */
    need_len(m, "SetRfFrequency", na, 4);
    if (m->packet_type < 0)
      violate(m, "SetRfFrequency before SetPacketType");
    if (!in_standby_fs(m))
      violate(m, "SetRfFrequency outside standby");
    if (na == 4) {
      m->frf = ((uint32_t)a[0] << 24) | ((uint32_t)a[1] << 16) | ((uint32_t)a[2] << 8) | a[3];
      m->have_freq = 1;
      if (!m->image_cal[0])
        violate(m, "SetRfFrequency without an image calibration for the band");
    }
    break;
  case 0x95: /* SetPaConfig */
    need_len(m, "SetPaConfig", na, 4);
    if (m->packet_type < 0)
      violate(m, "SetPaConfig before SetPacketType");
    if (na == 4) {
      if ((a[2] == 0 && m->variant != 1262) || (a[2] == 1 && m->variant != 1261))
        violate(m, "SetPaConfig: deviceSel %u does not match an SX%u", a[2], m->variant);
      if (a[3] != 1)
        violate(m, "SetPaConfig: paLut must be 1");
      if (a[0] > 7 || (m->variant == 1262 && a[1] > 7) || (m->variant == 1261 && a[1] > 7))
        violate(m, "SetPaConfig: duty cycle or hpMax out of range");
      memcpy(m->pa, a, 4);
      m->have_pa = 1;
      m->regs[0x08E7] = m->variant == 1262 ? 0x38 : 0x18; /* SetPaConfig resets the OCP */
    }
    break;
  case 0x8E: /* SetTxParams */
    need_len(m, "SetTxParams", na, 2);
    if (m->packet_type < 0)
      violate(m, "SetTxParams before SetPacketType");
    if (!m->have_pa)
      violate(m, "SetTxParams before SetPaConfig");
    if (na == 2) {
      int p = (int8_t)a[0];
      int lo = m->variant == 1262 ? -9 : -17, hi = m->variant == 1262 ? 22 : 14;
      if (p < lo || p > hi)
        violate(m, "SetTxParams: power %d out of range %d..%d", p, lo, hi);
      if (a[1] > 7)
        violate(m, "SetTxParams: bad ramp time");
      m->tx_power = (int8_t)p;
      if (m->variant == 1261 && m->pa[0] == 6)
        m->tx_power = 15; /* the +15 dBm configuration: parameter 14 stands for 15 dBm */
      m->ramp = a[1];
      m->have_txp = 1;
    }
    break;
  case 0x8F: /* SetBufferBaseAddress */
    need_len(m, "SetBufferBaseAddress", na, 2);
    if (na == 2) {
      m->tx_base = a[0];
      m->rx_base = a[1];
      m->have_buffer_base = 1;
    }
    break;
  case 0x8B: /* SetModulationParams (LoRa uses the first four) */
    if (na != 4 && na != 8)
      violate(m, "SetModulationParams: length %zu", na);
    if (m->packet_type != 1)
      violate(m, "SetModulationParams outside LoRa packet type");
    if (na >= 4) {
      if (a[0] < 5 || a[0] > 12)
        violate(m, "SetModulationParams: SF %u", a[0]);
      if (!bw_exact_from_code(a[1]))
        violate(m, "SetModulationParams: BW code %u", a[1]);
      if (a[2] < 1 || a[2] > 4)
        violate(m, "SetModulationParams: CR %u", a[2]);
      if (a[3] > 1)
        violate(m, "SetModulationParams: LDRO %u", a[3]);
      m->sf = a[0];
      m->bw = a[1];
      m->cr = a[2];
      m->ldro = a[3];
      m->have_mod = 1;
    }
    break;
  case 0x8C: /* SetPacketParams (LoRa uses the first six) */
    if (na != 6 && na != 9)
      violate(m, "SetPacketParams: length %zu", na);
    if (m->packet_type != 1)
      violate(m, "SetPacketParams outside LoRa packet type");
    if (na >= 6) {
      if (a[2] > 1 || a[4] > 1 || a[5] > 1)
        violate(m, "SetPacketParams: bad header/crc/iq value");
      m->preamble = (uint16_t)((a[0] << 8) | a[1]);
      if (m->preamble == 0)
        violate(m, "SetPacketParams: preamble 0");
      m->header_type = a[2];
      m->payload_len = a[3];
      m->crc_type = a[4];
      m->invert_iq = a[5];
      m->have_pkt = 1;
      /* errata: the command leaves bit 2 of register 0x0736 cleared */
      m->regs[0x0736] &= (uint8_t)~0x04;
    }
    break;
  case 0x88: /* SetCadParams */
    need_len(m, "SetCadParams", na, 7);
    if (na == 7) {
      if (a[0] > 4 || a[3] > 1)
        violate(m, "SetCadParams: bad values");
      memcpy(m->cad, a, 7);
      m->have_cad = 1;
    }
    break;
  case 0x08: /* SetDioIrqParams */
    need_len(m, "SetDioIrqParams", na, 8);
    if (na == 8) {
      m->irq_mask = (uint16_t)((a[0] << 8) | a[1]);
      m->dio1_mask = (uint16_t)((a[2] << 8) | a[3]);
      m->have_irq_params = 1;
    }
    break;
  case 0x12: /* GetIrqStatus */
    need_len(m, "GetIrqStatus", n, 4);
    if (n == 4) {
      uint16_t v = (uint16_t)(m->irq_status & m->irq_mask);
      rx[2] = (uint8_t)(v >> 8);
      rx[3] = (uint8_t)v;
    }
    break;
  case 0x02: /* ClearIrqStatus */
    need_len(m, "ClearIrqStatus", na, 2);
    if (na == 2)
      m->irq_status &= (uint16_t)~((a[0] << 8) | a[1]);
    break;
  case 0x13: /* GetRxBufferStatus */
    need_len(m, "GetRxBufferStatus", n, 4);
    if (n == 4) {
      rx[2] = m->rx_len;
      rx[3] = m->rx_start;
    }
    break;
  case 0x14: /* GetPacketStatus */
    need_len(m, "GetPacketStatus", n, 5);
    if (n == 5) {
      rx[2] = m->rx_rssi_raw;
      rx[3] = (uint8_t)m->rx_snr_raw;
      rx[4] = m->rx_rssi_raw;
    }
    break;
  case 0x15: /* GetRssiInst */
    need_len(m, "GetRssiInst", n, 3);
    if (n == 3) {
      sim_phy phy;
      phy_of(m, &phy);
      rx[2] = (uint8_t)(-2 * sim_rssi(m->medium, m->id, &phy));
    }
    break;
  case 0x0E: /* WriteBuffer */
    if (na < 2)
      violate(m, "WriteBuffer: length %zu", na);
    else if (m->mode == M_SLEEP)
      violate(m, "WriteBuffer in sleep");
    else if ((size_t)a[0] + (na - 1) > 256)
      violate(m, "WriteBuffer past the end of the buffer");
    else
      memcpy(m->buffer + a[0], a + 1, na - 1);
    break;
  case 0x1E: /* ReadBuffer: opcode, offset, NOP, data... */
    if (n < 4)
      violate(m, "ReadBuffer: length %zu", n);
    else if ((size_t)tx[1] + (n - 3) > 256)
      violate(m, "ReadBuffer past the end of the buffer");
    else
      memcpy(rx + 3, m->buffer + tx[1], n - 3);
    break;
  case 0x0D: /* WriteRegister */
    if (na < 3) {
      violate(m, "WriteRegister: length %zu", na);
    } else {
      unsigned addr = (unsigned)((a[0] << 8) | a[1]);
      for (i = 0; i < na - 2; i++) {
        if (addr + i >= sizeof(m->regs))
          violate(m, "WriteRegister: address 0x%x", addr + (unsigned)i);
        else
          m->regs[addr + i] = a[2 + i];
      }
    }
    break;
  case 0x1D: /* ReadRegister: opcode, addr hi, addr lo, NOP, data... */
    if (n < 5) {
      violate(m, "ReadRegister: length %zu", n);
    } else {
      unsigned addr = (unsigned)((tx[1] << 8) | tx[2]);
      for (i = 0; i < n - 4; i++)
        rx[4 + i] = addr + i < sizeof(m->regs) ? m->regs[addr + i] : 0;
    }
    break;
  case 0x9D: /* SetDIO2AsRfSwitchCtrl */
    need_len(m, "SetDIO2AsRfSwitchCtrl", na, 1);
    if (na == 1)
      m->dio2_rf = a[0];
    break;
  case 0x97: /* SetDIO3AsTCXOCtrl */
    need_len(m, "SetDIO3AsTCXOCtrl", na, 4);
    if (m->mode != M_RC)
      violate(m, "SetDIO3AsTCXOCtrl outside STDBY_RC");
    if (na == 4) {
      if (a[0] > 7)
        violate(m, "SetDIO3AsTCXOCtrl: voltage %u", a[0]);
      m->tcxo_ctrl_set = 1;
      m->tcxo_voltage = a[0];
      m->tcxo_delay = ((uint32_t)a[1] << 16) | ((uint32_t)a[2] << 8) | a[3];
    }
    break;
  case 0x96: /* SetRegulatorMode */
    need_len(m, "SetRegulatorMode", na, 1);
    if (m->mode != M_RC)
      violate(m, "SetRegulatorMode outside STDBY_RC");
    if (na == 1)
      m->regulator = a[0];
    break;
  case 0x89: /* Calibrate */
    need_len(m, "Calibrate", na, 1);
    if (m->mode != M_RC)
      violate(m, "Calibrate outside STDBY_RC");
    if (m->tcxo_present && !m->tcxo_ctrl_set)
      violate(m, "Calibrate before the TCXO was configured");
    if (na == 1) {
      m->calibration = a[0];
      set_busy(m, 3500);
    }
    break;
  case 0x98: /* CalibrateImage */
    need_len(m, "CalibrateImage", na, 2);
    if (m->mode != M_RC && m->mode != M_XOSC)
      violate(m, "CalibrateImage outside standby");
    if (na == 2) {
      m->image_cal[0] = a[0];
      m->image_cal[1] = a[1];
      set_busy(m, 1500);
    }
    break;
  case 0x93: /* SetRxTxFallbackMode */
    need_len(m, "SetRxTxFallbackMode", na, 1);
    if (na == 1) {
      if (a[0] != 0x20 && a[0] != 0x30 && a[0] != 0x40)
        violate(m, "SetRxTxFallbackMode: %02x", a[0]);
      m->fallback = a[0];
    }
    break;
  case 0x07: /* ClearDeviceErrors */
    need_len(m, "ClearDeviceErrors", na, 2);
    m->device_errors = 0;
    break;
  case 0x17: /* GetDeviceErrors */
    need_len(m, "GetDeviceErrors", n, 4);
    if (n == 4) {
      rx[2] = (uint8_t)(m->device_errors >> 8);
      rx[3] = (uint8_t)m->device_errors;
    }
    break;
  case 0xC0: /* GetStatus */
    need_len(m, "GetStatus", n, 2);
    break;
  case 0x9F:
  case 0xA0:
    need_len(m, "SetStopRxTimerOnPreamble/SetLoRaSymbNumTimeout", na, 1);
    break;
  default:
    violate(m, "unknown opcode 0x%02x", op);
  }
  if (op != 0x12 && op != 0x13 && op != 0x14 && op != 0x15 && op != 0x1E && op != 0x1D &&
      op != 0xC0 && op != 0x17 && op != 0x0D && op != 0x0E && op != 0x02 && op != 0x08 &&
      m->busy_until_us <= m->medium->now_us)
    set_busy(m, 80);
}

/* ---- HAL ---------------------------------------------------------------------------------- */
static int h_spi(void *ctx, const uint8_t *tx, uint8_t *rx, size_t n) {
  sx126x_model *m = ctx;
  uint8_t zero[300];
  if (n == 0 || n > 258) {
    violate(m, "SPI transfer of %zu bytes", n);
    return -1;
  }
  sync(m);
  if (m->absent) { /* nothing on the bus answers */
    if (rx)
      memset(rx, 0, n);
    return 0;
  }
  if (!tx) {
    memset(zero, 0, n);
    tx = zero;
  }
  if (busy(m)) {
    violate(m, "command 0x%02x while BUSY is high", tx[0]);
    return 0;
  }
  execute(m, tx, rx, n);
  sync(m);
  return 0;
}
static void h_write(void *ctx, rnc_radio_pin pin, int level) {
  sx126x_model *m = ctx;
  if (pin == RNC_PIN_RESET && level == 0) {
    /* hardware reset: back to STDBY_RC with defaults */
    unsigned variant = m->variant;
    int absent_flag = m->absent;
    int tcxo = m->tcxo_present, dio2 = m->dio2_switch;
    sim_medium *medium = m->medium;
    int id = m->id;
    rnc_radio_hal hal = m->hal;
    unsigned violations = m->violations, commands = m->commands, sent = m->frames_sent,
             recv = m->frames_received, crc = m->crc_errors, iqm = m->iq_misses,
             ant = m->antenna_misses, bw5 = m->bw500_degraded;
    char first[sizeof(m->first_violation)];
    memcpy(first, m->first_violation, sizeof(first));
    memset(m, 0, sizeof(*m));
    m->variant = variant;
    m->absent = absent_flag;
    m->tcxo_present = tcxo;
    m->dio2_switch = dio2;
    m->medium = medium;
    m->id = id;
    m->hal = hal;
    m->violations = violations;
    m->commands = commands;
    m->frames_sent = sent;
    m->frames_received = recv;
    m->crc_errors = crc;
    m->iq_misses = iqm;
    m->antenna_misses = ant;
    m->bw500_degraded = bw5;
    memcpy(m->first_violation, first, sizeof(first));
    m->mode = M_RC;
    m->packet_type = -1;
    m->fallback = 0x20;
    m->regs[0x0740] = 0x14;
    m->regs[0x0741] = 0x24;
    m->regs[0x0736] = 0x0D;
    m->regs[0x08AC] = 0x94;
    m->regs[0x08E7] = variant == 1262 ? 0x38 : 0x18;
    m->regs[0x0889] = 0x1B;
    m->regs[0x08D8] = 0xE0;
    set_busy(m, 3000);
  }
}
static int h_read(void *ctx, rnc_radio_pin pin) {
  sx126x_model *m = ctx;
  sync(m);
  if (pin == RNC_PIN_BUSY) {
    int b = busy(m);
    if (b)
      m->medium->now_us += 10; /* time passes while the caller spins on the line */
    return b;
  }
  if (pin == RNC_PIN_DIO)
    return (m->irq_status & m->irq_mask & m->dio1_mask) != 0;
  return -1;
}
static void h_delay(void *ctx, uint32_t us) {
  sx126x_model *m = ctx;
  m->medium->now_us += us;
}
static uint64_t h_now(void *ctx) { return ((sx126x_model *)ctx)->medium->now_us; }

void sx126x_model_init(sx126x_model *m, sim_medium *medium, unsigned variant, int tcxo_present,
                       int dio2_switch) {
  memset(m, 0, sizeof(*m));
  m->medium = medium;
  m->variant = variant;
  m->tcxo_present = tcxo_present;
  m->dio2_switch = dio2_switch;
  m->hal.context = m;
  m->hal.spi_transfer = h_spi;
  m->hal.gpio_write = h_write;
  m->hal.gpio_read = h_read;
  m->hal.delay_us = h_delay;
  m->hal.now_us = h_now;
  m->id = sim_medium_add(medium, m, &OPS);
  m->mode = M_RC;
  m->packet_type = -1;
  m->fallback = 0x20;
  m->regs[0x0740] = 0x14;
  m->regs[0x0741] = 0x24;
  m->regs[0x0736] = 0x0D;
  m->regs[0x08AC] = 0x94;
  m->regs[0x08E7] = variant == 1262 ? 0x38 : 0x18;
  m->regs[0x0889] = 0x1B;
  m->regs[0x08D8] = 0xE0;
}
