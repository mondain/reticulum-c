/* Software model of the SX1276/77/78/79 at register level; see sx127x_model.h. */
#include "sx127x_model.h"
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

enum {
  R_FIFO = 0x00, R_OPMODE = 0x01, R_FRF = 0x06, R_PACONFIG = 0x09, R_OCP = 0x0B, R_LNA = 0x0C,
  R_FIFOPTR = 0x0D, R_TXBASE = 0x0E, R_RXBASE = 0x0F, R_RXCUR = 0x10, R_IRQMASK = 0x11,
  R_IRQ = 0x12, R_RXNB = 0x13, R_MODEMSTAT = 0x18, R_PKTSNR = 0x19, R_PKTRSSI = 0x1A,
  R_RSSI = 0x1B, R_MC1 = 0x1D, R_MC2 = 0x1E, R_PRE_MSB = 0x20, R_PRE_LSB = 0x21,
  R_PLEN = 0x22, R_MAXPLEN = 0x23, R_MC3 = 0x26, R_DETOPT = 0x31, R_INVIQ = 0x33,
  R_HBW1 = 0x36, R_DETTHR = 0x37, R_SYNC = 0x39, R_HBW2 = 0x3A, R_INVIQ2 = 0x3B,
  R_DIOMAP1 = 0x40, R_VERSION = 0x42, R_PADAC = 0x4D
};
enum { F_CADDET = 0x01, F_CADDONE = 0x04, F_TXDONE = 0x08, F_VALIDHDR = 0x10, F_CRCERR = 0x20,
       F_RXDONE = 0x40 };

static void violate(sx127x_model *m, const char *fmt, ...) {
  va_list ap;
  m->violations++;
  if (m->violations == 1) {
    va_start(ap, fmt);
    vsnprintf(m->first_violation, sizeof(m->first_violation), fmt, ap);
    va_end(ap);
  }
}

static uint32_t bw_nominal(int code) {
  static const uint32_t t[10] = {7800, 10400, 15600, 20800, 31250, 41700, 62500, 125000, 250000, 500000};
  return code >= 0 && code <= 9 ? t[code] : 0;
}
double sx127x_model_freq_hz(const sx127x_model *m) {
  uint32_t frf = ((uint32_t)m->regs[R_FRF] << 16) | ((uint32_t)m->regs[R_FRF + 1] << 8) | m->regs[R_FRF + 2];
  return (double)frf * 32000000.0 / 524288.0;
}
static int is_lora(const sx127x_model *m) { return (m->regs[R_OPMODE] & 0x80) != 0; }

static void phy_of(const sx127x_model *m, sim_phy *p) {
  memset(p, 0, sizeof(*p));
  p->freq_hz = (uint32_t)(sx127x_model_freq_hz(m) + 0.5);
  p->bw_hz = bw_nominal(m->regs[R_MC1] >> 4);
  p->sf = (uint8_t)(m->regs[R_MC2] >> 4);
  p->cr = (uint8_t)(((m->regs[R_MC1] >> 1) & 7) + 4);
  p->ldro = (m->regs[R_MC3] >> 3) & 1;
  p->net = m->regs[R_SYNC] == 0x12 ? 0 : m->regs[R_SYNC] == 0x34 ? 1 : 2;
  /* RegPreamble + 4.25 symbols on air: what the medium needs is the whole count */
  p->preamble = (uint16_t)((((unsigned)m->regs[R_PRE_MSB] << 8) | m->regs[R_PRE_LSB]) + 4u);
  {
    uint8_t pc = m->regs[R_PACONFIG], dac = m->regs[R_PADAC];
    int dbm;
    if (pc & 0x80) { /* PA_BOOST */
      dbm = 2 + (pc & 0x0F);
      if (dac == 0x87)
        dbm += 3;
    } else {
      /* RFO: Pmax = 10.8 + 0.6 MaxPower, Pout = Pmax - (15 - OutputPower) */
      dbm = (int)floor(10.8 + 0.6 * ((pc >> 4) & 7) - (15 - (pc & 0x0F)) + 0.5);
    }
    p->txp_dbm = (int8_t)dbm;
  }
}

static double tsym_us(const sx127x_model *m) {
  sim_phy p;
  phy_of(m, &p);
  return pow(2.0, p.sf) / sim_bw_exact(p.bw_hz) * 1e6;
}

static void sync(sx127x_model *m) {
  uint64_t now = m->medium->now_us;
  if (m->mode == 3 && now >= m->tx_end_us) {
    m->regs[R_IRQ] |= F_TXDONE;
    m->mode = 1; /* LoRa returns to standby after a transmission */
    m->regs[R_OPMODE] = (uint8_t)((m->regs[R_OPMODE] & 0xF8) | 1);
    m->frames_sent++;
  }
  if (m->mode == 7 && now >= m->cad_end_us) {
    sim_phy p;
    uint64_t st;
    phy_of(m, &p);
    m->regs[R_IRQ] |= F_CADDONE;
    if (sim_sense(m->medium, m->id, &p, 0, &st))
      m->regs[R_IRQ] |= F_CADDET;
    m->mode = 1;
    m->regs[R_OPMODE] = (uint8_t)((m->regs[R_OPMODE] & 0xF8) | 1);
  }
}

/* ---- medium side ------------------------------------------------------------------------ */
static int rx_state(void *r, sim_phy *phy, uint64_t *since) {
  sx127x_model *m = r;
  sync(m);
  if (m->mode != 5 || !is_lora(m))
    return 0;
  if ((m->regs[R_MC1] >> 4) == 9) { /* errata of the 500 kHz bandwidth */
    double f = sx127x_model_freq_hz(m);
    int ok = (f >= 410e6 && f <= 525e6 && m->regs[R_HBW1] == 0x02 && m->regs[R_HBW2] == 0x7F) ||
             (f >= 820e6 && f <= 1020e6 && m->regs[R_HBW1] == 0x02 && m->regs[R_HBW2] == 0x64);
    if (!ok)
      m->bw500_degraded++;
  }
  phy_of(m, phy);
  *since = m->rx_since_us;
  return 1;
}
static void deliver(void *r, const uint8_t *frame, size_t len, int crc_ok, int rssi, int snr) {
  sx127x_model *m = r;
  int low = sx127x_model_freq_hz(m) < 525e6;
  memcpy(m->fifo + m->regs[R_RXBASE], frame, len);
  m->regs[R_RXCUR] = m->regs[R_RXBASE];
  m->regs[R_RXNB] = (uint8_t)len;
  m->regs[R_PKTSNR] = (uint8_t)(int8_t)snr;
  m->regs[R_PKTRSSI] = (uint8_t)(rssi - (low ? -164 : -157)); /* RegPktRssiValue + offset = dBm */
  m->regs[R_IRQ] |= F_RXDONE | F_VALIDHDR;
  if (!crc_ok) {
    m->regs[R_IRQ] |= F_CRCERR;
    m->crc_errors++;
  } else {
    m->frames_received++;
  }
}
static const sim_radio_ops OPS = {rx_state, deliver};

/* ---- register writes --------------------------------------------------------------------- */
static void set_opmode(sx127x_model *m, uint8_t v) {
  uint8_t old = m->regs[R_OPMODE];
  int new_mode = v & 7;
  sim_phy phy;
  if ((v & 0x80) != (old & 0x80) && m->mode != 0)
    violate(m, "LongRangeMode changed outside sleep");
  m->regs[R_OPMODE] = v;
  if (!(v & 0x80)) { /* FSK/OOK: not modelled */
    m->mode = new_mode;
    return;
  }
  if (new_mode == 3 || new_mode == 5 || new_mode == 7) {
    unsigned sf = m->regs[R_MC2] >> 4;
    if (sf < 6 || sf > 12)
      violate(m, "spreading factor %u out of range", sf);
    if (sf == 6 && !(m->regs[R_MC1] & 1))
      violate(m, "SF6 needs implicit header mode");
    if (sf == 6 && m->regs[R_DETOPT] % 8 != 5)
      violate(m, "SF6 needs detection optimise 0x05");
    if (sf != 6 && m->regs[R_DETOPT] % 8 != 3)
      violate(m, "SF7..12 need detection optimise 0x03");
  }
  phy_of(m, &phy);
  if (new_mode == 3) {
    double toa;
    uint8_t pc = m->regs[R_PACONFIG], dac = m->regs[R_PADAC];
    if (m->mode != 1 && m->mode != 3)
      violate(m, "transmit entered from mode %d", m->mode);
    if (m->regs[R_PLEN] == 0 && !(m->regs[R_MC1] & 1))
      violate(m, "transmit with payload length 0");
    if (dac != 0x84 && dac != 0x87)
      violate(m, "PA DAC value 0x%02x", dac);
    if (dac == 0x87 && !(pc & 0x80))
      violate(m, "PA DAC +20 dBm mode without PA_BOOST");
    if (dac == 0x87 && (pc & 0x0F) != 0x0F && 0)
      violate(m, "unused");
    toa = sim_toa_us(phy.bw_hz, phy.sf, phy.cr, phy.preamble, m->regs[R_PLEN], phy.ldro);
    m->tx_end_us = m->medium->now_us + (uint64_t)toa;
    sim_medium_tx(m->medium, m->id, m->fifo + m->regs[R_TXBASE], m->regs[R_PLEN], &phy, (uint64_t)toa);
    m->mode = 3;
  } else if (new_mode == 5) {
    m->mode = 5;
    m->rx_since_us = m->medium->now_us;
  } else if (new_mode == 7) {
    m->mode = 7;
    m->cad_end_us = m->medium->now_us + (uint64_t)(2.0 * tsym_us(m) + 1000.0);
  } else {
    m->mode = new_mode;
  }
  if (m->mode == 0 || m->mode == 1)
    m->mode = new_mode;
}

static void write_reg(sx127x_model *m, uint8_t reg, uint8_t v) {
  m->writes++;
  switch (reg) {
  case R_OPMODE:
    set_opmode(m, v);
    return;
  case R_IRQ:
    m->regs[R_IRQ] &= (uint8_t)~v; /* writing a one clears the flag */
    return;
  case R_VERSION:
  case R_RXNB:
  case R_RXCUR:
  case R_MODEMSTAT:
  case R_PKTSNR:
  case R_PKTRSSI:
  case R_RSSI:
    violate(m, "write to read-only register 0x%02x", reg);
    return;
  case R_MC1: case R_MC2: case R_MC3: case R_PRE_MSB: case R_PRE_LSB: case R_SYNC:
  case R_DETOPT: case R_DETTHR: case R_FRF: case R_FRF + 1: case R_FRF + 2:
    if (m->mode == 3 || m->mode == 5 || m->mode == 7)
      violate(m, "register 0x%02x written while transmitting or receiving", reg);
    break;
  case R_PACONFIG:
    break;
  case R_PADAC:
    if (v != 0x84 && v != 0x87)
      violate(m, "RegPaDac 0x%02x is not a documented value", v);
    break;
  case R_FIFOPTR:
  case R_TXBASE:
  case R_RXBASE:
  case R_PLEN:
  case R_MAXPLEN:
  case R_LNA:
  case R_OCP:
  case R_INVIQ:
  case R_INVIQ2:
  case R_HBW1:
  case R_HBW2:
  case R_DIOMAP1:
  case R_IRQMASK:
    break;
  default:
    if (reg >= 0x80)
      violate(m, "write to register 0x%02x", reg);
  }
  m->regs[reg] = v;
}

static int spi(void *ctx, const uint8_t *tx, uint8_t *rx, size_t n) {
  sx127x_model *m = ctx;
  uint8_t reg, i;
  int write;
  if (n < 2 || n > 257) {
    violate(m, "SPI transfer of %zu bytes", n);
    return -1;
  }
  sync(m);
  reg = tx[0] & 0x7F;
  write = (tx[0] & 0x80) != 0;
  if (rx)
    memset(rx, 0, n);
  if (reg == R_FIFO) {
    for (i = 0; i < n - 1; i++) {
      uint8_t p = m->regs[R_FIFOPTR];
      if (write) {
        if (m->mode != 1)
          violate(m, "FIFO written outside standby (mode %d)", m->mode);
        m->fifo[p] = tx[1 + i];
      } else if (rx) {
        if (m->mode == 0)
          violate(m, "FIFO read in sleep");
        rx[1 + i] = m->fifo[p];
      }
      m->regs[R_FIFOPTR] = (uint8_t)(p + 1);
    }
    return 0;
  }
  if (n != 2) {
    violate(m, "multi-byte access to register 0x%02x", reg);
    return 0;
  }
  if (write) {
    write_reg(m, reg, tx[1]);
  } else {
    m->reads++;
    if (reg == R_MODEMSTAT) {
      sim_phy p;
      uint64_t st;
      uint8_t v = 0x10;
      phy_of(m, &p);
      if (m->mode == 5 && sim_sense(m->medium, m->id, &p, (uint64_t)(4.0 * tsym_us(m)), &st))
        v = 0x01 | 0x02 | 0x04;
      m->regs[R_MODEMSTAT] = v;
    } else if (reg == R_RSSI) {
      sim_phy p;
      phy_of(m, &p);
      m->regs[R_RSSI] = (uint8_t)(sim_rssi(m->medium, m->id, &p) - (sx127x_model_freq_hz(m) < 525e6 ? -164 : -157));
    }
    if (rx)
      rx[1] = m->regs[reg];
  }
  return 0;
}
static void h_write(void *ctx, rnc_radio_pin pin, int level) {
  sx127x_model *m = ctx;
  if (pin == RNC_PIN_RESET && level == 0) {
    unsigned v = m->violations, fs = m->frames_sent, fr = m->frames_received, ce = m->crc_errors,
             bd = m->bw500_degraded, w = m->writes, r = m->reads;
    char first[sizeof(m->first_violation)];
    sim_medium *med = m->medium;
    int id = m->id, d0 = m->has_dio0;
    rnc_radio_hal hal = m->hal;
    memcpy(first, m->first_violation, sizeof(first));
    memset(m, 0, sizeof(*m));
    m->medium = med; m->id = id; m->has_dio0 = d0; m->hal = hal;
    m->violations = v; m->frames_sent = fs; m->frames_received = fr; m->crc_errors = ce;
    m->bw500_degraded = bd; m->writes = w; m->reads = r;
    memcpy(m->first_violation, first, sizeof(first));
    m->regs[R_OPMODE] = 0x09; /* FSK/OOK, LF mode, standby... reset value is sleep-ish */
    m->regs[R_OPMODE] = 0x01;
    m->mode = 1;
    m->regs[R_VERSION] = 0x12;
    m->regs[R_SYNC] = 0x12;
    m->regs[R_PACONFIG] = 0x4F;
    m->regs[R_PADAC] = 0x84;
    m->regs[R_OCP] = 0x2B;
    m->regs[R_LNA] = 0x20;
    m->regs[R_MC1] = 0x72;
    m->regs[R_MC2] = 0x70;
    m->regs[R_DETOPT] = 0xC3;
    m->regs[R_DETTHR] = 0x0A;
    m->regs[R_INVIQ] = 0x27;
    m->regs[R_INVIQ2] = 0x1D;
    m->regs[R_HBW1] = 0x03;
    m->regs[R_PRE_LSB] = 0x08;
    m->regs[R_FRF] = 0x6C; m->regs[R_FRF + 1] = 0x80;
    /* the FSK-mode reset value is not LoRa: a driver that does not enter sleep first
     * and then set LongRangeMode is caught by the opmode rule */
    m->mode = 1;
  }
}
static int h_read(void *ctx, rnc_radio_pin pin) {
  sx127x_model *m = ctx;
  sync(m);
  if (pin == RNC_PIN_DIO && m->has_dio0) {
    int map = m->regs[R_DIOMAP1] >> 6;
    uint8_t f = m->regs[R_IRQ];
    if (map == 0)
      return (f & F_RXDONE) != 0;
    if (map == 1)
      return (f & F_TXDONE) != 0;
    if (map == 2)
      return (f & F_CADDONE) != 0;
    return 0;
  }
  return -1;
}
static void h_delay(void *ctx, uint32_t us) { ((sx127x_model *)ctx)->medium->now_us += us; }
static uint64_t h_now(void *ctx) { return ((sx127x_model *)ctx)->medium->now_us; }

void sx127x_model_init(sx127x_model *m, sim_medium *medium, int has_dio0) {
  memset(m, 0, sizeof(*m));
  m->medium = medium;
  m->has_dio0 = has_dio0;
  m->hal.context = m;
  m->hal.spi_transfer = spi;
  m->hal.gpio_write = h_write;
  m->hal.gpio_read = h_read;
  m->hal.delay_us = h_delay;
  m->hal.now_us = h_now;
  m->id = sim_medium_add(medium, m, &OPS);
  m->regs[R_OPMODE] = 0x01;
  m->mode = 1;
  m->regs[R_VERSION] = 0x12;
  m->regs[R_SYNC] = 0x12;
  m->regs[R_PACONFIG] = 0x4F;
  m->regs[R_PADAC] = 0x84;
  m->regs[R_OCP] = 0x2B;
  m->regs[R_LNA] = 0x20;
  m->regs[R_MC1] = 0x72;
  m->regs[R_MC2] = 0x70;
  m->regs[R_DETOPT] = 0xC3;
  m->regs[R_DETTHR] = 0x0A;
  m->regs[R_INVIQ] = 0x27;
  m->regs[R_INVIQ2] = 0x1D;
  m->regs[R_HBW1] = 0x03;
  m->regs[R_PRE_LSB] = 0x08;
}
