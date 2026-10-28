/* SX1261/SX1262/SX1268 driver; see rnc_sx126x.h. Written from the public datasheet. */
#include "rnc_sx126x.h"
#include <string.h>

/* command opcodes */
#define OP_SET_SLEEP 0x84u
#define OP_SET_STANDBY 0x80u
#define OP_SET_TX 0x83u
#define OP_SET_RX 0x82u
#define OP_SET_CAD 0xC5u
#define OP_SET_PACKET_TYPE 0x8Au
#define OP_SET_RF_FREQUENCY 0x86u
#define OP_SET_PA_CONFIG 0x95u
#define OP_SET_TX_PARAMS 0x8Eu
#define OP_SET_BUFFER_BASE 0x8Fu
#define OP_SET_MODULATION 0x8Bu
#define OP_SET_PACKET_PARAMS 0x8Cu
#define OP_SET_CAD_PARAMS 0x88u
#define OP_SET_DIO_IRQ 0x08u
#define OP_GET_IRQ 0x12u
#define OP_CLEAR_IRQ 0x02u
#define OP_GET_RX_BUFFER 0x13u
#define OP_GET_PACKET_STATUS 0x14u
#define OP_GET_RSSI_INST 0x15u
#define OP_WRITE_BUFFER 0x0Eu
#define OP_READ_BUFFER 0x1Eu
#define OP_WRITE_REGISTER 0x0Du
#define OP_READ_REGISTER 0x1Du
#define OP_SET_DIO2_RF_SWITCH 0x9Du
#define OP_SET_DIO3_TCXO 0x97u
#define OP_SET_REGULATOR 0x96u
#define OP_CALIBRATE 0x89u
#define OP_CALIBRATE_IMAGE 0x98u
#define OP_SET_FALLBACK 0x93u
#define OP_GET_STATUS 0xC0u
#define OP_CLEAR_DEVICE_ERRORS 0x07u
#define OP_GET_DEVICE_ERRORS 0x17u

/* registers */
#define REG_IQ_POLARITY 0x0736u
#define REG_SYNC_WORD 0x0740u
#define REG_RX_GAIN 0x08ACu
#define REG_TX_CLAMP 0x08D8u
#define REG_OCP 0x08E7u
#define REG_BW500_FIX 0x0889u

/* IRQ bits */
#define IRQ_TX_DONE 0x0001u
#define IRQ_RX_DONE 0x0002u
#define IRQ_PREAMBLE 0x0004u
#define IRQ_SYNC_VALID 0x0008u
#define IRQ_HEADER_VALID 0x0010u
#define IRQ_HEADER_ERR 0x0020u
#define IRQ_CRC_ERR 0x0040u
#define IRQ_CAD_DONE 0x0080u
#define IRQ_CAD_DETECTED 0x0100u
#define IRQ_TIMEOUT 0x0200u
#define IRQ_ALL 0x03FFu

#define MODE_UNCONFIGURED 0
#define MODE_STANDBY 1
#define MODE_RX 2
#define MODE_TX 3
#define MODE_CAD 4

#define BUSY_TIMEOUT_US 150000u

/* ---- pure helpers -------------------------------------------------------------- */
uint32_t rnc_sx126x_frf(uint32_t freq_hz) {
  /* freq * 2^25 / 32e6, truncated (the register value the datasheet's formula gives) */
  return (uint32_t)(((uint64_t)freq_hz << 25) / UINT64_C(32000000));
}

int rnc_sx126x_bw_code(uint32_t bw_hz) {
  switch (bw_hz) {
  case 7800u: return 0x00;
  case 10400u: return 0x08;
  case 15600u: return 0x01;
  case 20800u: return 0x09;
  case 31250u: return 0x02;
  case 41700u: return 0x0A;
  case 62500u: return 0x03;
  case 125000u: return 0x04;
  case 250000u: return 0x05;
  case 500000u: return 0x06;
  default: return -1;
  }
}

int rnc_sx126x_pa(unsigned chip, int dbm, uint8_t pa[4], int8_t *tx_power) {
  if (chip == 1261u) {
    if (dbm < -17 || dbm > 15)
      return -1;
    pa[2] = 1; /* deviceSel: SX1261 */
    pa[3] = 1;
    if (dbm >= 15) { /* +15 dBm: duty cycle 6, TxParams power 14 */
      pa[0] = 6; pa[1] = 0; *tx_power = 14;
    } else if (dbm >= 11) { /* +14 dBm setting */
      pa[0] = 4; pa[1] = 0; *tx_power = (int8_t)dbm;
    } else { /* +10 dBm setting */
      pa[0] = 1; pa[1] = 0; *tx_power = (int8_t)dbm;
    }
    return 0;
  }
  if (dbm < -9 || dbm > 22)
    return -1;
  pa[2] = 0; /* deviceSel: SX1262 */
  pa[3] = 1;
  if (dbm >= 21) { pa[0] = 4; pa[1] = 7; }       /* optimal for +22 dBm */
  else if (dbm >= 18) { pa[0] = 3; pa[1] = 5; }  /* +20 dBm */
  else if (dbm >= 15) { pa[0] = 2; pa[1] = 3; }  /* +17 dBm */
  else { pa[0] = 2; pa[1] = 2; }                 /* +14 dBm */
  *tx_power = (int8_t)dbm;
  return 0;
}

int rnc_sx126x_image_band(uint32_t f, uint8_t out[2]) {
  if (f >= 430000000u && f <= 440000000u) { out[0] = 0x6B; out[1] = 0x6F; }
  else if (f >= 470000000u && f <= 510000000u) { out[0] = 0x75; out[1] = 0x81; }
  else if (f >= 779000000u && f <= 787000000u) { out[0] = 0xC1; out[1] = 0xC5; }
  else if (f >= 863000000u && f <= 870000000u) { out[0] = 0xD7; out[1] = 0xDB; }
  else if (f >= 902000000u && f <= 928000000u) { out[0] = 0xE1; out[1] = 0xE9; }
  else
    return -1;
  return 0;
}

/* ---- SPI plumbing ---------------------------------------------------------------- */
static int busy_high(rnc_sx126x *d) {
  int level = d->hal->gpio_read ? d->hal->gpio_read(d->hal->context, RNC_PIN_BUSY) : -1;
  return level > 0;
}
static int wait_idle(rnc_sx126x *d) {
  uint64_t start = d->hal->now_us(d->hal->context);
  if (!d->hal->gpio_read || d->hal->gpio_read(d->hal->context, RNC_PIN_BUSY) < 0) {
    d->hal->delay_us(d->hal->context, 2000u); /* no BUSY line: give the chip time */
    return 0;
  }
  while (busy_high(d)) {
    if (d->hal->now_us(d->hal->context) - start > BUSY_TIMEOUT_US) {
      d->busy_timeouts++;
      return -1;
    }
  }
  return 0;
}
static int xfer(rnc_sx126x *d, const uint8_t *tx, uint8_t *rx, size_t n) {
  if (wait_idle(d) != 0)
    return -1;
  return d->hal->spi_transfer(d->hal->context, tx, rx, n);
}
static int cmd(rnc_sx126x *d, uint8_t op, const uint8_t *args, size_t n) {
  uint8_t buf[16];
  if (n + 1u > sizeof(buf))
    return -1;
  buf[0] = op;
  if (n)
    memcpy(buf + 1, args, n);
  return xfer(d, buf, NULL, n + 1u);
}
static int cmd_read(rnc_sx126x *d, uint8_t op, uint8_t *out, size_t n) {
  uint8_t tx[8], rx[8];
  if (n + 2u > sizeof(tx))
    return -1;
  memset(tx, 0, sizeof(tx));
  tx[0] = op;
  if (xfer(d, tx, rx, n + 2u) != 0)
    return -1;
  memcpy(out, rx + 2, n); /* rx[1] is the status byte */
  return 0;
}
static int write_reg(rnc_sx126x *d, uint16_t addr, uint8_t value) {
  uint8_t b[4] = {OP_WRITE_REGISTER, (uint8_t)(addr >> 8), (uint8_t)addr, value};
  return xfer(d, b, NULL, sizeof(b));
}
static int read_reg(rnc_sx126x *d, uint16_t addr, uint8_t *value) {
  uint8_t tx[5] = {OP_READ_REGISTER, (uint8_t)(addr >> 8), (uint8_t)addr, 0, 0}, rx[5];
  if (xfer(d, tx, rx, sizeof(tx)) != 0)
    return -1;
  *value = rx[4];
  return 0;
}
static int get_irq(rnc_sx126x *d, uint16_t *irq) {
  uint8_t b[2];
  if (cmd_read(d, OP_GET_IRQ, b, 2) != 0)
    return -1;
  *irq = (uint16_t)((b[0] << 8) | b[1]);
  return 0;
}
static int clear_irq(rnc_sx126x *d, uint16_t mask) {
  uint8_t b[2] = {(uint8_t)(mask >> 8), (uint8_t)mask};
  return cmd(d, OP_CLEAR_IRQ, b, 2);
}
static int standby(rnc_sx126x *d, uint8_t xosc) {
  return cmd(d, OP_SET_STANDBY, &xosc, 1);
}

/* SetPacketParams, followed by the IQ polarity fix of the datasheet (errata: the
 * command leaves bit 2 of register 0x0736 wrong; for standard IQ it must be set). */
static int packet_params(rnc_sx126x *d, unsigned payload_len) {
  uint8_t b[9], iq;
  unsigned pre = d->params.preamble_symbols;
  b[0] = (uint8_t)(pre >> 8);
  b[1] = (uint8_t)pre;
  b[2] = 0;                  /* explicit header */
  b[3] = (uint8_t)payload_len;
  b[4] = 1;                  /* CRC on */
  b[5] = 0;                  /* standard IQ */
  b[6] = b[7] = b[8] = 0;
  if (cmd(d, OP_SET_PACKET_PARAMS, b, 6) != 0)
    return -1;
  if (read_reg(d, REG_IQ_POLARITY, &iq) != 0)
    return -1;
  return write_reg(d, REG_IQ_POLARITY, (uint8_t)(iq | 0x04u));
}

static int modulation_params(rnc_sx126x *d) {
  uint8_t b[4];
  int bw = rnc_sx126x_bw_code(d->params.bw_hz);
  uint8_t reg;
  if (bw < 0)
    return -1;
  b[0] = d->params.sf;
  b[1] = (uint8_t)bw;
  b[2] = (uint8_t)(d->params.cr - 4u);
  b[3] = (uint8_t)rnc_lora_ldro(d->params.bw_hz, d->params.sf);
  if (cmd(d, OP_SET_MODULATION, b, 4) != 0)
    return -1;
  /* datasheet errata: modulation quality at 500 kHz needs bit 2 of 0x0889 cleared, set
   * for the other bandwidths */
  if (read_reg(d, REG_BW500_FIX, &reg) != 0)
    return -1;
  reg = d->params.bw_hz == 500000u ? (uint8_t)(reg & 0xFBu) : (uint8_t)(reg | 0x04u);
  return write_reg(d, REG_BW500_FIX, reg);
}

/* ---- modem operations ------------------------------------------------------------ */
static int sx_init(rnc_modem *m, const rnc_lora_params *p) {
  rnc_sx126x *d = (rnc_sx126x *)m;
  uint8_t b[4], pa[4], img[2], sw_hi = 0, sw_lo = 0;
  int8_t txp;
  uint32_t frf;
  if (rnc_lora_params_check(p, 5u) != 0 || rnc_sx126x_image_band(p->freq_hz, img) != 0 ||
      p->freq_hz < 150000000u || p->freq_hz > 960000000u)
    return -2;
  if (rnc_sx126x_pa(d->board.chip, p->txp_dbm, pa, &txp) != 0)
    return -3;
  d->params = *p;
  if (!d->params.preamble_symbols)
    d->params.preamble_symbols = (uint16_t)rnc_lora_default_preamble(p->bw_hz, p->sf, p->cr);
  d->symbol_us = rnc_lora_symbol_us(p->bw_hz, p->sf);
  d->mode = MODE_UNCONFIGURED;
  d->carrier_until_us = 0;

  /* reset pulse (at least 100 us low), then the chip needs time to start */
  d->hal->gpio_write(d->hal->context, RNC_PIN_RESET, 0);
  d->hal->delay_us(d->hal->context, 2000u);
  d->hal->gpio_write(d->hal->context, RNC_PIN_RESET, 1);
  d->hal->delay_us(d->hal->context, 10000u);
  d->hal->gpio_write(d->hal->context, RNC_PIN_RXEN, 1);
  d->hal->gpio_write(d->hal->context, RNC_PIN_TXEN, 0);

  if (standby(d, 0) != 0)
    return -4;
  /* presence: the sync word registers hold 0x1424 (private) after a reset, 0x3444 public */
  if (read_reg(d, REG_SYNC_WORD, &sw_hi) != 0 || read_reg(d, REG_SYNC_WORD + 1u, &sw_lo) != 0)
    return -4;
  if (!((sw_hi == 0x14 && sw_lo == 0x24) || (sw_hi == 0x34 && sw_lo == 0x44)))
    return -5;
  if (d->board.dcdc) {
    b[0] = 1;
    if (cmd(d, OP_SET_REGULATOR, b, 1) != 0)
      return -4;
  }
  if (d->board.tcxo_code) {
    uint32_t delay = (uint32_t)(((uint64_t)(d->board.tcxo_start_us ? d->board.tcxo_start_us
                                                                     : 5000u) * 1000u) /
                                15625u);
    b[0] = (uint8_t)(d->board.tcxo_code - 1u);
    b[1] = (uint8_t)(delay >> 16);
    b[2] = (uint8_t)(delay >> 8);
    b[3] = (uint8_t)delay;
    if (cmd(d, OP_SET_DIO3_TCXO, b, 4) != 0)
      return -4;
  }
  b[0] = 0x7F; /* RC64k, RC13M, PLL, ADC pulse, ADC bulk N and P, image */
  if (cmd(d, OP_CALIBRATE, b, 1) != 0)
    return -4;
  d->hal->delay_us(d->hal->context, 5000u);
  b[0] = b[1] = 0; /* the TCXO start may have flagged an oscillator error */
  if (cmd(d, OP_CLEAR_DEVICE_ERRORS, b, 2) != 0)
    return -4;

  b[0] = 1; /* LoRa */
  if (cmd(d, OP_SET_PACKET_TYPE, b, 1) != 0 || standby(d, 1) != 0)
    return -4;
  {
    uint8_t err[2];
    /* the oscillator must be running now; a TCXO that did not start (wrong voltage setting, a
     * board without one configured as if it had one) shows as an XOSC start error */
    if (cmd_read(d, OP_GET_DEVICE_ERRORS, err, 2) != 0)
      return -4;
    if (err[1] & 0x20u)
      return -6;
  }
  if (d->board.dio2_rf_switch) {
    b[0] = 1;
    if (cmd(d, OP_SET_DIO2_RF_SWITCH, b, 1) != 0)
      return -4;
  }
  if (cmd(d, OP_CALIBRATE_IMAGE, img, 2) != 0)
    return -4;
  frf = rnc_sx126x_frf(p->freq_hz);
  b[0] = (uint8_t)(frf >> 24);
  b[1] = (uint8_t)(frf >> 16);
  b[2] = (uint8_t)(frf >> 8);
  b[3] = (uint8_t)frf;
  if (cmd(d, OP_SET_RF_FREQUENCY, b, 4) != 0)
    return -4;
  if (cmd(d, OP_SET_PA_CONFIG, pa, 4) != 0)
    return -4;
  b[0] = (uint8_t)txp;
  b[1] = 0x02; /* ramp time 40 us */
  if (cmd(d, OP_SET_TX_PARAMS, b, 2) != 0)
    return -4;
  if (d->board.chip != 1261u) {
    uint8_t clamp;
    /* datasheet: better resistance of the SX1262 transmitter to antenna mismatch */
    if (read_reg(d, REG_TX_CLAMP, &clamp) != 0 ||
        write_reg(d, REG_TX_CLAMP, (uint8_t)(clamp | 0x1Eu)) != 0)
      return -4;
  }
  if (d->board.ocp && write_reg(d, REG_OCP, d->board.ocp) != 0) /* after SetPaConfig */
    return -4;
  b[0] = b[1] = 0; /* TX and RX buffer base addresses */
  if (cmd(d, OP_SET_BUFFER_BASE, b, 2) != 0 || modulation_params(d) != 0 ||
      packet_params(d, 255u) != 0)
    return -4;
  /* private network sync word 0x1424 (the LoRa sync word 0x12 of the SX127x) */
  if (write_reg(d, REG_SYNC_WORD, 0x14) != 0 || write_reg(d, REG_SYNC_WORD + 1u, 0x24) != 0)
    return -4;
  if (write_reg(d, REG_RX_GAIN, 0x96) != 0) /* boosted receiver gain */
    return -4;
  {
    uint8_t irq[8] = {(uint8_t)(IRQ_ALL >> 8), (uint8_t)IRQ_ALL, (uint8_t)(IRQ_ALL >> 8),
                      (uint8_t)IRQ_ALL, 0, 0, 0, 0}; /* all events to IRQ status and DIO1 */
    if (cmd(d, OP_SET_DIO_IRQ, irq, 8) != 0)
      return -4;
  }
  b[0] = 0x30; /* after TX or RX: STDBY_XOSC */
  if (cmd(d, OP_SET_FALLBACK, b, 1) != 0)
    return -4;
  if (clear_irq(d, IRQ_ALL) != 0)
    return -4;
  d->mode = MODE_STANDBY;
  return 0;
}

static int sx_start_rx(rnc_modem *m) {
  rnc_sx126x *d = (rnc_sx126x *)m;
  uint8_t b[3] = {0xFF, 0xFF, 0xFF}; /* continuous */
  if (d->mode == MODE_UNCONFIGURED)
    return -1;
  d->hal->gpio_write(d->hal->context, RNC_PIN_TXEN, 0);
  if (clear_irq(d, IRQ_ALL) != 0 || packet_params(d, 255u) != 0 || cmd(d, OP_SET_RX, b, 3) != 0)
    return -1;
  d->mode = MODE_RX;
  d->carrier_until_us = 0;
  return 0;
}

static void carrier_update(rnc_sx126x *d, uint16_t irq, uint64_t now);

static int sx_poll_rx(rnc_modem *m, uint8_t *buf, size_t capacity, rnc_modem_rx_info *info) {
  rnc_sx126x *d = (rnc_sx126x *)m;
  uint16_t irq;
  uint8_t st[3], rb[2], tx[3 + RNC_MODEM_FRAME_MAX], rx[3 + RNC_MODEM_FRAME_MAX];
  uint64_t now;
  int result = 0;
  if (d->mode != MODE_RX)
    return 0;
  if (d->hal->gpio_read && d->hal->gpio_read(d->hal->context, RNC_PIN_DIO) == 0)
    return 0; /* nothing pending: every enabled event drives DIO1 */
  if (get_irq(d, &irq) != 0 || !irq)
    return 0;
  now = d->hal->now_us(d->hal->context);
  carrier_update(d, irq, now);
  if (irq & IRQ_RX_DONE) {
    if (irq & IRQ_CRC_ERR) {
      result = -1;
    } else if (cmd_read(d, OP_GET_RX_BUFFER, rb, 2) == 0 && rb[0] >= 1u && rb[0] <= capacity) {
      memset(tx, 0, sizeof(tx));
      tx[0] = OP_READ_BUFFER;
      tx[1] = rb[1];
      if (xfer(d, tx, rx, (size_t)rb[0] + 3u) == 0) {
        memcpy(buf, rx + 3, rb[0]);
        result = rb[0];
        if (info && cmd_read(d, OP_GET_PACKET_STATUS, st, 3) == 0) {
          info->rssi_dbm = (int16_t)(-(int)st[0] / 2);
          info->snr_quarter_db = (int16_t)(int8_t)st[1];
        } else if (info) {
          info->rssi_dbm = 0;
          info->snr_quarter_db = 0;
        }
      }
    } else {
      result = -1;
    }
  }
  (void)clear_irq(d, irq);
  return result;
}

static int sx_start_tx(rnc_modem *m, const uint8_t *frame, size_t size) {
  rnc_sx126x *d = (rnc_sx126x *)m;
  uint8_t buf[2 + RNC_MODEM_FRAME_MAX];
  uint8_t none[3] = {0, 0, 0};
  if (d->mode == MODE_UNCONFIGURED || size < 1u || size > RNC_MODEM_FRAME_MAX)
    return -1;
  if (standby(d, 1) != 0)
    return -1;
  buf[0] = OP_WRITE_BUFFER;
  buf[1] = 0;
  memcpy(buf + 2, frame, size);
  if (clear_irq(d, IRQ_ALL) != 0 || xfer(d, buf, NULL, size + 2u) != 0 ||
      packet_params(d, (unsigned)size) != 0)
    return -1;
  d->hal->gpio_write(d->hal->context, RNC_PIN_TXEN, 1);
  if (cmd(d, OP_SET_TX, none, 3) != 0) /* no chip timeout; the driver times it */
    return -1;
  d->tx_deadline_us = d->hal->now_us(d->hal->context) + rnc_lora_toa_us(&d->params, size) +
                      500000u;
  d->mode = MODE_TX;
  d->carrier_until_us = 0;
  return 0;
}

static int sx_poll_tx(rnc_modem *m) {
  rnc_sx126x *d = (rnc_sx126x *)m;
  uint16_t irq;
  if (d->mode != MODE_TX)
    return 1;
  if (get_irq(d, &irq) == 0 && (irq & IRQ_TX_DONE)) {
    (void)clear_irq(d, IRQ_ALL);
    d->hal->gpio_write(d->hal->context, RNC_PIN_TXEN, 0);
    d->mode = MODE_STANDBY;
    return 1;
  }
  if (d->hal->now_us(d->hal->context) > d->tx_deadline_us) {
    (void)standby(d, 1);
    (void)clear_irq(d, IRQ_ALL);
    d->hal->gpio_write(d->hal->context, RNC_PIN_TXEN, 0);
    d->mode = MODE_STANDBY;
    return -1;
  }
  return 0;
}

/* carrier detection from the IRQ flags (read, not cleared: poll_rx owns them) */
static void carrier_update(rnc_sx126x *d, uint16_t irq, uint64_t now) {
  if (irq & (IRQ_PREAMBLE | IRQ_HEADER_VALID | IRQ_SYNC_VALID))
    d->carrier_until_us = now + (uint64_t)(d->params.preamble_symbols + 40u) * d->symbol_us;
  if (irq & IRQ_HEADER_VALID)
    d->carrier_until_us = now + rnc_lora_toa_us(&d->params, 255u);
  if (irq & (IRQ_RX_DONE | IRQ_HEADER_ERR | IRQ_CRC_ERR | IRQ_TIMEOUT))
    d->carrier_until_us = 0;
}

static int sx_carrier(rnc_modem *m) {
  rnc_sx126x *d = (rnc_sx126x *)m;
  uint16_t irq;
  if (d->mode != MODE_RX)
    return 0;
  if ((!d->hal->gpio_read || d->hal->gpio_read(d->hal->context, RNC_PIN_DIO) != 0) &&
      get_irq(d, &irq) == 0 && irq)
    carrier_update(d, irq, d->hal->now_us(d->hal->context));
  return d->carrier_until_us && d->hal->now_us(d->hal->context) < d->carrier_until_us;
}

static int sx_rssi(rnc_modem *m, int *dbm) {
  rnc_sx126x *d = (rnc_sx126x *)m;
  uint8_t v;
  if (d->mode != MODE_RX || cmd_read(d, OP_GET_RSSI_INST, &v, 1) != 0)
    return -1;
  *dbm = -(int)v / 2;
  return 0;
}

static int sx_start_cad(rnc_modem *m) {
  rnc_sx126x *d = (rnc_sx126x *)m;
  uint8_t b[7];
  unsigned sf = d->params.sf;
  if (d->mode == MODE_UNCONFIGURED || d->mode == MODE_TX)
    return -1;
  /* CAD parameters: symbols to scan, detection peak and minimum, exit to standby, no
   * timeout. Values commonly used for 125 kHz and the common spreading factors. */
  b[0] = sf <= 8u ? 1u : 2u;                     /* CAD_ON_2_SYMB / CAD_ON_4_SYMB */
  b[1] = sf <= 8u ? 22u : sf == 9u ? 23u : sf == 10u ? 24u : sf == 11u ? 25u : 28u;
  b[2] = 10u;
  b[3] = 0; /* CAD_ONLY */
  b[4] = b[5] = b[6] = 0;
  if (standby(d, 1) != 0 || clear_irq(d, IRQ_ALL) != 0 || cmd(d, OP_SET_CAD_PARAMS, b, 7) != 0 ||
      cmd(d, OP_SET_CAD, NULL, 0) != 0)
    return -1;
  d->mode = MODE_CAD;
  return 0;
}

static int sx_poll_cad(rnc_modem *m) {
  rnc_sx126x *d = (rnc_sx126x *)m;
  uint16_t irq;
  if (d->mode != MODE_CAD)
    return 1;
  if (get_irq(d, &irq) != 0 || !(irq & IRQ_CAD_DONE))
    return 0;
  (void)clear_irq(d, IRQ_ALL);
  d->mode = MODE_STANDBY;
  return (irq & IRQ_CAD_DETECTED) ? 2 : 1;
}

static void sx_standby(rnc_modem *m) {
  rnc_sx126x *d = (rnc_sx126x *)m;
  if (d->mode != MODE_UNCONFIGURED) {
    (void)standby(d, 1);
    d->mode = MODE_STANDBY;
  }
}

static void sx_sleep(rnc_modem *m) {
  rnc_sx126x *d = (rnc_sx126x *)m;
  uint8_t cfg = 0x04; /* cold start, RTC wake-up off: configuration is lost */
  (void)cmd(d, OP_SET_SLEEP, &cfg, 1);
  d->mode = MODE_UNCONFIGURED;
}

static const rnc_modem_ops SX_OPS = {sx_init,      sx_start_rx, sx_poll_rx,  sx_start_tx,
                                     sx_poll_tx,   sx_carrier,  sx_rssi,     sx_start_cad,
                                     sx_poll_cad,  sx_standby,  sx_sleep};

void rnc_sx126x_attach(rnc_sx126x *d, const rnc_radio_hal *hal, const rnc_sx126x_board *board) {
  memset(d, 0, sizeof(*d));
  d->base.ops = &SX_OPS;
  d->hal = hal;
  if (board)
    d->board = *board;
  if (d->board.chip != 1261u)
    d->board.chip = 1262u;
}
