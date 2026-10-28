/* SX1276/77/78/79 driver; see rnc_sx127x.h. Written from the public datasheet. */
#include "rnc_sx127x.h"
#include <string.h>

#define REG_FIFO 0x00u
#define REG_OP_MODE 0x01u
#define REG_FRF_MSB 0x06u
#define REG_PA_CONFIG 0x09u
#define REG_OCP 0x0Bu
#define REG_LNA 0x0Cu
#define REG_FIFO_ADDR_PTR 0x0Du
#define REG_FIFO_TX_BASE 0x0Eu
#define REG_FIFO_RX_BASE 0x0Fu
#define REG_FIFO_RX_CURRENT 0x10u
#define REG_IRQ_FLAGS 0x12u
#define REG_RX_NB_BYTES 0x13u
#define REG_MODEM_STAT 0x18u
#define REG_PKT_SNR 0x19u
#define REG_PKT_RSSI 0x1Au
#define REG_RSSI 0x1Bu
#define REG_MODEM_CONFIG1 0x1Du
#define REG_MODEM_CONFIG2 0x1Eu
#define REG_PREAMBLE_MSB 0x20u
#define REG_PAYLOAD_LENGTH 0x22u
#define REG_MAX_PAYLOAD 0x23u
#define REG_MODEM_CONFIG3 0x26u
#define REG_HIGH_BW_OPT1 0x36u
#define REG_DETECT_OPTIMIZE 0x31u
#define REG_INVERT_IQ 0x33u
#define REG_DETECT_THRESHOLD 0x37u
#define REG_SYNC_WORD 0x39u
#define REG_HIGH_BW_OPT2 0x3Au
#define REG_INVERT_IQ2 0x3Bu
#define REG_DIO_MAPPING1 0x40u
#define REG_VERSION 0x42u
#define REG_PA_DAC 0x4Du

#define MODE_LORA 0x80u
#define MODE_LOW_FREQ 0x08u
#define MODE_SLEEP 0x00u
#define MODE_STANDBY 0x01u
#define MODE_TX 0x03u
#define MODE_RX_CONT 0x05u
#define MODE_CAD 0x07u

#define IRQ_CAD_DETECTED 0x01u
#define IRQ_CAD_DONE 0x04u
#define IRQ_TX_DONE 0x08u
#define IRQ_PAYLOAD_CRC_ERROR 0x20u
#define IRQ_RX_DONE 0x40u

#define S_UNCONFIGURED 0
#define S_STANDBY 1
#define S_RX 2
#define S_TX 3
#define S_CAD 4

/* ---- pure helpers -------------------------------------------------------------- */
uint32_t rnc_sx127x_frf(uint32_t freq_hz) {
  return (uint32_t)(((uint64_t)freq_hz << 19) / UINT64_C(32000000));
}

int rnc_sx127x_bw_code(uint32_t bw_hz) {
  switch (bw_hz) {
  case 7800u: return 0;
  case 10400u: return 1;
  case 15600u: return 2;
  case 20800u: return 3;
  case 31250u: return 4;
  case 41700u: return 5;
  case 62500u: return 6;
  case 125000u: return 7;
  case 250000u: return 8;
  case 500000u: return 9;
  default: return -1;
  }
}

int rnc_sx127x_pa(int pa_boost, int dbm, uint8_t *pa_config, uint8_t *pa_dac, uint8_t *ocp) {
  if (pa_boost) {
    if (dbm < 2 || dbm > 20)
      return -1;
    if (dbm <= 17) {
      *pa_config = (uint8_t)(0x80u | (unsigned)(dbm - 2));
      *pa_dac = 0x84; /* default */
      *ocp = 0x2B;    /* 100 mA (the reset value) */
    } else {
      /* +20 dBm mode: PA DAC 0x87 adds 3 dB to the output power setting */
      *pa_config = (uint8_t)(0x80u | (unsigned)(dbm - 5));
      *pa_dac = 0x87;
      *ocp = 0x31; /* 140 mA */
    }
    return 0;
  }
  if (dbm < 0 || dbm > 14)
    return -1;
  *pa_config = (uint8_t)(0x70u | (unsigned)dbm); /* MaxPower 7: Pout = OutputPower */
  *pa_dac = 0x84;
  *ocp = 0x2B;
  return 0;
}

/* ---- register access ---------------------------------------------------------------- */
static int rd(rnc_sx127x *d, uint8_t reg, uint8_t *v) {
  uint8_t tx[2] = {(uint8_t)(reg & 0x7Fu), 0}, rx[2];
  if (d->hal->spi_transfer(d->hal->context, tx, rx, 2) != 0)
    return -1;
  *v = rx[1];
  return 0;
}
static int wr(rnc_sx127x *d, uint8_t reg, uint8_t v) {
  uint8_t tx[2] = {(uint8_t)(reg | 0x80u), v};
  return d->hal->spi_transfer(d->hal->context, tx, NULL, 2);
}
static int op_mode(rnc_sx127x *d, uint8_t mode) {
  return wr(d, REG_OP_MODE, (uint8_t)(MODE_LORA | (d->low_band ? MODE_LOW_FREQ : 0u) | mode));
}
static int dio_high(rnc_sx127x *d) {
  /* 1: the line says something happened (or there is no line to ask); 0: nothing pending */
  int level = d->hal->gpio_read ? d->hal->gpio_read(d->hal->context, RNC_PIN_DIO) : -1;
  return level != 0;
}

int rnc_sx127x_set_header_mode(rnc_sx127x *d, int implicit, unsigned payload_length) {
  uint8_t v;
  if (rd(d, REG_MODEM_CONFIG1, &v) != 0)
    return -1;
  v = implicit ? (uint8_t)(v | 0x01u) : (uint8_t)(v & 0xFEu);
  if (wr(d, REG_MODEM_CONFIG1, v) != 0)
    return -1;
  if (implicit && wr(d, REG_PAYLOAD_LENGTH, (uint8_t)payload_length) != 0)
    return -1;
  return 0;
}

/* ---- modem operations ------------------------------------------------------------------ */
static int sx_init(rnc_modem *m, const rnc_lora_params *p) {
  rnc_sx127x *d = (rnc_sx127x *)m;
  uint8_t version = 0, pa, dac, ocp, v;
  uint32_t frf;
  int bw;
  unsigned preamble;
  /* SF6 only works with implicit headers, which the Reticulum air format does not use */
  if (rnc_lora_params_check(p, 7u) != 0 || p->freq_hz < 137000000u || p->freq_hz > 1020000000u)
    return -2;
  if (rnc_sx127x_pa(d->board.pa_boost, p->txp_dbm, &pa, &dac, &ocp) != 0)
    return -3;
  bw = rnc_sx127x_bw_code(p->bw_hz);
  d->params = *p;
  preamble = p->preamble_symbols ? p->preamble_symbols
                                 : rnc_lora_default_preamble(p->bw_hz, p->sf, p->cr);
  d->params.preamble_symbols = (uint16_t)preamble;
  d->low_band = p->freq_hz < 525000000u;
  d->mode = S_UNCONFIGURED;

  d->hal->gpio_write(d->hal->context, RNC_PIN_RESET, 0);
  d->hal->delay_us(d->hal->context, 2000u);
  d->hal->gpio_write(d->hal->context, RNC_PIN_RESET, 1);
  d->hal->delay_us(d->hal->context, 10000u);
  d->hal->gpio_write(d->hal->context, RNC_PIN_RXEN, 1);
  d->hal->gpio_write(d->hal->context, RNC_PIN_TXEN, 0);

  if (rd(d, REG_VERSION, &version) != 0 || version != 0x12)
    return -5;
  /* LoRa mode can only be selected from sleep */
  if (wr(d, REG_OP_MODE, MODE_SLEEP) != 0 || op_mode(d, MODE_SLEEP) != 0)
    return -4;
  frf = rnc_sx127x_frf(p->freq_hz);
  if (wr(d, REG_FRF_MSB, (uint8_t)(frf >> 16)) || wr(d, REG_FRF_MSB + 1u, (uint8_t)(frf >> 8)) ||
      wr(d, REG_FRF_MSB + 2u, (uint8_t)frf))
    return -4;
  if (wr(d, REG_FIFO_TX_BASE, 0) || wr(d, REG_FIFO_RX_BASE, 0))
    return -4;
  if (wr(d, REG_LNA, 0x23)) /* maximum gain (G1), boost on the high band port */
    return -4;
  /* modem: bandwidth, coding rate, explicit header | spreading factor, CRC on | AGC auto
   * plus the low data rate optimisation */
  if (wr(d, REG_MODEM_CONFIG1, (uint8_t)(((unsigned)bw << 4) | ((p->cr - 4u) << 1))) ||
      wr(d, REG_MODEM_CONFIG2, (uint8_t)((p->sf << 4) | 0x04u)) ||
      wr(d, REG_MODEM_CONFIG3,
         (uint8_t)(0x04u | (rnc_lora_ldro(p->bw_hz, p->sf) ? 0x08u : 0u))))
    return -4;
  if (rd(d, REG_DETECT_OPTIMIZE, &v) || wr(d, REG_DETECT_OPTIMIZE, (uint8_t)((v & 0xF8u) | 0x03u)) ||
      wr(d, REG_DETECT_THRESHOLD, 0x0A)) /* SF7..SF12 */
    return -4;
  /* the register holds the preamble length minus 4: on air N - 4 + 4.25 symbols, which is
   * the value the stock RNode firmware programs */
  if (wr(d, REG_PREAMBLE_MSB, (uint8_t)((preamble - 4u) >> 8)) ||
      wr(d, REG_PREAMBLE_MSB + 1u, (uint8_t)(preamble - 4u)))
    return -4;
  if (wr(d, REG_SYNC_WORD, 0x12)) /* private network sync word */
    return -4;
  if (wr(d, REG_INVERT_IQ, 0x27) || wr(d, REG_INVERT_IQ2, 0x1D)) /* standard IQ */
    return -4;
  if (wr(d, REG_MAX_PAYLOAD, 0xFF))
    return -4;
  /* errata: receiver optimisation for the 500 kHz bandwidth */
  if (bw == 9 && p->freq_hz >= 410000000u && p->freq_hz <= 525000000u) {
    if (wr(d, REG_HIGH_BW_OPT1, 0x02) || wr(d, REG_HIGH_BW_OPT2, 0x7F))
      return -4;
  } else if (bw == 9 && p->freq_hz >= 820000000u && p->freq_hz <= 1020000000u) {
    if (wr(d, REG_HIGH_BW_OPT1, 0x02) || wr(d, REG_HIGH_BW_OPT2, 0x64))
      return -4;
  } else if (wr(d, REG_HIGH_BW_OPT1, 0x03)) {
    return -4;
  }
  if (wr(d, REG_PA_CONFIG, pa) || wr(d, REG_PA_DAC, dac) || wr(d, REG_OCP, ocp))
    return -4;
  if (wr(d, REG_IRQ_FLAGS, 0xFF) || op_mode(d, MODE_STANDBY))
    return -4;
  d->mode = S_STANDBY;
  return 0;
}

static int sx_start_rx(rnc_modem *m) {
  rnc_sx127x *d = (rnc_sx127x *)m;
  if (d->mode == S_UNCONFIGURED)
    return -1;
  d->hal->gpio_write(d->hal->context, RNC_PIN_TXEN, 0);
  if (wr(d, REG_DIO_MAPPING1, 0x00) || /* DIO0 = RxDone */
      wr(d, REG_FIFO_ADDR_PTR, 0) || wr(d, REG_IRQ_FLAGS, 0xFF) || op_mode(d, MODE_RX_CONT))
    return -1;
  d->mode = S_RX;
  return 0;
}

static int sx_poll_rx(rnc_modem *m, uint8_t *buf, size_t capacity, rnc_modem_rx_info *info) {
  rnc_sx127x *d = (rnc_sx127x *)m;
  uint8_t flags, n, cur, snr = 0, prssi = 0;
  uint8_t tx[1 + RNC_MODEM_FRAME_MAX], rx[1 + RNC_MODEM_FRAME_MAX];
  if (d->mode != S_RX || !dio_high(d))
    return 0;
  if (rd(d, REG_IRQ_FLAGS, &flags) != 0 || !(flags & IRQ_RX_DONE))
    return 0;
  if (wr(d, REG_IRQ_FLAGS, flags) != 0) /* writing a one clears the flag */
    return 0;
  if (flags & IRQ_PAYLOAD_CRC_ERROR)
    return -1;
  if (rd(d, REG_RX_NB_BYTES, &n) || rd(d, REG_FIFO_RX_CURRENT, &cur) || n < 1u || n > capacity)
    return -1;
  if (wr(d, REG_FIFO_ADDR_PTR, cur))
    return -1;
  memset(tx, 0, (size_t)n + 1u);
  tx[0] = REG_FIFO;
  if (d->hal->spi_transfer(d->hal->context, tx, rx, (size_t)n + 1u) != 0)
    return -1;
  memcpy(buf, rx + 1, n);
  if (info) {
    int rssi;
    (void)rd(d, REG_PKT_SNR, &snr);
    (void)rd(d, REG_PKT_RSSI, &prssi);
    rssi = (d->low_band ? -164 : -157) + (int)prssi;
    if ((int8_t)snr < 0) /* datasheet: correct the packet RSSI for a negative SNR */
      rssi += (int8_t)snr / 4;
    info->rssi_dbm = (int16_t)rssi;
    info->snr_quarter_db = (int16_t)(int8_t)snr;
  }
  return n;
}

static int sx_start_tx(rnc_modem *m, const uint8_t *frame, size_t size) {
  rnc_sx127x *d = (rnc_sx127x *)m;
  uint8_t tx[1 + RNC_MODEM_FRAME_MAX];
  if (d->mode == S_UNCONFIGURED || size < 1u || size > RNC_MODEM_FRAME_MAX)
    return -1;
  if (op_mode(d, MODE_STANDBY) || wr(d, REG_FIFO_ADDR_PTR, 0))
    return -1;
  tx[0] = REG_FIFO | 0x80u;
  memcpy(tx + 1, frame, size);
  if (d->hal->spi_transfer(d->hal->context, tx, NULL, size + 1u) != 0)
    return -1;
  d->hal->gpio_write(d->hal->context, RNC_PIN_TXEN, 1);
  if (wr(d, REG_PAYLOAD_LENGTH, (uint8_t)size) || wr(d, REG_DIO_MAPPING1, 0x40) || /* TxDone */
      wr(d, REG_IRQ_FLAGS, 0xFF) || op_mode(d, MODE_TX))
    return -1;
  d->tx_deadline_us = d->hal->now_us(d->hal->context) + rnc_lora_toa_us(&d->params, size) +
                      500000u;
  d->mode = S_TX;
  return 0;
}

static int sx_poll_tx(rnc_modem *m) {
  rnc_sx127x *d = (rnc_sx127x *)m;
  uint8_t flags;
  if (d->mode != S_TX)
    return 1;
  if (dio_high(d) && rd(d, REG_IRQ_FLAGS, &flags) == 0 && (flags & IRQ_TX_DONE)) {
    (void)wr(d, REG_IRQ_FLAGS, 0xFF);
    d->hal->gpio_write(d->hal->context, RNC_PIN_TXEN, 0);
    (void)op_mode(d, MODE_STANDBY);
    d->mode = S_STANDBY;
    return 1;
  }
  if (d->hal->now_us(d->hal->context) > d->tx_deadline_us) {
    (void)op_mode(d, MODE_STANDBY);
    (void)wr(d, REG_IRQ_FLAGS, 0xFF);
    d->hal->gpio_write(d->hal->context, RNC_PIN_TXEN, 0);
    d->mode = S_STANDBY;
    return -1;
  }
  return 0;
}

static int sx_carrier(rnc_modem *m) {
  rnc_sx127x *d = (rnc_sx127x *)m;
  uint8_t st;
  if (d->mode != S_RX || rd(d, REG_MODEM_STAT, &st) != 0)
    return 0;
  return (st & 0x07u) != 0; /* signal detected, synchronised or receiving */
}

static int sx_rssi(rnc_modem *m, int *dbm) {
  rnc_sx127x *d = (rnc_sx127x *)m;
  uint8_t v;
  if (d->mode != S_RX || rd(d, REG_RSSI, &v) != 0)
    return -1;
  *dbm = (d->low_band ? -164 : -157) + (int)v;
  return 0;
}

static int sx_start_cad(rnc_modem *m) {
  rnc_sx127x *d = (rnc_sx127x *)m;
  if (d->mode == S_UNCONFIGURED || d->mode == S_TX)
    return -1;
  if (op_mode(d, MODE_STANDBY) || wr(d, REG_DIO_MAPPING1, 0x80) || /* DIO0 = CadDone */
      wr(d, REG_IRQ_FLAGS, 0xFF) || op_mode(d, MODE_CAD))
    return -1;
  d->mode = S_CAD;
  return 0;
}

static int sx_poll_cad(rnc_modem *m) {
  rnc_sx127x *d = (rnc_sx127x *)m;
  uint8_t flags;
  if (d->mode != S_CAD)
    return 1;
  if (rd(d, REG_IRQ_FLAGS, &flags) != 0 || !(flags & IRQ_CAD_DONE))
    return 0;
  (void)wr(d, REG_IRQ_FLAGS, 0xFF);
  d->mode = S_STANDBY;
  return (flags & IRQ_CAD_DETECTED) ? 2 : 1;
}

static void sx_standby(rnc_modem *m) {
  rnc_sx127x *d = (rnc_sx127x *)m;
  if (d->mode != S_UNCONFIGURED) {
    (void)op_mode(d, MODE_STANDBY);
    d->mode = S_STANDBY;
  }
}

static void sx_sleep(rnc_modem *m) {
  rnc_sx127x *d = (rnc_sx127x *)m;
  if (d->mode != S_UNCONFIGURED)
    (void)op_mode(d, MODE_SLEEP);
  d->mode = S_STANDBY;
}

static const rnc_modem_ops SX_OPS = {sx_init,     sx_start_rx, sx_poll_rx,  sx_start_tx,
                                     sx_poll_tx,  sx_carrier,  sx_rssi,     sx_start_cad,
                                     sx_poll_cad, sx_standby,  sx_sleep};

void rnc_sx127x_attach(rnc_sx127x *d, const rnc_radio_hal *hal, const rnc_sx127x_board *board) {
  memset(d, 0, sizeof(*d));
  d->base.ops = &SX_OPS;
  d->hal = hal;
  if (board)
    d->board = *board;
}
