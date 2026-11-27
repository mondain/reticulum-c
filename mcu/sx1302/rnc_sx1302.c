/* SX1302 concentrator as an rnc_modem; see rnc_sx1302.h. Linux, libloragw 2.1.0. */
#define _GNU_SOURCE
#include "rnc_sx1302.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/gpio.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#include "loragw_hal.h"

#define SERVICE_IF 8u          /* the LoRa service ("lora std") IF chain */
#define FETCH_INTERVAL_US 3000u
#define TX_SLACK_US 1000000u   /* poll_tx gives up this long after the expected end */

/* WM1302 (SX1250, US915) TX gain table, from sx1302_hal global_conf.json.sx1250.US915:
 * measured power at the connector for each power index. */
static const struct {
  int8_t dbm;
  uint8_t pa, idx;
} GAIN[] = {
    {12, 0, 15}, {13, 0, 16}, {14, 0, 17}, {15, 0, 19}, {16, 0, 20}, {17, 0, 22},
    {18, 1, 1},  {19, 1, 2},  {20, 1, 3},  {21, 1, 4},  {22, 1, 5},  {23, 1, 6},
    {24, 1, 7},  {25, 1, 9},  {26, 1, 11}, {27, 1, 14}};
#define GAIN_N (sizeof(GAIN) / sizeof(GAIN[0]))
#define TXP_MIN_EXTRAPOLATED 0
#define TXP_MAX 27

static uint64_t mono_us(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static void sleep_ms(unsigned ms) {
  struct timespec ts = {(time_t)(ms / 1000u), (long)(ms % 1000u) * 1000000L};
  while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
  }
}

static uint8_t bw_code(uint32_t bw_hz) {
  switch (bw_hz) {
  case 125000u: return BW_125KHZ;
  case 250000u: return BW_250KHZ;
  case 500000u: return BW_500KHZ;
  default: return BW_UNDEFINED;
  }
}

/* ---- GPIO: the reset sequence of reset_lgw.sh, on the character device ---------------- */

enum { L_POWER = 0, L_RESET = 1, L_SX1261 = 2 };

static int gpio_set(rnc_sx1302 *d, unsigned line, int level) {
  struct gpio_v2_line_values v;
  memset(&v, 0, sizeof(v));
  v.mask = 1ull << line;
  v.bits = level ? (1ull << line) : 0u;
  return ioctl(d->gpio_fd, GPIO_V2_LINE_SET_VALUES_IOCTL, &v);
}

static int gpio_open(rnc_sx1302 *d) {
  struct gpio_v2_line_request req;
  int chip;
  if (d->gpio_fd >= 0)
    return 0;
  chip = open(d->cfg.gpiochip, O_RDWR | O_CLOEXEC);
  if (chip < 0) {
    fprintf(stderr, "sx1302: %s: %s\n", d->cfg.gpiochip, strerror(errno));
    return -1;
  }
  memset(&req, 0, sizeof(req));
  req.offsets[L_POWER] = d->cfg.power_line;
  req.offsets[L_RESET] = d->cfg.reset_line;
  req.offsets[L_SX1261] = d->cfg.sx1261_reset_line;
  req.num_lines = 3;
  req.config.flags = GPIO_V2_LINE_FLAG_OUTPUT;
  /* initial levels: power off, SX1302 out of reset, SX1261 in reset */
  req.config.num_attrs = 1;
  req.config.attrs[0].attr.id = GPIO_V2_LINE_ATTR_ID_OUTPUT_VALUES;
  req.config.attrs[0].attr.values = 0;
  req.config.attrs[0].mask = 0x7u;
  snprintf(req.consumer, sizeof(req.consumer), "rnc-sx1302");
  if (ioctl(chip, GPIO_V2_GET_LINE_IOCTL, &req) < 0) {
    fprintf(stderr, "sx1302: GPIO lines %u/%u/%u on %s: %s\n", d->cfg.power_line,
            d->cfg.reset_line, d->cfg.sx1261_reset_line, d->cfg.gpiochip, strerror(errno));
    close(chip);
    return -1;
  }
  close(chip);
  d->gpio_fd = req.fd;
  return 0;
}

static int board_reset(rnc_sx1302 *d) {
  if (d->cfg.no_reset)
    return 0;
  if (gpio_open(d) != 0)
    return -1;
  /* same order and pauses as tools/reset_lgw.sh */
  if (gpio_set(d, L_POWER, 1) || (sleep_ms(100), 0) || gpio_set(d, L_RESET, 1) ||
      (sleep_ms(100), 0) || gpio_set(d, L_RESET, 0) || (sleep_ms(100), 0) ||
      gpio_set(d, L_SX1261, 0) || (sleep_ms(100), 0) || gpio_set(d, L_SX1261, 1)) {
    fprintf(stderr, "sx1302: GPIO write: %s\n", strerror(errno));
    return -1;
  }
  sleep_ms(100);
  return 0;
}

/* ---- concentrator -------------------------------------------------------------------- */

static void stop(rnc_sx1302 *d) {
  if (d->started) {
    lgw_stop();
    d->started = 0;
  }
  d->rx_head = d->rx_count = 0;
  d->tx_active = 0;
}

static int check(rnc_modem *m, const rnc_lora_params *p) {
  (void)m;
  if (!p || bw_code(p->bw_hz) == BW_UNDEFINED)
    return -2; /* the service channel takes 125, 250 and 500 kHz only */
  if (p->sf < 5u || p->sf > 12u)
    return -3;
  if (p->cr < 5u || p->cr > 8u)
    return -4;
  if (p->txp_dbm < TXP_MIN_EXTRAPOLATED || p->txp_dbm > TXP_MAX)
    return -5;
  if (p->freq_hz < 150000000u || p->freq_hz > 1000000000u)
    return -6; /* from the SX1250's lower limit to libloragw's upper one; the regional plan is the operator's
                * responsibility */
  return 0;
}

/* the gain entry for a power: the calibrated one, or an uncalibrated extrapolation below it */
static struct lgw_tx_gain_s gain_for(int8_t dbm, int *calibrated) {
  struct lgw_tx_gain_s g;
  size_t i;
  memset(&g, 0, sizeof(g));
  g.rf_power = dbm;
  /* unused by the SX1250, but lgw_txgain_setconf refuses a value outside 5..15 whatever the radio type; Semtech's
   * packet forwarder sets 5 for the SX1250 too */
  g.mix_gain = 5;
  for (i = 0; i < GAIN_N; i++)
    if (GAIN[i].dbm == dbm) {
      g.pa_gain = GAIN[i].pa;
      g.pwr_idx = GAIN[i].idx;
      *calibrated = 1;
      return g;
    }
  /* below 12 dBm: the table rises one index per dB there; one index under that trend, so
   * the estimate errs on the low side */
  g.pa_gain = 0;
  g.pwr_idx = (uint8_t)(GAIN[0].idx - (GAIN[0].dbm - dbm) - 1);
  *calibrated = 0;
  return g;
}

static int start(rnc_sx1302 *d, const rnc_lora_params *p) {
  struct lgw_conf_board_s board;
  struct lgw_conf_rxrf_s rf;
  struct lgw_conf_rxif_s ifc;
  struct lgw_tx_gain_lut_s lut;
  int calibrated = 0;
  uint8_t i;

  stop(d);
  if (board_reset(d) != 0)
    return -10;

  memset(&board, 0, sizeof(board));
  board.lorawan_public = false; /* private sync word 0x12, as an RNode */
  board.clksrc = 0;
  board.full_duplex = false;
  board.com_type = LGW_COM_SPI;
  snprintf(board.com_path, sizeof(board.com_path), "%s", d->cfg.spi_path);
  if (lgw_board_setconf(&board) != LGW_HAL_SUCCESS)
    return -11;

  memset(&rf, 0, sizeof(rf));
  rf.enable = true;
  rf.freq_hz = (uint32_t)((int64_t)p->freq_hz - d->cfg.if_offset_hz);
  rf.rssi_offset = d->cfg.rssi_offset;
  rf.rssi_tcomp.coeff_c = 20.41f; /* WM1302 SX1250 temperature compensation */
  rf.rssi_tcomp.coeff_d = 2162.56f;
  rf.type = LGW_RADIO_TYPE_SX1250;
  rf.tx_enable = true;
  rf.single_input_mode = false;
  if (lgw_rxrf_setconf(0, &rf) != LGW_HAL_SUCCESS)
    return -12;
  memset(&rf, 0, sizeof(rf));
  rf.enable = false;
  if (lgw_rxrf_setconf(1, &rf) != LGW_HAL_SUCCESS)
    return -12;

  for (i = 0; i < LGW_IF_CHAIN_NB; i++) {
    memset(&ifc, 0, sizeof(ifc));
    ifc.enable = false;
    if (i != SERVICE_IF && lgw_rxif_setconf(i, &ifc) != LGW_HAL_SUCCESS)
      return -13;
  }
  memset(&ifc, 0, sizeof(ifc));
  ifc.enable = true;
  ifc.rf_chain = 0;
  ifc.freq_hz = d->cfg.if_offset_hz;
  ifc.bandwidth = bw_code(p->bw_hz);
  ifc.datarate = p->sf;
  ifc.implicit_hdr = false;
  if (lgw_rxif_setconf(SERVICE_IF, &ifc) != LGW_HAL_SUCCESS)
    return -13;

  memset(&lut, 0, sizeof(lut));
  lut.lut[0] = gain_for(p->txp_dbm, &calibrated);
  lut.size = 1;
  if (lgw_txgain_setconf(0, &lut) != LGW_HAL_SUCCESS)
    return -14;
  if (!calibrated)
    fprintf(stderr,
            "sx1302: WARNING %d dBm is below the calibrated gain table (12..27 dBm); "
            "using an uncalibrated power index %u, measure the output\n",
            p->txp_dbm, lut.lut[0].pwr_idx);

  if (d->cfg.verbose)
    fprintf(stderr, "sx1302: starting concentrator, rf0 %u Hz, if %d Hz, bw %u, sf %u, txp %d\n",
            (unsigned)((int64_t)p->freq_hz - d->cfg.if_offset_hz), (int)d->cfg.if_offset_hz, (unsigned)p->bw_hz, p->sf,
            p->txp_dbm);
  if (lgw_start() != LGW_HAL_SUCCESS) {
    fprintf(stderr, "sx1302: lgw_start failed (SPI enabled? I2C enabled? GPIO lines right?)\n");
    return -15;
  }
  d->started = 1;
  d->running = *p;
  return 0;
}

static int op_init(rnc_modem *m, const rnc_lora_params *p) {
  rnc_sx1302 *d = (rnc_sx1302 *)m;
  int r = check(m, p);
  if (r != 0)
    return r;
  /* the coding rate and preamble are transmit settings only: no restart for them */
  if (d->started && d->running.freq_hz == p->freq_hz && d->running.bw_hz == p->bw_hz &&
      d->running.sf == p->sf && d->running.txp_dbm == p->txp_dbm) {
    d->running = *p;
    rnc_sx1302_flush(d);
    return 0;
  }
  return start(d, p);
}

static int op_start_rx(rnc_modem *m) {
  /* the concentrator receives whenever it runs, also right after a transmission */
  return ((rnc_sx1302 *)m)->started ? 0 : -1;
}

static void fetch(rnc_sx1302 *d) {
  struct lgw_pkt_rx_s pkts[8];
  int n, i;
  uint64_t now = mono_us();
  if (now - d->last_fetch_us < FETCH_INTERVAL_US)
    return;
  d->last_fetch_us = now;
  n = lgw_receive(8, pkts);
  if (n < 0) {
    d->fetch_errors++;
    return;
  }
  for (i = 0; i < n; i++) {
    const struct lgw_pkt_rx_s *k = &pkts[i];
    unsigned slot;
    if (k->modulation != MOD_LORA || k->size == 0u || k->size > 255u)
      continue;
    if (d->rx_count >= sizeof(d->rxq) / sizeof(d->rxq[0])) {
      d->rx_head = (d->rx_head + 1u) % (unsigned)(sizeof(d->rxq) / sizeof(d->rxq[0]));
      d->rx_count--; /* oldest frame dropped */
    }
    slot = (d->rx_head + d->rx_count) % (unsigned)(sizeof(d->rxq) / sizeof(d->rxq[0]));
    memcpy(d->rxq[slot].data, k->payload, k->size);
    d->rxq[slot].size = k->size;
    d->rxq[slot].crc_ok = k->status == STAT_CRC_OK;
    d->rxq[slot].rssi = (int16_t)(k->rssis < 0 ? k->rssis - 0.5f : k->rssis + 0.5f);
    d->rxq[slot].snr_q = (int16_t)(k->snr * 4.0f);
    d->rx_count++;
  }
}

static int op_poll_rx(rnc_modem *m, uint8_t *buf, size_t capacity, rnc_modem_rx_info *info) {
  rnc_sx1302 *d = (rnc_sx1302 *)m;
  unsigned slot;
  int size;
  if (!d->started)
    return 0;
  if (!d->rx_count)
    fetch(d);
  if (!d->rx_count)
    return 0;
  slot = d->rx_head;
  d->rx_head = (d->rx_head + 1u) % (unsigned)(sizeof(d->rxq) / sizeof(d->rxq[0]));
  d->rx_count--;
  if (!d->rxq[slot].crc_ok)
    return -1; /* bad CRC, or no CRC at all: an RNode always sends one */
  if (d->rxq[slot].size > capacity)
    return -1;
  memcpy(buf, d->rxq[slot].data, d->rxq[slot].size);
  size = d->rxq[slot].size;
  if (info) {
    info->rssi_dbm = d->rxq[slot].rssi;
    info->snr_quarter_db = d->rxq[slot].snr_q;
  }
  return size;
}

static int op_start_tx(rnc_modem *m, const uint8_t *frame, size_t size) {
  rnc_sx1302 *d = (rnc_sx1302 *)m;
  struct lgw_pkt_tx_s t;
  if (!d->started || !frame || size == 0u || size > 255u)
    return -1;
  memset(&t, 0, sizeof(t));
  t.freq_hz = d->running.freq_hz;
  t.tx_mode = IMMEDIATE;
  t.rf_chain = 0;
  t.rf_power = d->running.txp_dbm;
  t.modulation = MOD_LORA;
  t.bandwidth = bw_code(d->running.bw_hz);
  t.datarate = d->running.sf;
  t.coderate = (uint8_t)(d->running.cr - 4u); /* CR_LORA_4_5 = 1 .. CR_LORA_4_8 = 4 */
  t.invert_pol = false;                       /* IQ polarity, standard as an RNode */
  t.preamble = d->running.preamble_symbols;
  t.no_crc = false;
  t.no_header = false;
  t.size = (uint16_t)size;
  memcpy(t.payload, frame, size);
  if (lgw_send(&t) != LGW_HAL_SUCCESS) {
    d->tx_errors++;
    return -1;
  }
  d->tx_toa_us = (uint64_t)lgw_time_on_air(&t) * 1000u;
  d->tx_start_us = mono_us();
  d->tx_active = 1;
  return 0;
}

static int op_poll_tx(rnc_modem *m) {
  rnc_sx1302 *d = (rnc_sx1302 *)m;
  uint8_t code = TX_STATUS_UNKNOWN;
  uint64_t elapsed;
  if (!d->tx_active)
    return 1;
  elapsed = mono_us() - d->tx_start_us;
  /* the status may read FREE for a moment after lgw_send, before the emission starts, so
   * the frame is only taken as sent once its time on air has passed */
  if (elapsed < d->tx_toa_us)
    return 0;
  if (lgw_status(0, TX_STATUS, &code) != LGW_HAL_SUCCESS)
    code = TX_STATUS_UNKNOWN;
  if (code == TX_FREE) {
    d->tx_active = 0;
    return 1;
  }
  if (elapsed > d->tx_toa_us + TX_SLACK_US) {
    lgw_abort_tx(0);
    d->tx_active = 0;
    d->tx_errors++;
    return -1;
  }
  return 0;
}

static int op_carrier(rnc_modem *m) {
  (void)m;
  return 0; /* not observable through libloragw; see rnc_sx1302.h */
}

static int op_rssi(rnc_modem *m, int *dbm) {
  (void)m;
  (void)dbm;
  return -1;
}

static int op_start_cad(rnc_modem *m) {
  (void)m;
  return -1;
}

static int op_poll_cad(rnc_modem *m) {
  (void)m;
  return 1; /* never started; report a free channel */
}

/* rnc_lora_if calls standby on every stop and reconfigure. Restarting the concentrator
 * costs seconds, so standby only ends a transmission and drops what was received; the
 * concentrator keeps listening (nothing is sent) until the next init or sleep. */
static void op_standby(rnc_modem *m) {
  rnc_sx1302 *d = (rnc_sx1302 *)m;
  if (d->started && d->tx_active)
    lgw_abort_tx(0);
  d->tx_active = 0;
  d->rx_head = d->rx_count = 0;
}

static void op_sleep(rnc_modem *m) {
  rnc_sx1302 *d = (rnc_sx1302 *)m;
  stop(d);
  if (d->gpio_fd >= 0)
    (void)gpio_set(d, L_POWER, 0);
}

static const rnc_modem_ops OPS = {op_init,    op_start_rx, op_poll_rx,   op_start_tx,
                                  op_poll_tx, op_carrier,  op_rssi,      op_start_cad,
                                  op_poll_cad, op_standby, op_sleep,     check};

void rnc_sx1302_init(rnc_sx1302 *d, const rnc_sx1302_config *cfg) {
  memset(d, 0, sizeof(*d));
  d->modem.ops = &OPS;
  d->gpio_fd = -1;
  if (cfg)
    d->cfg = *cfg;
  if (!d->cfg.spi_path)
    d->cfg.spi_path = "/dev/spidev0.0";
  if (!d->cfg.gpiochip)
    d->cfg.gpiochip = "/dev/gpiochip0";
}

void rnc_sx1302_flush(rnc_sx1302 *d) {
  struct lgw_pkt_rx_s pkts[8];
  unsigned rounds;
  d->rx_head = d->rx_count = 0;
  if (!d->started)
    return;
  for (rounds = 0; rounds < 8u && lgw_receive(8, pkts) > 0; rounds++) {
  }
}

void rnc_sx1302_close(rnc_sx1302 *d) {
  op_sleep(&d->modem);
  if (d->gpio_fd >= 0) {
    close(d->gpio_fd);
    d->gpio_fd = -1;
  }
}
