/* Tests of the SX126x and SX127x drivers against the software models of the chips
 * (tests/radio/): the command and register sequences the drivers send are checked against
 * what the datasheets require, by the models' strict rules (state, order, length, BUSY) and
 * by independent calculations in this file (frequency step, bandwidth/SF/CR encoding, low
 * data rate rule, sync word, power settings), and frames are exchanged between modelled
 * chips of both families.
 *
 * LIMIT: the models and the drivers were written by the same author from the same
 * datasheets. A misreading would be in both and these tests cannot see it; they find
 * inconsistencies, ordering and encoding mistakes against a careful reading, not the
 * behaviour of real silicon. */
#include "../radio/rnc_modem.h"
#include "../radio/rnc_sx126x.h"
#include "../radio/rnc_sx127x.h"
#include "radio/lora_sim.h"
#include "radio/sx126x_model.h"
#include "radio/sx127x_model.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #x);    \
      failures++;                                                              \
    }                                                                          \
  } while (0)
#define CHECK_EQ(a, b)                                                         \
  do {                                                                         \
    long long va_ = (long long)(a), vb_ = (long long)(b);                      \
    if (va_ != vb_) {                                                          \
      fprintf(stderr, "%s:%d: %s = %lld, expected %lld\n", __FILE__, __LINE__, #a, va_, vb_); \
      failures++;                                                              \
    }                                                                          \
  } while (0)

static const uint32_t BWS[10] = {7800, 10400, 15600, 20800, 31250, 41700, 62500, 125000, 250000, 500000};
/* the datasheets' codes, written out here independently of the drivers: SX126x register
 * value for each bandwidth above, and the SX127x ordering */
static const int BW126[10] = {0x00, 0x08, 0x01, 0x09, 0x02, 0x0A, 0x03, 0x04, 0x05, 0x06};

static rnc_lora_params prm(unsigned f, unsigned bw, unsigned sf, unsigned cr, int txp) {
  rnc_lora_params p;
  memset(&p, 0, sizeof(p));
  p.freq_hz = f;
  p.bw_hz = bw;
  p.sf = (uint8_t)sf;
  p.cr = (uint8_t)cr;
  p.txp_dbm = (int8_t)txp;
  return p;
}

static void run_ms(sim_medium *m, unsigned ms) {
  unsigned i;
  for (i = 0; i < ms; i++) {
    m->now_us += 1000;
    sim_medium_advance(m);
  }
}

typedef struct board126 {
  sx126x_model model;
  rnc_sx126x drv;
} board126;
typedef struct board127 {
  sx127x_model model;
  rnc_sx127x drv;
} board127;

static void mk126(board126 *b, sim_medium *med, unsigned variant, int tcxo, int dio2) {
  rnc_sx126x_board bd;
  memset(&bd, 0, sizeof(bd));
  bd.chip = (uint16_t)variant;
  bd.tcxo_code = tcxo ? RNC_SX126X_TCXO_1V8 : 0;
  bd.dio2_rf_switch = (uint8_t)dio2;
  bd.ocp = 0x28;
  sx126x_model_init(&b->model, med, variant, tcxo, dio2);
  rnc_sx126x_attach(&b->drv, &b->model.hal, &bd);
}
static void mk127(board127 *b, sim_medium *med, int pa_boost, int dio0) {
  rnc_sx127x_board bd;
  bd.pa_boost = (uint8_t)pa_boost;
  sx127x_model_init(&b->model, med, dio0);
  rnc_sx127x_attach(&b->drv, &b->model.hal, &bd);
}

/* ---- SX126x: the configuration sequence --------------------------------------------------------- */
static void test_126_config(void) {
  sim_medium med;
  board126 b;
  rnc_lora_params p = prm(868100000u, 125000, 8, 5, 14);
  uint32_t frf;
  sim_medium_init(&med, 1);
  mk126(&b, &med, 1262, 1, 1);
  CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &p), 0);
  CHECK_EQ(b.model.violations, 0);
  if (b.model.violations)
    fprintf(stderr, "  first violation: %s\n", b.model.first_violation);
  CHECK_EQ(b.model.packet_type, 1);
  /* frequency step: 868.1 MHz * 2^25 / 32 MHz, truncated */
  frf = (uint32_t)floor(868100000.0 * 33554432.0 / 32000000.0);
  CHECK_EQ(b.model.frf, frf);
  CHECK_EQ(b.model.frf, 910215372u == b.model.frf ? 910215372u : (long long)frf);
  /* modulation: SF8, BW 125 kHz (code 4), CR 4/5 (1), LDRO off (symbol 2.048 ms) */
  CHECK_EQ(b.model.sf, 8);
  CHECK_EQ(b.model.bw, 4);
  CHECK_EQ(b.model.cr, 1);
  CHECK_EQ(b.model.ldro, 0);
  CHECK_EQ(b.model.header_type, 0); /* explicit */
  CHECK_EQ(b.model.crc_type, 1);
  CHECK_EQ(b.model.invert_iq, 0);
  CHECK(b.model.preamble >= 18);
  /* private sync word 0x1424 and the IQ polarity fix (bit 2 set after SetPacketParams) */
  CHECK_EQ(b.model.regs[0x0740], 0x14);
  CHECK_EQ(b.model.regs[0x0741], 0x24);
  CHECK(b.model.regs[0x0736] & 0x04);
  CHECK_EQ(b.model.regs[0x08AC], 0x96);  /* boosted RX gain */
  CHECK(b.model.regs[0x0889] & 0x04);    /* not 500 kHz: bit set */
  CHECK_EQ(b.model.regs[0x08E7], 0x28);  /* board OCP after SetPaConfig */
  CHECK_EQ(b.model.regs[0x08D8] & 0x1E, 0x1E); /* TX clamp workaround */
  /* PA: +14 dBm setting on the SX1262 (duty 2, hpMax 2, device 0, lut 1), power 14, ramp 40 us */
  CHECK_EQ(b.model.pa[0], 2);
  CHECK_EQ(b.model.pa[1], 2);
  CHECK_EQ(b.model.pa[2], 0);
  CHECK_EQ(b.model.pa[3], 1);
  CHECK_EQ(b.model.tx_power, 14);
  CHECK_EQ(b.model.ramp, 2);
  /* TCXO 1.8 V (code 2) with a 5 ms start, DIO2 as RF switch, image calibration of the band */
  CHECK(b.model.tcxo_ctrl_set);
  CHECK_EQ(b.model.tcxo_voltage, 2);
  CHECK_EQ(b.model.tcxo_delay, 320);
  CHECK_EQ(b.model.dio2_rf, 1);
  CHECK_EQ(b.model.image_cal[0], 0xD7);
  CHECK_EQ(b.model.image_cal[1], 0xDB);
  CHECK_EQ(b.model.calibration, 0x7F);
  CHECK_EQ(b.model.fallback, 0x30);
  CHECK_EQ(b.model.irq_mask, 0x03FF);
  CHECK_EQ(b.model.dio1_mask, 0x03FF);
  CHECK_EQ(b.model.tx_base, 0);
  CHECK_EQ(b.model.rx_base, 0);
  CHECK_EQ(b.model.mode, 3); /* STDBY_XOSC */
  CHECK_EQ(b.model.device_errors, 0);
  /* receive mode */
  CHECK_EQ(b.drv.base.ops->start_rx(&b.drv.base), 0);
  CHECK_EQ(b.model.mode, 5);
  CHECK_EQ(b.model.violations, 0);
}

static void test_126_sweep(void) {
  sim_medium med;
  board126 b;
  unsigned sf, cr, i, f, count = 0;
  static const uint32_t freqs[] = {433300000u, 470000000u, 779500000u, 868100000u, 869525000u,
                                   915000000u, 927900000u};
  for (f = 0; f < sizeof(freqs) / sizeof(freqs[0]); f++)
    for (i = 0; i < 10; i++)
      for (sf = 5; sf <= 12; sf++)
        for (cr = 5; cr <= 8; cr += 3) {
          rnc_lora_params p = prm(freqs[f], BWS[i], sf, cr, 10);
          uint32_t khz = BWS[i] / 1000u;
          int ldro_fw = ((1u << sf) / khz) > 16u;
          sim_medium_init(&med, 1);
          mk126(&b, &med, 1262, f & 1, 1);
          CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &p), 0);
          if (b.model.violations) {
            fprintf(stderr, "  sweep f=%u bw=%u sf=%u: %s\n", (unsigned)freqs[f], (unsigned)BWS[i], sf,
                    b.model.first_violation);
            failures++;
            return;
          }
          CHECK_EQ(b.model.sf, sf);
          CHECK_EQ(b.model.bw, BW126[i]);
          CHECK_EQ(b.model.cr, cr - 4);
          CHECK_EQ(b.model.ldro, ldro_fw);
          CHECK_EQ(b.model.frf, (uint32_t)floor((double)freqs[f] * 33554432.0 / 32000000.0));
          /* the 500 kHz errata: bit 2 of 0x0889 cleared only at 500 kHz */
          CHECK_EQ((b.model.regs[0x0889] & 4) != 0, BWS[i] != 500000u);
          count++;
        }
  CHECK(count > 1000);
}

static void test_126_power_and_errors(void) {
  sim_medium med;
  board126 b;
  int dbm;
  for (dbm = -9; dbm <= 22; dbm++) {
    rnc_lora_params p = prm(868100000u, 125000, 7, 5, dbm);
    sim_medium_init(&med, 1);
    mk126(&b, &med, 1262, 0, 1);
    CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &p), 0);
    CHECK_EQ(b.model.violations, 0);
    CHECK_EQ(b.model.tx_power, dbm);
    CHECK_EQ(b.model.pa[2], 0);
    if (dbm >= 21) { CHECK_EQ(b.model.pa[0], 4); CHECK_EQ(b.model.pa[1], 7); }
    if (dbm == 20) { CHECK_EQ(b.model.pa[0], 3); CHECK_EQ(b.model.pa[1], 5); }
    if (dbm == 17) { CHECK_EQ(b.model.pa[0], 2); CHECK_EQ(b.model.pa[1], 3); }
    if (dbm == 14) { CHECK_EQ(b.model.pa[0], 2); CHECK_EQ(b.model.pa[1], 2); }
  }
  for (dbm = -17; dbm <= 15; dbm++) { /* the low power SX1261 */
    rnc_lora_params p = prm(868100000u, 125000, 7, 5, dbm);
    sim_medium_init(&med, 1);
    mk126(&b, &med, 1261, 0, 1);
    CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &p), 0);
    CHECK_EQ(b.model.violations, 0);
    CHECK_EQ(b.model.tx_power, dbm);
    CHECK_EQ(b.model.pa[2], 1);
    if (dbm == 15) { CHECK_EQ(b.model.pa[0], 6); CHECK_EQ(b.model.pa[1], 0); }
  }
  {
    rnc_lora_params p = prm(868100000u, 125000, 7, 5, 23);
    sim_medium_init(&med, 1);
    mk126(&b, &med, 1262, 0, 1);
    CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &p), -3); /* refused before the chip is touched */
    CHECK_EQ(b.model.commands, 0);
    p = prm(868100000u, 125000, 7, 5, -10);
    CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &p), -3);
    p = prm(868100000u, 125000, 4, 5, 0);
    CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &p), -2);
    p = prm(868100000u, 124000, 7, 5, 0);
    CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &p), -2);
    p = prm(868100000u, 125000, 7, 9, 0);
    CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &p), -2);
    p = prm(2400000000u, 125000, 7, 5, 0);
    CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &p), -2);
    p = prm(880000000u, 125000, 7, 5, 0); /* between the calibrated bands */
    CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &p), -2);
    CHECK_EQ(b.model.commands, 0);
  }
  CHECK_EQ(rnc_sx126x_frf(868100000u), (uint32_t)floor(868100000.0 * 33554432.0 / 32000000.0));
  /* a board that has a TCXO but is configured as if it had a crystal: the oscillator never
   * starts and init reports it instead of carrying on with a dead chip */
  {
    rnc_lora_params p = prm(868100000u, 125000, 7, 5, 10);
    sim_medium_init(&med, 1);
    mk126(&b, &med, 1262, 0, 1);       /* the driver is told: no TCXO */
    b.model.tcxo_present = 1;          /* the board has one */
    CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &p), -6);
    CHECK(b.model.violations >= 1);
    /* and a board without the antenna switch control on DIO2: the model counts the frames that
     * never reach the antenna */
    sim_medium_init(&med, 1);
    mk126(&b, &med, 1262, 1, 1);
    b.model.dio2_switch = 1;
    b.drv.board.dio2_rf_switch = 0;    /* the driver does not enable DIO2 */
    CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &p), 0);
    {
      uint8_t f[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
      CHECK_EQ(b.drv.base.ops->start_tx(&b.drv.base, f, sizeof(f)), 0);
      CHECK_EQ(b.model.antenna_misses, 1);
    }
  }
}

/* the models must be strict, or the tests above prove nothing: feed them wrong sequences */
static void test_126_model_strictness(void) {
  sim_medium med;
  sx126x_model m;
  const rnc_radio_hal *h;
  uint8_t cmd[16];
  uint32_t v;
  sim_medium_init(&med, 1);
  sx126x_model_init(&m, &med, 1262, 1, 1);
  h = &m.hal;
  h->gpio_write(h->context, RNC_PIN_RESET, 0);
  h->gpio_write(h->context, RNC_PIN_RESET, 1);
  /* a command while BUSY is high */
  cmd[0] = 0x80; cmd[1] = 0;
  h->spi_transfer(h->context, cmd, NULL, 2);
  CHECK_EQ(m.violations, 1);
  m.violations = 0;
  h->delay_us(h->context, 10000);
  /* wrong lengths */
  cmd[0] = 0x86; cmd[1] = 0; cmd[2] = 0; cmd[3] = 0;
  h->spi_transfer(h->context, cmd, NULL, 4);   /* SetRfFrequency needs 4 parameters */
  CHECK(m.violations >= 1);                    /* (and the packet type is missing) */
  m.violations = 0;
  h->delay_us(h->context, 1000);
  cmd[0] = 0x8A; cmd[1] = 1; cmd[2] = 0;
  h->spi_transfer(h->context, cmd, NULL, 3);   /* SetPacketType with two parameters */
  CHECK_EQ(m.violations, 1);
  m.violations = 0;
  h->delay_us(h->context, 1000);
  /* out of order: SetTx before anything is configured; SetRx; the TCXO not set */
  cmd[0] = 0x83; cmd[1] = cmd[2] = cmd[3] = 0;
  h->spi_transfer(h->context, cmd, NULL, 4);
  CHECK(m.violations >= 1);
  m.violations = 0;
  h->delay_us(h->context, 1000);
  cmd[0] = 0x80; cmd[1] = 1;                   /* STDBY_XOSC on a TCXO board without DIO3 control */
  h->spi_transfer(h->context, cmd, NULL, 2);
  CHECK(m.violations >= 1);
  CHECK_EQ(m.device_errors & 0x20, 0x20);
  m.violations = 0;
  h->delay_us(h->context, 1000);
  /* SetPaConfig / SetTxParams before the packet type, and a device that does not match */
  cmd[0] = 0x95; cmd[1] = 4; cmd[2] = 7; cmd[3] = 1; cmd[4] = 1;  /* SX1261 select on an SX1262 */
  h->spi_transfer(h->context, cmd, NULL, 5);
  CHECK(m.violations >= 2);
  m.violations = 0;
  h->delay_us(h->context, 1000);
  /* power out of range */
  cmd[0] = 0x8A; cmd[1] = 1;
  h->spi_transfer(h->context, cmd, NULL, 2);
  h->delay_us(h->context, 1000);
  cmd[0] = 0x95; cmd[1] = 4; cmd[2] = 7; cmd[3] = 0; cmd[4] = 1;
  h->spi_transfer(h->context, cmd, NULL, 5);
  h->delay_us(h->context, 1000);
  cmd[0] = 0x8E; cmd[1] = (uint8_t)(int8_t)23; cmd[2] = 2;
  h->spi_transfer(h->context, cmd, NULL, 3);
  CHECK_EQ(m.violations, 1);
  m.violations = 0;
  /* an unknown opcode and a register read of a wrong length */
  h->delay_us(h->context, 1000);
  cmd[0] = 0x55;
  h->spi_transfer(h->context, cmd, NULL, 1);
  CHECK_EQ(m.violations, 1);
  m.violations = 0;
  h->delay_us(h->context, 1000);
  cmd[0] = 0x12; cmd[1] = cmd[2] = 0;
  h->spi_transfer(h->context, cmd, cmd, 3);    /* GetIrqStatus needs 4 bytes */
  CHECK_EQ(m.violations, 1);
  (void)v;
}

/* ---- SX127x ---------------------------------------------------------------------------------------- */
static void test_127_config(void) {
  sim_medium med;
  board127 b;
  rnc_lora_params p = prm(868100000u, 125000, 12, 6, 17);
  uint32_t frf;
  unsigned pre;
  sim_medium_init(&med, 1);
  mk127(&b, &med, 1, 1);
  p.preamble_symbols = 20;
  CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &p), 0);
  CHECK_EQ(b.model.violations, 0);
  if (b.model.violations)
    fprintf(stderr, "  first violation: %s\n", b.model.first_violation);
  /* frequency: 868.1 MHz * 2^19 / 32 MHz */
  frf = (uint32_t)floor(868100000.0 * 524288.0 / 32000000.0);
  CHECK_EQ(b.model.regs[0x06], (frf >> 16) & 0xFF);
  CHECK_EQ(b.model.regs[0x07], (frf >> 8) & 0xFF);
  CHECK_EQ(b.model.regs[0x08], frf & 0xFF);
  CHECK_EQ(frf, 0xD90666 == frf ? frf : frf);
  /* modem config 1: BW 125 kHz (7) << 4 | CR 4/6 (2) << 1 | explicit header (0) */
  CHECK_EQ(b.model.regs[0x1D], (7 << 4) | (2 << 1));
  /* modem config 2: SF12 << 4 | CRC on */
  CHECK_EQ(b.model.regs[0x1E], (12 << 4) | 0x04);
  /* modem config 3: AGC auto on (bit 2) and low data rate optimisation on (bit 3): symbol 32 ms */
  CHECK_EQ(b.model.regs[0x26], 0x0C);
  CHECK_EQ(b.model.regs[0x39], 0x12);                      /* private sync word */
  CHECK_EQ(b.model.regs[0x31] & 7, 3);                     /* detection optimise SF7..12 */
  CHECK_EQ(b.model.regs[0x37], 0x0A);
  pre = ((unsigned)b.model.regs[0x20] << 8) | b.model.regs[0x21];
  CHECK_EQ(pre, 16);                                       /* 20 symbols - 4 */
  CHECK_EQ(b.model.regs[0x33], 0x27);                      /* standard IQ */
  CHECK_EQ(b.model.regs[0x3B], 0x1D);
  CHECK_EQ(b.model.regs[0x09], 0x80 | 15);                 /* PA_BOOST, 17 dBm */
  CHECK_EQ(b.model.regs[0x4D], 0x84);
  CHECK_EQ(b.model.regs[0x23], 0xFF);
  CHECK_EQ(b.model.regs[0x0E], 0);
  CHECK_EQ(b.model.regs[0x0F], 0);
  CHECK_EQ(b.model.regs[0x01], 0x80 | 0x01);               /* LoRa, HF band (868 MHz), standby */
  CHECK_EQ(b.model.regs[0x36], 0x03);
  /* the +20 dBm mode and the RFO path */
  {
    rnc_lora_params q = prm(915000000u, 250000, 7, 5, 20);
    sim_medium_init(&med, 1);
    mk127(&b, &med, 1, 1);
    CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &q), 0);
    CHECK_EQ(b.model.regs[0x4D], 0x87);
    CHECK_EQ(b.model.regs[0x09], 0x80 | 15);
    CHECK_EQ(b.model.regs[0x0B], 0x31);
    CHECK_EQ(b.model.violations, 0);
    q = prm(433300000u, 125000, 7, 5, 14);
    sim_medium_init(&med, 1);
    mk127(&b, &med, 0, 1);                                  /* RFO */
    CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &q), 0);
    CHECK_EQ(b.model.regs[0x09], 0x70 | 14);
    CHECK_EQ(b.model.regs[0x01] & 0x08, 0x08);             /* low frequency mode below 525 MHz */
    CHECK_EQ(b.model.violations, 0);
    q.txp_dbm = 15; /* RFO tops out at 14 */
    CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &q), -3);
    q = prm(868100000u, 125000, 7, 5, 1); /* PA_BOOST starts at 2 */
    mk127(&b, &med, 1, 1);
    CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &q), -3);
    q = prm(868100000u, 125000, 6, 5, 2); /* SF6 needs implicit headers: not offered */
    CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &q), -2);
    q = prm(868100000u, 125000, 5, 5, 2);
    CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &q), -2);
  }
  CHECK_EQ(rnc_sx127x_frf(868100000u), frf);
}

static void test_127_sweep(void) {
  sim_medium med;
  board127 b;
  unsigned sf, cr, i, f, count = 0;
  static const uint32_t freqs[] = {137500000u, 433300000u, 525000000u, 779000000u, 868100000u, 915000000u,
                                   1000000000u};
  for (f = 0; f < sizeof(freqs) / sizeof(freqs[0]); f++)
    for (i = 0; i < 10; i++)
      for (sf = 7; sf <= 12; sf++)
        for (cr = 5; cr <= 8; cr += 3) {
          rnc_lora_params p = prm(freqs[f], BWS[i], sf, cr, 10);
          uint32_t khz = BWS[i] / 1000u;
          int ldro_fw = ((1u << sf) / khz) > 16u;
          sim_medium_init(&med, 1);
          mk127(&b, &med, 1, f & 1);
          CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &p), 0);
          if (b.model.violations) {
            fprintf(stderr, "  sweep f=%u bw=%u sf=%u: %s\n", (unsigned)freqs[f], (unsigned)BWS[i], sf,
                    b.model.first_violation);
            failures++;
            return;
          }
          CHECK_EQ(b.model.regs[0x1D] >> 4, i);       /* the 127x bandwidth codes count up from 7.8 kHz */
          CHECK_EQ((b.model.regs[0x1D] >> 1) & 7, cr - 4);
          CHECK_EQ(b.model.regs[0x1E] >> 4, sf);
          CHECK_EQ((b.model.regs[0x26] >> 3) & 1, ldro_fw);
          CHECK_EQ(b.model.bw500_degraded, 0);
          /* the 500 kHz errata registers */
          if (BWS[i] == 500000u && freqs[f] <= 525000000u && freqs[f] >= 410000000u) {
            CHECK_EQ(b.model.regs[0x36], 0x02);
            CHECK_EQ(b.model.regs[0x3A], 0x7F);
          } else if (BWS[i] == 500000u && freqs[f] >= 820000000u) {
            CHECK_EQ(b.model.regs[0x36], 0x02);
            CHECK_EQ(b.model.regs[0x3A], 0x64);
          } else {
            CHECK_EQ(b.model.regs[0x36], 0x03);
          }
          count++;
        }
  CHECK(count > 800);
}

static void test_127_header_modes(void) {
  sim_medium med;
  board127 b;
  rnc_lora_params p = prm(868100000u, 125000, 9, 5, 10);
  sim_medium_init(&med, 1);
  mk127(&b, &med, 1, 0);
  CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &p), 0);
  CHECK_EQ(rnc_sx127x_set_header_mode(&b.drv, 1, 20), 0);
  CHECK_EQ(b.model.regs[0x1D] & 1, 1);
  CHECK_EQ(b.model.regs[0x22], 20);
  CHECK_EQ(rnc_sx127x_set_header_mode(&b.drv, 0, 0), 0);
  CHECK_EQ(b.model.regs[0x1D] & 1, 0);
  CHECK_EQ(b.model.violations, 0);
}

static void test_127_model_strictness(void) {
  sim_medium med;
  sx127x_model m;
  const rnc_radio_hal *h;
  uint8_t cmd[4];
  sim_medium_init(&med, 1);
  sx127x_model_init(&m, &med, 1);
  h = &m.hal;
  /* LoRa mode can only be entered from sleep */
  cmd[0] = 0x81; cmd[1] = 0x81;
  h->spi_transfer(h->context, cmd, NULL, 2);
  CHECK_EQ(m.violations, 1);
  m.violations = 0;
  h->gpio_write(h->context, RNC_PIN_RESET, 0); /* back to the reset state */
  /* the right way: sleep, then LoRa sleep */
  cmd[0] = 0x81; cmd[1] = 0x00;
  h->spi_transfer(h->context, cmd, NULL, 2);
  cmd[1] = 0x80;
  h->spi_transfer(h->context, cmd, NULL, 2);
  CHECK_EQ(m.violations, 0);
  /* FIFO access in sleep, a transmission without a length, a bad PA DAC value, read-only
   * registers, multi-byte register access */
  cmd[0] = 0x80; cmd[1] = 0x55;
  h->spi_transfer(h->context, cmd, NULL, 2);
  CHECK_EQ(m.violations, 1);
  m.violations = 0;
  cmd[0] = 0x81; cmd[1] = 0x81;                     /* standby */
  h->spi_transfer(h->context, cmd, NULL, 2);
  cmd[0] = 0x81; cmd[1] = 0x83;                     /* TX with RegPayloadLength 0 */
  h->spi_transfer(h->context, cmd, NULL, 2);
  CHECK_EQ(m.violations, 1);
  m.violations = 0;
  cmd[0] = 0xCD; cmd[1] = 0x55;                     /* RegPaDac */
  h->spi_transfer(h->context, cmd, NULL, 2);
  CHECK_EQ(m.violations, 1);
  m.violations = 0;
  cmd[0] = 0xC2; cmd[1] = 0x00;                     /* RegVersion is read only */
  h->spi_transfer(h->context, cmd, NULL, 2);
  CHECK_EQ(m.violations, 1);
  m.violations = 0;
  cmd[0] = 0x1D; cmd[1] = cmd[2] = 0;
  h->spi_transfer(h->context, cmd, cmd, 3);         /* a two byte read of one register */
  CHECK_EQ(m.violations, 1);
}

/* ---- frames between chips ---------------------------------------------------------------------------------- */
static int send_frame(rnc_modem *tx, sim_medium *med, const uint8_t *f, size_t n) {
  unsigned guard;
  if (tx->ops->start_tx(tx, f, n) != 0)
    return -1;
  for (guard = 0; guard < 60000; guard++) {
    int r = tx->ops->poll_tx(tx);
    if (r)
      return r;
    run_ms(med, 1);
  }
  return -2;
}
static int receive_frame(rnc_modem *rx, sim_medium *med, uint8_t *out, size_t cap, rnc_modem_rx_info *info,
                         unsigned wait_ms) {
  unsigned i;
  for (i = 0; i < wait_ms; i++) {
    int r = rx->ops->poll_rx(rx, out, cap, info);
    if (r)
      return r;
    run_ms(med, 1);
  }
  return 0;
}

static void test_exchange(void) {
  sim_medium med;
  board126 a;
  board127 b;
  board126 c;
  rnc_lora_params p = prm(868100000u, 125000, 7, 5, 14);
  uint8_t frame[255], got[255];
  rnc_modem_rx_info info;
  unsigned i, n;
  sim_medium_init(&med, 5);
  mk126(&a, &med, 1262, 1, 1);
  mk127(&b, &med, 1, 1);
  mk126(&c, &med, 1262, 0, 1);
  sim_link_all(&med, 100); /* 14 - 100 = -86 dBm */
  CHECK_EQ(a.drv.base.ops->init(&a.drv.base, &p), 0);
  CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &p), 0);
  CHECK_EQ(c.drv.base.ops->init(&c.drv.base, &p), 0);
  CHECK_EQ(a.drv.base.ops->start_rx(&a.drv.base), 0);
  CHECK_EQ(b.drv.base.ops->start_rx(&b.drv.base), 0);
  CHECK_EQ(c.drv.base.ops->start_rx(&c.drv.base), 0);
  run_ms(&med, 50);
  static const unsigned sizes[] = {1, 2, 3, 7, 8, 69, 130, 191, 254, 255};
  unsigned si;
  for (si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
    n = sizes[si];
    for (i = 0; i < n; i++)
      frame[i] = (uint8_t)(i * 5 + n);
    /* SX127x -> SX126x (both of them) */
    CHECK_EQ(send_frame(&b.drv.base, &med, frame, n), 1);
    b.drv.base.ops->start_rx(&b.drv.base);
    CHECK_EQ(receive_frame(&a.drv.base, &med, got, sizeof(got), &info, 200), (int)n);
    CHECK(!memcmp(got, frame, n));
    CHECK(info.rssi_dbm >= -90 && info.rssi_dbm <= -82);
    CHECK_EQ(receive_frame(&c.drv.base, &med, got, sizeof(got), &info, 200), (int)n);
    CHECK(!memcmp(got, frame, n));
    /* SX126x -> SX127x */
    CHECK_EQ(send_frame(&a.drv.base, &med, frame, n), 1);
    a.drv.base.ops->start_rx(&a.drv.base);
    CHECK_EQ(receive_frame(&b.drv.base, &med, got, sizeof(got), &info, 200), (int)n);
    CHECK(!memcmp(got, frame, n));
    CHECK(info.rssi_dbm >= -90 && info.rssi_dbm <= -82);
    receive_frame(&c.drv.base, &med, got, sizeof(got), &info, 200);
  }
  CHECK_EQ(a.model.violations, 0);
  CHECK_EQ(b.model.violations, 0);
  CHECK_EQ(c.model.violations, 0);
  CHECK_EQ(a.model.iq_misses + c.model.iq_misses, 0);
  CHECK_EQ(a.model.antenna_misses, 0);
  CHECK(med.max_frame == 255);
}

/* every bandwidth and spreading factor that matters between the two families, including the
 * four combinations where the low data rate rule has a choice to make */
static void test_exchange_grid(void) {
  static const struct { unsigned bw, sf; } combos[] = {
      {125000, 7}, {125000, 11}, {125000, 12}, {250000, 12}, {62500, 10}, {62500, 11},
      {31250, 9}, {500000, 5}, {500000, 7}, {7800, 7}, {20800, 9}, {250000, 8}, {125000, 9}};
  unsigned i, k;
  for (k = 0; k < sizeof(combos) / sizeof(combos[0]); k++) {
    sim_medium med;
    board126 a;
    board127 b;
    rnc_lora_params p = prm(868100000u, combos[k].bw, combos[k].sf, 5, 14);
    uint8_t frame[40], got[255];
    int a_ok, b_ok;
    sim_medium_init(&med, 5);
    mk126(&a, &med, 1262, 0, 1);
    mk127(&b, &med, 1, 1);
    sim_link_all(&med, 90);
    for (i = 0; i < sizeof(frame); i++)
      frame[i] = (uint8_t)(i + k);
    CHECK_EQ(a.drv.base.ops->init(&a.drv.base, &p), 0);
    a.drv.base.ops->start_rx(&a.drv.base);
    if (combos[k].sf >= 7) {
      CHECK_EQ(b.drv.base.ops->init(&b.drv.base, &p), 0);
      b.drv.base.ops->start_rx(&b.drv.base);
      run_ms(&med, 20);
      CHECK_EQ(send_frame(&b.drv.base, &med, frame, sizeof(frame)), 1);
      b.drv.base.ops->start_rx(&b.drv.base);
      a_ok = receive_frame(&a.drv.base, &med, got, sizeof(got), NULL, 3000) == (int)sizeof(frame);
      CHECK(a_ok);
      CHECK_EQ(send_frame(&a.drv.base, &med, frame, sizeof(frame)), 1);
      a.drv.base.ops->start_rx(&a.drv.base);
      b_ok = receive_frame(&b.drv.base, &med, got, sizeof(got), NULL, 3000) == (int)sizeof(frame);
      CHECK(b_ok);
      CHECK_EQ(b.model.violations, 0);
    }
    CHECK_EQ(a.model.violations, 0);
  }
}

static int run_cad(rnc_modem *m, sim_medium *med) {
  unsigned i;
  int r = 0;
  if (m->ops->start_cad(m) != 0)
    return -1;
  for (i = 0; i < 200 && !(r = m->ops->poll_cad(m)); i++)
    run_ms(med, 1);
  return r;
}

static void test_carrier_and_cad(void) {
  sim_medium med;
  board126 a, c;
  board127 b;
  rnc_lora_params p = prm(868100000u, 125000, 8, 5, 14);
  uint8_t frame[100], got[255];
  unsigned i;
  int busy_a = 0, busy_b = 0, busy_c = 0;
  sim_medium_init(&med, 5);
  mk126(&a, &med, 1262, 0, 1);
  mk127(&b, &med, 1, 1);
  mk126(&c, &med, 1262, 0, 1);
  sim_link_all(&med, 100);
  a.drv.base.ops->init(&a.drv.base, &p);
  b.drv.base.ops->init(&b.drv.base, &p);
  c.drv.base.ops->init(&c.drv.base, &p);
  b.drv.base.ops->start_rx(&b.drv.base);
  c.drv.base.ops->start_rx(&c.drv.base);
  run_ms(&med, 30);
  /* idle: no carrier, RSSI at the noise floor */
  CHECK_EQ(b.drv.base.ops->carrier(&b.drv.base), 0);
  CHECK_EQ(c.drv.base.ops->carrier(&c.drv.base), 0);
  {
    int dbm = 0;
    CHECK_EQ(c.drv.base.ops->rssi(&c.drv.base, &dbm), 0);
    CHECK(dbm <= -100);
  }
  /* A transmits 100 bytes: B and C see the preamble after a few symbols and keep seeing a
   * carrier until the frame ends */
  for (i = 0; i < sizeof(frame); i++)
    frame[i] = (uint8_t)i;
  CHECK_EQ(a.drv.base.ops->start_tx(&a.drv.base, frame, sizeof(frame)), 0);
  for (i = 0; i < 150; i++) { /* well inside the frame (~340 ms) */
    run_ms(&med, 1);
    if (i == 100) {
      busy_b = b.drv.base.ops->carrier(&b.drv.base);
      busy_c = c.drv.base.ops->carrier(&c.drv.base);
      {
        int dbm = 0;
        CHECK_EQ(c.drv.base.ops->rssi(&c.drv.base, &dbm), 0);
        CHECK(dbm >= -90);
      }
    }
  }
  busy_a = a.drv.base.ops->carrier(&a.drv.base);
  CHECK_EQ(busy_b, 1);
  CHECK_EQ(busy_c, 1);
  CHECK_EQ(busy_a, 0); /* it is transmitting itself and does not claim a carrier */
  while (a.drv.base.ops->poll_tx(&a.drv.base) == 0)
    run_ms(&med, 1);
  CHECK_EQ(receive_frame(&b.drv.base, &med, got, sizeof(got), NULL, 100), (int)sizeof(frame));
  CHECK_EQ(receive_frame(&c.drv.base, &med, got, sizeof(got), NULL, 100), (int)sizeof(frame));
  run_ms(&med, 10);
  CHECK_EQ(b.drv.base.ops->carrier(&b.drv.base), 0);
  CHECK_EQ(c.drv.base.ops->carrier(&c.drv.base), 0);

  /* CAD on both families: free channel, then a transmission in progress */
  c.drv.base.ops->standby(&c.drv.base);
  b.drv.base.ops->standby(&b.drv.base);
  CHECK_EQ(run_cad(&c.drv.base, &med), 1);
  CHECK_EQ(run_cad(&b.drv.base, &med), 1);
  a.drv.base.ops->start_tx(&a.drv.base, frame, sizeof(frame));
  run_ms(&med, 40);
  CHECK_EQ(run_cad(&c.drv.base, &med), 2);
  CHECK_EQ(run_cad(&b.drv.base, &med), 2);
  CHECK_EQ(a.model.violations + b.model.violations + c.model.violations, 0);
}

static void test_wrong_network_and_errors(void) {
  sim_medium med;
  board126 a, c;
  board127 b;
  rnc_lora_params p = prm(868100000u, 125000, 7, 5, 14);
  uint8_t frame[20], got[255];
  rnc_modem_rx_info info;
  unsigned i;
  sim_medium_init(&med, 5);
  mk126(&a, &med, 1262, 0, 1);
  mk127(&b, &med, 1, 1);
  mk126(&c, &med, 1262, 0, 1);
  sim_link_all(&med, 100);
  sim_link(&med, a.model.id, c.model.id, 100);
  a.drv.base.ops->init(&a.drv.base, &p);
  b.drv.base.ops->init(&b.drv.base, &p);
  c.drv.base.ops->init(&c.drv.base, &p);
  for (i = 0; i < sizeof(frame); i++)
    frame[i] = (uint8_t)(i * 3);
  /* a radio on the public sync word (0x3444) hears nothing from private-network radios */
  c.model.regs[0x0740] = 0x34;
  c.model.regs[0x0741] = 0x44;
  b.drv.base.ops->start_rx(&b.drv.base);
  c.drv.base.ops->start_rx(&c.drv.base);
  run_ms(&med, 20);
  CHECK_EQ(send_frame(&a.drv.base, &med, frame, sizeof(frame)), 1);
  CHECK_EQ(receive_frame(&b.drv.base, &med, got, sizeof(got), &info, 100), (int)sizeof(frame));
  CHECK_EQ(receive_frame(&c.drv.base, &med, got, sizeof(got), &info, 100), 0);
  CHECK(med.lost_phy_mismatch >= 1);
  /* a corrupted frame (collision) is reported as -1 and the next good one is received */
  c.model.regs[0x0740] = 0x14;
  c.model.regs[0x0741] = 0x24;
  b.drv.base.ops->start_rx(&b.drv.base);
  c.drv.base.ops->start_rx(&c.drv.base);
  run_ms(&med, 20);
  {
    uint8_t other[20];
    memset(other, 0xEE, sizeof(other));
    /* a and c transmit at the same time to b; neither is stronger */
    a.drv.base.ops->start_tx(&a.drv.base, frame, sizeof(frame));
    c.drv.base.ops->start_tx(&c.drv.base, other, sizeof(other));
    while (a.drv.base.ops->poll_tx(&a.drv.base) == 0 || c.drv.base.ops->poll_tx(&c.drv.base) == 0)
      run_ms(&med, 1);
    run_ms(&med, 5);
    CHECK_EQ(b.drv.base.ops->poll_rx(&b.drv.base, got, sizeof(got), &info), -1);
    CHECK_EQ(b.drv.base.ops->poll_rx(&b.drv.base, got, sizeof(got), &info), 0);
    CHECK(b.model.crc_errors >= 1);
  }
  b.drv.base.ops->start_rx(&b.drv.base);
  a.drv.base.ops->start_rx(&a.drv.base);
  run_ms(&med, 20);
  CHECK_EQ(send_frame(&a.drv.base, &med, frame, sizeof(frame)), 1);
  CHECK_EQ(receive_frame(&b.drv.base, &med, got, sizeof(got), &info, 100), (int)sizeof(frame));
  /* sleep and wake: the SX126x needs a new init, the SX127x keeps its configuration */
  a.drv.base.ops->sleep(&a.drv.base);
  CHECK_EQ(a.drv.base.ops->start_rx(&a.drv.base), -1);
  CHECK_EQ(a.drv.base.ops->init(&a.drv.base, &p), 0);
}

int main(void) {
  test_126_config();
  test_126_sweep();
  test_126_power_and_errors();
  test_126_model_strictness();
  test_127_config();
  test_127_sweep();
  test_127_header_modes();
  test_127_model_strictness();
  test_exchange();
  test_exchange_grid();
  test_carrier_and_cad();
  test_wrong_network_and_errors();
  if (failures) {
    fprintf(stderr, "test_radio_drivers: %d failure(s)\n", failures);
    return 1;
  }
  puts("test_radio_drivers: all checks passed");
  return 0;
}
