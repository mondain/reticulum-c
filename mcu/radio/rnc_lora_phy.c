/* LoRa physical layer arithmetic; see rnc_lora_phy.h. Portable C, no platform headers. */
#include "rnc_lora_phy.h"

/* nominal value (what configurations and Reticulum use) and the exact bandwidth in
 * millihertz (what the symbol time is made of) */
static const struct {
  uint32_t nominal;
  uint64_t exact_mhz;
} BW[10] = {{7800u, 7812500u},     {10400u, 10416667u},   {15600u, 15625000u},
            {20800u, 20833333u},   {31250u, 31250000u},   {41700u, 41666667u},
            {62500u, 62500000u},   {125000u, 125000000u}, {250000u, 250000000u},
            {500000u, 500000000u}};

int rnc_lora_bw_index(uint32_t bw_hz) {
  int i;
  for (i = 0; i < 10; i++)
    if (BW[i].nominal == bw_hz)
      return i;
  return -1;
}

int rnc_lora_params_check(const rnc_lora_params *p, unsigned min_sf) {
  if (!p || rnc_lora_bw_index(p->bw_hz) < 0)
    return -1;
  if (p->sf < min_sf || p->sf > RNC_LORA_SF_MAX || p->cr < 5u || p->cr > 8u)
    return -1;
  if (p->freq_hz < 137000000u || p->freq_hz > 1020000000u)
    return -1;
  return 0;
}

uint32_t rnc_lora_symbol_us(uint32_t bw_hz, unsigned sf) {
  int i = rnc_lora_bw_index(bw_hz);
  uint64_t num;
  if (i < 0 || sf > 16u)
    return 0;
  num = (UINT64_C(1) << sf) * UINT64_C(1000000000);
  return (uint32_t)((num + BW[i].exact_mhz / 2u) / BW[i].exact_mhz);
}

/* The rule the RNode firmware applies (integer arithmetic on the nominal bandwidth
 * in kHz: 2^SF / (BW / 1000) > 16) rather than "symbol time above 16 ms". The two
 * differ where the symbol time is 16.384 ms (SF12 at 250 kHz, SF11 at 125 kHz, SF10
 * at 62.5 kHz, SF9 at 31.25 kHz): the firmware leaves the optimisation off there,
 * and as the explicit LoRa header carries no flag for it, a different choice would
 * make the two ends unable to decode each other. */
int rnc_lora_ldro(uint32_t bw_hz, unsigned sf) {
  uint32_t khz = bw_hz / 1000u;
  if (!khz || sf > 16u)
    return 0;
  return ((UINT32_C(1) << sf) / khz) > 16u;
}

unsigned rnc_lora_default_preamble(uint32_t bw_hz, unsigned sf, unsigned cr) {
  uint32_t sym = rnc_lora_symbol_us(bw_hz, sf);
  rnc_lora_params p;
  uint64_t target_us;
  unsigned n;
  p.freq_hz = 868000000u;
  p.bw_hz = bw_hz;
  p.sf = (uint8_t)sf;
  p.cr = (uint8_t)cr;
  p.txp_dbm = 0;
  p.preamble_symbols = 0;
  target_us = rnc_lora_bitrate(&p) > 30000u ? 6000u : 24000u;
  if (!sym)
    return 18u;
  n = (unsigned)((target_us + sym - 1u) / sym);
  return n < 18u ? 18u : n;
}

uint64_t rnc_lora_toa_us(const rnc_lora_params *p, size_t payload) {
  int i = rnc_lora_bw_index(p->bw_hz);
  int64_t sf = p->sf, de = rnc_lora_ldro(p->bw_hz, p->sf), cr = p->cr;
  int64_t num, den, blocks, symbols_q4;
  uint64_t preamble;
  if (i < 0 || p->sf < 5u || p->sf > 12u || p->cr < 5u || p->cr > 8u)
    return 0;
  preamble = p->preamble_symbols ? p->preamble_symbols
                                 : rnc_lora_default_preamble(p->bw_hz, p->sf, p->cr);
  if (sf >= 7)
    num = 8 * (int64_t)payload - 4 * sf + 28 + 16;
  else
    num = 8 * (int64_t)payload - 4 * sf + 20 + 16;
  den = 4 * (sf - 2 * de);
  blocks = num > 0 ? (num + den - 1) / den : 0;
  /* quarter symbols: preamble + 4.25 (6.25 for SF5/SF6), then the payload symbols */
  symbols_q4 = (int64_t)preamble * 4 + (sf >= 7 ? 17 : 25) + (8 + blocks * (cr)) * 4;
  /* time = symbols * 2^SF / BW, bandwidth in millihertz; rounded up, so a budget made
   * of these figures is never short */
  {
    uint64_t div = 4u * BW[i].exact_mhz;
    uint64_t t = (uint64_t)symbols_q4 * (UINT64_C(1) << p->sf) * UINT64_C(1000000000);
    return (t + div - 1u) / div;
  }
}

uint32_t rnc_lora_bitrate(const rnc_lora_params *p) {
  uint64_t den, rate;
  if (!p || p->sf < 5u || p->sf > 12u || p->cr < 5u || p->cr > 8u)
    return 1u;
  den = (uint64_t)p->cr << p->sf;
  rate = ((uint64_t)p->sf * 4u * p->bw_hz + den / 2u) / den;
  return rate ? (uint32_t)rate : 1u;
}

uint64_t rnc_lora_packet_toa_us(const rnc_lora_params *p, size_t size) {
  if (size <= 254u)
    return rnc_lora_toa_us(p, size + 1u);
  return rnc_lora_toa_us(p, 255u) + rnc_lora_toa_us(p, size - 254u + 1u);
}
