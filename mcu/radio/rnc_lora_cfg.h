#ifndef RNC_LORA_CFG_H
#define RNC_LORA_CFG_H
/*
 * LoRa radio settings of the firmware: parsing, validation and printing. Header only,
 * C and C++, no platform headers; the ports store the fields (NVS, Preferences) and the
 * console (rnc_mcu_net.h) edits them as the keys lora.mode, lora.freq, lora.bw, lora.sf,
 * lora.cr, lora.txp and lora.airtime.
 *
 * REGULATORY SAFETY. There are no default transmit settings. The radio stays off
 * (never transmits, never receives) until the mode is leaf or gateway AND frequency,
 * bandwidth, spreading factor, coding rate and transmit power have all been set
 * explicitly. Only the airtime budget has a default: 1 percent of every hour, a value
 * chosen to be low. The operator is responsible for a legal frequency, power and duty
 * cycle where the board is used (and for the antenna: the power is at the chip's output).
 */
#include "rnc_lora_phy.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RNC_LORA_MODE_OFF 0u     /* no radio (the default) */
#define RNC_LORA_MODE_LEAF 1u    /* LoRa is the only interface; no forwarding */
#define RNC_LORA_MODE_GATEWAY 2u /* the serial or Wi-Fi interface plus LoRa, transport on */

#define RNC_LORA_SET_FREQ 0x01u
#define RNC_LORA_SET_BW 0x02u
#define RNC_LORA_SET_SF 0x04u
#define RNC_LORA_SET_CR 0x08u
#define RNC_LORA_SET_TXP 0x10u
#define RNC_LORA_SET_ALL 0x1Fu

#define RNC_LORA_AIRTIME_DEFAULT 100u /* hundredths of a percent: 1.00 % */

typedef struct rnc_lora_cfg {
  uint8_t mode;       /* RNC_LORA_MODE_* */
  uint8_t set;        /* RNC_LORA_SET_* bits: which fields were set explicitly */
  uint8_t sf, cr;     /* cr: denominator 5..8 */
  int8_t txp_dbm;
  uint16_t airtime;   /* hundredths of a percent per hour, 1..10000 */
  uint32_t freq_hz, bw_hz;
} rnc_lora_cfg;

static inline void rnc_lora_cfg_init(rnc_lora_cfg *c) {
  memset(c, 0, sizeof(*c));
  c->airtime = RNC_LORA_AIRTIME_DEFAULT;
}

/* 1 when the radio may run: a mode other than off and every transmit setting set. */
static inline int rnc_lora_cfg_ready(const rnc_lora_cfg *c) {
  return c->mode != RNC_LORA_MODE_OFF && (c->set & RNC_LORA_SET_ALL) == RNC_LORA_SET_ALL;
}

static inline void rnc_lora_cfg_params(const rnc_lora_cfg *c, rnc_lora_params *p) {
  memset(p, 0, sizeof(*p));
  p->freq_hz = c->freq_hz;
  p->bw_hz = c->bw_hz;
  p->sf = c->sf;
  p->cr = c->cr;
  p->txp_dbm = c->txp_dbm;
}

/* "123456" -> 123456 (digits only, at most 10), else -1 */
static inline int64_t rnc_lora_cfg_uint(const char *s) {
  int64_t v = 0;
  size_t i, n = strlen(s);
  if (n == 0 || n > 10)
    return -1;
  for (i = 0; i < n; i++) {
    if (s[i] < '0' || s[i] > '9')
      return -1;
    v = v * 10 + (s[i] - '0');
  }
  return v;
}
/* Decimal with at most `places` digits after the point, scaled: "868.1" with places 6 ->
 * 868100000; -1 on a malformed value. */
static inline int64_t rnc_lora_cfg_decimal(const char *s, unsigned places) {
  int64_t whole = 0, frac = 0;
  size_t i = 0, n = strlen(s), digits = 0;
  unsigned seen = 0;
  int point = 0;
  if (n == 0 || n > 14)
    return -1;
  for (; i < n; i++) {
    if (s[i] == '.' && !point) {
      point = 1;
    } else if (s[i] >= '0' && s[i] <= '9') {
      digits++;
      if (!point) {
        whole = whole * 10 + (s[i] - '0');
      } else {
        if (seen >= places)
          return -1;
        frac = frac * 10 + (s[i] - '0');
        seen++;
      }
    } else {
      return -1;
    }
  }
  if (!digits)
    return -1;
  for (; seen < places; seen++)
    frac *= 10;
  {
    int64_t scale = 1;
    unsigned k;
    for (k = 0; k < places; k++)
      scale *= 10;
    return whole * scale + frac;
  }
}

/* Sets one field from its text; `key` is the name without "lora." (mode, freq, bw, sf, cr,
 * txp, airtime). Returns 0, or -1 for a refused value or unknown key (nothing changes).
 *   mode     off | leaf | gateway
 *   freq     Hz (868100000) or MHz with a decimal point (868.1); 137 to 1020 MHz
 *   bw       Hz (125000) or kHz below 1000 (125, 62.5, 7.8); one of the ten chip bandwidths
 *   sf       5..12
 *   cr       5..8 (the denominator of 4/5 .. 4/8), or written 4/5 .. 4/8
 *   txp      dBm at the chip output, -9..22
 *   airtime  percent of an hour, 0.01 to 100 (default 1)
 * Whether the board's chip supports the value is checked when the radio starts. */
static inline int rnc_lora_cfg_set(rnc_lora_cfg *c, const char *key, const char *value) {
  int64_t v;
  if (!strcmp(key, "mode")) {
    if (!strcmp(value, "off"))
      c->mode = RNC_LORA_MODE_OFF;
    else if (!strcmp(value, "leaf"))
      c->mode = RNC_LORA_MODE_LEAF;
    else if (!strcmp(value, "gateway"))
      c->mode = RNC_LORA_MODE_GATEWAY;
    else
      return -1;
  } else if (!strcmp(key, "freq")) {
    v = strchr(value, '.') ? rnc_lora_cfg_decimal(value, 6) : rnc_lora_cfg_uint(value);
    if (v < 137000000 || v > 1020000000)
      return -1;
    c->freq_hz = (uint32_t)v;
    c->set |= RNC_LORA_SET_FREQ;
  } else if (!strcmp(key, "bw")) {
    if (strchr(value, '.')) {
      v = rnc_lora_cfg_decimal(value, 2); /* kHz with up to two decimals */
      if (v > 0)
        v *= 10;
    } else {
      v = rnc_lora_cfg_uint(value);
      if (v > 0 && v < 1000)
        v *= 1000;
    }
    /* nominal bandwidths: 7.8 and 7.81 mean the same chip setting */
    if (v == 7810) v = 7800;
    if (v == 10420) v = 10400;
    if (v == 15630) v = 15600;
    if (v == 20830) v = 20800;
    if (v == 41670) v = 41700;
    if (v < 0 || rnc_lora_bw_index((uint32_t)v) < 0)
      return -1;
    c->bw_hz = (uint32_t)v;
    c->set |= RNC_LORA_SET_BW;
  } else if (!strcmp(key, "sf")) {
    v = rnc_lora_cfg_uint(value);
    if (v < 5 || v > 12)
      return -1;
    c->sf = (uint8_t)v;
    c->set |= RNC_LORA_SET_SF;
  } else if (!strcmp(key, "cr")) {
    if (!strncmp(value, "4/", 2))
      value += 2;
    v = rnc_lora_cfg_uint(value);
    if (v < 5 || v > 8)
      return -1;
    c->cr = (uint8_t)v;
    c->set |= RNC_LORA_SET_CR;
  } else if (!strcmp(key, "txp")) {
    int neg = value[0] == '-';
    v = rnc_lora_cfg_uint(value + neg);
    if (v < 0 || (neg ? v > 9 : v > 22))
      return -1;
    c->txp_dbm = (int8_t)(neg ? -v : v);
    c->set |= RNC_LORA_SET_TXP;
  } else if (!strcmp(key, "airtime")) {
    v = rnc_lora_cfg_decimal(value, 2);
    if (v < 1 || v > 10000)
      return -1;
    c->airtime = (uint16_t)v;
  } else {
    return -1;
  }
  return 0;
}

static inline void rnc_lora_cfg_line(char *t, size_t cap, size_t *n, const char *key,
                                     const char *sel, const char *value) {
  int w;
  if (sel && *sel && strcmp(sel, key))
    return;
  if (*n >= cap)
    return;
  w = snprintf(t + *n, cap - *n, "%slora.%s=%s", *n ? "\n" : "", key, value);
  if (w > 0)
    *n += (size_t)w < cap - *n ? (size_t)w : cap - *n - 1u;
}

/* Writes "lora.key=value" (or "lora.key=(not set)") for one key, or every key one per
 * line when `key` is NULL or empty. */
static inline void rnc_lora_cfg_get(const rnc_lora_cfg *c, const char *key, char *out,
                                    size_t size) {
  char t[256], v[24];
  size_t n = 0;
  t[0] = 0;
  rnc_lora_cfg_line(t, sizeof(t), &n, "mode", key,
                    c->mode == RNC_LORA_MODE_LEAF      ? "leaf"
                    : c->mode == RNC_LORA_MODE_GATEWAY ? "gateway"
                                                       : "off");
  (void)snprintf(v, sizeof(v), "%lu", (unsigned long)c->freq_hz);
  rnc_lora_cfg_line(t, sizeof(t), &n, "freq", key, (c->set & RNC_LORA_SET_FREQ) ? v : "(not set)");
  (void)snprintf(v, sizeof(v), "%lu", (unsigned long)c->bw_hz);
  rnc_lora_cfg_line(t, sizeof(t), &n, "bw", key, (c->set & RNC_LORA_SET_BW) ? v : "(not set)");
  (void)snprintf(v, sizeof(v), "%u", (unsigned)c->sf);
  rnc_lora_cfg_line(t, sizeof(t), &n, "sf", key, (c->set & RNC_LORA_SET_SF) ? v : "(not set)");
  (void)snprintf(v, sizeof(v), "%u", (unsigned)c->cr);
  rnc_lora_cfg_line(t, sizeof(t), &n, "cr", key, (c->set & RNC_LORA_SET_CR) ? v : "(not set)");
  (void)snprintf(v, sizeof(v), "%d", (int)c->txp_dbm);
  rnc_lora_cfg_line(t, sizeof(t), &n, "txp", key, (c->set & RNC_LORA_SET_TXP) ? v : "(not set)");
  (void)snprintf(v, sizeof(v), "%u.%02u", (unsigned)(c->airtime / 100u),
                 (unsigned)(c->airtime % 100u));
  rnc_lora_cfg_line(t, sizeof(t), &n, "airtime", key, v);
  if (!n)
    (void)snprintf(t, sizeof(t), "error: unknown key");
  (void)snprintf(out, size, "%s", t);
}

#ifdef __cplusplus
}
#endif
#endif
