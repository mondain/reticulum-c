#ifndef RNC_LORA_PHY_H
#define RNC_LORA_PHY_H
/*
 * LoRa physical layer arithmetic shared by the drivers, the framing and the
 * interface adapter: parameter validation, symbol time, low data rate optimisation,
 * time on air (the Semtech formula, integer microseconds) and the bit rate that
 * Reticulum's RNode interface uses for announce and path timing.
 */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rnc_lora_params {
  uint32_t freq_hz;
  uint32_t bw_hz; /* 7800 10400 15600 20800 31250 41700 62500 125000 250000 500000 */
  uint8_t sf;     /* 5..12 (the SX127x supports 6..12) */
  uint8_t cr;     /* coding rate denominator 5..8 (4/5 .. 4/8) */
  int8_t txp_dbm; /* power at the chip's output */
  uint16_t preamble_symbols; /* 0 = rnc_lora_default_preamble() */
} rnc_lora_params;

#define RNC_LORA_SF_MIN 5u
#define RNC_LORA_SF_MAX 12u

/* The ten bandwidths the chips support, as nominal values: 7800 stands for 7.81 kHz,
 * 10400 for 10.42, 15600 for 15.63, 20800 for 20.83, 31250 for 31.25, 41700 for 41.67
 * and 62500 for 62.5 kHz (the names the RNode firmware and Reticulum use). Returns the
 * index 0..9 in increasing order, or -1. */
int rnc_lora_bw_index(uint32_t bw_hz);

/* Parameter validation: 0 when sane. `min_sf` is 5 (SX126x) or 6 (SX127x). */
int rnc_lora_params_check(const rnc_lora_params *p, unsigned min_sf);

/* Symbol duration in microseconds: 2^SF / BW. */
uint32_t rnc_lora_symbol_us(uint32_t bw_hz, unsigned sf);
/* 1 when the low data rate optimisation must be on: the symbol time exceeds 16 ms
 * (the rule of both chips' datasheets). */
int rnc_lora_ldro(uint32_t bw_hz, unsigned sf);
/* Preamble length used when the configuration gives none: at least 18 symbols and
 * long enough to cover 24 ms (6 ms above 30 kbit/s); see PROVENANCE.md. */
unsigned rnc_lora_default_preamble(uint32_t bw_hz, unsigned sf, unsigned cr);

/* Time on air in microseconds of one LoRa frame (explicit header, CRC on) of
 * `payload` bytes, by the Semtech formula (SX1276 datasheet "Time on air"; SX1261/2
 * datasheet 6.1.4): preamble N + 4.25 symbols (6.25 for SF5 and SF6), then 8 + max(
 * ceil((8 PL - 4 SF + 28 + 16 CRC) / (4 (SF - 2 DE))) (CR + 4), 0) symbols, DE = low
 * data rate optimisation. For SF5/SF6 the SX126x datasheet drops the "+ 8" of the
 * numerator (the header term alone is 20). */
uint64_t rnc_lora_toa_us(const rnc_lora_params *p, size_t payload);

/* Bits per second of the interface for Reticulum's announce and path timing:
 * SF * (4 / CR) / (2^SF / BW), rounded, at least 1 (the figure the RNode interface of
 * the host SDK and of the reference stack compute). */
uint32_t rnc_lora_bitrate(const rnc_lora_params *p);

/* Total time on air of a Reticulum packet of `size` bytes as the air framing sends it
 * (one frame up to 254 bytes, else two frames). */
uint64_t rnc_lora_packet_toa_us(const rnc_lora_params *p, size_t size);

#ifdef __cplusplus
}
#endif
#endif
