#ifndef RETICULUM_C_NETSTAMP_H
#define RETICULUM_C_NETSTAMP_H
#include <reticulum_c/rnc.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Network stamps, as RNS 1.6 uses them on announces, path requests and link requests (RNS.Stamps).
 * A cost is fractional: 8 bits of fixed point, capped at 100. A stamp meets a cost when
 * SHA-256(material || stamp), read as a 256 bit big-endian integer, does not exceed the target for that
 * cost. The workblock is the material itself (no expansion), as for announces and path requests.
 * These functions are unrelated to the discovery stamps of rnc_stamp.h, which keep their own rules. */
#define RNC_NETSTAMP_SIZE 14u
#define RNC_NETSTAMP_COST_CAP 100
#define RNC_NETSTAMP_LINK_COST_CAP 40
/* cost_to_fp: floor(cost * 256 + 0.5) clamped to 0..100*256; NaN gives 0. */
uint16_t rnc_netstamp_cost_to_fp(double cost);
double rnc_netstamp_cost_from_fp(uint16_t fp);
/* The two byte wire form: integer part, then 1/256ths. */
void rnc_netstamp_cost_to_bytes(double cost, uint8_t out[2]);
double rnc_netstamp_cost_from_bytes(const uint8_t in[2]);
double rnc_netstamp_quantize(double cost);
/* Entry f of the authoritative mantissa table (0 for f > 255 except 256, which is 0 as well). */
uint64_t rnc_netstamp_table(size_t index);
/* 1 when the stamp meets the cost. stamp_size is RNC_NETSTAMP_SIZE for detached stamps, 32 for a stamped
 * X25519 public key. 0 on any error. */
int rnc_netstamp_valid(const void *material, size_t material_size, const void *stamp,
                       size_t stamp_size, double cost);
/* The stamp's value on the cost grid (RNS.Stamps.stamp_value); 0 on error. */
double rnc_netstamp_value(const void *material, size_t material_size, const void *stamp,
                          size_t stamp_size);
#ifdef __cplusplus
}
#endif
#endif
