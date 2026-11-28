#ifndef RNC_BATTERY_H
#define RNC_BATTERY_H
/* A single LiPo cell judged by its voltage, for boards without a fuel gauge. The figures are rough: voltage
 * depends on load and temperature as well as charge. States are the RNode protocol's: 1 discharging, 2 charging,
 * 3 charged. */
#include <stdint.h>

/* millivolts at the cell from a reading of `bits` bits against `reference_mv`, behind a divider of `divider` */
static inline unsigned rnc_adc_millivolts(unsigned raw, unsigned bits, unsigned reference_mv, unsigned divider) {
  return (unsigned)(((uint64_t)raw * reference_mv * divider) >> bits);
}

static inline unsigned rnc_lipo_percent(unsigned millivolts) {
  static const uint16_t curve[][2] = {{3300, 0},  {3500, 6},  {3600, 13}, {3700, 30},
                                      {3800, 55}, {3900, 72}, {4000, 85}, {4150, 100}};
  unsigned i;
  if (millivolts <= curve[0][0])
    return 0;
  for (i = 1; i < sizeof(curve) / sizeof(curve[0]); ++i)
    if (millivolts <= curve[i][0])
      return curve[i - 1][1] + (millivolts - curve[i - 1][0]) * (unsigned)(curve[i][1] - curve[i - 1][1]) /
                                   (unsigned)(curve[i][0] - curve[i - 1][0]);
  return 100;
}

/* `external_power`: USB is connected. -1 when the voltage says no cell is there. */
static inline int rnc_lipo_battery(unsigned millivolts, int external_power, unsigned *state, unsigned *percent) {
  if (millivolts < 2500)
    return -1;
  *percent = rnc_lipo_percent(millivolts);
  *state = !external_power ? 1u : millivolts >= 4150 ? 3u : 2u;
  return 0;
}
#endif
