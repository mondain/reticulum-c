#ifndef RNC_AXP2101_H
#define RNC_AXP2101_H
#include <stdint.h>
/* T-Beam Supreme radio rail: AXP2101 ALDO3, 3.3 V. Register layout and voltage
 * encoding follow XPowersLib's AXP2101 definitions (500 mV + 100 mV/step).
 * Do not alter the CPU supply or any other peripheral rail. */
static inline int rnc_axp2101_enable_radio(void *context,
    int (*read_reg)(void *, uint8_t, uint8_t *),
    int (*write_reg)(void *, uint8_t, uint8_t)) {
  uint8_t id, voltage, enabled, check;
  if (!read_reg || !write_reg || read_reg(context, 0x03, &id) != 0 || id != 0x4a)
    return -1;
  if (read_reg(context, 0x94, &voltage) != 0 ||
      write_reg(context, 0x94, (uint8_t)((voltage & 0xe0u) | 28u)) != 0 ||
      read_reg(context, 0x94, &check) != 0 || (check & 0x1fu) != 28u)
    return -1;
  if (read_reg(context, 0x90, &enabled) != 0 ||
      write_reg(context, 0x90, (uint8_t)(enabled | 0x04u)) != 0 ||
      read_reg(context, 0x90, &check) != 0 || !(check & 0x04u))
    return -1;
  return 0;
}
/* The AXP2101's own account of the battery, read only (XPowersLib: STATUS1 bit 3 battery present, STATUS2 bits 7:5
 * 1 charging, 2 discharging, 0 standby, its low three bits 4 when charging is done, 0xA4 the fuel gauge's percent).
 * States as the RNode protocol has them: 0 unknown, 1 discharging, 2 charging, 3 charged. -1: nothing to report. */
static inline int rnc_axp2101_battery(void *context, int (*read_reg)(void *, uint8_t, uint8_t *), unsigned *state,
                                      unsigned *percent) {
  uint8_t status1, status2, level;
  if (!read_reg || read_reg(context, 0x00, &status1) != 0 || !(status1 & 0x08u) ||
      read_reg(context, 0x01, &status2) != 0 || read_reg(context, 0xa4, &level) != 0 || level > 100u)
    return -1;
  *percent = level;
  *state = (status2 >> 5) == 1u ? 2u : (status2 >> 5) == 2u ? 1u : (status2 & 0x07u) == 4u ? 3u : 0u;
  return 0;
}
#endif
