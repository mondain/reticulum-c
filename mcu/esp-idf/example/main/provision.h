#ifndef PROVISION_H
#define PROVISION_H
/* Runtime provisioning over the serial port: a line console that edits the settings in
 * the "rnccfg" NVS partition (mode, ssid, password, host, port). See mcu/README.txt.
 *
 * The console is NOT always on. It runs when
 *   - the board is in Wi-Fi mode and the stored settings cannot start a connection, or
 *   - during the short window after every boot, when the line  rnc-config  arrives on
 *     the serial port or the BOOT button is pressed and held for a third of a second
 *     (the button is read after the chip started; holding it while resetting selects
 *     the ROM download mode, which is a different thing).
 * While it runs, the Reticulum node does not. */
#include "rnc_mcu_net.h"

/* Waits up to `window_ms` for a request to enter the console. 0 disables the window.
 * `button_gpio` < 0 disables the button. Returns 1 when requested. */
int provision_requested(unsigned window_ms, int button_gpio);

/* Runs the console until reboot; does not return. `reason` is shown in the banner. */
void provision_console(rnc_mcu_cfg *cfg, const char *reason);
#endif
