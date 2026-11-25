# Status screens for the T-Echo and the T-Beam Supreme: design

Status: approved 2026-11-14 (with the builder-check calls of section 6.6). Built and checked on the T-Echo and the Supreme on 2026-11-15 (see mcu/README.md). Stacked on
feature/rnode-mode (PR #43): it uses that branch's Bluetooth PIN and RNode module.

## 1. Intent

Both LilyGo boards have a screen that this firmware leaves blank. The owner wants them to
show the Bluetooth PIN (so a phone can pair without a computer) and the radio status (is
it on, on what settings, is anything arriving), at a glance. Nothing else was asked for.

## 2. Goals

- A status screen on the T-Echo (e-paper) and on the T-Beam Supreme (OLED), in every run
  mode (serial, wifi, leaf, gateway, rnode): mode, radio on or off and its settings,
  last signal (RSSI, SNR), packet counts, airtime used, which host link is up (USB or
  Bluetooth), firmware version.
- The Bluetooth PIN is shown only while it is needed: Bluetooth is on (a PIN is set) and
  no authenticated link exists. It is hidden once a phone has paired and connected, and
  never shown when no PIN is set.
- One status record filled in by the firmware and one text layout of it, in portable C
  with host unit tests, so the same words appear on both screens and the rules (above all
  the PIN rule) are tested without hardware.
- Known-good libraries for the drawing: GxEPD2 for the e-paper, Adafruit SH110X for the
  OLED, both on Adafruit GFX, so one routine draws on either.
- Only the two environments with these screens build the display code and its libraries;
  every other environment is unchanged.

## 3. Non-goals

- No buttons, menus, touch, graphics, QR codes, icons, GPS, battery or clock pages.
- No host-pushed images (the RNode display protocol), no sleep or low-power display
  management, no backlight control.
- Not the other boards that have screens (T3-S3, Heltec boards); the interface allows
  them later. (Added 2026-11-25: the Heltec WiFi LoRa 32 V3 now shows the same page, on its
  SSD1306 OLED, with RNC_DISPLAY_SSD1306.)
- The generic ESP-IDF image is untouched.

## 4. Anti-goals (a working result that would still be a failure)

- Display code that delays the radio, the serial stream or Bluetooth.
- The PIN left on screen while a paired phone is connected, or shown when no PIN is set.
- Any secret on screen other than the PIN (never the Wi-Fi password).
- A board whose screen fails to start losing its radio or USB function.

## 5. Approaches considered

A. Own drivers and a built-in font, no libraries: tiny, no downloads, but two fiddly
   drivers (the e-paper start-up and refresh sequences) to get right on hardware.

B. Libraries (GxEPD2, Adafruit SH110X, Adafruit GFX, BusIO): quickest to pixels and
   known-good, 50 to 100 KB of flash on the two environments, library downloads. CHOSEN
   by the owner.

## 6. Design

### 6.1 Hardware facts

(from the RNode firmware's Boards.h and Display.h, which also gives
this repo's radio pin numbers for both boards, so the source is consistent with
mcu/radio/rnc_boards.c; to be confirmed on the boards)

- T-Echo: GxEPD2_154_D67 e-paper (200 x 200 native), SPI: CS 30, DC 28, RESET 2, BUSY 3,
  SCK 31, MOSI 29, no MISO; VEXT (pin 12) is already driven high for the radio. The
  radio uses SPIM2 with the identity pin map; the display needs another SPIM instance.
- T-Beam Supreme: SH1106 128 x 64 OLED, I2C address 0x3C, SDA 17, SCL 18 (a second bus:
  the AXP2101 power chip is on 42/41). Whether the OLED needs a rail switched on through
  the AXP2101 is not known and is to be settled on the board.

### 6.2 Status record and layout (portable C, mcu/app)

- rnc_status: mode text, radio state (off, on), radio parameters (frequency, bandwidth,
  SF, CR, power), last RSSI and SNR with a "no signal yet" flag, rx and tx packet counts,
  airtime used (percent of the budget), host link (none, USB, Bluetooth), Bluetooth state
  (off, advertising, connected unauthenticated, authenticated), the PIN digits, the
  firmware version.
- rnc_status_layout(): turns it into at most 8 lines of at most 21 characters (the OLED
  size with a 6 x 8 font), fixed order, text truncated, no allocation. The PIN line
  appears only under the rule in section 2. The e-paper draws the same lines larger.
- Unit tests: every line for typical states, each Bluetooth state against the PIN rule,
  no signal yet, long values, exact frequency formatting.

### 6.3 Filling the record (firmware, mcu/platformio/src)

- rnode mode: from the RNode module (radio on, settings, counters) and the Bluetooth
  state (a new rnc_ble_state() in ble_mode.h with the four states above).
- node modes: from the settings (mode, lora settings) and the application statistics the
  firmware already keeps.
- A snapshot is taken in the radio task and handed over; the display task never touches
  radio or protocol state directly.

### 6.4 Display task and refresh

- One low-priority FreeRTOS task per board draws the layout with Adafruit GFX. Its work
  (an e-paper refresh blocks for seconds) can never hold up the radio task.
- OLED: redraw when the layout changed, at most once a second.
- E-paper: redraw when the layout changed, at most every 15 seconds, using partial
  refresh, plus a full refresh every 5 minutes to clear ghosting (the figures the RNode
  firmware uses). A change in whether the PIN is shown is drawn at once (at least 2
  seconds after the last refresh) because a person is waiting for it.
- If the screen does not initialise, the task ends and nothing else is affected.

### 6.5 Build

- lib_deps and a build flag only in the lilygo_t_echo and lilygo_t_beam_supreme
  environments; libraries pinned to exact versions. Other environments build without
  them. Flash and RAM use are recorded per environment.

### 6.6 Calls made after the builder check (answers from the repository, or the author's calls)

- Bluetooth state: nRF52840 reports "secured" from the Bluefruit connection
  (`Bluefruit.Connection(handle)->secured()` / the secured callback), ESP32 from the
  existing g_connected and g_secure flags. The UART characteristics refuse access until the
  link is encrypted and authenticated (SoftDevice and NimBLE attribute permissions;
  checked on the T-Echo from BlueZ: an unpaired central gets nothing). States: OFF (no PIN
  set, service not started), ADVERTISING (no central), CONNECTED (a central, not yet
  authenticated), SECURE. The PIN is visible in ADVERTISING and CONNECTED, hidden in OFF and
  SECURE. A bonded phone that reconnects is authenticated at once (its stored key encrypts
  the link), so the PIN does not appear for it; a pairing that is abandoned leaves the state
  CONNECTED, so the PIN stays visible until the link drops.
- Modes: the run mode is "serial", "wifi" or "rnode"; leaf and gateway are the separate
  lora.mode setting (off, leaf, gateway). The mode line shows RNode, or the transport
  (USB or WiFi) with the LoRa mode. Bluetooth is only started in rnode mode, so outside it
  the Bluetooth state is OFF and no PIN is ever shown. The host link is none, USB,
  Bluetooth or WiFi.
- Data: last RSSI and SNR, the rx and tx packet counts and the airtime budget come from
  the LoRa interface (rnc_lora_if stats and budget, rnc_airtime_used), which is the same
  object in every mode (g_radio.li). Airtime used is shown as a percentage of the budget.
  "No signal yet" means no packet received since boot.
- Reading: the display task reads these values directly, read-only, as aligned word reads;
  a snapshot that mixes values from two instants is acceptable for a status screen. It
  never writes to them. (This replaces the earlier "snapshot handed over" idea.)
- Phases: the record has a phase (starting, setup, running). The display task starts early
  in setup(), shows "reticulum-c VERSION / starting", shows "Setup mode / rnc-config console"
  while the boot setup console runs, and the status page once the firmware runs. A screen
  that fails to initialise ends its task silently. An e-paper that shows the last frame
  while the radio is off is fine.
- Version: RNC_MCU_VERSION (the release version, not the 1.74 RNode protocol version).
- PIN: the record's PIN field is filled only when the PIN rule says it is visible, and is
  zeroed otherwise, so the drawing code cannot leak it; the layout is the only code that
  prints it.
- Layouts: two profiles of the same layout code: OLED 21 columns by 8 rows (6 x 8 font),
  e-paper 16 columns by 12 rows (text size 2 on 200 x 200). The PIN is always on its own
  line; if rows run out, lower-priority lines are dropped first, never the PIN.
- Buses: the T-Echo display uses SPIM3 (SPIM0 and SPIM1 are disabled in the Adafruit nRF52 core, found on the board) (the radio uses SPIM2; the RNode firmware uses the
  same pairing on this board); software SPI only if a conflict appears. The Supreme OLED
  uses the default Wire on SDA 17 and SCL 18; the AXP2101 is on Wire1 (42/41) in
  radio_hal.cpp, so the buses are not shared. Whether the OLED needs a power rail is settled
  on the board, which is connected.
- Files and builds: portable code in mcu/app/rnc_status.{h,c}, tests in
  mcu/tests/test_status.c (added to mcu/CMakeLists.txt and run by mcu/tests/mcu_unit.sh),
  the file added to the library.json srcFilter so every environment compiles it (the
  linker drops what is unreferenced; "the other environments are unchanged" means no
  behaviour change and a size change of a few hundred bytes at most). The display sources
  compile only when the environment sets RNC_DISPLAY_OLED or RNC_DISPLAY_EPAPER. The CI
  mcu jobs already build every PlatformIO environment.

## 7. Testing and evidence

- Host unit tests of the layout and the PIN rule (run with the other mcu tests).
- All eight PlatformIO environments build; the six without a screen produce the same
  output as before apart from the version.
- On the boards, by looking: T-Echo and Supreme in rnode mode with and without a PIN,
  pairing a computer through BlueZ (PIN appears, then disappears when paired), radio on,
  packets counted. The owner confirms what the screens look like; the document records
  what was seen and what was not.

## 8. Left to the builder

- Exact line contents and wording, fonts and text sizes, library versions, how to give
  the e-paper its own SPI instance, the Supreme OLED power rail, file layout.

## 9. Open decisions for the owner

- Confirm the PIN rule (shown only while Bluetooth is on and no authenticated link exists).
- Confirm the e-paper refresh policy (15 s minimum, 5 minute full refresh).
