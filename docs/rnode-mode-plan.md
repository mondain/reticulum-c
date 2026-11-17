# RNode Mode Implementation Plan

> For agentic workers: REQUIRED SUB-SKILL: use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task by task.
> Steps use checkbox syntax for tracking.

**Goal:** Add an `rnode` run mode to the microcontroller firmware so a host running
Reticulum (Sideband, rnsd) drives the board's LoRa radio as an RNode, over USB serial
first and Bluetooth LE second.

**Architecture:** A new portable C module `mcu/radio/rnc_rnode.{h,c}` implements the device
side of the RNode KISS protocol on top of the existing `rnc_lora_if` (drivers, air framing,
CSMA, airtime budget). `rnc_lora_if` gains stop/reconfigure so the host can change radio
settings at run time. `mcu/platformio/src/main.cpp` runs it instead of the Reticulum node
when `mode=rnode`. Bluetooth is a second byte transport behind the same module.

**Tech Stack:** C11 (portable core), Arduino/PlatformIO firmware (C++), CMake + ctest,
the project's host adapter `RNC_HOST_RNODE` and simulated LoRa (`rnc_lora_sim`) for tests,
reference Reticulum 1.5.5 for interop.

**Spec:** docs/rnode-mode-design.md (approved 2026-11-14). Read it first.

## Global Constraints

- The firmware reports an RNode firmware version of at least 1.74 (detect reply, command 0x50).
- No default transmit settings anywhere. The radio stays off until frequency, bandwidth,
  spreading factor, coding rate and power are all set AND radio state is on. A test fails
  if any of that is violated (`mcu/tests/mcu_radio.sh` style rule).
- The airtime budget stays a hard cap: default 1 percent of every hour
  (`RNC_LORA_AIRTIME_DEFAULT` = 100 hundredths); the host may change it only through
  the airtime lock commands within the limits in `rnc_lora_cfg.h`.
- In rnode mode the serial port carries only KISS frames, never log text.
- The setup window after boot is unchanged (line `rnc-config`, 2 s); bytes that are not
  that line are buffered (bounded) and replayed to the KISS parser afterwards.
- The mode string is `rnode` (fits `rnc_mcu_cfg.mode[8]`).
- Bluetooth: Nordic UART service, name `RNode XXXX`, six digit PIN set by the operator
  (`set ble.pin 123456`), off and not advertising until a PIN is set.
- The command list and reply formats come from the host code (`src/host_posix.c`) and RNS
  1.5.5 (`e40191b3`, PROVENANCE.md), not from memory.
- C code compiles with `-Wall -Wextra -Wpedantic -Werror`; new sources are added to
  `mcu/CMakeLists.txt`, `library.json` and
  `mcu/esp-idf/components/reticulum_c_mcu_app/CMakeLists.txt`.
- Commit messages: no emoji, no tool taglines.

## Review Focus

1. A data frame arrives before the radio is fully configured and on: it is dropped and counted,
   nothing is transmitted (Task 4).
2. Malformed KISS input: a bad escape, a frame above 508 payload bytes, a command with a short
   payload, a flood without FEND: no crash, no state change, parser resyncs on the next FEND (Task 2).
3. Invalid radio values (bandwidth not in the table, spreading factor outside the chip's range,
   power above the board limit, coding rate outside 5 to 8): not applied and not echoed, so the
   host sees the mismatch (Task 3).
4. Host drops or the board resets with a packet queued or half sent: the queue and parser state
   are cleared, nothing is sent late (Task 4).
5. A host DETECT that arrives during the boot window is replayed and answered; the line
   `rnc-config` is never passed to the KISS parser (Task 6).

---

## Stage 1: USB

### Task 1: Stop and reconfigure `rnc_lora_if`

**Files:** Modify `mcu/radio/rnc_lora_if.h`, `mcu/radio/rnc_lora_if.c`; Test `mcu/tests/test_radio_sim.c`

**Interfaces:**
- Produces: `void rnc_lora_if_stop(rnc_lora_if *li)` (radio idle, state 0, queue and
  reassembly cleared, budget and CSMA kept);
  `int rnc_lora_if_reconfigure(rnc_lora_if *li, const rnc_lora_params *p)` (stop, then
  `rnc_lora_if_start`; returns that result; counters and the budget history survive).

- [ ] Step 1: add test `lora_if_reconfigure_keeps_budget`: spend part of the budget, call
  reconfigure with a new frequency and spreading factor, assert `budget` used time is
  unchanged, `stats.restarts` unchanged, `rnc_lora_if_up()` is 1, and a packet sent after
  uses the new time on air.
- [ ] Step 2: add test `lora_if_stop_clears_queue`: queue 2 packets, stop, assert nothing is
  transmitted by the simulated modem during 10 s of steps, `rnc_lora_if_up()` is 0.
- [ ] Step 3: run `ctest -R reticulum_mcu_radio_sim`; expect the new tests to fail (symbols missing).
- [ ] Step 4: implement both functions in `rnc_lora_if.c` using the existing start path.
- [ ] Step 5: run the same ctest plus `reticulum_mcu_radio_core`; expect PASS. Commit
  `radio: add stop and reconfigure to the LoRa interface`.

### Task 2: KISS framing, detect and identity commands in `rnc_rnode`

**Files:** Create `mcu/radio/rnc_rnode.h`, `mcu/radio/rnc_rnode.c`, `mcu/tests/test_rnode.c`;
Modify `mcu/CMakeLists.txt` (library source and `test_mcu_rnode` in the `foreach` list),
`library.json`, ESP-IDF component CMake.

**Interfaces:**
- Produces (header `rnc_rnode.h`):
  - `typedef struct rnc_rnode rnc_rnode;` (struct defined in the header, no allocation)
  - `void rnc_rnode_init(rnc_rnode *rn, rnc_lora_if *li, uint8_t platform, uint8_t mcu, uint8_t board)`
  - `void rnc_rnode_feed(rnc_rnode *rn, const uint8_t *bytes, size_t size, uint64_t now_us)`
    (host bytes in; never blocks)
  - `size_t rnc_rnode_pull(rnc_rnode *rn, uint8_t *out, size_t capacity)` (bytes to send to the host)
  - `unsigned rnc_rnode_step(rnc_rnode *rn, uint64_t now_us)` (like `rnc_lora_if_step`, returns ms until next call)
  - `void rnc_rnode_reset(rnc_rnode *rn)` (host gone: clear parser, queues)
  - constants `RNC_RNODE_FW_MAJOR 1`, `RNC_RNODE_FW_MINOR 74`.

- [ ] Step 1: tests (assert exact bytes): DETECT request `C0 08 73 C0` answers `C0 08 46 C0`;
  command 0x50 answers `C0 50 01 4A C0`; commands 0x48, 0x49 and 0x47 answer the
  `platform`, `mcu` and `board` values given to init; a frame containing `C0`, `DB`
  payload bytes round-trips through escaping (`DB DC`, `DB DD`).
- [ ] Step 2: Review Focus 2 tests: `DB 41` (bad escape), a 600 byte frame, a flood of 10000
  bytes without FEND, a 0x01 command with a 1 byte payload: each yields no reply and no
  state change, and the next valid DETECT is answered.
- [ ] Step 3: run `test_mcu_rnode`; expect FAIL (build error or assertion).
- [ ] Step 4: implement the framer (FEND 0xC0, FESC 0xDB, TFEND 0xDC, TFESC 0xDD, bounded
  buffer of `RNC_AIR_PACKET_MAX + 8`) and the handlers above. Confirm each constant and reply
  format against `src/host_posix.c` and RNS 1.5.5 `RNodeInterface.py` and cite the
  source line in a comment.
- [ ] Step 5: run the test; expect PASS. Commit `radio: add the RNode KISS framer and identity commands`.

### Task 3: Radio settings, echo, state gating and airtime locks

**Files:** Modify `rnc_rnode.c`, `rnc_rnode.h`; Test `mcu/tests/test_rnode.c`

**Interfaces:**
- Consumes: Task 1 `rnc_lora_if_reconfigure`, `rnc_lora_if_stop`; Task 2 framer.
- Produces: commands 1 (frequency, 4 bytes big endian), 2 (bandwidth, 4 bytes), 3 (power),
  4 (spreading factor), 5 (coding rate), 6 (radio state) each answered with the applied value;
  0x0b and 0x0c airtime locks (hundredths of a percent, big endian) applied to the budget;
  `int rnc_rnode_radio_on(const rnc_rnode *rn)`.

- [ ] Step 1: tests: after the host sets all five parameters and state 1, `rnc_rnode_radio_on()`
  is 1 and `rnc_lora_if_up()` is 1 and each setting was echoed with the same value; with state 1
  but one parameter missing, radio on stays 0 and the modem receives no SPI traffic
  (`rnc_lora_sim` counters); state 0 stops the radio.
- [ ] Step 2: Review Focus 3 tests: bandwidth 12345, spreading factor 4 (and 5 on an SX127x
  board model), coding rate 9, power above the board limit: no reply echo, radio unchanged.
- [ ] Step 3: airtime test: lock 0x0b with 50 (0.50 percent) shrinks the budget; value 0 or
  above 10000 is refused (not echoed).
- [ ] Step 4: run; expect FAIL. Implement: validate with `rnc_lora_phy` tables and the board
  limits, call `rnc_lora_if_reconfigure` only when all five are valid and state is on.
- [ ] Step 5: run `test_mcu_rnode`, `reticulum_mcu_radio_core`; PASS. Commit
  `radio: RNode radio settings with echo, state gating and airtime locks`.

### Task 4: Data path, flow control and signal reports

**Files:** Modify `rnc_rnode.c`; Test `mcu/tests/test_rnode.c`

**Interfaces:** KISS data frame (command 0x00) to `rnc_lora_if_send`; receive path emits the
RSSI frame (0x23) and SNR frame (0x24) then the data frame; READY (0x0f) sent when the transmit
queue has room; `rnc_rnode_reset` clears everything.

- [ ] Step 1: tests over two `rnc_lora_sim` interfaces: a 500 byte packet sent through the
  RNode on side A arrives as `C0 23 xx C0 C0 24 xx C0 C0 00 ... C0` on side B with RSSI
  encoded as `value + 157` and SNR in quarter dB (check against `rnode_report` in
  `src/host_posix.c`).
- [ ] Step 2: Review Focus 1 test: a data frame while the radio is off is dropped, counted
  in a new `drops_radio_off` field, and the simulated modem never transmits.
- [ ] Step 3: Review Focus 4 test: queue 3 packets, call `rnc_rnode_reset`, step 10 s: nothing
  is transmitted and the parser accepts a fresh DETECT.
- [ ] Step 4: flow control test: after `RNC_LORA_TXQ` packets are queued no READY is sent until
  one has gone out.
- [ ] Step 5: run; expect FAIL, implement, run; PASS. Commit `radio: RNode data path, flow control and signal reports`.

### Task 5: Host adapter and reference interop

**Files:** Create `mcu/tests/test_rnode_host.c` (registered like `test_mcu_*`, ctest name
`reticulum_mcu_rnode_host`, label `mcu`), `mcu/tests/mcu_rnode_reference.sh` (modelled on
`mcu/tests/mcu_radio_reference.sh`, run only with `RNC_INTEROP_TESTS`)

**Interfaces:** Consumes Tasks 1 to 4.

- [ ] Step 1: write `test_rnode_host.c`: a pseudo terminal pair; the project's `RNC_HOST_RNODE`
  interface on one end (settings 915 MHz, 125 kHz, SF8, CR 5, 10 dBm as in
  `rnode_detect_run` in `tests/test_host.c`), `rnc_rnode` on the other, a simulated LoRa peer.
  Assert: detect completes, `rnc_host_get_status().radio_ready` becomes 1, and an
  `rnc_node` packet sent by the host appears at the peer and the reverse.
- [ ] Step 2: run `ctest -R rnode_host`; expect FAIL until the glue (pty pump) is written in the
  test; fix the test glue only, not the module.
- [ ] Step 3: `mcu_rnode_reference.sh`: start the module behind a pty, point the unmodified
  reference Reticulum 1.5.5 `RNodeInterface` at it and assert it reports the interface online
  and exchanges one announce with a peer. Skip with a clear message without `RNC_INTEROP_TESTS`.
- [ ] Step 4: run both; expect PASS. Commit `tests: RNode mode against the host adapter and the reference`.

### Task 6: `rnode` run mode, boot window replay, settings and console

**Files:** Modify `mcu/app/rnc_mcu_net.h` (mode `rnode`, console help and validation),
`mcu/platformio/src/main.cpp`, `mcu/platformio/src/wifi_mode.cpp`,
`mcu/platformio/src/nrf_mode.cpp`, `mcu/esp-idf/example/main/` settings code,
`mcu/radio/rnc_rnode.{h,c}` (boot window helper), `mcu/tests/test_net.c`, `mcu/tests/test_rnode.c`

**Interfaces:**
- Produces: `RNC_MCU_MODE_RNODE "rnode"`; `rnc_rnode_window_t` with
  `void rnc_rnode_window_init(rnc_rnode_window_t *w)`,
  `int rnc_rnode_window_feed(rnc_rnode_window_t *w, uint8_t byte)` (returns 1 when the line
  `rnc-config` has just been completed),
  `size_t rnc_rnode_window_take(rnc_rnode_window_t *w, uint8_t *out, size_t capacity)` (the buffered
  bytes to replay, excluding the console line; bounded to 256 bytes, oldest dropped).

- [ ] Step 1: `test_net.c`: `set mode rnode` accepted, `set mode xyz` still refused, `get mode`
  reports it, settings round trip through the existing save/load test helpers.
- [ ] Step 2: Review Focus 5 test in `test_rnode.c`: bytes `C0 08 73 C0` fed to the window then
  taken are exactly those bytes; `rnc-config\n` returns 1 and is not in the replay; a
  300 byte stream keeps the last 256.
- [ ] Step 3: run; expect FAIL. Implement the helper and the mode string.
- [ ] Step 4: in `main.cpp`: when `cfg.mode == "rnode"` and the lora settings are not needed
  (the host supplies them), run the boot window with the helper, then a task that pumps
  `Serial` bytes into `rnc_rnode_feed`, writes `rnc_rnode_pull` output to `Serial`, and calls
  `rnc_rnode_step`; do not create the Reticulum node; keep the log hook off. Build the
  PlatformIO environments `lilygo_t_echo` and `heltec_wifi_lora_32_V3`
  (`mcu/build-platformio.sh`); both must build.
- [ ] Step 5: run `reticulum_mcu_net`, `reticulum_mcu_rnode`; PASS. Commit `firmware: add the rnode run mode`.

### Task 7: Tools, browser setup form, docs

**Files:** Modify `mcu/tools/wifi-config.sh` (`--mode rnode`), `web/src/config.js` and
`web/src/app.js` plus `web/index.html` (host connection choice "RNode modem" for boards that
have a radio), `web/tests/config.test.js`, `mcu/README.md`, `mcu/radio/README.md`,
`docs/releasing.md`, `.github/scripts/package-mcu.sh` (flash.txt and README text),
`COMPATIBILITY.md`

- [ ] Step 1: `web/tests/config.test.js`: with transport `rnode`, `buildCommands` returns
  `set mode rnode` then `save`, and no lora commands; with a radio-less board it throws.
- [ ] Step 2: run `cd web && npm test`; expect FAIL; implement; PASS.
- [ ] Step 3: `mcu/tests/test_wifi_config.sh` (existing) gains a `--mode rnode` case.
- [ ] Step 4: document the mode, the evidence level (emulator and reference tested; hardware
  not yet) and the regulatory behaviour of 6.4 in the design.
- [ ] Step 5: run the full `ctest` and `cd web && npm test`; PASS. Commit `tools: rnode mode in setup tools, flasher and docs`.

### Task 8: Bench on the T-Echo over USB

**Files:** Modify `mcu/radio/README.md`, `docs/rnode-mode-design.md` (status), `COMPATIBILITY.md`

- [ ] Step 1: flash a build from this branch to the T-Echo with the browser flasher; set `mode rnode`.
- [ ] Step 2: on a computer run `rnsd` with an `RNodeInterface` on the board's port (915 MHz,
  125 kHz, SF8, CR 5, 0 dBm); confirm it reports the interface online; exchange an announce
  and a request with the Supreme gateway on the same settings.
- [ ] Step 3: record the result, settings and any retry in `mcu/radio/README.md` as the
  evidence level for rnode mode. Commit `docs: record the rnode mode bench result`.

## Stage 2: Bluetooth

### Task 9: Byte transport interface and BLE settings

**Files:** Create `mcu/radio/rnc_rnode_io.h`; Modify `rnc_rnode.{h,c}`, `rnc_mcu_net.h`
(`ble.pin`), settings code from Task 6, `mcu/tests/test_net.c`, `mcu/tests/test_rnode.c`

**Interfaces:** `typedef struct rnc_rnode_io { int (*read)(void*, uint8_t*, size_t); int (*write)(void*, const uint8_t*, size_t); void *ctx; } rnc_rnode_io;`
`int rnc_mcu_cfg_ble_ready(const rnc_mcu_cfg *c)` (1 only when `ble.pin` is exactly six digits).

- [ ] Step 1: tests: `set ble.pin 123456` accepted; `12345`, `1234567`, `12a456` refused;
  `get ble.pin` never prints the PIN (prints `(set)` or `(empty)`); `ble_ready` is 0 until set.
- [ ] Step 2: run, expect FAIL, implement, PASS. Two io sources feed one `rnc_rnode` in a test
  (USB stub and BLE stub), each reaching the same command results.
- [ ] Step 3: commit `firmware: byte transport interface and the BLE PIN setting`.

### Task 10: nRF52840 Bluetooth (T-Echo, T114, RAK4631)

**Files:** Create `mcu/platformio/src/ble_nrf.cpp`; Modify `mcu/platformio/src/main.cpp`,
`mcu/platformio/platformio.ini`

- [ ] Step 1: Bluefruit Nordic UART service named `RNode` plus the last four hex digits of the
  device id; passkey pairing with the stored PIN; no advertising unless `ble_ready`.
- [ ] Step 2: build `lilygo_t_echo`, `heltec_t114`, `wiscore_rak4631`; record flash and RAM
  use against the limits in the board JSON; stop and report if over budget.
- [ ] Step 3: bench: pair the T-Echo with Sideband on the phone, set the radio there, exchange
  an announce. Record in `mcu/radio/README.md`. Commit `firmware: Bluetooth LE transport for nRF52840 boards`.

### Task 11: ESP32 Bluetooth

**Files:** Create `mcu/platformio/src/ble_esp32.cpp`; Modify `main.cpp`, `platformio.ini`

- [ ] Step 1: NimBLE Nordic UART service with the same naming and passkey rule.
- [ ] Step 2: build the five ESP32 environments; for any that does not fit with its other
  modes, compile the transport out for that board and document the limit in
  `mcu/platformio/README.md`. Commit `firmware: Bluetooth LE transport for ESP32 boards`.

## Self-Review Notes

- Spec coverage: 6.1 Tasks 2 to 4; 6.2 Task 1; 6.3 Task 4; 6.4 Tasks 3 and 4 and the Global
  Constraints; 6.5 Task 6 (window, serial only); 6.6 Tasks 9 to 11; section 7 Tasks 1 to 8;
  tools and flasher Task 7. Section 3 non-goals are untouched.
- Names used across tasks: `rnc_rnode_*`, `rnc_lora_if_stop`, `rnc_lora_if_reconfigure`,
  `rnc_rnode_window_*`, `rnc_rnode_io`, `RNC_MCU_MODE_RNODE`.
- Task 8 and the bench steps in Tasks 10 and 11 need the physical board and your presence.
