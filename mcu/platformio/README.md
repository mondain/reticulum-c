# reticulum-c on PlatformIO / Arduino (ESP32, ESP32-S3, nRF52840)

The same example node as mcu/esp-idf (see ../README.md), packaged for the Arduino
framework so it builds for common LoRa boards with one command:

- the protocol core and the portable application (mcu/app) are a PlatformIO
  library: library.json at the repository root
- this directory is a PlatformIO project: platformio.ini (one environment per
  board), src/main.cpp (the Arduino port), src/wifi_mode.cpp (Wi-Fi TCP transport and
  provisioning, ESP32 only), src/nrf_mode.cpp (nRF52 radio settings and console),
  boards/ (board definitions PlatformIO
  does not ship), scripts/ (collects the flashable files)

STATUS: every environment below builds. T-Echo, Supreme SX1262, XIAO SX1262 and Heltec V3 have passed
short hardware bench runs ("Bench record" in ../README.md); other boards have no radio evidence.
The board talks to a host over its serial/USB port, or (ESP32 and ESP32-S3 environments
only) over Wi-Fi and TCP, see "Wi-Fi mode" below, and, once configured, over a LoRa radio,
see "LoRa radio" below. A host client through the Supreme gateway reached the
T-Echo leaf over LoRa at 915 MHz/BW125k/SF8/CR4/5/0dBm, verified /echo and /info,
and observed the T-Echo at three hops. This is not a range or sustained-load test.

## Environments

| env | board | chip | Serial (HDLC) |
| --- | --- | --- | --- |
| heltec_wifi_lora_32_V3 | Heltec WiFi LoRa 32 V3 | ESP32-S3 | UART0 (CP2102 bridge) |
| heltec_wifi_lora_32_V2 | Heltec WiFi LoRa 32 V2 | ESP32 | UART0 (CP2102 bridge) |
| lilygo_t_beam_supreme | LilyGo T-Beam Supreme SX1262 | ESP32-S3 | native USB (CDC) |
| ttgo_t_beam | LilyGo T-Beam (original) | ESP32 | UART0 (CP2104 bridge) |
| lilygo_t3_s3 | LilyGo T3-S3 (also: other ESP32-S3 boards with USB) | ESP32-S3 | native USB (CDC) |
| wiscore_rak4631 | RAKwireless WisCore RAK4631 | nRF52840 | native USB (CDC) |
| heltec_t114 | Heltec Mesh Node T114 | nRF52840 | native USB (CDC) |
| seeed_xiao_nrf52840_wio | Seeed XIAO nRF52840 with Wio-SX1262 | nRF52840 | native USB (CDC) |
| lilygo_t_echo | LilyGo T-Echo | nRF52840 | native USB (CDC) |

The LilyGo T-Deck is not an environment: PlatformIO 6.12 has no board definition for
it. Use lilygo_t3_s3 as the template (the T-Deck is an ESP32-S3 with native USB).

## Pinned versions (reproducible builds)

```text
PlatformIO   6.1.19            installed by mcu/build-platformio.sh into a venv
espressif32  6.12.0            = arduino-esp32 2.0.17 (ESP-IDF 4.4), xtensa gcc 8.4
nordicnrf52  10.10.0           = Adafruit nRF52 core 1.7.0, arm-none-eabi-gcc 7.2.1,
                               adafruit-nrfutil 1.503
```

## Board definitions without an official PlatformIO entry

platformio/nordicnrf52 10.10.0 has no wiscore_rak4631, heltec_t114 or lilygo_t_echo.
boards/wiscore_rak4631.json, boards/heltec_t114.json and boards/lilygo_t_echo.json were
written here, as copies of the platform's adafruit_feather_nrf52840.json (the nearest
nRF52840 board with the same bootloader: Adafruit nRF52 bootloader with UF2 and serial
DFU, S140 6.1.1 memory map, application at 0x26000, linker script nrf52840_s140_v6.ld)
with the name, vendor, USB product string and the Arduino variant changed. The variant is
variants/rnc_nrf52840 (written for this project): an identity pin map, so Arduino pin n is
chip GPIO n (P1.k is 32 + k) and the radio pin numbers of mcu/radio/rnc_boards.c can be used
as they are; it drives no LED or button. The boards are known to ship the Adafruit
bootloader. Acknowledged serial DFU has been exercised on the T-Echo;
the RAK4631 and T114 bootloader paths remain unverified on hardware.

## Prerequisites

- python3 with the venv module, and network access on the first build (PlatformIO
  downloads the platform, toolchain and framework: roughly 0.8 GB for the ESP32
  framework plus 0.4 GB per ESP32 toolchain, and 0.5 GB for nRF52, into ~/.platformio
  or $PLATFORMIO_CORE_DIR)
- to flash: esptool (ESP32: pip install esptool) or a file manager (nRF52, UF2)

## Building

One command that installs the pinned PlatformIO and builds, collecting the files:

```sh
mcu/build-platformio.sh                          all environments -> mcu/out/platformio/<env>/
mcu/build-platformio.sh lilygo_t_echo            one environment
mcu/build-platformio.sh heltec_wifi_lora_32_V3 ttgo_t_beam /tmp/fw     several, own OUTDIR
```

or with your own PlatformIO 6.1.x:

```sh
cd mcu/platformio
pio run -e heltec_wifi_lora_32_V3                the firmware: .pio/build/<env>/
(the flashable files are collected in .pio/build/<env>/artifacts/)
pio run -e heltec_wifi_lora_32_V3 -t upload      build and flash over USB
```

`OUTDIR/<env>/` holds: flash.txt (the exact commands), size.txt, build-info.txt,
build.log, reticulum-c-mcu.elf, flash.json (offsets, sizes and SHA-256 hashes), and

```text
ESP32 / ESP32-S3: merged.bin (one image for flash address 0x0), reticulum-c-mcu.bin
                  (the application only), bootloader.bin, partitions.bin, boot_app0.bin
nRF52840:         reticulum-c-mcu.uf2, reticulum-c-mcu.hex, reticulum-c-mcu-dfu.zip
```

`OUTDIR/size-report.txt` has the RAM and flash lines of every environment.

Setting RNC_MCU_BUILD_EPOCH or SOURCE_DATE_EPOCH (seconds) fixes the build time that the
clock policy uses (../README.md, "Unix time policy"); the default is the current time.

## LoRa radio

All nine environments contain the LoRa driver for their board (the board table is
mcu/radio/rnc_boards.c; the environment name selects the entry): SX1262 on heltec_wifi_lora_32_V3,
lilygo_t3_s3, lilygo_t_beam_supreme, wiscore_rak4631, heltec_t114, seeed_xiao_nrf52840_wio, lilygo_t_echo;
SX1276 on heltec_wifi_lora_32_V2 and
ttgo_t_beam (v1.0/v1.1, its AXP192 radio rail is switched on over I2C). The radio is OFF, and the
chip is not touched, until the mode and the frequency, bandwidth, spreading factor, coding rate
and transmit power have been set at runtime; no transmit defaults are compiled in, and
the operator is responsible for a legal frequency, power and duty cycle (mcu/radio/README.md).

```text
lora.mode leaf      LoRa is the only interface (announces on LoRa, answers /echo and /info
                    over LoRa, forwards nothing); Serial is free for status text and the
                    Wi-Fi mode, if set, is not started
lora.mode gateway   the serial (or Wi-Fi) interface plus LoRa with Reticulum transport ON
lora.freq lora.bw lora.sf lora.cr lora.txp lora.airtime   the radio settings
```

Provision with the console (send the line `rnc-config` on Serial within 2 seconds after reset;
also on the nRF52 boards, where only the lora.* keys matter) or, on ESP32 without a console,
mcu/tools/wifi-config.sh --arduino ... --lora-mode ... (see its header; that replaces the whole
NVS partition including the identity). Storage: ESP32 Preferences namespace rnc_net; nRF52 the
internal file system (/rnc_lora). Example console session (values are an illustration, use
ones that are legal for you):

```text
set lora.mode leaf / set lora.freq 868.1 / set lora.bw 125 / set lora.sf 8 / set lora.cr 5 /
set lora.txp 14 / save / reboot
```

Sizes with the radio (measured, PlatformIO, before -> after): wiscore_rak4631 flash 203884 ->
235904 bytes, RAM 13164 -> 16732; heltec_wifi_lora_32_V3 flash 759353 -> 795501, RAM 48552 ->
52520 (the others in mcu/build-platformio.sh's size-report.txt). On nRF52 the heap that remains
for malloc is 218788 bytes (222356 before), enough for the node's 86 KB, the 16 KB task stack
and the radio's 3.5 KB.

## Flashing

ESP32 / ESP32-S3 (esptool, from the board's USB port):

Initial installation or intentional identity/settings reset only:

```sh
python3 -m esptool --chip esp32s3 -p /dev/ttyUSB0 -b 460800 write_flash 0x0 merged.bin
```

WARNING: merged.bin contains erased padding over NVS and resets both the node's
identity and its provisioned settings. To update an existing node, use the
separate-parts command in flash.txt; with the same partition layout it preserves
NVS. Back up state before changing partition layouts.

--chip esp32 for the ESP32 boards; /dev/ttyACM0 for a native USB port (lilygo_t3_s3);
COMx on Windows. If the board does not enter the bootloader by itself, hold BOOT, tap
RESET, release BOOT. flash.txt has the same command for the board you built, and the
separate-parts variant.

nRF52840 (RAK4631, T114, T-Echo): these images require the Adafruit nRF52 bootloader.

1. Double-tap RESET: a USB drive appears (names like RAK4631, HT-n5262, TECHOBOOT).
2. Copy reticulum-c-mcu.uf2 onto it. The board reboots into the firmware.

Alternative over the serial DFU port (pip install adafruit-nrfutil):

```sh
adafruit-nrfutil --verbose dfu serial --package reticulum-c-mcu-dfu.zip -p /dev/ttyACM0 -b 115200 --singlebank
```

The UF2 and DFU files contain the application only (from 0x26000); the internal
file system holding identity/settings, bootloader and SoftDevice stay in place.
A board without the Adafruit bootloader needs it flashed
first with a debug probe (see the board vendor's instructions); that is not covered here.

## Browser install and setup

https://mondain.github.io/reticulum-c/ publishes all nine board images with a
version selector and SHA-256 downloads. Main builds are labeled `main-<commit>`;
they are separate from tagged release archives. The catalog retains up to five
versions as new builds are deployed, prioritizing tagged releases in its history.
Choose the exact board/radio variant: Supreme LR1121 and T-Beam v1.2 are unsupported.

On a desktop Chromium browser with Web Serial, select and confirm the board, then
connect its USB port. ESP32 updates download and verify the separate parts by
SHA-256, write the board-specific flash headers and verify flash contents with
MD5. The default update preserves NVS with an unchanged partition layout. Factory
installation requires an explicit erase choice and confirmation and erases all
flash, including identity and settings. The site does not flash merged.bin.

For nRF52840, request the bootloader or double-tap RESET, then choose the bootloader
serial port for acknowledged application-only DFU. UF2 is also downloadable for
drag-and-drop installation. Application-only updates preserve the internal file
system. Browser transfer checks have been exercised on the Supreme SX1262 and
T-Echo; other board paths have build and automated-test coverage.

The setup form uses this firmware's rnc-config console, not the RNode EEPROM/KISS
protocol. Connect settings, tap RESET if prompted, read the saved values, then
save and reboot. Radio settings have no transmit defaults: enter all settings
and select a legal frequency, power and airtime budget. Wi-Fi edits apply only
when selected; leaving an existing masked password blank preserves it. Explicitly
choose an open network to clear it. The form never reads the password in clear.

## Serial setup

With the radio off and host transport set to serial (the default), Serial carries
only the HDLC byte stream of the Reticulum SerialInterface (flag 0x7E,
escape 0x7D, mask 0x20): the application's log hook is not connected and framework
logging is off (ESP32: CORE_DEBUG_LEVEL=0 and esp_log_level_set(NONE)). The ESP32 boot ROM
still prints a few bytes at reset at 115200 baud; the HDLC receiver ignores them. nRF52
boards boot silently.

```text
UART boards (heltec V3/V2, T-Beam): 115200 baud, 8N1 (RNC_MCU_BAUD to change it)
USB boards (Supreme, T3-S3, RAK4631, T114, T-Echo): the baud rate is ignored; the host must
assert DTR, which every normal serial open does (the nRF52 USB stack drops output while
DTR is low).
```

reticulum-c-node configuration (any host node with a SerialInterface works):

```ini
[reticulum]
enable_transport = Yes
share_instance = No

[interfaces]
  [[MCU board]]
    type = SerialInterface
    port = /dev/ttyACM0
    speed = 115200
    databits = 8
    parity = none
    stopbits = 1
```

Within a few seconds the node logs the announce of reticulum_c.mcu.example; request /echo
or /info from it (mcu/tests/echo_client.c; /info reports the board name = the environment,
the version, uptime and free heap). The device announces at start, 5 seconds later, then
every 10 minutes. It is a leaf node unless LoRa gateway mode is configured.

## What the port does (src/main.cpp)

```text
transport   Serial (UART or USB CDC), RX buffer 2 KB on ESP32; non-blocking reads
random      ESP32 serial mode: esp_fill_random with the SAR ADC entropy source on
            (bootloader_random_enable; do not add an ADC user without reading the
            ESP-IDF notes on random numbers). ESP32 Wi-Fi mode: the radio is the entropy
            source and bootloader_random_enable is not called.
            nRF52: the RNG peripheral with bias correction, or the SoftDevice's random
            pool when the SoftDevice is enabled (the SoftDevice owns the peripheral then)
time        millis(), extended to 64 bits (49-day wrap handled)
identity    ESP32: Preferences (NVS) namespace "reticulum"
            nRF52: InternalFileSystem (LittleFS in internal flash), files /rnc_identity
            and /rnc_time, replaced atomically (write a .tmp file, then rename)
clock       no unix_seconds hook: build epoch + uptime + persisted mark, written
            when the node announces (../README.md, "Unix time policy")
task        the node runs in its own FreeRTOS task with a 16 KB stack
free heap   reported by /info (ESP.getFreeHeap, dbgHeapFree)
```

The identity is stored unencrypted in flash: anyone with physical access can read it.

## Wi-Fi mode (ESP32 and ESP32-S3 environments)

The ESP32 environments can run the same node over Wi-Fi: HDLC frames (as on the serial
interface, and as Reticulum's TCPClientInterface/TCPServerInterface use them) on a TCP
client connection to the TCPServerInterface of a reticulum-c-node, rnsd or any node that
listens on TCP:

```ini
[[Boards]]
  type = TCPServerInterface
  listen_ip = 0.0.0.0
  listen_port = 4242
```

An unprovisioned image starts in serial mode. Updates that preserve settings
retain the selected mode. The nRF52 environments have no Wi-Fi.

The mode and the credentials are set at runtime and are NEVER in a release image. They
are stored with Preferences in the standard NVS partition, namespace "rnc_net", keys
mode ("serial" or "wifi"), ssid (1 to 32 bytes), password (empty or 8 to 63 characters),
host, port (default 4242). The identity is in the same partition (namespace "reticulum").

(a) The serial console (115200 baud 8N1 on UART boards, the USB port on native USB
boards; the same port that carries HDLC in serial mode). It runs only when

- mode is wifi and the stored settings are missing or invalid (it starts at once;
  the node does not run), or
- during a window of 2 seconds after every boot (RNC_MCU_PROVISION_WINDOW_MS; 0
  removes it), when the line `rnc-config` arrives on Serial, or the BOOT button
  (GPIO0, RNC_MCU_BOOT_PIN) is pressed and held for 300 ms after the reset.

In serial mode the window delays the start of the node by that time. Commands: help,
get [key] (the password is shown as (set), never in clear), set KEY VALUE (the rest of
the line is the value), clear, save, reboot. Example, right after a reset:

```text
rnc-config
set mode wifi
set ssid MyNetwork
set password correct horse battery
set host 192.168.1.10
save
reboot
```

The password is echoed as `*` while typing and is stored only by save. To go back:
set mode serial, save, reboot.

(b) mcu/tools/wifi-config.sh --arduino, without a console:

```sh
mcu/tools/wifi-config.sh --arduino --chip esp32 --device /dev/ttyUSB0 \
    --ssid MyNetwork --host 192.168.1.10 --password-stdin < password.txt
```

It builds an NVS image with IDF's nvs_partition_gen and flashes it at the NVS
partition (0x9000, 0x5000 bytes, the default partition table of these boards). That
REPLACES the whole NVS partition, so the node gets a new identity at its next start.
(The ESP-IDF firmware, ../README.md, has a separate settings partition and keeps its
identity.) --image-only FILE writes the image without flashing. Needs esptool and the
generator (pip install esptool esp-idf-nvs-partition-gen) or Docker.

Behaviour: the Wi-Fi station reconnects by itself (auto reconnect; an attempt that gets
nowhere for 30 s is restarted with backoff), and the TCP connection is retried with
backoff 0.5 s doubling to 30 s with jitter. The socket has TCP_NODELAY and keepalive;
reads and writes are non-blocking on the raw socket; output goes through a 4096 byte
queue and a frame that does not fit is dropped whole. While the link is down the
application neither reads nor writes nor announces; when it returns it resets the HDLC
decoder and announces again after half a second. WiFiClient::connect blocks the Reticulum
task for up to 3 seconds per attempt (name resolution included): use an IP address for the
host if that matters. In Wi-Fi mode Serial carries status text, not HDLC.

For developers only: `-DRNC_MCU_DEV_WIFI_SSID=\"net\"` `-DRNC_MCU_DEV_WIFI_PASSWORD=\"secret..\"`
`-DRNC_MCU_DEV_WIFI_HOST=\"192.168.1.10\"` `-DRNC_MCU_DEV_WIFI_PORT=4242` passed through
PLATFORMIO_BUILD_FLAGS (not in platformio.ini) compile defaults in, used while nothing is
stored. build-platformio.sh marks such a build (dev-wifi-defaults: yes in build-info.txt),
refuses it with RNC_RELEASE=1, and the release packaging refuses it. The credentials are
then readable in the image: never distribute such a build.

SECURITY NOTES. The TCP link is plaintext and unauthenticated at the transport level, like
any Reticulum TCP interface (Reticulum's own link encryption and signed announces apply
above it; no IFAC here): anyone on the path can read or alter the bytes, and anyone who can
reach the server's port can connect. The credentials and the identity sit in NVS
UNENCRYPTED unless you enable NVS/flash encryption yourself (not done here): anyone who
holds the board can read them.

## nRF52 memory and the profile decision

The nRF52840 has 256 KB of RAM. The linker script of the Adafruit core reserves the
lowest 24 KB for the SoftDevice (even though this firmware does not enable it), the rest
is .data/.bss, a 2 KB main stack and the heap. A measured radio-enabled RAK4631
build had the following layout; size.txt reports the actual build's values:

```text
RAM region for the application       0x20006000 .. 0x20040000   232 KB
.data + .bss (PlatformIO "RAM")      16,732 bytes
heap (__HeapBase .. __HeapLimit)     218,788 bytes (214 KB), in size.txt
main stack                           2 KB
```

The default mcu profile needs about 86 KB of heap for the node, the responder and two
links (tests/footprint.c, a host measurement), about 5 KB for the application's scratch
buffers and a 16 KB task stack taken from the heap: about 107 KB in total, plus
about 4 KB for the radio interface. The measured build leaves roughly 100 KB
for the Adafruit core's own tasks (USB, timers; a few KB)
and for you. That is far above the 30 KB margin, so the nRF52 builds use the default mcu
profile unchanged and no smaller profile is defined. (PlatformIO's RAM percentage counts
only static data; it is not the memory budget.) /info reports the runtime free heap.

If you need the memory (for example for a radio driver, a display or BLE), a custom
profile can still be supplied for the library and the sketch together:

```sh
RNC_PROFILE_HEADER=/absolute/path/my_profile.h pio run -e lilygo_t_echo
```

(copy include/reticulum_c/rnc_profile_mcu.h and change the values). The profile constants
size public structs, so the library and the sketch must use the same one; the variable
does that. After changing it, run tests/footprint.c with the same header on the host:

```sh
cmake -S . -B build-p -DRNC_PROFILE=mcu -DRNC_CRYPTO=portable \
      -DCMAKE_C_FLAGS='-DRNC_PROFILE_HEADER=\"/absolute/path/my_profile.h\"'
cmake --build build-p --target footprint && build-p/footprint <budget_bytes>
```

## Using the library in your own PlatformIO project

In platformio.ini of your project, with the Arduino framework on an ESP32 or nRF52840
board:

```ini
lib_deps = https://github.com/mondain/reticulum-c.git#v<version>
; or from a checkout or an unpacked reticulum-c-<version>-platformio-library archive:
; lib_deps = file:///path/to/reticulum-c
; lib_deps = symlink:///path/to/reticulum-c
lib_ldf_mode = chain
```

and `#include "rnc_mcu_app.h"` (the portable application; mcu/app/rnc_mcu_platform.h is the
table to fill) or the core headers `<reticulum_c/rnc_node.h>` etc. library.json builds the
portable core plus mcu/app with RNC_PROFILE_MCU=1, RNC_CRYPTO_PORTABLE=1 and
RNC_PORTABLE_NO_RPC_DIGESTS=1; mcu/platformio/lib_extra.py adds the include paths and the
profile to your sources too, and supplies RNC_MCU_VERSION (from CMakeLists.txt, else
library.json) and RNC_MCU_BUILD_EPOCH. Use a task stack of at least 12 KB (16 KB here).

## Limits

- Hardware bench coverage: short runs on the T-Echo, Supreme SX1262, XIAO SX1262 and Heltec V3 ("Bench record" in
  ../README.md). Other boards retain build/model coverage. Range, sustained load and stock RNode interoperability
  remain unverified.
- Host interfaces are serial/USB or, on ESP32, a Wi-Fi TCP client (no access point mode, UDP/AutoInterface, TLS or
  IFAC). LoRa is available as a leaf or gateway interface once configured, and in RNode mode the board speaks the
  RNode protocol over USB or Bluetooth LE instead.
- Wi-Fi mode (ESP32 environments) is built, not run on hardware; its application logic is
  tested on the host (mcu/tests). It adds about 420 KB of flash (heltec V3: 339 KB ->
  759 KB) and 30 KB of static RAM, plus the Wi-Fi driver's heap, and uses more power.
- Leaf node unless LoRa gateway mode is configured: at most 2 links,
  8 remembered announces, 12 paths, packets up to 500 bytes
  (include/reticulum_c/rnc_profile_mcu.h).
- AES is table-based software (not constant time against cache timing); X25519/Ed25519
  are Monocypher. Hardware crypto is not used.
- The nRF52 board definitions are derived (see above). The identity pin map
  supports the radio GPIOs; display and buttons have no application support.
- The nRF52 firmware assumes the Adafruit bootloader and the S140 6.1.1 memory map.
- T-Deck: no environment (no PlatformIO board definition).
