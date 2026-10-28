reticulum-c on PlatformIO / Arduino (ESP32, ESP32-S3, nRF52840)
===============================================================

The same example node as mcu/esp-idf (see ../README.txt), packaged for the Arduino
framework so it builds for common LoRa boards with one command:

  - the protocol core and the portable application (mcu/app) are a PlatformIO
    library: library.json at the repository root
  - this directory is a PlatformIO project: platformio.ini (one environment per
    board), src/main.cpp (the Arduino port), boards/ (board definitions PlatformIO
    does not ship), scripts/ (collects the flashable files)

STATUS: every environment below builds. The firmware has NOT been run on hardware.
There is no LoRa radio driver: the board talks to a host over its serial/USB port.

Environments
------------
  env                      board                          chip       Serial (HDLC)
  heltec_wifi_lora_32_V3   Heltec WiFi LoRa 32 V3         ESP32-S3   UART0 (CP2102 bridge)
  heltec_wifi_lora_32_V2   Heltec WiFi LoRa 32 V2         ESP32      UART0 (CP2102 bridge)
  ttgo_t_beam              LilyGo T-Beam (original)       ESP32      UART0 (CP2104 bridge)
  lilygo_t3_s3             LilyGo T3-S3 (also: other      ESP32-S3   native USB (CDC)
                           ESP32-S3 boards with USB)
  wiscore_rak4631          RAKwireless WisCore RAK4631    nRF52840   native USB (CDC)
  heltec_t114              Heltec Mesh Node T114          nRF52840   native USB (CDC)
  lilygo_t_echo            LilyGo T-Echo                  nRF52840   native USB (CDC)

The LilyGo T-Deck is not an environment: PlatformIO 6.12 has no board definition for
it. Use lilygo_t3_s3 as the template (the T-Deck is an ESP32-S3 with native USB).

Pinned versions (reproducible builds)
-------------------------------------
  PlatformIO   6.1.19            installed by mcu/build-platformio.sh into a venv
  espressif32  6.12.0            = arduino-esp32 2.0.17 (ESP-IDF 4.4), xtensa gcc 8.4
  nordicnrf52  10.10.0           = Adafruit nRF52 core 1.7.0, arm-none-eabi-gcc 7.2.1,
                                   adafruit-nrfutil 1.503

Board definitions without an official PlatformIO entry
------------------------------------------------------
platformio/nordicnrf52 10.10.0 has no wiscore_rak4631, heltec_t114 or lilygo_t_echo.
boards/wiscore_rak4631.json, boards/heltec_t114.json and boards/lilygo_t_echo.json were
written here, as copies of the platform's adafruit_feather_nrf52840.json (the nearest
nRF52840 board with the same bootloader: Adafruit nRF52 bootloader with UF2 and serial
DFU, S140 6.1.1 memory map, application at 0x26000, linker script nrf52840_s140_v6.ld)
with only the name, vendor and USB product string changed. They also reuse the Feather's
Arduino variant (pin map). That is enough for this firmware, which uses only the USB
serial port, the timer, the RNG and the internal flash; it is NOT a pin map for the
boards' radios, displays or buttons (a LoRa driver would need those). The three boards
are known to ship the Adafruit bootloader; this was not tested on the boards.

Prerequisites
-------------
  - python3 with the venv module, and network access on the first build (PlatformIO
    downloads the platform, toolchain and framework: roughly 0.8 GB for the ESP32
    framework plus 0.4 GB per ESP32 toolchain, and 0.5 GB for nRF52, into ~/.platformio
    or $PLATFORMIO_CORE_DIR)
  - to flash: esptool (ESP32: pip install esptool) or a file manager (nRF52, UF2)

Building
--------
One command that installs the pinned PlatformIO and builds, collecting the files:

  mcu/build-platformio.sh                          all environments -> mcu/out/platformio/<env>/
  mcu/build-platformio.sh lilygo_t_echo            one environment
  mcu/build-platformio.sh heltec_wifi_lora_32_V3 ttgo_t_beam /tmp/fw     several, own OUTDIR

or with your own PlatformIO 6.1.x:

  cd mcu/platformio
  pio run -e heltec_wifi_lora_32_V3                the firmware: .pio/build/<env>/
  (the flashable files are collected in .pio/build/<env>/artifacts/)
  pio run -e heltec_wifi_lora_32_V3 -t upload      build and flash over USB

OUTDIR/<env>/ holds: flash.txt (the exact commands), size.txt, build-info.txt,
build.log, reticulum-c-mcu.elf, and
  ESP32 / ESP32-S3: merged.bin (one image for flash address 0x0), reticulum-c-mcu.bin
                    (the application only), bootloader.bin, partitions.bin, boot_app0.bin
  nRF52840:         reticulum-c-mcu.uf2, reticulum-c-mcu.hex, reticulum-c-mcu-dfu.zip
OUTDIR/size-report.txt has the RAM and flash lines of every environment.

Setting RNC_MCU_BUILD_EPOCH or SOURCE_DATE_EPOCH (seconds) fixes the build time that the
clock policy uses (../README.txt, "Unix time policy"); the default is the current time.

Flashing
--------
ESP32 / ESP32-S3 (esptool, from the board's USB port):

  python3 -m esptool --chip esp32s3 -p /dev/ttyUSB0 -b 460800 write_flash 0x0 merged.bin

--chip esp32 for the ESP32 boards; /dev/ttyACM0 for a native USB port (lilygo_t3_s3);
COMx on Windows. If the board does not enter the bootloader by itself, hold BOOT, tap
RESET, release BOOT. flash.txt has the same command for the board you built, and the
separate-parts variant.

nRF52840 (RAK4631, T114, T-Echo): the boards run the Adafruit nRF52 bootloader.
  1. Double-tap RESET: a USB drive appears (names like RAK4631, HT-n5262, TECHOBOOT).
  2. Copy reticulum-c-mcu.uf2 onto it. The board reboots into the firmware.
Alternative over the serial DFU port (pip install adafruit-nrfutil):

  adafruit-nrfutil --verbose dfu serial --package reticulum-c-mcu-dfu.zip -p /dev/ttyACM0 -b 115200 --singlebank

The UF2 file contains the application only (from 0x26000); the bootloader and SoftDevice
that came with the board stay. A board without the Adafruit bootloader needs it flashed
first with a debug probe (see the board vendor's instructions); that is not covered here.

Serial setup
------------
Serial carries only the HDLC byte stream of the Reticulum SerialInterface (flag 0x7E,
escape 0x7D, mask 0x20): the application's log hook is not connected and framework
logging is off (ESP32: CORE_DEBUG_LEVEL=0 and esp_log_level_set(NONE)). The ESP32 boot ROM
still prints a few bytes at reset at 115200 baud; the HDLC receiver ignores them. nRF52
boards boot silently.

  UART boards (heltec V3/V2, T-Beam): 115200 baud, 8N1 (RNC_MCU_BAUD to change it)
  USB CDC boards (T3-S3, RAK4631, T114, T-Echo): the baud rate is ignored; the host must
  assert DTR, which every normal serial open does (the nRF52 USB stack drops output while
  DTR is low).

reticulum-c-node configuration (any host node with a SerialInterface works):

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

Within a few seconds the node logs the announce of reticulum_c.mcu.example; request /echo
or /info from it (mcu/tests/echo_client.c; /info reports the board name = the environment,
the version, uptime and free heap). The device announces at start, 5 seconds later, then
every 10 minutes. It is a leaf node: it does not forward traffic.

What the port does (src/main.cpp)
---------------------------------
  transport   Serial (UART or USB CDC), RX buffer 2 KB on ESP32; non-blocking reads
  random      ESP32: esp_fill_random with the SAR ADC entropy source on
              (bootloader_random_enable; this firmware uses no Wi-Fi or Bluetooth, so do not
              add an ADC user without reading the ESP-IDF notes on random numbers).
              nRF52: the RNG peripheral with bias correction, or the SoftDevice's random
              pool when the SoftDevice is enabled (the SoftDevice owns the peripheral then)
  time        millis(), extended to 64 bits (49-day wrap handled)
  identity    ESP32: Preferences (NVS) namespace "reticulum"
              nRF52: InternalFileSystem (LittleFS in internal flash), files /rnc_identity
              and /rnc_time, replaced atomically (write a .tmp file, then rename)
  clock       no unix_seconds hook: build epoch + uptime + persisted high-water mark, one
              flash write per 2 minutes of uptime (../README.txt, "Unix time policy")
  task        the node runs in its own FreeRTOS task with a 16 KB stack
  free heap   reported by /info (ESP.getFreeHeap, dbgHeapFree)
The identity is stored unencrypted in flash: anyone with physical access can read it.

nRF52 memory and the profile decision
-------------------------------------
The nRF52840 has 256 KB of RAM. The linker script of the Adafruit core reserves the
lowest 24 KB for the SoftDevice (even though this firmware does not enable it), the rest
is .data/.bss, a 2 KB main stack and the heap. Measured on the built ELF (all three
nRF52 environments are identical in memory):

  RAM region for the application       0x20006000 .. 0x20040000   232 KB
  .data + .bss (PlatformIO "RAM")      13,164 bytes
  heap (__HeapBase .. __HeapLimit)     222,356 bytes (217 KB), in size.txt
  main stack                           2 KB

The default mcu profile needs about 86 KB of heap for the node, the responder and two
links (tests/footprint.c, a host measurement), about 5 KB for the application's scratch
buffers and a 16 KB task stack taken from the heap: about 107 KB in total, which leaves
about 115 KB of the 222 KB heap for the Adafruit core's own tasks (USB, timers; a few KB)
and for you. That is far above the 30 KB margin, so the nRF52 builds use the default mcu
profile unchanged and no smaller profile is defined. (PlatformIO's "RAM: 5.3%" counts
only static data; it is not the memory budget.) The runtime heap was not measured on a
board; /info reports the free heap so you can read it.

If you need the memory (for example for a radio driver, a display or BLE), a custom
profile can still be supplied for the library and the sketch together:

  RNC_PROFILE_HEADER=/absolute/path/my_profile.h pio run -e lilygo_t_echo

(copy include/reticulum_c/rnc_profile_mcu.h and change the values). The profile constants
size public structs, so the library and the sketch must use the same one; the variable
does that. After changing it, run tests/footprint.c with the same header on the host:

  cmake -S . -B build-p -DRNC_PROFILE=mcu -DRNC_CRYPTO=portable \
        -DCMAKE_C_FLAGS='-DRNC_PROFILE_HEADER=\"/absolute/path/my_profile.h\"'
  cmake --build build-p --target footprint && build-p/footprint <budget_bytes>

Using the library in your own PlatformIO project
------------------------------------------------
In platformio.ini of your project, with the Arduino framework on an ESP32 or nRF52840
board:

  lib_deps = https://github.com/mondain/reticulum-c.git#v<version>
  ; or from a checkout or an unpacked reticulum-c-<version>-platformio-library archive:
  ; lib_deps = file:///path/to/reticulum-c
  ; lib_deps = symlink:///path/to/reticulum-c
  lib_ldf_mode = chain

and #include "rnc_mcu_app.h" (the portable application; mcu/app/rnc_mcu_platform.h is the
table to fill) or the core headers <reticulum_c/rnc_node.h> etc. library.json builds the
portable core plus mcu/app with RNC_PROFILE_MCU=1, RNC_CRYPTO_PORTABLE=1 and
RNC_PORTABLE_NO_RPC_DIGESTS=1; mcu/platformio/lib_extra.py adds the include paths and the
profile to your sources too, and supplies RNC_MCU_VERSION (from CMakeLists.txt, else
library.json) and RNC_MCU_BUILD_EPOCH. Use a task stack of at least 12 KB (16 KB here).

Limits
------
  - Not run on hardware: the builds are verified, the firmware behaviour is verified only
    through the portable application on the host (mcu/tests).
  - No LoRa radio driver (SX126x/SX127x), no RNode-style firmware, no Bluetooth or Wi-Fi
    interface: a host node is needed to route to a network.
  - Leaf node: no transport/forwarding, at most 2 links, 8 remembered announces, 12 paths,
    packets up to 500 bytes (include/reticulum_c/rnc_profile_mcu.h).
  - AES is table-based software (not constant time against cache timing); X25519/Ed25519
    are Monocypher. Hardware crypto is not used.
  - The nRF52 board definitions are derived (see above); display, buttons and LoRa pins
    are not mapped.
  - The nRF52 firmware assumes the Adafruit bootloader and the S140 6.1.1 memory map.
  - T-Deck: no environment (no PlatformIO board definition).
