reticulum-c for microcontrollers (ESP32 and ESP32-S3)
======================================================

This directory holds everything needed to run the reticulum-c protocol core on a
microcontroller and an example firmware you can flash today:

  mcu/app/          portable example application (no platform headers)
  mcu/host/         host build of the same application (pty or stdin/stdout)
  mcu/tests/        tests: clock policy, and the application against reticulum-c-node
  mcu/esp-idf/      ESP-IDF components and the example project
  mcu/build-esp-idf.sh   one command that builds a flashable image
  mcu/platformio/   the same firmware for the Arduino framework on ESP32 and nRF52840
                    boards (Heltec V3/V2, T-Beam, T3-S3, RAK4631, Heltec T114, LilyGo
                    T-Echo): see mcu/platformio/README.txt; build with mcu/build-platformio.sh

STATUS: the firmware builds for esp32 and esp32s3 and the same application logic
passes the host tests against reticulum-c-node and the reference Reticulum. It has
NOT been run on hardware yet.

What the firmware is
--------------------
A Reticulum node for a microcontroller with one interface: the Reticulum
SerialInterface framing (HDLC: flag 0x7E, escape 0x7D, mask 0x20) on a UART or on the
chip's USB Serial/JTAG port. It

  - creates a persistent identity at first boot (stored in NVS flash),
  - registers the destination  reticulum_c.mcu.example,
  - announces at start, again 5 seconds later, then every 10 minutes
    (Kconfig: Reticulum MCU example -> Announce interval),
  - answers requests on the destination's links:
      /echo   returns the request value unchanged
      /info   returns a MessagePack map: name ("reticulum-c-mcu"), version, board,
              uptime (seconds) and heap (free bytes)

The firmware is a leaf node: it does not forward other nodes' traffic (no
transport). A host node (reticulum-c-node or the reference rnsd) that has the
board as a SerialInterface routes between the board and the rest of the network.

Prerequisites
-------------
  - Docker (for --docker builds), or an ESP-IDF 5.x environment (tested with
    5.4.4; the Docker image is espressif/idf:v5.4.4, override with RNC_IDF_IMAGE)
  - esptool (pip install esptool) to flash
  - To run the host tests: cmake, a C compiler, OpenSSL development files, bash.

Building
--------
  mcu/build-esp-idf.sh --docker esp32      [OUTDIR]
  mcu/build-esp-idf.sh --docker esp32s3    [OUTDIR]
  mcu/build-esp-idf.sh esp32s3             (inside an active ESP-IDF environment)

OUTDIR defaults to mcu/out/<chip>. It receives reticulum-c-mcu.bin (the app),
bootloader.bin, partition-table.bin, merged.bin (a single image to write at flash
address 0x0), reticulum-c-mcu.elf, size.txt (memory and per-component report) and
flash.txt (the exact esptool commands). The bootloader offset differs per chip
(0x1000 on ESP32, 0x0 on ESP32-S3); the script checks it and merged.bin already
contains it.

Flashing
--------
  python3 -m esptool --chip esp32s3 -p /dev/ttyUSB0 -b 460800 write_flash 0x0 merged.bin

(see flash.txt in OUTDIR; use /dev/ttyACM0 for a native USB port). If the board does
not enter the bootloader by itself, hold BOOT, tap RESET, release BOOT.

Settings are in "idf.py menuconfig" under "Reticulum MCU example" (transport, UART
number and pins, baud rate, task stack, announce interval, board name).
sdkconfig.defaults and sdkconfig.defaults.esp32 / .esp32s3 hold the per-chip
defaults. The default flash size is 4 MB; set it to match your board.

Serial and host setup
---------------------
The firmware uses UART0 at 115200 baud, 8N1, which is the port behind the USB-UART
bridge on the common boards, so the host sees the board as /dev/ttyUSB0 or
/dev/ttyACM0. Nothing else may print on that port: the console is disabled (ESP32)
or moved to the chip's USB Serial/JTAG port (ESP32-S3) in sdkconfig.defaults. The
boot ROM still prints a few bytes at reset; the HDLC receiver ignores them.

reticulum-c-node configuration (the node needs a TCP or other interface for the
rest of the network):

  [reticulum]
  enable_transport = Yes
  share_instance = No

  [interfaces]
    [[MCU board]]
      type = SerialInterface
      port = /dev/ttyUSB0
      speed = 115200
      databits = 8
      parity = none
      stopbits = 1

    [[TCP]]
      type = TCPServerInterface
      listen_ip = 127.0.0.1
      listen_port = 4242

The reference Reticulum (rnsd) takes the same SerialInterface section. Within a few
seconds of the board starting (or the node starting) the node logs the announce of
the board's destination. A client can then request /echo or /info from it, for
example with mcu/tests/echo_client.c (built in the default build as echo_client).

Without hardware, the host build runs the same application on a pty:

  cmake -S . -B build-mcu -DRNC_PROFILE=mcu -DRNC_CRYPTO=portable -DBUILD_TESTING=OFF
  cmake --build build-mcu --target reticulum-c-mcu-host
  build-mcu/mcu/reticulum-c-mcu-host --pty --state /tmp/mcu-state

It prints pty=/dev/pts/N; use that as the SerialInterface port. The profile and the
crypto backend must be selected for the whole build: the mcu profile changes the
sizes of public structures, so it cannot share a build directory with the default
build. ctest in a default build runs this automatically (label mcu): the test
builds the firmware logic in its own directory, starts it on a pty behind a
reticulum-c-node with a SerialInterface and a loopback TCP server, and a client
requests /echo and /info over TCP. With the reference oracle (RNC_INTEROP_TESTS)
the unmodified reference Reticulum repeats the /echo and /info requests.

Using the components in your own ESP-IDF project
------------------------------------------------
  set(EXTRA_COMPONENT_DIRS /path/to/reticulum-c/mcu/esp-idf/components)

and REQUIRES reticulum_c (the core) and optionally reticulum_c_mcu_app (the portable
application, mcu/app). The core component builds with RNC_PROFILE_MCU defined
publicly, so every file that includes reticulum_c headers sees the same capacity
constants. The repository root also works as a component directory when the
checkout directory is named reticulum_c (an IDF component is named after its
directory), or through the IDF Component Manager (idf_component.yml in the root).
To write your own application use the platform table in mcu/app/rnc_mcu_platform.h:
write/read bytes, random, monotonic ms, optional unix seconds, log, persist/load.

Drive it from any task or loop with rnc_mcu_app_step(app, now_ms); call it at least
every 5 to 20 ms (more often at higher baud rates; the example UART buffer is 2 KB).

Unix time policy
----------------
Announces carry a unix timestamp. A receiving node drops an announce more than 300
seconds in the future, and the reference stack ignores an announce that is not newer
than the one behind its stored path. Boards usually have no clock, so the
application keeps its own, which never goes backwards and is only ever late:

  1. If the platform's unix_seconds hook returns a non-zero value (RTC, SNTP, GPS),
     that value is used. The example firmware has no such hook.
  2. Otherwise: build time (RNC_MCU_BUILD_EPOCH, set by the build at configure time)
     plus uptime, raised to a high-water mark stored in NVS every 120 seconds. After
     a reboot the clock starts at the stored mark plus 121 seconds, so it is later
     than any announce sent before the reset and paths on the other side keep
     updating. It is never ahead of real time by more than about two minutes.
  3. rnc_mcu_app_set_unix() moves the clock forward when the host or a user tells
     the device the real time (a port can wire this to a command or a GPS fix).

Consequences: the clock is behind real time by (now - build time - uptime) until a
real source is wired in; this only matters for logs and for peers that compare
timestamps with their own clock. Rebuild or set the time to bring it up to date.
Flash writes for the mark: one NVS write per 2 minutes of uptime.

Memory
------
Measured with tests/footprint.c in the mcu profile (a node, a responder and two
active links; heap bytes): about 86 KB for the node, the responder (1 KB request
limit) and two links, plus about 5 KB for the application's scratch buffers: around
92 KB of heap in total. Task stack: the core needed 7.7 KB high-water in the
footprint scenario; the example task uses 16 KB (Kconfig minimum 12 KB). Static
RAM of the firmware: about 12 KB (ESP32) and 14 KB (ESP32-S3) of .data and .bss.
Flash: the application image is about 251 KB (ESP32) and 275 KB (ESP32-S3), the
core itself about 57 KB of code plus tables. See size.txt in OUTDIR for the
build's own report.

Boards
------
The firmware targets chips, not boards, because the serial path is the same:

  esp32     Heltec WiFi LoRa 32 V2, LilyGo T-Beam (original), TTGO LoRa32, and
            other ESP32 boards. UART0 on GPIO1 (TX) / GPIO3 (RX).
  esp32s3   Heltec WiFi LoRa 32 V3, LilyGo T-Beam Supreme, T-Deck, T-Deck Plus,
            T3-S3, and other ESP32-S3 boards. UART0 on GPIO43 (TX) / GPIO44 (RX);
            boards with a native USB port can use the USB Serial/JTAG transport
            (menuconfig), in which case move the console off it.

Board pin maps differ for the radio, display and power chips; none of those is
driven yet. Set the board name in menuconfig so /info reports it.

Limits
------
  - There is no LoRa radio driver yet: the board talks to a host over serial only.
    The radio (SX126x/SX127x), RNode-style firmware behavior, Bluetooth and Wi-Fi
    interfaces are not part of this firmware.
  - AES is table-based software (not constant time with respect to cache timing);
    X25519/Ed25519 come from Monocypher. The ESP32 hardware crypto is not used.
  - Not tested on hardware; only built, and run on the host.
  - Leaf node only: no transport (forwarding), at most 2 links, 8 remembered
    announces, 12 paths (see include/reticulum_c/rnc_profile_mcu.h).
  - The random numbers come from esp_fill_random with the SAR ADC entropy source
    switched on (bootloader_random_enable), because the firmware does not run the
    radio. Do not enable it together with an ADC user without reading the ESP-IDF
    notes on random numbers.
  - The mcu profile caps packets at 500 bytes (the Reticulum default MTU); links
    through larger-MTU interfaces are clamped to it.
