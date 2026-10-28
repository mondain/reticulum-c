reticulum-c for microcontrollers (ESP32 and ESP32-S3)
======================================================

This directory holds everything needed to run the reticulum-c protocol core on a
microcontroller and an example firmware you can flash today:

  mcu/app/          portable example application (no platform headers)
  mcu/radio/        LoRa radio support: SX126x and SX127x drivers, air framing, CSMA, airtime
                    budget, board table (portable C; see mcu/radio/README.txt)
  mcu/host/         host build of the same application (pty, stdin/stdout or TCP client)
  mcu/tests/        tests: clock policy, transport link handling, Wi-Fi helpers, the LoRa
                    radio against software models of the chips, and the application against
                    reticulum-c-node (serial, TCP, gateway)
  mcu/tools/        wifi-config.sh: provision the Wi-Fi settings without a console
  mcu/esp-idf/      ESP-IDF components and the example project
  mcu/build-esp-idf.sh   one command that builds a flashable image
  mcu/platformio/   the same firmware for the Arduino framework on ESP32 and nRF52840
                    boards (Heltec V3/V2, T-Beam, T3-S3, RAK4631, Heltec T114, LilyGo
                    T-Echo): see mcu/platformio/README.txt; build with mcu/build-platformio.sh

STATUS: the firmware builds for esp32 and esp32s3 and the same application logic
passes the host tests against reticulum-c-node and the reference Reticulum. It has
NOT been run on hardware yet. The LoRa radio support (below) is new and has only ever
run against software models of the radio chips: nothing has been sent or received on air.

What the firmware is
--------------------
A Reticulum node for a microcontroller with one interface, in one of two modes chosen
at runtime (see "Wi-Fi mode" below):

  serial (the default)  the Reticulum SerialInterface framing (HDLC: flag 0x7E,
                        escape 0x7D, mask 0x20) on a UART or on the chip's USB
                        Serial/JTAG port;
  wifi                  the same HDLC framing on a TCP connection (station mode) to
                        the TCPServerInterface of a Reticulum node, so the board joins
                        a network with no cable.

A freshly flashed image is in serial mode, exactly as before. The node

  - creates a persistent identity at first boot (stored in NVS flash),
  - registers the destination  reticulum_c.mcu.example,
  - announces at start, again 5 seconds later, then every 10 minutes
    (Kconfig: Reticulum MCU example -> Announce interval),
  - answers requests on the destination's links:
      /echo   returns the request value unchanged
      /info   returns a MessagePack map: name ("reticulum-c-mcu"), version, board,
              uptime (seconds) and heap (free bytes)

The firmware is a leaf node: it does not forward other nodes' traffic (no
transport), except in the LoRa gateway mode below. A host node (reticulum-c-node or the
reference rnsd) that has the board as a SerialInterface, or that accepts its TCP
connection, routes between the board and the rest of the network.

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
bootloader.bin, partition-table.bin, partitions.csv, merged.bin (a single image to
write at flash address 0x0), reticulum-c-mcu.elf, size.txt (memory and per-component
report) and flash.txt (the exact esptool commands). The bootloader offset differs per chip
(0x1000 on ESP32, 0x0 on ESP32-S3); the script checks it and merged.bin already
contains it.

Flashing
--------
  python3 -m esptool --chip esp32s3 -p /dev/ttyUSB0 -b 460800 write_flash 0x0 merged.bin

(see flash.txt in OUTDIR; use /dev/ttyACM0 for a native USB port). If the board does
not enter the bootloader by itself, hold BOOT, tap RESET, release BOOT.

The partition table (mcu/esp-idf/example/partitions.csv) has the application at 0x10000
(1.5 MB), the identity NVS at 0x9000 and a separate 16 KB NVS partition "rnccfg" at
0x190000 for the Wi-Fi settings. The partition table is part of merged.bin; the
bootloader, the table and the application sit at the same offsets as in earlier
versions, so the identity stored in the "nvs" partition survives an update by
esptool. The rnccfg partition is not part of merged.bin: flashing does not touch the
provisioned settings.

Settings are in "idf.py menuconfig" under "Reticulum MCU example" (serial port, UART
number and pins, baud rate, task stack, announce interval, board name, the
provisioning window and BOOT pin, and the developer-only Wi-Fi defaults).
sdkconfig.defaults and sdkconfig.defaults.esp32 / .esp32s3 hold the per-chip
defaults. The default flash size is 4 MB; set it to match your board.

Serial and host setup
---------------------
In serial mode the firmware uses UART0 at 115200 baud, 8N1, which is the port behind the USB-UART
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

Wi-Fi mode
----------
In wifi mode the board joins an access point (station mode) and opens a TCP client
connection to host:port, the TCPServerInterface of a reticulum-c-node, the reference
rnsd, or any node that listens for TCP. The stream is HDLC framed like the serial
interface, which is also what Reticulum's TCPClientInterface/TCPServerInterface use. The
node needs nothing special:

  [[Boards]]
    type = TCPServerInterface
    listen_ip = 0.0.0.0
    listen_port = 4242

The board announces after every (re)connection, so the node learns the path again at
once. The announce schedule is otherwise unchanged.

The connection is supervised at two levels, each with its own reconnect and exponential
backoff (0.5 s doubling to 30 s, with a little jitter): the access point (esp_wifi
events; an attempt that gets nowhere for 30 s is restarted) and the TCP connection
(connect timeout 10 s; a refused or reset connection, an end of stream or a send error
all take it down and start the backoff). The socket is non-blocking with TCP_NODELAY and
keepalive (idle 30 s, interval 10 s, 3 probes: a vanished server is noticed in about a
minute). When the connection goes down the application stops reading and writing, drops
what it had queued for it (a late delivery over the next connection helps nobody), resets
the HDLC decoder (a half frame of the old connection is never glued to the new stream)
and does not announce until the link is up again. Output goes through a 4096 byte queue;
a frame that does not fit is dropped whole (Reticulum tolerates lost frames; a half frame
would cost two), after the queue was given a chance to drain.

Provisioning
------------
The Wi-Fi settings are NEVER compiled into a release image. They live in NVS and are
set at runtime, in two ways. The keys, in namespace "rnc_net" of the NVS partition
"rnccfg" (ESP-IDF firmware; the Arduino/PlatformIO firmware uses the standard NVS
partition, namespace rnc_net, see mcu/platformio/README.txt):

  mode      string   "serial" (default when nothing is stored) or "wifi"
  ssid      string   1 to 32 bytes
  password  string   empty or absent (open network), else 8 to 63 characters
  host      string   name or address of the node's TCPServerInterface
  port      u16      default 4242

and the radio keys (LoRa radio section below): lora_mode (string off|leaf|gateway), lora_set
(u8: which transmit settings were set), lora_freq and lora_bw (u32, Hz), lora_sf and lora_cr
(u8), lora_txp (i8, dBm), lora_air (u16, hundredths of a percent). In the console and in
wifi-config.sh they are lora.mode, lora.freq, lora.bw, lora.sf, lora.cr, lora.txp, lora.airtime.

(a) The serial console. It is not always on: it runs only when
      - mode is wifi and the stored ssid, password or host are missing or invalid (it
        starts at once, the Reticulum node does not run), or
      - during a window of 2 seconds after every boot (Kconfig: provisioning window), when
        the line  rnc-config  arrives on the serial port, or the BOOT button (GPIO0) is
        pressed and held for 300 ms. Holding BOOT while resetting selects the chip's ROM
        download mode instead; press it after the reset. In serial mode the window delays
        the start of the node by that time (set it to 0 to remove the window; then only
        a Wi-Fi mode with unusable settings, or the tool below, can provision).
    The console is on the same serial port as the HDLC stream (115200 baud 8N1; the
    USB-UART bridge of the board), because that is the port every board exposes. Use any
    terminal. Commands (end a line with Enter):

      help                show the commands
      get [key]           show one setting or all; the password is shown as (set) or
                          (empty), never in clear
      set KEY VALUE       KEY is mode, ssid, password, host, port or a lora.* key; VALUE is the rest of
                          the line, so an SSID with spaces needs no quotes; refused values
                          are reported and change nothing
      clear               restore the defaults (serial mode, nothing else)
      save                write the settings to flash
      reboot              restart the board

    Example:  rnc-config   (within 2 seconds of reset)
              set mode wifi
              set ssid MyNetwork
              set password correct horse battery
              set host 192.168.1.10
              set port 4242
              save
              reboot
    The password is echoed as * while you type it; it is not stored until save. A
    wrong line is refused, nothing is stored on a refusal. To go back to the serial
    transport: set mode serial, save, reboot.

(b) The host tool, mcu/tools/wifi-config.sh, which needs no console:

      mcu/tools/wifi-config.sh --chip esp32s3 --device /dev/ttyUSB0 \
          --ssid MyNetwork --host 192.168.1.10 --password-stdin < password.txt

    It writes the settings as an NVS image (IDF's nvs_partition_gen: pip install
    esp-idf-nvs-partition-gen, an active ESP-IDF environment, or --docker with the pinned
    espressif/idf image) and flashes it at the offset of the rnccfg partition with esptool,
    reading the offset and size from partitions.csv (in the build output and in the
    release zips). Only that partition is written, so the identity is kept. --mode serial
    writes serial mode, --image-only FILE writes the image without flashing it (to flash
    with another tool), --password on the command line is possible but visible in the
    process list; prefer --password-stdin or the environment variable RNC_WIFI_PASSWORD.
    There is no console step: the board comes up in wifi mode at its next reset. The tool
    is a bash script; the image generator and esptool are Python programs (an
    alternative that needs no Python is to type the settings into the console).

For developers only: Kconfig "Developer defaults for Wi-Fi (NOT FOR RELEASE)" compiles an
SSID, password and server into the image, used while nothing is stored (anything
provisioned wins). The build marks itself in build-info.txt (dev-wifi-defaults: yes),
refuses to run with RNC_RELEASE=1, and the release packaging refuses to package it. Set
it through a defaults file kept outside the repository:
  RNC_SDKCONFIG_EXTRA=/path/dev.defaults mcu/build-esp-idf.sh --docker esp32
The credentials are then readable in the image and in the ELF file.

SECURITY NOTES. The TCP link is plaintext and unauthenticated at the transport level, like
any Reticulum TCP interface: anyone on the path can read and modify the bytes, and anyone
who can reach the server's port can connect to it (use a firewall, a trusted network or a
tunnel). Reticulum's own protections apply above it (encrypted links, signed announces);
an interface access code (IFAC) is not implemented by this firmware. The Wi-Fi password and
the settings sit in flash UNENCRYPTED: anyone who holds the board can read them (esptool
read_flash). NVS encryption and flash encryption exist in ESP-IDF (they need a key partition
and a different provisioning flow) and are not enabled here. The console can edit the
settings of anyone with serial access to the board; the tool and the console need physical
access. The identity key is stored unencrypted in the same way.

LoRa radio keys: wifi-config.sh also takes --lora-mode off|leaf|gateway, --lora-freq,
--lora-bw, --lora-sf, --lora-cr, --lora-txp and --lora-airtime (see its header); it refuses
leaf or gateway unless freq, bw, sf, cr and txp are all given.

Provisioning tests: mcu/tests/test_wifi_config.sh checks the tool's input validation and
(where an image generator is available) the contents of the NVS image it builds;
mcu/tests/test_net.c tests the settings validation and the console commands.

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

The host build also has the Wi-Fi mode's logic, with a TCP client socket instead of the
Wi-Fi driver: build/mcu/reticulum-c-mcu-host --tcp HOST:PORT. It reconnects with
backoff as the firmware does, and logs "tcp: connection failed", "tcp: connection lost",
"transport up" and "transport down". ctest (label mcu) runs
  reticulum_mcu_unit   clock policy, link handling (no announce while down, announce soon
                       after the link returns, queued output dropped, HDLC decoder
                       reset), backoff, output queue, settings and console; no sockets
  reticulum_mcu_tcp    the harness started before the node (it retries, then connects),
                       the C echo client requests /echo and /info through the node, the
                       node is killed (the harness notices) and started again on the same
                       port (the harness reconnects, announces again although its
                       regular interval is 10 minutes, and answers again); with
                       RNC_INTEROP_TESTS the reference Reticulum does the same
                       (reticulum_mcu_tcp_reference)
  reticulum_mcu_wifi_config   the provisioning tool
  reticulum_mcu_radio         the LoRa support on the host: radio core, the SX126x and SX127x
                       drivers against software models of the chips, the LoRa interface on a
                       simulated shared channel (loss, collisions, hidden node, airtime budget),
                       two instances of the application talking Reticulum over simulated
                       LoRa (announce, path request, links, /echo and /info with packets of
                       up to 483 bytes that cross the air as two frames), the regulatory gate
  reticulum_mcu_radio_mutations   breaks the header layout, the split reassembly, the sync
                       word, the airtime limiter and others in a scratch copy: the tests must
                       fail for every one of the 30 mutations
  reticulum_mcu_gateway   a reticulum-c-node reaches the /echo and /info of a simulated board
                       behind the harness in gateway mode (reticulum-c-mcu-host --lora gateway
                       ..., see its header: the radio settings are required, as on the board)
  reticulum_mcu_radio_reference   (RNC_INTEROP_TESTS) the LoRa bit rate of 320 settings against
                       the unmodified reference RNodeInterface
The radio models are written by the author of the drivers; see mcu/radio/README.txt for what
this does and does not show.

LoRa radio (optional)
---------------------
With a LoRa board selected the firmware can give the node a second interface, a LoRa radio,
whose over-the-air format is meant to be compatible with stock RNodes on the same frequency
and modem settings (header byte with a sequence nibble and a split flag, packets above 254
bytes in two frames, private-network sync word, CRC, explicit header). Everything is
described in mcu/radio/README.txt; the essentials:

  REGULATORY. The radio is OFF, and the chip is not even spoken to, until the operator has
  set lora.mode (leaf or gateway) AND lora.freq, lora.bw, lora.sf, lora.cr and lora.txp. No
  default transmit setting exists anywhere in the sources or in a release image. The
  operator is responsible for a legal frequency, power and duty cycle (the power is the
  power at the chip's output, not at the antenna). The airtime budget (lora.airtime)
  defaults to 1 percent of every hour and is enforced before every transmission.

  Modes. lora.mode off (default): no radio, the serial or Wi-Fi leaf of the earlier
  versions. leaf: LoRa is the only interface; the node announces on LoRa and answers /echo
  and /info over LoRa; no forwarding; the serial port is free for status text (the Wi-Fi
  mode, if configured, is not started). gateway: the serial or Wi-Fi interface plus LoRa
  with Reticulum transport ON, so that a host node reaches the LoRa network through the
  board. Transport is OFF in every other mode. The mcu profile's tables are small (see
  Limits); a gateway is a small bridge, not a repeater for a busy network.

  Build. ESP-IDF: menuconfig -> Reticulum MCU example -> LoRa board (Heltec V3 on esp32s3;
  Heltec V2 or T-Beam v1.0/1.1 on esp32; LilyGo T3-S3 on esp32s3), or RNC_SDKCONFIG_EXTRA
  with CONFIG_RETICULUM_MCU_LORA_BOARD_HELTEC_V3=y and so on. The default is no LoRa board.
  The Arduino/PlatformIO environments (mcu/platformio) select their board by name. The board
  only chooses the pin map and the chip; the radio settings are provisioned.

  Settings. Console: rnc-config within 2 seconds after reset, then for example
      set lora.mode leaf / set lora.freq 868.1 / set lora.bw 125 / set lora.sf 8 /
      set lora.cr 5 / set lora.txp 14 / save / reboot
  (use values that are legal for you). Or mcu/tools/wifi-config.sh --lora-mode ... .

  Boards (variants, pins and how sure I am: mcu/radio/README.txt): Heltec WiFi LoRa 32 V3
  (SX1262), V2 (SX1276), LilyGo T-Beam v1.0/1.1 (SX1276, AXP192 radio rail switched over
  I2C), LilyGo T3-S3 (SX1262 variant), RAK4631 (SX1262), Heltec T114 (SX1262), LilyGo T-Echo
  (SX1262). The T-Beam Supreme (AXP2101) and the T-Beam v1.2 are not supported.

  Memory (ESP-IDF, measured): the LoRa support adds about 14.7 KB of flash on esp32 (775264
  -> 789984 bytes) and 14.7 KB on esp32s3 (765040 -> 779744) to an image without a board;
  selecting a board adds its SPI and I2C drivers (esp32s3 with the Heltec V3: 813088 bytes).
  Static RAM grows by about 3.5 KB (.bss), the heap use by about 4 KB (the interface
  object, 3.3 KB, and the application's packet buffer, 0.5 KB, plus a pending 508 byte
  receive and three 508 byte transmit slots, all inside that object). The node's own
  86 KB footprint (tests/footprint.c, limit 96 KB) is unchanged.

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

Board pin maps differ for the radio, display and power chips. Only the LoRa radio is
driven (see the LoRa radio section; the display, GPS, buttons and the battery are not).
Set the board name in menuconfig so /info reports it.

Limits
------
  - The LoRa radio (SX126x/SX127x) is new, optional and OFF until configured; it has never
    run on a real radio. The firmware is not an RNode (it does not speak KISS to a host); it
    is a Reticulum node with a LoRa interface. Bluetooth is not part of this firmware. Wi-Fi
    is a TCP client only (no access point mode, no Reticulum AutoInterface, no UDP, no TLS,
    no IFAC).
  - Wi-Fi mode needs more memory: the firmware image grows from about 251 KB to
    775 KB on ESP32 (765 KB on ESP32-S3), static RAM from 12 KB to 39 KB (ESP32), and the
    Wi-Fi driver takes tens of KB of heap on top of the node's 92 KB. Wi-Fi power save
    stays at the driver default (modem sleep): latency of tens of milliseconds, and the
    radio draws far more current than the serial firmware.
  - Name resolution (getaddrinfo) of the server host blocks the Reticulum task for as
    long as the resolver takes; use an IP address if that matters.
  - Wi-Fi mode is not tested on hardware: only built. The application logic and the TCP
    client are tested on the host (above); the ESP-IDF Wi-Fi and lwIP glue, the
    provisioning console and the NVS partition handling are compiled but never ran.
  - nRF52840 boards have no Wi-Fi; their firmware (mcu/platformio) has the
    serial mode only.
  - AES is table-based software (not constant time with respect to cache timing);
    X25519/Ed25519 come from Monocypher. The ESP32 hardware crypto is not used.
  - Not tested on hardware; only built, and run on the host.
  - Leaf node unless the LoRa gateway mode is configured: at most 2 links, 8 remembered
    announces, 12 paths, 4 queued announces, 8 link table entries, 2 interfaces (see
    include/reticulum_c/rnc_profile_mcu.h).
  - Serial mode: the random numbers come from esp_fill_random with the SAR ADC entropy
    source switched on (bootloader_random_enable), because the firmware does not run
    the radio. Do not enable it together with an ADC user without reading the ESP-IDF
    notes on random numbers. Wi-Fi mode does not call bootloader_random_enable: the
    radio is the entropy source.
  - The mcu profile caps packets at 500 bytes (the Reticulum default MTU); links
    through larger-MTU interfaces are clamped to it.
