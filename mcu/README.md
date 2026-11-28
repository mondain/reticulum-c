# reticulum-c for microcontrollers (ESP32, ESP32-S3 and nRF52840)

This directory holds everything needed to run the reticulum-c protocol core on a
microcontroller and an example firmware you can flash today:

```text
mcu/app/          portable example application (no platform headers)
mcu/radio/        LoRa radio support: SX126x and SX127x drivers, air framing, CSMA, airtime
                  budget, board table (portable C; see mcu/radio/README.md)
mcu/host/         host build of the same application (pty, stdin/stdout or TCP client)
mcu/tests/        tests: clock policy, transport link handling, Wi-Fi helpers, the LoRa
                  radio against software models of the chips, and the application against
                  reticulum-c-node (serial, TCP, gateway)
mcu/tools/        wifi-config.sh: provision the Wi-Fi settings without a console
mcu/esp-idf/      ESP-IDF components and the example project
mcu/build-esp-idf.sh   one command that builds a flashable image
mcu/platformio/   the same firmware for the Arduino framework on ESP32 and nRF52840
                  boards (Heltec V3/V2, T-Beam, T-Beam Supreme SX1262, T3-S3, RAK4631,
                  Heltec T114, LilyGo T-Echo): see mcu/platformio/README.md;
                  build with mcu/build-platformio.sh
```

STATUS: the firmware builds for ESP32, ESP32-S3 and nRF52840, and the same application logic
passes the host tests against reticulum-c-node and the reference Reticulum.
Hardware has been checked on a T-Echo, a T-Beam Supreme, a XIAO nRF52840 with Wio-SX1262 and a Heltec V3: short bench runs, listed in "Bench record" below. Other boards, range, sustained load and stock RNode
radio interoperability remain unverified.

## What the firmware is

A Reticulum node for a microcontroller. With the optional LoRa radio off, it has
one host interface, selected at runtime (see "Wi-Fi mode" below):

```text
serial (the default)  the Reticulum SerialInterface framing (HDLC: flag 0x7E,
                      escape 0x7D, mask 0x20) on a UART or on the chip's USB
                      Serial/JTAG port;
wifi (ESP32 only)      the same HDLC framing on a TCP connection (station mode) to
                      the TCPServerInterface of a Reticulum node, so the board joins
                      a network with no cable.
```

An unprovisioned image starts in serial mode. Updates that preserve settings
retain the selected mode. The node

- creates a persistent identity at first boot (ESP32: NVS; nRF52840: internal file system),
- registers the destination `reticulum_c.mcu.example`,
- announces at start, again 5 seconds later, then every 10 minutes
  (Kconfig: Reticulum MCU example -> Announce interval),
- answers requests on the destination's links:
  - `/echo` returns the request value unchanged
  - `/info` returns a MessagePack map: name ("reticulum-c-mcu"), version, board,
    uptime (seconds) and heap (free bytes)

The firmware is a leaf node: it does not forward other nodes' traffic (no
transport), except in the LoRa gateway mode below. A host node (reticulum-c-node or the
reference rnsd) that has the board as a SerialInterface, or that accepts its TCP
connection, routes between the board and the rest of the network.

The build and ESP-IDF instructions below cover ESP32 and ESP32-S3. For nRF52840
builds, USB serial provisioning and application-only UF2/DFU updates, use
mcu/platformio/README.md. nRF52840 stores its identity in its internal file system.

## Browser install and setup

https://mondain.github.io/reticulum-c/ provides the nine exact PlatformIO board
images and a serial setup console. Select the board and catalog version; these
can be main-commit builds as well as releases. Web Serial needs a supported
Chromium browser on a desktop and a USB connection; downloads remain available
in other browsers. See mcu/platformio/README.md for update and erase behavior.

## Prerequisites

- Docker (for `--docker` builds), or an ESP-IDF 5.x environment (tested with
  5.4.4; the Docker image is espressif/idf:v5.4.4, override with RNC_IDF_IMAGE)
- esptool (pip install esptool) to flash
- To run the host tests: cmake, a C compiler, OpenSSL development files, bash.

## Building

```sh
mcu/build-esp-idf.sh --docker esp32      [OUTDIR]
mcu/build-esp-idf.sh --docker esp32s3    [OUTDIR]
mcu/build-esp-idf.sh esp32s3             (inside an active ESP-IDF environment)
```

OUTDIR defaults to `mcu/out/<chip>`. It receives reticulum-c-mcu.bin (the app),
bootloader.bin, partition-table.bin, partitions.csv, merged.bin (a single image to
write at flash address 0x0), reticulum-c-mcu.elf, size.txt (memory and per-component
report) and flash.txt (the exact esptool commands). The bootloader offset differs per chip
(0x1000 on ESP32, 0x0 on ESP32-S3); the script checks it and merged.bin already
contains it.

## Flashing

Initial installation or intentional identity reset only:

```sh
python3 -m esptool --chip esp32s3 -p /dev/ttyUSB0 -b 460800 write_flash 0x0 merged.bin
```

WARNING: merged.bin contains erased padding over the identity NVS partition.
Flashing it resets the identity and clock mark. To update an existing node,
use the separate-parts command in flash.txt; with an unchanged partition layout
it writes only the bootloader, partition table and application, preserving NVS.

(see flash.txt in OUTDIR; use /dev/ttyACM0 for a native USB port). If the board does
not enter the bootloader by itself, hold BOOT, tap RESET, release BOOT.

The partition table (mcu/esp-idf/example/partitions.csv) has the application at 0x10000
(1.5 MB), the identity NVS at 0x9000 and a separate 16 KB NVS partition "rnccfg" at
0x190000 for the Wi-Fi settings. The partition table is part of merged.bin; the
bootloader, the table and the application sit at the same offsets as in earlier
versions, so the identity stored in the "nvs" partition survives a separate-parts
update. The rnccfg partition is not part of merged.bin: flashing does not touch the
provisioned settings.

Settings are in "idf.py menuconfig" under "Reticulum MCU example" (serial port, UART
number and pins, baud rate, task stack, announce interval, board name, the
provisioning window and BOOT pin, and the developer-only Wi-Fi defaults).
sdkconfig.defaults and sdkconfig.defaults.esp32 / .esp32s3 hold the per-chip
defaults. The default flash size is 4 MB; set it to match your board.

## Serial and host setup

In serial mode the firmware uses UART0 at 115200 baud, 8N1, which is the port behind the USB-UART
bridge on the common boards, so the host sees the board as /dev/ttyUSB0 or
/dev/ttyACM0. Nothing else may print on that port: the console is disabled (ESP32)
or moved to the chip's USB Serial/JTAG port (ESP32-S3) in sdkconfig.defaults. The
boot ROM still prints a few bytes at reset; the HDLC receiver ignores them.

reticulum-c-node configuration (the node needs a TCP or other interface for the
rest of the network):

```ini
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
```

The reference Reticulum (rnsd) takes the same SerialInterface section. Within a few
seconds of the board starting (or the node starting) the node logs the announce of
the board's destination. A client can then request /echo or /info from it, for
example with mcu/tests/echo_client.c (built in the default build as echo_client).

## Wi-Fi mode

In wifi mode the board joins an access point (station mode) and opens a TCP client
connection to host:port, the TCPServerInterface of a reticulum-c-node, the reference
rnsd, or any node that listens for TCP. The stream is HDLC framed like the serial
interface, which is also what Reticulum's TCPClientInterface/TCPServerInterface use. The
node needs nothing special:

```ini
[[Boards]]
  type = TCPServerInterface
  listen_ip = 0.0.0.0
  listen_port = 4242
```

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

## RNode mode (host-driven LoRa modem)

Besides the Reticulum node, the PlatformIO firmware can be a LoRa modem that a host
drives, the role of a stock RNode: set `mode rnode` in the setup console (or the browser
setup form, "Run as: RNode modem"; tools/wifi-config.sh --mode rnode on ESP32) and reboot.
The board then runs no Reticulum node. The serial port carries KISS frames only, in the
RNode protocol: a host (Sideband, rnsd, this project's RNode interface) detects the board,
sets the frequency, bandwidth, spreading factor, coding rate and power, switches the radio
on, and exchanges raw packets. The over-the-air format is the one the node modes already
use. Go back with `set mode serial` (the line `rnc-config` within two seconds after a
reset still opens the setup console, in every mode).

Regulatory behaviour: nothing is transmitted until the host has set all five settings
and the radio state. A host that says it is leaving (LEAVE) or asks for a restart (RESET), or
a board reset, turns the radio off and clears the settings. A host that disappears without
saying so (a crash, unplugging the cable) does not: the radio keeps its settings until the
board is reset. The airtime budget stays
active: 1 percent of every hour by default; the host may change it with the airtime lock
commands, within 0.01 to 100 percent, and the smaller of the short and long lock values
is used. You are responsible for what the host configures.

While the radio is on the board also reports about itself, in the stock firmware's messages, which `reticulum-c-ctl
status` and `rnstatus` show: once a second its airtime and the channel load (15 seconds and an hour), the noise floor
and any interference; every five seconds its temperature (ESP32-S3 and nRF52 boards) and, on the T-Beam Supreme and
the T-Echo only, the battery. The figures are this firmware's own: the channel is looked at ten times a second, load
includes the board's own sending, interference is a level at least 11 dB over the noise floor that is not a LoRa
signal, the hour's load is of the whole hour (what came before the radio was turned on counts as quiet), and the T-Echo's charge is judged from the cell's voltage, which is rough.

Destination stamp (RNS 1.6, all PlatformIO boards in node mode): networks running Reticulum 1.6 can
refuse announces without a proof of work. A board does not search for it: the stamp depends only on the
board's public data, so it is found elsewhere and loaded. `get stamp.material` prints what to stamp (it is
empty until the board has run once and created its identity), `get stamp.status` says none, valid or
stale, and `set stamp HEX` (28 hexadecimal digits) takes a stamp only if it meets the required value (25)
over that material; `set stamp clear` removes it. The stamp is stored on `save`, under its own key
beside the identity, and checked at every boot: one that does not fit this identity is ignored and shows as
stale. With a stamp the board's announces carry it and the link request cost (12.5); without one they are
unchanged. `reticulum-c-flash --port DEVICE --stamp` and the browser installer do all of this in one step.
The ESP-IDF example application has no stamp console yet.

Bluetooth LE (all PlatformIO boards): in rnode mode the board can also be
driven over Bluetooth, as a stock RNode is. It is off, and does not advertise, until you
set a six digit PIN: `set ble.pin 123456` (console or the setup tools; it is never printed,
get shows only (set) or (empty), and an empty value turns Bluetooth off again). The board
then advertises as "RNode XXXX" (XXXX: the last 16 bits of its address) with the Nordic UART
service; a phone or computer pairs with the PIN (passkey entry) and uses the same KISS
stream over the two UART characteristics. Without pairing there is no access: notifications
cannot be enabled and writes are refused. USB keeps working alongside; the module answers
the transport that last sent bytes. nRF52840 boards use the Adafruit Bluefruit stack; the ESP32
and ESP32-S3 boards use NimBLE-Arduino (pinned in platformio.ini; it adds about 5 percent of
a 3.3 MB flash partition, and on the boards with a 1.3 MB partition the image is now 86
percent full on the T-Beam v1.0/1.1 and 74 percent on the T3-S3). On ESP32 the link must be
authenticated before any byte is accepted or sent.

Not included: stock RNode EEPROM provisioning, signing and firmware-update flows
(rnodeconf cannot flash or provision this firmware), battery and temperature reports. The generic ESP-IDF image has no Bluetooth or radio selection and ignores this mode.

Status screens (LilyGo T-Echo e-paper, LilyGo T-Beam Supreme OLED, Heltec WiFi LoRa 32 V3
OLED). These three boards draw a
status page: name and version, the phase (setup or running), radio on or off, frequency and
transmit power, bandwidth, spreading factor and coding rate, RSSI and SNR of the last packet,
packet counts and airtime used, the link (USB, Bluetooth or none) and, only while it is
needed, the Bluetooth PIN. The PIN row appears only when a PIN is set (ble.pin) and Bluetooth
is advertising or connected but not yet secured; it is hidden while off, once the link is
encrypted and whenever no PIN is set. The screen only reads the node's state, runs as a
low priority task, and a screen that fails to start never affects the radio, USB or
Bluetooth. The e-paper refreshes at most every 15 s (2 s when the PIN row changes) with a
full refresh every 5 minutes; the OLED every second. Libraries (pinned in platformio.ini):
GxEPD2, Adafruit GFX, Adafruit SH110X (Supreme), Adafruit SSD1306 (Heltec V3), Adafruit
BusIO. The Heltec V3 panel is powered from Vext (GPIO36, on when low) and reset on GPIO21;
both OLEDs are at I2C 0x3C on SDA 17 and SCL 18. The e-paper uses SPIM3 (the Adafruit
nRF52 core disables SPIM0 and SPIM1). Other boards build without a screen driver.
Evidence: the layout, the PIN rule and the refresh policy are unit tested (test_mcu_status).
On 2026-11-25 the Heltec V3 OLED showed the status page (serial mode, LoRa gateway); its
PIN rows, RNode mode and the other modes were not checked on that board. On 2026-11-15 the
Supreme OLED showed the status page, and the T-Echo e-paper showed the status page and, with ble.pin set and mode rnode, showed the PIN while advertising, removed
it while a PC was paired and connected, and showed it again after the disconnect. Not
checked on hardware: the no-PIN case, the 5 minute full refresh, the Supreme PIN rows.

Evidence: the protocol logic is unit tested, and tested against this project's own host
RNode adapter over a pseudo terminal with a simulated LoRa peer. On 2026-11-14 a T-Echo
running this firmware in rnode mode was driven over USB by that host adapter (915 MHz,
125 kHz, SF8, CR 4/5, 0 dBm), with a T-Beam Supreme running the earlier gateway firmware
(same settings, close by) as the other station:
  - the board was detected and its radio settings acknowledged (radio_ready);

- an announce of 167 bytes sent through the T-Echo was received by the Supreme and
  delivered to its serial host (announce counted);
- announces transmitted by the Supreme arrived at the host through the T-Echo as valid
  announces (two of 167 bytes) with RSSI -31 dBm and SNR 12.75 and 14.25 dB.

Reference RNodeInterface (RNS 1.5.5), T-Echo, 2026-11-17: from a Linux PC, a pseudo terminal bridged
to the T-Echo's Bluetooth UART (a script written for the test, not part of the project) was given to the
unmodified reference as an RNodeInterface port (915 MHz, 125 kHz, SF8, CR 4/5, 0 dBm). The T-Echo answered
detect, firmware 1.74, platform and MCU, and echoed the frequency, bandwidth, transmit power, spreading
factor, coding rate and radio state it was given, correctly. With the reference's default settings the
interface was refused ("Bandwidth mismatch" and the like) because the reference checks the readback 0.25
seconds after configuring a serial port and the answer, through the bridge and Bluetooth, arrived about
0.26 seconds after the command; the reference waits 1 second when it drives Bluetooth itself. With that one
wait lengthened to 1 second the interface came online and sent a 167 byte announce (the reference's
counter shows 167 bytes written to the T-Echo; whether the T-Echo then transmitted it was not read from
its screen). This project's host node (reticulum-c-node, RNodeInterface) also configured the T-Echo
through the same bridge and received the Supreme's announce over LoRa, delivered over Bluetooth; after
announces sent through it by that node the T-Echo's screen read TX 7, RX 2, SNR 12.5 dB, link Bluetooth,
and the Supreme's read RX 7.

Reference RNodeInterface over USB, 2026-11-17: with the T-Echo on USB and no change to the reference's
timing, the unmodified reference configured it (the same settings), came online and sent announces, which
the Supreme received and forwarded to its serial host (below). NOT verified: the reference's own Bluetooth
mode, anything received through the reference (its receive counter rose; the packets were not examined),
and rnsd.

Supreme gateway under a network feed, 2026-11-17: a plain announce for a new destination, sent by a host
through the T-Echo in rnode mode, did not reach the Supreme's serial side in 9 minutes, whereas the
T-Echo's own announce in leaf mode was forwarded the same day (2 hops, /echo and /info answered). The
packets did reach the Supreme's node (its RX counter, 7, counts packets that passed air-frame
reassembly); neither the radio nor the framing, which rnode and leaf modes share, was at fault, and an
announce stamped 10 minutes in the past failed as well as one stamped with real time, so the 300 second
rule for announces from the future was not the cause (the Supreme's clock was 156 seconds behind). The
cause was the state the Supreme had built up: a host connected to a public network had passed it several
hundred announces, which filled its 12 path slots (kept for 7 days, no eviction), and a full table refused
every new destination; independently, a full announce queue made it refuse to learn announces at all. After a
reset the Supreme forwarded host announces again. Both are fixed (path eviction, and learning that does not
depend on the relay queue; COMPATIBILITY.md, "Path table pressure"). Hardware check of the fix, build
110b48a on the Supreme: 218 announces were passed to it from a public network in 4 minutes, then two fresh host
announces were sent through the T-Echo (USB, reference RNodeInterface), one with a real-time stamp and one
dated 10 minutes back; both reached the Supreme's serial side, twice each (the relay and its retry). One
run on one board. Rechecked on the 0.5.2 release build on 2026-11-17: after 3 hours 23 minutes without a
reboot (free heap 189,772 bytes, 144 below the start) and a 5 minute public-network feed, two fresh
announces from the T-Echo over LoRa were forwarded to the serial side within a second, and a reference
client on the public network reached the Supreme at 3 hops (`/echo`, `/info`). One board, one afternoon.

NOT verified over USB: rnsd, and Sideband (its Bluetooth session is recorded above). The script
mcu/tests/mcu_rnode_reference.sh has not been run (the reference was driven by hand over USB, above). Also not verified: a stock RNode on the other end, rnodeconf (it needs the EEPROM commands,
which are not implemented), range, sustained load, and the flow-control path with a real
host. A host program that opens the Supreme's USB port resets it (ESP32-S3 USB serial),
which is a property of that board, not of rnode mode. Other boards build only.

Bluetooth evidence (T-Echo, 2026-11-14): from a Linux PC (BlueZ) the board advertised as
"RNode 23B8", pairing with the PIN succeeded, notifications could be enabled, and writing
DETECT and the version request to the UART characteristic returned c0 08 46 c0 c0 50 01 4a c0
(detect OK, firmware 1.74) as notifications. Unpaired, notifications stayed off and a write
request was refused. The ESP32 Bluetooth transport was only compiled (all five ESP32
environments), never run on hardware.
Sideband (Android), T-Echo, 2026-11-15: after pairing the phone with the PIN in Android's
Bluetooth settings, Sideband connected over BLE once "Connect using Bluetooth" and "Device
requires BLE" were on and Sideband was restarted (its "Bluetooth" without BLE is classic
Bluetooth and cannot see this board). The board's status screen then showed the frequency
and the BLE link. Over the air (915 MHz, 125 kHz, SF8, CR 4/5, 0 dBm, close range) the
T-Echo then counted RX 2 and TX 2 against a T-Beam Supreme running this project's gateway
firmware, and its screen showed RSSI -46 dBm and SNR 12.5 dB for the last packet. NOT
verified: that Sideband itself displayed the received announces, many connect/disconnect
cycles, the range, and the ESP32 transport.

## Provisioning

The Wi-Fi settings are NEVER compiled into a release image. They live in NVS and are
set at runtime, in two ways. The keys, in namespace "rnc_net" of the NVS partition
"rnccfg" (ESP-IDF firmware; the Arduino/PlatformIO firmware uses the standard NVS
partition, namespace rnc_net, see mcu/platformio/README.md):

```text
mode      string   "serial" (default when nothing is stored) or "wifi"
ssid      string   1 to 32 bytes
password  string   empty or absent (open network), else 8 to 63 characters
host      string   name or address of the node's TCPServerInterface
port      u16      default 4242
```

and the radio keys (LoRa radio section below): lora_mode (string `off|leaf|gateway`), lora_set
(u8: which transmit settings were set), lora_freq and lora_bw (u32, Hz), lora_sf and lora_cr
(u8), lora_txp (i8, dBm), lora_air (u16, hundredths of a percent). In the console and in
wifi-config.sh they are lora.mode, lora.freq, lora.bw, lora.sf, lora.cr, lora.txp, lora.airtime.

(a) The serial console. It is not always on: it runs only when

- mode is wifi and the stored ssid, password or host are missing or invalid (it
  starts at once, the Reticulum node does not run), or
- during a window of 2 seconds after every boot (Kconfig: provisioning window), when
  the line `rnc-config` arrives on the serial port, or the BOOT button (GPIO0) is
  pressed and held for 300 ms. Holding BOOT while resetting selects the chip's ROM
  download mode instead; press it after the reset. In serial mode the window delays
  the start of the node by that time (set it to 0 to remove the window; then only
  a Wi-Fi mode with unusable settings, or the tool below, can provision).

The console is on the same serial port as the HDLC stream (115200 baud 8N1; the
USB-UART bridge of the board), because that is the port every board exposes. Use any
terminal. Commands (end a line with Enter):

```text
help                show the commands
get [key]           show one setting or all; the password is shown as (set) or
                    (empty), never in clear
set KEY VALUE       KEY is mode, ssid, password, host, port or a lora.* key; VALUE is the rest of
                    the line, so an SSID with spaces needs no quotes; refused values
                    are reported and change nothing
clear               restore the defaults (serial mode, nothing else)
save                write the settings to flash
reboot              restart the board
```

```text
Example:  rnc-config   (within 2 seconds of reset)
          set mode wifi
          set ssid MyNetwork
          set password correct horse battery
          set host 192.168.1.10
          set port 4242
          save
          reboot
```

The password is echoed as `*` while you type it; it is not stored until save. A
wrong line is refused, nothing is stored on a refusal. To go back to the serial
transport: set mode serial, save, reboot.

(b) The host tool, mcu/tools/wifi-config.sh, which needs no console:

```sh
mcu/tools/wifi-config.sh --chip esp32s3 --device /dev/ttyUSB0 \
    --ssid MyNetwork --host 192.168.1.10 --password-stdin < password.txt
```

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

```sh
RNC_SDKCONFIG_EXTRA=/path/dev.defaults mcu/build-esp-idf.sh --docker esp32
```

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

LoRa radio keys: wifi-config.sh also takes `--lora-mode off|leaf|gateway`, --lora-freq,
--lora-bw, --lora-sf, --lora-cr, --lora-txp and --lora-airtime (see its header); it refuses
leaf or gateway unless freq, bw, sf, cr and txp are all given.

Provisioning tests: mcu/tests/test_wifi_config.sh checks the tool's input validation and
(where an image generator is available) the contents of the NVS image it builds;
mcu/tests/test_net.c tests the settings validation and the console commands.

Without hardware, the host build runs the same application on a pty:

```sh
cmake -S . -B build-mcu -DRNC_PROFILE=mcu -DRNC_CRYPTO=portable -DBUILD_TESTING=OFF
cmake --build build-mcu --target reticulum-c-mcu-host
build-mcu/mcu/reticulum-c-mcu-host --pty --state /tmp/mcu-state
```

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

```text
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
```

The radio models are written by the author of the drivers; see mcu/radio/README.md for what
this does and does not show.

## LoRa radio (optional)

With a LoRa board selected the firmware can give the node a second interface, a LoRa radio,
whose over-the-air format is meant to be compatible with stock RNodes on the same frequency
and modem settings (header byte with a sequence nibble and a split flag, packets above 254
bytes in two frames, private-network sync word, CRC, explicit header). Everything is
described in mcu/radio/README.md; the essentials:

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
Heltec V2 or T-Beam v1.0/1.1 on esp32; LilyGo T3-S3 or Supreme SX1262 on esp32s3),
or RNC_SDKCONFIG_EXTRA
with CONFIG_RETICULUM_MCU_LORA_BOARD_HELTEC_V3=y and so on. The default is no LoRa board.
The Arduino/PlatformIO environments (mcu/platformio) select their board by name. The board
only chooses the pin map and the chip; the radio settings are provisioned.

Settings. Console: rnc-config within 2 seconds after reset, then for example

```text
set lora.mode leaf / set lora.freq 868.1 / set lora.bw 125 / set lora.sf 8 /
set lora.cr 5 / set lora.txp 14 / save / reboot
```

(use values that are legal for you). Or mcu/tools/wifi-config.sh --lora-mode ... .

Boards (variants, pins and how sure I am: mcu/radio/README.md): Heltec WiFi LoRa 32 V3
(SX1262), V2 (SX1276), LilyGo T-Beam v1.0/1.1 (SX1276, AXP192 radio rail switched over
I2C), LilyGo T3-S3 (SX1262 variant), RAK4631 (SX1262), Heltec T114 (SX1262), LilyGo T-Echo
(SX1262). The T-Beam Supreme SX1262 is supported with AXP2101 ALDO3 power control;
Supreme LR1121 variants and the T-Beam v1.2 are not supported.

Memory (ESP-IDF, measured): the LoRa support adds about 14.7 KB of flash on esp32 (775264
-> 789984 bytes) and 14.7 KB on esp32s3 (765040 -> 779744) to an image without a board;
selecting a board adds its SPI and I2C drivers (esp32s3 with the Heltec V3: 813088 bytes).
Static RAM grows by about 3.5 KB (.bss), the heap use by about 4 KB (the interface
object, 3.3 KB, and the application's packet buffer, 0.5 KB, plus a pending 508 byte
receive and three 508 byte transmit slots, all inside that object). The node's own
86 KB footprint (tests/footprint.c, limit 96 KB) is unchanged.

## Using the components in your own ESP-IDF project

```cmake
set(EXTRA_COMPONENT_DIRS /path/to/reticulum-c/mcu/esp-idf/components)
```

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

## Unix time policy

Announces carry a unix timestamp. A receiving node drops an announce more than 300
seconds in the future, and the reference stack ignores an announce that is not newer
than the one behind its stored path. Boards usually have no clock, so the
application keeps its own, which never goes backwards and is normally late:

1. If the platform's unix_seconds hook returns a non-zero value (RTC, SNTP, GPS),
   that value is used. The example firmware has no such hook.
2. Otherwise: build time (RNC_MCU_BUILD_EPOCH, set by the build at configure time)
   plus uptime, raised to a high-water mark stored in NVS at every boot and then every
   120 seconds. After a reboot the clock starts at the stored mark plus 121 seconds,
   so it is later than any announce sent before the reset and paths on the other side
   keep updating. Each restart can move the clock up to 121 seconds ahead of the time
   that really passed; a board restarting over and over soon after it was built could
   so get ahead of real time, and receivers drop announces more than 300 seconds in
   the future. (Up to 0.8.0 no mark was stored at boot, and a board restarted within
   120 seconds could repeat its time.)
3. rnc_mcu_app_set_unix() moves the clock forward when the host or a user tells
   the device the real time (a port can wire this to a command or a GPS fix).
   

Consequences: the clock is behind real time by (now - build time - uptime) until a
real source is wired in; this only matters for logs and for peers that compare
timestamps with their own clock. Rebuild or set the time to bring it up to date.
Flash writes for the mark: one NVS write per boot and one per 2 minutes of uptime.

## Memory

Measured with tests/footprint.c in the mcu profile (a node, a responder and two
active links; heap bytes): about 86 KB for the node, the responder (1 KB request
limit) and two links, plus about 5 KB for the application's scratch buffers: around
92 KB of heap in total. Task stack: the core needed 7.7 KB high-water in the
footprint scenario; the example task uses 16 KB (Kconfig minimum 12 KB). Static
RAM of the firmware: about 12 KB (ESP32) and 14 KB (ESP32-S3) of .data and .bss.
The earlier serial-only application image was about 251 KB (ESP32) and 275 KB
(ESP32-S3), with about 57 KB of core code and tables. These are baseline
measurements, not sizes for the current Wi-Fi/radio-enabled images. See size.txt
in OUTDIR for the actual build's report.

The tables are small on purpose, and a gateway that is attached to a large network by its host fills
them: the 12 paths, and the 4 announces that wait for the radio's announce bandwidth. A route costs
1168 bytes and a waiting announce 560 (measured in this profile; the whole node is about 51 KB). When the
path table is full the board gives up the least recently used path learned over the serial or Wi-Fi side
before one learned over the radio, and a closer announce displaces a farther one in the queue; see
COMPATIBILITY.md, "Path table pressure". Paths live one day in this profile.

## Boards

The firmware targets chips, not boards, because the serial path is the same:

```text
esp32     Heltec WiFi LoRa 32 V2, LilyGo T-Beam (original), TTGO LoRa32, and
          other ESP32 boards. UART0 on GPIO1 (TX) / GPIO3 (RX).
esp32s3   Heltec WiFi LoRa 32 V3, LilyGo T-Beam Supreme, T-Deck, T-Deck Plus,
          T3-S3, and other ESP32-S3 boards. UART0 on GPIO43 (TX) / GPIO44 (RX);
          boards with a native USB port can use the USB Serial/JTAG transport
          (menuconfig), in which case move the console off it.
```

Board pin maps differ for the radio, display and power chips. Only the LoRa radio is
driven (see the LoRa radio section; GPS, buttons and the battery are not). The T-Echo e-paper
and the Supreme and Heltec V3 OLEDs show a status page (see the status screens paragraph in the RNode section).
Set the board name in menuconfig so /info reports it.

## Bench record

Everything here was short range, on a desk, with a few boards. It is not a range, soak or sustained-load result, and
no test has had a stock RNode on the other end. Sizes are the payload sent; "intact" means compared byte for byte.

| Date | Hardware | What was run | Result |
| --- | --- | --- | --- |
| 2026-11-14 | T-Echo leaf, T-Beam Supreme gateway; 915 MHz, 125 kHz, SF8, CR 4/5, 0 dBm | Host to leaf through the gateway: `/echo`, `/info` | Passed at three hops; one request retried |
| 2026-11-14 to 17 | T-Echo in RNode mode | USB and Bluetooth from this project's node and the reference RNodeInterface; Sideband over Bluetooth | See "RNode mode" for what passed and what was not checked |
| 2026-11-23 | XIAO nRF52840 Wio-SX1262 (RNode mode), Supreme gateway; 10 dBm; firmware 0.5.3 | Driven by the reference RNS and by `reticulum-c-node`: announce, `/echo`, `/info` | Passed; RSSI -31 dBm, SNR 14 dB |
| 2026-11-24 | T-Echo (RNode mode), Supreme gateway; firmware 0.5.3 | `reticulum-c-node` RNodeInterface: announce, `/echo`, `/info` | Passed |
| 2026-11-24 | XIAO as RNode of a reference RNS 1.6.1 node that enforces stamps; Supreme | Announces from a stamped and an unstamped board | Stamped one accepted, unstamped one dropped |
| 2026-11-25 | Heltec V3 | OLED status page (serial mode, LoRa gateway) | Shown; its radio was not tested over the air |
| 2026-11-27 | Raspberry Pi 3 (64-bit OpenMANET) with a Wi-Fi HaLow card, joined to a HaLow access point; release 0.6.1 | `AutoInterface` over HaLow, 256 KiB file | Intact in 1.7 s, also after a reboot |
| 2026-11-27 | T-Echo (RNode mode) on that Pi, Supreme (RNode mode) on a PC; 920 MHz, 17 dBm at the Pi | LoRa to HaLow to the home network, small files through the Pi | 4 of 8 failed. Traced to the Supreme losing bytes over USB (next row); the through-the-Pi run was not repeated after the fix |
| 2026-11-27 | Same boards; T-Beam Supreme with the USB fix (0.7.1) | 20 known packets to the Supreme; 100-byte files from it to the Pi | Packets intact: 14 of 20 before, 20 of 20 after. Files: 6 of 8 before, 8 of 8 after |
| 2026-11-28 | T-Beam Supreme and T-Echo, both RNode mode; 920 MHz, 125 kHz, SF8, CR 4/5, 2 dBm; code of 0.8.0 | Radio reports read by `reticulum-c-ctl status`; 2 KiB and 1 KiB files between the boards | Files intact; RSSI -30 to -33 dBm, SNR 12 to 14 dB. Airtime and channel load rose and fell with the transfers; noise floor -90 to -92 dBm; temperature 29 to 30 C; battery read 100 % charged on USB power (discharging was not checked) |
| 2026-11-28 | T-Echo back on the Pi (release 0.7.0), T-Beam Supreme on a PC | One announce over LoRa | Received by the Pi; RSSI -65 dBm, SNR 12.5 dB |
| 2026-11-28 | Heltec V3 (updated from 0.6.0 keeping its settings), serial mode with LoRa gateway; 915 MHz, 125 kHz, SF8, CR 4/5, 0 dBm; firmware 0.8.0 | Over USB serial: announce, `/echo`, `/info`. Over LoRa from a T-Beam Supreme in RNode mode at 2 dBm, with nothing on the Heltec's serial port: the same, with the board reset before each run | USB passed. LoRa passed 3 of 3 with a node that had no memory of the board, each run needing one or two request retries; RSSI -41 to -42 dBm, SNR 12.5 to 14.5 dB. Forwarding between USB and LoRa was not tested |

Never run on a bench: T-Beam v1.0/v1.1, T3-S3, Heltec V2, RAK4631, Heltec T114, the ESP-IDF builds, the ESP32
Bluetooth transport, Wi-Fi mode, and the SX1302 concentrator program (`mcu/sx1302/`).

## Limits

- The LoRa radio (SX126x/SX127x) is optional and OFF until configured. The bench
  record above covers T-Echo, Supreme and XIAO SX1262 using PlatformIO firmware;
  ESP-IDF board ports and other boards retain build/model coverage only.
  By default the firmware is a Reticulum node with a LoRa interface; in rnode mode it
  speaks the stock RNode KISS protocol to a host instead (see "RNode mode"). Bluetooth LE
  is available on the PlatformIO boards in rnode mode once a PIN is set. Wi-Fi
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
  provisioning console and NVS handling in the ESP-IDF port remain unverified
  on hardware. The PlatformIO console has been exercised on the Supreme and T-Echo.
- nRF52840 boards have no Wi-Fi; their firmware (mcu/platformio) has the
  serial host transport and optional LoRa leaf/gateway modes.
- AES is table-based software (not constant time with respect to cache timing);
  X25519/Ed25519 come from Monocypher. The ESP32 hardware crypto is not used.
- Hardware coverage is a short bench exchange, not range, sustained-load or
  stock RNode interoperability evidence.
- Leaf node unless the LoRa gateway mode is configured: at most 2 links, 8 remembered
  announces, 12 paths, 4 queued announces, 8 link table entries, 2 interfaces (see
  include/reticulum_c/rnc_profile_mcu.h).
- Serial mode: the random numbers come from esp_fill_random with the SAR ADC entropy
  source switched on (bootloader_random_enable), because Wi-Fi and Bluetooth are
  off. Do not enable it together with an ADC user without reading the ESP-IDF
  notes on random numbers. Wi-Fi mode does not call bootloader_random_enable: the
  radio is the entropy source.
- The mcu profile caps packets at 500 bytes (the Reticulum default MTU); links
  through larger-MTU interfaces are clamped to it.
