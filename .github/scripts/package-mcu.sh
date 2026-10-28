#!/usr/bin/env bash
# Packages the microcontroller release files.
#
#   package-mcu.sh board   RELEASE BOARD BUILD_OUT_DIR OUTDIR
#       reticulum-c-RELEASE-mcu-BOARD.zip from the output of mcu/build-esp-idf.sh
#       (BOARD esp-idf-esp32 | esp-idf-esp32s3) or of one environment directory of
#       mcu/build-platformio.sh (BOARD = lower-cased environment name)
#   package-mcu.sh sources RELEASE OUTDIR
#       reticulum-c-RELEASE-esp-idf-component.tar.gz and
#       reticulum-c-RELEASE-platformio-library.tar.gz from the tracked files of this checkout
#
# RELEASE is the release label (the tag, for example v0.3.0). The scripts are run by
# .github/workflows/release.yml and can be run by hand the same way.
set -eu

ROOT=$(cd -P "$(dirname "$0")/../.." && pwd)
ROOT=${RNC_ROOT:-$ROOT}
VERSION=$(sed -n 's/^project(reticulum_c VERSION \([0-9][0-9.]*\).*/\1/p' "$ROOT/CMakeLists.txt")

STAGES=""
trap 'rm -rf $STAGES' EXIT

usage() { sed -n '2,12p' "$0" >&2; exit 2; }

# describe BOARD: sets TITLE, MANUAL (file in the checkout), SERIAL (setup text), WIFI
# (empty for the nRF52 boards, "idf" or "arduino" for the ESP32 firmware)
describe() {
  MANUAL=mcu/platformio/README.txt
  WIFI=
  LORA=
  case $1 in
    esp-idf-esp32)
      TITLE="ESP32 boards (ESP-IDF build): Heltec WiFi LoRa 32 V2, LilyGo T-Beam, TTGO LoRa32 and other ESP32 boards with a USB-UART bridge"
      MANUAL=mcu/README.txt
      WIFI=idf
      SERIAL="UART0 (GPIO1 TX / GPIO3 RX) at 115200 baud, 8N1: the port behind the USB-UART bridge." ;;
    esp-idf-esp32s3)
      TITLE="ESP32-S3 boards (ESP-IDF build): Heltec WiFi LoRa 32 V3, LilyGo T-Beam Supreme, T3-S3, T-Deck and other ESP32-S3 boards"
      MANUAL=mcu/README.txt
      WIFI=idf
      SERIAL="UART0 (GPIO43 TX / GPIO44 RX) at 115200 baud, 8N1; boards with a native USB port can use the USB Serial/JTAG transport (menuconfig, needs a rebuild)." ;;
    heltec_wifi_lora_32_v3) WIFI=arduino; LORA=arduino; TITLE="Heltec WiFi LoRa 32 V3 (ESP32-S3), Arduino/PlatformIO build"
      SERIAL="UART0 behind the CP2102 USB bridge, 115200 baud, 8N1." ;;
    heltec_wifi_lora_32_v2) WIFI=arduino; LORA=arduino; TITLE="Heltec WiFi LoRa 32 V2 (ESP32), Arduino/PlatformIO build"
      SERIAL="UART0 behind the CP2102 USB bridge, 115200 baud, 8N1." ;;
    ttgo_t_beam) WIFI=arduino; LORA=arduino; TITLE="LilyGo T-Beam, original (ESP32), Arduino/PlatformIO build"
      SERIAL="UART0 behind the CP2104 USB bridge, 115200 baud, 8N1." ;;
    lilygo_t3_s3) WIFI=arduino; LORA=arduino; TITLE="LilyGo T3-S3 (ESP32-S3, native USB), Arduino/PlatformIO build"
      SERIAL="The native USB serial port (CDC); the baud rate is ignored." ;;
    wiscore_rak4631) LORA=arduino; TITLE="RAKwireless WisCore RAK4631 (nRF52840), Arduino/PlatformIO build"
      SERIAL="The native USB serial port (CDC); the host must assert DTR." ;;
    heltec_t114) LORA=arduino; TITLE="Heltec Mesh Node T114 (nRF52840), Arduino/PlatformIO build"
      SERIAL="The native USB serial port (CDC); the host must assert DTR." ;;
    lilygo_t_echo) LORA=arduino; TITLE="LilyGo T-Echo (nRF52840), Arduino/PlatformIO build"
      SERIAL="The native USB serial port (CDC); the host must assert DTR." ;;
    *) echo "package-mcu: unknown board '$1'" >&2; exit 2 ;;
  esac
}

package_board() {
  release=$1 board=$2 src=$3 out=$4
  describe "$board"
  [ -f "$src/flash.txt" ] || { echo "package-mcu: $src has no flash.txt (is it a build output directory?)" >&2; exit 1; }
  # a build with Wi-Fi credentials compiled in (developer option) is never packaged
  if [ -f "$src/build-info.txt" ] && grep -q '^dev-wifi-defaults: yes' "$src/build-info.txt"; then
    echo "package-mcu: $src was built with Wi-Fi credentials compiled in (dev-wifi-defaults: yes): refusing to package it" >&2
    exit 1
  fi
  name=reticulum-c-$release-mcu-$board
  stage=$(mktemp -d "${TMPDIR:-/tmp}/rnc-package.XXXXXX")
  STAGES="$STAGES $stage"
  dir=$stage/$name
  mkdir -p "$dir" "$out"; out=$(cd "$out" && pwd)
  # the firmware files; not the build tree, the log or the (large) ELF files
  for f in "$src"/*; do
    [ -f "$f" ] || continue
    case ${f##*/} in
      build.log|*.elf|build-info.txt) continue ;;
    esac
    cp "$f" "$dir/"
  done
  cp "$ROOT/LICENSE" "$dir/"
  if [ -n "$WIFI" ]; then # the Wi-Fi provisioning tool, with the partition table it reads
    mkdir -p "$dir/tools"
    cp "$ROOT/mcu/tools/wifi-config.sh" "$dir/tools/"
  fi
  cp "$ROOT/$MANUAL" "$dir/MANUAL.txt"
  {
    echo "release:   $release"
    echo "version:   $VERSION"
    echo "board:     $board"
    echo "target:    $TITLE"
    [ ! -f "$src/build-info.txt" ] || grep -v '^\(version\|firmware\):' "$src/build-info.txt"
  } > "$dir/BUILDINFO"
  WIFI_TEXT="" WIFI_LIMIT="" WIFI_SECURITY="" LORA_TEXT="" LORA_LIMIT="No LoRa radio in this image"
  LORA_TOOL=""
  if [ "$LORA" = arduino ] && [ -n "$WIFI" ]; then
    LORA_TOOL="
  or without a console: tools/wifi-config.sh --arduino --chip CHIP --device /dev/ttyUSB0 --mode serial \\
      --lora-mode leaf --lora-freq F --lora-bw B --lora-sf N --lora-cr N --lora-txp DBM
  (replaces the whole NVS partition, so the board gets a new identity)"
  fi
  if [ "$WIFI" = idf ]; then
    LORA_LIMIT="No LoRa radio in this generic image (select a LoRa board in menuconfig and build from source)"
  fi
  if [ "$LORA" = arduino ]; then
    LORA_LIMIT="LoRa radio support is built in but OFF until you configure it"
    LORA_TEXT="
LORA. This image contains a LoRa radio driver for this board. THE RADIO IS OFF AND NEVER
TRANSMITS until you have configured the mode and ALL of: frequency, bandwidth, spreading
factor, coding rate and transmit power. There are NO default settings in the image. YOU are
responsible for a legal frequency, power (the power is at the chip's output, not at the
antenna) and duty cycle where you operate the board. The airtime budget defaults to 1 percent
of every hour; it is a safety net, not a compliance proof.
  Modes:  lora.mode leaf     LoRa is the only interface; announces on LoRa and answers /echo
                             and /info over LoRa; no forwarding
          lora.mode gateway  the serial (or Wi-Fi) interface plus LoRa with Reticulum transport
                             on, so a host node reaches the LoRa network through the board
  Settings, from the console (send the line  rnc-config  within 2 seconds after reset; then
  set lora.mode leaf, set lora.freq 868.1, set lora.bw 125, set lora.sf 8, set lora.cr 5,
  set lora.txp 14, set lora.airtime 1, save, reboot)$LORA_TOOL
  The over-the-air format is meant to be compatible with stock RNodes on the same frequency
  and modem settings. THIS HAS NEVER BEEN TRIED ON AIR: the firmware has not run on a radio.
  Read MANUAL.txt and the notes in the project (mcu/radio/README.txt) before relying on it.
"
  fi
  if [ -n "$WIFI" ]; then
    if [ "$WIFI" = idf ]; then arduino_flag=""; else arduino_flag=" --arduino"; fi
    WIFI_LIMIT=" or, once provisioned, over Wi-Fi and TCP (no access point mode)"
    WIFI_SECURITY="
  - Wi-Fi mode: the TCP link is plaintext and unauthenticated at the transport level (like
    any Reticulum TCP interface); the Wi-Fi password sits unencrypted in flash."
    WIFI_TEXT="
WI-FI. The firmware starts in serial mode. It can instead join a Wi-Fi network and connect
to the TCPServerInterface of a Reticulum node (same HDLC framing, TCP client). No
credentials are in this image: provision them after flashing, in either way:

  1. no console: tools/wifi-config.sh$arduino_flag --chip CHIP --device /dev/ttyUSB0 \\
         --ssid NAME --host NODE_ADDRESS --password-stdin < password.txt
     (needs esptool and esp-idf-nvs-partition-gen from pip, or Docker with --docker)
  2. console: within 2 seconds after reset send the line  rnc-config  on the serial port
     (115200 baud, 8N1), or press BOOT after reset; then  set mode wifi, set ssid ...,
     set password ..., set host ..., save, reboot.

MANUAL.txt describes both, the reconnect behaviour and the security notes.
"
  fi
  cat > "$dir/README.txt" <<EOF
reticulum-c $release example firmware
======================================
For: $TITLE

This is a Reticulum node for a microcontroller with, by default, ONE interface: the
Reticulum SerialInterface framing (HDLC) on the board's serial port. It registers the destination
reticulum_c.mcu.example, announces itself and answers /echo and /info requests. A host
running reticulum-c-node or the reference rnsd, with this board as a SerialInterface,
routes between the board and the network.

Serial port: $SERIAL
In serial mode nothing but the HDLC stream is written to it.
$WIFI_TEXT$LORA_TEXT
Files
  flash.txt     the exact flashing commands for this board (start here)
  BUILDINFO     release, version, commit, toolchain versions, build time
  size.txt      memory and flash use
  MANUAL.txt    the full manual for this firmware (setup, host configuration, limits)
  the images    .bin / .uf2 / .hex / .zip, named in flash.txt
The ELF file with symbols is not included; build from source to debug.

Limits (read MANUAL.txt for the complete list)
  - NOT tested on hardware: the firmware builds, and the same application logic passes
    the host tests (the radio against software models of the chips); it has not been
    flashed to a board by the project yet, and nothing has been sent or received on air.
  - $LORA_LIMIT; the board talks to a host over serial/USB$WIFI_LIMIT. No Bluetooth.
  - Leaf node (no forwarding) unless the LoRa gateway mode is configured; at most 2 links,
    8 remembered announces, 12 paths.
  - Software AES (table based, not constant time against cache timing).
  - The identity is stored unencrypted in the board's flash.$WIFI_SECURITY

Verify the download with sha256sum -c SHA256SUMS (published with the release).
EOF
  (cd "$stage" && rm -f "$out/$name.zip" && zip -qrX "$out/$name.zip" "$name")
  echo "packaged $out/$name.zip"
}

# one tracked-files archive of a checkout: tar the files git knows, under one directory
source_archive() {
  release=$1 kind=$2 out=$3
  shift 3
  name=reticulum-c-$release-$kind
  stage=$(mktemp -d "${TMPDIR:-/tmp}/rnc-package.XXXXXX")
  STAGES="$STAGES $stage"
  mkdir -p "$stage/$name" "$out"; out=$(cd "$out" && pwd)
  (cd "$ROOT" && git ls-files -- "$@") > "$stage/files"
  [ -s "$stage/files" ] || { echo "package-mcu: no tracked files matched for $kind (is $ROOT a git checkout?)" >&2; exit 1; }
  tar -C "$ROOT" -cf - -T "$stage/files" | tar -C "$stage/$name" -xf -
  cat > "$stage/$name/README-$kind.txt"
  tar -C "$stage" -czf "$out/$name.tar.gz" "$name"
  echo "packaged $out/$name.tar.gz"
}

package_sources() {
  release=$1 out=$2
  source_archive "$release" esp-idf-component "$out" \
    CMakeLists.txt idf_component.yml LICENSE include src mcu/app mcu/radio mcu/esp-idf mcu/tools mcu/build-esp-idf.sh mcu/README.txt <<EOF
reticulum-c $release as an ESP-IDF component
=============================================
The Reticulum protocol core (C11, sans-I/O), built with the small mcu capacity profile and
the portable crypto backend (no mbedTLS or OpenSSL), and a portable example application,
for ESP32 and ESP32-S3 with ESP-IDF 5.x. Version $VERSION.

Use it from your project's top-level CMakeLists.txt, before including project.cmake:

  set(EXTRA_COMPONENT_DIRS /path/to/this/directory/mcu/esp-idf/components)

and require the component in yours: REQUIRES reticulum_c (the core) and, optionally,
reticulum_c_mcu_app (the example application). The core defines RNC_PROFILE_MCU publicly so
every file that includes the reticulum_c headers sees the same capacity constants.

mcu/esp-idf/example is a complete firmware project; mcu/build-esp-idf.sh --docker esp32s3
builds it (see mcu/README.txt for the details, boards and limits).

This is a source archive: the firmware images are in the reticulum-c-$release-mcu-*.zip
files of the release. Not tested on hardware. The LoRa radio (mcu/radio) is optional and OFF
until configured: select the board with the Kconfig choice "LoRa board" and read
mcu/radio/README.txt (regulatory notes) first.
EOF
  source_archive "$release" platformio-library "$out" \
    CMakeLists.txt library.json LICENSE include src mcu/app mcu/radio mcu/platformio mcu/tools mcu/README.txt mcu/build-platformio.sh <<EOF
reticulum-c $release as a PlatformIO library
============================================
The Reticulum protocol core (C11, sans-I/O) and a portable example application for the
Arduino framework on ESP32 / ESP32-S3 and nRF52840 boards: library.json at this directory.
Version $VERSION.

In your platformio.ini:

  lib_deps = file:///path/to/this/directory
  lib_ldf_mode = chain

then #include "rnc_mcu_app.h" (see mcu/app) or the core headers. The library is built with the
mcu capacity profile and the portable crypto backend (no OpenSSL); the build flags and the
include paths for your sources come from library.json and mcu/platformio/lib_extra.py.

mcu/platformio is a complete project for seven boards (README.txt there); with a Python 3
and network access, mcu/build-platformio.sh builds all of them with a pinned PlatformIO.

This is a source archive: the firmware images are in the reticulum-c-$release-mcu-*.zip
files of the release. Not tested on hardware. The LoRa radio (mcu/radio) is optional and OFF
until configured; read mcu/radio/README.txt (regulatory notes) first.
EOF
}

case ${1:-} in
  board) [ $# -eq 5 ] || usage; package_board "$2" "$3" "$4" "$5" ;;
  sources) [ $# -eq 3 ] || usage; package_sources "$2" "$3" ;;
  *) usage ;;
esac
