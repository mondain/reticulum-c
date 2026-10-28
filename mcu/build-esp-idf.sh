#!/usr/bin/env bash
# Builds the ESP-IDF example firmware (mcu/esp-idf/example) for an ESP32 or ESP32-S3.
#
#   mcu/build-esp-idf.sh [--docker] esp32|esp32s3 [OUTDIR]
#
# Without --docker an ESP-IDF environment must already be active (idf.py on PATH,
# after ". $IDF_PATH/export.sh"). With --docker the build runs inside the official
# espressif/idf image, pinned below, so only Docker is needed.
#
# OUTDIR (default: mcu/out/<chip>) receives
#   reticulum-c-mcu.bin   the application image
#   bootloader.bin, partition-table.bin
#   merged.bin            one flashable image, written at address 0x0
#   reticulum-c-mcu.elf   with symbols, for debugging
#   size.txt              memory and per-component size report
#   flash.txt             the exact esptool commands
#   partitions.csv        the partition table (the "rnccfg" partition holds the Wi-Fi
#                         settings; see mcu/tools/wifi-config.sh)
#   build/                the IDF build tree
#
# RNC_SDKCONFIG_EXTRA=FILE adds an sdkconfig defaults file (for example the developer
# Wi-Fi defaults below, kept outside the repository).
#
# RELEASE BUILDS MUST NOT CONTAIN Wi-Fi CREDENTIALS. The Kconfig option
# RETICULUM_MCU_DEV_WIFI_DEFAULTS compiles them in for developers; a build that has it
# is marked "dev-wifi-defaults: yes" in build-info.txt (the release packaging refuses
# such a build) and the script fails when RNC_RELEASE=1 is set.
set -eu

IDF_IMAGE=${RNC_IDF_IMAGE:-espressif/idf:v5.4.4}
USE_DOCKER=0
if [ "${1:-}" = "--docker" ]; then USE_DOCKER=1; shift; fi
CHIP=${1:-}
case "$CHIP" in
  esp32) BOOT_OFFSET=0x1000 ;;
  esp32s3) BOOT_OFFSET=0x0 ;;
  *) echo "usage: $0 [--docker] esp32|esp32s3 [OUTDIR]" >&2; exit 2 ;;
esac
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
OUT=${2:-$HERE/out/$CHIP}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

# The version is set once, in the project() line of CMakeLists.txt; the firmware
# (through the component's CMake files) and the files stamped below read it from there.
VERSION=$(sed -n 's/^project(reticulum_c VERSION \([0-9][0-9.]*\).*/\1/p' "$ROOT/CMakeLists.txt")
[ -n "$VERSION" ] || { echo "cannot read the version from $ROOT/CMakeLists.txt" >&2; exit 1; }
COMMIT=${RNC_COMMIT:-$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)}

EXTRA_MOUNT=""
if [ -n "${RNC_SDKCONFIG_EXTRA:-}" ] && [ "${RNC_IN_DOCKER:-}" != 1 ]; then
  [ -f "$RNC_SDKCONFIG_EXTRA" ] || { echo "no such file: $RNC_SDKCONFIG_EXTRA" >&2; exit 1; }
  EXTRA_FILE=$(cd "$(dirname "$RNC_SDKCONFIG_EXTRA")" && pwd)/$(basename "$RNC_SDKCONFIG_EXTRA")
  EXTRA_MOUNT="-v $EXTRA_FILE:/extra.defaults:ro"
fi
if [ "$USE_DOCKER" = 1 ]; then
  command -v docker >/dev/null || { echo "docker not found" >&2; exit 1; }
  [ -z "$EXTRA_MOUNT" ] || export RNC_SDKCONFIG_EXTRA=/extra.defaults
  # The container user must own the output, so run as the invoking user. The source
  # tree is mounted read-write because the IDF component manager writes a lock file
  # next to the project; those files are in the example's .gitignore.
  exec docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp \
    -e RNC_IN_DOCKER=1 -e RNC_COMMIT="$COMMIT" -e RNC_IDF_IMAGE="$IDF_IMAGE" \
    -e RNC_SDKCONFIG_EXTRA="${RNC_SDKCONFIG_EXTRA:-}" -e RNC_RELEASE="${RNC_RELEASE:-0}" \
    $EXTRA_MOUNT -v "$ROOT:/project" -v "$OUT:/out" -w /project \
    "$IDF_IMAGE" bash /project/mcu/build-esp-idf.sh "$CHIP" /out
fi

command -v idf.py >/dev/null || {
  echo "idf.py not found: activate an ESP-IDF 5.x environment first (. \$IDF_PATH/export.sh), or use --docker" >&2
  exit 1
}
EXAMPLE=$ROOT/mcu/esp-idf/example
BUILD=$OUT/build
DEFAULTS="$EXAMPLE/sdkconfig.defaults;$EXAMPLE/sdkconfig.defaults.$CHIP"
[ -z "${RNC_SDKCONFIG_EXTRA:-}" ] || DEFAULTS="$DEFAULTS;$RNC_SDKCONFIG_EXTRA"
rm -rf "$BUILD"
(
  cd "$EXAMPLE"
  idf.py -B "$BUILD" -DIDF_TARGET="$CHIP" -DSDKCONFIG="$BUILD/sdkconfig" \
    -DSDKCONFIG_DEFAULTS="$DEFAULTS" build
  idf.py -B "$BUILD" -DIDF_TARGET="$CHIP" -DSDKCONFIG="$BUILD/sdkconfig" \
    -DSDKCONFIG_DEFAULTS="$DEFAULTS" size > "$OUT/size.txt"
  idf.py -B "$BUILD" -DIDF_TARGET="$CHIP" -DSDKCONFIG="$BUILD/sdkconfig" \
    -DSDKCONFIG_DEFAULTS="$DEFAULTS" size-components >> "$OUT/size.txt"
)

DEV_WIFI=no
if grep -q '^CONFIG_RETICULUM_MCU_DEV_WIFI_DEFAULTS=y' "$BUILD/sdkconfig"; then
  DEV_WIFI=yes
  echo "WARNING: this build has Wi-Fi credentials compiled in (RETICULUM_MCU_DEV_WIFI_DEFAULTS): developer build, do not distribute" >&2
  if [ "${RNC_RELEASE:-0}" = 1 ]; then
    echo "refusing: RNC_RELEASE=1 and credentials are compiled in" >&2
    exit 1
  fi
fi
cp "$EXAMPLE/partitions.csv" "$OUT/partitions.csv"
cp "$BUILD/reticulum_c_mcu.bin" "$OUT/reticulum-c-mcu.bin"
cp "$BUILD/reticulum_c_mcu.elf" "$OUT/reticulum-c-mcu.elf"
cp "$BUILD/bootloader/bootloader.bin" "$OUT/bootloader.bin"
cp "$BUILD/partition_table/partition-table.bin" "$OUT/partition-table.bin"

# The offsets and flash parameters IDF itself would flash with are in flash_args;
# check the bootloader offset (0x1000 on ESP32, 0x0 on ESP32-S3) before merging.
grep -q "^$BOOT_OFFSET bootloader/bootloader.bin" "$BUILD/flash_args" || {
  echo "unexpected bootloader offset in $BUILD/flash_args (wanted $BOOT_OFFSET)" >&2
  cat "$BUILD/flash_args" >&2
  exit 1
}
(cd "$BUILD" && python3 -m esptool --chip "$CHIP" merge_bin -o "$OUT/merged.bin" @flash_args)

APP_OFFSET=$(sed -n 's/^\(0x[0-9a-f]*\) reticulum_c_mcu.bin$/\1/p' "$BUILD/flash_args")
PT_OFFSET=$(sed -n 's/^\(0x[0-9a-f]*\) partition_table\/partition-table.bin$/\1/p' "$BUILD/flash_args")
FLASH_OPTS=$(head -1 "$BUILD/flash_args")
cat > "$OUT/flash.txt" <<EOF
reticulum-c $VERSION example firmware, ESP-IDF build for $CHIP.

Flash the single merged image (all parts, from address 0x0 of the flash):

  python3 -m esptool --chip $CHIP -p /dev/ttyUSB0 -b 460800 write_flash 0x0 merged.bin

Or flash the parts separately (same result):

  python3 -m esptool --chip $CHIP -p /dev/ttyUSB0 -b 460800 write_flash $FLASH_OPTS \\
    $BOOT_OFFSET bootloader.bin $PT_OFFSET partition-table.bin $APP_OFFSET reticulum-c-mcu.bin

The firmware starts in serial mode (HDLC on the serial port). To use it over Wi-Fi
instead, provision it after flashing, with no credentials in the image:

  mcu/tools/wifi-config.sh --chip $CHIP --port /dev/ttyUSB0 --ssid NAME --host NODE_ADDRESS
      (writes only the "rnccfg" partition, the identity is kept; needs the repository
       checkout and esptool + ESP-IDF's nvs_partition_gen or Docker)
  or, with a serial terminal at 115200 baud: send the line  rnc-config  within 2
  seconds after reset (or press BOOT), then use  set mode wifi, set ssid ..., save,
  reboot  (see MANUAL.txt).

Replace /dev/ttyUSB0 with the board's port (/dev/ttyACM0 on a native USB port,
COMx on Windows). Hold BOOT while pressing RESET if the board does not enter the
bootloader by itself. Install esptool with: pip install esptool
EOF
{
  echo "version:   $VERSION"
  echo "commit:    $COMMIT"
  echo "firmware:  esp-idf-$CHIP"
  echo "idf:       $(idf.py --version 2>/dev/null | tail -1)"
  echo "image:     ${RNC_IDF_IMAGE:-$IDF_IMAGE}"
  echo "compiler:  $("xtensa-$CHIP-elf-gcc" --version 2>/dev/null | head -1)"
  echo "dev-wifi-defaults: $DEV_WIFI"
  echo "built:     $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$OUT/build-info.txt"
echo "built $CHIP (reticulum-c $VERSION): $OUT"
ls -l "$OUT/merged.bin" "$OUT/reticulum-c-mcu.bin" "$OUT/bootloader.bin" "$OUT/partition-table.bin"
