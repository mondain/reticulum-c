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
#   build/                the IDF build tree
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

if [ "$USE_DOCKER" = 1 ]; then
  command -v docker >/dev/null || { echo "docker not found" >&2; exit 1; }
  # The container user must own the output, so run as the invoking user. The source
  # tree is mounted read-write because the IDF component manager writes a lock file
  # next to the project; those files are in the example's .gitignore.
  exec docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp \
    -e RNC_IN_DOCKER=1 \
    -v "$ROOT:/project" -v "$OUT:/out" -w /project \
    "$IDF_IMAGE" bash /project/mcu/build-esp-idf.sh "$CHIP" /out
fi

command -v idf.py >/dev/null || {
  echo "idf.py not found: activate an ESP-IDF 5.x environment first (. \$IDF_PATH/export.sh), or use --docker" >&2
  exit 1
}
EXAMPLE=$ROOT/mcu/esp-idf/example
BUILD=$OUT/build
DEFAULTS="$EXAMPLE/sdkconfig.defaults;$EXAMPLE/sdkconfig.defaults.$CHIP"
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
Flash the single merged image (all parts, from address 0x0 of the flash):

  python3 -m esptool --chip $CHIP -p /dev/ttyUSB0 -b 460800 write_flash 0x0 merged.bin

Or flash the parts separately (same result):

  python3 -m esptool --chip $CHIP -p /dev/ttyUSB0 -b 460800 write_flash $FLASH_OPTS \\
    $BOOT_OFFSET bootloader.bin $PT_OFFSET partition-table.bin $APP_OFFSET reticulum-c-mcu.bin

Replace /dev/ttyUSB0 with the board's port (/dev/ttyACM0 on a native USB port,
COMx on Windows). Hold BOOT while pressing RESET if the board does not enter the
bootloader by itself. Install esptool with: pip install esptool
EOF
echo "built $CHIP: $OUT"
ls -l "$OUT/merged.bin" "$OUT/reticulum-c-mcu.bin" "$OUT/bootloader.bin" "$OUT/partition-table.bin"
