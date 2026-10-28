#!/usr/bin/env bash
# Provisions the Wi-Fi settings of an ESP32 / ESP32-S3 reticulum-c firmware without a
# serial console: builds the NVS image of the settings partition "rnccfg" and
# flashes it. Only that partition is written; the node's identity (default NVS
# partition) and the firmware are untouched.
#
#   wifi-config.sh --chip esp32|esp32s3 --device /dev/ttyUSB0 --ssid NAME --host HOST
#                  [--password-stdin | --password SECRET] [--port 4242]
#                  [--mode wifi|serial] [--partitions partitions.csv]
#                  [--offset 0x190000 --size 0x4000] [--image-only FILE.bin] [--arduino]
#                  [--docker] [--baud 460800]
#
#   --password-stdin   read the password from the first line of standard input (keeps it
#                      out of the process list). The environment variable
#                      RNC_WIFI_PASSWORD is used when neither option is given; with none
#                      of them the network is taken to be open.
#   --mode serial      stores "serial" (and removes the Wi-Fi use): the board goes back
#                      to the HDLC serial transport.
#   --partitions FILE  the partitions.csv of the firmware (the release zips contain it);
#                      the offset and size of "rnccfg" are read from it. Default: the
#                      file next to this script or one directory up (the release zips),
#                      or mcu/esp-idf/example/partitions.csv of the repository, or
#                      0x190000 / 0x4000.
#   --image-only FILE  write the NVS image there and do not flash (flash it yourself at
#                      the offset printed, with any tool, for example
#                      esptool.py write_flash 0x190000 FILE.bin).
#   --arduino          for the Arduino/PlatformIO firmware (mcu/platformio), which keeps
#                      the settings in the standard NVS partition (0x9000, 0x5000 bytes)
#                      together with its identity: writing it REPLACES the whole NVS
#                      partition, so the node gets a new identity at its next start
#                      (and any other NVS data of the sketch is lost). The ESP-IDF
#                      firmware has a separate settings partition and keeps its identity.
#   --docker           run the image generator (and esptool, if the host has none) in
#                      the pinned espressif/idf image instead of needing ESP-IDF tools.
#
# Needs: esptool (pip install esptool) and the NVS image generator (pip install
# esp-idf-nvs-partition-gen, or an ESP-IDF environment: $IDF_PATH is used), or Docker.
#
# SECURITY: the settings are stored UNENCRYPTED in flash, and the TCP link to the
# node is plaintext and unauthenticated at the transport level (Reticulum's own link
# encryption applies above it). Anyone with the board can read the password. See
# mcu/README.txt. The image file and the temporary CSV contain the password: they are
# written with mode 600 and the temporary ones are removed on exit.
set -eu

IDF_IMAGE=${RNC_IDF_IMAGE:-espressif/idf:v5.4.4}
HERE=$(cd "$(dirname "$0")" && pwd)

CHIP="" DEVICE="" SSID="" HOST="" PASSWORD="" SERVER_PORT=4242 MODE=wifi BAUD=460800
PART_FILE="" OFFSET="" SIZE="" IMAGE_ONLY="" USE_DOCKER=0 PW_STDIN=0 PW_GIVEN=0
ARDUINO=0
usage() { sed -n '2,40p' "$0" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case $1 in
    --chip) CHIP=${2:?}; shift 2 ;;
    --device) DEVICE=${2:?}; shift 2 ;;
    --ssid) SSID=${2:?}; shift 2 ;;
    --host) HOST=${2:?}; shift 2 ;;
    --password) PASSWORD=${2?}; PW_GIVEN=1; shift 2 ;;
    --password-stdin) PW_STDIN=1; shift ;;
    --port) SERVER_PORT=${2:?}; shift 2 ;;
    --mode) MODE=${2:?}; shift 2 ;;
    --partitions) PART_FILE=${2:?}; shift 2 ;;
    --offset) OFFSET=${2:?}; shift 2 ;;
    --size) SIZE=${2:?}; shift 2 ;;
    --image-only) IMAGE_ONLY=${2:?}; shift 2 ;;
    --baud) BAUD=${2:?}; shift 2 ;;
    --docker) USE_DOCKER=1; shift ;;
    --arduino) ARDUINO=1; shift ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

die() { echo "wifi-config: $*" >&2; exit 1; }

case $MODE in wifi|serial) ;; *) die "--mode must be wifi or serial" ;; esac
case $CHIP in esp32|esp32s3|"") ;; *) die "--chip must be esp32 or esp32s3" ;; esac
if [ -z "$IMAGE_ONLY" ]; then
  [ -n "$CHIP" ] || die "--chip is required"
  [ -n "$DEVICE" ] || die "--device is required (or use --image-only)"
fi
if [ $PW_STDIN = 1 ]; then
  IFS= read -r PASSWORD || true
elif [ $PW_GIVEN = 0 ] && [ -n "${RNC_WIFI_PASSWORD:-}" ]; then
  PASSWORD=$RNC_WIFI_PASSWORD
fi

# the same rules as the firmware's console (mcu/app/rnc_mcu_net.h)
if [ "$MODE" = wifi ]; then
  [ -n "$SSID" ] || die "--ssid is required for wifi mode"
  [ -n "$HOST" ] || die "--host is required for wifi mode"
  [ ${#SSID} -le 32 ] || die "the SSID is at most 32 bytes"
  if [ -n "$PASSWORD" ] && { [ ${#PASSWORD} -lt 8 ] || [ ${#PASSWORD} -gt 63 ]; }; then
    die "the password must be 8 to 63 characters (or empty for an open network)"
  fi
  [ ${#HOST} -le 63 ] || die "the host is at most 63 characters"
  case $HOST in *[!A-Za-z0-9._:-]*) die "the host may contain letters, digits and . _ : - only" ;; esac
fi
case $SERVER_PORT in ''|*[!0-9]*) die "--port must be a number" ;; esac
[ "$SERVER_PORT" -ge 1 ] && [ "$SERVER_PORT" -le 65535 ] || die "--port must be 1..65535"
for v in "$SSID" "$PASSWORD"; do
  case $v in *$'\n'*|*$'\r'*) die "the SSID and the password cannot contain line breaks" ;; esac
done

# the partition's offset and size
if [ $ARDUINO = 1 ]; then
  OFFSET=${OFFSET:-0x9000}
  SIZE=${SIZE:-0x5000}
  echo "wifi-config: --arduino writes the whole NVS partition at $OFFSET: the node's identity is replaced" >&2
fi
if [ -z "$OFFSET" ] || [ -z "$SIZE" ]; then
  if [ -z "$PART_FILE" ]; then
    for c in "$HERE/partitions.csv" "$HERE/../partitions.csv" "$HERE/../esp-idf/example/partitions.csv"; do
      [ -f "$c" ] && { PART_FILE=$c; break; }
    done
  fi
  if [ -n "$PART_FILE" ]; then
    [ -f "$PART_FILE" ] || die "no such file: $PART_FILE"
    row=$(grep -E '^[[:space:]]*rnccfg[[:space:]]*,' "$PART_FILE" | head -1 || true)
    [ -n "$row" ] || die "no rnccfg partition in $PART_FILE (is this the reticulum-c firmware's table?)"
    [ -n "$OFFSET" ] || OFFSET=$(echo "$row" | awk -F, '{gsub(/[[:space:]]/, "", $4); print $4}')
    [ -n "$SIZE" ] || SIZE=$(echo "$row" | awk -F, '{gsub(/[[:space:]]/, "", $5); print $5}')
  fi
  OFFSET=${OFFSET:-0x190000}
  SIZE=${SIZE:-0x4000}
fi

TMP=$(mktemp -d "${TMPDIR:-/tmp}/rnc-wifi-config.XXXXXX")
chmod 700 "$TMP"
trap 'rm -rf "$TMP"' EXIT
umask 077

# the CSV for nvs_partition_gen; every value is quoted, a quote inside is doubled
q() { printf '"%s"' "$(printf '%s' "$1" | sed 's/"/""/g')"; }
{
  echo "key,type,encoding,value"
  echo "rnc_net,namespace,,"
  echo "mode,data,string,$(q "$MODE")"
  if [ "$MODE" = wifi ]; then
    echo "ssid,data,string,$(q "$SSID")"
    [ -z "$PASSWORD" ] || echo "password,data,string,$(q "$PASSWORD")"
    echo "host,data,string,$(q "$HOST")"
  fi
  echo "port,data,u16,$SERVER_PORT"
} > "$TMP/rnccfg.csv"

GEN_ARGS="generate rnccfg.csv rnccfg.bin $SIZE"
run_gen() { # in $TMP
  if [ "$USE_DOCKER" = 1 ]; then
    command -v docker >/dev/null || die "docker not found"
    docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$TMP:/work" -w /work "$IDF_IMAGE" \
      python3 -m esp_idf_nvs_partition_gen $GEN_ARGS > "$TMP/gen.log" 2>&1 \
      || docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$TMP:/work" -w /work "$IDF_IMAGE" \
           bash -c 'python3 "$IDF_PATH/components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py" '"$GEN_ARGS" \
           > "$TMP/gen.log" 2>&1
  elif python3 -c 'import esp_idf_nvs_partition_gen' 2>/dev/null; then
    (cd "$TMP" && python3 -m esp_idf_nvs_partition_gen $GEN_ARGS) > "$TMP/gen.log" 2>&1
  elif [ -n "${IDF_PATH:-}" ] && [ -f "$IDF_PATH/components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py" ]; then
    (cd "$TMP" && python3 "$IDF_PATH/components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py" $GEN_ARGS) > "$TMP/gen.log" 2>&1
  else
    die "no NVS image generator: pip install esp-idf-nvs-partition-gen, activate ESP-IDF, or use --docker"
  fi
}
run_gen || { sed 's/^/  /' "$TMP/gen.log" >&2; die "the NVS image could not be generated"; }
[ -s "$TMP/rnccfg.bin" ] || die "the generator produced no image"

if [ -n "$IMAGE_ONLY" ]; then
  cp "$TMP/rnccfg.bin" "$IMAGE_ONLY"
  chmod 600 "$IMAGE_ONLY"
  echo "NVS image written to $IMAGE_ONLY; flash it at $OFFSET (partition rnccfg, $SIZE bytes)"
  exit 0
fi

if [ $ARDUINO = 1 ]; then
  echo "flashing the NVS partition at $OFFSET on $DEVICE ($CHIP)"
else
  echo "flashing the settings partition rnccfg at $OFFSET on $DEVICE ($CHIP); the identity is kept"
fi
if command -v esptool.py >/dev/null 2>&1; then
  esptool.py --chip "$CHIP" -p "$DEVICE" -b "$BAUD" write_flash "$OFFSET" "$TMP/rnccfg.bin"
elif command -v esptool >/dev/null 2>&1; then
  esptool --chip "$CHIP" -p "$DEVICE" -b "$BAUD" write_flash "$OFFSET" "$TMP/rnccfg.bin"
elif python3 -c 'import esptool' 2>/dev/null; then
  python3 -m esptool --chip "$CHIP" -p "$DEVICE" -b "$BAUD" write_flash "$OFFSET" "$TMP/rnccfg.bin"
elif [ "$USE_DOCKER" = 1 ]; then
  docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp --device "$DEVICE" -v "$TMP:/work" -w /work \
    "$IDF_IMAGE" python3 -m esptool --chip "$CHIP" -p "$DEVICE" -b "$BAUD" write_flash "$OFFSET" rnccfg.bin
else
  die "esptool not found (pip install esptool), or use --docker, or --image-only and flash it yourself"
fi
if [ "$MODE" = wifi ]; then
  echo "done: reset the board; it joins \"$SSID\" and connects to $HOST:$SERVER_PORT"
else
  echo "done: reset the board; it uses the serial transport"
fi
