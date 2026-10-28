#!/usr/bin/env bash
# Tests mcu/tools/wifi-config.sh without a board: input validation, and that the NVS
# image it builds holds the settings under the namespace and keys the firmware reads
# (rnc_net: mode, ssid, password, host, port). The image generator comes from
# pip (esp-idf-nvs-partition-gen), an ESP-IDF environment or the pinned Docker image;
# when none is available the generator part is skipped (exit status 77 = skipped).
#
#   test_wifi_config.sh SOURCE_DIR
set -u
SRC=$1
TOOL="$SRC/mcu/tools/wifi-config.sh"
D=$(mktemp -d /tmp/rnc-wifi-config-test-XXXXXX)
trap 'rm -rf "$D"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
PART="$SRC/mcu/esp-idf/example/partitions.csv"

# refused input (these never reach the generator)
"$TOOL" --image-only "$D/x.bin" --ssid net --host h --password short > "$D/o" 2>&1 && fail "short password accepted"
"$TOOL" --image-only "$D/x.bin" --host h > "$D/o" 2>&1 && fail "missing ssid accepted"
"$TOOL" --image-only "$D/x.bin" --ssid net > "$D/o" 2>&1 && fail "missing host accepted"
"$TOOL" --image-only "$D/x.bin" --ssid net --host h --port 0 > "$D/o" 2>&1 && fail "port 0 accepted"
"$TOOL" --image-only "$D/x.bin" --ssid net --host h --port 70000 > "$D/o" 2>&1 && fail "port 70000 accepted"
"$TOOL" --image-only "$D/x.bin" --ssid net --host 'bad host' > "$D/o" 2>&1 && fail "host with a space accepted"
"$TOOL" --image-only "$D/x.bin" --ssid 012345678901234567890123456789012 --host h > "$D/o" 2>&1 && fail "33 byte ssid accepted"
"$TOOL" --chip esp32 --ssid net --host h > "$D/o" 2>&1 && fail "missing device accepted"
[ ! -e "$D/x.bin" ] || fail "an image was written for refused input"
echo "input validation ok"

mode=""
if python3 -c 'import esp_idf_nvs_partition_gen' 2>/dev/null ||
   { [ -n "${IDF_PATH:-}" ] && [ -f "$IDF_PATH/components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py" ]; }; then
  mode=""
elif command -v docker >/dev/null 2>&1 && docker image inspect "${RNC_IDF_IMAGE:-espressif/idf:v5.4.4}" >/dev/null 2>&1; then
  mode="--docker"
else
  echo "no NVS image generator available: skipping the image checks"
  exit 77
fi

printf 'pass "word,1' | "$TOOL" $mode --partitions "$PART" --image-only "$D/wifi.bin" \
  --ssid 'My, "Net" work' --host 192.168.1.10 --port 4965 --password-stdin > "$D/o" 2>&1 \
  || { cat "$D/o" >&2; fail "image generation failed"; }
grep -q "flash it at 0x190000" "$D/o" || fail "wrong offset: $(cat "$D/o")"
[ "$(stat -c %s "$D/wifi.bin")" = 16384 ] || fail "the image is not the size of the partition"
for text in rnc_net mode wifi ssid 'My, "Net" work' password 'pass "word,1' host 192.168.1.10 port; do
  grep -a -q -F -- "$text" "$D/wifi.bin" || fail "the image lacks: $text"
done
echo "wifi image ok"

"$TOOL" $mode --partitions "$PART" --image-only "$D/open.bin" --ssid openap --host node.example > "$D/o" 2>&1 \
  || { cat "$D/o" >&2; fail "open network image failed"; }
grep -a -q -F password "$D/open.bin" && fail "an open network image holds a password key"
"$TOOL" $mode --partitions "$PART" --image-only "$D/serial.bin" --mode serial > "$D/o" 2>&1 \
  || { cat "$D/o" >&2; fail "serial mode image failed"; }
grep -a -q -F serial "$D/serial.bin" || fail "the serial image lacks the mode"
"$TOOL" $mode --arduino --image-only "$D/arduino.bin" --ssid net --host h > "$D/o" 2>&1 \
  || { cat "$D/o" >&2; fail "arduino image failed"; }
grep -q "flash it at 0x9000 (partition rnccfg, 0x5000" "$D/o" || fail "wrong arduino offset: $(cat "$D/o")"
[ "$(stat -c %s "$D/arduino.bin")" = 20480 ] || fail "the arduino image is not the size of the NVS partition"
echo "wifi-config tests passed"
