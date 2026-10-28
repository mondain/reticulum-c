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
# the radio: incomplete or out of range settings are refused (there are no defaults)
"$TOOL" --image-only "$D/x.bin" --mode serial --lora-mode leaf > "$D/o" 2>&1 && fail "lora leaf without settings accepted"
"$TOOL" --image-only "$D/x.bin" --mode serial --lora-mode leaf --lora-freq 868.1 --lora-bw 125 --lora-sf 8 --lora-cr 5 > "$D/o" 2>&1 && fail "lora leaf without txp accepted"
"$TOOL" --image-only "$D/x.bin" --mode serial --lora-mode gateway --lora-freq 868.1 --lora-bw 125 --lora-sf 8 --lora-txp 14 > "$D/o" 2>&1 && fail "lora gateway without cr accepted"
"$TOOL" --image-only "$D/x.bin" --mode serial --lora-mode wide > "$D/o" 2>&1 && fail "lora mode 'wide' accepted"
for bad in "--lora-freq 12" "--lora-freq 2400" "--lora-freq abc" "--lora-bw 100" "--lora-bw 125001" "--lora-sf 4" "--lora-sf 13" \
           "--lora-cr 9" "--lora-cr 4" "--lora-txp 23" "--lora-txp -10" "--lora-txp x" "--lora-airtime 0" "--lora-airtime 101"; do
  "$TOOL" --image-only "$D/x.bin" --mode serial $bad > "$D/o" 2>&1 && fail "accepted: $bad"
done
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
# LoRa settings: the keys the firmware reads (lora_mode, lora_set, lora_freq, lora_bw, lora_sf,
# lora_cr, lora_txp, lora_air); and an image without any radio setting keeps the radio off
"$TOOL" $mode --partitions "$PART" --image-only "$D/lora.bin" --mode serial --lora-mode gateway \
  --lora-freq 868.1 --lora-bw 125 --lora-sf 8 --lora-cr 4/5 --lora-txp 14 --lora-airtime 0.5 > "$D/o" 2>&1 \
  || { cat "$D/o" >&2; fail "lora image failed"; }
grep -q "responsible for the legality" "$D/o" || fail "no regulatory reminder"
for text in lora_mode gateway lora_set lora_freq lora_bw lora_sf lora_cr lora_txp lora_air; do
  grep -a -q -F -- "$text" "$D/lora.bin" || fail "the lora image lacks: $text"
done
for text in lora_freq lora_bw lora_sf lora_cr lora_txp; do
  grep -a -q -F -- "$text" "$D/serial.bin" && fail "the plain image holds a radio setting: $text"
done
grep -a -q -F lora_mode "$D/serial.bin" || fail "the plain image does not say lora_mode off"
echo "lora image ok"
"$TOOL" $mode --arduino --image-only "$D/arduino.bin" --ssid net --host h > "$D/o" 2>&1 \
  || { cat "$D/o" >&2; fail "arduino image failed"; }
grep -q "flash it at 0x9000 (partition rnccfg, 0x5000" "$D/o" || fail "wrong arduino offset: $(cat "$D/o")"
[ "$(stat -c %s "$D/arduino.bin")" = 20480 ] || fail "the arduino image is not the size of the NVS partition"
echo "wifi-config tests passed"
