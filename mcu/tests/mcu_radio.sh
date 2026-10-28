#!/usr/bin/env bash
# Builds the LoRa support in its own mcu-profile build directory and runs its tests on the
# host: the radio core (physical layer arithmetic, air framing, airtime budget, CSMA,
# settings), the SX126x and SX127x drivers against the chip models, the interface adapter on
# a simulated shared medium (loss, collisions, hidden node), and the portable application
# talking Reticulum over simulated LoRa. Also checks that no frequency or power is compiled
# into any firmware source.
#
#   mcu_radio.sh SOURCE_DIR
set -u
SRC=$1
D=$(mktemp -d /tmp/rnc-mcu-radio-XXXXXX)
trap 'rm -rf "$D"' EXIT
fail() { echo "FAIL: $*" >&2; tail -30 "$D"/*.log >&2 2>/dev/null; exit 1; }

# REGULATORY: release images carry no default transmit settings. No Kconfig symbol, sdkconfig
# default, PlatformIO build flag or firmware source may supply a frequency, power, bandwidth,
# spreading factor or coding rate for the radio; they come from NVS / Preferences / the
# file system only, set by the operator.
check_no_defaults() {
  local hits
  hits=$(grep -rniE 'LORA_?(FREQ|BW|BANDWIDTH|SF|SPREADING|CR|CODING|TXP|TX_POWER|POWER)' \
      "$SRC/mcu/esp-idf/example/main/Kconfig.projbuild" "$SRC"/mcu/esp-idf/example/sdkconfig.defaults* \
      "$SRC/mcu/platformio/platformio.ini" 2>/dev/null | grep -viE '^[^:]*:[0-9]+:[[:space:]]*(#|;)' || true)
  [ -z "$hits" ] || { echo "$hits" >&2; fail "a LoRa transmit setting appears in a build configuration"; }
  hits=$(grep -rnE 'rnc_lora_cfg_set\([^,]*,[[:space:]]*"(freq|bw|sf|cr|txp)",[[:space:]]*"' \
      "$SRC/mcu/esp-idf" "$SRC/mcu/platformio/src" "$SRC/mcu/app" "$SRC/mcu/radio" 2>/dev/null || true)
  [ -z "$hits" ] || { echo "$hits" >&2; fail "a firmware source sets a LoRa transmit setting from a literal"; }
}
check_no_defaults
echo "no LoRa transmit setting is compiled into the firmware configuration or sources"

cmake -S "$SRC" -B "$D/build" -DRNC_PROFILE=mcu -DRNC_CRYPTO=portable -DBUILD_TESTING=OFF \
  -DRNC_MCU_UNIT_TESTS=ON > "$D/cmake.log" 2>&1 || fail "configure"
cmake --build "$D/build" --target test_mcu_radio_core test_mcu_radio_drivers test_mcu_radio_sim \
  test_mcu_radio_app -j4 > "$D/build.log" 2>&1 || fail "build"
for t in radio_core radio_drivers radio_sim radio_app; do
  "$D/build/mcu/test_mcu_$t" > "$D/run_$t.log" 2>&1 || { cat "$D/run_$t.log" >&2; fail "test_mcu_$t"; }
  cat "$D/run_$t.log"
done
echo "mcu radio tests passed"
