#!/usr/bin/env bash
# Builds the MCU application in its own mcu-profile build directory and runs the
# unit tests that need no sockets and no node: the clock policy and the transport
# link handling (reconnect, announce after reconnect, HDLC reset).
#
#   mcu_unit.sh SOURCE_DIR
set -u
SRC=$1
D=$(mktemp -d /tmp/rnc-mcu-unit-XXXXXX)
trap 'rm -rf "$D"' EXIT
fail() { echo "FAIL: $*" >&2; tail -30 "$D"/*.log >&2 2>/dev/null; exit 1; }
cmake -S "$SRC" -B "$D/build" -DRNC_PROFILE=mcu -DRNC_CRYPTO=portable -DBUILD_TESTING=OFF \
  -DRNC_MCU_UNIT_TESTS=ON > "$D/cmake.log" 2>&1 || fail "configure"
cmake --build "$D/build" --target test_mcu_clock test_mcu_link test_mcu_net -j4 > "$D/build.log" 2>&1 || fail "build"
"$D/build/mcu/test_mcu_clock" || fail "test_mcu_clock"
"$D/build/mcu/test_mcu_link" || fail "test_mcu_link"
"$D/build/mcu/test_mcu_net" || fail "test_mcu_net"
echo "mcu unit tests passed"
