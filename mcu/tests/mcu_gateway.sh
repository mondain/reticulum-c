#!/usr/bin/env bash
# The gateway mode of the firmware logic, run on the host:
#
#   C echo client --TCP-- reticulum-c-node --TCP-- harness (gateway) ~~simulated LoRa~~ peer board
#
# The harness is the same application as the firmware in gateway mode (reticulum-c-mcu-host
# --lora gateway): its Wi-Fi style TCP interface is a client of the node, its second interface
# is a modelled radio on a simulated channel, and Reticulum transport is on. A second instance
# of the application (the peer, a leaf with a modelled SX1276) sits on the same simulated
# channel. The C echo client attaches to the node and must reach the PEER's /echo and /info
# THROUGH the gateway board.
#
# Also checks, with the same binary:
#   - the regulatory gate: with an incomplete radio configuration the harness refuses to start
#     the radio and never transmits or receives on LoRa (the peer is not even created);
#   - a lossy channel (10 % of the frames lost): the requests still complete.
#
#   mcu_gateway.sh SOURCE_DIR NODE_EXE ECHO_CLIENT_EXE
set -u
SRC=$1 NODE=$2 CLIENT=$3
D=$(mktemp -d /tmp/rnc-mcu-gw-XXXXXX)
NODE_PID=""
MCU_PIDS=()
cleanup() {
  local p
  [ -n "$NODE_PID" ] && kill "$NODE_PID" 2>/dev/null
  for p in "${MCU_PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  [ -n "$NODE_PID" ] && wait "$NODE_PID" 2>/dev/null
  for p in "${MCU_PIDS[@]:-}"; do [ -n "$p" ] && wait "$p" 2>/dev/null; done
  rm -rf "$D"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  # stop the boards first so that they print their counters into the logs
  for p in ${MCU_PIDS[@]+"${MCU_PIDS[@]}"}; do kill "$p" 2>/dev/null; done
  sleep 1
  for f in "$D"/*.log; do [ -f "$f" ] && { echo "--- $f" >&2; tail -25 "$f" >&2; }; done
  exit 1
}
wait_for() {
  local text=$1 count=$2 secs=$3 file=$4 i
  for i in $(seq 1 $((secs * 10))); do
    [ "$(grep -c -- "$text" "$file" 2>/dev/null)" -ge "$count" ] && return 0
    sleep 0.1
  done
  return 1
}

cmake -S "$SRC" -B "$D/build" -DRNC_PROFILE=mcu -DRNC_CRYPTO=portable -DBUILD_TESTING=OFF \
  > "$D/cmake.log" 2>&1 || fail "configure of the mcu build"
cmake --build "$D/build" --target reticulum-c-mcu-host -j4 > "$D/build.log" 2>&1 || fail "build of the mcu firmware"
MCU="$D/build/mcu/reticulum-c-mcu-host"
[ -x "$MCU" ] || fail "no $MCU"

PORT=$((20000 + (RANDOM % 20000)))
mkdir -p "$D/node" "$D/state"
cat > "$D/node/config" <<CFG
[reticulum]
enable_transport = Yes
share_instance = No
[interfaces]
[[TCP]]
type = TCPServerInterface
listen_ip = 127.0.0.1
listen_port = $PORT
CFG
"$NODE" --config "$D/node/config" --identity "$D/node/id" --admin "$D/node/admin" > "$D/node.log" 2>&1 &
NODE_PID=$!
wait_for "Ready identity=" 1 10 "$D/node.log" || fail "the node did not start"

# the radio settings are given explicitly, as the firmware needs them (868.1 MHz, 125 kHz,
# SF8, 4/5, 14 dBm at the chip, 10 percent airtime so the test is not throttled)
LORA=(--lora gateway --lora-freq 868.1 --lora-bw 125 --lora-sf 8 --lora-cr 5 --lora-txp 14 --lora-airtime 10)

# ---- the regulatory gate: an incomplete configuration keeps the radio off ------------------
"$MCU" --tcp "127.0.0.1:$PORT" --state "$D/state0" --lora gateway --lora-freq 868.1 --lora-bw 125 \
  --lora-sf 8 --lora-cr 5 > "$D/gate.out" 2> "$D/gate.log" &
GATE_PID=$!
MCU_PIDS+=($GATE_PID)
wait_for "radio DISABLED" 1 10 "$D/gate.log" || fail "the incomplete configuration did not disable the radio"
wait_for "transport up" 1 20 "$D/gate.log" || fail "the harness did not connect without the radio"
grep -q "peer1 destination" "$D/gate.log" && fail "a peer exists although the radio is disabled"
kill "$GATE_PID" 2>/dev/null
wait "$GATE_PID" 2>/dev/null
echo "regulatory gate: ok (radio refused without lora.txp)"

run_through_gateway() { # $1 = label, rest = extra harness arguments
  local label=$1
  shift
  mkdir -p "$D/state-$label"
  "$MCU" --tcp "127.0.0.1:$PORT" --state "$D/state-$label" "${LORA[@]}" --lora-peers 1 "$@" \
    > "$D/gw-$label.out" 2> "$D/gw-$label.log" &
  MCU_PIDS+=($!)
  wait_for "transport up" 1 20 "$D/gw-$label.log" || fail "the gateway did not connect to the node ($label)"
  wait_for "peer1 destination" 1 10 "$D/gw-$label.log" || fail "no peer ($label)"
  wait_for "lora up" 1 10 "$D/gw-$label.log" || true
  # the gateway's own announce reaches the client after 2 hops; the peer's after 3
  "$CLIENT" --connect "127.0.0.1:$PORT" --timeout 150 --min-hops 3 > "$D/client-$label.log" 2>&1 \
    || fail "the C client could not reach the peer through the gateway ($label)"
  grep -q "all checks passed" "$D/client-$label.log" || fail "the C client did not finish its checks ($label)"
  grep "announce from" "$D/client-$label.log"
  echo "through the gateway ($label): /echo and /info of the board behind it: ok"
}

run_through_gateway clean
LAST_PID=${MCU_PIDS[${#MCU_PIDS[@]}-1]}
kill "$LAST_PID" 2>/dev/null
wait "$LAST_PID" 2>/dev/null
run_through_gateway lossy --lora-loss 100
echo "mcu gateway test passed"
