#!/usr/bin/env bash
# The MCU example firmware logic over its Wi-Fi transport, run on the host: the same
# application as the firmware with a TCP CLIENT socket (reticulum-c-mcu-host --tcp),
# attached to the TCPServerInterface of a reticulum-c-node, with reconnect.
#
#   mcu_tcp.sh SOURCE_DIR NODE_EXE ECHO_CLIENT_EXE [PYTHON REFERENCE_DIR]
#
# 1. builds the mcu-profile firmware build (separate build directory);
# 2. starts a default-build reticulum-c-node with a loopback TCPServerInterface;
# 3. starts the firmware harness as a TCP client of that interface;
# 4. the C client (a second TCP connection to the same node) waits for the MCU
#    destination's announce and requests /echo and /info (and the reference RNS does
#    the same when PYTHON and REFERENCE_DIR are given);
# 5. the node is killed: the harness must notice and keep trying; the node is started
#    again on the same port: the harness must reconnect, announce again (its regular
#    interval is far longer than the test, so only the reconnect can have produced the
#    announce), and answer /echo and /info again, to the C client and the reference.
# 6. a harness started while no node is listening must connect once the node appears.
set -u
SRC=$1 NODE=$2 CLIENT=$3 PYTHON=${4:-} REFDIR=${5:-}
D=$(mktemp -d /tmp/rnc-mcu-tcp-XXXXXX)
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
  for f in "$D"/*.log; do [ -f "$f" ] && { echo "--- $f" >&2; tail -25 "$f" >&2; }; done
  exit 1
}
# waits up to $3 seconds for $2 occurrences of the text $1 in file $4
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
start_node() { # $1 = log file
  "$NODE" --config "$D/node/config" --identity "$D/node/id" --admin "$D/node/admin" > "$1" 2>&1 &
  NODE_PID=$!
  wait_for "Ready identity=" 1 10 "$1" || fail "the node did not start ($1)"
}
stop_node() {
  kill "$NODE_PID" 2>/dev/null
  wait "$NODE_PID" 2>/dev/null
  NODE_PID=""
}
run_clients() { # $1 = label
  "$CLIENT" --connect "127.0.0.1:$PORT" --timeout 40 > "$D/client-$1.log" 2>&1 || fail "the C client ($1)"
  grep -q "all checks passed" "$D/client-$1.log" || fail "the C client did not finish its checks ($1)"
  echo "C client ($1): ok"
  if [ -n "$PYTHON" ] && [ -n "$REFDIR" ]; then
    mkdir -p "$D/rns-$1"
    cat > "$D/rns-$1/config" <<CFG
[reticulum]
enable_transport = No
share_instance = No
[logging]
loglevel = 2
[interfaces]
  [[T]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = $PORT
CFG
    PYTHONPATH="$REFDIR" "$PYTHON" "$SRC/mcu/tests/ref_client.py" "$D/rns-$1" 50 > "$D/ref-$1.log" 2>&1 \
      || fail "the reference client ($1)"
    cat "$D/ref-$1.log"
  fi
}

# ---- the harness starts BEFORE the node exists: it must keep trying, then connect
"$MCU" --tcp "127.0.0.1:$PORT" --state "$D/state" --announce-ms 600000 > "$D/mcu.out" 2> "$D/mcu.log" &
MCU_PIDS+=($!)
wait_for "tcp: connection failed" 2 15 "$D/mcu.log" || fail "the harness did not retry while no node was listening"
start_node "$D/node1.log"
wait_for "transport up" 1 20 "$D/mcu.log" || fail "the harness did not connect once the node appeared"
echo "connected after the node appeared"
run_clients first

# ---- the node goes away: the harness notices and keeps trying
stop_node
wait_for "transport down" 1 10 "$D/mcu.log" || fail "the harness did not notice the lost connection"
wait_for "tcp: connection failed" 4 20 "$D/mcu.log" || fail "the harness did not keep retrying"
echo "connection loss noticed, retrying"

# ---- the node returns on the same port: reconnect, new announce, answers again
start_node "$D/node2.log"
wait_for "transport up" 2 20 "$D/mcu.log" || fail "the harness did not reconnect"
echo "reconnected"
run_clients second

# the announce must have come from the reconnect, not from the (10 minute) interval
[ "$(grep -c "transport up" "$D/mcu.log")" -ge 2 ] || fail "no second link-up in the log"
echo "mcu tcp test passed"
