#!/usr/bin/env bash
# Runs the MCU example firmware logic on the host and talks to it over a pty.
#
#   mcu_host.sh SOURCE_DIR NODE_EXE ECHO_CLIENT_EXE [PYTHON REFERENCE_DIR]
#
# 1. builds the library and mcu/app in a SEPARATE build directory with
#    -DRNC_PROFILE=mcu -DRNC_CRYPTO=portable (the profile changes struct sizes, so
#    it cannot share a build with the default one);
# 2. starts that firmware build on a pty;
# 3. starts the default-build reticulum-c-node with a SerialInterface on the pty
#    and a loopback TCPServerInterface;
# 4. the C client (and, when PYTHON and REFERENCE_DIR are given, the unmodified
#    reference RNS) waits for the MCU destination's announce and requests /echo
#    and /info over TCP.
set -u
SRC=$1 NODE=$2 CLIENT=$3 PYTHON=${4:-} REFDIR=${5:-}
D=$(mktemp -d /tmp/rnc-mcu-XXXXXX)
PIDS=()
cleanup() {
  local p
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && wait "$p" 2>/dev/null; done
  rm -rf "$D"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $*" >&2
  for f in "$D"/*.log; do [ -f "$f" ] && { echo "--- $f" >&2; tail -25 "$f" >&2; }; done
  exit 1
}

# 1. the firmware build (profile mcu, portable crypto)
cmake -S "$SRC" -B "$D/build" -DRNC_PROFILE=mcu \
  -DRNC_CRYPTO=portable -DBUILD_TESTING=OFF > "$D/cmake.log" 2>&1 || fail "configure of the mcu build"
cmake --build "$D/build" --target reticulum-c-mcu-host -j4 > "$D/build.log" 2>&1 || fail "build of the mcu firmware"
MCU="$D/build/mcu/reticulum-c-mcu-host"
[ -x "$MCU" ] || fail "no $MCU"

# 2. the firmware on a pty; it prints the slave path
mkdir -p "$D/state"
"$MCU" --pty --state "$D/state" --announce-ms 2000 > "$D/mcu.out" 2> "$D/mcu.log" &
PIDS+=($!)
PTY=
for i in $(seq 1 50); do
  PTY=$(sed -n 's/^pty=//p' "$D/mcu.out" | head -1)
  [ -n "$PTY" ] && break
  sleep 0.1
done
[ -n "$PTY" ] || fail "the firmware printed no pty path"

# 3. the node: serial to the firmware, TCP for the clients
PORT=$((20000 + (RANDOM % 20000)))
mkdir -p "$D/node"
cat > "$D/node/config" <<CFG
[reticulum]
enable_transport = Yes
share_instance = No
[interfaces]
[[MCU]]
type = SerialInterface
port = $PTY
speed = 115200
databits = 8
parity = none
stopbits = 1
[[TCP]]
type = TCPServerInterface
listen_ip = 127.0.0.1
listen_port = $PORT
CFG
"$NODE" --config "$D/node/config" --identity "$D/node/id" --admin "$D/node/admin" > "$D/node.log" 2>&1 &
PIDS+=($!)
for i in $(seq 1 50); do grep -q "Ready identity=" "$D/node.log" 2>/dev/null && break; sleep 0.1; done
grep -q "Ready identity=" "$D/node.log" || fail "the node did not start"

# 4a. the C client
"$CLIENT" --connect "127.0.0.1:$PORT" --timeout 45 > "$D/client.log" 2>&1 || fail "the C client"
grep -q "all checks passed" "$D/client.log" || fail "the C client did not finish its checks"
cat "$D/client.log"

# 4b. the reference stack, when the oracle is enabled
if [ -n "$PYTHON" ] && [ -n "$REFDIR" ]; then
  mkdir -p "$D/rns"
  cat > "$D/rns/config" <<CFG
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
  PYTHONPATH="$REFDIR" "$PYTHON" "$SRC/mcu/tests/ref_client.py" "$D/rns" 60 > "$D/ref.log" 2>&1 || fail "the reference client"
  cat "$D/ref.log"
fi
echo "mcu host test passed"
