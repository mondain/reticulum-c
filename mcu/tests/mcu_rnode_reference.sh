#!/usr/bin/env bash
# The RNode device side against the UNMODIFIED reference RNodeInterface (RNS 1.5.5): the
# reference opens a pty on which rnode_pty_device runs the module, detects the board,
# accepts its firmware, configures the radio, validates the echoed settings and sends an
# announce, which must reach the simulated peer on the channel.
#
#   mcu_rnode_reference.sh DEVICE_EXE PYTHON REFERENCE_DIR DRIVER_PY
#
# Needs pyserial for the reference; exits 77 (skipped) when it is missing.
set -u
DEV=$1 PYTHON=$2 REFDIR=$3 DRIVER=$4
D=$(mktemp -d /tmp/rnc-rnode-ref-XXXXXX)
PID=
cleanup() { [ -n "$PID" ] && kill "$PID" 2>/dev/null; [ -n "$PID" ] && wait "$PID" 2>/dev/null; rm -rf "$D"; }
trap cleanup EXIT
"$DEV" > "$D/dev.out" 2> "$D/dev.err" &
PID=$!
PTY=
for i in $(seq 1 50); do
  PTY=$(sed -n 's/^pty=//p' "$D/dev.out" | head -1)
  [ -n "$PTY" ] && break
  sleep 0.1
done
[ -n "$PTY" ] || { echo "FAIL: the device printed no pty path"; cat "$D/dev.err"; exit 1; }
PYTHONPATH="$REFDIR:$(cd "$(dirname "$0")/../.." && pwd)/tests/oracle_env" "$PYTHON" "$DRIVER" "$PTY" 12 > "$D/ref.out" 2> "$D/ref.err"
rc=$?
if [ $rc -eq 77 ]; then cat "$D/ref.err" >&2; exit 77; fi
[ $rc -eq 0 ] || { echo "FAIL: the reference driver exited $rc"; cat "$D/ref.err" "$D/ref.out" "$D/dev.out"; exit 1; }
grep -q "^rnode: radio on 915000000 Hz bw 125000 sf 8 cr 5 txp 10" "$D/dev.out" \
  || { echo "FAIL: the radio was not configured as the reference asked"; cat "$D/dev.out"; exit 1; }
grep -q "^peer: heard " "$D/dev.out" || { echo "FAIL: the announce did not reach the peer"; cat "$D/dev.out"; exit 1; }
echo "reference RNodeInterface: detected, configured, announce heard by the peer"
