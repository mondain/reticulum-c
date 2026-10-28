#!/usr/bin/env bash
# The on-air bit rate of the firmware's LoRa interface against the figure the UNMODIFIED
# reference RNodeInterface (RNS 1.5.5, updateBitrate) computes, for every spreading factor,
# bandwidth and coding rate the firmware accepts (8 x 10 x 4 settings). The reference's
# value is a float; ours is that value rounded to an integer (at least 1), so they must
# agree to within one half.
#
#   mcu_radio_reference.sh SOURCE_DIR PYTHON REFERENCE_DIR
set -u
SRC=$1 PYTHON=$2 REFDIR=$3
D=$(mktemp -d /tmp/rnc-mcu-ref-XXXXXX)
trap 'rm -rf "$D"' EXIT
cc -std=c11 -O1 -Wall -Wextra -Werror -I"$SRC/mcu/radio" "$SRC/mcu/tests/radio/bitrate_dump.c" \
  "$SRC/mcu/radio/rnc_lora_phy.c" -o "$D/ours" || { echo "FAIL: build"; exit 1; }
"$D/ours" > "$D/ours.txt" || exit 1
PYTHONPATH="$REFDIR" "$PYTHON" "$SRC/mcu/tests/ref_rnode_bitrate.py" > "$D/ref.txt" 2> "$D/ref.err"
rc=$?
if [ $rc -eq 77 ]; then
  cat "$D/ref.err" >&2
  exit 77
fi
[ $rc -eq 0 ] || { cat "$D/ref.err" >&2; echo "FAIL: the reference script failed"; exit 1; }
[ "$(wc -l < "$D/ours.txt")" -eq 320 ] && [ "$(wc -l < "$D/ref.txt")" -eq 320 ] \
  || { echo "FAIL: unexpected line counts"; exit 1; }
"$PYTHON" - "$D/ours.txt" "$D/ref.txt" <<'PY' || exit 1
import sys
ours = [l.split() for l in open(sys.argv[1])]
ref = [l.split() for l in open(sys.argv[2])]
bad = 0
for o, r in zip(ours, ref):
    assert o[:3] == r[:3], (o, r)
    a, b = int(o[3]), float(r[3])
    expect = max(1, int(b + 0.5))
    if a != expect:
        print("MISMATCH sf=%s bw=%s cr=%s ours=%d reference=%.6f" % (o[0], o[1], o[2], a, b))
        bad += 1
print("%d settings compared against the reference RNodeInterface, %d mismatches" % (len(ours), bad))
sys.exit(1 if bad else 0)
PY
