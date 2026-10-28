#!/usr/bin/env bash
# Mutation checks of the LoRa tests: breaks one thing at a time in a scratch copy of the
# radio sources (header layout, split reassembly, sync word, airtime limiter, and a few more)
# and requires that the radio unit tests (core, drivers, sim) FAIL for every mutation. A
# mutation that the tests do not notice fails this script. The real sources are never touched.
#
#   mcu_radio_mutations.sh SOURCE_DIR [COMPILER]
set -u
SRC=$1
CC=${2:-${CC:-cc}}
D=$(mktemp -d /tmp/rnc-mcu-mut-XXXXXX)
trap 'rm -rf "$D"' EXIT
mkdir -p "$D/pristine"
cp -r "$SRC/mcu/radio" "$D/pristine/radio"
cp -r "$SRC/mcu/tests" "$D/pristine/tests"
cp "$SRC/mcu/tests/test_radio_core.c" "$SRC/mcu/tests/test_radio_drivers.c" "$SRC/mcu/tests/test_radio_sim.c" "$D/pristine/tests/"

RADIO="radio/rnc_lora_phy.c radio/rnc_lora_air.c radio/rnc_lora_mac.c radio/rnc_lora_if.c radio/rnc_sx126x.c radio/rnc_sx127x.c radio/rnc_boards.c radio/rnc_radio.c"
SIM="tests/radio/lora_sim.c tests/radio/sx126x_model.c tests/radio/sx127x_model.c tests/radio/sim_board.c"
CFLAGS="-std=c11 -O1 -w -Iradio -Itests"

# builds and runs the three tests in directory $1; returns 0 when all pass, 1 when a test
# fails, 2 when the build itself fails (a mutation that does not compile proves nothing)
run_tests() {
  local dir=$1 t
  for t in core drivers sim; do
    local srcs="tests/test_radio_$t.c"
    case $t in
      core) srcs="$srcs radio/rnc_lora_phy.c radio/rnc_lora_air.c radio/rnc_lora_mac.c tests/radio/lora_sim.c" ;;
      *) srcs="$srcs $RADIO $SIM" ;;
    esac
    (cd "$dir" && $CC $CFLAGS $srcs -o "t_$t" -lm) > "$dir/build_$t.log" 2>&1 || return 2
  done
  for t in core drivers sim; do
    (cd "$dir" && timeout 600 "./t_$t") > "$dir/run_$t.log" 2>&1 || return 1
  done
  return 0
}

# the unmodified sources must pass, or the whole exercise means nothing
cp -r "$D/pristine" "$D/base"
run_tests "$D/base"
rc=$?
if [ $rc -ne 0 ]; then
  echo "FAIL: the unmutated tests do not pass (status $rc)"
  tail -5 "$D"/base/build_*.log "$D"/base/run_*.log 2>/dev/null
  exit 1
fi

n=0
bad=0
# mutate NAME FILE 'sed expression'
mutate() {
  local name=$1 file=$2 expr=$3 dir="$D/m$n"
  n=$((n + 1))
  cp -r "$D/pristine" "$dir"
  sed -i "$expr" "$dir/$file"
  if cmp -s "$D/pristine/$file" "$dir/$file"; then
    echo "FAIL  $name: the mutation did not change $file (stale pattern)"
    bad=$((bad + 1))
    return
  fi
  run_tests "$dir"
  case $? in
    1) echo "ok    $name: caught" ;;
    2) echo "FAIL  $name: does not build"; bad=$((bad + 1)) ;;
    0) echo "FAIL  $name: SURVIVED (all tests pass)"; bad=$((bad + 1)) ;;
  esac
}

# 1. header layout
mutate "header: sequence in bits 3..0 instead of 7..4" radio/rnc_lora_air.c \
  's/((sequence \& 0x0Fu) << 4)/(sequence \& 0x0Fu)/'
mutate "header: split flag in bit 1 instead of bit 0" radio/rnc_lora_air.h \
  's/#define RNC_AIR_FLAG_SPLIT 0x01u/#define RNC_AIR_FLAG_SPLIT 0x02u/'
mutate "header: sequence read from the low nibble" radio/rnc_lora_air.c \
  's/  seq = frame\[0\] >> 4;/  seq = frame[0] \& 0x0F;/'
mutate "frame: 253 bytes in the first half" radio/rnc_lora_air.h \
  's/#define RNC_AIR_FRAGMENT 254u/#define RNC_AIR_FRAGMENT 253u/'
# 2. split reassembly
mutate "reassembly: the second half is never accepted" radio/rnc_lora_air.c \
  's/rx->pending_size + n <= rx->max_packet) {/0) {/'
mutate "reassembly: halves joined in the wrong order" radio/rnc_lora_air.c \
  's/      memcpy(out, rx->pending, rx->pending_size);/      memcpy(out + n, rx->pending, rx->pending_size);/'
mutate "reassembly: sequence number not compared" radio/rnc_lora_air.c \
  's/rx->pending_seq == seq \&\&/1 \&\&/'
mutate "reassembly: orphan halves never expire" radio/rnc_lora_air.c \
  's/rx->pending_seq != RNC_AIR_SEQ_NONE \&\& rx->timeout_us \&\&/0 \&\&/'
mutate "reassembly: a whole packet does not drop a pending half" radio/rnc_lora_air.c \
  's/    if (rx->pending_seq != RNC_AIR_SEQ_NONE) {\n      rx->dropped_orphans++;/XX/;0,/rx->dropped_orphans++;/s//rx->dropped_expired += 0;/'
# 3. sync word
mutate "sync word: SX126x private word 0x1424 becomes 0x3444" radio/rnc_sx126x.c \
  's/write_reg(d, REG_SYNC_WORD, 0x14) != 0 || write_reg(d, REG_SYNC_WORD + 1u, 0x24)/write_reg(d, REG_SYNC_WORD, 0x34) != 0 || write_reg(d, REG_SYNC_WORD + 1u, 0x44)/'
mutate "sync word: SX127x private word 0x12 becomes 0x34" radio/rnc_sx127x.c \
  's/wr(d, REG_SYNC_WORD, 0x12)/wr(d, REG_SYNC_WORD, 0x34)/'
# 4. airtime limiter
mutate "airtime: the budget check always allows" radio/rnc_lora_mac.c \
  's/  return after <= a->budget_ms;/  return 1;/'
mutate "airtime: a packet longer than the budget is allowed" radio/rnc_lora_mac.c \
  's/  if (toa_ms > a->budget_ms)/  if (0)/'
mutate "airtime: transmissions are not booked" radio/rnc_lora_mac.c \
  's/  a->bin_ms\[i\] += toa_ms;/  a->bin_ms[i] += 0;/'
mutate "airtime: the budget is not checked again when the channel is won" radio/rnc_lora_if.c \
  's/if (rnc_airtime_allows(\&li->budget, now_ms, (uint32_t)toa_ms) != 1) {/if (0) {/'
mutate "airtime: bins expire after 60 instead of 61 minutes" radio/rnc_lora_mac.h \
  's/#define RNC_AIRTIME_BINS 61u/#define RNC_AIRTIME_BINS 60u/'
# 5. modem settings and channel access
mutate "ldro: rule uses >= 16 (the datasheet reading) instead of the firmware's > 16" radio/rnc_lora_phy.c \
  's/return ((UINT32_C(1) << sf) \/ khz) > 16u;/return ((UINT32_C(1) << sf) \/ khz) >= 16u;/'
mutate "frequency: step uses 2^24 instead of 2^25 (SX126x)" radio/rnc_sx126x.c \
  's/((uint64_t)freq_hz << 25)/((uint64_t)freq_hz << 24)/'
mutate "iq: the SX126x polarity fix is not applied" radio/rnc_sx126x.c \
  's/write_reg(d, REG_IQ_POLARITY, (uint8_t)(iq | 0x04u))/write_reg(d, REG_IQ_POLARITY, iq)/'
mutate "csma: the channel is never seen busy" radio/rnc_lora_if.c \
  's/    int busy = li->modem->ops->carrier(li->modem);/    int busy = 0;/'
mutate "csma: no backoff (window of one slot)" radio/rnc_lora_mac.c \
  's/c->cw_target_ms = (uint64_t)(random % window) \* c->slot_ms;/c->cw_target_ms = 0 * window * random;/'
mutate "bitrate: coding rate ignored" radio/rnc_lora_phy.c \
  's/  den = (uint64_t)p->cr << p->sf;/  den = (uint64_t)5 << p->sf;/'
mutate "time on air: preamble term dropped" radio/rnc_lora_phy.c \
  's/symbols_q4 = (int64_t)preamble \* 4 + /symbols_q4 = /'
mutate "tx: power amplifier configured for the wrong device" radio/rnc_sx126x.c \
  's/  pa\[2\] = 0; \/\* deviceSel: SX1262 \*\//  pa[2] = 1;/'

# 6. the regulatory gate and the oscillator check
mutate "regulatory: the radio starts without every transmit setting" radio/rnc_lora_cfg.h \
  's/(c->set \& RNC_LORA_SET_ALL) == RNC_LORA_SET_ALL/(c->set \& RNC_LORA_SET_ALL) != 0/'
mutate "regulatory: mode off no longer keeps the radio off" radio/rnc_radio.c \
  's/  if (cfg->mode == RNC_LORA_MODE_OFF)/  if (0)/'
mutate "regulatory: the board's power limit is ignored" radio/rnc_radio.c \
  's/      p.txp_dbm > board->max_txp_dbm)/      0)/'
mutate "regulatory: an unsupported board is driven" radio/rnc_radio.c \
  's/!board->supported || //'
mutate "init: an oscillator that did not start is not noticed" radio/rnc_sx126x.c \
  's/    if (err\[1\] \& 0x20u)/    if (0)/'
mutate "tx: DIO2 is never enabled as the antenna switch" radio/rnc_sx126x.c \
  's/  if (d->board.dio2_rf_switch) {/  if (0) {/'

if [ $bad -ne 0 ]; then
  echo "mutation checks: $bad of $n mutations were NOT caught"
  exit 1
fi
echo "mutation checks: all $n mutations caught"
