#!/bin/sh
# AutoInterface over virtual cables between private network namespaces (Linux, no root needed):
#   unshare -rn sh auto_netns.sh NODE CTL [PYTHON REFERENCE_DIR]
# A node "hub" with AutoInterface and no `devices` line, and peers on the far ends of cables. With PYTHON, the peer
# on the first cable is the reference's rnsd.
set -u
node=$1 ctl=$2 python=${3:-} reference=${4:-}
base=$(mktemp -d /tmp/rnc-auto-XXXXXX)
pids=''
fail() {
  echo "FAIL: $*" >&2
  for log in "$base"/*/log; do echo "== $log" >&2; tail -25 "$log" >&2; done
  exit 1
}
cleanup() {
  for p in $pids; do kill "$p" 2>/dev/null; done
  sleep 1
  for p in $pids; do kill -9 "$p" 2>/dev/null; done
  rm -rf "$base"
}
trap cleanup EXIT

ip link set lo up
# a network namespace of its own for each peer, held open by a sleeping process
space() {
  unshare -n sleep 600 &
  eval "ns_$1=$!"
  pids="$pids $!"
  i=0
  while [ "$(readlink /proc/$!/ns/net)" = "$(readlink /proc/self/ns/net)" ] && [ $i -lt 100 ]; do
    sleep 0.05
    i=$((i + 1))
  done
}
inside() {
  eval "t=\$ns_$1"
  shift
  nsenter -t "$t" -n "$@"
}
# cable HUB_END PEER PEER_END
cable() {
  ip link add "$1" type veth peer name "$3" || fail "veth"
  eval "t=\$ns_$2"
  ip link set "$3" netns "$t" || fail "move $3"
  ip link set "$1" up
  inside "$2" ip link set "$3" up
}
config() {
  mkdir -p "$base/$1"
  # only the hub relays, so that what it takes in from its peers can be counted
  if [ "$1" = hub ]; then transport=Yes; else transport=No; fi
  printf '[reticulum]\nenable_transport = %s\nshare_instance = Yes\n[interfaces]\n[[Mesh]]\ntype = AutoInterface\nenabled = Yes\n' \
    "$transport" >"$base/$1/config"
}
# start NAME: this port's node in NAME's namespace (the hub in this one)
start() {
  config "$1"
  if [ "$1" = hub ]; then
    "$node" --config "$base/hub" --admin "$base/hub/admin" -v >"$base/hub/log" 2>&1 &
    pids="$pids $!"
  else
    eval "t=\$ns_$1"
    nsenter -t "$t" -n "$node" --config "$base/$1" -v >"$base/$1/log" 2>&1 &
    pids="$pids $!"
  fi
}
start_reference() {
  config "$1"
  printf '[stamps]\ndestination_value = 8\npr_value = 8\n' >>"$base/$1/config"
  eval "t=\$ns_$1"
  PYTHONPATH="$reference:${PYTHONPATH:-}" nsenter -t "$t" -n "$python" -u -m RNS.Utilities.rnsd --config "$base/$1" -vvv >"$base/$1/log" 2>&1 &
  pids="$pids $!"
}
# until SECONDS COMMAND...: retries four times a second
until_true() {
  n=$(($1 * 4))
  shift
  while ! "$@" >/dev/null 2>&1; do
    n=$((n - 1))
    [ $n -le 0 ] && return 1
    sleep 0.25
  done
}
logged() { grep -q "$2" "$base/$1/log"; }
# a peer has found the hub: this port logs the interface coming up, the reference counts it in its statistics
sees_a_peer() {
  logged "$1" 'AutoInterfacePeer\[.*is up' ||
    inside "$1" "$ctl" status -j --config "$base/$1" | grep -Eq '"peers": ?[1-9]'
}
found_hub() { until_true 40 sees_a_peer "$1" || fail "node $1 did not find the hub"; }
link_local() { ip -6 -o addr show dev "$1" scope link | awk '{print $4}' | cut -d/ -f1 | head -1; }
settled() {
  addresses=$("$@" ip -6 -o addr show scope link) && [ -n "$addresses" ] && ! echo "$addresses" | grep -q tentative
}
# announce FROM: a new identity announced by that peer; leaves its destination in $dest
announce() {
  if [ -n "$python" ] && [ "$1" = a ]; then
    announce_reference "$1"
    return
  fi
  "$ctl" id -g "$base/$1/announce.id" -f >/dev/null || fail "identity"
  dest=$(inside "$1" "$ctl" id -i "$base/$1/announce.id" -a rnc.auto.test --config "$base/$1" |
    sed -n 's/.*destination <\([0-9a-f]*\)>.*/\1/p')
  [ -n "$dest" ] || fail "announce from $1"
}
# From a reference client that stays connected a while: rnsd sends an announce on about a second after it gets it,
# and drops it if the program that handed it over has gone by then ("next hop interface doesn't exist")
announce_reference() {
  eval "t=\$ns_$1"
  : >"$base/$1/dest"
  PYTHONPATH="$reference:${PYTHONPATH:-}" nsenter -t "$t" -n "$python" -u -c '
import sys, time, RNS
RNS.Reticulum(sys.argv[1], loglevel=0)
d = RNS.Destination(RNS.Identity(), RNS.Destination.IN, RNS.Destination.SINGLE, "rnc", "auto", "test")
d.announce()
print(d.hash.hex(), flush=True)
time.sleep(20)
' "$base/$1" >"$base/$1/dest" 2>>"$base/$1/log" &
  pids="$pids $!"
  until_true 20 grep -q . "$base/$1/dest" || fail "reference announce from $1"
  dest=$(head -1 "$base/$1/dest")
}
has_path() { inside "$1" "$ctl" path -t --config "$base/$1" | grep -q "$dest"; }
# packets the hub has taken in from its peers
hub_received() {
  python3 -c '
import re, socket, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(b"STATUS\n"); s.settimeout(3); out = b""
while True:
    d = s.recv(4096)
    if not d: break
    out += d
print(sum(int(m) for m in re.findall(r"parent=[1-9]\d* kind=4 .*? rx=(\d+)", out.decode())))
' "$base/hub/admin"
}

# crosses FROM TO: an announce from one peer reaches another through the hub
crosses() {
  announce "$1"
  until_true 20 has_path "$2"
}

space a
space b
space c

# 1. no usable device at start: the interface stays, and takes the devices that appear later
start hub
until_true 10 logged hub 'Ready identity=' || fail "the hub did not start without any device"
logged hub 'Cannot open interface' && fail "the interface was refused for want of a device"

# 2. two cables appear; both are used, and an announce crosses the hub from one to the other
cable h1 a a1
cable h2 b b1
until_true 15 settled env
until_true 15 settled inside a
until_true 15 settled inside b
if [ -n "$python" ]; then start_reference a; else start a; fi
start b
until_true 40 logged hub 'AutoInterfacePeer\[h1/.*is up' || fail "no peer on the first late device"
until_true 40 logged hub 'AutoInterfacePeer\[h2/.*is up' || fail "no peer on the second device"
until_true 20 inside b "$ctl" status --config "$base/b" || fail "node b not answering"
until_true 30 inside a "$ctl" status --config "$base/a" || fail "node a not answering"
found_hub a
found_hub b
sleep 3
crosses a b || fail "an announce did not cross from the first cable to the second"
crosses b a || fail "an announce did not cross from the second cable to the first"

# 3. a second cable to the same peer (only this port's node: the reference does not take devices added later):
#    the same announce arrives twice and is taken in once
if [ -z "$python" ]; then
  cable h3 a a3
  until_true 40 logged hub 'AutoInterfacePeer\[h3/.*is up' || fail "no peer on the third device"
  sleep 4
  before=$(hub_received)
  announce a
  until_true 20 has_path b || fail "announce over two cables"
  sleep 1
  after=$(hub_received)
  [ $((after - before)) -eq 1 ] || fail "a doubled announce was taken in $((after - before)) times"
  ip link del h3
  until_true 20 logged hub 'h3.*removed' || fail "a removed device was not noticed"
fi

# 4. the hub's link-local address on a cable changes: it carries on with the new one
ip -6 addr flush dev h2 scope link
ip -6 addr add fe80::dead:beef/64 dev h2 nodad
until_true 40 logged b 'AutoInterfacePeer\[b1/fe80::dead:beef\].*is up' || fail "the new address was not announced"
sleep 4
crosses b a || fail "nothing got through after the address change"
crosses a b || fail "nothing reached the changed address"

# 5. a cable that appears while everything is running
cable h4 c c1
until_true 15 settled env
until_true 15 settled inside c
start c
until_true 40 logged hub 'AutoInterfacePeer\[h4/.*is up' || fail "no peer on a device added while running"
until_true 20 inside c "$ctl" status --config "$base/c" || fail "node c not answering"
found_hub c
sleep 3
crosses c b || fail "an announce from the added cable did not arrive"
# every link here is healthy, so multicast must have come back everywhere
sleep 8
grep -l 'no multicast echoes\|carrier lost' "$base"/*/log && fail "a healthy link was reported as having no multicast echo"
echo "AutoInterface over several devices works"
