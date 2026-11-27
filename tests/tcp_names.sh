#!/bin/sh
# TCP client interfaces given a host name, in a private network with its own hosts file and name server (Linux, no
# root needed):
#   unshare -rmn sh tcp_names.sh NODE
set -u
node=$1
base=$(mktemp -d /tmp/rnc-names-XXXXXX)
pids=''
fail() {
  echo "FAIL: $*" >&2
  for log in "$base"/*/log; do echo "== $log" >&2; tail -15 "$log" >&2; done
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
printf '127.0.0.1 localhost\n' >"$base/hosts"
printf 'hosts: files dns\n' >"$base/nsswitch.conf"
printf 'nameserver 127.0.0.1\noptions timeout:5 attempts:1\n' >"$base/resolv.conf"
for f in hosts nsswitch.conf resolv.conf; do
  mount --bind "$base/$f" "/etc/$f" || fail "bind $f"
done
# a name server that takes questions and never answers them
python3 -c 'import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 53))
while True:
    s.recvfrom(512)' &
pids="$pids $!"
# the hosts file is bind mounted, so it is rewritten in place
names() { printf '127.0.0.1 localhost\n%b' "$1" >"$base/hosts"; }

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
# start NAME INTERFACE_SECTION
start() {
  mkdir -p "$base/$1"
  printf '[reticulum]\nenable_transport = Yes\nshare_instance = No\n[interfaces]\n[[Link]]\n%b' "$2" >"$base/$1/config"
  "$node" --config "$base/$1" --admin "$base/$1/admin" -v >"$base/$1/log" 2>&1 &
  eval "pid_$1=$!"
  pids="$pids $!"
  until_true 20 logged "$1" 'Ready identity=' || fail "node $1 did not start"
}
status() {
  python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(1); s.connect(sys.argv[1]); s.sendall(b"STATUS\n")
print(s.recv(4096).decode())' "$base/$1/admin"
}
online() { status "$1" | grep -q 'parent=0 kind=2 .*online=1'; }
connected_clients() { status "$1" | grep -c 'parent=[1-9].*online=1'; }
server() { start "$1" "type = TCPServerInterface\nlisten_ip = $2\nlisten_port = 4242\n"; }

server a 127.0.0.2
# 1. a name that does not resolve yet: the interface is there and keeps trying
start c 'type = TCPClientInterface\ntarget_host = peer.test\ntarget_port = 4242\nreconnect_wait = 1\n'
logged c 'Cannot open interface' && fail "an interface was refused because its name did not resolve"
until_true 20 logged c 'cannot look up peer.test' || fail "the failed lookup was not reported"
online c && fail "online without an address"
# 2. the name appears
names '127.0.0.2 peer.test\n'
until_true 20 online c || fail "did not connect once the name resolved"
[ "$(connected_clients a)" = 1 ] || fail "the first server does not have the client"
# 3. the server moves to another address
kill "$pid_a"
names '127.0.0.3 peer.test\n'
server b 127.0.0.3
has_client() { [ "$(connected_clients b)" = 1 ]; }
until_true 30 has_client || fail "did not follow the name to its new address"

# 4. a name server that does not answer does not hold the node up
start d 'type = TCPClientInterface\ntarget_host = slow.invalid\ntarget_port = 4242\nreconnect_wait = 1\n'
i=0
while [ $i -lt 24 ]; do
  status d >/dev/null 2>&1 || fail "the node stopped answering while a name was being looked up"
  sleep 0.5
  i=$((i + 1))
done
logged d 'cannot look up slow.invalid' || fail "the slow lookup never finished"
# it stops at once even with a lookup under way
sleep 1.5
before=$(date +%s)
kill "$pid_d"
gone() { ! kill -0 "$pid_d" 2>/dev/null; }
until_true 3 gone || fail "the node did not stop while looking up a name"

# 5. a Wi-Fi RNode given by name
python3 -c 'import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.4", 7633)); s.listen(1)
c, _ = s.accept()
open("'"$base"'/rnode-got", "wb").write(c.recv(64))
import time; time.sleep(60)' &
pids="$pids $!"
start e 'type = RNodeInterface\nport = tcp://rnode.test\nfrequency = 915000000\nbandwidth = 125000\ntxpower = 2\nspreadingfactor = 8\ncodingrate = 5\n'
logged e 'Cannot open interface' && fail "an RNode was refused because its name did not resolve"
names '127.0.0.3 peer.test\n127.0.0.4 rnode.test\n'
until_true 30 test -s "$base/rnode-got" || fail "the RNode name was not looked up again"
echo "host names are looked up for every connection"
