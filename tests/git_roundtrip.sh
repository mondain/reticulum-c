#!/bin/bash
# Repository transport round trips through a node, with a real git client.
#   git_roundtrip.sh MODE NODE SERVER HELPER [PYTHON REFERENCE_DIR]
# MODE ref_client: the reference git-remote-rns against reticulum-c-git.
#      c_client:   reticulum-c-git-remote against reticulum-c-git.
#      ref_server: reticulum-c-git-remote against the reference rngit server.
set -u
MODE=$1 NODE=$2 SERVER=$3 HELPER=$4 PYTHON=${5:-} REFDIR=${6:-}
D=$(mktemp -d /tmp/rnc-git-XXXXXX)
PIDS=()
cleanup() {
  local p
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  for p in "${PIDS[@]}"; do wait "$p" 2>/dev/null; done
  rm -rf "$D"
}
[ -n "${KEEP:-}" ] || trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; for f in "$D"/*.log; do echo "--- $f" >&2; tail -20 "$f" >&2; done; exit 1; }
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
export GIT_TERMINAL_PROMPT=0
PORT=$((20000 + (RANDOM % 20000)))

# node
mkdir -p "$D/node"
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
PIDS+=($!)
for i in $(seq 1 50); do grep -q "Ready identity=" "$D/node.log" 2>/dev/null && break; sleep 0.1; done
grep -q "Ready identity=" "$D/node.log" || fail "node did not start"

# repositories
mkdir -p "$D/repos/pub" "$D/repos/priv" "$D/repos/locked" "$D/repos/ro" "$D/srv"
for g in pub priv locked ro; do
  git init -q --bare -b main "$D/repos/$g/proj.git"
done
# seed content into pub/proj.git
git init -q -b main "$D/seed"
echo one > "$D/seed/a.txt"; git -C "$D/seed" add a.txt; git -C "$D/seed" commit -q -m first
git -C "$D/seed" push -q "$D/repos/pub/proj.git" main
git -C "$D/seed" push -q "$D/repos/locked/proj.git" main
git -C "$D/seed" push -q "$D/repos/priv/proj.git" main
git -C "$D/seed" push -q "$D/repos/ro/proj.git" main

# client identity (the hash is needed for the permissions)
mkdir -p "$D/cli" "$D/rns"
if [ "$MODE" = c_client ] || [ "$MODE" = ref_server ]; then
  "$SERVER" --print-identity --config "$D/cli" --identity "$D/cli/client_identity" >/dev/null 2>&1 || true
  CLIENT_HASH=$("$SERVER" --print-identity --config "$D/cli" --identity "$D/cli/client_identity" 2>/dev/null | sed -n 's/.*Identity  *: <\(.*\)>/\1/p')
else
  CLIENT_HASH=$(PYTHONPATH=$REFDIR "$PYTHON" -c "
import RNS
i=RNS.Identity(); i.to_file('$D/cli/client_identity'); print(RNS.hexrep(i.hash, delimit=False))")
fi
[ ${#CLIENT_HASH} = 32 ] || fail "no client identity hash ($CLIENT_HASH)"

# server
if [ "$MODE" = ref_server ]; then
  mkdir -p "$D/refrns"
  cat > "$D/refrns/config" <<CFG
[reticulum]
enable_transport = No
share_instance = No
[logging]
loglevel = 4
[interfaces]
  [[T]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = $PORT
CFG
  cat > "$D/srv/config" <<CFG
[rngit]
announce_interval = 1
[logging]
loglevel = 4
[repositories]
pub = $D/repos/pub
priv = $D/repos/priv
locked = $D/repos/locked
ro = $D/repos/ro
[access]
pub = r:all, w:all
ro = r:all
priv = rw:$CLIENT_HASH
locked = r:none
CFG
  PYTHONPATH=$REFDIR "$PYTHON" -u -c "
import sys
from RNS.Utilities.rngit import server
sys.argv=['rngit','--config','$D/srv','--rnsconfig','$D/refrns']
server.main()" > "$D/server.log" 2>&1 &
  PIDS+=($!)
  for i in $(seq 1 100); do grep -q "listening on" "$D/server.log" 2>/dev/null && break; sleep 0.1; done
  DEST=$(sed -n 's/.*listening on <\(.*\)>.*/\1/p' "$D/server.log" | head -1)
else
  cat > "$D/srv/config" <<CFG
[rngit]
announce_interval = 1
[repositories]
pub = $D/repos/pub
priv = $D/repos/priv
locked = $D/repos/locked
ro = $D/repos/ro
[access]
pub = r:all, w:all
ro = r:all
priv = rw:$CLIENT_HASH
locked = r:none
CFG
  "$SERVER" --connect "127.0.0.1:$PORT" --config "$D/srv" > "$D/server.out" 2> "$D/server.log" &
  PIDS+=($!)
  for i in $(seq 1 100); do grep -q "listening on" "$D/server.out" 2>/dev/null && break; sleep 0.1; done
  DEST=$(sed -n 's/.*listening on <\(.*\)>.*/\1/p' "$D/server.out" | head -1)
fi
[ ${#DEST} = 32 ] || fail "no server destination ($DEST)"

# client helper on PATH as git-remote-rns
mkdir -p "$D/bin"
case $MODE in
ref_client)
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
  cat > "$D/bin/git-remote-rns" <<SH
#!/bin/sh
export PYTHONPATH="$REFDIR"
export RNGIT_CONFIG="$D/cli" RNS_CONFIG="$D/rns"
exec "$PYTHON" -c 'from RNS.Utilities.rngit.client import main; main()' "\$@"
SH
  ;;
*)
  cat > "$D/bin/git-remote-rns" <<SH
#!/bin/sh
export RNGIT_CONNECT="127.0.0.1:$PORT" RNGIT_CONFIG="$D/cli"
exec "$HELPER" "\$@"
SH
  ;;
esac
chmod +x "$D/bin/git-remote-rns"
export PATH="$D/bin:$PATH"
sleep 2   # the server announces on start; let the node learn the path

URL="rns://$DEST"
set -e
# clone, commit, push, clone again
git clone -q "$URL/pub/proj.git" "$D/w1" 2> "$D/clone1.log" || { cat "$D/clone1.log" >&2; fail "clone pub"; }
[ "$(cat "$D/w1/a.txt")" = one ] || fail "cloned content"
echo two > "$D/w1/b.txt"; git -C "$D/w1" add b.txt; git -C "$D/w1" commit -q -m second
git -C "$D/w1" push -q origin main 2> "$D/push1.log" || { cat "$D/push1.log" >&2; fail "push pub"; }
[ "$(git -C "$D/repos/pub/proj.git" rev-parse main)" = "$(git -C "$D/w1" rev-parse main)" ] || fail "server head after push"
git clone -q "$URL/pub/proj.git" "$D/w2" 2> "$D/clone2.log" || fail "second clone"
[ "$(git -C "$D/w2" rev-parse main)" = "$(git -C "$D/w1" rev-parse main)" ] || fail "second clone head"
# incremental fetch
echo three > "$D/w1/c.txt"; git -C "$D/w1" add c.txt; git -C "$D/w1" commit -q -m third
git -C "$D/w1" push -q origin main 2>/dev/null || fail "second push"
git -C "$D/w2" pull -q 2>"$D/pull.log" || { cat "$D/pull.log" >&2; fail "pull"; }
[ -f "$D/w2/c.txt" ] || fail "pull content"
# branch push, then delete it
git -C "$D/w1" push -q origin main:refs/heads/topic 2>/dev/null || fail "branch push"
git -C "$D/repos/pub/proj.git" rev-parse refs/heads/topic >/dev/null || fail "branch on server"
git -C "$D/w1" push -q origin :refs/heads/topic 2>/dev/null || fail "branch delete"
! git -C "$D/repos/pub/proj.git" rev-parse refs/heads/topic >/dev/null 2>&1 || fail "branch still on server"
# a push of history the server already has (empty bundle path)
git -C "$D/w1" push -q origin main:refs/heads/alias 2>/dev/null || fail "alias push"
set +e
# permissions: priv is readable and writable by this identity; locked is neither writable nor listed for push
git clone -q "$URL/priv/proj.git" "$D/w3" 2>/dev/null || fail "clone priv as allowed identity"
if git clone -q "$URL/locked/proj.git" "$D/w4" 2>/dev/null; then fail "clone of locked repository was allowed"; fi
if git clone -q "$URL/pub/nosuch.git" "$D/w5" 2>/dev/null; then fail "clone of unknown repository was allowed"; fi
# a read-only group can be cloned but not pushed to, and its refs cannot be deleted
git clone -q "$URL/ro/proj.git" "$D/w6" 2>/dev/null || fail "clone read-only repository"
echo extra > "$D/w6/x.txt"; git -C "$D/w6" add x.txt; git -C "$D/w6" commit -q -m extra
if git -C "$D/w6" push -q origin main 2>/dev/null; then fail "push to a read-only repository was allowed"; fi
if git -C "$D/w6" push -q origin :refs/heads/main 2>/dev/null; then fail "ref delete in a read-only repository was allowed"; fi
[ "$(git -C "$D/repos/ro/proj.git" rev-parse main)" = "$(git -C "$D/seed" rev-parse main)" ] || fail "read-only repository changed"
echo PASS
