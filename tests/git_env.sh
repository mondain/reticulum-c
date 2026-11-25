# Shared set-up of the git round-trip tests: a node, a repository node
# (C or reference), a client helper on PATH. Sourced, not run.
set -u
MODE=$1 NODE=$2 SERVER=$3 HELPER=$4 PYTHON=${5:-} REFDIR=${6:-}
# the oracle processes stamp cheaply (tests/oracle_env/sitecustomize.py): RNS 1.6 searches a proof of work per announce
ORACLE_ENV=$(cd "$(dirname "$0")" && pwd)/oracle_env
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
# RNC_GIT_ENFORCE: the node requires stamps, so the repository node and the client have to stamp.
# With the value "ref" an unmodified reference node does the requiring.
if [ -n "${RNC_GIT_ENFORCE:-}" ]; then
  printf '[stamps]\nenforce_stamps = Yes\ndestination_cost = 8\npr_cost = 8\n' >> "$D/node/config"
fi
if [ "${RNC_GIT_ENFORCE:-}" = ref ]; then
  sed -i 's/^type = TCPServerInterface/type = TCPServerInterface\nenabled = Yes/' "$D/node/config"
  PYTHONPATH=$REFDIR "$PYTHON" -u -c 'import sys
from RNS.Utilities import rnsd
sys.argv = ["rnsd", "--config", sys.argv[1], "-v"]
rnsd.main()' "$D/node" > "$D/node.log" 2>&1 &
  PIDS+=($!)
  for i in $(seq 1 100); do (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break; sleep 0.1; done
  (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null || fail "reference node did not start"
else
  "$NODE" --config "$D/node/config" --identity "$D/node/id" --admin "$D/node/admin" > "$D/node.log" 2>&1 &
  PIDS+=($!)
  for i in $(seq 1 50); do grep -q "Ready identity=" "$D/node.log" 2>/dev/null && break; sleep 0.1; done
  grep -q "Ready identity=" "$D/node.log" || fail "node did not start"
fi

# repositories
mkdir -p "$D/repos/pub" "$D/repos/priv" "$D/repos/locked" "$D/repos/ro" "$D/repos/dev" "$D/srv"
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
  CLIENT_HASH=$(PYTHONPATH=$REFDIR:$ORACLE_ENV "$PYTHON" -c "
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
dev = $D/repos/dev
[access]
pub = r:all, w:all
ro = r:all
dev = r:all, adm:$CLIENT_HASH
priv = rw:$CLIENT_HASH
locked = r:none
CFG
  PYTHONPATH=$REFDIR:$ORACLE_ENV "$PYTHON" -u -c "
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
dev = $D/repos/dev
[access]
pub = r:all, w:all
ro = r:all
dev = r:all, adm:$CLIENT_HASH
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
export PYTHONPATH="$REFDIR:$ORACLE_ENV"
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
# the server announces on start; wait until the node has learned the path
if [ "${RNC_GIT_ENFORCE:-}" = ref ]; then
  sleep 8   # the reference node does not log announces; the server's second one follows after 5 s
else
for i in $(seq 1 300); do grep -q "announce destination=$DEST" "$D/node.log" 2>/dev/null && break; sleep 0.1; done
grep -q "announce destination=$DEST" "$D/node.log" || fail "the node never saw the server's announce"
fi


URL="rns://$DEST"
