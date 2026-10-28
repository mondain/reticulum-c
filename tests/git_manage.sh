#!/bin/bash
# Repository management round trips: fork, mirror, sync, releases and work
# documents, with the C admin tool or the reference CLI as the client.
#   git_manage.sh MODE NODE SERVER HELPER [PYTHON REFERENCE_DIR]
# MODE c_client:   reticulum-c-git-admin against reticulum-c-git.
#      ref_client: the reference `rngit` subcommands against reticulum-c-git.
#      ref_server: reticulum-c-git-admin against the reference rngit node
#                  (releases and work documents; the reference node cannot fork
#                  from an rns:// source here, it has no helper of its own).
. "$(dirname "$0")/git_env.sh"
ADMIN=$(dirname "$HELPER")/reticulum-c-git-admin
set -e
export RNGIT_CONNECT="127.0.0.1:$PORT" RNGIT_CONFIG="$D/cli"
cd "$D"

ref() {   # ref SUBCOMMAND ARGS...: the reference rngit client
  local sub=$1; shift
  EDITOR="$D/editor.sh" PYTHONPATH=$REFDIR "$PYTHON" - "$sub" "$@" <<PY
import sys
from RNS.Utilities.rngit import server
sub, rest = sys.argv[1], sys.argv[2:]
sys.argv = ['rngit', sub, '--config', '$D/cli', '--rnsconfig', '$D/rns', '-i', '$D/cli/client_identity'] + rest
server.main()
PY
}
if [ "$MODE" = ref_client ]; then
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
fi
# editor for the reference client: writes whatever $EDITOR_TEXT holds
cat > "$D/editor.sh" <<'SH'
#!/bin/sh
printf '%s\n' "$EDITOR_TEXT" > "$1"
SH
chmod +x "$D/editor.sh"
adm() {   # adm TEXT ARGS...: run an admin command; TEXT is the editor text of the reference
  local text=$1; shift
  if [ "$MODE" = ref_client ]; then EDITOR_TEXT="$text" ref "$@"; else "$ADMIN" "$@"; fi
}
out() { "$@" 2>&1; }

# a repository to work on, with content and a tag
adm "" create "$URL/dev/made.git" > create.log 2>&1 || { cat create.log >&2; fail "create"; }
git clone -q "$URL/pub/proj.git" w 2>/dev/null
git -C w tag v1
git -C w push -q "$URL/dev/made.git" main:refs/heads/master v1 2>/dev/null || fail "push main and tag"

if [ "$MODE" != ref_server ]; then
  # fork and mirror from another repository on the same node, over rns://
  case $MODE in
  c_client)   "$ADMIN" fork "$URL/pub/proj.git" "$URL/dev/forked.git" > fork.log 2>&1 ;;
  ref_client) EDITOR_TEXT= ref fork "$URL/pub/proj.git" "$URL/dev/forked.git" > fork.log 2>&1 ;;
  esac || { cat fork.log >&2; fail "fork"; }
  [ "$(git -C "$D/repos/dev/forked.git" config repository.rngit.type)" = fork ] || fail "fork type"
  [ "$(git -C "$D/repos/dev/forked.git" rev-parse main)" = "$(git -C "$D/repos/pub/proj.git" rev-parse main)" ] || fail "fork content"
  grep -q "^adm:$CLIENT_HASH" "$D/repos/dev/forked.git.allowed" || fail "fork owner"
  case $MODE in
  c_client)   "$ADMIN" mirror "$URL/pub/proj.git" "$URL/dev/mirrored.git" > mirror.log 2>&1 ;;
  ref_client) EDITOR_TEXT= ref mirror "$URL/pub/proj.git" "$URL/dev/mirrored.git" > mirror.log 2>&1 ;;
  esac || { cat mirror.log >&2; fail "mirror"; }
  [ "$(git -C "$D/repos/dev/mirrored.git" config repository.rngit.type)" = mirror ] || fail "mirror type"
  [ "$(git -C "$D/repos/dev/mirrored.git" symbolic-ref HEAD)" = refs/heads/main ] || fail "mirror HEAD"
  # a new commit upstream arrives through sync
  echo three > w/c.txt; git -C w add c.txt; git -C w commit -q -m third
  git -C w push -q origin main 2>/dev/null || fail "push upstream"
  [ "$(git -C "$D/repos/dev/forked.git" rev-parse main)" != "$(git -C "$D/repos/pub/proj.git" rev-parse main)" ] || fail "fork moved by itself"
  case $MODE in
  c_client)   "$ADMIN" sync "$URL/dev/forked.git" > sync.log 2>&1 ;;
  ref_client) ref sync "$URL/dev/forked.git" > sync.log 2>&1 ;;
  esac || { cat sync.log >&2; fail "sync"; }
  [ "$(git -C "$D/repos/dev/forked.git" rev-parse main)" = "$(git -C "$D/repos/pub/proj.git" rev-parse main)" ] || fail "sync content"
  # a repository that is neither fork nor mirror cannot be synced
  if [ "$MODE" = c_client ]; then
    if "$ADMIN" sync "$URL/dev/made.git" >/dev/null 2>&1; then fail "sync of a plain repository was allowed"; fi
    if "$ADMIN" fork "file:///etc" "$URL/dev/bad.git" >/dev/null 2>&1; then fail "a file:// source was allowed"; fi
  fi
fi

# releases
mkdir -p dist; echo "binary one" > dist/tool-1.bin; head -c 70000 /dev/urandom > dist/big.bin
case $MODE in
ref_client) (cd w && EDITOR_TEXT="First release" ref release "$URL/dev/made.git" create "v1:$D/dist") > rel.log 2>&1 ;;
*)          (cd w && "$ADMIN" release "$URL/dev/made.git" create "v1:$D/dist" -m "First release") > rel.log 2>&1 ;;
esac || { cat rel.log >&2; fail "release create"; }
grep -q "^status = published" "$D/repos/dev/made.git.releases/v1/META" || fail "release published"
[ -f "$D/repos/dev/made.git.releases/v1/artifacts/manifest.rsm" ] || fail "manifest uploaded"
[ "$(cat "$D/repos/dev/made.git.releases/latest")" = v1 ] || fail "latest release"
if [ "$MODE" = ref_client ]; then
  ref release "$URL/dev/made.git" list > rl.log 2>&1 || fail "release list"
else
  "$ADMIN" release "$URL/dev/made.git" list > rl.log 2>&1 || fail "release list"
fi
grep -q "v1" rl.log || { cat rl.log >&2; fail "release list content"; }
mkdir -p got; (cd got
  if [ "$MODE" = ref_client ]; then ref release "$URL/dev/made.git" fetch "latest:all" > ../rf.log 2>&1
  else "$ADMIN" release "$URL/dev/made.git" fetch "latest:all" > ../rf.log 2>&1; fi) || { cat rf.log >&2; fail "release fetch"; }
cmp got/tool-1.bin dist/tool-1.bin && cmp got/big.bin dist/big.bin || fail "fetched artifacts differ"
# offline verification with the C tool; a changed file is refused
"$ADMIN" release dist/manifest.rsm verify -o >/dev/null 2>&1 || (cd dist && "$ADMIN" release manifest.rsm verify >/dev/null 2>&1) || fail "offline verify"
cp -r dist dist_bad; echo tampered >> dist_bad/tool-1.bin
if (cd dist_bad && "$ADMIN" release manifest.rsm verify >/dev/null 2>&1); then fail "a tampered artifact verified"; fi
# a wrong required signer is refused
if (cd dist && "$ADMIN" release manifest.rsm verify --signer 00000000000000000000000000000000 >/dev/null 2>&1); then fail "wrong signer accepted"; fi
if [ "$MODE" != c_client ]; then
  # the reference verifies what the C tool needs verified too
  if [ "$MODE" = ref_client ]; then
    (cd dist && "$ADMIN" release manifest.rsm verify >/dev/null 2>&1) || fail "C tool verifying a reference manifest"
  else
    (cd dist && ref release -o manifest.rsm verify >/dev/null 2>&1) || fail "reference verifying a C manifest"
  fi
fi
# deleting
if [ "$MODE" = ref_client ]; then
  printf 'y\n' | ref release "$URL/dev/made.git" delete v1 > rd.log 2>&1 || fail "release delete"
else
  "$ADMIN" release "$URL/dev/made.git" delete v1 -y > rd.log 2>&1 || fail "release delete"
fi
[ ! -d "$D/repos/dev/made.git.releases/v1" ] || fail "release still on the node"

# work documents
case $MODE in
ref_client)
  EDITOR_TEXT="It breaks" ref work "$URL/dev/made.git" create -t "Bug one" > wc.log 2>&1 || { cat wc.log >&2; fail "work create"; }
  ref work "$URL/dev/made.git" list > wl.log 2>&1 || fail "work list" ;;
*)
  "$ADMIN" work "$URL/dev/made.git" create -t "Bug one" -m "It breaks" > wc.log 2>&1 || { cat wc.log >&2; fail "work create"; }
  "$ADMIN" work "$URL/dev/made.git" list > wl.log 2>&1 || fail "work list" ;;
esac
grep -q "Bug one" wl.log || { cat wl.log >&2; fail "work list content"; }
if [ "$MODE" = ref_client ]; then
  ref work "$URL/dev/made.git" view -d 1 > wv.log 2>&1 || fail "work view"
else
  "$ADMIN" work "$URL/dev/made.git" view -d 1 > wv.log 2>&1 || fail "work view"
fi
grep -q "It breaks" wv.log && grep -q "Valid" wv.log || { cat wv.log >&2; fail "work view content and signature"; }
if [ "$MODE" = ref_client ]; then
  EDITOR_TEXT="Now it fails twice" ref work "$URL/dev/made.git" edit -d 1 > we.log 2>&1 || { cat we.log >&2; fail "work edit"; }
  EDITOR_TEXT="Me too" ref work "$URL/dev/made.git" update -d 1 > wu.log 2>&1 || fail "work update"
  ref work "$URL/dev/made.git" complete -d 1 > wd.log 2>&1 || fail "work complete"
else
  "$ADMIN" work "$URL/dev/made.git" edit -d 1 -m "Now it fails twice" > we.log 2>&1 || { cat we.log >&2; fail "work edit"; }
  "$ADMIN" work "$URL/dev/made.git" update -d 1 -m "Me too" > wu.log 2>&1 || fail "work update"
  "$ADMIN" work "$URL/dev/made.git" complete -d 1 > wd.log 2>&1 || fail "work complete"
fi
[ -d "$D/repos/dev/made.git.work/completed/1" ] || fail "document not completed"
if [ "$MODE" = ref_client ]; then
  ref work "$URL/dev/made.git" activate -d 1 > wa.log 2>&1 || fail "work activate"
  ref work "$URL/dev/made.git" view -d 1 > wv2.log 2>&1 || fail "work view again"
else
  "$ADMIN" work "$URL/dev/made.git" activate -d 1 > wa.log 2>&1 || fail "work activate"
  "$ADMIN" work "$URL/dev/made.git" view -d 1 > wv2.log 2>&1 || fail "work view again"
fi
grep -q "Now it fails twice" wv2.log && grep -q "Me too" wv2.log || { cat wv2.log >&2; fail "edited document and comment"; }
# proposals and permissions need a second identity: skipped here (handler tests cover them)
if [ "$MODE" != ref_server ]; then
  # deleting: the reference refuses when the document has no permission file; the C node does not
  :
fi
if [ "$MODE" = ref_client ]; then
  printf 'y\n' | ref work "$URL/dev/made.git" delete -d 1 > wx.log 2>&1 || true
else
  "$ADMIN" work "$URL/dev/made.git" delete -d 1 > wx.log 2>&1 || true
fi
echo PASS
