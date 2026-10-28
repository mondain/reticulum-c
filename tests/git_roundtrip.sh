#!/bin/bash
# Repository transport round trips through a node, with a real git client.
#   git_roundtrip.sh MODE NODE SERVER HELPER [PYTHON REFERENCE_DIR]
# MODE ref_client: the reference git-remote-rns against reticulum-c-git.
#      c_client:   reticulum-c-git-remote against reticulum-c-git.
#      ref_server: reticulum-c-git-remote against the reference rngit server.
. "$(dirname "$0")/git_env.sh"
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
# repository management: create, push into the new repository, edit permissions
ADMIN=$(dirname "$HELPER")/reticulum-c-git-admin
admin() {   # admin KIND URL [FILE]: create, or set the permission file of a group/repository
  local kind=$1 url=$2 file=${3:-}
  if [ "$MODE" = ref_client ]; then
    printf '#!/bin/sh\ncp "%s" "$1"\n' "$file" > "$D/editor.sh"; chmod +x "$D/editor.sh"
    local cmd=create; [ "$kind" = create ] || cmd=perms
    EDITOR="$D/editor.sh" PYTHONPATH=$REFDIR "$PYTHON" -c "
import sys
from RNS.Utilities.rngit import server
sys.argv=['rngit','$cmd','--config','$D/cli','--rnsconfig','$D/rns','-i','$D/cli/client_identity','$url']
server.main()" > "$D/admin.log" 2>&1
  elif [ "$kind" = create ]; then
    RNGIT_CONNECT="127.0.0.1:$PORT" "$ADMIN" --config "$D/cli" create "$url" > "$D/admin.log" 2>&1
  else
    RNGIT_CONNECT="127.0.0.1:$PORT" "$ADMIN" --config "$D/cli" "$kind" "$url" set "$file" > "$D/admin.log" 2>&1
  fi
}
admin create "$URL/dev/made.git" || { cat "$D/admin.log" >&2; fail "create repository"; }
[ -f "$D/repos/dev/made.git/HEAD" ] || fail "created repository missing"
grep -q "^adm:$CLIENT_HASH" "$D/repos/dev/made.git.allowed" || fail "creator is not administrator"
git -C "$D/w1" push -q "$URL/dev/made.git" main:refs/heads/master 2>/dev/null || fail "push into created repository"
[ "$(git -C "$D/repos/dev/made.git" rev-parse master)" = "$(git -C "$D/w1" rev-parse main)" ] || fail "created repository head"
if admin create "$URL/dev/made.git"; then fail "creating an existing repository was allowed"; fi
if admin create "$URL/pub/other.git"; then fail "create without create permission was allowed"; fi
# repository permissions: write set to none blocks pushes (even the administrator's), then all allows them
echo "w:none" > "$D/perm_none.txt"; echo "w:all" > "$D/perm_all.txt"
git clone -q "$URL/dev/made.git" "$D/w7" 2>/dev/null || fail "clone created repository"
echo more > "$D/w7/m.txt"; git -C "$D/w7" add m.txt; git -C "$D/w7" commit -q -m more
admin rperms "$URL/dev/made.git" "$D/perm_none.txt" || { cat "$D/admin.log" >&2; fail "set repository permissions"; }
if git -C "$D/w7" push -q origin master:refs/heads/master 2>/dev/null; then fail "write to a repository set to none was allowed"; fi
admin rperms "$URL/dev/made.git" "$D/perm_all.txt" || { cat "$D/admin.log" >&2; fail "reset repository permissions"; }
git -C "$D/w7" push -q origin master:refs/heads/master 2>"$D/push7.log" || { cat "$D/push7.log" >&2; fail "write after permissions were set to all"; }
# group permissions are written to the group's allowed file
echo "w:all" > "$D/perm_group.txt"
admin gperms "$URL/dev" "$D/perm_group.txt" || { cat "$D/admin.log" >&2; fail "set group permissions"; }
grep -q "^w:all" "$D/repos/dev.allowed" || fail "group permission file"
echo "bogus" > "$D/perm_bad.txt"
if admin gperms "$URL/dev" "$D/perm_bad.txt"; then fail "an invalid permission was accepted"; fi
echo PASS
