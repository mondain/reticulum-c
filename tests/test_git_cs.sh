#!/bin/bash
# Commit signing with a Reticulum identity: reticulum-c-git-cs against git and,
# when a reference checkout is given, against the reference rngcs.
#   test_git_cs.sh TOOL [PYTHON REFERENCE_DIR]
set -u
TOOL=$1 PYTHON=${2:-} REFDIR=${3:-}
D=$(mktemp -d /tmp/rnc-gitcs-XXXXXX)
[ -n "${KEEP:-}" ] || trap 'rm -rf "$D"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_TERMINAL_PROMPT=0 GIT_AUTHOR_NAME=t GIT_COMMITTER_NAME=t
cd "$D" || exit 1

# expect STATUS DESCRIPTION CMD... : run CMD (stdin from $IN, else empty),
# stdout to out.txt and stderr to err.txt, compare the exit status
expect() {
  local want=$1 what=$2 got; shift 2
  "$@" < "${IN:-/dev/null}" > out.txt 2> err.txt
  got=$?
  [ "$got" = "$want" ] || { cat out.txt err.txt >&2; fail "$what: exit $got, expected $want"; }
}
mkid() { head -c 64 /dev/urandom > "$1"; chmod 600 "$1"; }
sign_hash() { # sign_hash IDFILE: print the signer hash of that identity
  IN=seed.txt expect 0 "sign $1" "$TOOL" -Y sign -n git -f "$1"
  cp out.txt "$1.sig"
  expect 0 "principal $1" "$TOOL" -Y find-principals -s "$1.sig"
  cat out.txt
}

mkid idA; mkid idB
echo seed > seed.txt
IN=seed.txt expect 0 "sign stdout" "$TOOL" -Y sign -n git -f idA
grep -q '^-----BEGIN SSH SIGNATURE-----$' out.txt || fail "armor header"
grep -q '^-----END SSH SIGNATURE-----$' out.txt || fail "armor footer"
HASHA=$(sign_hash idA); HASHB=$(sign_hash idB)
[ ${#HASHA} = 32 ] || fail "principal is not 32 hex chars: $HASHA"
[ "$HASHA" != "$HASHB" ] || fail "identities collide"

payload() { # payload FILE AUTHOR_HASH
  printf 'tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor t <%s> 1700000000 +0000\ncommitter t <%s> 1700000000 +0000\n\nmessage\n' "$2" "$2" > "$1"
}
payload pa "$HASHA"
IN=pa expect 0 "sign payload" "$TOOL" -Y sign -n git -f idA; cp out.txt pa.sig

# ---- positive -------------------------------------------------------------
IN=pa expect 0 "verify" "$TOOL" -Y verify -n git -f /dev/null -I "$HASHA" -s pa.sig
grep -q "Good \"git\" signature for commit, signed with Reticulum Identity key <$HASHA>" out.txt || fail "verify message: $(cat out.txt)"
IN=pa expect 0 "verify without principal" "$TOOL" -Y verify -n git -f /dev/null -s pa.sig
IN=pa expect 0 "verify with -O options" "$TOOL" -Y verify -n git -f /dev/null -I "$HASHA" -O verify-time=20300101 -s pa.sig
expect 0 "check-novalidate" "$TOOL" -Y check-novalidate -n git -s pa.sig
# signing a file writes FILE.sig
cp pa pfile; expect 0 "sign file" "$TOOL" -Y sign -n git -f idA pfile
{ [ -f pfile.sig ] && [ ! -s out.txt ]; } || fail "sign file did not write pfile.sig quietly"
IN=pa expect 0 "verify file signature" "$TOOL" -Y verify -n git -f /dev/null -I "$HASHA" -s pfile.sig
# signing is deterministic (Ed25519): same input, same signature
cmp -s pa.sig pfile.sig || fail "signature is not reproducible"

# ---- a real git commit ----------------------------------------------------
git init -q -b main repo
echo hello > repo/f.txt
git -C repo add f.txt
touch allowed
GITSIGN=(-c gpg.format=ssh -c "gpg.ssh.program=$TOOL" -c "user.signingkey=$D/idA" -c "gpg.ssh.allowedSignersFile=$D/allowed")
GIT_AUTHOR_EMAIL=$HASHA GIT_COMMITTER_EMAIL=$HASHA git -C repo "${GITSIGN[@]}" commit -q -S -m "signed commit" || fail "git commit -S"
git -C repo cat-file commit HEAD | grep -q '^gpgsig -----BEGIN SSH SIGNATURE-----' || fail "commit carries no gpgsig"
git -C repo "${GITSIGN[@]}" verify-commit HEAD > vc.out 2>&1 || { cat vc.out >&2; fail "git verify-commit"; }
[ "$(git -C repo "${GITSIGN[@]}" log -1 --format=%G? HEAD 2>&1)" = G ] || fail "git does not report a good signature"
# a signed annotated tag, the tagger being the identity
GIT_COMMITTER_EMAIL=$HASHA git -C repo "${GITSIGN[@]}" tag -s -m "signed tag" v1 || fail "git tag -s"
git -C repo "${GITSIGN[@]}" verify-tag v1 > vt.out 2>&1 || { cat vt.out >&2; fail "git verify-tag"; }

# ---- negative -------------------------------------------------------------
# a commit whose author is not the signer
GIT_AUTHOR_EMAIL=$HASHB GIT_COMMITTER_EMAIL=$HASHA git -C repo "${GITSIGN[@]}" commit -q --allow-empty -S -m "wrong author" || fail "git commit -S 2"
if git -C repo "${GITSIGN[@]}" verify-commit HEAD > vc2.out 2>&1; then fail "commit signed by someone else verified"; fi
[ "$(git -C repo "${GITSIGN[@]}" log -1 --format=%G? HEAD 2>&1)" != G ] || fail "wrong-author commit reported good"
# tampered payload
sed 's/message/messagX/' pa > pa_tamper
IN=pa_tamper expect 1 "tampered payload" "$TOOL" -Y verify -n git -f /dev/null -I "$HASHA" -s pa.sig
grep -q "Invalid signature" err.txt || fail "tampered payload message"
IN=/dev/null expect 1 "empty payload" "$TOOL" -Y verify -n git -f /dev/null -s pa.sig
# signed by B, claimed author A
IN=pa expect 0 "sign with B" "$TOOL" -Y sign -n git -f idB; cp out.txt pa_b.sig
IN=pa expect 1 "wrong signer" "$TOOL" -Y verify -n git -f /dev/null -s pa_b.sig
grep -q "Commit not signed by author <$HASHA>" out.txt || fail "wrong signer message: $(cat out.txt)"
# right signer, wrong principal
IN=pa expect 1 "wrong principal" "$TOOL" -Y verify -n git -f /dev/null -I "$HASHB" -s pa.sig
grep -q "Principal mismatch" err.txt || fail "principal mismatch message"
# modified signature bytes (inside the 64 byte Ed25519 signature at offset 90)
sigbin() { sed -e '/BEGIN SSH/d' -e '/END SSH/d' "$1" | base64 -d > "$2"; }
rearmor() { { echo "-----BEGIN SSH SIGNATURE-----"; base64 -w 70 "$1"; echo "-----END SSH SIGNATURE-----"; } > "$2"; }
poke() { printf "$3" | dd of="$1" bs=1 seek="$2" conv=notrunc 2>/dev/null; }
sigbin pa.sig pa.bin
cp pa.bin bad1.bin; poke bad1.bin 100 '\x55'; rearmor bad1.bin bad1.sig
IN=pa expect 1 "flipped signature byte" "$TOOL" -Y verify -n git -f /dev/null -s bad1.sig
expect 0 "flipped signature byte still parses" "$TOOL" -Y check-novalidate -n git -s bad1.sig
# modified envelope (inside the signed hash)
cp pa.bin bad2.bin; poke bad2.bin 190 '\x55'; rearmor bad2.bin bad2.sig
IN=pa expect 1 "flipped envelope byte" "$TOOL" -Y verify -n git -f /dev/null -s bad2.sig
# wrong namespace: the namespace string "git" starts at byte 69
cp pa.bin bad3.bin; poke bad3.bin 69 'x'; rearmor bad3.bin bad3.sig
IN=pa expect 1 "wrong namespace verify" "$TOOL" -Y verify -n git -f /dev/null -s bad3.sig
grep -qi "namespace" err.txt || fail "namespace message"
expect 1 "wrong namespace check-novalidate" "$TOOL" -Y check-novalidate -n git -s bad3.sig
expect 1 "wrong namespace find-principals" "$TOOL" -Y find-principals -s bad3.sig
# damaged and missing files
head -c 40 pa.bin > trunc.bin; rearmor trunc.bin trunc.sig
IN=pa expect 1 "truncated signature" "$TOOL" -Y verify -n git -f /dev/null -s trunc.sig
echo "not a signature" > junk.sig
IN=pa expect 1 "junk signature" "$TOOL" -Y verify -n git -f /dev/null -s junk.sig
expect 1 "junk check-novalidate" "$TOOL" -Y check-novalidate -n git -s junk.sig
expect 1 "junk find-principals" "$TOOL" -Y find-principals -s junk.sig
IN=pa expect 1 "missing signature file" "$TOOL" -Y verify -n git -f /dev/null -s nonexistent.sig
expect 1 "missing check-novalidate file" "$TOOL" -Y check-novalidate -n git -s nonexistent.sig
expect 1 "missing key file" "$TOOL" -Y sign -n git -f nonexistent pa
head -c 63 /dev/urandom > shortid; chmod 600 shortid
expect 1 "short key file" "$TOOL" -Y sign -n git -f shortid pa
# command line
expect 2 "no operation" "$TOOL" -n git
expect 2 "bad operation" "$TOOL" -Y bogus
expect 1 "unknown argument" "$TOOL" -Y sign -f idA -U pa extra

# ---- differential against the reference ------------------------------------
if [ -n "$PYTHON" ] && [ -n "$REFDIR" ]; then
  export PYTHONPATH="$REFDIR:${PYTHONPATH:-}"
  cat > refcs <<REF
#!/bin/sh
exec "$PYTHON" -m RNS.Utilities.rngit.commitsigs "\$@"
REF
  chmod +x refcs
  REF=$D/refcs
  # the reference signature, checked by ours
  IN=pa expect 0 "reference sign" "$REF" -Y sign -n git -f idA; cp out.txt pa_ref.sig
  cmp -s pa_ref.sig pa.sig || fail "reference signature differs from ours byte for byte"
  IN=pa expect 0 "ours verifies reference signature" "$TOOL" -Y verify -n git -f /dev/null -I "$HASHA" -s pa_ref.sig
  expect 0 "reference find-principals" "$REF" -Y find-principals -s pa.sig
  [ "$(cat out.txt)" = "$HASHA" ] || fail "reference principal differs"
  # ours, checked by the reference
  IN=pa expect 0 "reference verifies our signature" "$REF" -Y verify -n git -f /dev/null -I "$HASHA" -s pa.sig
  expect 0 "reference check-novalidate" "$REF" -Y check-novalidate -n git -s pa.sig
  # negatives agree: exit status and stdout
  for case_ in "pa_tamper pa.sig" "pa pa_b.sig" "pa bad1.sig" "pa bad2.sig" "pa bad3.sig" "pa trunc.sig" "pa junk.sig"; do
    set -- $case_
    "$TOOL" -Y verify -n git -f /dev/null -s "$2" < "$1" > o1.txt 2> /dev/null; r1=$?
    "$REF" -Y verify -n git -f /dev/null -s "$2" < "$1" > o2.txt 2> /dev/null; r2=$?
    [ "$r1" = "$r2" ] || fail "exit codes differ for $case_: ours $r1 reference $r2"
    [ "$r1" = 1 ] || fail "$case_ unexpectedly verified"
    cmp -s o1.txt o2.txt || fail "stdout differs for $case_"
  done
  # real commits: signed by the reference and checked by ours, and back
  GITREF=(-c gpg.format=ssh -c "gpg.ssh.program=$REF" -c "user.signingkey=$D/idA" -c "gpg.ssh.allowedSignersFile=$D/allowed")
  echo two > repo/g.txt; git -C repo add g.txt
  GIT_AUTHOR_EMAIL=$HASHA GIT_COMMITTER_EMAIL=$HASHA git -C repo "${GITREF[@]}" commit -q -S -m "signed by the reference" || fail "reference git commit -S"
  git -C repo "${GITSIGN[@]}" verify-commit HEAD > vc3.out 2>&1 || { cat vc3.out >&2; fail "our tool rejected a reference-signed commit"; }
  echo three > repo/h.txt; git -C repo add h.txt
  GIT_AUTHOR_EMAIL=$HASHA GIT_COMMITTER_EMAIL=$HASHA git -C repo "${GITSIGN[@]}" commit -q -S -m "signed by ours" || fail "git commit -S (ours)"
  git -C repo "${GITREF[@]}" verify-commit HEAD > vc4.out 2>&1 || { cat vc4.out >&2; fail "reference rejected our commit"; }
fi
echo "git_cs OK"
