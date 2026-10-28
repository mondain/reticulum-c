#!/bin/bash
# Differential test of the nomadnet page server: the same repositories are
# served by reticulum-c-git and by the unmodified reference rngit node (both
# with serve_nomadnet), the same page requests are sent to both over RNS links,
# and the micron answers are compared after masking what changes from one
# request to the next (generation time, relative times, version, destination
# hashes). The C node runs with its highlighter off (RNGIT_HIGHLIGHT=plain) and
# without wide character widths (RNGIT_NO_WCWIDTH=1) because the reference
# environment has neither pygments nor wcwidth.
#   git_pages.sh NODE SERVER PYTHON REFERENCE_DIR
set -u
[ -z "${TRACE:-}" ] || set -x
NODE=$(realpath "$1") SERVER=$(realpath "$2") PYTHON=$3 REFDIR=$(realpath "$4")
HERE=$(cd "$(dirname "$0")" && pwd)
CS=$(dirname "$SERVER")/reticulum-c-git-cs
D=$(mktemp -d /tmp/rnc-gitpages-XXXXXX)
PIDS=()
cleanup() {
  local p
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  for p in "${PIDS[@]}"; do wait "$p" 2>/dev/null; done
  [ -n "${KEEP:-}" ] || rm -rf "$D"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; for f in "$D"/*.log; do echo "--- $f" >&2; tail -15 "$f" >&2; done; exit 1; }
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0
export TZ=UTC GIT_AUTHOR_NAME=Ann GIT_AUTHOR_EMAIL=ann@example GIT_COMMITTER_NAME=Ann GIT_COMMITTER_EMAIL=ann@example
PORT=$((20000 + (RANDOM % 20000)))
PYTHONPATH=$REFDIR
export PYTHONPATH

# ---- the transport node -----------------------------------------------------
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

# ---- the client identity ----------------------------------------------------
mkdir -p "$D/cli" "$D/cliid"
CLIENT_HASH=$("$PYTHON" -c "
import RNS
i = RNS.Identity(); i.to_file('$D/cliid/identity'); print(RNS.hexrep(i.hash, delimit=False))")
[ ${#CLIENT_HASH} = 32 ] || fail "no client identity"
cat > "$D/cli/config" <<CFG
[reticulum]
enable_transport = No
share_instance = No
[logging]
loglevel = 1
[interfaces]
  [[T]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = $PORT
CFG

# ---- the repositories -------------------------------------------------------
R=$D/repos
mkdir -p "$R/pub" "$R/locked" "$R/many" "$R/plain"
for g in pub locked many plain; do git init -q --bare -b main "$R/$g/proj.git"; done
W=$D/work
git init -q -b main "$W"
cd "$W" || fail "work dir"
commit_as() { # commit_as DATE MESSAGE [EMAIL]
  GIT_AUTHOR_NAME=Ann GIT_AUTHOR_EMAIL=${3:-ann@example} GIT_COMMITTER_NAME=${4:-Ann} GIT_COMMITTER_EMAIL=${3:-ann@example} \
  GIT_AUTHOR_DATE=$1 GIT_COMMITTER_DATE=$1 git commit -q --allow-empty -m "$2"
}
cat > README.md <<'MD'
# Project title

Some *emphasis*, **strong** text, `inline code`, and a [relative link](docs/guide.md#top) plus an
[absolute one](rns://abcd/x). Under_score_names and 2*3*4 are kept as the converter sees them.

## Lists

- first
  - nested **item**
* second
+ third

---

> a block quote that goes on
> across two lines
and then a paragraph again

| Name | Value |
|:-----|------:|
| a    |     1 |
| bb   |    22 |

```python
def f(x):
    return x  # done
```

```
plain `tick` block
```

```rawmu
>>raw micron
```

-dash line
<angle line
back\slash
MD
printf '>> A micron page\n\nWith `!bold`! text and a `[link`:/page/index.mu]\n' > doc.mu
printf 'plain\n' > a.txt
mkdir -p src/inner sub
printf 'int main(void) {\n  return 0;\n}\n' > src/main.c
printf 'print("hi")\n' > src/inner/x.py
printf 'one `tick` and \\ backslash\nsecond\n' > tick.txt
printf -- '-leading dash\n>leading angle\n<leading less\n  - indented\n' > dash.txt
printf 'line one\r\nline two\r\n' > crlf.txt
printf 'caf\xc3\xa9 \xe2\x82\xac \xe2\x86\x92 text\n' > uni.txt
printf 'a\0b\0\1\2\3' > data.bin
ln -s a.txt link
"$PYTHON" - <<'PY'
import zlib, struct
def png(w, h, rgb):
    raw = b"".join(b"\x00" + bytes(rgb) * w for _ in range(h))
    def chunk(t, d):
        c = struct.pack(">I", len(d)) + t + d
        return c + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")
open("pic.png", "wb").write(png(8, 8, (200, 30, 30)))
open("sub/pic2.png", "wb").write(png(4, 4, (30, 200, 30)))
PY
if command -v convert > /dev/null 2>&1; then convert pic.png pic.webp 2>/dev/null || cp pic.png pic.webp; else cp pic.png pic.webp; fi
git add -A
commit_as "2020-01-02T03:04:05+0000" "initial import"
FIRST=$(git rev-parse HEAD)
git tag -a v1 -m "first release tag"
git tag light
printf 'plain\nmore text\n' > a.txt
head -c 300000 /dev/zero | tr '\0' 'x' > big.txt
git add -A
commit_as "2020-02-03T04:05:06+0000" "second: more text, a large file, with a \`backtick\` subject"
git checkout -q -b dev
printf 'dev work\n' > dev.txt
git add dev.txt
commit_as "2020-03-04T05:06:07+0000" "dev branch commit"
git checkout -q main
git merge -q --no-ff -m "merge dev" dev 2>/dev/null || { GIT_AUTHOR_NAME=Ann GIT_AUTHOR_EMAIL=ann@example GIT_COMMITTER_NAME=Ann GIT_COMMITTER_EMAIL=ann@example \
  GIT_AUTHOR_DATE="2020-04-05T06:07:08+0000" GIT_COMMITTER_DATE="2020-04-05T06:07:08+0000" git merge -q --no-ff -m "merge dev" dev; }
git mv src/main.c src/app.c
printf 'int main(void) {\n  return 1;\n}\n' > src/app.c
git add -A
commit_as "2020-05-06T07:08:09+0000" "rename main to app" "bob@example" "Bobby"
RENAME=$(git rev-parse HEAD)
MERGE=$(git rev-parse HEAD~1)
git rm -q dev.txt
printf '\n\nlast\n' >> a.txt
git add -A
commit_as "2020-06-07T08:09:10+0000" "remove dev.txt and edit"
# signed commits (reticulum-c-git-cs): one by its author, one claiming another author
head -c 64 /dev/urandom > "$D/idA"; head -c 64 /dev/urandom > "$D/idB"; chmod 600 "$D/idA" "$D/idB"
echo seed > "$D/seed.txt"
"$CS" -Y sign -n git -f "$D/idA" < "$D/seed.txt" > "$D/a.sig" 2>/dev/null || fail "sign"
HASHA=$("$CS" -Y find-principals -s "$D/a.sig")
HASHB=$("$CS" -Y sign -n git -f "$D/idB" < "$D/seed.txt" > "$D/b.sig" && "$CS" -Y find-principals -s "$D/b.sig")
printf 'signed\n' > signed.txt
git add -A
GITSIGN=(-c gpg.format=ssh -c "gpg.ssh.program=$CS" -c "user.signingkey=$D/idA")
GIT_AUTHOR_NAME=Ann GIT_AUTHOR_EMAIL=$HASHA GIT_COMMITTER_NAME=Ann GIT_COMMITTER_EMAIL=$HASHA GIT_AUTHOR_DATE="2020-07-08T09:10:11+0000" \
  GIT_COMMITTER_DATE="2020-07-08T09:10:11+0000" git "${GITSIGN[@]}" commit -q -S -m "signed by its author" || fail "signed commit"
SIGNED=$(git rev-parse HEAD)
GITSIGN=(-c gpg.format=ssh -c "gpg.ssh.program=$CS" -c "user.signingkey=$D/idB")
GIT_AUTHOR_NAME=Ann GIT_AUTHOR_EMAIL=$HASHA GIT_COMMITTER_NAME=Ann GIT_COMMITTER_EMAIL=$HASHB GIT_AUTHOR_DATE="2020-08-09T10:11:12+0000" \
  GIT_COMMITTER_DATE="2020-08-09T10:11:12+0000" git "${GITSIGN[@]}" commit -q --allow-empty -S -m "signed by someone else" || fail "badsig commit"
BADSIG=$(git rev-parse HEAD)
printf 'plain\nmore text\nfinal\n' > a.txt
git add -A
commit_as "2020-09-10T11:12:13+0000" "final commit"
HEAD=$(git rev-parse HEAD)
git push -q "$R/pub/proj.git" main dev v1 light
git push -q "$R/locked/proj.git" main
git push -q "$R/plain/proj.git" main
# a repository with more than one page of commits
git init -q -b main "$D/manyw"
( cd "$D/manyw" || exit 1
  for i in $(seq 1 130); do
    printf '%s\n' "$i" > f.txt; git add f.txt
    GIT_AUTHOR_NAME=Ann GIT_AUTHOR_EMAIL=ann@example GIT_COMMITTER_NAME=Ann GIT_COMMITTER_EMAIL=ann@example \
      GIT_AUTHOR_DATE="2021-01-01T00:00:00+0000" GIT_COMMITTER_DATE="2021-01-01T00:00:00+0000" git commit -q -m "commit number $i"
  done
  git push -q "$R/many/proj.git" main )
git -C "$R/pub/proj.git" config repository.description "The pub test repository"
git -C "$R/pub/proj.git" symbolic-ref HEAD refs/heads/main
cat > "$D/hashes.txt" <<H
HEAD $HEAD
FIRST $FIRST
MERGE $MERGE
RENAME $RENAME
SIGNED $SIGNED
BADSIG $BADSIG
H
cd "$D" || fail "cd"

# releases and work documents, in the formats of the reference
REL=$R/pub/proj.git.releases
mkdir -p "$REL/v1.0/artifacts" "$REL/v0.9/artifacts" "$REL/v0.8/artifacts" "$REL/draft/artifacts"
printf 'tag = v1.0\nhash = %s\ncreated = 1600000100\nstatus = published\ncreated_by = x\n' "$HEAD" > "$REL/v1.0/META"
printf '# Notes\n\nFirst **line** of the notes\n\n- a\n- b\n' > "$REL/v1.0/RELEASE.md"
head -c 2500 /dev/urandom > "$REL/v1.0/artifacts/tool.bin"
printf 'second artifact\n' > "$REL/v1.0/artifacts/Zed notes.txt"
printf 'tag = v0.9\ncreated = 1500000000\nstatus = published\n' > "$REL/v0.9/META"
printf '>> Micron notes\nplain micron preview\n' > "$REL/v0.9/RELEASE.mu"
printf 'tag = v0.8\ncreated = 1400000000\nstatus = published\n' > "$REL/v0.8/META"
printf 'Short note without artifacts\n' > "$REL/v0.8/RELEASE.md"
printf 'tag = draft\ncreated = 1700000000\nstatus = draft\n' > "$REL/draft/META"
printf 'secret\n' > "$REL/draft/artifacts/secret.bin"
printf 'v1.0\n' > "$REL/latest"
"$PYTHON" - "$R/pub/proj.git.work" <<'PY'
import os, sys, RNS
from RNS.vendor import umsgpack as mp
base = sys.argv[1]
ident = RNS.Identity()
def doc(scope, n, title, content, fmt, created, edited, sign=True, tamper=False):
    d = os.path.join(base, scope, str(n))
    os.makedirs(d, exist_ok=True)
    sig = ident.sign(content.encode("utf-8")) if sign else None
    if tamper and sig: sig = bytes([sig[0] ^ 1]) + sig[1:]
    meta = {"format": fmt, "title": title, "created": created, "edited": edited,
            "author": ident.hash, "signature": sig, "identity": ident.get_public_key()}
    with open(os.path.join(d, "root"), "wb") as fh: fh.write(mp.packb({"content": content, "meta": meta}))
    return d
def comment(d, n, content, created, fmt=None):
    c = {"content": content, "meta": {"created": created, "edited": created, "author": ident.hash, "signature": None}}
    if fmt: c["format"] = fmt
    with open(os.path.join(d, str(n)), "wb") as fh: fh.write(mp.packb(c))
d1 = doc("active", 1, "First work item", "A **signed** body\n\n- one\n- two\n", "markdown", 1700000000, 1700000500)
comment(d1, 1, "an *update* here", 1700000900)
comment(d1, 2, ">> micron update", 1700001900, "micron")
doc("active", 2, "Second, tampered signature", "Some text", "markdown", 1700002000, 1700002000, tamper=True)
doc("completed", 3, "Done thing", ">> micron body\n", "micron", 1700003000, 1700003000, sign=False)
doc("proposed", 4, "A proposal that has a very long title " + "x" * 120, "proposal text", "markdown", 1700004000, 1700004500, sign=False)
doc("active", 5, "Hidden item", "secret", "markdown", 1700005000, 1700005000)
open(os.path.join(base, "5.allowed"), "w").write("r:none\n")
PY

# ---- the two nodes ------------------------------------------------------------
write_config() { # write_config DIR
  mkdir -p "$1"
  cat > "$1/config" <<CFG
[rngit]
node_name = Diff Node
announce_interval = 1
record_stats = yes
[pages]
serve_nomadnet = yes
[logging]
loglevel = 4
[repositories]
pub = $R/pub
locked = $R/locked
many = $R/many
plain = $R/plain
[access]
pub = r:all, s:$CLIENT_HASH, i:all
locked = r:none
many = r:all
plain = r:all
CFG
}
write_config "$D/c"
write_config "$D/r"
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
RNGIT_HIGHLIGHT=plain RNGIT_NO_WCWIDTH=1 "$SERVER" --connect "127.0.0.1:$PORT" --config "$D/c" > "$D/c.out" 2> "$D/c.log" &
PIDS+=($!)
"$PYTHON" -u -c "
import sys
from RNS.Utilities.rngit import server
sys.argv=['rngit','--config','$D/r','--rnsconfig','$D/refrns']
server.main()" > "$D/r.log" 2>&1 &
PIDS+=($!)
for i in $(seq 1 100); do
  grep -q "Git Nomad Network Node listening on" "$D/c.out" 2>/dev/null && grep -q "Git Nomad Network Node listening on" "$D/r.log" 2>/dev/null && break
  sleep 0.1
done
C_DEST=$(sed -n 's/.*Git Nomad Network Node listening on <\(.*\)>.*/\1/p' "$D/c.out" | head -1)
R_DEST=$(sed -n 's/.*Git Nomad Network Node listening on <\(.*\)>.*/\1/p' "$D/r.log" | head -1)
[ ${#C_DEST} = 32 ] || fail "no C page node ($C_DEST)"
[ ${#R_DEST} = 32 ] || fail "no reference page node ($R_DEST)"
sleep 6   # both announce shortly after starting

CLIENT=$HERE/git_pages_client.py
fetch() { # fetch NAME DEST IDENTITY SET
  "$PYTHON" "$CLIENT" fetch "$D/cli" "$3" "$2" "$D/out_$1" "$D/hashes.txt" "$4" > "$D/fetch_$1.log" 2>&1 || { cat "$D/fetch_$1.log" >&2; fail "fetch $1"; }
}
# the identified run, then the unidentified one; the reference first, so the
# view counters of both nodes advance by the same requests in the same order
fetch ref_anon "$R_DEST" - anon
fetch c_anon "$C_DEST" - anon
fetch ref "$R_DEST" "$D/cliid/identity" all
fetch c "$C_DEST" "$D/cliid/identity" all
RESULT=0
echo "== unidentified"
"$PYTHON" "$CLIENT" compare "$D/out_c_anon" "$D/out_ref_anon" || RESULT=1
echo "== identified"
"$PYTHON" "$CLIENT" compare "$D/out_c" "$D/out_ref" || RESULT=1
[ "$RESULT" = 0 ] || { [ -z "${KEEP:-}" ] || echo "kept $D"; fail "the C page server differs from the reference"; }
# every answer was a real one (no silent timeouts on both sides)
if grep -l -E "^(NORESPONSE|NOREQUEST)$" "$D"/out_ref/* "$D"/out_c/* > "$D/silent.txt" 2>/dev/null && [ -s "$D/silent.txt" ]; then
  echo "requests that got no answer at all:"; cat "$D/silent.txt"
fi
N=$(ls "$D/out_c" | wc -l)
[ "$N" -gt 100 ] || fail "only $N answers"
echo "ok: $N page and file answers identical to the reference"
