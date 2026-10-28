"""Page requests for the differential test of the rngit page server
(tests/git_pages.sh): a nomadnet style client that requests the same pages from
a node and writes each answer to a file, and a comparison of two such outputs.

  git_pages_client.py fetch  RNS_CONFIG IDENTITY_FILE|- DEST_HEX OUT_DIR HASHES_FILE [all|anon]
  git_pages_client.py compare OUT_A OUT_B

Only used by the interop tests: it needs the reference Reticulum (RNS)."""
import difflib
import hashlib
import os
import re
import sys
import time

# (name, path, data, set): set "all" for the identified run, "anon" also runs without identity
FIX = "proj.git"
REQUESTS = [
    ("index", "/page/index.mu", None, "anon"),
    ("index_data", "/page/index.mu", {"var_x": "y"}, "anon"),
    ("group", "/page/group.mu", {"var_g": "pub"}, "anon"),
    ("group_none", "/page/group.mu", {"var_g": "nogroup"}, "anon"),
    ("group_locked", "/page/group.mu", {"var_g": "locked"}, "anon"),
    ("group_empty", "/page/group.mu", {}, "all"),
    ("repo", "/page/repo.mu", {"var_g": "pub", "var_r": FIX}, "anon"),
    ("repo_ref", "/page/repo.mu", {"var_g": "pub", "var_r": FIX, "var_ref": "dev"}, "all"),
    ("repo_locked", "/page/repo.mu", {"var_g": "locked", "var_r": FIX}, "anon"),
    ("repo_missing", "/page/repo.mu", {"var_g": "pub", "var_r": "nothere.git"}, "all"),
    ("repo_invalid", "/page/repo.mu", {"var_g": "pub"}, "all"),
    ("repo_plain", "/page/repo.mu", {"var_g": "plain", "var_r": FIX}, "all"),
    ("tree", "/page/tree.mu", {"var_g": "pub", "var_r": FIX}, "all"),
    ("tree_src", "/page/tree.mu", {"var_g": "pub", "var_r": FIX, "var_path": "src"}, "all"),
    ("tree_sub", "/page/tree.mu", {"var_g": "pub", "var_r": FIX, "var_path": "src/inner"}, "all"),
    ("tree_slash", "/page/tree.mu", {"var_g": "pub", "var_r": FIX, "var_path": "src/"}, "all"),
    ("tree_branch", "/page/tree.mu", {"var_g": "pub", "var_r": FIX, "var_ref": "dev"}, "all"),
    ("tree_tag", "/page/tree.mu", {"var_g": "pub", "var_r": FIX, "var_ref": "v1"}, "all"),
    ("tree_badref", "/page/tree.mu", {"var_g": "pub", "var_r": FIX, "var_ref": "nosuchref"}, "all"),
    ("tree_notdir", "/page/tree.mu", {"var_g": "pub", "var_r": FIX, "var_path": "nosuchdir"}, "all"),
    ("tree_travel", "/page/tree.mu", {"var_g": "pub", "var_r": FIX, "var_path": "../.."}, "all"),
    ("tree_locked", "/page/tree.mu", {"var_g": "locked", "var_r": FIX}, "all"),
    ("tree_page", "/page/tree.mu", {"var_g": "pub", "var_r": FIX, "var_page": "1"}, "all"),
    ("tree_pagebad", "/page/tree.mu", {"var_g": "pub", "var_r": FIX, "var_page": "x"}, "all"),
    ("blob_txt", "/page/blob.mu", {"var_g": "pub", "var_r": FIX, "var_path": "a.txt"}, "all"),
    ("blob_md", "/page/blob.mu", {"var_g": "pub", "var_r": FIX, "var_path": "README.md"}, "all"),
    ("blob_md_raw", "/page/blob.mu", {"var_g": "pub", "var_r": FIX, "var_path": "README.md", "var_raw": "y"}, "all"),
    ("blob_md_render", "/page/blob.mu", {"var_g": "pub", "var_r": FIX, "var_path": "README.md", "var_render": "y"}, "all"),
    ("blob_mu", "/page/blob.mu", {"var_g": "pub", "var_r": FIX, "var_path": "doc.mu"}, "all"),
    ("blob_c", "/page/blob.mu", {"var_g": "pub", "var_r": FIX, "var_path": "src/main.c"}, "all"),
    ("blob_c_enc", "/page/blob.mu", {"var_g": "pub", "var_r": FIX, "var_path": "src%2Fmain.c"}, "all"),
    ("blob_dot", "/page/blob.mu", {"var_g": "pub", "var_r": FIX, "var_path": "./a.txt"}, "all"),
    ("blob_dir", "/page/blob.mu", {"var_g": "pub", "var_r": FIX, "var_path": "src"}, "all"),
    ("blob_bin", "/page/blob.mu", {"var_g": "pub", "var_r": FIX, "var_path": "pic.png"}, "all"),
    ("blob_bin2", "/page/blob.mu", {"var_g": "pub", "var_r": FIX, "var_path": "data.bin"}, "all"),
    ("blob_link", "/page/blob.mu", {"var_g": "pub", "var_r": FIX, "var_path": "link"}, "all"),
    ("blob_big", "/page/blob.mu", {"var_g": "pub", "var_r": FIX, "var_path": "big.txt"}, "all"),
    ("blob_backtick", "/page/blob.mu", {"var_g": "pub", "var_r": FIX, "var_path": "tick.txt"}, "all"),
    ("blob_dashes", "/page/blob.mu", {"var_g": "pub", "var_r": FIX, "var_path": "dash.txt"}, "all"),
    ("blob_crlf", "/page/blob.mu", {"var_g": "pub", "var_r": FIX, "var_path": "crlf.txt"}, "all"),
    ("blob_utf8", "/page/blob.mu", {"var_g": "pub", "var_r": FIX, "var_path": "uni.txt"}, "all"),
    ("blob_oldref", "/page/blob.mu", {"var_g": "pub", "var_r": FIX, "var_path": "a.txt", "var_ref": "v1"}, "all"),
    ("blob_missing", "/page/blob.mu", {"var_g": "pub", "var_r": FIX, "var_path": "nofile"}, "all"),
    ("blob_travel", "/page/blob.mu", {"var_g": "pub", "var_r": FIX, "var_path": "../../../etc/passwd"}, "all"),
    ("blob_nopath", "/page/blob.mu", {"var_g": "pub", "var_r": FIX}, "all"),
    ("blob_locked", "/page/blob.mu", {"var_g": "locked", "var_r": FIX, "var_path": "a.txt"}, "all"),
    ("commits", "/page/commits.mu", {"var_g": "pub", "var_r": FIX}, "all"),
    ("commits_branch", "/page/commits.mu", {"var_g": "pub", "var_r": FIX, "var_ref": "dev"}, "all"),
    ("commits_path", "/page/commits.mu", {"var_g": "pub", "var_r": FIX, "var_path": "src/main.c"}, "all"),
    ("commits_page1", "/page/commits.mu", {"var_g": "pub", "var_r": FIX, "var_page": "1"}, "all"),
    ("commits_many", "/page/commits.mu", {"var_g": "many", "var_r": FIX}, "all"),
    ("commits_many1", "/page/commits.mu", {"var_g": "many", "var_r": FIX, "var_page": "1"}, "all"),
    ("commits_many2", "/page/commits.mu", {"var_g": "many", "var_r": FIX, "var_page": "2"}, "all"),
    ("commits_bad", "/page/commits.mu", {"var_g": "pub", "var_r": FIX, "var_ref": "zzz"}, "all"),
    ("commits_locked", "/page/commits.mu", {"var_g": "locked", "var_r": FIX}, "all"),
    ("commit_head", "/page/commit.mu", {"var_g": "pub", "var_r": FIX, "var_h": "@HEAD"}, "all"),
    ("commit_first", "/page/commit.mu", {"var_g": "pub", "var_r": FIX, "var_h": "@FIRST"}, "all"),
    ("commit_merge", "/page/commit.mu", {"var_g": "pub", "var_r": FIX, "var_h": "@MERGE"}, "all"),
    ("commit_rename", "/page/commit.mu", {"var_g": "pub", "var_r": FIX, "var_h": "@RENAME"}, "all"),
    ("commit_signed", "/page/commit.mu", {"var_g": "pub", "var_r": FIX, "var_h": "@SIGNED"}, "all"),
    ("commit_badsig", "/page/commit.mu", {"var_g": "pub", "var_r": FIX, "var_h": "@BADSIG"}, "all"),
    ("commit_short", "/page/commit.mu", {"var_g": "pub", "var_r": FIX, "var_h": "abc"}, "all"),
    ("commit_unknown", "/page/commit.mu", {"var_g": "pub", "var_r": FIX, "var_h": "deadbeefdeadbeef"}, "all"),
    ("commit_tag", "/page/commit.mu", {"var_g": "pub", "var_r": FIX, "var_h": "refs/tags/v1"}, "all"),
    ("commit_locked", "/page/commit.mu", {"var_g": "locked", "var_r": FIX, "var_h": "@HEAD"}, "all"),
    ("refs", "/page/refs.mu", {"var_g": "pub", "var_r": FIX}, "all"),
    ("refs_heads", "/page/refs.mu", {"var_g": "pub", "var_r": FIX, "var_type": "heads"}, "all"),
    ("refs_tags", "/page/refs.mu", {"var_g": "pub", "var_r": FIX, "var_type": "tags"}, "all"),
    ("refs_locked", "/page/refs.mu", {"var_g": "locked", "var_r": FIX}, "all"),
    ("refs_invalid", "/page/refs.mu", {"var_g": "pub"}, "all"),
    ("releases", "/page/releases.mu", {"var_g": "pub", "var_r": FIX}, "all"),
    ("releases_none", "/page/releases.mu", {"var_g": "plain", "var_r": FIX}, "all"),
    ("release", "/page/release.mu", {"var_g": "pub", "var_r": FIX, "var_t": "v1.0"}, "all"),
    ("release_mu", "/page/release.mu", {"var_g": "pub", "var_r": FIX, "var_t": "v0.9"}, "all"),
    ("release_noart", "/page/release.mu", {"var_g": "pub", "var_r": FIX, "var_t": "v0.8"}, "all"),
    ("release_latest", "/page/release.mu", {"var_g": "pub", "var_r": FIX, "var_t": "latest"}, "all"),
    ("release_draft", "/page/release.mu", {"var_g": "pub", "var_r": FIX, "var_t": "draft"}, "all"),
    ("release_missing", "/page/release.mu", {"var_g": "pub", "var_r": FIX, "var_t": "v9"}, "all"),
    ("release_noarg", "/page/release.mu", {"var_g": "pub", "var_r": FIX}, "all"),
    ("work", "/page/work.mu", {"var_g": "pub", "var_r": FIX}, "all"),
    ("work_all", "/page/work.mu", {"var_g": "pub", "var_r": FIX, "var_scope": "all"}, "all"),
    ("work_done", "/page/work.mu", {"var_g": "pub", "var_r": FIX, "var_scope": "completed"}, "all"),
    ("work_prop", "/page/work.mu", {"var_g": "pub", "var_r": FIX, "var_scope": "proposed"}, "all"),
    ("work_badscope", "/page/work.mu", {"var_g": "pub", "var_r": FIX, "var_scope": "zzz"}, "all"),
    ("work_doc1", "/page/work_doc.mu", {"var_g": "pub", "var_r": FIX, "var_id": "1"}, "all"),
    ("work_doc2", "/page/work_doc.mu", {"var_g": "pub", "var_r": FIX, "var_id": "2"}, "all"),
    ("work_doc3", "/page/work_doc.mu", {"var_g": "pub", "var_r": FIX, "var_id": "3", "var_scope": "completed"}, "all"),
    ("work_doc4", "/page/work_doc.mu", {"var_g": "pub", "var_r": FIX, "var_id": "4"}, "all"),
    ("work_doc_hidden", "/page/work_doc.mu", {"var_g": "pub", "var_r": FIX, "var_id": "5"}, "all"),
    ("work_doc_none", "/page/work_doc.mu", {"var_g": "pub", "var_r": FIX, "var_id": "99"}, "all"),
    ("work_doc_bad", "/page/work_doc.mu", {"var_g": "pub", "var_r": FIX, "var_id": "x"}, "all"),
    ("work_doc_locked", "/page/work_doc.mu", {"var_g": "locked", "var_r": FIX, "var_id": "1"}, "all"),
    ("artifact", "/file/artifact", {"var_g": "pub", "var_r": FIX, "var_t": "v1.0", "var_a": "tool.bin"}, "all"),
    ("artifact_latest", "/file/artifact", {"var_g": "pub", "var_r": FIX, "var_t": "latest", "var_a": "tool.bin"}, "all"),
    ("artifact_draft", "/file/artifact", {"var_g": "pub", "var_r": FIX, "var_t": "draft", "var_a": "secret.bin"}, "all"),
    ("artifact_slash", "/file/artifact", {"var_g": "pub", "var_r": FIX, "var_t": "v1.0", "var_a": "../META"}, "all"),
    ("artifact_missing", "/file/artifact", {"var_g": "pub", "var_r": FIX, "var_t": "v1.0", "var_a": "nofile"}, "all"),
    ("download", "/file/download", {"var_g": "pub", "var_r": FIX, "var_path": "a.txt"}, "all"),
    ("download_bin", "/file/download", {"var_g": "pub", "var_r": FIX, "var_path": "data.bin"}, "all"),
    ("download_md_mu", "/file/download", {"var_g": "pub", "var_r": FIX, "var_path": "README.md", "var_fmt": "mu"}, "all"),
    ("download_fmt_bad", "/file/download", {"var_g": "pub", "var_r": FIX, "var_path": "a.txt", "var_fmt": "mu"}, "all"),
    ("download_missing", "/file/download", {"var_g": "pub", "var_r": FIX, "var_path": "nofile"}, "all"),
    ("download_travel", "/file/download", {"var_g": "pub", "var_r": FIX, "var_path": "../../etc/passwd"}, "all"),
    ("download_locked", "/file/download", {"var_g": "locked", "var_r": FIX, "var_path": "a.txt"}, "all"),
    ("workdoc_dl", "/file/workdoc", {"var_g": "pub", "var_r": FIX, "var_id": "1"}, "all"),
    ("workdoc_dl3", "/file/workdoc", {"var_g": "pub", "var_r": FIX, "var_id": "3"}, "all"),
    ("workdoc_dl_none", "/file/workdoc", {"var_g": "pub", "var_r": FIX, "var_id": "99"}, "all"),
    ("workdoc_dl_locked", "/file/workdoc", {"var_g": "locked", "var_r": FIX, "var_id": "1"}, "all"),
    ("media_png", "/media", {"key": "k", "path": "/media/pub/proj.git/HEAD/pic.png"}, "all"),
    ("media_enc", "/media", {"key": "k", "path": "/media/pub/proj.git/HEAD/sub%2Fpic2.png"}, "all"),
    ("media_webp", "/media", {"key": "k", "path": "/media/pub/proj.git/HEAD/pic.webp"}, "all"),
    ("media_nokey", "/media", {"path": "/media/pub/proj.git/HEAD/pic.png"}, "all"),
    ("media_short", "/media", {"key": "k", "path": "/media/pub/proj.git"}, "all"),
    ("media_locked", "/media", {"key": "k", "path": "/media/locked/proj.git/HEAD/pic.png"}, "all"),
    ("media_missing", "/media", {"key": "k", "path": "/media/pub/proj.git/HEAD/nofile.png"}, "all"),
    ("stats", "/page/stats.mu", {"var_g": "pub", "var_r": FIX}, "all"),
    ("stats_nostats", "/page/stats.mu", {"var_g": "plain", "var_r": FIX}, "all"),
    ("stats_locked", "/page/stats.mu", {"var_g": "locked", "var_r": FIX}, "all"),
    ("stats_invalid", "/page/stats.mu", {"var_g": "pub"}, "all"),
]
# git hashes that depend on the fixture are given as @NAME and read from HASHES
HASHES = {}


def load_hashes(path):
    with open(path) as fh:
        for line in fh:
            k, v = line.split()
            HASHES[k] = v


def fetch(rns_config, identity_file, dest_hex, out_dir, which):
    import RNS
    RNS.Reticulum(rns_config, loglevel=1)
    os.makedirs(out_dir, exist_ok=True)
    dest_hash = bytes.fromhex(dest_hex)
    deadline = time.time() + 90
    while not (RNS.Transport.has_path(dest_hash) and RNS.Identity.recall(dest_hash)):
        RNS.Transport.request_path(dest_hash)
        time.sleep(0.5)
        if time.time() > deadline:
            print("no path to", dest_hex, file=sys.stderr)
            return 1
    ident = RNS.Identity.recall(dest_hash)
    dest = RNS.Destination(ident, RNS.Destination.OUT, RNS.Destination.SINGLE, "nomadnetwork", "node")
    if dest.hash != dest_hash:
        print("destination hash mismatch: the announce is not for nomadnetwork.node", file=sys.stderr)
        return 1
    link = RNS.Link(dest)
    deadline = time.time() + 60
    while link.status != RNS.Link.ACTIVE:
        time.sleep(0.1)
        if time.time() > deadline or link.status == RNS.Link.CLOSED:
            print("link failed", file=sys.stderr)
            return 1
    if identity_file != "-":
        link.identify(RNS.Identity.from_file(identity_file))
        time.sleep(1.5)
    for index, (name, path, data, which_set) in enumerate(REQUESTS):
        if which == "anon" and which_set != "anon":
            continue
        if data:
            data = {k: HASHES.get(v[1:], v) if isinstance(v, str) and v.startswith("@") else v for k, v in data.items()}
        holder = {}

        def got(r, holder=holder):
            resp = r.response
            if hasattr(resp, "read"):
                resp = resp.read()
            holder["data"], holder["meta"] = resp, r.metadata

        receipt = link.request(path, data=data, timeout=12, response_callback=got)
        if receipt is False:
            body = "NOREQUEST"
        else:
            end = time.time() + 20
            while "data" not in holder and receipt.get_status() != RNS.RequestReceipt.FAILED:
                time.sleep(0.05)
                if time.time() > end:
                    break
            if "data" not in holder:
                body = "NORESPONSE"
            else:
                body = render(holder["data"], holder["meta"])
        with open(os.path.join(out_dir, "%03d_%s.txt" % (index, name)), "w", encoding="utf-8", errors="replace") as fh:
            fh.write(body)
    link.teardown()
    time.sleep(0.5)
    return 0


def render(response, metadata):
    if response is None:
        return "NONE"
    if response is False:
        return "FALSE"
    if hasattr(response, "read"):
        try:
            response = response.read()
        except ValueError:
            with open(response.name, "rb") as fh:
                response = fh.read()
    if isinstance(response, (bytes, bytearray)) and metadata is not None:
        name = metadata.get("name") if isinstance(metadata, dict) else metadata
        if isinstance(name, bytes):
            name = name.decode("utf-8", "replace")
        return "FILE name=%s size=%d sha256=%s" % (name, len(response), hashlib.sha256(response).hexdigest())
    if isinstance(response, (bytes, bytearray)):
        return response.decode("utf-8", "replace")
    if isinstance(response, (list, tuple)):
        parts = []
        for p in response:
            if isinstance(p, (bytes, bytearray)):
                p = p.decode("utf-8", "replace")
            parts.append(repr(p))
        return "LIST " + " | ".join(parts)
    return "OTHER " + repr(response)


NORMALISERS = [
    (re.compile(r"Generated in [^`\n]*"), "Generated in T"),
    (re.compile(r"Served by rngit [^`\n]*`"), "Served by rngit V`"),
    (re.compile(r"rns://[0-9a-f]{32}/"), "rns://DEST/"),
    (re.compile(r"(\d+ (minute|hour|day|week|month|year)s? ago|just now)"), "AGO"),
]


def normalise(text, name=""):
    if "_stats" in name and ">>Stats for" in text:
        # the reference shares the counters of every repository until it reloads
        # its stats file (STATS_INIT_REPO is stored, not copied), so only the shape
        head = text.split("over the last")[0]
        return re.sub(r"\d+", "N", head)
    for pattern, repl in NORMALISERS:
        text = pattern.sub(repl, text)
    return text


def compare(a_dir, b_dir):
    names = sorted(set(os.listdir(a_dir)) | set(os.listdir(b_dir)))
    bad = 0
    for name in names:
        pa, pb = os.path.join(a_dir, name), os.path.join(b_dir, name)
        if not (os.path.exists(pa) and os.path.exists(pb)):
            print("only in one output:", name)
            bad += 1
            continue
        ta = normalise(open(pa, encoding="utf-8").read(), name)
        tb = normalise(open(pb, encoding="utf-8").read(), name)
        if ta != tb:
            bad += 1
            print("=== DIFFERENT:", name)
            for line in difflib.unified_diff(tb.splitlines(), ta.splitlines(), "reference", "c", lineterm="", n=2):
                print(line)
    print("%d of %d answers differ" % (bad, len(names)))
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1] == "fetch":
        # fetch RNS_CONFIG IDENTITY_FILE|- DEST_HEX OUT_DIR HASHES_FILE [SET]
        load_hashes(sys.argv[6])
        sys.exit(fetch(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[7] if len(sys.argv) > 7 else "all"))
    elif sys.argv[1] == "compare":
        sys.exit(compare(sys.argv[2], sys.argv[3]))
