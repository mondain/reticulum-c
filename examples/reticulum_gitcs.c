/* reticulum-c-git-cs: sign and verify git commits and tags with a Reticulum
 * identity, compatible with the reference rngcs (RNS/Utilities/rngit/
 * commitsigs.py).
 *
 * It replaces ssh-keygen as git's gpg.ssh.program and understands the same
 * calls:
 *
 *   reticulum-c-git-cs -Y sign -n git -f IDENTITY_FILE [FILE]
 *   reticulum-c-git-cs -Y verify -n git -f SIGNERS -I PRINCIPAL -s SIGFILE
 *   reticulum-c-git-cs -Y check-novalidate -n git -s SIGFILE
 *   reticulum-c-git-cs -Y find-principals -f SIGNERS -s SIGFILE
 *
 *   git -c gpg.format=ssh -c gpg.ssh.program=reticulum-c-git-cs \
 *       -c user.signingkey=IDENTITY_FILE commit -S
 *
 * The signature is an SSHSIG blob (namespace "git", an ssh-ed25519 public key
 * built from the identity's signing key) whose signature field carries an RSG
 * envelope: a 64 byte Ed25519 signature followed by the MessagePack map
 * {hashtype:"sha256", hash:SHA-256(payload), meta:{signer, pubkey}} it signs.
 * The signer is the identity hash and has to be the commit author's e-mail
 * address (the tagger's for a tag). The allowed signers file, -n and the -O
 * options are accepted and ignored, as the reference does. */
#define _POSIX_C_SOURCE 200809L
#include "msgpack_tree.h"
#include <limits.h>
#include <openssl/rand.h>
#include <reticulum_c/rnc_host.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define SIG_LEN 64u
#define NAMESPACE_GIT "git"
#define HASH_ALGORITHM "sha256"
#define MAGIC "SSHSIG"

static rnc_result secure_random(void *context, uint8_t *out, size_t size) {
  (void)context;
  return size <= INT_MAX && RAND_priv_bytes(out, (int)size) == 1 ? RNC_OK
                                                                 : RNC_CRYPTO;
}

/* ---- growable byte buffer ----------------------------------------------- */
typedef struct buf {
  uint8_t *p;
  size_t n, cap;
  int failed;
} buf;
static void buf_put(buf *b, const void *data, size_t n) {
  if (b->failed)
    return;
  if (n > SIZE_MAX / 2 - b->n) {
    b->failed = 1;
    return;
  }
  if (b->n + n > b->cap) {
    size_t cap = b->cap ? b->cap : 256;
    uint8_t *p;
    while (cap < b->n + n)
      cap *= 2;
    p = realloc(b->p, cap);
    if (!p) {
      b->failed = 1;
      return;
    }
    b->p = p;
    b->cap = cap;
  }
  if (n)
    memcpy(b->p + b->n, data, n);
  b->n += n;
}
static void buf_byte(buf *b, uint8_t v) { buf_put(b, &v, 1); }
static void buf_u32(buf *b, uint32_t v) {
  uint8_t t[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8),
                  (uint8_t)v};
  buf_put(b, t, 4);
}
static void buf_ssh_string(buf *b, const void *data, size_t n) {
  if (n > UINT32_MAX) {
    b->failed = 1;
    return;
  }
  buf_u32(b, (uint32_t)n);
  buf_put(b, data, n);
}

/* ---- MessagePack emitter (just what the envelope needs) ------------------ */
static void mp_map(buf *b, unsigned pairs) { buf_byte(b, (uint8_t)(0x80 | pairs)); }
static void mp_str(buf *b, const char *s) {
  size_t n = strlen(s);
  buf_byte(b, (uint8_t)(0xa0 | n)); /* every string used here is < 32 bytes */
  buf_put(b, s, n);
}
static void mp_bin(buf *b, const void *data, size_t n) {
  buf_byte(b, 0xc4);
  buf_byte(b, (uint8_t)n); /* every blob used here is < 256 bytes */
  buf_put(b, data, n);
}

/* ---- input -------------------------------------------------------------- */
static int read_stream(FILE *f, buf *out) {
  uint8_t chunk[4096];
  size_t got;
  while ((got = fread(chunk, 1, sizeof(chunk), f)) > 0)
    buf_put(out, chunk, got);
  return !ferror(f) && !out->failed;
}
static int read_path(const char *path, buf *out) {
  FILE *f = fopen(path, "rb");
  int ok;
  if (!f)
    return 0;
  ok = read_stream(f, out);
  fclose(f);
  return ok;
}
static int is_file(const char *path) {
  struct stat st;
  return path && stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* ---- base64 ------------------------------------------------------------- */
static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void base64_armor(buf *out, const uint8_t *data, size_t n) {
  buf enc = {0};
  size_t i, col = 0;
  for (i = 0; i < n; i += 3) {
    uint32_t v = (uint32_t)data[i] << 16;
    size_t left = n - i;
    if (left > 1)
      v |= (uint32_t)data[i + 1] << 8;
    if (left > 2)
      v |= data[i + 2];
    buf_byte(&enc, (uint8_t)B64[v >> 18 & 63]);
    buf_byte(&enc, (uint8_t)B64[v >> 12 & 63]);
    buf_byte(&enc, left > 1 ? (uint8_t)B64[v >> 6 & 63] : '=');
    buf_byte(&enc, left > 2 ? (uint8_t)B64[v & 63] : '=');
  }
  buf_put(out, "-----BEGIN SSH SIGNATURE-----\n", 30);
  for (i = 0; i < enc.n; i += 70) {
    col = enc.n - i < 70 ? enc.n - i : 70;
    buf_put(out, enc.p + i, col);
    buf_byte(out, '\n');
  }
  buf_put(out, "-----END SSH SIGNATURE-----\n", 28);
  free(enc.p);
}
/* Python's b64decode: characters outside the alphabet are dropped, the
 * quantum must be complete. */
static int base64_decode(const char *text, size_t n, buf *out) {
  uint32_t acc = 0;
  size_t i, chars = 0, pad = 0, quad = 0;
  for (i = 0; i < n; ++i) {
    const char *at;
    if (text[i] == '=') {
      ++pad;
      continue;
    }
    at = text[i] ? strchr(B64, text[i]) : NULL;
    if (!at)
      continue;
    if (pad)
      continue; /* data after padding is ignored by Python */
    acc = acc << 6 | (uint32_t)(at - B64);
    ++chars;
    if (++quad == 4) {
      buf_byte(out, (uint8_t)(acc >> 16));
      buf_byte(out, (uint8_t)(acc >> 8));
      buf_byte(out, (uint8_t)acc);
      quad = 0;
      acc = 0;
    }
  }
  if ((chars + pad) % 4 != 0)
    return 0;
  if (quad == 1)
    return 0;
  if (quad == 2)
    buf_byte(out, (uint8_t)(acc >> 4));
  else if (quad == 3) {
    buf_byte(out, (uint8_t)(acc >> 10));
    buf_byte(out, (uint8_t)(acc >> 2));
  }
  return !out->failed;
}

/* ---- SSHSIG -------------------------------------------------------------- */
typedef struct sshsig {
  const uint8_t *public_key, *namespace_, *reserved, *hash_algorithm, *rsg;
  size_t public_key_len, namespace_len, reserved_len, hash_algorithm_len,
      rsg_len;
} sshsig;
static int read_ssh_string(const uint8_t *d, size_t n, size_t *off,
                           const uint8_t **out, size_t *len) {
  uint32_t l;
  if (n - *off < 4)
    return 0;
  l = (uint32_t)d[*off] << 24 | (uint32_t)d[*off + 1] << 16 |
      (uint32_t)d[*off + 2] << 8 | d[*off + 3];
  if (n - *off - 4 < l)
    return 0;
  *out = d + *off + 4;
  *len = l;
  *off += 4 + (size_t)l;
  return 1;
}
static int parse_sshsig(const uint8_t *d, size_t n, sshsig *s) {
  size_t off = 6;
  if (n < 6 || memcmp(d, MAGIC, 6))
    return 0;
  if (n - off < 4 || d[off] || d[off + 1] || d[off + 2] || d[off + 3] != 1)
    return 0;
  off += 4;
  return read_ssh_string(d, n, &off, &s->public_key, &s->public_key_len) &&
         read_ssh_string(d, n, &off, &s->namespace_, &s->namespace_len) &&
         read_ssh_string(d, n, &off, &s->reserved, &s->reserved_len) &&
         read_ssh_string(d, n, &off, &s->hash_algorithm,
                         &s->hash_algorithm_len) &&
         read_ssh_string(d, n, &off, &s->rsg, &s->rsg_len);
}
static int contains(const char *line, size_t len, const char *needle) {
  size_t n = strlen(needle), i;
  for (i = 0; i + n <= len; ++i)
    if (!memcmp(line + i, needle, n))
      return 1;
  return 0;
}
/* Reads and parses a signature file; raw owns the bytes s points into. */
static int load_sshsig(const char *path, buf *raw, sshsig *s) {
  buf file = {0}, bytes = {0};
  size_t pos = 0;
  int in_sig = 0, ok = 0;
  memset(s, 0, sizeof(*s));
  if (!read_path(path, &file))
    goto done;
  while (pos < file.n) {
    size_t end = pos;
    const char *line;
    size_t len;
    while (end < file.n && file.p[end] != '\n')
      ++end;
    line = (const char *)file.p + pos;
    len = end - pos;
    pos = end < file.n ? end + 1 : end;
    {
      size_t a = 0, b = len;
      while (a < b && (line[a] == ' ' || line[a] == '\t' || line[a] == '\r'))
        ++a;
      while (b > a && (line[b - 1] == ' ' || line[b - 1] == '\t' ||
                       line[b - 1] == '\r'))
        --b;
      line += a;
      len = b - a;
    }
    if (contains(line, len, "BEGIN SSH SIGNATURE")) {
      in_sig = 1;
      continue;
    }
    if (contains(line, len, "END SSH SIGNATURE"))
      break;
    if (in_sig)
      buf_put(&bytes, line, len);
  }
  if (!bytes.n || bytes.failed)
    goto done;
  if (!base64_decode((const char *)bytes.p, bytes.n, raw))
    goto done;
  ok = parse_sshsig(raw->p, raw->n, s);
done:
  free(file.p);
  free(bytes.p);
  return ok;
}

/* ---- RSG envelope -------------------------------------------------------- */
typedef struct envelope {
  val pool[32];
  val root;
  reader r;
  const uint8_t *body; /* the signed bytes */
  size_t body_len;
} envelope;
/* An envelope is msgpack after the 64 byte signature, and nothing may follow
 * the value. */
static int envelope_parse(envelope *e, const uint8_t *rsg, size_t n) {
  if (n < SIG_LEN + 1)
    return 0;
  e->body = rsg + SIG_LEN;
  e->body_len = n - SIG_LEN;
  e->r.p = e->body;
  e->r.end = e->body + e->body_len;
  e->r.pool = e->pool;
  e->r.used = 0;
  e->r.cap = sizeof(e->pool) / sizeof(e->pool[0]);
  return parse(&e->r, &e->root, 0) && e->r.p == e->r.end;
}
static int truthy(const val *v) {
  switch (v->type) {
  case V_NIL:
    return 0;
  case V_BOOL:
  case V_UINT:
    return v->u != 0;
  case V_INT:
    return v->i != 0;
  case V_REAL:
    return v->d != 0;
  default:
    return v->n != 0;
  }
}
static void hex_out(char *out, const uint8_t *d, size_t n) {
  size_t i;
  for (i = 0; i < n; ++i)
    sprintf(out + 2 * i, "%02x", d[i]);
}

/* ---- commit headers ------------------------------------------------------ */
static int utf8_ok(const uint8_t *s, size_t n) {
  size_t i = 0;
  while (i < n) {
    uint8_t c = s[i];
    size_t extra = c < 0x80 ? 0 : (c >= 0xc2 && c < 0xe0) ? 1
                                  : (c >= 0xe0 && c < 0xf0) ? 2
                                  : (c >= 0xf0 && c < 0xf5) ? 3
                                                            : 99;
    size_t k;
    uint32_t cp;
    if (extra == 99 || n - i <= extra)
      return extra == 0;
    cp = extra == 0 ? c : extra == 1 ? c & 0x1fu : extra == 2 ? c & 0x0fu : c & 7u;
    for (k = 1; k <= extra; ++k) {
      if ((s[i + k] & 0xc0) != 0x80)
        return 0;
      cp = cp << 6 | (s[i + k] & 0x3fu);
    }
    if ((extra == 2 && (cp < 0x800 || (cp >= 0xd800 && cp < 0xe000))) ||
        (extra == 3 && (cp < 0x10000 || cp > 0x10ffff)))
      return 0;
    i += extra + 1;
  }
  return 1;
}
typedef struct header_value {
  const uint8_t *p; /* NULL when absent */
  size_t n;
  int bad_utf8;
} header_value;
/* The header lines of a commit or tag object, up to the first empty line. The
 * reference's rule: "<prefix>... <ADDRESS> ..." with the address between the
 * first "<" and the first ">", which has to sit after the prefix and not end
 * the line. A tag is told by a line starting "tag " before the tagger. */
static void scan_headers(const uint8_t *m, size_t n, header_value *author,
                         header_value *committer, header_value *tagger,
                         int *is_tag) {
  size_t pos = 0;
  memset(author, 0, sizeof(*author));
  memset(committer, 0, sizeof(*committer));
  memset(tagger, 0, sizeof(*tagger));
  *is_tag = 0;
  while (pos < n) {
    size_t end = pos, next, len, s, e, k;
    const uint8_t *line = m + pos;
    while (end < n && m[end] != '\n' && m[end] != '\r')
      ++end;
    len = end - pos;
    next = end;
    if (next < n)
      next += m[next] == '\r' && next + 1 < n && m[next + 1] == '\n' ? 2 : 1;
    pos = next;
    if (len == 0)
      break;
    {
      struct {
        const char *prefix;
        header_value *slot;
        int needs_tag;
      } kinds[3] = {{"author ", author, 0},
                    {"committer ", committer, 0},
                    {"tagger ", tagger, 1}};
      if (len >= 4 && !memcmp(line, "tag ", 4))
        *is_tag = 1;
      for (k = 0; k < 3; ++k) {
        size_t pl = strlen(kinds[k].prefix);
        if (kinds[k].slot->p || len < pl || memcmp(line, kinds[k].prefix, pl))
          continue;
        if (kinds[k].needs_tag && !*is_tag)
          continue;
        for (s = 0; s < len && line[s] != '<'; ++s)
          ;
        for (e = 0; e < len && line[e] != '>'; ++e)
          ;
        if (s < len && s > pl && e < len && e > s && e < len - 1) {
          kinds[k].slot->p = line + s + 1;
          kinds[k].slot->n = e - s - 1;
          kinds[k].slot->bad_utf8 = !utf8_ok(kinds[k].slot->p, kinds[k].slot->n);
        }
      }
    }
  }
}

/* ---- command line -------------------------------------------------------- */
typedef struct options {
  const char *op, *keyfile, *principal, *sigfile, *file;
} options;

static int load_identity(const char *path, rnc_identity *id) {
  if (!path || !is_file(path)) {
    fprintf(stderr, "Identity file not found: %s\n", path ? path : "None");
    return 0;
  }
  if (rnc_host_identity_load(path, secure_random, NULL, id) != RNC_OK ||
      !id->has_private) {
    fprintf(stderr,
            "Error: Could not load identity or identity has no private key\n");
    return 0;
  }
  return 1;
}

static int do_sign(const options *o) {
  rnc_identity id;
  buf message = {0}, envelope = {0}, rsg = {0}, wire = {0}, blob = {0},
      armored = {0};
  uint8_t digest[32], signature[SIG_LEN];
  int rc = 1;
  if (!load_identity(o->keyfile, &id))
    return 1;
  if (o->file && is_file(o->file)) {
    if (!read_path(o->file, &message)) {
      fprintf(stderr, "Error reading %s\n", o->file);
      goto done;
    }
  } else if (!read_stream(stdin, &message)) {
    fprintf(stderr, "Error reading input\n");
    goto done;
  }
  if (rnc_hash(message.p, message.n, digest) != RNC_OK) {
    fprintf(stderr, "Error creating signature: hash failed\n");
    goto done;
  }
  mp_map(&envelope, 3);
  mp_str(&envelope, "hashtype");
  mp_str(&envelope, "sha256");
  mp_str(&envelope, "hash");
  mp_bin(&envelope, digest, sizeof(digest));
  mp_str(&envelope, "meta");
  mp_map(&envelope, 2);
  mp_str(&envelope, "signer");
  mp_bin(&envelope, id.hash, sizeof(id.hash));
  mp_str(&envelope, "pubkey");
  mp_bin(&envelope, id.public_key, sizeof(id.public_key));
  if (envelope.failed ||
      rnc_identity_sign(&id, envelope.p, envelope.n, signature) != RNC_OK) {
    fprintf(stderr, "Error creating signature\n");
    goto done;
  }
  buf_put(&rsg, signature, sizeof(signature));
  buf_put(&rsg, envelope.p, envelope.n);
  /* ssh-ed25519 wire format of the identity's signing key */
  buf_ssh_string(&wire, "ssh-ed25519", 11);
  buf_ssh_string(&wire, id.public_key + 32, 32);
  buf_put(&blob, MAGIC, 6);
  buf_u32(&blob, 1);
  buf_ssh_string(&blob, wire.p, wire.n);
  buf_ssh_string(&blob, NAMESPACE_GIT, 3);
  buf_ssh_string(&blob, "", 0);
  buf_ssh_string(&blob, HASH_ALGORITHM, 6);
  buf_ssh_string(&blob, rsg.p, rsg.n);
  if (blob.failed || rsg.failed || wire.failed) {
    fprintf(stderr, "Error creating SSH signature\n");
    goto done;
  }
  base64_armor(&armored, blob.p, blob.n);
  if (armored.failed) {
    fprintf(stderr, "Error armoring signature\n");
    goto done;
  }
  if (o->file && is_file(o->file)) {
    size_t len = strlen(o->file);
    char *path = malloc(len + 5);
    FILE *f;
    if (!path)
      goto done;
    memcpy(path, o->file, len);
    memcpy(path + len, ".sig", 5);
    f = fopen(path, "w");
    if (!f || fwrite(armored.p, 1, armored.n, f) != armored.n ||
        fclose(f) != 0) {
      fprintf(stderr, "Error writing signature file: %s\n", path);
      free(path);
      goto done;
    }
    free(path);
  } else if (fwrite(armored.p, 1, armored.n, stdout) != armored.n ||
             fflush(stdout) != 0)
    goto done;
  rc = 0;
done:
  rnc_identity_clear(&id);
  free(message.p);
  free(envelope.p);
  free(rsg.p);
  free(wire.p);
  free(blob.p);
  free(armored.p);
  return rc;
}

static int do_find_principals(const options *o) {
  buf raw = {0};
  sshsig s;
  envelope e;
  const val *meta, *signer;
  char hex[2 * 255 + 1];
  int rc = 1;
  if (!o->sigfile || !is_file(o->sigfile)) {
    fprintf(stderr, "Error: Signature file not found\n");
    return 1;
  }
  if (!load_sshsig(o->sigfile, &raw, &s)) {
    fprintf(stderr, "Error parsing SSH signature\n");
    goto done;
  }
  if (s.namespace_len != 3 || memcmp(s.namespace_, NAMESPACE_GIT, 3)) {
    fprintf(stderr, "Error: Namespace mismatch\n");
    goto done;
  }
  meta = envelope_parse(&e, s.rsg, s.rsg_len) ? map_get(&e.root, "meta") : NULL;
  signer = map_get(meta, "signer");
  if (!signer || signer->type != V_BIN || signer->n > 255) {
    fprintf(stderr, "Could not determine signer identity\n");
    goto done;
  }
  hex_out(hex, signer->p, signer->n);
  printf("%s\n", hex);
  rc = 0;
done:
  free(raw.p);
  return rc;
}

static int do_check_novalidate(const options *o) {
  buf raw = {0};
  sshsig s;
  envelope e;
  int rc = 1;
  if (!o->sigfile || !is_file(o->sigfile))
    return 1;
  if (load_sshsig(o->sigfile, &raw, &s) && s.namespace_len == 3 &&
      !memcmp(s.namespace_, NAMESPACE_GIT, 3) &&
      envelope_parse(&e, s.rsg, s.rsg_len) && truthy(&e.root))
    rc = 0;
  free(raw.p);
  return rc;
}

static int do_verify(const options *o) {
  buf raw = {0}, message = {0};
  sshsig s;
  envelope e;
  header_value author, committer, tagger;
  int is_tag, rc = 1;
  const val *hashtype, *hash, *meta, *pubkey;
  rnc_identity signer;
  uint8_t digest[32];
  char signer_hex[33];
  if (!o->sigfile || !is_file(o->sigfile)) {
    fprintf(stderr, "Error: Signature file not found\n");
    return 1;
  }
  if (!read_stream(stdin, &message)) {
    fprintf(stderr, "Error reading input\n");
    goto done;
  }
  if (!load_sshsig(o->sigfile, &raw, &s)) {
    fprintf(stderr, "Error parsing signature\n");
    goto done;
  }
  scan_headers(message.p, message.n, &author, &committer, &tagger, &is_tag);
  /* the reference reports an undecodable header on standard output and carries
   * on with the number 1 in place of the address */
  if (author.p && author.bad_utf8)
    printf("Error while determining author from signed commit\n");
  if (committer.p && committer.bad_utf8)
    printf("Error while determining committer from signed commit\n");
  if (s.namespace_len != 3 || memcmp(s.namespace_, NAMESPACE_GIT, 3)) {
    fprintf(stderr, "Invalid commit signature namespace\n");
    goto done;
  }
  if (!message.n) {
    fprintf(stderr, "No message specified for rsg validation\n");
    goto done;
  }
  if (s.rsg_len == SIG_LEN) {
    fprintf(stderr, "Cannot validate legacy rsg format\n");
    goto done;
  }
  if (!envelope_parse(&e, s.rsg, s.rsg_len) || e.root.type != V_MAP) {
    fprintf(stderr, "Invalid signature\n");
    goto done;
  }
  hashtype = map_get(&e.root, "hashtype");
  hash = map_get(&e.root, "hash");
  meta = map_get(&e.root, "meta");
  pubkey = map_get(meta, "pubkey");
  if (!hashtype || !hash || !meta || meta->type != V_MAP ||
      !map_get(meta, "signer") || !pubkey || hashtype->type != V_STR ||
      hashtype->n != 6 || memcmp(hashtype->p, "sha256", 6) ||
      pubkey->type != V_BIN || pubkey->n != 64 ||
      rnc_identity_from_public(&signer, pubkey->p) != RNC_OK ||
      rnc_hash(message.p, message.n, digest) != RNC_OK ||
      hash->type != V_BIN || hash->n != 32 || memcmp(hash->p, digest, 32) ||
      rnc_identity_verify(&signer, e.body, e.body_len, s.rsg) != RNC_OK) {
    fprintf(stderr, "Invalid signature\n");
    goto done;
  }
  hex_out(signer_hex, signer.hash, sizeof(signer.hash));
  {
    const header_value *who = is_tag ? &tagger : &author;
    int ok = who->p && !who->bad_utf8 && who->n == 32 &&
             !memcmp(who->p, signer_hex, 32);
    if (!ok) {
      printf("Commit not signed by author <%.*s>\n",
             who->p ? (who->bad_utf8 ? 1 : (int)who->n) : 0,
             who->p ? (who->bad_utf8 ? "1" : (const char *)who->p) : "");
      goto done;
    }
  }
  if (o->principal && *o->principal && strcmp(o->principal, signer_hex)) {
    fprintf(stderr, "Principal mismatch\n");
    goto done;
  }
  printf("Good \"git\" signature for commit, signed with Reticulum Identity key "
         "<%s>\n",
         signer_hex);
  rc = 0;
done:
  free(raw.p);
  free(message.p);
  return rc;
}

static void usage(FILE *out) {
  fprintf(out,
          "usage: reticulum-c-git-cs [-h] -Y {sign,find-principals,"
          "check-novalidate,verify}\n"
          "                          [-n NAMESPACE] [-f KEYFILE] [-I PRINCIPAL] "
          "[-s SIGFILE]\n"
          "                          [-O SSH_OPTIONS] [file]\n");
}
static int arg_error(const char *message) {
  usage(stderr);
  fprintf(stderr, "reticulum-c-git-cs: error: %s\n", message);
  return 2;
}

int main(int argc, char **argv) {
  options o;
  int i, only_positional = 0, unknown = 0;
  const char *bad = NULL;
  memset(&o, 0, sizeof(o));
  for (i = 1; i < argc; ++i) {
    const char *a = argv[i];
    const char **slot = NULL;
    if (only_positional || a[0] != '-' || !a[1]) {
      if (o.file) {
        if (!unknown++)
          bad = a;
      } else
        o.file = a;
      continue;
    }
    if (!strcmp(a, "--")) {
      only_positional = 1;
      continue;
    }
    if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
      usage(stdout);
      return 0;
    }
    if (a[1] == 'Y' || a[1] == 'n' || a[1] == 'f' || a[1] == 'I' ||
        a[1] == 's' || a[1] == 'O') {
      static const char *ignored;
      const char *value;
      slot = a[1] == 'Y'   ? &o.op
             : a[1] == 'f' ? &o.keyfile
             : a[1] == 'I' ? &o.principal
             : a[1] == 's' ? &o.sigfile
                           : &ignored;
      if (a[2])
        value = a + 2;
      else if (i + 1 < argc && (argv[i + 1][0] != '-' || !argv[i + 1][1]))
        value = argv[++i];
      else {
        char msg[64];
        snprintf(msg, sizeof(msg), "argument -%c: expected one argument", a[1]);
        return arg_error(msg);
      }
      *slot = value;
      continue;
    }
    if (!unknown++)
      bad = a;
  }
  if (!o.op)
    return arg_error("the following arguments are required: -Y");
  if (strcmp(o.op, "sign") && strcmp(o.op, "find-principals") &&
      strcmp(o.op, "check-novalidate") && strcmp(o.op, "verify")) {
    char msg[192];
    snprintf(msg, sizeof(msg),
             "argument -Y: invalid choice: '%.40s' (choose from 'sign', "
             "'find-principals', 'check-novalidate', 'verify')",
             o.op);
    return arg_error(msg);
  }
  if (unknown) {
    fprintf(stderr, "Error: Unknown argument: %s\n", bad);
    return 1;
  }
  if (!strcmp(o.op, "sign"))
    return do_sign(&o);
  if (!strcmp(o.op, "find-principals"))
    return do_find_principals(&o);
  if (!strcmp(o.op, "check-novalidate"))
    return do_check_novalidate(&o);
  return do_verify(&o);
}
