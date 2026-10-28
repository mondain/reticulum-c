/* reticulum-c-git-admin: manage repositories on a repository node (the
 * reference's `rngit create`, `fork`, `mirror`, `sync`, `perms`, `release` and
 * `work` subcommands).
 *
 *   reticulum-c-git-admin [--connect HOST:PORT] [--config DIR] COMMAND ARGS
 *
 *   create  URL                      create a repository
 *   fork    SOURCE URL               fork SOURCE (any URL the node can fetch,
 *   mirror  SOURCE URL               including rns://) to URL; a mirror follows it
 *   sync    URL                      pull the upstream of a fork or mirror now
 *   gperms  URL get | set FILE|-     group permissions (URL is rns://DEST/GROUP)
 *   rperms  URL get | set FILE|-     repository permissions
 *   release URL list|view TAG|delete TAG|latest TAG [-y]
 *   release URL create TAG:DIR [-s IDENTITYFILE] [-n NAME] [-L] (-m TEXT | -F FILE)
 *   release URL fetch TAG:ARTIFACT|all [--signer HASH]       ("latest" is a tag)
 *   release MANIFEST.rsm verify|fetch [--signer HASH]        (offline or by origin)
 *   work    URL list [--scope active|completed|proposed|all]
 *   work    URL view|delete|complete|activate -d ID [--scope S]
 *   work    URL create|propose -t TITLE (-m TEXT | -F FILE | -)
 *   work    URL edit -d ID [-t TITLE] (-m TEXT | -F FILE | -)
 *   work    URL update -d ID (-m TEXT | -F FILE | -)      add a comment
 *   work    URL perms -d ID get | set FILE|-
 *
 * Where the reference opens $EDITOR, text comes from -m, -F or standard input.
 * The identity is CONFIG/client_identity (RNGIT_CONFIG or ~/.rngit), the one
 * git-remote-rns uses; work documents and release manifests are signed with it
 * (releases with -s instead, if given). Permission texts are lines such as
 * `r:HASH`, `w:all`, `rel:none`, `adm:HASH`. */
#include "rngit_common.h"
#include <dirent.h>
#include <fnmatch.h>
#include <openssl/evp.h>
#include <strings.h>

#define PATH_TIMEOUT_MS 15000u

/* A short-lived tool: allocations are handed back by the operating system at
 * exit. Keeping them reachable from a static table stops leak checkers from
 * reporting the error paths that return without freeing. */
static void *kept[4096];
static size_t kept_next;
static void *keep(void *p) {
  kept[kept_next++ % (sizeof(kept) / sizeof(kept[0]))] = p;
  return p;
}
#define malloc(n) keep(malloc(n))
#define calloc(n, m) keep(calloc(n, m))

static rngit_client *C;
static char config_dir[PATH_MAX];
static char opt_text[65536];
static int opt_text_set, opt_yes, opt_local, opt_offline;
static const char *opt_file, *opt_title, *opt_scope = "active", *opt_signer, *opt_identity, *opt_name;
static long opt_doc = -1;

static char *trim(char *s) {
  char *e;
  while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
    ++s;
  e = s + strlen(s);
  while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n'))
    *--e = 0;
  return s;
}
static int ini_get(const char *path, const char *section, const char *key, char *out, size_t cap) {
  FILE *f = fopen(path, "r");
  char line[1024], current[64] = "";
  int found = 0;
  if (!f)
    return 0;
  while (!found && fgets(line, sizeof(line), f)) {
    char *t = trim(line), *eq;
    if (*t == '#' || !*t)
      continue;
    if (*t == '[') {
      char *end = strchr(t, ']');
      if (end) {
        *end = 0;
        snprintf(current, sizeof(current), "%s", t + 1);
      }
      continue;
    }
    eq = strchr(t, '=');
    if (!eq)
      continue;
    *eq = 0;
    if (!strcmp(current, section) && !strcmp(trim(t), key)) {
      snprintf(out, cap, "%s", trim(eq + 1));
      found = 1;
    }
  }
  fclose(f);
  return found;
}
static int is_dir_path(const char *p) {
  struct stat st;
  return !stat(p, &st) && S_ISDIR(st.st_mode);
}
static int is_file_path(const char *p) {
  struct stat st;
  return !stat(p, &st) && S_ISREG(st.st_mode);
}
static int fail(const char *message) {
  fprintf(stderr, "reticulum-c-git-admin: %s\n", message);
  return 1;
}
static void fatal(const char *message) {
  fail(message);
  exit(1);
}

/* ---- a URL: rns://DESTINATION/GROUP[/REPOSITORY] ------------------------- */
typedef struct url {
  uint8_t destination[16];
  char hex[33], rest[600];
  int components; /* 1 = group, 2 = group/repository */
} url;
static int parse_url(const char *text, url *u) {
  const char *hash = text + 6, *slash;
  char target[300], value[300], path[PATH_MAX + 32];
  size_t n;
  if (strncasecmp(text, "rns://", 6))
    return 0;
  slash = strchr(hash, '/');
  if (!slash || !slash[1])
    return 0;
  n = (size_t)(slash - hash);
  if (n >= sizeof(target))
    return 0;
  memcpy(target, hash, n);
  target[n] = 0;
  snprintf(path, sizeof(path), "%s/client_config", config_dir);
  if (!rngit_hex_decode(target, u->destination, 16)) {
    if (!ini_get(path, "aliases", target, value, sizeof(value)) ||
        !rngit_hex_decode(value, u->destination, 16))
      return 0;
  }
  {
    size_t i;
    for (i = 0; i < 16; ++i)
      snprintf(u->hex + 2 * i, 3, "%02x", u->destination[i]);
  }
  snprintf(u->rest, sizeof(u->rest), "%s", slash + 1);
  while (strlen(u->rest) && u->rest[strlen(u->rest) - 1] == '/')
    u->rest[strlen(u->rest) - 1] = 0;
  u->components = strchr(u->rest, '/') ? 2 : 1;
  return 1;
}
/* the URL with the destination spelled as hex, as the reference sends it */
static void resolved(const url *u, char *out, size_t cap) {
  snprintf(out, cap, "rns://%s/%s", u->hex, u->rest);
}

/* ---- connection and requests --------------------------------------------- */
static void connect_node(const url *u, const char *connect_arg) {
  char path[PATH_MAX + 32], connect[300];
  const char *env;
  struct stat st;
  C = calloc(1, sizeof(*C));
  if (!C)
    fatal("out of memory");
  C->max_value = 15u << 20;
  memcpy(C->destination, u->destination, 16);
  snprintf(path, sizeof(path), "%s/client_config", config_dir);
  if (connect_arg)
    snprintf(connect, sizeof(connect), "%s", connect_arg);
  else if ((env = getenv("RNGIT_CONNECT")) && *env)
    snprintf(connect, sizeof(connect), "%s", env);
  else if (!ini_get(path, "client", "connect", connect, sizeof(connect)))
    fatal("no node to attach to; use --connect HOST:PORT, RNGIT_CONNECT or connect in client_config");
  if (stat(config_dir, &st) && mkdir(config_dir, 0700) && errno != EEXIST)
    fatal("cannot create the configuration directory");
  snprintf(path, sizeof(path), "%s/client_identity", config_dir);
  if (!rngit_open_node(&C->net, connect, path, "rngit admin link"))
    exit(1);
  C->net.requester = rnc_requester_new(C->net.node, C->max_value, rngit_random, NULL);
  if (!C->net.requester)
    fatal("Could not set up the request client");
  if (rnc_host_await_path(C->net.host, C->destination, PATH_TIMEOUT_MS, NULL, NULL) != RNC_OK)
    fatal("Could not resolve path to the repository node");
}
static int send(const char *path, const uint8_t *body, size_t n, unsigned seconds, rngit_response *r) {
  if (!rngit_request(C, path, body, n, (uint64_t)seconds * 1000u, r)) {
    fail("No response from remote");
    return 0;
  }
  return 1;
}
/* a plain status reply: 1 when it is a success */
static int status_ok(const rngit_response *r, const char *prefix) {
  const uint8_t *text;
  size_t n;
  int status = rngit_plain(r, &text, &n);
  if (status == 0)
    return 1;
  if (status < 0)
    fail("No response from remote");
  else
    fprintf(stderr, "reticulum-c-git-admin: %s%.*s\n", prefix, (int)(n < 300 ? n : 300), (const char *)text);
  return 0;
}
/* the packed value after a status byte 0 */
static val dpool[8192];
static int reply_value(const rngit_response *r, val *v) {
  val pool[4];
  reader rd = {r->data, r->data + r->size, pool, 0, 4};
  val bin;
  reader in;
  if (!parse(&rd, &bin, 0) || bin.type != V_BIN || bin.n < 1 || bin.p[0] != 0)
    return 0;
  if (bin.n == 1)
    return 0;
  in = (reader){bin.p + 1, bin.p + bin.n, dpool, 0, 8192};
  return parse(&in, v, 0);
}
static void print_time(double t, const char *fmt, char *out, size_t cap) {
  time_t tt = (time_t)t;
  struct tm tm;
  if (t <= 0) {
    snprintf(out, cap, "unknown");
    return;
  }
  localtime_r(&tt, &tm);
  strftime(out, cap, fmt, &tm);
}
static const char *str_of(const val *v, char *buf, size_t cap) {
  if (!v || !val_is_text(v) || !val_copy(v, buf, cap))
    buf[0] = 0;
  return buf;
}

/* ---- text input ----------------------------------------------------------- */
static char *read_text(const char *file, size_t *n) {
  FILE *f;
  char *buf = malloc(262144);
  *n = 0;
  if (!buf)
    return NULL;
  if (opt_text_set) {
    *n = strlen(opt_text);
    memcpy(buf, opt_text, *n + 1);
    return buf;
  }
  f = !file || !strcmp(file, "-") ? stdin : fopen(file, "rb");
  if (!f) {
    free(buf);
    return NULL;
  }
  *n = fread(buf, 1, 262143, f);
  buf[*n] = 0;
  if (f != stdin)
    fclose(f);
  return buf;
}
static char *input_text(size_t *n) {
  char *t = read_text(opt_file, n);
  if (!t)
    fatal("Could not read the text");
  return t;
}

/* ---- the node side of simple commands -------------------------------------- */
static int cmd_create(const url *u) {
  uint8_t buf[1024];
  mp_out o = {buf, sizeof(buf), 0, 0};
  rngit_response r;
  int rc = 1;
  mp_map(&o, 1);
  mp_uint(&o, GIT_IDX_REPOSITORY);
  mp_cstr(&o, u->rest);
  if (o.failed || !send(GIT_PATH_CREATE, buf, o.n, 120, &r))
    return 1;
  if (status_ok(&r, "")) {
    printf("Repository %s created\n", u->rest);
    rc = 0;
  }
  free(r.data);
  return rc;
}
static int cmd_clone(const url *target, const char *source, const char *kind) {
  uint8_t buf[2048];
  mp_out o = {buf, sizeof(buf), 0, 0};
  rngit_response r;
  char resolved_source[700];
  int rc = 1;
  url s;
  if (!strncasecmp(source, "rns://", 6)) {
    if (!parse_url(source, &s) || s.components != 2)
      return fail("Invalid source URL");
    resolved(&s, resolved_source, sizeof(resolved_source));
    source = resolved_source;
  }
  mp_map(&o, 2);
  mp_uint(&o, GIT_IDX_REPOSITORY);
  mp_cstr(&o, target->rest);
  mp_cstr(&o, "source");
  mp_cstr(&o, source);
  printf("Remote is %sing repository to %s...\n", kind, target->rest);
  fflush(stdout);
  if (o.failed || !send(strcmp(kind, "fork") ? GIT_PATH_MIRROR : GIT_PATH_FORK, buf, o.n, 7200, &r))
    return 1;
  if (status_ok(&r, "")) {
    printf("Repository %sed to %s\n", kind, target->rest);
    rc = 0;
  }
  free(r.data);
  return rc;
}
static int cmd_sync(const url *u) {
  uint8_t buf[1024];
  mp_out o = {buf, sizeof(buf), 0, 0};
  rngit_response r;
  int rc = 1;
  mp_map(&o, 1);
  mp_uint(&o, GIT_IDX_REPOSITORY);
  mp_cstr(&o, u->rest);
  puts("Remote is syncing repository...");
  fflush(stdout);
  if (o.failed || !send(GIT_PATH_SYNC, buf, o.n, 7200, &r))
    return 1;
  if (status_ok(&r, "")) {
    puts("Repository synced");
    rc = 0;
  }
  free(r.data);
  return rc;
}
static int cmd_perms(const url *u, const char *kind, const char *step, const char *file) {
  uint8_t *buf = malloc(1 << 17);
  mp_out o = {buf, 1 << 17, 0, 0};
  rngit_response r;
  int is_group = kind[0] == 'g', rc = 1;
  char *content = NULL;
  size_t content_n = 0;
  if (!buf)
    return fail("out of memory");
  if (!strcmp(step, "set") && !(content = read_text(file, &content_n)))
    return fail("Could not read the permission file");
  mp_map(&o, content ? 4 : 3);
  mp_uint(&o, is_group ? GIT_IDX_GROUP : GIT_IDX_REPOSITORY);
  mp_cstr(&o, u->rest);
  mp_cstr(&o, "operation");
  mp_cstr(&o, kind);
  mp_cstr(&o, "step");
  mp_cstr(&o, step);
  if (content) {
    mp_cstr(&o, "content");
    mp_str(&o, content, content_n);
  }
  free(content);
  if (o.failed || !send(GIT_PATH_PERMS, buf, o.n, 120, &r)) {
    free(buf);
    return 1;
  }
  if (status_ok(&r, "Remote error: ")) {
    if (!strcmp(step, "get")) {
      val v;
      const val *text;
      if (reply_value(&r, &v) && (text = map_get(&v, "content")) && val_is_text(text))
        fwrite(text->p, 1, text->n, stdout);
    } else
      printf("Permissions updated for %s\n", u->rest);
    rc = 0;
  }
  free(r.data);
  free(buf);
  return rc;
}

/* ---- RSG: a signature and a MessagePack envelope --------------------------- */
static int sha256_bytes(const void *data, size_t n, uint8_t out[32]) {
  EVP_MD_CTX *c = EVP_MD_CTX_new();
  unsigned len = 0;
  int ok = c && EVP_DigestInit_ex(c, EVP_sha256(), NULL) && EVP_DigestUpdate(c, data, n) &&
           EVP_DigestFinal_ex(c, out, &len) && len == 32;
  EVP_MD_CTX_free(c);
  return ok;
}
static int sha256_file(const char *path, uint8_t out[32]) {
  FILE *f = fopen(path, "rb");
  EVP_MD_CTX *c = EVP_MD_CTX_new();
  unsigned len = 0;
  unsigned char buf[65536];
  size_t n;
  int ok = f && c && EVP_DigestInit_ex(c, EVP_sha256(), NULL);
  while (ok && (n = fread(buf, 1, sizeof(buf), f)) > 0)
    ok = EVP_DigestUpdate(c, buf, n);
  ok = ok && ferror(f) == 0 && EVP_DigestFinal_ex(c, out, &len) && len == 32;
  if (f)
    fclose(f);
  EVP_MD_CTX_free(c);
  return ok;
}
/* extra: pre-encoded meta entries (count pairs); message: embedded or NULL */
static size_t rsg_create(const rnc_identity *signer, const uint8_t hash[32], const uint8_t *message,
                         size_t message_n, const uint8_t *extra, size_t extra_n, size_t extra_pairs,
                         uint8_t *out, size_t cap) {
  uint8_t *env = malloc(cap);
  mp_out e;
  uint8_t sig[64];
  size_t n;
  if (!env)
    return 0;
  e = (mp_out){env, cap, 0, 0};
  mp_map(&e, message ? 4 : 3);
  mp_cstr(&e, "hashtype"); mp_cstr(&e, "sha256");
  mp_cstr(&e, "hash"); mp_bin(&e, hash, 32);
  mp_cstr(&e, "meta");
  if (2 + extra_pairs < 16)
    mp_map(&e, 2 + extra_pairs);
  else {
    uint8_t b[3] = {0xde, (uint8_t)((2 + extra_pairs) >> 8), (uint8_t)(2 + extra_pairs)};
    mp_put(&e, b, 3);
  }
  mp_cstr(&e, "signer"); mp_bin(&e, signer->hash, 16);
  mp_cstr(&e, "pubkey"); mp_bin(&e, signer->public_key, 64);
  mp_put(&e, extra, extra_n);
  if (message) {
    mp_cstr(&e, "message");
    mp_bin(&e, message, message_n);
  }
  if (e.failed || rnc_identity_sign(signer, env, e.n, sig) != RNC_OK || e.n + 64 > cap) {
    free(env);
    return 0;
  }
  memcpy(out, sig, 64);
  memcpy(out + 64, env, e.n);
  n = e.n + 64;
  free(env);
  return n;
}
typedef struct rsg_info {
  val pool[2048];
  val root;
  uint8_t signer[16];
} rsg_info;
/* validate_rsg: 1 when the signature, hash and (optional) required signer hold;
 * info receives the parsed envelope. */
static int rsg_validate(const uint8_t *rsg, size_t n, const uint8_t message_hash[32], const uint8_t *required,
                        rsg_info *info) {
  reader rd;
  const val *hashtype, *hash, *meta, *signer, *pubkey;
  rnc_identity who;
  if (n < 65)
    return 0;
  rd = (reader){rsg + 64, rsg + n, info->pool, 0, 2048};
  if (!parse(&rd, &info->root, 0) || info->root.type != V_MAP || rd.p != rd.end)
    return 0;
  hashtype = map_get(&info->root, "hashtype");
  hash = map_get(&info->root, "hash");
  meta = map_get(&info->root, "meta");
  if (!hashtype || !val_is_text(hashtype) || hashtype->n != 6 || memcmp(hashtype->p, "sha256", 6) || !hash ||
      hash->type != V_BIN || hash->n != 32 || !meta)
    return 0;
  signer = map_get(meta, "signer");
  pubkey = map_get(meta, "pubkey");
  if (!signer || !pubkey || pubkey->type != V_BIN || pubkey->n != 64 || signer->type != V_BIN || signer->n != 16)
    return 0;
  if (rnc_identity_from_public(&who, pubkey->p) != RNC_OK)
    return 0;
  memcpy(info->signer, who.hash, 16);
  if (required && memcmp(who.hash, required, 16))
    return 0;
  if (message_hash && memcmp(hash->p, message_hash, 32))
    return 0;
  return rnc_identity_verify(&who, rsg + 64, n - 64, rsg) == RNC_OK;
}
static void print_hash_pretty(const uint8_t *h) {
  size_t i;
  fputc('<', stdout);
  for (i = 0; i < 16; ++i)
    printf("%02x", h[i]);
  fputc('>', stdout);
}

/* ---- releases --------------------------------------------------------------- */
static int cmd_release_list(const url *u) {
  uint8_t buf[1024];
  mp_out o = {buf, sizeof(buf), 0, 0};
  rngit_response r;
  val v;
  int rc = 1;
  mp_map(&o, 2);
  mp_uint(&o, GIT_IDX_REPOSITORY); mp_cstr(&o, u->rest);
  mp_cstr(&o, "operation"); mp_cstr(&o, "list");
  if (!send(GIT_PATH_RELEASE, buf, o.n, 120, &r))
    return 1;
  if (!status_ok(&r, "Server error: "))
    goto done;
  if (!reply_value(&r, &v)) {
    puts("No releases for this repository");
    rc = 0;
    goto done;
  }
  {
    const val *rels = v.type == V_ARR ? &v : map_get(&v, "releases"), *latest = v.type == V_MAP ? map_get(&v, "latest") : NULL;
    size_t i;
    if (!rels || !rels->n) {
      puts("No releases for this repository");
      rc = 0;
      goto done;
    }
    printf("%-10s %-10s %-17s %-5s Notes\n", "Tag", "Status", "Created", "Objs");
    puts("--------------------------------------------------------------------------------");
    for (i = 0; i < rels->n; ++i) {
      const val *e = &rels->kids[i];
      char tag[64], status[32], created[32], preview[160], *nl;
      str_of(map_get(e, "tag"), tag, sizeof(tag));
      str_of(map_get(e, "status"), status, sizeof(status));
      str_of(map_get(e, "preview"), preview, sizeof(preview));
      if ((nl = strchr(preview, '\n')) != NULL)
        *nl = 0;
      preview[34] = 0;
      tag[10] = 0;
      status[9] = 0;
      print_time((double)as_uint(map_get(e, "created")), "%Y-%m-%d %H:%M", created, sizeof(created));
      printf("%-10s %-10s %-17s %-5llu %s\n", tag, status, created, (unsigned long long)as_uint(map_get(e, "artifacts")), preview);
    }
    if (latest && val_is_text(latest)) {
      char l[64];
      printf("\nThe latest release is: %s\n", str_of(latest, l, sizeof(l)));
    }
  }
  rc = 0;
done:
  free(r.data);
  return rc;
}
static int cmd_release_view(const url *u, const char *tag) {
  uint8_t buf[1024];
  mp_out o = {buf, sizeof(buf), 0, 0};
  rngit_response r;
  val v;
  int rc = 1;
  mp_map(&o, 3);
  mp_uint(&o, GIT_IDX_REPOSITORY); mp_cstr(&o, u->rest);
  mp_cstr(&o, "operation"); mp_cstr(&o, "view");
  mp_cstr(&o, "tag"); mp_cstr(&o, tag);
  if (!send(GIT_PATH_RELEASE, buf, o.n, 300, &r))
    return 1;
  if (status_ok(&r, "Remote error: ")) {
    if (!reply_value(&r, &v))
      fail("Empty response from remote");
    else {
      char s[256], created[40];
      char *notes = malloc(65536);
      const val *arts = map_get(&v, "artifacts");
      size_t i;
      printf("Release : %s\n", str_of(map_get(&v, "tag"), s, sizeof(s)));
      printf("Status  : %s\n", str_of(map_get(&v, "status"), s, sizeof(s)));
      print_time((double)as_uint(map_get(&v, "created")), "%Y-%m-%d %H:%M:%S", created, sizeof(created));
      printf("Created : %s\n", created);
      printf("Thanks  : %llu\n", (unsigned long long)as_uint(map_get(&v, "thanks")));
      if (notes && str_of(map_get(&v, "notes"), notes, 65536)[0])
        printf("\nRelease Notes\n=============\n\n%s\n", notes);
      free(notes);
      if (arts && arts->n) {
        char head[40];
        snprintf(head, sizeof(head), "Artifacts (%zu)", arts->n);
        printf("\n%s\n", head);
        for (i = 0; head[i]; ++i)
          putchar('=');
        putchar('\n');
        for (i = 0; i < arts->n; ++i)
          printf(" - %s (%llu B)\n", str_of(map_get(&arts->kids[i], "name"), s, sizeof(s)),
                 (unsigned long long)as_uint(map_get(&arts->kids[i], "size")));
      }
      putchar('\n');
      rc = 0;
    }
  }
  free(r.data);
  return rc;
}
static int confirm(const char *question) {
  char line[16];
  if (opt_yes)
    return 1;
  printf("%s [y/N]: ", question);
  fflush(stdout);
  return fgets(line, sizeof(line), stdin) && (line[0] == 'y' || line[0] == 'Y');
}
static int cmd_release_simple(const url *u, const char *op, const char *tag) {
  uint8_t buf[1024];
  mp_out o = {buf, sizeof(buf), 0, 0};
  rngit_response r;
  int rc = 1;
  char question[300];
  snprintf(question, sizeof(question), !strcmp(op, "delete") ? "Are you sure you want to delete release %s?"
                                                              : "Are you sure you want to set %s as the latest release?", tag);
  if (!confirm(question)) {
    puts(!strcmp(op, "delete") ? "Deletion cancelled" : "Update cancelled");
    return 0;
  }
  mp_map(&o, 3);
  mp_uint(&o, GIT_IDX_REPOSITORY); mp_cstr(&o, u->rest);
  mp_cstr(&o, "operation"); mp_cstr(&o, op);
  mp_cstr(&o, "tag"); mp_cstr(&o, tag);
  if (!send(GIT_PATH_RELEASE, buf, o.n, 120, &r))
    return 1;
  if (status_ok(&r, "Remote error: ")) {
    printf(!strcmp(op, "delete") ? "Release %s deleted\n" : "Release %s set as latest\n", tag);
    rc = 0;
  }
  free(r.data);
  return rc;
}
static int release_step(const url *u, const char *step, const char *tag, const uint8_t *extra, size_t extra_n,
                        size_t extra_pairs, unsigned seconds, const char *what) {
  uint8_t *buf = malloc(15u << 20);
  mp_out o;
  rngit_response r;
  int rc = 1;
  if (!buf)
    return fail("out of memory");
  o = (mp_out){buf, 15u << 20, 0, 0};
  mp_map(&o, 4 + extra_pairs);
  mp_uint(&o, GIT_IDX_REPOSITORY); mp_cstr(&o, u->rest);
  mp_cstr(&o, "operation"); mp_cstr(&o, "create");
  mp_cstr(&o, "step"); mp_cstr(&o, step);
  mp_cstr(&o, "tag"); mp_cstr(&o, tag);
  mp_put(&o, extra, extra_n);
  if (o.failed) {
    free(buf);
    return fail("The request is too large");
  }
  if (send(GIT_PATH_RELEASE, buf, o.n, seconds, &r)) {
    if (status_ok(&r, what))
      rc = 0;
    free(r.data);
  }
  free(buf);
  return rc;
}
static int read_whole(const char *path, uint8_t **data, size_t *n) {
  FILE *f = fopen(path, "rb");
  long size;
  *data = NULL;
  if (!f)
    return 0;
  fseek(f, 0, SEEK_END);
  size = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (size < 0 || size > (14L << 20)) {
    fclose(f);
    return 0;
  }
  *data = malloc((size_t)size + 1);
  if (!*data || fread(*data, 1, (size_t)size, f) != (size_t)size) {
    fclose(f);
    free(*data);
    *data = NULL;
    return 0;
  }
  fclose(f);
  *n = (size_t)size;
  return 1;
}
static int cmd_release_create(const url *u, const char *spec, const rnc_identity *default_signer) {
  char tag[256], dir[PATH_MAX], path[PATH_MAX * 2], commit[128] = "";
  const char *colon = strchr(spec, ':');
  rnc_identity signer = *default_signer;
  DIR *d;
  struct dirent *e;
  uint8_t *manifest_extra = malloc(4u << 20), hash[32];
  mp_out me;
  size_t count = 0, i;
  char names[256][300];
  size_t artifacts_total = 0;
  char *notes = NULL;
  size_t notes_n = 0;
  uint8_t *manifest = malloc(8u << 20);
  size_t manifest_n;
  time_t now = time(NULL);
  char iso[40];
  struct tm tm;
  uint8_t rsg[4096];
  int rc = 1;
  if (!manifest_extra || !manifest)
    return fail("out of memory");
  if (!colon || colon == spec || !colon[1])
    return fail("Invalid release specification\nDid you provide both a tag and artifacts path such as \"1.0.0:./dist\"?");
  snprintf(tag, sizeof(tag), "%.*s", (int)(colon - spec), spec);
  snprintf(dir, sizeof(dir), "%s", colon + 1);
  if (opt_signer) {
    if (rnc_host_identity_load(opt_signer, rngit_random, NULL, &signer) != RNC_OK)
      return fail("Could not load signer identity");
  }
  {
    char *rev[] = {"git", "rev-list", "-n", "1", tag, NULL};
    char out[256];
    size_t n;
    if (rngit_run(NULL, rev, out, sizeof(out), &n).status == 0) {
      snprintf(commit, sizeof(commit), "%s", trim(out));
    } else
      printf("Could not get commit hash for tag %s. Does the tag exist in the local repository?\n", tag);
  }
  if (!is_dir_path(dir))
    return fail("Specified artifacts directory does not exist");
  d = opendir(dir);
  while (d && (e = readdir(d)) != NULL && count < 256) {
    struct stat st;
    size_t len = strlen(e->d_name);
    snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
    if (e->d_name[0] == '.' || stat(path, &st) || !S_ISREG(st.st_mode))
      continue;
    if ((len > 4 && !strcmp(e->d_name + len - 4, ".rsg")) || (len > 4 && !strcmp(e->d_name + len - 4, ".rsm")))
      continue;
    if (len >= sizeof(names[0]))
      continue;
    snprintf(names[count++], sizeof(names[0]), "%s", e->d_name);
  }
  if (d)
    closedir(d);
  if (!count)
    return fail("No files found in specified artifact directory");
  printf("Creating release %s\n", tag);
  notes = input_text(&notes_n);
  {
    size_t a = 0, b = notes_n;
    while (a < b && (notes[a] == '\n' || notes[a] == ' '))
      ++a;
    while (b > a && (notes[b - 1] == '\n' || notes[b - 1] == ' '))
      --b;
    if (a == b) {
      puts("Release creation cancelled");
      return 0;
    }
    memmove(notes, notes + a, b - a);
    notes[b - a] = 0;
    notes_n = b - a;
  }
  gmtime_r(&now, &tm);
  strftime(iso, sizeof(iso), "%Y-%m-%dT%H:%M:%SZ", &tm);
  me = (mp_out){manifest_extra, 4u << 20, 0, 0};
  mp_cstr(&me, "name"); mp_cstr(&me, opt_name ? opt_name : strrchr(u->rest, '/') + 1);
  mp_cstr(&me, "version"); mp_cstr(&me, tag);
  mp_cstr(&me, "released"); mp_cstr(&me, iso);
  mp_cstr(&me, "timestamp"); mp_uint(&me, (uint64_t)now);
  mp_cstr(&me, "origin"); mp_bin(&me, u->destination, 16);
  mp_cstr(&me, "path"); mp_cstr(&me, u->rest);
  mp_cstr(&me, "commit");
  if (commit[0])
    mp_cstr(&me, commit);
  else
    mp_nil(&me);
  mp_cstr(&me, "artifacts");
  mp_array(&me, count);
  for (i = 0; i < count; ++i) {
    uint8_t ts[32], *rsg_buf = rsg;
    mp_out t = {ts, sizeof(ts), 0, 0};
    size_t rn;
    snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
    printf("Signing %s\n", path);
    if (!sha256_file(path, hash))
      return fail("Could not hash an artifact");
    mp_cstr(&t, "timestamp");
    mp_uint(&t, (uint64_t)now);
    rn = rsg_create(&signer, hash, NULL, 0, ts, t.n, 1, rsg_buf, sizeof(rsg));
    if (!rn)
      return fail("Could not create signature for an artifact");
    snprintf(path, sizeof(path), "%s/%s.rsg", dir, names[i]);
    {
      FILE *f = fopen(path, "wb");
      if (!f || fwrite(rsg_buf, 1, rn, f) != rn || fclose(f))
        return fail("Could not write a signature file");
    }
    mp_map(&me, 2);
    mp_cstr(&me, "name"); mp_cstr(&me, names[i]);
    mp_cstr(&me, "rsg"); mp_bin(&me, rsg_buf, rn);
  }
  if (me.failed)
    return fail("Release manifest generation failed");
  if (!sha256_bytes(notes, notes_n, hash))
    return fail("Release manifest generation failed");
  manifest_n = rsg_create(&signer, hash, (const uint8_t *)notes, notes_n, manifest_extra, me.n, 8, manifest, 8u << 20);
  if (!manifest_n)
    return fail("Release manifest generation failed");
  snprintf(path, sizeof(path), "%s/manifest.rsm", dir);
  {
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(manifest, 1, manifest_n, f) != manifest_n || fclose(f))
      return fail("Could not write the manifest");
  }
  if (opt_local) {
    printf("Local release %s:%s generated successfully in %s\n", opt_name ? opt_name : u->rest, tag, dir);
    return 0;
  }
  puts("Initializing release on remote...");
  {
    uint8_t extra[70000];
    mp_out x = {extra, sizeof(extra), 0, 0};
    mp_cstr(&x, "hash");
    mp_cstr(&x, commit);
    mp_cstr(&x, "notes");
    mp_str(&x, notes, notes_n);
    mp_cstr(&x, "notes_format");
    mp_cstr(&x, "markdown");
    if (x.failed || release_step(u, "init", tag, extra, x.n, 3, 120, "Server error during init: "))
      return 1;
  }
  puts("Release initialized");
  artifacts_total = count * 2 + 1;
  printf("\nSending %zu artifact%s...\n", artifacts_total, artifacts_total == 1 ? "" : "s");
  for (i = 0; i < count * 2 + 1; ++i) {
    char name[320];
    uint8_t *data, *extra;
    size_t n;
    mp_out x;
    if (i < count)
      snprintf(name, sizeof(name), "%s", names[i]);
    else if (i < count * 2)
      snprintf(name, sizeof(name), "%s.rsg", names[i - count]);
    else
      snprintf(name, sizeof(name), "manifest.rsm");
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (!read_whole(path, &data, &n)) {
      printf("  Failed to send %s: could not read it\n", name);
      continue;
    }
    extra = malloc(n + 1024);
    if (!extra) {
      free(data);
      return fail("out of memory");
    }
    x = (mp_out){extra, n + 1024, 0, 0};
    mp_cstr(&x, "artifact_name"); mp_cstr(&x, name);
    mp_cstr(&x, "artifact_data"); mp_bin(&x, data, n);
    if (x.failed || release_step(u, "artifact", tag, extra, x.n, 2, 7200, "  Failed to send: "))
      printf("  Failed to send %s\n", name);
    else
      printf("  %s (%zu B) transferred\n", name, n);
    free(extra);
    free(data);
  }
  puts("\nFinalizing release...");
  if (release_step(u, "finalize", tag, NULL, 0, 0, 300, "Server error during finalize: "))
    return 1;
  printf("Release %s published\n", tag);
  rc = 0;
  free(manifest);
  free(manifest_extra);
  free(notes);
  return rc;
}

/* fetch (or, offline, verify) the artifacts a signed manifest lists */
static int fetch_file(const url *u, const char *tag, const char *name, char *out_path, size_t cap) {
  uint8_t buf[2048];
  mp_out o = {buf, sizeof(buf), 0, 0};
  rngit_response r;
  FILE *f;
  mp_map(&o, 4);
  mp_uint(&o, GIT_IDX_REPOSITORY); mp_cstr(&o, u->rest);
  mp_cstr(&o, "operation"); mp_cstr(&o, "fetch");
  mp_cstr(&o, "tag"); mp_cstr(&o, tag);
  mp_cstr(&o, "artifact"); mp_cstr(&o, name);
  if (!send(GIT_PATH_RELEASE, buf, o.n, 7200, &r))
    return 0;
  if (!r.meta_size) {
    status_ok(&r, "Remote error: ");
    free(r.data);
    return 0;
  }
  snprintf(out_path, cap, "%s.part", name);
  f = fopen(out_path, "wb");
  if (!f || fwrite(r.data, 1, r.size, f) != r.size || fclose(f)) {
    free(r.data);
    return 0;
  }
  printf("  Transferring %s: 100%% (%zu B)\n", name, r.size);
  free(r.data);
  return 1;
}
static int cmd_release_fetch(url *u, const char *spec, const char *manifest_file) {
  char tag[256], artifact[300] = "all", rsm_path[PATH_MAX + 8];
  const char *colon = strchr(spec ? spec : "latest:all", ':');
  uint8_t required[16], *manifest = NULL, *rsg;
  size_t manifest_n = 0;
  rsg_info *info = calloc(1, sizeof(*info));
  const val *msg, *meta, *arts;
  int have_required = 0, valid_count = 0, rc = 1;
  size_t i, wanted = 0;
  uint8_t hash[32];
  if (!spec)
    spec = "latest:all";
  colon = strchr(spec, ':');
  if (!colon)
    return fail("Invalid release specification");
  snprintf(tag, sizeof(tag), "%.*s", (int)(colon - spec), spec);
  snprintf(artifact, sizeof(artifact), "%s", colon + 1);
  if (opt_signer) {
    if (!rngit_hex_decode(opt_signer, required, 16))
      return fail("Invalid required signer identity hash");
    have_required = 1;
  }
  if (!info)
    return fail("out of memory");
  if (manifest_file) {
    snprintf(rsm_path, sizeof(rsm_path), "%s", manifest_file);
    if (!read_whole(rsm_path, &manifest, &manifest_n))
      return fail("Could not read the manifest");
  } else {
    if (!fetch_file(u, tag, "manifest.rsm", rsm_path, sizeof(rsm_path)))
      return 1;
    if (!read_whole(rsm_path, &manifest, &manifest_n))
      return fail("Could not read the fetched manifest");
    unlink(rsm_path);
  }
  rsg = manifest;
  /* the manifest embeds the notes it signs: validate against their hash */
  {
    rsg_info peek;
    reader rd = {rsg + 64, rsg + manifest_n, peek.pool, 0, 2048};
    if (manifest_n < 65 || !parse(&rd, &peek.root, 0) || !(msg = map_get(&peek.root, "message")) || !val_is_text(msg))
      return fail("No embedded message in release manifest");
    if (!sha256_bytes(msg->p, msg->n, hash))
      return fail("Could not hash the manifest message");
  }
  if (!rsg_validate(rsg, manifest_n, hash, have_required ? required : NULL, info)) {
    if (have_required) {
      printf("Release manifest not signed by ");
      print_hash_pretty(required);
      puts(", aborting");
      return 1;
    }
    return fail("Could not validate release manifest signature");
  }
  printf("Release manifest validated, signed by ");
  print_hash_pretty(info->signer);
  putchar('\n');
  meta = map_get(map_get(&info->root, "meta"), "name") ? map_get(&info->root, "meta") : NULL;
  if (!meta)
    return fail("Incomplete package data in manifest");
  {
    const val *name = map_get(meta, "name"), *version = map_get(meta, "version"), *origin = map_get(meta, "origin"),
              *path = map_get(meta, "path");
    char nbuf[128], vbuf[128];
    if (!name || !version || !val_is_text(name) || !val_is_text(version))
      return fail("Incomplete package data in manifest");
    if (!origin || !path)
      return fail("Incomplete release origin data in manifest");
    if (memchr(name->p, '/', name->n) || memchr(version->p, '/', version->n))
      return fail("Invalid data in release manifest");
    if (origin->type != V_BIN || origin->n != 16)
      return fail("Invalid origin hash length in manifest");
    if (!manifest_file) {
      char out_name[300];
      FILE *f;
      snprintf(out_name, sizeof(out_name), "%s_%s.rsm", str_of(name, nbuf, sizeof(nbuf)), str_of(version, vbuf, sizeof(vbuf)));
      f = fopen(out_name, "wb");
      if (f) {
        fwrite(manifest, 1, manifest_n, f);
        fclose(f);
      }
    }
  }
  arts = map_get(meta, "artifacts");
  if (!arts || arts->type != V_ARR || !arts->n)
    return fail("Release manifest contains no artifacts");
  printf("%s artifacts...\n", opt_offline ? "Validating" : "Fetching");
  for (i = 0; i < arts->n; ++i) {
    const val *an = map_get(&arts->kids[i], "name"), *ar = map_get(&arts->kids[i], "rsg");
    char name[300], base[300], tmp[PATH_MAX];
    uint8_t digest[32];
    rsg_info *ai;
    const char *b;
    if (!an || !ar || ar->type != V_BIN || !val_copy(an, name, sizeof(name)))
      continue;
    b = strrchr(name, '/') ? strrchr(name, '/') + 1 : name;
    snprintf(base, sizeof(base), "%s", b);
    if (strcmp(artifact, "all") && fnmatch(artifact, name, 0))
      continue;
    wanted++;
    ai = calloc(1, sizeof(*ai));
    if (!ai)
      return fail("out of memory");
    if (!opt_offline && is_file_path(base) && sha256_file(base, digest) &&
        rsg_validate(ar->p, ar->n, digest, have_required ? required : NULL, ai)) {
      printf("  Existing file %s validated, not fetching again\n", base);
      valid_count++;
      free(ai);
      continue;
    }
    if (opt_offline) {
      if (!is_file_path(base)) {
        printf("  File %s from manifest does not exist locally, cannot validate\n", base);
        free(ai);
        continue;
      }
      snprintf(tmp, sizeof(tmp), "%s", base);
    } else if (!fetch_file(u, tag, base, tmp, sizeof(tmp))) {
      free(ai);
      return 1;
    }
    if (!sha256_file(tmp, digest) || !rsg_validate(ar->p, ar->n, digest, have_required ? required : NULL, ai)) {
      if (opt_offline)
        printf("  File %s does not match manifest\n", base);
      else {
        unlink(tmp);
        free(ai);
        return fail("Fetched file does not match the manifest, aborting");
      }
    } else {
      if (!opt_offline && rename(tmp, base))
        return fail("Could not store a fetched file");
      if (opt_offline)
        printf("  File %s validated against manifest %s\n", base, manifest_file);
      valid_count++;
    }
    free(ai);
  }
  if (!wanted)
    return fail("No available artifacts specified for fetch");
  if (opt_offline) {
    if ((size_t)valid_count == wanted) {
      puts("\nAll files validated");
      rc = 0;
    } else
      puts("\nRelease is not valid");
  } else
    rc = (size_t)valid_count == wanted ? 0 : 1;
  free(info);
  free(manifest);
  return rc;
}

/* ---- work documents ------------------------------------------------------------ */
static int work_call(const url *u, const char *op, const uint8_t *extra, size_t extra_n, size_t extra_pairs,
                     unsigned seconds, rngit_response *r) {
  uint8_t *buf = malloc(400000);
  mp_out o;
  int ok;
  if (!buf)
    return 0;
  o = (mp_out){buf, 400000, 0, 0};
  mp_map(&o, 2 + extra_pairs);
  mp_uint(&o, GIT_IDX_REPOSITORY); mp_cstr(&o, u->rest);
  mp_cstr(&o, "operation"); mp_cstr(&o, op);
  mp_put(&o, extra, extra_n);
  ok = !o.failed && send(GIT_PATH_WORK, buf, o.n, seconds, r);
  free(buf);
  return ok;
}
static int work_simple(const url *u, const char *op, int needs_scope) {
  uint8_t x[128];
  mp_out o = {x, sizeof(x), 0, 0};
  rngit_response r;
  int rc = 1;
  if (opt_doc < 0)
    return fail("No document ID specified");
  mp_cstr(&o, "doc_id"); mp_uint(&o, (uint64_t)opt_doc);
  if (needs_scope) {
    mp_cstr(&o, "scope");
    mp_cstr(&o, opt_scope);
  }
  if (!work_call(u, op, x, o.n, needs_scope ? 2 : 1, 120, &r))
    return 1;
  if (status_ok(&r, "Remote error: ")) {
    printf("Document %ld %s\n", opt_doc, !strcmp(op, "delete") ? "deleted" : !strcmp(op, "complete") ? "completed" : "activated");
    rc = 0;
  }
  free(r.data);
  return rc;
}
static int work_list_cmd(const url *u) {
  uint8_t x[64];
  mp_out o = {x, sizeof(x), 0, 0};
  rngit_response r;
  val v;
  int rc = 1, s;
  mp_cstr(&o, "scope");
  mp_cstr(&o, opt_scope);
  if (!work_call(u, "list", x, o.n, 1, 120, &r))
    return 1;
  if (!status_ok(&r, "Remote error: "))
    goto done;
  if (!reply_value(&r, &v)) {
    puts("No work documents found.");
    rc = 0;
    goto done;
  }
  for (s = 0; s < 3; ++s) {
    static const char *const names[3] = {"active", "completed", "proposed"};
    const val *docs = map_get(&v, names[s]);
    size_t i;
    if (strcmp(opt_scope, "all") && strcmp(opt_scope, names[s]))
      continue;
    if (docs && docs->n) {
      char head[40];
      snprintf(head, sizeof(head), "%c%s documents", names[s][0] - 32, names[s] + 1);
      printf("\n%s\n", head);
      for (i = 0; head[i]; ++i)
        putchar('=');
      printf("\n\n%-4s %-30s %-17s %-18s %s\n", "ID", "Title", "Author", "Created", "Comments");
      puts("--------------------------------------------------------------------------------");
      for (i = 0; i < docs->n; ++i) {
        const val *e = &docs->kids[i];
        char title[512], author[40], created[40];
        str_of(map_get(e, "title"), title, sizeof(title));
        str_of(map_get(e, "author"), author, sizeof(author));
        title[29] = 0;
        author[16] = 0;
        print_time(as_double(map_get(e, "created")), "%Y-%m-%d %H:%M", created, sizeof(created));
        printf("%-4llu %-30s %-16s~ %-18s %llu\n", (unsigned long long)as_uint(map_get(e, "id")), title, author, created,
               (unsigned long long)as_uint(map_get(e, "comments")));
      }
      putchar('\n');
    } else if (strcmp(opt_scope, "all"))
      printf("No %s work documents found.\n", names[s]);
  }
  rc = 0;
done:
  free(r.data);
  return rc;
}
static int work_view_cmd(const url *u) {
  uint8_t x[128];
  mp_out o = {x, sizeof(x), 0, 0};
  rngit_response r;
  val v;
  int rc = 1;
  if (opt_doc < 0)
    return fail("No document ID specified");
  mp_cstr(&o, "doc_id"); mp_uint(&o, (uint64_t)opt_doc);
  mp_cstr(&o, "scope"); mp_cstr(&o, opt_scope);
  if (!work_call(u, "view", x, o.n, 2, 120, &r))
    return 1;
  if (status_ok(&r, "Remote error: ")) {
    if (!reply_value(&r, &v))
      fail("Empty response from remote");
    else {
      const val *meta = map_get(&v, "meta"), *content = map_get(&v, "content"), *comments = map_get(&v, "comments");
      const val *sig = map_get(meta, "signature"), *pub = map_get(meta, "identity");
      char title[512], author[64], created[40], edited[40], format[16], status[64] = "Document not signed", who[128];
      char *body = malloc(262144);
      size_t i;
      str_of(map_get(meta, "title"), title, sizeof(title));
      str_of(map_get(meta, "author"), author, sizeof(author));
      str_of(map_get(meta, "format"), format, sizeof(format));
      snprintf(who, sizeof(who), "%s (not locally validated)", author);
      if (sig && sig->type == V_BIN && sig->n == 64 && pub && pub->type == V_BIN && pub->n == 64) {
        rnc_identity pi;
        snprintf(status, sizeof(status), "Not valid");
        if (rnc_identity_from_public(&pi, pub->p) == RNC_OK && content && val_is_text(content) &&
            rnc_identity_verify(&pi, content->p, content->n, sig->p) == RNC_OK) {
          snprintf(status, sizeof(status), "Valid");
          snprintf(who, sizeof(who), "<%s>", author);
        }
      }
      print_time(as_double(map_get(meta, "created")), "%Y-%m-%d %H:%M:%S", created, sizeof(created));
      print_time(as_double(map_get(meta, "edited")), "%Y-%m-%d %H:%M:%S", edited, sizeof(edited));
      printf("%s (#%llu)\n", title, (unsigned long long)as_uint(map_get(&v, "id")));
      printf("Author    : %s\nSignature : %s\nStatus    : %s\n", who, status, opt_scope);
      printf("Created   : %s\nEdited    : %s\nFormat    : %s\nUpdates   : %zu\n\n", created, edited, format,
             comments ? comments->n : 0);
      if (body && content && val_is_text(content) && content->n < 262144)
        fwrite(content->p, 1, content->n, stdout);
      puts("");
      for (i = 0; comments && i < comments->n; ++i) {
        const val *c = &comments->kids[i], *cc = map_get(c, "content");
        char ca[64], ct[40];
        str_of(map_get(c, "author"), ca, sizeof(ca));
        print_time(as_double(map_get(c, "created")), "%Y-%m-%d %H:%M:%S", ct, sizeof(ct));
        if (i == 0)
          puts("\nUpdates\n=======");
        printf("\n#%llu by %s at %s\n", (unsigned long long)as_uint(map_get(c, "id")), ca, ct);
        if (cc && val_is_text(cc))
          fwrite(cc->p, 1, cc->n, stdout);
        puts("");
      }
      puts("");
      free(body);
      rc = 0;
    }
  }
  free(r.data);
  return rc;
}
static int work_write_cmd(const url *u, const char *op) {
  char *content = NULL, *c2;
  size_t n = 0;
  uint8_t *x = malloc(400000);
  mp_out o;
  int rc = 1, is_edit = !strcmp(op, "edit"), is_comment = !strcmp(op, "comment"), pairs = 0;
  uint8_t sig[64];
  if (!x)
    return fail("out of memory");
  if ((is_edit || is_comment) && opt_doc < 0)
    return fail("No document ID specified");
  if (!is_edit && !is_comment && !opt_title)
    return fail("A title is required (-t)");
  content = input_text(&n);
  c2 = content;
  /* the node signs-checks the stripped text for create and propose, the text as
   * sent for edit */
  if (!is_edit) {
    size_t a = 0, b = n;
    while (a < b && (c2[a] == ' ' || c2[a] == '\n' || c2[a] == '\t' || c2[a] == '\r'))
      ++a;
    while (b > a && (c2[b - 1] == ' ' || c2[b - 1] == '\n' || c2[b - 1] == '\t' || c2[b - 1] == '\r'))
      --b;
    memmove(c2, c2 + a, b - a);
    c2[b - a] = 0;
    n = b - a;
  }
  if (!n && !(is_edit && opt_title)) {
    puts(is_comment ? "Update cancelled" : "Cancelled");
    return 0;
  }
  o = (mp_out){x, 400000, 0, 0};
  if (is_edit || !is_comment) {
    if (rnc_identity_sign(&C->net.id, c2, n, sig) != RNC_OK)
      return fail("Could not sign work document");
  }
  if (is_edit) {
    mp_cstr(&o, "doc_id"); mp_uint(&o, (uint64_t)opt_doc);
    mp_cstr(&o, "scope"); mp_cstr(&o, opt_scope);
    mp_cstr(&o, "content"); mp_str(&o, c2, n);
    mp_cstr(&o, "title"); mp_cstr(&o, opt_title ? opt_title : "");
    mp_cstr(&o, "signature"); mp_bin(&o, sig, 64);
    pairs = 5;
  } else if (is_comment) {
    mp_cstr(&o, "doc_id"); mp_uint(&o, (uint64_t)opt_doc);
    mp_cstr(&o, "scope"); mp_cstr(&o, opt_scope);
    mp_cstr(&o, "content"); mp_str(&o, c2, n);
    mp_cstr(&o, "format"); mp_cstr(&o, "markdown");
    pairs = 4;
  } else {
    mp_cstr(&o, "title"); mp_cstr(&o, opt_title);
    mp_cstr(&o, "content"); mp_str(&o, c2, n);
    mp_cstr(&o, "format"); mp_cstr(&o, "markdown");
    mp_cstr(&o, "signature"); mp_bin(&o, sig, 64);
    pairs = 4;
  }
  if (o.failed) {
    free(x);
    return fail("The text is too large");
  }
  {
    rngit_response rr;
    if (work_call(u, op, x, o.n, (size_t)pairs, 600, &rr)) {
      if (status_ok(&rr, "Remote error: ")) {
        val v;
        if (!is_edit && reply_value(&rr, &v))
          printf("%s %s as document %llu\n", is_comment ? "Update" : !strcmp(op, "create") ? "Created" : "Proposed",
                 is_comment ? "added" : "work document", (unsigned long long)as_uint(map_get(&v, "id")));
        else
          puts("Work document updated");
        rc = 0;
      }
      free(rr.data);
    }
  }
  free(x);
  free(content);
  return rc;
}
static int work_perms_cmd(const url *u, const char *step, const char *file) {
  uint8_t *x = malloc(300000);
  mp_out o;
  rngit_response r;
  char *content = NULL;
  size_t n = 0;
  int rc = 1;
  if (!x)
    return fail("out of memory");
  if (opt_doc < 0)
    return fail("No document ID specified");
  o = (mp_out){x, 300000, 0, 0};
  mp_cstr(&o, "doc_id"); mp_uint(&o, (uint64_t)opt_doc);
  mp_cstr(&o, "step"); mp_cstr(&o, step);
  if (!strcmp(step, "set")) {
    if (!(content = read_text(file, &n)))
      return fail("Could not read the permission file");
    mp_cstr(&o, "content");
    mp_str(&o, content, n);
    free(content);
  }
  if (!o.failed && work_call(u, "perms", x, o.n, !strcmp(step, "set") ? 3 : 2, 120, &r)) {
    if (status_ok(&r, "Remote error: ")) {
      if (!strcmp(step, "get")) {
        val v;
        const val *t;
        if (reply_value(&r, &v) && (t = map_get(&v, "content")) && val_is_text(t))
          fwrite(t->p, 1, t->n, stdout);
      } else
        puts("Permissions updated");
      rc = 0;
    }
    free(r.data);
  }
  free(x);
  return rc;
}

static void usage(void) {
  fputs("usage: reticulum-c-git-admin [--connect HOST:PORT] [--config DIR] COMMAND ARGS\n"
        "  create URL | fork SOURCE URL | mirror SOURCE URL | sync URL\n"
        "  gperms|rperms URL get | set FILE|-\n"
        "  release URL list | view TAG | delete TAG [-y] | latest TAG [-y]\n"
        "  release URL create TAG:DIR [-s IDFILE] [-n NAME] [-L] (-m TEXT | -F FILE)\n"
        "  release URL|MANIFEST.rsm fetch TAG:ARTIFACT|all [--signer HASH] | verify\n"
        "  work URL list [--scope S] | view|delete|complete|activate -d ID\n"
        "  work URL create|propose -t TITLE (-m TEXT | -F FILE | -) | edit -d ID [-t T] (...)\n"
        "  work URL update -d ID (-m TEXT | -F FILE) | perms -d ID get | set FILE|-\n",
        stderr);
}
int main(int argc, char **argv) {
  const char *connect = NULL, *pos[6] = {0};
  int np = 0, i, rc = 1;
  const char *env;
  url u;
  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, rngit_on_signal);
  signal(SIGTERM, rngit_on_signal);
  for (i = 1; i < argc; ++i) {
#define NEXT (i + 1 < argc ? argv[++i] : (usage(), exit(2), (char *)NULL))
    if (!strcmp(argv[i], "--connect"))
      connect = NEXT;
    else if (!strcmp(argv[i], "--config"))
      setenv("RNGIT_CONFIG", NEXT, 1);
    else if (!strcmp(argv[i], "-m")) {
      snprintf(opt_text, sizeof(opt_text), "%s", NEXT);
      opt_text_set = 1;
    } else if (!strcmp(argv[i], "-F"))
      opt_file = NEXT;
    else if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--title"))
      opt_title = NEXT;
    else if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--id"))
      opt_doc = strtol(NEXT, NULL, 10);
    else if (!strcmp(argv[i], "--scope"))
      opt_scope = NEXT;
    else if (!strcmp(argv[i], "--signer"))
      opt_signer = NEXT;
    else if (!strcmp(argv[i], "-s"))
      opt_identity = NEXT;
    else if (!strcmp(argv[i], "-n") || !strcmp(argv[i], "--name"))
      opt_name = NEXT;
    else if (!strcmp(argv[i], "-y"))
      opt_yes = 1;
    else if (!strcmp(argv[i], "-L") || !strcmp(argv[i], "--local"))
      opt_local = 1;
    else if (!strcmp(argv[i], "-o") || !strcmp(argv[i], "--offline"))
      opt_offline = 1;
    else if (!strcmp(argv[i], "-") && np >= 3) {
      opt_file = "-";
    } else if (np < 6)
      pos[np++] = argv[i];
    else
      return usage(), 2;
  }
  if (np < 2)
    return usage(), 2;
  env = getenv("RNGIT_CONFIG");
  if (env && *env)
    snprintf(config_dir, sizeof(config_dir), "%s", env);
  else
    snprintf(config_dir, sizeof(config_dir), "%s/.rngit", getenv("HOME") ? getenv("HOME") : ".");
  if (!strcmp(pos[0], "release") && strlen(pos[1]) > 4 && !strcasecmp(pos[1] + strlen(pos[1]) - 4, ".rsm") &&
      is_file_path(pos[1])) {
    /* a local manifest: the origin is in it */
    uint8_t *m;
    size_t mn;
    rsg_info *info = calloc(1, sizeof(*info));
    const val *meta, *origin, *path;
    char path_text[600], target[800];
    if (!info || !read_whole(pos[1], &m, &mn) || mn < 65)
      return fail("Could not read the manifest");
    {
      reader rd = {m + 64, m + mn, info->pool, 0, 2048};
      if (!parse(&rd, &info->root, 0))
        return fail("Could not read the manifest");
    }
    meta = map_get(&info->root, "meta");
    origin = map_get(meta, "origin");
    path = map_get(meta, "path");
    if (!origin || origin->type != V_BIN || origin->n != 16 || !path || !val_copy(path, path_text, sizeof(path_text)))
      return fail("Incomplete release origin data in manifest");
    {
      char hex[33];
      size_t k;
      for (k = 0; k < 16; ++k)
        snprintf(hex + 2 * k, 3, "%02x", origin->p[k]);
      snprintf(target, sizeof(target), "rns://%s/%s", hex, path_text);
    }
    if (!parse_url(target, &u))
      return fail("Invalid release origin");
    if (np >= 3 && !strcmp(pos[2], "verify"))
      opt_offline = 1;
    if (opt_offline) {
      /* offline needs no node */
      return cmd_release_fetch(&u, np >= 4 ? pos[3] : "latest:all", pos[1]);
    }
    connect_node(&u, connect);
    rc = cmd_release_fetch(&u, np >= 4 ? pos[3] : "latest:all", NULL);
    rngit_close_node(&C->net);
    return rc;
  }
  if (!strcmp(pos[0], "fork") || !strcmp(pos[0], "mirror")) {
    if (np < 3 || !parse_url(pos[2], &u))
      return usage(), 2;
    connect_node(&u, connect);
    rc = cmd_clone(&u, pos[1], pos[0]);
    goto out;
  }
  if (!parse_url(pos[1], &u))
    return fail("Invalid URL (rns://DESTINATION/GROUP[/REPOSITORY])");
  if (!strcmp(pos[0], "create")) {
    if (u.components != 2)
      return fail("Invalid number of URL components");
    connect_node(&u, connect);
    rc = cmd_create(&u);
  } else if (!strcmp(pos[0], "sync")) {
    connect_node(&u, connect);
    rc = cmd_sync(&u);
  } else if (!strcmp(pos[0], "gperms") || !strcmp(pos[0], "rperms")) {
    int is_group = pos[0][0] == 'g';
    if (np < 3 || (strcmp(pos[2], "get") && strcmp(pos[2], "set")) || u.components != (is_group ? 1 : 2))
      return usage(), 2;
    connect_node(&u, connect);
    rc = cmd_perms(&u, pos[0], pos[2], np >= 4 ? pos[3] : opt_file);
  } else if (!strcmp(pos[0], "release")) {
    if (np < 3 || u.components != 2)
      return usage(), 2;
    if (!strcmp(pos[2], "create") && np >= 4 && opt_local) {
      /* a local release needs no node, only the signing identity */
      rnc_identity local_id;
      char idpath[PATH_MAX + 32];
      snprintf(idpath, sizeof(idpath), "%s/client_identity", config_dir);
      if (rnc_host_identity_load(opt_signer ? opt_signer : idpath, rngit_random, NULL, &local_id) != RNC_OK)
        return fail("Could not load the signing identity");
      return cmd_release_create(&u, pos[3], &local_id);
    }
    connect_node(&u, connect);
    if (!strcmp(pos[2], "list"))
      rc = cmd_release_list(&u);
    else if (!strcmp(pos[2], "view") && np >= 4)
      rc = cmd_release_view(&u, pos[3]);
    else if ((!strcmp(pos[2], "delete") || !strcmp(pos[2], "latest")) && np >= 4)
      rc = cmd_release_simple(&u, pos[2], pos[3]);
    else if (!strcmp(pos[2], "create") && np >= 4) {
      rnc_identity none = C->net.id;
      rc = cmd_release_create(&u, pos[3], &none);
    } else if (!strcmp(pos[2], "fetch"))
      rc = cmd_release_fetch(&u, np >= 4 ? pos[3] : NULL, NULL);
    else
      return usage(), 2;
  } else if (!strcmp(pos[0], "work")) {
    if (np < 3 || u.components != 2)
      return usage(), 2;
    connect_node(&u, connect);
    if (!strcmp(pos[2], "list"))
      rc = work_list_cmd(&u);
    else if (!strcmp(pos[2], "view"))
      rc = work_view_cmd(&u);
    else if (!strcmp(pos[2], "create") || !strcmp(pos[2], "propose") || !strcmp(pos[2], "edit"))
      rc = work_write_cmd(&u, pos[2]);
    else if (!strcmp(pos[2], "update"))
      rc = work_write_cmd(&u, "comment");
    else if (!strcmp(pos[2], "delete") || !strcmp(pos[2], "complete") || !strcmp(pos[2], "activate"))
      rc = work_simple(&u, pos[2], !strcmp(pos[2], "delete"));
    else if (!strcmp(pos[2], "perms") && np >= 4 && (!strcmp(pos[3], "get") || !strcmp(pos[3], "set")))
      rc = work_perms_cmd(&u, pos[3], np >= 5 ? pos[4] : opt_file);
    else
      return usage(), 2;
  } else
    return usage(), 2;
out:
  if (C)
    rngit_close_node(&C->net);
  return rc;
}
