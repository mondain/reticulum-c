/* Work documents (issues and proposals) for reticulum-c-git, included by
 * reticulum_git.c: the /mgmt/work path of the reference. They live in
 * NAME.work/{active,completed,proposed}/ID/ as MessagePack files: `root` is the
 * document, the numbered files are its comments; NAME.work/ID.allowed holds a
 * document's own permissions. Documents are signed by their author. */
#ifndef RETICULUM_C_RNGIT_WORK_H
#define RETICULUM_C_RNGIT_WORK_H

#define WORK_DOC_LIMIT (256 * 1024)
#define DOC_POOL 4096
static const char *const work_scopes[3] = {"active", "completed", "proposed"};

/* The identity of the caller of the running request. */
static const rnc_identity *test_identity; /* set by tests that call handlers directly */
static int caller_identity(rnc_identity *out) {
  if (test_identity) {
    *out = *test_identity;
    return 1;
  }
  return G.net.responder && rnc_responder_request_identity(G.net.responder, out) == RNC_OK;
}

typedef struct doc {
  uint8_t *raw;
  val *pool;
  val root;
} doc;
static void doc_free(doc *d) {
  free(d->raw);
  free(d->pool);
  memset(d, 0, sizeof(*d));
}
static int doc_load(const char *path, doc *d) {
  FILE *f = fopen(path, "rb");
  size_t n;
  reader rd;
  memset(d, 0, sizeof(*d));
  if (!f)
    return 0;
  d->raw = malloc(WORK_DOC_LIMIT * 2);
  d->pool = malloc(DOC_POOL * sizeof(val));
  if (!d->raw || !d->pool) {
    fclose(f);
    doc_free(d);
    return 0;
  }
  n = fread(d->raw, 1, WORK_DOC_LIMIT * 2, f);
  fclose(f);
  rd = (reader){d->raw, d->raw + n, d->pool, 0, DOC_POOL};
  if (!parse(&rd, &d->root, 0) || d->root.type != V_MAP) {
    doc_free(d);
    return 0;
  }
  return 1;
}
static const val *doc_meta(const doc *d) { return map_get(&d->root, "meta"); }
static int doc_author_is(const doc *d, const uint8_t id[16]) {
  const val *a = map_get(doc_meta(d), "author");
  return a && a->type == V_BIN && a->n == 16 && !memcmp(a->p, id, 16);
}
static int save_doc(const char *path, const uint8_t *packed, size_t n) {
  char dir[PATH_MAX + 8], *slash;
  snprintf(dir, sizeof(dir), "%s", path);
  slash = strrchr(dir, '/');
  if (slash) {
    *slash = 0;
    if (!is_dir(dir) && !mkdirs(dir))
      return 0;
  }
  return write_atomic(path, (const char *)packed, n);
}
/* A document or comment body: {"content": ..., "meta": {...}} */
typedef struct docmeta {
  const char *format;
  const char *title; /* NULL = nil */
  double created, edited;
  const uint8_t *author; /* 16 bytes */
  const uint8_t *signature; /* 64 bytes or NULL */
  const uint8_t *identity; /* 64 bytes or NULL */
  int comment;
} docmeta;
static size_t doc_emit(uint8_t *buf, size_t cap, const char *content, size_t content_n, const docmeta *m) {
  mp_out o = {buf, cap, 0, 0};
  mp_map(&o, 2);
  mp_cstr(&o, "content");
  mp_str(&o, content, content_n);
  mp_cstr(&o, "meta");
  mp_map(&o, m->comment ? 6 : 7);
  mp_cstr(&o, "format"); mp_cstr(&o, m->format);
  mp_cstr(&o, "title");
  if (m->title)
    mp_cstr(&o, m->title);
  else
    mp_nil(&o);
  mp_cstr(&o, "created"); mp_double(&o, m->created);
  mp_cstr(&o, "edited"); mp_double(&o, m->edited);
  mp_cstr(&o, "author"); mp_bin(&o, m->author, 16);
  mp_cstr(&o, "signature");
  if (m->signature)
    mp_bin(&o, m->signature, 64);
  else
    mp_nil(&o);
  if (!m->comment) {
    mp_cstr(&o, "identity");
    mp_bin(&o, m->identity, 64);
  }
  return o.failed ? 0 : o.n;
}

/* resolve_doc_permission: the document's own list first, then the repository's,
 * then the group's. */
static int doc_allowed(const uint8_t id[16], const group *g, const repo *r, const char *work_path,
                       long doc_id, int p) {
  perm_set d[P_COUNT];
  char path[PATH_MAX + 32];
  const perm_set *rp, *gp;
  if (!g || !r)
    return 0;
  memset(d, 0, sizeof(d));
  snprintf(path, sizeof(path), "%s/%ld.allowed", work_path, doc_id);
  if (is_dir(work_path))
    load_allowed(path, d);
  if (p != P_READ && p != P_WRITE && p != P_CREATE && p != P_INTERACT && p != P_PROPOSE && p != P_ADMIN)
    return 0;
  if (d[p].none) return 0;
  if (d[p].all) return 1;
  if (set_has(&d[p], id)) return 1;
  if (set_has(&d[P_ADMIN], id)) return 1;
  rp = &r->perms[p];
  gp = &g->perms[p];
  if (rp->none) return 0;
  if (rp->all) return 1;
  if (set_has(rp, id)) return 1;
  if (set_has(&r->perms[P_ADMIN], id)) return 1;
  if (rp->entries > 0) return 0;
  if (gp->none) return 0;
  if (gp->all) return 1;
  if (set_has(gp, id)) return 1;
  if (set_has(&g->perms[P_ADMIN], id)) return 1;
  return 0;
}
static int doc_id_of(const val *v, long *out) {
  char text[32], *end;
  if (!v)
    return 0;
  if (v->type == V_UINT && v->u < 1000000000UL) {
    *out = (long)v->u;
    return 1;
  }
  if (v->type == V_INT && v->i > -1000000000L && v->i < 1000000000L) {
    *out = (long)v->i;
    return 1;
  }
  if (val_is_text(v) && val_copy(v, text, sizeof(text))) {
    *out = strtol(text, &end, 10);
    return *text && !*end;
  }
  return 0;
}
static int scope_valid(const char *s) {
  return !strcmp(s, "active") || !strcmp(s, "completed") || !strcmp(s, "proposed") || !strcmp(s, "all");
}
/* where a document lives: the scope index, or -1 */
static int find_doc(const char *work_path, long id, char *dir, size_t cap) {
  int i;
  for (i = 0; i < 3; ++i) {
    snprintf(dir, cap, "%s/%s/%ld", work_path, work_scopes[i], id);
    if (is_dir(dir))
      return i;
  }
  return -1;
}
static long max_numeric_entry(const char *base) {
  DIR *d = opendir(base);
  struct dirent *e;
  long m = 0;
  if (!d)
    return 0;
  while ((e = readdir(d)) != NULL) {
    char *end;
    long v;
    if (!e->d_name[0] || e->d_name[0] < '0' || e->d_name[0] > '9')
      continue;
    v = strtol(e->d_name, &end, 10);
    if (!*end && v > m)
      m = v;
  }
  closedir(d);
  return m;
}
static long next_doc_id(const char *work_path) {
  long m = 0;
  int i;
  for (i = 0; i < 3; ++i) {
    char base[PATH_MAX + 16];
    long v;
    snprintf(base, sizeof(base), "%s/%s", work_path, work_scopes[i]);
    v = max_numeric_entry(base);
    if (v > m)
      m = v;
  }
  return m + 1;
}
static double wall_now(void) {
  struct timespec t;
  clock_gettime(CLOCK_REALTIME, &t);
  return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
static void strip_text(const char *in, size_t n, char *out, size_t *out_n) {
  size_t a = 0, b = n;
  while (a < b && (in[a] == ' ' || in[a] == '\t' || in[a] == '\n' || in[a] == '\r'))
    ++a;
  while (b > a && (in[b - 1] == ' ' || in[b - 1] == '\t' || in[b - 1] == '\n' || in[b - 1] == '\r'))
    --b;
  memcpy(out, in + a, b - a);
  out[b - a] = 0;
  *out_n = b - a;
}
static void reply_map_id(uint8_t *out, size_t cap, size_t *written, long id, const char *scope) {
  uint8_t body[128];
  mp_out o = {body, sizeof(body), 0, 0}, w = {out, cap, 0, 0};
  mp_byte(&o, GIT_RES_OK);
  mp_map(&o, scope ? 2 : 1);
  mp_cstr(&o, "id");
  mp_uint(&o, (uint64_t)id);
  if (scope) {
    mp_cstr(&o, "scope");
    mp_cstr(&o, scope);
  }
  mp_bin(&w, body, o.n);
  *written = w.failed ? 0 : w.n;
}
static const char *format_of(const val *v, char *buf, size_t cap) {
  if (v && val_is_text(v) && val_copy(v, buf, cap) && (!strcmp(buf, "markdown") || !strcmp(buf, "micron")))
    return buf;
  snprintf(buf, cap, "markdown");
  return buf;
}
static void hex_of_author(const val *meta, char out_hex[33]) {
  const val *a = map_get(meta, "author");
  out_hex[0] = 0;
  if (a && a->type == V_BIN && a->n == 16) {
    size_t i;
    for (i = 0; i < 16; ++i)
      snprintf(out_hex + 2 * i, 3, "%02x", a->p[i]);
  }
}
static double num_of(const val *v) { return v ? as_double(v) : 0; }

static void work_list(const char *work_path, const val *root, const uint8_t *identity, const group *g,
                      const repo *r, uint8_t *out, size_t cap, size_t *written) {
  char scope[16] = "active";
  uint8_t *body = malloc(2u << 20);
  mp_out o = {body, 2u << 20, 0, 0};
  int si;
  if (map_get(root, "scope"))
    val_copy(map_get(root, "scope"), scope, sizeof(scope));
  if (!body) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
    return;
  }
  mp_byte(&o, GIT_RES_OK);
  mp_map(&o, 3);
  for (si = 0; si < 3; ++si) {
    struct entry {
      long id;
      double created, edited;
      char title[512], author[33], format[16];
      long comments;
    } *items = calloc(256, sizeof(struct entry));
    size_t n = 0, i, k;
    char base[PATH_MAX + 16];
    DIR *d;
    struct dirent *e;
    mp_cstr(&o, work_scopes[si]);
    if (!items) {
      mp_array(&o, 0);
      continue;
    }
    if (!strcmp(scope, work_scopes[si]) || !strcmp(scope, "all")) {
      snprintf(base, sizeof(base), "%s/%s", work_path, work_scopes[si]);
      d = opendir(base);
      while (d && (e = readdir(d)) != NULL && n < 256) {
        char dir[PATH_MAX * 2], rootp[PATH_MAX * 2 + 8], *end;
        long id = strtol(e->d_name, &end, 10);
        doc dd;
        const val *meta, *t;
        DIR *cd;
        struct dirent *ce;
        long comments = 0;
        struct entry *it = &items[n];
        if (e->d_name[0] < '0' || e->d_name[0] > '9' || *end)
          continue;
        snprintf(dir, sizeof(dir), "%s/%s", base, e->d_name);
        if (!is_dir(dir) || !doc_allowed(identity, g, r, work_path, id, P_READ))
          continue;
        snprintf(rootp, sizeof(rootp), "%s/root", dir);
        if (!doc_load(rootp, &dd))
          continue;
        meta = doc_meta(&dd);
        it->id = id;
        it->created = num_of(map_get(meta, "created"));
        it->edited = num_of(map_get(meta, "edited"));
        t = map_get(meta, "title");
        if (t && val_is_text(t) && t->n < sizeof(it->title) && val_copy(t, it->title, sizeof(it->title))) {
        } else
          snprintf(it->title, sizeof(it->title), "Untitled");
        hex_of_author(meta, it->author);
        format_of(map_get(meta, "format"), it->format, sizeof(it->format));
        cd = opendir(dir);
        while (cd && (ce = readdir(cd)) != NULL) {
          char cp[PATH_MAX * 2 + 8], *cend;
          if (ce->d_name[0] < '0' || ce->d_name[0] > '9')
            continue;
          (void)strtol(ce->d_name, &cend, 10);
          snprintf(cp, sizeof(cp), "%s/%s", dir, ce->d_name);
          if (!*cend && is_file(cp))
            comments++;
        }
        if (cd)
          closedir(cd);
        it->comments = comments;
        doc_free(&dd);
        n++;
      }
      if (d)
        closedir(d);
    }
    for (i = 0; i + 1 < n; ++i)
      for (k = i + 1; k < n; ++k)
        if (items[k].created > items[i].created) {
          struct entry tmp = items[i];
          items[i] = items[k];
          items[k] = tmp;
        }
    mp_array(&o, n);
    for (i = 0; i < n; ++i) {
      mp_map(&o, 7);
      mp_cstr(&o, "id"); mp_uint(&o, (uint64_t)items[i].id);
      mp_cstr(&o, "title"); mp_cstr(&o, items[i].title);
      mp_cstr(&o, "created"); mp_double(&o, items[i].created);
      mp_cstr(&o, "edited"); mp_double(&o, items[i].edited);
      mp_cstr(&o, "author"); mp_cstr(&o, items[i].author);
      mp_cstr(&o, "format"); mp_cstr(&o, items[i].format);
      mp_cstr(&o, "comments"); mp_uint(&o, (uint64_t)items[i].comments);
    }
    free(items);
  }
  if (o.failed)
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
  else {
    mp_out w = {out, cap, 0, 0};
    mp_bin(&w, body, o.n);
    *written = w.failed ? 0 : w.n;
  }
  free(body);
}
static void work_view(const char *work_path, const val *root, uint8_t *out, size_t cap, size_t *written) {
  long id;
  char dir[PATH_MAX * 2], rootp[PATH_MAX * 2 + 8], scope[16] = "all";
  int si;
  doc d;
  const val *meta, *content, *t, *ident, *sig;
  uint8_t *body;
  mp_out o;
  DIR *cd;
  struct dirent *ce;
  struct comment_item { long id; doc d; } *comments = NULL;
  size_t n = 0, i, k;
  char author[33], format[16];
  if (map_get(root, "scope"))
    val_copy(map_get(root, "scope"), scope, sizeof(scope));
  if (!scope_valid(scope)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    return;
  }
  if (!map_get(root, "doc_id") || map_get(root, "doc_id")->type == V_NIL) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "No document ID specified");
    return;
  }
  if (!doc_id_of(map_get(root, "doc_id"), &id)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid document ID");
    return;
  }
  si = find_doc(work_path, id, dir, sizeof(dir));
  if (si < 0) {
    reply(out, cap, written, GIT_RES_NOT_FOUND, "Not found");
    return;
  }
  snprintf(rootp, sizeof(rootp), "%s/root", dir);
  if (!is_file(rootp)) {
    reply(out, cap, written, GIT_RES_NOT_FOUND, "Document not found");
    return;
  }
  if (!doc_load(rootp, &d)) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Error loading document");
    return;
  }
  body = malloc(2u << 20);
  comments = calloc(1024, sizeof(comments[0]));
  if (!body || !comments) {
    free(body); free(comments); doc_free(&d);
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
    return;
  }
  cd = opendir(dir);
  while (cd && (ce = readdir(cd)) != NULL && n < 1024) {
    char cp[PATH_MAX * 2 + 8], *cend;
    long cid;
    if (ce->d_name[0] < '0' || ce->d_name[0] > '9')
      continue;
    cid = strtol(ce->d_name, &cend, 10);
    snprintf(cp, sizeof(cp), "%s/%s", dir, ce->d_name);
    if (*cend || !is_file(cp) || !doc_load(cp, &comments[n].d))
      continue;
    comments[n++].id = cid;
  }
  if (cd)
    closedir(cd);
  for (i = 0; i + 1 < n; ++i)
    for (k = i + 1; k < n; ++k)
      if (comments[k].id < comments[i].id) {
        struct comment_item tmp = comments[i];
        comments[i] = comments[k];
        comments[k] = tmp;
      }
  meta = doc_meta(&d);
  content = map_get(&d.root, "content");
  o = (mp_out){body, 2u << 20, 0, 0};
  mp_byte(&o, GIT_RES_OK);
  mp_map(&o, 5);
  mp_cstr(&o, "id"); mp_uint(&o, (uint64_t)id);
  mp_cstr(&o, "scope"); mp_cstr(&o, work_scopes[si]);
  mp_cstr(&o, "content");
  if (content && val_is_text(content))
    mp_str(&o, (const char *)content->p, content->n);
  else
    mp_cstr(&o, "");
  mp_cstr(&o, "comments");
  mp_array(&o, n);
  for (i = 0; i < n; ++i) {
    const val *cm = doc_meta(&comments[i].d), *cc = map_get(&comments[i].d.root, "content");
    hex_of_author(cm, author);
    format_of(map_get(cm, "format"), format, sizeof(format));
    mp_map(&o, 6);
    mp_cstr(&o, "id"); mp_uint(&o, (uint64_t)comments[i].id);
    mp_cstr(&o, "content");
    if (cc && val_is_text(cc))
      mp_str(&o, (const char *)cc->p, cc->n);
    else
      mp_cstr(&o, "");
    mp_cstr(&o, "created"); mp_double(&o, num_of(map_get(cm, "created")));
    mp_cstr(&o, "edited"); mp_double(&o, num_of(map_get(cm, "edited")));
    mp_cstr(&o, "author"); mp_cstr(&o, author);
    mp_cstr(&o, "format"); mp_cstr(&o, format);
  }
  hex_of_author(meta, author);
  format_of(map_get(meta, "format"), format, sizeof(format));
  t = map_get(meta, "title");
  ident = map_get(meta, "identity");
  sig = map_get(meta, "signature");
  mp_cstr(&o, "meta");
  mp_map(&o, 7);
  mp_cstr(&o, "title");
  if (t && val_is_text(t))
    mp_str(&o, (const char *)t->p, t->n);
  else
    mp_cstr(&o, "Untitled");
  mp_cstr(&o, "created"); mp_double(&o, num_of(map_get(meta, "created")));
  mp_cstr(&o, "edited"); mp_double(&o, num_of(map_get(meta, "edited")));
  mp_cstr(&o, "author"); mp_cstr(&o, author);
  mp_cstr(&o, "identity");
  if (ident && ident->type == V_BIN)
    mp_bin(&o, ident->p, ident->n);
  else
    mp_nil(&o);
  mp_cstr(&o, "signature");
  if (sig && sig->type == V_BIN)
    mp_bin(&o, sig->p, sig->n);
  else
    mp_nil(&o);
  mp_cstr(&o, "format"); mp_cstr(&o, format);
  if (o.failed)
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
  else {
    mp_out w = {out, cap, 0, 0};
    mp_bin(&w, body, o.n);
    *written = w.failed ? 0 : w.n;
  }
  for (i = 0; i < n; ++i)
    doc_free(&comments[i].d);
  free(comments);
  free(body);
  doc_free(&d);
}
/* create (active) and propose (proposed) share everything but where the
 * document goes and, for proposals, the owner's permission file. */
static void work_new(const char *work_path, const val *root, const rnc_identity *who, int propose,
                     uint8_t *out, size_t cap, size_t *written) {
  const val *tv = map_get(root, "title"), *cv = map_get(root, "content"), *sv = map_get(root, "signature");
  char *title = calloc(1, (tv && val_is_text(tv) ? tv->n : 0) + 1), *content = calloc(1, (cv && val_is_text(cv) ? cv->n : 0) + 1);
  size_t tn = 0, cn = 0;
  char format[16], path[PATH_MAX * 2], docdir[PATH_MAX * 2];
  uint8_t *buf = NULL;
  size_t n;
  long id;
  double now;
  docmeta m;
  if (!title || !content) {
    free(title); free(content);
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
    return;
  }
  if (tv && val_is_text(tv))
    strip_text((const char *)tv->p, tv->n, title, &tn);
  if (cv && val_is_text(cv))
    strip_text((const char *)cv->p, cv->n, content, &cn);
  format_of(map_get(root, "format"), format, sizeof(format));
  if (!sv || sv->type == V_NIL || !(val_is_text(sv) && sv->n)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "No signature provided");
    goto done;
  }
  if (sv->n != 64) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid signature length");
    goto done;
  }
  if (rnc_identity_verify(who, content, cn, sv->p) != RNC_OK) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid signature");
    goto done;
  }
  if (tn + cn + strlen(format) > WORK_DOC_LIMIT) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Content limit exceeded");
    goto done;
  }
  if (!tn) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Title is required");
    goto done;
  }
  if (!cn) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Content is required");
    goto done;
  }
  id = next_doc_id(work_path);
  now = wall_now();
  snprintf(docdir, sizeof(docdir), "%s/%s/%ld", work_path, propose ? "proposed" : "active", id);
  snprintf(path, sizeof(path), "%s/root", docdir);
  buf = malloc(WORK_DOC_LIMIT * 2);
  if (!buf)
    goto fail;
  m = (docmeta){format, title, now, now, who->hash, sv->p, who->public_key, 0};
  n = doc_emit(buf, WORK_DOC_LIMIT * 2, content, cn, &m);
  if (!n || !save_doc(path, buf, n))
    goto fail;
  if (propose) {
    char hex[33], perms[96], allowed_path[PATH_MAX * 2];
    hex_string(who->hash, hex);
    snprintf(perms, sizeof(perms), "i:%s\nw:%s\n", hex, hex);
    snprintf(allowed_path, sizeof(allowed_path), "%s/%ld.allowed", work_path, id);
    if (!write_atomic(allowed_path, perms, strlen(perms))) {
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Error setting document ownership");
      goto done;
    }
  }
  reply_map_id(out, cap, written, id, propose ? "proposed" : "active");
  goto done;
fail:
  reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Error saving document");
done:
  free(buf);
  free(title);
  free(content);
}
static void work_edit(const char *work_path, const val *root, const rnc_identity *who, uint8_t *out,
                      size_t cap, size_t *written) {
  const val *tv = map_get(root, "title"), *cv = map_get(root, "content"), *sv = map_get(root, "signature");
  char scope[16] = "active", dir[PATH_MAX * 2], rootp[PATH_MAX * 2 + 8];
  long id;
  int si;
  doc d;
  uint8_t *buf = NULL;
  char *new_title = NULL, *new_content = NULL, format[16];
  const val *meta, *old_t, *old_c;
  size_t size = 0, tn = 0, cn = 0, n;
  docmeta m;
  if (map_get(root, "scope"))
    val_copy(map_get(root, "scope"), scope, sizeof(scope));
  if (tv && val_is_text(tv))
    size += tv->n;
  if (cv && val_is_text(cv))
    size += cv->n;
  if (!scope_valid(scope)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    return;
  }
  if (!sv || !(val_is_text(sv) && sv->n)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "No signature provided");
    return;
  }
  if (sv->n != 64) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid signature length");
    return;
  }
  /* the signature covers the content exactly as sent, unstripped */
  if (rnc_identity_verify(who, cv && val_is_text(cv) ? cv->p : (const uint8_t *)"", cv && val_is_text(cv) ? cv->n : 0, sv->p) != RNC_OK) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid signature");
    return;
  }
  if (size > WORK_DOC_LIMIT) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Content limit exceeded");
    return;
  }
  if (!(cv && val_is_text(cv) && cv->n) && !(tv && val_is_text(tv) && tv->n)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "No changes specified");
    return;
  }
  if (!map_get(root, "doc_id") || map_get(root, "doc_id")->type == V_NIL || !doc_id_of(map_get(root, "doc_id"), &id)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, map_get(root, "doc_id") ? "Invalid document ID" : "No document ID specified");
    return;
  }
  si = find_doc(work_path, id, dir, sizeof(dir));
  if (si < 0) {
    reply(out, cap, written, GIT_RES_NOT_FOUND, "Not found");
    return;
  }
  snprintf(rootp, sizeof(rootp), "%s/root", dir);
  if (!is_file(rootp)) {
    reply(out, cap, written, GIT_RES_NOT_FOUND, "Document not found");
    return;
  }
  if (!doc_load(rootp, &d)) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Error loading document");
    return;
  }
  if (!doc_author_is(&d, who->hash)) {
    reply(out, cap, written, GIT_RES_DISALLOWED, "No access, not author");
    doc_free(&d);
    return;
  }
  meta = doc_meta(&d);
  old_t = map_get(meta, "title");
  old_c = map_get(&d.root, "content");
  new_title = calloc(1, (old_t && val_is_text(old_t) ? old_t->n : 0) + (tv && val_is_text(tv) ? tv->n : 0) + 1);
  new_content = calloc(1, (old_c && val_is_text(old_c) ? old_c->n : 0) + (cv && val_is_text(cv) ? cv->n : 0) + 1);
  buf = malloc(WORK_DOC_LIMIT * 2 + 4096);
  if (!new_title || !new_content || !buf)
    goto fail;
  if (tv && val_is_text(tv) && tv->n)
    strip_text((const char *)tv->p, tv->n, new_title, &tn);
  else if (old_t && val_is_text(old_t)) {
    memcpy(new_title, old_t->p, old_t->n);
    tn = old_t->n;
  }
  if (cv && val_is_text(cv) && cv->n)
    strip_text((const char *)cv->p, cv->n, new_content, &cn);
  else if (old_c && val_is_text(old_c)) {
    memcpy(new_content, old_c->p, old_c->n);
    cn = old_c->n;
  }
  format_of(map_get(meta, "format"), format, sizeof(format));
  m = (docmeta){format, new_title, num_of(map_get(meta, "created")), wall_now(), who->hash, sv->p, who->public_key, 0};
  n = doc_emit(buf, WORK_DOC_LIMIT * 2 + 4096, new_content, cn, &m);
  if (!n || !save_doc(rootp, buf, n))
    goto fail;
  reply(out, cap, written, GIT_RES_OK, "");
  goto done;
fail:
  reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Error saving document");
done:
  free(buf);
  free(new_title);
  free(new_content);
  doc_free(&d);
}
static void work_comment(const char *work_path, const val *root, const rnc_identity *who, uint8_t *out,
                         size_t cap, size_t *written) {
  const val *cv = map_get(root, "content"), *sv = map_get(root, "signature");
  char scope[16] = "active", dir[PATH_MAX * 2], path[PATH_MAX * 2 + 16], format[16];
  char *content;
  size_t cn = 0, n;
  long id, cid;
  int si;
  uint8_t *buf;
  docmeta m;
  double now;
  if (map_get(root, "scope"))
    val_copy(map_get(root, "scope"), scope, sizeof(scope));
  if (!scope_valid(scope)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    return;
  }
  if (cv && val_is_text(cv) && cv->n > WORK_DOC_LIMIT) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Content limit exceeded");
    return;
  }
  if (!map_get(root, "doc_id") || map_get(root, "doc_id")->type == V_NIL) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "No document ID specified");
    return;
  }
  if (!doc_id_of(map_get(root, "doc_id"), &id)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid document ID");
    return;
  }
  content = calloc(1, (cv && val_is_text(cv) ? cv->n : 0) + 1);
  buf = malloc(WORK_DOC_LIMIT * 2 + 4096);
  if (!content || !buf) {
    free(content); free(buf);
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
    return;
  }
  if (cv && val_is_text(cv))
    strip_text((const char *)cv->p, cv->n, content, &cn);
  if (!cn) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Content is required");
    goto done;
  }
  si = find_doc(work_path, id, dir, sizeof(dir));
  snprintf(path, sizeof(path), "%s/root", dir);
  if (si < 0 || !is_file(path)) {
    reply(out, cap, written, GIT_RES_NOT_FOUND, "Document not found");
    goto done;
  }
  cid = max_numeric_entry(dir) + 1;
  now = wall_now();
  format_of(map_get(root, "format"), format, sizeof(format));
  m = (docmeta){format, NULL, now, now, who->hash, sv && val_is_text(sv) && sv->n == 64 ? sv->p : NULL, NULL, 1};
  n = doc_emit(buf, WORK_DOC_LIMIT * 2 + 4096, content, cn, &m);
  snprintf(path, sizeof(path), "%s/%ld", dir, cid);
  if (!n || !save_doc(path, buf, n)) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Error saving comment");
    goto done;
  }
  reply_map_id(out, cap, written, cid, NULL);
done:
  free(content);
  free(buf);
}
static void work_delete(const char *work_path, const val *root, const rnc_identity *who, const group *g,
                        const repo *r, uint8_t *out, size_t cap, size_t *written) {
  char scope[16] = "active", dir[PATH_MAX * 2], rootp[PATH_MAX * 2 + 8], allowed_path[PATH_MAX * 2 + 16];
  long id;
  int si;
  doc d;
  if (map_get(root, "scope"))
    val_copy(map_get(root, "scope"), scope, sizeof(scope));
  if (!scope_valid(scope)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    return;
  }
  if (!map_get(root, "doc_id") || map_get(root, "doc_id")->type == V_NIL) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "No document ID specified");
    return;
  }
  if (!doc_id_of(map_get(root, "doc_id"), &id)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid document ID");
    return;
  }
  si = find_doc(work_path, id, dir, sizeof(dir));
  snprintf(rootp, sizeof(rootp), "%s/root", dir);
  if (si < 0 || !is_file(rootp)) {
    reply(out, cap, written, GIT_RES_NOT_FOUND, "Document not found");
    return;
  }
  if (!doc_load(rootp, &d)) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Error loading document");
    return;
  }
  if (!doc_author_is(&d, who->hash) && !doc_allowed(who->hash, g, r, work_path, id, P_ADMIN)) {
    reply(out, cap, written, GIT_RES_DISALLOWED, "No access, not author");
    doc_free(&d);
    return;
  }
  doc_free(&d);
  /* the reference fails when the document has no permission file (everything
   * but proposals); here that is not an error */
  snprintf(allowed_path, sizeof(allowed_path), "%s/%ld.allowed", work_path, id);
  if (unlink(allowed_path) && errno != ENOENT) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
    return;
  }
  remove_tree(dir);
  reply(out, cap, written, GIT_RES_OK, "");
}
static void work_move(const char *work_path, const val *root, const rnc_identity *who, const group *g,
                      const repo *r, int to_completed, uint8_t *out, size_t cap, size_t *written) {
  long id;
  char src[PATH_MAX * 2], dst[PATH_MAX * 2], rootp[PATH_MAX * 2 + 8];
  int si, found = -1;
  doc d;
  const char *target = to_completed ? "completed" : "active";
  if (!map_get(root, "doc_id") || map_get(root, "doc_id")->type == V_NIL) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "No document ID specified");
    return;
  }
  if (!doc_id_of(map_get(root, "doc_id"), &id)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid document ID");
    return;
  }
  for (si = 0; si < 3; ++si) {
    /* complete takes active documents, activate completed or proposed ones */
    if (to_completed ? si != 0 : si == 0)
      continue;
    snprintf(src, sizeof(src), "%s/%s/%ld", work_path, work_scopes[si], id);
    if (is_dir(src)) {
      found = si;
      break;
    }
  }
  if (found < 0) {
    reply(out, cap, written, GIT_RES_NOT_FOUND, "Document not found");
    return;
  }
  snprintf(rootp, sizeof(rootp), "%s/root", src);
  if (!doc_load(rootp, &d)) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Error loading document");
    return;
  }
  if (!doc_author_is(&d, who->hash) && !doc_allowed(who->hash, g, r, work_path, id, P_ADMIN)) {
    reply(out, cap, written, GIT_RES_DISALLOWED, "Not allowed");
    doc_free(&d);
    return;
  }
  doc_free(&d);
  snprintf(dst, sizeof(dst), "%s/%s", work_path, target);
  if (!is_dir(dst) && !mkdirs(dst)) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
    return;
  }
  snprintf(dst, sizeof(dst), "%s/%s/%ld", work_path, target, id);
  if (rename(src, dst)) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
    return;
  }
  reply_map_id(out, cap, written, id, target);
}
static void work_perms(const char *work_path, const val *root, const rnc_identity *who, const group *g,
                        const repo *r, uint8_t *out, size_t cap, size_t *written) {
  char step[16], dir[PATH_MAX * 2], rootp[PATH_MAX * 2 + 8], allowed_path[PATH_MAX * 2 + 16];
  int read_access = allowed(who->hash, g, r, P_READ), write_access = allowed(who->hash, g, r, P_WRITE);
  int interact = allowed(who->hash, g, r, P_INTERACT), manage = interact && write_access;
  long id;
  doc d;
  int is_author, admin;
  if (!read_access) {
    reply(out, cap, written, GIT_RES_NOT_FOUND, "Not found");
    return;
  }
  if (!manage) {
    reply(out, cap, written, GIT_RES_DISALLOWED, "Not allowed");
    return;
  }
  if (!val_copy(map_get(root, "step"), step, sizeof(step))) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    return;
  }
  if (strcmp(step, "get") && strcmp(step, "set")) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid step");
    return;
  }
  if (!map_get(root, "doc_id") || map_get(root, "doc_id")->type == V_NIL) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "No document ID specified");
    return;
  }
  if (!doc_id_of(map_get(root, "doc_id"), &id)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid document ID");
    return;
  }
  if (find_doc(work_path, id, dir, sizeof(dir)) < 0) {
    reply(out, cap, written, GIT_RES_NOT_FOUND, "Document not found");
    return;
  }
  snprintf(rootp, sizeof(rootp), "%s/root", dir);
  if (!doc_load(rootp, &d)) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Error loading document");
    return;
  }
  is_author = doc_author_is(&d, who->hash);
  doc_free(&d);
  admin = doc_allowed(who->hash, g, r, work_path, id, P_ADMIN);
  if (!((is_author && manage) || admin)) {
    reply(out, cap, written, GIT_RES_DISALLOWED, "Not allowed");
    return;
  }
  snprintf(allowed_path, sizeof(allowed_path), "%s/%ld.allowed", work_path, id);
  if (!strcmp(step, "get"))
    perms_reply_content(out, cap, written, allowed_path);
  else {
    const val *cv = map_get(root, "content");
    char *text = calloc(1, (cv && val_is_text(cv) ? cv->n : 0) + 1), bad[200];
    int bad_line = 0;
    if (!text) {
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Error setting permissions");
      return;
    }
    if (cv && val_is_text(cv))
      memcpy(text, cv->p, cv->n);
    if (!valid_statements(text, &bad_line, bad, sizeof(bad))) {
      char msg[300];
      snprintf(msg, sizeof(msg), "Invalid permission \"%s\" on line %d", bad, bad_line);
      reply(out, cap, written, GIT_RES_INVALID_REQ, msg);
    } else if (!is_dir(work_path) && !mkdirs(work_path)) {
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Error setting permissions");
    } else if (!write_atomic(allowed_path, text, strlen(text)))
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Error setting permissions");
    else
      reply(out, cap, written, GIT_RES_OK, "");
    free(text);
  }
}
static rnc_result handle_work(void *context, const char *path, const uint8_t *request_data, size_t size,
                              const uint8_t *identity, uint8_t *out, size_t cap, size_t *written) {
  val *pool = malloc(POOL_NODES * sizeof(val)), root;
  const group *g;
  const repo *r;
  char operation[16], work_path[PATH_MAX + 16];
  int read_access, write_access, interact_access, propose_access, admin_access, access = 0;
  long doc_id = 0;
  int has_doc = 0;
  rnc_identity who;
  const val *dv;
  (void)context; (void)path;
  if (!pool)
    return RNC_NO_SPACE;
  if (!identity) {
    reply(out, cap, written, GIT_RES_DISALLOWED, "Not identified");
    goto done;
  }
  if (!parse_request(request_data, size, pool, &root)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    goto done;
  }
  if (!locate(&root, identity, &g, &r, out, cap, written))
    goto done;
  if (!val_copy(map_get(&root, "operation"), operation, sizeof(operation)) || !operation[0]) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    goto done;
  }
  read_access = r && allowed(identity, g, r, P_READ);
  write_access = r && allowed(identity, g, r, P_WRITE);
  interact_access = r && allowed(identity, g, r, P_INTERACT);
  propose_access = r && allowed(identity, g, r, P_PROPOSE);
  admin_access = r && allowed(identity, g, r, P_ADMIN);
  if (!read_access) {
    reply(out, cap, written, GIT_RES_NOT_FOUND, "Not found");
    goto done;
  }
  snprintf(work_path, sizeof(work_path), "%s.work", r->path);
  dv = map_get(&root, "doc_id");
  if (dv && !(dv->type == V_NIL || (dv->type == V_UINT && !dv->u) || (dv->type == V_BOOL && !dv->u))) {
    if (!doc_id_of(dv, &doc_id)) {
      if (!strcmp(operation, "read") || !strcmp(operation, "view") || !strcmp(operation, "comment") ||
          !strcmp(operation, "edit") || !strcmp(operation, "delete") || !strcmp(operation, "perms")) {
        reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
        goto done;
      }
    } else
      has_doc = 1;
  }
  if (has_doc && (!strcmp(operation, "read") || !strcmp(operation, "view") || !strcmp(operation, "comment") ||
                  !strcmp(operation, "edit") || !strcmp(operation, "delete") || !strcmp(operation, "perms"))) {
    read_access = doc_allowed(identity, g, r, work_path, doc_id, P_READ) || admin_access;
    if (!read_access) {
      reply(out, cap, written, GIT_RES_NOT_FOUND, "Document not found");
      goto done;
    }
  }
  if (has_doc && !strcmp(operation, "comment"))
    interact_access |= doc_allowed(identity, g, r, work_path, doc_id, P_INTERACT);
  if (has_doc && !strcmp(operation, "edit")) {
    interact_access |= doc_allowed(identity, g, r, work_path, doc_id, P_INTERACT);
    write_access |= doc_allowed(identity, g, r, work_path, doc_id, P_WRITE);
  }
  {
    int comment_access = interact_access && (read_access || write_access);
    int manage_access = interact_access && write_access;
    if (!strcmp(operation, "list") || !strcmp(operation, "view"))
      access = read_access;
    else if (!strcmp(operation, "comment"))
      access = comment_access;
    else if (!strcmp(operation, "propose"))
      access = propose_access;
    else if (!strcmp(operation, "create") || !strcmp(operation, "edit") || !strcmp(operation, "delete") ||
             !strcmp(operation, "complete") || !strcmp(operation, "activate"))
      access = manage_access;
    else if (!strcmp(operation, "perms"))
      access = admin_access;
  }
  if (!access) {
    reply(out, cap, written, GIT_RES_DISALLOWED, "Not allowed");
    goto done;
  }
  if (!caller_identity(&who)) {
    reply(out, cap, written, GIT_RES_DISALLOWED, "Not identified");
    goto done;
  }
  if (!strcmp(operation, "list"))
    work_list(work_path, &root, identity, g, r, out, cap, written);
  else if (!strcmp(operation, "view"))
    work_view(work_path, &root, out, cap, written);
  else if (!strcmp(operation, "comment"))
    work_comment(work_path, &root, &who, out, cap, written);
  else if (!strcmp(operation, "create"))
    work_new(work_path, &root, &who, 0, out, cap, written);
  else if (!strcmp(operation, "propose"))
    work_new(work_path, &root, &who, 1, out, cap, written);
  else if (!strcmp(operation, "edit"))
    work_edit(work_path, &root, &who, out, cap, written);
  else if (!strcmp(operation, "delete"))
    work_delete(work_path, &root, &who, g, r, out, cap, written);
  else if (!strcmp(operation, "complete"))
    work_move(work_path, &root, &who, g, r, 1, out, cap, written);
  else if (!strcmp(operation, "activate"))
    work_move(work_path, &root, &who, g, r, 0, out, cap, written);
  else if (!strcmp(operation, "perms"))
    work_perms(work_path, &root, &who, g, r, out, cap, written);
  else
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
done:
  free(pool);
  return RNC_OK;
}
#endif
