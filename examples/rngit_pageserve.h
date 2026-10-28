/* Request handlers and set-up of the page server (included by reticulum_git.c
 * after rngit_pageviews.h): the response generators registered by pages.py's
 * register_request_handlers, the file serving paths (artifact, media, download,
 * work document download) and the registration of the nomadnetwork.node
 * destination. */
#ifndef RETICULUM_C_RNGIT_PAGESERVE_H
#define RETICULUM_C_RNGIT_PAGESERVE_H

typedef void (*pg_fn)(pgreq *, sbuf *);
static rnc_result pg_serve(pg_fn fn, const uint8_t *data, size_t size, const uint8_t *identity, uint8_t *out, size_t cap,
                           size_t *written) {
  pgreq rq;
  sbuf page;
  mp_out o = {out, cap, 0, 0};
  *written = 0;
  if (!pg_req_open(&rq, data, size, identity)) {
    pg_req_close(&rq);
    return RNC_NO_SPACE;
  }
  sb_init(&page);
  page.limit = cap > 64 ? (cap - 64 < SBUF_LIMIT ? cap - 64 : SBUF_LIMIT) : 0;
  fn(&rq, &page);
  if (page.over)
    log_line("A page was cut at %zu bytes", page.limit);
  mp_bin(&o, sb_str(&page), page.n);
  *written = o.failed ? 0 : o.n;
  sb_free(&page);
  pg_req_close(&rq);
  return o.failed ? RNC_NO_SPACE : RNC_OK;
}
#define PG_HANDLER(name, fn)                                                                                   \
  static rnc_result name(void *context, const char *path, const uint8_t *request_data, size_t size,           \
                         const uint8_t *identity, uint8_t *out, size_t cap, size_t *written) {                \
    (void)context;                                                                                             \
    (void)path;                                                                                                \
    return pg_serve(fn, request_data, size, identity, out, cap, written);                                     \
  }
static void pg_front_w(pgreq *rq, sbuf *page) { pg_front(rq, page); }
static void pg_group_w(pgreq *rq, sbuf *page) { pg_group(rq, page); }
PG_HANDLER(pg_h_index, pg_front_w)
PG_HANDLER(pg_h_group, pg_group_w)
PG_HANDLER(pg_h_repo, pg_repo_page)
PG_HANDLER(pg_h_tree, pg_tree_page)
PG_HANDLER(pg_h_blob, pg_blob_page)
PG_HANDLER(pg_h_commits, pg_commits_page)
PG_HANDLER(pg_h_commit, pg_commit_page)
PG_HANDLER(pg_h_refs, pg_refs_page)
PG_HANDLER(pg_h_stats, pg_stats_page)
PG_HANDLER(pg_h_releases, pg_releases_page)
PG_HANDLER(pg_h_release, pg_release_page)
PG_HANDLER(pg_h_work, pg_work_page)
PG_HANDLER(pg_h_work_doc, pg_work_doc_page)

/* ---- file responses -------------------------------------------------------- */
/* the {"name": bytes} metadata of a file response */
static int pg_file_meta(rnc_responder_file *file, const char *name) {
  mp_out o = {file->metadata, file->metadata_capacity, 0, 0};
  mp_map(&o, 1);
  mp_cstr(&o, "name");
  mp_bin(&o, name, strlen(name));
  if (o.failed)
    return 0;
  file->metadata_size = o.n;
  return 1;
}
/* False: the msgpack false; the reference returns it for a refused media request */
static rnc_result pg_reply_false(uint8_t *out, size_t cap, size_t *written) {
  if (cap < 1)
    return RNC_AGAIN;
  out[0] = 0xc2;
  *written = 1;
  return RNC_OK;
}
/* the whole content of a file into the response buffer; 0 when too large */
static int pg_load_file(const char *path, rnc_responder_file *file) {
  FILE *f = fopen(path, "rb");
  size_t n;
  if (!f)
    return 0;
  n = fread(file->data, 1, file->data_capacity, f);
  if (n == file->data_capacity && fgetc(f) != EOF) {
    fclose(f);
    log_line("File %s is larger than the response limit, not served", path);
    return 0;
  }
  fclose(f);
  file->data_size = n;
  return n > 0;
}
/* a blob of the repository into the response buffer */
static int pg_load_blob(const repo *r, const char *resolved, const char *file_path, long long size, rnc_responder_file *file) {
  char stripped[3100], spec[3300];
  char *argv[] = {"git", "show", spec, NULL};
  size_t n = 0;
  proc_result pr;
  if (size < 0 || (size_t)size >= file->data_capacity) {
    log_line("Blob %s is larger than the response limit, not served", file_path);
    return 0;
  }
  pgit_strip_slashes(file_path, stripped, sizeof(stripped));
  pgit_spec(spec, sizeof(spec), resolved, stripped);
  rngit_run_timeout_ms = 0;
  pr = rngit_run(r->path, argv, (char *)file->data, file->data_capacity, &n);
  if (pr.status != 0)
    return 0;
  file->data_size = n;
  return n > 0;
}

static rnc_result pg_h_artifact(void *context, const char *path, const uint8_t *request_data, size_t size, const uint8_t *identity,
                                uint8_t *out, size_t cap, size_t *written, rnc_responder_file *file) {
  pgreq rq;
  pgctx c;
  char tag[300], artifact[300], rpath[PATH_MAX + 16], release_dir[PATH_MAX * 2 + 8], art_path[PATH_MAX * 3 + 32];
  const repo *r;
  meta m;
  rnc_result res = RNC_AGAIN;
  (void)context;
  (void)path;
  (void)out;
  (void)cap;
  (void)written;
  if (!pg_req_open(&rq, request_data, size, identity)) {
    pg_req_close(&rq);
    return RNC_NO_SPACE;
  }
  pg_get(&rq, "var_g", c.gname, sizeof(c.gname), "");
  pg_get(&rq, "var_r", c.rname, sizeof(c.rname), "");
  pg_get(&rq, "var_t", tag, sizeof(tag), "");
  pg_get(&rq, "var_a", artifact, sizeof(artifact), "");
  url_unquote_plus(artifact);
  if (strchr(artifact, '/'))
    goto done;
  r = pg_accessible_repo(&rq, c.gname, c.rname, &c.g);
  if (!r)
    goto done;
  snprintf(rpath, sizeof(rpath), "%s.releases", r->path);
  if (!pg_resolve_tag(rpath, tag, sizeof(tag), NULL))
    goto done;
  if (!plain_name(tag) || !plain_name(artifact))
    goto done;
  snprintf(release_dir, sizeof(release_dir), "%s/%s", rpath, tag);
  if (!meta_read(release_dir, &m) || strcmp(m.status[0] ? m.status : "unknown", "published"))
    goto done;
  snprintf(art_path, sizeof(art_path), "%s/artifacts/%s", release_dir, artifact);
  if (!is_dir(release_dir) || !is_file(art_path))
    goto done;
  if (!pg_load_file(art_path, file) || !pg_file_meta(file, artifact)) {
    file->data_size = 0;
    goto done;
  }
  stats_release_download_succeeded(c.gname, c.rname, identity);
  res = RNC_OK;
done:
  pg_req_close(&rq);
  return res;
}

static rnc_result pg_h_media(void *context, const char *path, const uint8_t *request_data, size_t size, const uint8_t *identity,
                             uint8_t *out, size_t cap, size_t *written, rnc_responder_file *file) {
  pgreq rq;
  char media_path[3400], *comps[8], *p, file_path[3300], resolved[72], ext[32], spec[3500];
  size_t nc = 0;
  const repo *r;
  const group *g;
  blob_info bi;
  rnc_result res = RNC_AGAIN;
  int fail_false = 0;
  (void)context;
  (void)path;
  if (!pg_req_open(&rq, request_data, size, identity)) {
    pg_req_close(&rq);
    return RNC_NO_SPACE;
  }
  if (!rq.is_map || !map_get(&rq.root, "key") || !map_get(&rq.root, "path")) {
    fail_false = 1;
    goto done;
  }
  pg_get(&rq, "path", media_path, sizeof(media_path), "");
  if (!media_path[0]) {
    fail_false = 1;
    goto done;
  }
  /* removeprefix("/media").lstrip("/").split("/") */
  p = media_path;
  if (starts_with(p, "/media"))
    p += 6;
  while (*p == '/')
    ++p;
  {
    char *start = p, *slash;
    for (;;) {
      slash = nc < 3 ? strchr(start, '/') : NULL;
      if (slash)
        *slash = 0;
      comps[nc++] = start;
      if (!slash)
        break;
      start = slash + 1;
    }
  }
  if (nc < 4) {
    fail_false = 1;
    goto done;
  }
  snprintf(file_path, sizeof(file_path), "%s", comps[3]);
  url_unquote_plus(file_path);
  r = pg_accessible_repo(&rq, comps[0], comps[1], &g);
  if (!r || !pgit_resolve(r->path, comps[2], resolved) || !file_path[0] || !pgit_blob_info(r->path, resolved, file_path, &bi)) {
    fail_false = 1;
    goto done;
  }
  pg_ext(file_path, ext, sizeof(ext));
  if (G.media_conversion && pg_is_image_ext(ext) && strcmp(ext, ".webp")) {
    char stripped[3100], name[300], *stem, *slash;
    char *argv[] = {"git", "show", spec, NULL};
    size_t n = 0;
    pgit_strip_slashes(file_path, stripped, sizeof(stripped));
    pgit_spec(spec, sizeof(spec), resolved, stripped);
    if (mc_convert_to_webp(argv, r->path, file->data, file->data_capacity, &n)) {
      slash = strrchr(stripped, '/');
      snprintf(name, sizeof(name), "%s", slash ? slash + 1 : stripped);
      stem = strrchr(name, '.');
      if (stem && stem != name)
        *stem = 0;
      strncat(name, ".webp", sizeof(name) - strlen(name) - 1);
      if (pg_file_meta(file, name)) {
        file->data_size = n;
        res = RNC_OK;
        goto done;
      }
    }
  }
  if (!pg_load_blob(r, resolved, file_path, bi.size, file)) {
    file->data_size = 0;
    goto done;
  }
  {
    const char *slash = strrchr(file_path, '/');
    if (!pg_file_meta(file, slash ? slash + 1 : file_path)) {
      file->data_size = 0;
      goto done;
    }
  }
  res = RNC_OK;
done:
  pg_req_close(&rq);
  if (fail_false)
    return pg_reply_false(out, cap, written);
  return res;
}

static rnc_result pg_h_download(void *context, const char *path, const uint8_t *request_data, size_t size, const uint8_t *identity,
                                uint8_t *out, size_t cap, size_t *written, rnc_responder_file *file) {
  pgreq rq;
  pgctx c;
  char file_path[3100], fmt[16], resolved[72], ext[32];
  const repo *r;
  blob_info bi;
  rnc_result res = RNC_AGAIN;
  (void)context;
  (void)path;
  (void)out;
  (void)cap;
  (void)written;
  if (!pg_req_open(&rq, request_data, size, identity)) {
    pg_req_close(&rq);
    return RNC_NO_SPACE;
  }
  pg_get(&rq, "var_g", c.gname, sizeof(c.gname), "");
  pg_get(&rq, "var_r", c.rname, sizeof(c.rname), "");
  pg_get(&rq, "var_ref", c.ref, sizeof(c.ref), "HEAD");
  pg_get(&rq, "var_fmt", fmt, sizeof(fmt), "");
  pg_get(&rq, "var_path", file_path, sizeof(file_path), "");
  url_unquote_plus(file_path);
  pg_ext(file_path, ext, sizeof(ext));
  if (fmt[0] && strcmp(ext, ".md"))
    goto done;
  r = pg_accessible_repo(&rq, c.gname, c.rname, &c.g);
  if (!r || !pgit_resolve(r->path, c.ref, resolved) || !file_path[0] || !pgit_blob_info(r->path, resolved, file_path, &bi))
    goto done;
  {
    const char *slash = strrchr(file_path, '/'), *base = slash ? slash + 1 : file_path;
    if (!fmt[0]) {
      if (!pg_load_blob(r, resolved, file_path, bi.size, file) || !pg_file_meta(file, base)) {
        file->data_size = 0;
        goto done;
      }
      stats_download_succeeded(c.gname, c.rname, identity);
      res = RNC_OK;
    } else if (!strcmp(fmt, "mu")) {
      /* the reference counts the download before it converts */
      char name[300], *dot;
      sbuf mu, upd;
      md_conv mc;
      char scope[3600], *text;
      size_t n;
      if (!pg_load_blob(r, resolved, file_path, bi.size, file)) {
        file->data_size = 0;
        goto done;
      }
      stats_download_succeeded(c.gname, c.rname, identity);
      text = md_dup((const char *)file->data, file->data_size);
      file->data_size = 0;
      if (!text || !pgit_utf8_valid(text, strlen(text))) {
        free(text);
        goto done;
      }
      (void)n;
      pg_universal_newlines(text);
      pg_blob_scope(scope, sizeof(scope), c.gname, c.rname, c.ref, file_path);
      md_init(&mc, PG_MAX_RENDER_WIDTH, scope);
      sb_init(&mu);
      sb_init(&upd);
      md_format_block(&mc, text, &mu);
      free(text);
      if (mu.p) {
        py_rstrip(mu.p);
        mu.n = strlen(mu.p);
      }
      if (!mu.n || mu.n > file->data_capacity) {
        sb_free(&mu);
        sb_free(&upd);
        goto done;
      }
      memcpy(file->data, mu.p, mu.n);
      file->data_size = mu.n;
      sb_free(&mu);
      sb_free(&upd);
      snprintf(name, sizeof(name), "%s", base);
      dot = strrchr(name, '.');
      if (dot && dot != name)
        *dot = 0;
      strncat(name, ".mu", sizeof(name) - strlen(name) - 1);
      if (!pg_file_meta(file, name)) {
        file->data_size = 0;
        goto done;
      }
      res = RNC_OK;
    }
  }
done:
  pg_req_close(&rq);
  return res;
}

/* serve_wd_download: the answer is the plain list [file name, content] */
static rnc_result pg_h_wd_download(void *context, const char *path, const uint8_t *request_data, size_t size, const uint8_t *identity,
                                   uint8_t *out, size_t cap, size_t *written) {
  pgreq rq;
  pgctx c;
  char id_s[64], scope[32], work_path[PATH_MAX + 16], doc_dir[PATH_MAX * 2 + 32], rp[PATH_MAX * 2 + 48], *end;
  long doc_id;
  const repo *r;
  doc dc;
  rnc_result res = RNC_AGAIN;
  (void)context;
  (void)path;
  *written = 0;
  if (!pg_req_open(&rq, request_data, size, identity)) {
    pg_req_close(&rq);
    return RNC_NO_SPACE;
  }
  pg_get(&rq, "var_g", c.gname, sizeof(c.gname), "");
  pg_get(&rq, "var_r", c.rname, sizeof(c.rname), "");
  pg_get(&rq, "var_id", id_s, sizeof(id_s), "");
  pg_get(&rq, "var_scope", scope, sizeof(scope), "all");
  if (strcmp(scope, "active") && strcmp(scope, "completed") && strcmp(scope, "all"))
    snprintf(scope, sizeof(scope), "active");
  if (!c.gname[0] || !c.rname[0] || !id_s[0])
    goto done;
  {
    char *s = py_strip(id_s);
    doc_id = strtol(s, &end, 10);
    if (end == s || *end || doc_id < 0 || doc_id > 999999999L)
      goto done;
  }
  r = pg_accessible_repo(&rq, c.gname, c.rname, &c.g);
  if (!r)
    goto done;
  snprintf(work_path, sizeof(work_path), "%s.work", r->path);
  if (!doc_allowed(pg_eff(&rq), c.g, r, work_path, doc_id, P_READ))
    goto done;
  pg_doc_dir(work_path, doc_id, scope, sizeof(scope), doc_dir, sizeof(doc_dir));
  snprintf(rp, sizeof(rp), "%s/root", doc_dir);
  if (!is_file(rp) || !doc_load(rp, &dc))
    goto done;
  {
    const val *meta = doc_meta(&dc), *cv = map_get(&dc.root, "content"), *tv = map_get(meta, "title"), *fv = map_get(meta, "format");
    char title[2048], fmt[32], name[2100];
    char *text = md_dup(cv && val_is_text(cv) ? (const char *)cv->p : "", cv && val_is_text(cv) ? cv->n : 0), *stripped;
    if (!tv || tv->type == V_NIL)
      snprintf(title, sizeof(title), "Untitled");
    else if (!val_copy(tv, title, sizeof(title)))
      title[0] = 0;
    title[u8_prefix(title, 256)] = 0;
    if (!fv || !val_copy(fv, fmt, sizeof(fmt)))
      snprintf(fmt, sizeof(fmt), "markdown");
    if (text) {
      stripped = py_strip(text);
      if (*stripped) {
        mp_out o = {out, cap, 0, 0};
        snprintf(name, sizeof(name), "%s%s", title, !strcmp(fmt, "micron") ? ".mu" : ".md");
        stats_download_succeeded(c.gname, c.rname, identity);
        mp_array(&o, 2);
        mp_cstr(&o, name);
        mp_bin(&o, stripped, strlen(stripped));
        if (!o.failed) {
          *written = o.n;
          res = RNC_OK;
        }
      }
      free(text);
    }
    doc_free(&dc);
  }
done:
  pg_req_close(&rq);
  return res;
}

/* ---- set-up ------------------------------------------------------------------ */
/* the reference's defaults of the page server and the statistics */
static void pages_defaults(void) {
  snprintf(G.node_name, sizeof(G.node_name), "Anonymous Git Node");
  G.use_nerdfonts = 1;
  G.media_conversion = 1;
  G.highlight_syntax = 1;
}
/* the node of the page server: its destination on the identity, announced with
 * the node name as app data, and the request handlers */
static int pages_setup(void) {
  char dir[PATH_MAX + 32];
  rnc_result r = RNC_OK;
  size_t nn = strlen(G.node_name);
  snprintf(dir, sizeof(dir), "%s/templates", G.config_dir);
  if (!is_dir(dir) && !mkdirs(dir))
    log_line("Could not create templates directory %s", dir);
  if (nn > 316)
    nn = 316;
  if (rnc_node_add_destination(G.net.node, &G.net.id, PG_NODE_APP, G.node_name, nn, pg_node_dest) != RNC_OK)
    return 0;
  if (rnc_responder_add_destination(G.net.responder, &G.net.id, pg_node_dest) != RNC_OK)
    return 0;
#define PGREG(p, h) \
  if (r == RNC_OK)  \
    r = rnc_responder_register(G.net.responder, pg_node_dest, p, RNC_SERVICE_ALLOW_ALL, NULL, 0, h, NULL);
#define PGREGF(p, h) \
  if (r == RNC_OK)   \
    r = rnc_responder_register_file(G.net.responder, pg_node_dest, p, RNC_SERVICE_ALLOW_ALL, NULL, 0, h, NULL);
  PGREG("/page/index.mu", pg_h_index)
  PGREG("/page/group.mu", pg_h_group)
  PGREG("/page/repo.mu", pg_h_repo)
  PGREG("/page/tree.mu", pg_h_tree)
  PGREG("/page/blob.mu", pg_h_blob)
  PGREG("/page/commits.mu", pg_h_commits)
  PGREG("/page/commit.mu", pg_h_commit)
  PGREG("/page/refs.mu", pg_h_refs)
  PGREG("/page/stats.mu", pg_h_stats)
  PGREG("/page/releases.mu", pg_h_releases)
  PGREG("/page/release.mu", pg_h_release)
  PGREG("/page/work.mu", pg_h_work)
  PGREG("/page/work_doc.mu", pg_h_work_doc)
  PGREGF("/media", pg_h_media)
  PGREGF("/file/artifact", pg_h_artifact)
  PGREGF("/file/download", pg_h_download)
  PGREG("/file/workdoc", pg_h_wd_download)
#undef PGREG
#undef PGREGF
  return r == RNC_OK;
}

#endif
