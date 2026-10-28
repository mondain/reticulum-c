/* Release management for reticulum-c-git (included by reticulum_git.c): the
 * /mgmt/release path of the reference. A release is a directory
 * NAME.releases/TAG with a META file (key = value lines like the reference's
 * ConfigObj), RELEASE.md or RELEASE.mu notes, THANKS and an artifacts/
 * directory; NAME.releases/latest names the latest published tag. */
#ifndef RETICULUM_C_RNGIT_RELEASE_H
#define RETICULUM_C_RNGIT_RELEASE_H
#include <dirent.h>

static int mkdirs(const char *path) {
  char tmp[PATH_MAX];
  char *p;
  if (snprintf(tmp, sizeof(tmp), "%s", path) >= (int)sizeof(tmp))
    return 0;
  for (p = tmp + 1; *p; ++p)
    if (*p == '/') {
      *p = 0;
      if (mkdir(tmp, 0755) && errno != EEXIST)
        return 0;
      *p = '/';
    }
  return !mkdir(tmp, 0755) || errno == EEXIST;
}
static int is_dir(const char *path) {
  struct stat st;
  return !stat(path, &st) && S_ISDIR(st.st_mode);
}
static int is_file(const char *path) {
  struct stat st;
  return !stat(path, &st) && S_ISREG(st.st_mode);
}
/* A tag or artifact name: one path component, nothing that climbs. */
static int plain_name(const char *s) {
  return s[0] && strcmp(s, ".") && strcmp(s, "..") && !strchr(s, '/');
}
static size_t read_small(const char *path, char *buf, size_t cap) {
  FILE *f = fopen(path, "rb");
  size_t n = 0;
  if (f) {
    n = fread(buf, 1, cap - 1, f);
    fclose(f);
  }
  buf[n] = 0;
  return n;
}
static char *rtrim_all(char *s) {
  char *e = s + strlen(s);
  while (e > s && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t'))
    *--e = 0;
  return s;
}

typedef struct meta {
  char tag[256], hash[128], status[32], created_by[64];
  long long created, published_at;
  int has_tag, has_hash;
} meta;
static int meta_read(const char *release_dir, meta *m) {
  char path[PATH_MAX + 16], line[1024];
  FILE *f;
  memset(m, 0, sizeof(*m));
  snprintf(path, sizeof(path), "%s/META", release_dir);
  f = fopen(path, "r");
  if (!f)
    return 0;
  while (fgets(line, sizeof(line), f)) {
    char *t = trim(line), *eq = strchr(t, '=');
    char *key, *value;
    size_t n;
    if (!eq || *t == '#')
      continue;
    *eq = 0;
    key = trim(t);
    value = trim(eq + 1);
    n = strlen(value);
    if (n >= 2 && ((value[0] == '"' && value[n - 1] == '"') || (value[0] == '\'' && value[n - 1] == '\''))) {
      value[n - 1] = 0;
      ++value;
    }
    if (!strcmp(key, "tag")) { snprintf(m->tag, sizeof(m->tag), "%s", value); m->has_tag = 1; }
    else if (!strcmp(key, "hash")) { snprintf(m->hash, sizeof(m->hash), "%s", value); m->has_hash = 1; }
    else if (!strcmp(key, "status")) snprintf(m->status, sizeof(m->status), "%s", value);
    else if (!strcmp(key, "created_by")) snprintf(m->created_by, sizeof(m->created_by), "%s", value);
    else if (!strcmp(key, "created")) m->created = strtoll(value, NULL, 10);
    else if (!strcmp(key, "published_at")) m->published_at = strtoll(value, NULL, 10);
  }
  fclose(f);
  return 1;
}
static void meta_quote(const char *v, char *out, size_t cap) {
  if (!*v || strpbrk(v, ",#\"'\n") || v[0] == ' ' || v[strlen(v) - 1] == ' ')
    snprintf(out, cap, "\"%s\"", v);
  else
    snprintf(out, cap, "%s", v);
}
static int meta_write(const char *release_dir, const meta *m) {
  char path[PATH_MAX + 16], text[2048], q[600];
  size_t n = 0;
  meta_quote(m->tag, q, sizeof(q));
  n += (size_t)snprintf(text + n, sizeof(text) - n, "tag = %s\n", q);
  if (m->has_hash && m->hash[0]) {
    meta_quote(m->hash, q, sizeof(q));
    n += (size_t)snprintf(text + n, sizeof(text) - n, "hash = %s\n", q);
  }
  n += (size_t)snprintf(text + n, sizeof(text) - n, "created = %lld\nstatus = %s\ncreated_by = %s\n",
                        m->created, m->status, m->created_by);
  if (m->published_at)
    n += (size_t)snprintf(text + n, sizeof(text) - n, "published_at = %lld\n", m->published_at);
  snprintf(path, sizeof(path), "%s/META", release_dir);
  return write_atomic(path, text, n);
}
static int latest_tag(const char *releases_path, char *out, size_t cap) {
  char path[PATH_MAX + 16];
  snprintf(path, sizeof(path), "%s/latest", releases_path);
  if (!is_file(path))
    return 0;
  read_small(path, out, cap);
  rtrim_all(out);
  return 1;
}
static int count_files(const char *dir, int dirs_too) {
  DIR *d = opendir(dir);
  struct dirent *e;
  int n = 0;
  if (!d)
    return 0;
  while ((e = readdir(d)) != NULL) {
    char full[PATH_MAX * 2];
    if (e->d_name[0] == '.')
      continue;
    snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
    if (is_file(full) || (dirs_too && is_dir(full)))
      n++;
  }
  closedir(d);
  return n;
}
/* the notes file of a release: its text and format */
static int read_notes(const char *release_dir, char *buf, size_t cap, const char **format, int with_txt) {
  static const char *const names[] = {"RELEASE.md", "RELEASE.mu", "RELEASE.txt"};
  static const char *const formats[] = {"markdown", "micron", "text"};
  size_t i;
  for (i = 0; i < (with_txt ? 3u : 2u); ++i) {
    char path[PATH_MAX + 16];
    snprintf(path, sizeof(path), "%s/%s", release_dir, names[i]);
    if (is_file(path)) {
      read_small(path, buf, cap);
      *format = formats[i];
      return 1;
    }
  }
  buf[0] = 0;
  return 0;
}
static int thanks_count(const char *release_dir) {
  char path[PATH_MAX + 16];
  uint8_t data[256];
  FILE *f;
  size_t n;
  val pool[8];
  reader rd;
  val v;
  const val *c;
  snprintf(path, sizeof(path), "%s/THANKS", release_dir);
  f = fopen(path, "rb");
  if (!f)
    return 0;
  n = fread(data, 1, sizeof(data), f);
  fclose(f);
  rd = (reader){data, data + n, pool, 0, 8};
  if (!parse(&rd, &v, 0) || !(c = map_get(&v, "count")))
    return 0;
  return (int)as_uint(c);
}
static void release_list(const char *releases_path, uint8_t *out, size_t cap, size_t *written) {
  DIR *d = opendir(releases_path);
  struct dirent *e;
  struct item {
    long long created;
    meta m;
    char preview[512], tag[256];
    const char *format;
    int artifacts;
  } *items = calloc(512, sizeof(struct item));
  size_t n = 0, i, k;
  mp_out o = {NULL, 0, 0, 0};
  uint8_t *body = malloc(1 << 20);
  char latest[256] = "";
  int has_latest = 0;
  if (!items || !body) {
    free(items); free(body);
    if (d) closedir(d);
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Error listing releases");
    return;
  }
  while (d && (e = readdir(d)) != NULL && n < 512) {
    char dir[PATH_MAX * 2], notes[8192], art[PATH_MAX * 2];
    struct item *it = &items[n];
    const char *fmt = "markdown";
    if (e->d_name[0] == '.')
      continue;
    snprintf(dir, sizeof(dir), "%s/%s", releases_path, e->d_name);
    if (!is_dir(dir) || !meta_read(dir, &it->m))
      continue;
    snprintf(it->tag, sizeof(it->tag), "%s", it->m.has_tag ? it->m.tag : e->d_name);
    if (!it->m.status[0])
      snprintf(it->m.status, sizeof(it->m.status), "unknown");
    it->created = it->m.created;
    it->preview[0] = 0;
    if (read_notes(dir, notes, sizeof(notes), &fmt, 1)) {
      /* the preview: lines that are neither headings nor quotes, trimmed */
      char *save = NULL, *line;
      size_t pn = 0;
      for (line = strtok_r(notes, "\n", &save); line; line = strtok_r(NULL, "\n", &save))
        if (line[0] != '#' && line[0] != '>' && pn + strlen(line) + 2 < sizeof(it->preview))
          pn += (size_t)snprintf(it->preview + pn, sizeof(it->preview) - pn, "%s\n", line);
      rtrim_all(it->preview);
      {
        char *s = it->preview;
        while (*s == ' ' || *s == '\n' || *s == '\t') ++s;
        memmove(it->preview, s, strlen(s) + 1);
      }
    }
    it->format = fmt;
    snprintf(art, sizeof(art), "%s/artifacts", dir);
    it->artifacts = count_files(art, 0);
    n++;
  }
  if (d)
    closedir(d);
  /* newest first */
  for (i = 0; i + 1 < n; ++i)
    for (k = i + 1; k < n; ++k)
      if (items[k].created > items[i].created) {
        struct item t = items[i];
        items[i] = items[k];
        items[k] = t;
      }
  if (latest_tag(releases_path, latest, sizeof(latest))) {
    for (i = 0; i < n; ++i)
      if (!strcmp(items[i].tag, latest) && !strcmp(items[i].m.status, "published"))
        has_latest = 1;
  }
  o = (mp_out){body, 1 << 20, 0, 0};
  mp_byte(&o, GIT_RES_OK);
  mp_map(&o, 2);
  mp_cstr(&o, "releases");
  mp_array(&o, n);
  for (i = 0; i < n; ++i) {
    mp_map(&o, 8);
    mp_cstr(&o, "tag"); mp_cstr(&o, items[i].tag);
    mp_cstr(&o, "hash"); mp_cstr(&o, items[i].m.hash);
    mp_cstr(&o, "created"); mp_uint(&o, (uint64_t)items[i].created);
    mp_cstr(&o, "status"); mp_cstr(&o, items[i].m.status);
    mp_cstr(&o, "created_by"); mp_cstr(&o, items[i].m.created_by);
    mp_cstr(&o, "preview"); mp_cstr(&o, items[i].preview);
    mp_cstr(&o, "format"); mp_cstr(&o, items[i].format);
    mp_cstr(&o, "artifacts"); mp_uint(&o, (uint64_t)items[i].artifacts);
  }
  mp_cstr(&o, "latest");
  if (has_latest)
    mp_cstr(&o, latest);
  else
    mp_nil(&o);
  if (o.failed) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Error listing releases");
  } else {
    mp_out w = {out, cap, 0, 0};
    mp_bin(&w, body, o.n);
    *written = w.failed ? 0 : w.n;
  }
  free(items);
  free(body);
}
static void reply_packed(uint8_t *out, size_t cap, size_t *written, const uint8_t *packed, size_t n) {
  /* a status byte 0 followed by the packed value, as one binary value */
  uint8_t *body = malloc(n + 1);
  mp_out w = {out, cap, 0, 0};
  if (!body) {
    *written = 0;
    return;
  }
  body[0] = GIT_RES_OK;
  memcpy(body + 1, packed, n);
  mp_bin(&w, body, n + 1);
  *written = w.failed ? 0 : w.n;
  free(body);
}
static int resolve_tag(const char *releases_path, const val *tag_v, char *tag, size_t cap,
                       uint8_t *out, size_t outcap, size_t *written) {
  if (!tag_v || !val_copy(tag_v, tag, cap) || !plain_name(tag)) {
    reply(out, outcap, written, GIT_RES_INVALID_REQ, "Invalid tag specified");
    return 0;
  }
  if (!strcmp(tag, "latest")) {
    if (!latest_tag(releases_path, tag, cap) || !*tag) {
      reply(out, outcap, written, GIT_RES_NOT_FOUND, "No latest release found");
      return 0;
    }
    if (!plain_name(tag)) {
      reply(out, outcap, written, GIT_RES_INVALID_REQ, "Invalid tag specified");
      return 0;
    }
  }
  return 1;
}
static rnc_result release_view(const char *releases_path, const val *root, uint8_t *out, size_t cap,
                               size_t *written) {
  char tag[256], dir[PATH_MAX * 2], notes[65536], art_dir[PATH_MAX * 2];
  const char *fmt = "text";
  meta m;
  uint8_t *body = malloc(1 << 20);
  mp_out o = {body, 1 << 20, 0, 0};
  DIR *d;
  struct dirent *e;
  size_t count = 0;
  struct { char name[300]; long long size; } *arts = calloc(512, sizeof(arts[0]));
  size_t i;
  if (!body || !arts) {
    free(body); free(arts);
    return RNC_NO_SPACE;
  }
  if (!resolve_tag(releases_path, map_get(root, "tag"), tag, sizeof(tag), out, cap, written))
    goto done;
  snprintf(dir, sizeof(dir), "%s/%s", releases_path, tag);
  if (!is_dir(dir)) {
    reply(out, cap, written, GIT_RES_NOT_FOUND, "Release not found");
    goto done;
  }
  if (!meta_read(dir, &m)) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Error getting release data");
    goto done;
  }
  if (!m.status[0])
    snprintf(m.status, sizeof(m.status), "unknown");
  read_notes(dir, notes, sizeof(notes), &fmt, 0);
  if (!notes[0])
    fmt = "text";
  snprintf(art_dir, sizeof(art_dir), "%s/artifacts", dir);
  d = opendir(art_dir);
  while (d && (e = readdir(d)) != NULL && count < 512) {
    char full[PATH_MAX * 3];
    struct stat st;
    if (e->d_name[0] == '.')
      continue;
    snprintf(full, sizeof(full), "%s/%s", art_dir, e->d_name);
    if (!stat(full, &st) && S_ISREG(st.st_mode)) {
      snprintf(arts[count].name, sizeof(arts[count].name), "%s", e->d_name);
      arts[count].size = (long long)st.st_size;
      count++;
    }
  }
  if (d)
    closedir(d);
  mp_byte(&o, GIT_RES_OK);
  mp_map(&o, 9);
  mp_cstr(&o, "tag"); mp_cstr(&o, m.has_tag ? m.tag : tag);
  mp_cstr(&o, "hash"); mp_cstr(&o, m.hash);
  mp_cstr(&o, "created"); mp_uint(&o, (uint64_t)m.created);
  mp_cstr(&o, "status"); mp_cstr(&o, m.status);
  mp_cstr(&o, "created_by"); mp_cstr(&o, m.created_by);
  mp_cstr(&o, "notes"); mp_cstr(&o, notes);
  mp_cstr(&o, "notes_format"); mp_cstr(&o, fmt);
  mp_cstr(&o, "artifacts");
  mp_array(&o, count);
  for (i = 0; i < count; ++i) {
    mp_map(&o, 2);
    mp_cstr(&o, "name"); mp_cstr(&o, arts[i].name);
    mp_cstr(&o, "size"); mp_uint(&o, (uint64_t)arts[i].size);
  }
  mp_cstr(&o, "thanks"); mp_uint(&o, (uint64_t)thanks_count(dir));
  if (o.failed) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Error getting release data");
  } else {
    mp_out w = {out, cap, 0, 0};
    mp_bin(&w, body, o.n);
    *written = w.failed ? 0 : w.n;
  }
done:
  free(body);
  free(arts);
  return RNC_OK;
}
static void release_fetch(const char *releases_path, const val *root, uint8_t *out, size_t cap,
                          size_t *written, rnc_responder_file *file) {
  char tag[256], artifact[300], path[PATH_MAX * 3];
  const val *a = map_get(root, "artifact");
  FILE *f;
  size_t got = 0, n;
  if (!resolve_tag(releases_path, map_get(root, "tag"), tag, sizeof(tag), out, cap, written))
    return;
  if (!a || !val_copy(a, artifact, sizeof(artifact)) || !plain_name(artifact)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid artifact specified");
    return;
  }
  snprintf(path, sizeof(path), "%s/%s", releases_path, tag);
  if (!is_dir(path)) {
    reply(out, cap, written, GIT_RES_NOT_FOUND, "Release not found");
    return;
  }
  snprintf(path, sizeof(path), "%s/%s/artifacts/%s", releases_path, tag, artifact);
  if (!is_file(path)) {
    reply(out, cap, written, GIT_RES_NOT_FOUND, "Artifact not found");
    return;
  }
  f = fopen(path, "rb");
  if (!f) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
    return;
  }
  while ((n = fread(file->data + got, 1, file->data_capacity - got, f)) > 0)
    got += n;
  if (!feof(f) || !got) {
    fclose(f);
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, got ? "Remote error" : "Artifact not found");
    return;
  }
  fclose(f);
  {
    mp_out m = {file->metadata, file->metadata_capacity, 0, 0};
    mp_map(&m, 1);
    mp_cstr(&m, "name");
    mp_bin(&m, artifact, strlen(artifact));
    if (m.failed) {
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
      return;
    }
    file->metadata_size = m.n;
  }
  file->data_size = got;
}
static void release_create(const char *releases_path, const char *repository_path, const val *root,
                           const uint8_t *identity, uint8_t *out, size_t cap, size_t *written) {
  char step[16], tag[256], dir[PATH_MAX * 2], path[PATH_MAX * 3];
  if (!val_copy(map_get(root, "step"), step, sizeof(step))) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    return;
  }
  if (!strcmp(step, "init")) {
    const val *hash = map_get(root, "hash"), *notes = map_get(root, "notes"), *nf = map_get(root, "notes_format");
    char ref[400], format[16] = "markdown", hex[33];
    meta m;
    if (!val_copy(map_get(root, "tag"), tag, sizeof(tag)) || !plain_name(tag)) {
      reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid tag specified");
      return;
    }
    snprintf(ref, sizeof(ref), "refs/tags/%s", tag);
    {
      char *check[] = {"git", "rev-parse", "--verify", ref, NULL};
      if (rngit_run(repository_path, check, NULL, 0, NULL).status != 0) {
        char msg[400];
        snprintf(msg, sizeof(msg), "Tag '%s' does not exist in repository", tag);
        reply(out, cap, written, GIT_RES_INVALID_REQ, msg);
        return;
      }
    }
    if (!is_dir(releases_path) && !mkdirs(releases_path)) {
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
      return;
    }
    snprintf(dir, sizeof(dir), "%s/%s", releases_path, tag);
    if (is_dir(dir)) {
      reply(out, cap, written, GIT_RES_DISALLOWED, "Release already exists");
      return;
    }
    snprintf(path, sizeof(path), "%s/artifacts", dir);
    if (!mkdirs(path)) {
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
      return;
    }
    memset(&m, 0, sizeof(m));
    snprintf(m.tag, sizeof(m.tag), "%s", tag);
    m.has_tag = 1;
    if (hash && val_is_text(hash) && hash->n && hash->n < sizeof(m.hash)) {
      memcpy(m.hash, hash->p, hash->n);
      m.hash[hash->n] = 0;
      m.has_hash = 1;
    }
    m.created = (long long)time(NULL);
    snprintf(m.status, sizeof(m.status), "draft");
    hex_string(identity, hex);
    snprintf(m.created_by, sizeof(m.created_by), "%s", hex);
    if (!meta_write(dir, &m)) {
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
      return;
    }
    if (nf && val_is_text(nf) && nf->n < sizeof(format)) {
      memcpy(format, nf->p, nf->n);
      format[nf->n] = 0;
    }
    if (notes && val_is_text(notes) && notes->n) {
      snprintf(path, sizeof(path), "%s/%s", dir, !strcmp(format, "micron") ? "RELEASE.mu" : "RELEASE.md");
      (void)write_atomic(path, (const char *)notes->p, notes->n);
    }
    {
      mp_out t = {malloc(32), 32, 0, 0};
      snprintf(path, sizeof(path), "%s/THANKS", dir);
      if (t.p) {
        mp_map(&t, 1);
        mp_cstr(&t, "count");
        mp_uint(&t, 0);
        (void)write_atomic(path, (const char *)t.p, t.n);
        free(t.p);
      }
    }
    log_line("Created release %s in draft status", tag);
    reply(out, cap, written, GIT_RES_OK, "");
  } else if (!strcmp(step, "artifact")) {
    const val *name_v = map_get(root, "artifact_name"), *data = map_get(root, "artifact_data");
    char name[300];
    meta m;
    if (!val_copy(map_get(root, "tag"), tag, sizeof(tag)) || !name_v || !val_copy(name_v, name, sizeof(name))) {
      reply(out, cap, written, GIT_RES_INVALID_REQ, "Missing tag or artifact name");
      return;
    }
    if (strchr(tag, '/')) {
      reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid tag specified");
      return;
    }
    if (!data || data->type == V_NIL) {
      reply(out, cap, written, GIT_RES_INVALID_REQ, "No artifact data");
      return;
    }
    if (!plain_name(tag) || !plain_name(name) || !val_is_text(data)) {
      reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
      return;
    }
    snprintf(dir, sizeof(dir), "%s/%s", releases_path, tag);
    if (!is_dir(dir)) {
      reply(out, cap, written, GIT_RES_NOT_FOUND, "Release not found");
      return;
    }
    if (!meta_read(dir, &m) || strcmp(m.status, "draft")) {
      reply(out, cap, written, GIT_RES_DISALLOWED, "Release was finalized and is not writable");
      return;
    }
    snprintf(path, sizeof(path), "%s/artifacts", dir);
    if (!is_dir(path) && !mkdirs(path)) {
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
      return;
    }
    snprintf(path, sizeof(path), "%s/artifacts/%s", dir, name);
    {
      FILE *f = fopen(path, "wb");
      int ok = f && fwrite(data->p, 1, data->n, f) == data->n;
      if (f)
        ok = fclose(f) == 0 && ok;
      if (!ok) {
        reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
        return;
      }
    }
    reply(out, cap, written, GIT_RES_OK, "");
  } else if (!strcmp(step, "finalize")) {
    meta m;
    if (!val_copy(map_get(root, "tag"), tag, sizeof(tag)) || !tag[0]) {
      reply(out, cap, written, GIT_RES_INVALID_REQ, "No tag specified");
      return;
    }
    if (strchr(tag, '/') || !plain_name(tag)) {
      reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid tag specified");
      return;
    }
    snprintf(dir, sizeof(dir), "%s/%s", releases_path, tag);
    if (!is_dir(dir)) {
      reply(out, cap, written, GIT_RES_NOT_FOUND, "Release not found");
      return;
    }
    if (!meta_read(dir, &m) || strcmp(m.status, "draft")) {
      reply(out, cap, written, GIT_RES_DISALLOWED, "Release was finalized and is not writable");
      return;
    }
    snprintf(m.status, sizeof(m.status), "published");
    m.published_at = (long long)time(NULL);
    if (!meta_write(dir, &m)) {
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
      return;
    }
    snprintf(path, sizeof(path), "%s/latest", releases_path);
    (void)write_atomic(path, tag, strlen(tag));
    reply(out, cap, written, GIT_RES_OK, "");
  } else
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
}
static void release_simple(const char *releases_path, const val *root, int is_delete, uint8_t *out,
                           size_t cap, size_t *written) {
  char tag[256], dir[PATH_MAX * 2], path[PATH_MAX * 3];
  if (!val_copy(map_get(root, "tag"), tag, sizeof(tag)) || !tag[0]) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "No tag specified");
    return;
  }
  /* stricter than the reference, which would remove the parent of the
   * releases directory for the tag ".." */
  if (!plain_name(tag)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid tag specified");
    return;
  }
  snprintf(dir, sizeof(dir), "%s/%s", releases_path, tag);
  if (!is_dir(dir)) {
    reply(out, cap, written, GIT_RES_NOT_FOUND, "Release not found");
    return;
  }
  if (is_delete) {
    remove_tree(dir);
    log_line("Deleted release %s from %s", tag, releases_path);
    reply(out, cap, written, GIT_RES_OK, "");
  } else {
    snprintf(path, sizeof(path), "%s/latest", releases_path);
    if (!write_atomic(path, tag, strlen(tag)))
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
    else
      reply(out, cap, written, GIT_RES_OK, "");
  }
}
static rnc_result handle_release(void *context, const char *path, const uint8_t *request_data,
                                 size_t size, const uint8_t *identity, uint8_t *out, size_t cap,
                                 size_t *written, rnc_responder_file *file) {
  val *pool = malloc(POOL_NODES * sizeof(val)), root;
  const group *g;
  const repo *r;
  char operation[16], releases_path[PATH_MAX + 16];
  int read_access, release_access, access;
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
  if (!val_copy(map_get(&root, "operation"), operation, sizeof(operation))) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    goto done;
  }
  read_access = r && allowed(identity, g, r, P_READ);
  release_access = r && allowed(identity, g, r, P_RELEASE);
  if (!read_access) {
    reply(out, cap, written, GIT_RES_NOT_FOUND, "Not found");
    goto done;
  }
  if (!strcmp(operation, "create") || !strcmp(operation, "delete") || !strcmp(operation, "latest"))
    access = release_access;
  else if (!strcmp(operation, "list") || !strcmp(operation, "view") || !strcmp(operation, "fetch"))
    access = 1;
  else
    access = 0;
  if (!access) {
    reply(out, cap, written, GIT_RES_DISALLOWED, "Not allowed");
    goto done;
  }
  snprintf(releases_path, sizeof(releases_path), "%s.releases", r->path);
  if (!strcmp(operation, "list")) {
    if (!is_dir(releases_path)) {
      uint8_t empty[1] = {0x90};
      reply_packed(out, cap, written, empty, 1);
    } else
      release_list(releases_path, out, cap, written);
  } else if (!strcmp(operation, "view"))
    (void)release_view(releases_path, &root, out, cap, written);
  else if (!strcmp(operation, "fetch"))
    release_fetch(releases_path, &root, out, cap, written, file);
  else if (!strcmp(operation, "create"))
    release_create(releases_path, r->path, &root, identity, out, cap, written);
  else if (!strcmp(operation, "delete"))
    release_simple(releases_path, &root, 1, out, cap, written);
  else
    release_simple(releases_path, &root, 0, out, cap, written);
done:
  free(pool);
  return RNC_OK;
}
#endif
