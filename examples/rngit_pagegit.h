/* Git data extraction for the page server of reticulum-c-git (included by
 * reticulum_git.c): the "Git Data Extraction" half of pages.py. Every git
 * invocation is an argument vector run by rngit_run (never a shell), with the
 * reference's 8 second command limit; refs and paths that come from a request
 * are checked before they reach an argument. */
#ifndef RETICULUM_C_RNGIT_PAGEGIT_H
#define RETICULUM_C_RNGIT_PAGEGIT_H

#define PG_GIT_TIMEOUT_MS 8000u
#define PG_BLOB_LIMIT (256u * 1024u)
#define PG_TREE_ENTRIES_PER_PAGE 1000u
#define PG_COMMITS_PER_PAGE 100u
#define PG_TREE_PARSE_MAX 20000u
#define PG_OUT_MAX (4u << 20)
#define PG_DIFF_MAX (512u << 10)
#define PG_FILES_MAX 400u

/* Python's text mode reads translate "\r\n" and "\r" to "\n" */
static size_t pgit_universal_newlines(char *s, size_t n) {
  size_t i, w = 0;
  for (i = 0; i < n; ++i) {
    if (s[i] == '\r') {
      s[w++] = '\n';
      if (i + 1 < n && s[i + 1] == '\n')
        ++i;
    } else
      s[w++] = s[i];
  }
  s[w] = 0;
  return w;
}
/* git with the command limit; stdout goes into a fresh buffer of up to cap
 * bytes (NULL out: discarded). Returns 1 when git exited 0. */
static int pgit_run(const char *repo_path, char *const *argv, char **out, size_t cap, size_t *n_out) {
  proc_result r;
  size_t n = 0;
  char *buf = NULL;
  if (out) {
    buf = malloc(cap + 1);
    if (!buf)
      return 0;
    *out = buf;
  }
  rngit_run_timeout_ms = PG_GIT_TIMEOUT_MS;
  r = rngit_run(repo_path, argv, buf, buf ? cap + 1 : 0, &n);
  if (buf && r.status == 0)
    n = pgit_universal_newlines(buf, n);
  if (n_out)
    *n_out = n;
  if (r.status != 0 && buf) {
    free(buf);
    *out = NULL;
  }
  return r.status == 0;
}
static int pgit_ok(const char *repo_path, char *const *argv) { return pgit_run(repo_path, argv, NULL, 0, NULL); }
static int pgit_text_ok(const char *s) { return s && !strchr(s, '\n') && s[0] != '-' && strlen(s) < 900; }

/* a path inside a tree: nothing that climbs or names a directory twice */
static int pgit_path_ok(const char *p) {
  const char *c = p;
  if (strlen(p) >= 3000)
    return 0;
  while (*c) {
    const char *e = strchr(c, '/');
    size_t l = e ? (size_t)(e - c) : strlen(c);
    if ((l == 1 && c[0] == '.') || (l == 2 && c[0] == '.' && c[1] == '.'))
      return 0;
    if (!e)
      break;
    c = e + 1;
  }
  return 1;
}

/* resolve_ref: the full lower case hash of a ref, or 0 */
static int pgit_resolve(const char *repo_path, const char *ref, char out[72]) {
  char *argv[] = {"git", "rev-parse", "--verify", (char *)ref, NULL}, *text;
  size_t n, i;
  if (!ref[0] || !pgit_text_ok(ref) || strchr(ref, '\r'))
    return 0;
  if (!pgit_run(repo_path, argv, &text, 512, &n))
    return 0;
  {
    char *s = py_strip(text);
    size_t l = strlen(s);
    if (l < 40 || l > 64 || (l & 1u)) {
      free(text);
      return 0;
    }
    for (i = 0; i < l; ++i) {
      char c = s[i];
      if (c >= 'A' && c <= 'F')
        c = (char)(c + 32);
      if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
        free(text);
        return 0;
      }
      out[i] = c;
    }
    out[l] = 0;
  }
  free(text);
  return 1;
}

/* get_repository_description */
static int pgit_description(const char *repo_path, char *out, size_t cap) {
  char *argv[] = {"git", "config", "--get", "repository.description", NULL}, *text;
  char path[PATH_MAX + 32];
  if (pgit_run(repo_path, argv, &text, 4096, NULL)) {
    char *s = py_strip(text);
    if (*s) {
      snprintf(out, cap, "%s", s);
      free(text);
      return 1;
    }
    free(text);
  }
  snprintf(path, sizeof(path), "%s.description", repo_path);
  if (is_file(path)) {
    char buf[4096];
    read_small(path, buf, sizeof(buf));
    if (*py_strip(buf)) {
      snprintf(out, cap, "%s", py_strip(buf));
      return 1;
    }
  }
  return 0;
}

/* get_repository_refs: only the counts the repository page shows */
static void pgit_ref_counts(const char *repo_path, int *heads, int *tags) {
  char *argv[] = {"git", "for-each-ref", "--format", "%(objectname) %(refname) %(refname:short)", "refs/heads",
                  "refs/tags", NULL}, *text, *save = NULL, *line;
  *heads = *tags = 0;
  if (!pgit_run(repo_path, argv, &text, PG_OUT_MAX, NULL))
    return;
  for (line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
    const char *sp = strchr(line, ' ');
    if (!sp)
      continue;
    if (starts_with(sp + 1, "refs/heads/"))
      ++*heads;
    else if (starts_with(sp + 1, "refs/tags/"))
      ++*tags;
  }
  free(text);
}
static long pgit_commit_count(const char *repo_path, const char *ref) {
  char *argv[] = {"git", "rev-list", "--count", (char *)ref, NULL}, *text;
  long n = 0;
  if (pgit_run(repo_path, argv, &text, 64, NULL)) {
    n = strtol(py_strip(text), NULL, 10);
    free(text);
  }
  return n;
}
/* get_readme_content: first match wins; returns a malloc'd text or NULL */
static char *pgit_readme(const char *repo_path, int *is_markdown) {
  static const struct {
    const char *name;
    int md;
  } names[] = {{"README.mu", 0}, {"Readme.mu", 0}, {"readme.mu", 0}, {"README", 0},     {"readme", 0},
               {"README.md", 1}, {"readme.md", 1}, {"README.rst", 0}, {"README.txt", 0}, {"readme.rst", 0},
               {"readme.txt", 0}};
  size_t i;
  for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    char spec[64], *text;
    char *argv[] = {"git", "show", spec, NULL};
    snprintf(spec, sizeof(spec), "HEAD:%s", names[i].name);
    if (pgit_run(repo_path, argv, &text, PG_OUT_MAX, NULL)) {
      *is_markdown = names[i].md;
      return text;
    }
  }
  *is_markdown = 0;
  return NULL;
}

/* ---- blobs --------------------------------------------------------------- */
typedef struct blob_info {
  long long size;
  int is_tree, is_binary, is_symlink;
  char symlink_target[1024];
} blob_info;
static void pgit_spec(char *out, size_t cap, const char *ref, const char *path) {
  snprintf(out, cap, "%s:%s", ref, path);
}
/* the path with the surrounding slashes removed (path.strip("/")) */
static void pgit_strip_slashes(const char *in, char *out, size_t cap) {
  size_t n;
  while (*in == '/')
    ++in;
  snprintf(out, cap, "%s", in);
  n = strlen(out);
  while (n && out[n - 1] == '/')
    out[--n] = 0;
}
/* get_blob_info: 1 and *bi filled, or 0 (not found) */
static int pgit_blob_info(const char *repo_path, const char *ref, const char *path, blob_info *bi) {
  char file_path[3100], spec[3300], *text, parent[3100], name[3100];
  char *slash;
  memset(bi, 0, sizeof(*bi));
  pgit_strip_slashes(path, file_path, sizeof(file_path));
  if (!pgit_path_ok(file_path))
    return 0;
  pgit_spec(spec, sizeof(spec), ref, file_path);
  {
    char *argv[] = {"git", "cat-file", "-s", spec, NULL};
    if (!pgit_run(repo_path, argv, &text, 64, NULL))
      return 0;
    bi->size = strtoll(py_strip(text), NULL, 10);
    free(text);
  }
  {
    char *argv[] = {"git", "ls-tree", spec, NULL};
    bi->is_tree = pgit_ok(repo_path, argv);
  }
  slash = strrchr(file_path, '/');
  if (slash) {
    snprintf(parent, sizeof(parent), "%.*s", (int)(slash - file_path), file_path);
    snprintf(name, sizeof(name), "%s", slash + 1);
  } else {
    parent[0] = 0;
    snprintf(name, sizeof(name), "%s", file_path);
  }
  {
    char pspec[3300];
    char *argv[] = {"git", "ls-tree", pspec, NULL};
    if (parent[0])
      pgit_spec(pspec, sizeof(pspec), ref, parent);
    else
      snprintf(pspec, sizeof(pspec), "%s", ref);
    if (pgit_run(repo_path, argv, &text, PG_OUT_MAX, NULL)) {
      char *save = NULL, *line, needle[3200];
      snprintf(needle, sizeof(needle), "\t%s", name);
      for (line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save))
        if (strstr(line, needle) && starts_with(line, "120000")) {
          bi->is_symlink = 1;
          break;
        }
      free(text);
    }
  }
  if (bi->is_symlink) {
    char *argv[] = {"git", "show", spec, NULL};
    if (pgit_run(repo_path, argv, &text, sizeof(bi->symlink_target) - 1, NULL)) {
      snprintf(bi->symlink_target, sizeof(bi->symlink_target), "%s", py_strip(text));
      free(text);
    }
  } else {
    char *argv[] = {"git", "show", spec, NULL};
    size_t n;
    if (pgit_run(repo_path, argv, &text, 8192, &n)) {
      if (memchr(text, 0, n > 8192 ? 8192 : n))
        bi->is_binary = 1;
      free(text);
    }
  }
  return 1;
}
static int pgit_utf8_valid(const char *s, size_t n) {
  size_t i = 0;
  while (i < n) {
    unsigned char c = (unsigned char)s[i];
    size_t extra = c < 0x80 ? 0 : (c >= 0xc2 && c < 0xe0) ? 1 : (c >= 0xe0 && c < 0xf0) ? 2 : (c >= 0xf0 && c < 0xf5) ? 3 : 99;
    size_t k;
    unsigned cp;
    if (extra == 99 || n - i <= extra)
      return extra == 0;
    cp = extra == 0 ? c : extra == 1 ? c & 0x1fu : extra == 2 ? c & 0x0fu : c & 7u;
    for (k = 1; k <= extra; ++k) {
      if (((unsigned char)s[i + k] & 0xc0) != 0x80)
        return 0;
      cp = cp << 6 | ((unsigned char)s[i + k] & 0x3fu);
    }
    if ((extra == 2 && (cp < 0x800 || (cp >= 0xd800 && cp < 0xe000))) || (extra == 3 && (cp < 0x10000 || cp > 0x10ffff)))
      return 0;
    i += extra + 1;
  }
  return 1;
}
/* get_blob_content: the text of a blob (at most limit bytes), or NULL */
static char *pgit_blob_content(const char *repo_path, const char *ref, const char *path, size_t limit, size_t *n) {
  char file_path[3100], spec[3300], *text;
  char *argv[] = {"git", "show", spec, NULL};
  pgit_strip_slashes(path, file_path, sizeof(file_path));
  if (!pgit_path_ok(file_path))
    return NULL;
  pgit_spec(spec, sizeof(spec), ref, file_path);
  if (!pgit_run(repo_path, argv, &text, limit, n))
    return NULL;
  if (!pgit_utf8_valid(text, *n)) {
    free(text);
    return NULL;
  }
  return text;
}

/* ---- trees ---------------------------------------------------------------- */
typedef struct tree_entry {
  char *name;
  char type[8]; /* blob, tree, commit, link */
  char mode[8];
  long long size;
  char *link_target;
  size_t order;
} tree_entry;
static void pgit_entries_free(tree_entry *e, size_t n) {
  size_t i;
  for (i = 0; i < n; ++i) {
    free(e[i].name);
    free(e[i].link_target);
  }
  free(e);
}
/* get_tree_entries: returns 1 with *out (maybe empty), 0 on error */
static int pgit_tree_entries(const char *repo_path, const char *ref, const char *path, tree_entry **out, size_t *count) {
  char tree_path[3100], spec[3300], *text, *save = NULL, *line;
  char *argv[] = {"git", "ls-tree", "-l", spec, NULL};
  tree_entry *e = NULL;
  size_t n = 0, cap = 0;
  *out = NULL;
  *count = 0;
  pgit_strip_slashes(path ? path : "", tree_path, sizeof(tree_path));
  if (!pgit_path_ok(tree_path))
    return 0;
  if (tree_path[0])
    pgit_spec(spec, sizeof(spec), ref, tree_path);
  else
    snprintf(spec, sizeof(spec), "%s", ref);
  if (!pgit_run(repo_path, argv, &text, PG_OUT_MAX, NULL)) {
    char *cat[] = {"git", "cat-file", "-t", spec, NULL}, *type;
    if (!pgit_run(repo_path, cat, &type, 64, NULL))
      return 0;
    n = !strcmp(py_strip(type), "tree");
    free(type);
    return (int)n; /* a valid but empty tree */
  }
  for (line = strtok_r(text, "\n", &save); line && n < PG_TREE_PARSE_MAX; line = strtok_r(NULL, "\n", &save)) {
    char *tab = strchr(line, '\t'), meta[256], *tok[4] = {0}, *ms = NULL, *t;
    int nt = 0;
    tree_entry *te;
    if (!tab || !*py_strip(line))
      continue;
    snprintf(meta, sizeof(meta), "%.*s", (int)(tab - line) < 255 ? (int)(tab - line) : 255, line);
    for (t = strtok_r(meta, " \t", &ms); t && nt < 4; t = strtok_r(NULL, " \t", &ms))
      tok[nt++] = t;
    if (nt < 3)
      continue;
    if (n == cap) {
      size_t nc = cap ? cap * 2 : 64;
      tree_entry *ne = realloc(e, nc * sizeof(tree_entry));
      if (!ne)
        break;
      e = ne;
      cap = nc;
    }
    te = &e[n];
    memset(te, 0, sizeof(*te));
    te->name = md_dup(tab + 1, strlen(tab + 1));
    snprintf(te->type, sizeof(te->type), "%s", tok[1]);
    snprintf(te->mode, sizeof(te->mode), "%s", tok[0]);
    te->size = nt >= 4 ? strtoll(tok[3], NULL, 10) : 0;
    te->order = n;
    if (!strcmp(te->mode, "120000")) {
      char lspec[3500], *content;
      char *show[] = {"git", "show", lspec, NULL};
      snprintf(te->type, sizeof(te->type), "link");
      if (tree_path[0])
        snprintf(lspec, sizeof(lspec), "%s:%s/%s", ref, tree_path, te->name);
      else
        snprintf(lspec, sizeof(lspec), "%s:%s", ref, te->name);
      if (pgit_run(repo_path, show, &content, 1024, NULL)) {
        te->link_target = md_dup(py_strip(content), strlen(py_strip(content)));
        free(content);
      }
    }
    ++n;
  }
  free(text);
  *out = e;
  *count = n;
  return 1;
}
static int pgit_lower_cmp(const char *a, const char *b) {
  for (; *a && *b; ++a, ++b) {
    int ca = *a >= 'A' && *a <= 'Z' ? *a + 32 : (unsigned char)*a, cb = *b >= 'A' && *b <= 'Z' ? *b + 32 : (unsigned char)*b;
    if (ca != cb)
      return ca < cb ? -1 : 1;
  }
  return (unsigned char)*a < (unsigned char)*b ? -1 : (unsigned char)*a > (unsigned char)*b ? 1 : 0;
}
static int pgit_entry_cmp(const void *x, const void *y) {
  const tree_entry *a = x, *b = y;
  int da = !strcmp(a->type, "tree") || !strcmp(a->type, "commit"), db = !strcmp(b->type, "tree") || !strcmp(b->type, "commit");
  int c;
  if (da != db)
    return da ? -1 : 1;
  c = pgit_lower_cmp(a->name, b->name);
  if (c)
    return c;
  return a->order < b->order ? -1 : a->order > b->order;
}

/* ---- commits -------------------------------------------------------------- */
typedef struct commit_row {
  char hash[72], *subject, *author;
  long long timestamp;
} commit_row;
static void pgit_commits_free(commit_row *c, size_t n) {
  size_t i;
  for (i = 0; i < n; ++i) {
    free(c[i].subject);
    free(c[i].author);
  }
  free(c);
}
/* get_commits: 1 with rows (maybe none), 0 on error */
static int pgit_commits(const char *repo_path, const char *ref, const char *file_path, unsigned long skip,
                        unsigned long limit, commit_row **out, size_t *count) {
  char skips[32], limits[32], *text, *save = NULL, *line;
  char *argv[12];
  size_t n = 0, cap = 0, k = 0;
  commit_row *rows = NULL;
  static const char sep[] = "|_SEP_|";
  *out = NULL;
  *count = 0;
  snprintf(skips, sizeof(skips), "%lu", skip);
  snprintf(limits, sizeof(limits), "%lu", limit);
  argv[k++] = "git";
  argv[k++] = "log";
  argv[k++] = "--format=%H|_SEP_|%s|_SEP_|%an|_SEP_|%ae|_SEP_|%at";
  argv[k++] = "--skip";
  argv[k++] = skips;
  argv[k++] = "-n";
  argv[k++] = limits;
  argv[k++] = (char *)ref;
  if (file_path && *file_path) {
    if (!pgit_path_ok(file_path))
      return 0;
    argv[k++] = "--";
    argv[k++] = (char *)file_path;
  }
  argv[k] = NULL;
  if (!pgit_run(repo_path, argv, &text, PG_OUT_MAX, NULL))
    return 0;
  for (line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
    char *p[5], *cur = line;
    int i;
    commit_row *r;
    if (!*py_strip(line))
      continue;
    for (i = 0; i < 4; ++i) {
      char *at = strstr(cur, sep);
      if (!at)
        break;
      *at = 0;
      p[i] = cur;
      cur = at + strlen(sep);
    }
    if (i < 4)
      continue;
    p[4] = cur;
    if (n == cap) {
      size_t nc = cap ? cap * 2 : 32;
      commit_row *nr = realloc(rows, nc * sizeof(commit_row));
      if (!nr)
        break;
      rows = nr;
      cap = nc;
    }
    r = &rows[n++];
    memset(r, 0, sizeof(*r));
    snprintf(r->hash, sizeof(r->hash), "%s", p[0]);
    r->subject = md_dup(p[1], strlen(p[1]));
    r->author = md_dup(p[2], strlen(p[2]));
    r->timestamp = strtoll(p[4], NULL, 10);
  }
  free(text);
  *out = rows;
  *count = n;
  return 1;
}

/* ---- one commit ------------------------------------------------------------ */
typedef struct file_change {
  char *path;
  char status;
  long additions, deletions;
} file_change;
typedef struct commit_info {
  char parents[8][72];
  size_t nparents;
  char *author_name, *author_email, *author_date, *committer_name, *committer_email, *committer_date, *message;
  file_change *files;
  size_t nfiles;
  char *diff;
} commit_info;
static void pgit_commit_info_free(commit_info *ci) {
  size_t i;
  free(ci->author_name);
  free(ci->author_email);
  free(ci->author_date);
  free(ci->committer_name);
  free(ci->committer_email);
  free(ci->committer_date);
  free(ci->message);
  for (i = 0; i < ci->nfiles; ++i)
    free(ci->files[i].path);
  free(ci->files);
  free(ci->diff);
  memset(ci, 0, sizeof(*ci));
}
/* get_commit_info; 1 on success */
static int pgit_commit_info(const char *repo_path, const char *hash, commit_info *ci) {
  char *argv[] = {"git", "show", "--no-patch", "--format=%P%n%an%n%ae%n%aI%n%cn%n%ce%n%cI%n%B", (char *)hash, NULL};
  char *text, *lines[8] = {0}, *p;
  size_t i, n;
  memset(ci, 0, sizeof(*ci));
  if (!pgit_run(repo_path, argv, &text, PG_OUT_MAX, &n))
    return 0;
  p = text;
  for (i = 0; i < 7; ++i) {
    char *nl = strchr(p, '\n');
    if (!nl) {
      free(text);
      return 0;
    }
    *nl = 0;
    lines[i] = p;
    p = nl + 1;
  }
  /* parents: whitespace separated on the first line */
  {
    char *save = NULL, *t;
    for (t = strtok_r(lines[0], " \t\r", &save); t && ci->nparents < 8; t = strtok_r(NULL, " \t\r", &save))
      snprintf(ci->parents[ci->nparents++], 72, "%s", t);
  }
  ci->author_name = md_dup(lines[1], strlen(lines[1]));
  ci->author_email = md_dup(lines[2], strlen(lines[2]));
  ci->author_date = md_dup(lines[3], strlen(lines[3]));
  ci->committer_name = md_dup(lines[4], strlen(lines[4]));
  ci->committer_email = md_dup(lines[5], strlen(lines[5]));
  ci->committer_date = md_dup(lines[6], strlen(lines[6]));
  {
    char *m = md_dup(p, strlen(p));
    if (m) {
      char *s = py_strip(m);
      ci->message = md_dup(s, strlen(s));
      free(m);
    }
  }
  free(text);
  {
    char *stat_argv[] = {"git", "diff-tree", "--numstat", "-r", (char *)hash, NULL};
    char *st, *save = NULL, *line;
    if (pgit_run(repo_path, stat_argv, &st, PG_OUT_MAX, NULL)) {
      for (line = strtok_r(st, "\n", &save); line && ci->nfiles < PG_FILES_MAX; line = strtok_r(NULL, "\n", &save)) {
        char *t1 = strchr(line, '\t'), *t2, *adds, *dels, *path;
        file_change *fc;
        char status = 'M';
        if (!*py_strip(line) || !t1)
          continue;
        t2 = strchr(t1 + 1, '\t');
        if (!t2)
          continue;
        *t1 = 0;
        *t2 = 0;
        adds = line;
        dels = t1 + 1;
        path = t2 + 1;
        {
          char *t3 = strchr(path, '\t');
          if (t3)
            *t3 = 0;
        }
        if (!strcmp(adds, "-") && !strcmp(dels, "-")) {
          status = 'R';
          adds = dels = "0";
        }
        if (ci->nparents) {
          char spec[3300], *chk[] = {"git", "cat-file", "-e", spec, NULL};
          snprintf(spec, sizeof(spec), "%s:%s", ci->parents[0], path);
          if (!pgit_path_ok(path) || !pgit_ok(repo_path, chk))
            status = 'A';
          else {
            snprintf(spec, sizeof(spec), "%s:%s", hash, path);
            if (!pgit_ok(repo_path, chk))
              status = 'D';
          }
        }
        if (!ci->files) {
          ci->files = calloc(PG_FILES_MAX, sizeof(file_change));
          if (!ci->files)
            break;
        }
        fc = &ci->files[ci->nfiles++];
        fc->path = md_dup(path, strlen(path));
        fc->status = status;
        {
          char *e1, *e2;
          long a = strtol(adds, &e1, 10), d = strtol(dels, &e2, 10);
          fc->additions = *adds && !*e1 ? a : 0;
          fc->deletions = *dels && !*e2 ? d : 0;
        }
      }
      free(st);
    }
  }
  {
    char *diff_argv[] = {"git", "show", "--format=", (char *)hash, NULL};
    char *d;
    if (pgit_run(repo_path, diff_argv, &d, PG_DIFF_MAX, NULL))
      ci->diff = d;
  }
  return 1;
}

/* ---- refs ------------------------------------------------------------------ */
typedef struct ref_row {
  char *name, short_hash[8], *subject, *tag_message;
  int is_default, is_annotated;
} ref_row;
typedef struct refs_info {
  ref_row *heads, *tags;
  size_t nheads, ntags;
} refs_info;
static void pgit_refs_free(refs_info *r) {
  size_t i;
  for (i = 0; i < r->nheads; ++i) {
    free(r->heads[i].name);
    free(r->heads[i].subject);
  }
  for (i = 0; i < r->ntags; ++i) {
    free(r->tags[i].name);
    free(r->tags[i].subject);
    free(r->tags[i].tag_message);
  }
  free(r->heads);
  free(r->tags);
  memset(r, 0, sizeof(*r));
}
static void pgit_refs_info(const char *repo_path, const char *default_branch, refs_info *out) {
  char *argv[] = {"git", "for-each-ref", "--format=%(objectname)|%(refname)|%(refname:short)|%(subject)",
                  "refs/heads", "refs/tags", NULL}, *text, *save = NULL, *line;
  memset(out, 0, sizeof(*out));
  if (!pgit_run(repo_path, argv, &text, PG_OUT_MAX, NULL))
    return;
  for (line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
    char *p[3], *cur = line, *subject;
    int i;
    ref_row row, **dst;
    size_t *cnt;
    if (!*py_strip(line))
      continue;
    for (i = 0; i < 3; ++i) {
      char *bar = strchr(cur, '|');
      if (!bar)
        break;
      *bar = 0;
      p[i] = cur;
      cur = bar + 1;
    }
    if (i < 3)
      continue;
    subject = cur;
    memset(&row, 0, sizeof(row));
    row.name = md_dup(p[2], strlen(p[2]));
    snprintf(row.short_hash, sizeof(row.short_hash), "%.7s", p[0]);
    row.subject = md_dup(subject, strlen(subject));
    row.is_default = default_branch && !strcmp(p[2], default_branch);
    if (starts_with(p[1], "refs/heads/")) {
      dst = &out->heads;
      cnt = &out->nheads;
    } else if (starts_with(p[1], "refs/tags/")) {
      char *targv[] = {"git", "for-each-ref", "--format=%(objecttype)|%(contents:subject)", p[1], NULL}, *tt;
      dst = &out->tags;
      cnt = &out->ntags;
      if (pgit_run(repo_path, targv, &tt, 4096, NULL)) {
        char *s = py_strip(tt), *bar = strchr(s, '|');
        if (bar) {
          *bar = 0;
          if (!strcmp(s, "tag")) {
            row.is_annotated = 1;
            row.tag_message = md_dup(bar + 1, strlen(bar + 1));
          }
        }
        free(tt);
      }
    } else {
      free(row.name);
      free(row.subject);
      continue;
    }
    {
      ref_row *nr = realloc(*dst, (*cnt + 1) * sizeof(ref_row));
      if (!nr) {
        free(row.name);
        free(row.subject);
        free(row.tag_message);
        continue;
      }
      *dst = nr;
      (*dst)[(*cnt)++] = row;
    }
  }
  free(text);
}

/* ---- commit signatures (get_commit_signature) ------------------------------ */
typedef struct sig_status {
  int is_signed, valid, author_match;
  char message[320];
} sig_status;
static void sig_set(sig_status *s, int is_signed, int valid, int match, const char *msg) {
  s->is_signed = is_signed;
  s->valid = valid;
  s->author_match = match;
  snprintf(s->message, sizeof(s->message), "%s", msg);
}
static const char pg_b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/* base64.b64decode: characters outside the alphabet are dropped, the quantum
 * must be complete. */
static int pg_b64_decode(const char *text, size_t n, uint8_t *out, size_t cap, size_t *outn) {
  uint32_t acc = 0;
  size_t i, chars = 0, pad = 0, quad = 0, o = 0;
  for (i = 0; i < n; ++i) {
    const char *at;
    if (text[i] == '=') {
      ++pad;
      continue;
    }
    at = text[i] ? strchr(pg_b64, text[i]) : NULL;
    if (!at || pad)
      continue;
    acc = acc << 6 | (uint32_t)(at - pg_b64);
    ++chars;
    if (++quad == 4) {
      if (o + 3 > cap)
        return 0;
      out[o++] = (uint8_t)(acc >> 16);
      out[o++] = (uint8_t)(acc >> 8);
      out[o++] = (uint8_t)acc;
      quad = 0;
      acc = 0;
    }
  }
  if ((chars + pad) % 4 != 0 || quad == 1)
    return 0;
  if (o + 2 > cap)
    return 0;
  if (quad == 2)
    out[o++] = (uint8_t)(acc >> 4);
  else if (quad == 3) {
    out[o++] = (uint8_t)(acc >> 10);
    out[o++] = (uint8_t)(acc >> 2);
  }
  *outn = o;
  return 1;
}
static int pg_ssh_string(const uint8_t *d, size_t n, size_t *off, const uint8_t **out, size_t *len) {
  uint32_t l;
  if (n - *off < 4)
    return 0;
  l = (uint32_t)d[*off] << 24 | (uint32_t)d[*off + 1] << 16 | (uint32_t)d[*off + 2] << 8 | d[*off + 3];
  if (n - *off - 4 < l)
    return 0;
  *out = d + *off + 4;
  *len = l;
  *off += 4 + (size_t)l;
  return 1;
}
/* The author address of a signed commit: "author NAME <ADDRESS> ..." with the
 * address between the first "<" and ">", after the prefix, not ending the line
 * (commitsigs.extract_commit_author). Returns 1 with *out, 0 when absent. */
static int pg_commit_author(const char *m, size_t n, char *out, size_t cap) {
  size_t pos = 0;
  while (pos < n) {
    size_t end = pos, s, e;
    const char *line = m + pos;
    size_t len;
    while (end < n && m[end] != '\n' && m[end] != '\r')
      ++end;
    len = end - pos;
    pos = end < n ? end + (m[end] == '\r' && end + 1 < n && m[end + 1] == '\n' ? 2 : 1) : end;
    if (!len)
      break;
    if (len >= 7 && !memcmp(line, "author ", 7)) {
      for (s = 0; s < len && line[s] != '<'; ++s)
        ;
      for (e = 0; e < len && line[e] != '>'; ++e)
        ;
      if (s < len && s > 7 && e < len && e > s && e < len - 1) {
        if (e - s - 1 >= cap)
          return 0;
        memcpy(out, line + s + 1, e - s - 1);
        out[e - s - 1] = 0;
        return 1;
      }
    }
  }
  return 0;
}
static void pgit_commit_signature(const char *repo_path, const char *hash, sig_status *st) {
  char *argv[] = {"git", "cat-file", "-p", (char *)hash, NULL}, *text, *line, *next;
  sbuf sig, signed_c;
  int in_sig = 0, have_sig = 0;
  size_t n;
  if (!pgit_run(repo_path, argv, &text, PG_OUT_MAX, &n)) {
    sig_set(st, 0, 0, 0, "Could not read commit object");
    return;
  }
  sb_init(&sig);
  sb_init(&signed_c);
  sig.limit = signed_c.limit = PG_OUT_MAX;
  {
    int first_signed = 1, first_sig = 1;
    for (line = text; line; line = next) {
      char *nl = strchr(line, '\n');
      if (nl) {
        *nl = 0;
        next = nl + 1;
      } else
        next = NULL;
      if (starts_with(line, "gpgsig ") || starts_with(line, "gpgsig-sha256 ")) {
        in_sig = 1;
        have_sig = 1;
        if (!first_sig)
          sb_addc(&sig, '\n');
        first_sig = 0;
        sb_adds(&sig, strchr(line, ' ') + 1);
      } else if (in_sig) {
        if (line[0] == ' ') {
          sb_addc(&sig, '\n');
          sb_adds(&sig, line + 1);
        } else {
          in_sig = 0;
          if (!first_signed)
            sb_addc(&signed_c, '\n');
          first_signed = 0;
          sb_adds(&signed_c, line);
        }
      } else {
        if (!first_signed)
          sb_addc(&signed_c, '\n');
        first_signed = 0;
        sb_adds(&signed_c, line);
      }
    }
  }
  free(text);
  if (!have_sig) {
    sig_set(st, 0, 0, 0, "Not signed");
    goto done;
  }
  {
    /* unarmor: base64 between the BEGIN and END lines */
    sbuf b64;
    char *copy = md_dup(sb_str(&sig), sig.n), *l2, *nx;
    int in_a = 0;
    uint8_t *raw = malloc(sig.n + 8);
    size_t rn = 0, off = 6;
    const uint8_t *pk, *ns, *rs, *ha, *rsg;
    size_t pkl, nsl, rsl, hal, rsgl;
    sb_init(&b64);
    b64.limit = sig.n + 8;
    if (!copy || !raw) {
      free(copy);
      free(raw);
      sb_free(&b64);
      sig_set(st, 1, 0, 0, "Signature validation error");
      goto done;
    }
    {
      char *s = py_strip(copy);
      for (l2 = s; l2; l2 = nx) {
        char *nl = strchr(l2, '\n');
        if (nl) {
          *nl = 0;
          nx = nl + 1;
        } else
          nx = NULL;
        if (strstr(l2, "BEGIN SSH SIGNATURE")) {
          in_a = 1;
          continue;
        }
        if (strstr(l2, "END SSH SIGNATURE"))
          break;
        if (in_a)
          sb_adds(&b64, py_strip(l2));
      }
    }
    free(copy);
    if (!b64.n || !pg_b64_decode(sb_str(&b64), b64.n, raw, sig.n + 8, &rn)) {
      free(raw);
      sb_free(&b64);
      sig_set(st, 1, 0, 0, "Signature validation error");
      goto done;
    }
    sb_free(&b64);
    if (rn < 10 || memcmp(raw, "SSHSIG", 6) || raw[6] || raw[7] || raw[8] || raw[9] != 1 ||
        !(off = 10, 1) || !pg_ssh_string(raw, rn, &off, &pk, &pkl) || !pg_ssh_string(raw, rn, &off, &ns, &nsl) ||
        !pg_ssh_string(raw, rn, &off, &rs, &rsl) || !pg_ssh_string(raw, rn, &off, &ha, &hal) ||
        !pg_ssh_string(raw, rn, &off, &rsg, &rsgl)) {
      free(raw);
      sig_set(st, 1, 0, 0, "Malformed SSH wrapping for RSG data");
      goto done;
    }
    /* validate_rsg */
    {
      val pool[32], root;
      reader rd;
      const val *hashtype, *hv, *meta, *pubkey;
      rnc_identity signer;
      uint8_t digest[32];
      char signer_hex[33], author[256];
      int ok = 0;
      if (!signed_c.n || rsgl == 64) {
        free(raw);
        sig_set(st, 1, 0, 0, "Signature validation error");
        goto done;
      }
      if (rsgl < 65)
        goto invalid;
      rd = (reader){rsg + 64, rsg + rsgl, pool, 0, 32};
      if (!parse(&rd, &root, 0) || rd.p != rd.end || root.type != V_MAP)
        goto invalid;
      hashtype = map_get(&root, "hashtype");
      hv = map_get(&root, "hash");
      meta = map_get(&root, "meta");
      if (!hashtype || !hv || !meta || meta->type != V_MAP || !map_get(meta, "signer") ||
          !(pubkey = map_get(meta, "pubkey")) || hashtype->type != V_STR || hashtype->n != 6 ||
          memcmp(hashtype->p, "sha256", 6) || pubkey->type != V_BIN || pubkey->n != 64 ||
          rnc_identity_from_public(&signer, pubkey->p) != RNC_OK || rnc_hash(signed_c.p, signed_c.n, digest) != RNC_OK ||
          hv->type != V_BIN || hv->n != 32 || memcmp(hv->p, digest, 32) ||
          rnc_identity_verify(&signer, rsg + 64, rsgl - 64, rsg) != RNC_OK)
        goto invalid;
      ok = 1;
    invalid:
      free(raw);
      if (!ok) {
        sig_set(st, 1, 0, 0, "Invalid signature");
        goto done;
      }
      hex_string(signer.hash, signer_hex);
      if (!pg_commit_author(signed_c.p, signed_c.n, author, sizeof(author))) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Could not verify author");
        sig_set(st, 1, 1, 0, msg);
      } else if (!strcmp(author, signer_hex)) {
        char msg[96];
        snprintf(msg, sizeof(msg), "Valid, signed by <%s>", signer_hex);
        sig_set(st, 1, 1, 1, msg);
      } else {
        char msg[320];
        snprintf(msg, sizeof(msg), "Invalid signer <%s>, author is <%.200s>", signer_hex, author);
        sig_set(st, 1, 1, 0, msg);
      }
    }
  }
done:
  sb_free(&sig);
  sb_free(&signed_c);
}

#endif
