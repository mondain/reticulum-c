/* The nomadnet page server of reticulum-c-git (included by reticulum_git.c):
 * pages.py's NomadNetworkNode. A second destination "nomadnetwork.node" on the
 * node's identity serves micron pages for browsing the repositories, with the
 * request paths, request fields (var_g, var_r, var_ref, ...), permission checks,
 * templates and markup of the reference. Enabled by
 *
 *   [pages]
 *   serve_nomadnet = yes
 *   unicode_icons  = no      # yes: plain Unicode glyphs instead of Nerd Font icons
 *   media_conversion = yes   # convert images for the media page when an encoder exists
 *   highlight_syntax = yes   # (C addition) no: literal code blocks, as without pygments
 *
 * Templates: CONFIG/templates/NAME.mu (front, group, repo, tree, blob, commits,
 * commit, refs, stats, releases, release, work, work_doc, no_ident, base) with
 * {PAGE_CONTENT}; base also takes {NODE_NAME}, {VERSION}, {NAVIGATION},
 * {GEN_TIME}. An executable template is run and its output used. */
#ifndef RETICULUM_C_RNGIT_PAGES_H
#define RETICULUM_C_RNGIT_PAGES_H
#include "rngit_text.h"
#include "rngit_highlight.h"
#include "rngit_md.h"
#include "rngit_media.h"
#include "rngit_pagegit.h"


#define PG_VERSION "1.5.5-c"
#define PG_MAX_RENDER_WIDTH 100
#define PG_TAB "   "
#define PG_NODE_APP "nomadnetwork.node"
#define CLR_FOLDER "`Ffe6"
#define CLR_FILE "`F66d"
#define CLR_DIM "`F666"
#define CLR_DIM_H "`F444"
#define CLR_OK_DIM "`FT537855"
#define CLR_DIFF_A "`F0a0"
#define CLR_DIFF_R "`F900"
#define CLR_DIFF_P "`F0aa"
#define RCLR_PUSH "B9A810"
#define RCLR_PUSH_G "791212"
#define RCLR_FETCH "10b981"
#define RCLR_FETCH_G "1c5e71"
#define RCLR_VIEW "3b82f6"
#define RCLR_VIEW_G "13428A"
#define RCLR_DOWNLOAD "7831E0"
#define RCLR_DOWNLOAD_G "c5754d"

static uint8_t pg_null_ident[16];
static int pg_null_ready;
static uint8_t pg_node_dest[16]; /* the nomadnetwork.node destination */
static uint8_t pg_repo_dest[16]; /* the git.repositories destination */

/* ---- thanks de-duplication: the last 256 (link, path) pairs --------------- */
static uint8_t pg_thanks_ring[256][32];
static size_t pg_thanks_n, pg_thanks_pos;
static int pg_thanks_seen(const uint8_t link_id[16], const char *path) {
  uint8_t key[32], buf[16 + PATH_MAX + 16];
  size_t i, pl = strlen(path);
  if (pl > PATH_MAX)
    pl = PATH_MAX;
  memcpy(buf, link_id, 16);
  memcpy(buf + 16, path, pl);
  (void)rnc_hash(buf, 16 + pl, key);
  for (i = 0; i < pg_thanks_n; ++i)
    if (!memcmp(pg_thanks_ring[i], key, 32))
      return 1;
  memcpy(pg_thanks_ring[pg_thanks_pos], key, 32);
  pg_thanks_pos = (pg_thanks_pos + 1) % 256;
  if (pg_thanks_n < 256)
    pg_thanks_n++;
  return 0;
}
static const uint8_t pg_zero_link[16];
static const uint8_t *pg_current_link(uint8_t out[16]) {
  if (G.net.responder && rnc_responder_request_link_id(G.net.responder, out) == RNC_OK)
    return out;
  return pg_zero_link;
}

/* ---- the request --------------------------------------------------------- */
typedef struct pgreq {
  val *pool;
  val root;
  int is_map;
  const uint8_t *identity; /* NULL when the caller did not identify */
  uint8_t link_id[16];
  double st;
} pgreq;
static double pg_now(void) {
  struct timespec t;
  clock_gettime(CLOCK_REALTIME, &t);
  return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
static void pg_null_init(void) {
  uint8_t key[64];
  rnc_identity id;
  if (pg_null_ready)
    return;
  memset(key, 0, sizeof(key));
  if (rnc_identity_from_private(&id, key) == RNC_OK) {
    memcpy(pg_null_ident, id.hash, 16);
    rnc_identity_clear(&id);
  }
  pg_null_ready = 1;
}
static int pg_req_open(pgreq *r, const uint8_t *data, size_t size, const uint8_t *identity) {
  reader rd;
  memset(r, 0, sizeof(*r));
  pg_null_init();
  r->identity = identity;
  r->st = pg_now();
  (void)pg_current_link(r->link_id);
  r->pool = malloc(POOL_NODES * sizeof(val));
  if (!r->pool)
    return 0;
  rd = (reader){data, data + size, r->pool, 0, POOL_NODES};
  r->is_map = parse(&rd, &r->root, 0) && r->root.type == V_MAP;
  return 1;
}
static void pg_req_close(pgreq *r) { free(r->pool); }
static const uint8_t *pg_eff(const pgreq *r) { return r->identity ? r->identity : pg_null_ident; }
/* data.get(key, default): 1 when present; the value as text */
static int pg_get(const pgreq *r, const char *key, char *out, size_t cap, const char *dflt) {
  const val *v = r->is_map ? map_get(&r->root, key) : NULL;
  if (!v) {
    snprintf(out, cap, "%s", dflt);
    return 0;
  }
  if (v->type == V_UINT)
    snprintf(out, cap, "%llu", (unsigned long long)v->u);
  else if (v->type == V_INT)
    snprintf(out, cap, "%lld", (long long)v->i);
  else if (!val_copy(v, out, cap))
    out[0] = 0;
  return 1;
}
static int pg_truthy(const pgreq *r, const char *key) {
  char t[64];
  const val *v = r->is_map ? map_get(&r->root, key) : NULL;
  if (!v)
    return 0;
  if (v->type == V_BOOL || v->type == V_UINT)
    return v->u != 0;
  (void)pg_get(r, key, t, sizeof(t), "");
  return t[0] != 0 || (val_is_text(v) && v->n > 0);
}

/* ---- permissions ---------------------------------------------------------- */
static int pg_perm(const pgreq *r, const group *g, const repo *rp, int p) { return allowed(pg_eff(r), g, rp, p); }
static const repo *pg_accessible_repo(const pgreq *r, const char *gname, const char *rname, const group **gout) {
  const group *g = find_group(gname);
  const repo *rp = g ? find_repo(g, rname) : NULL;
  if (gout)
    *gout = g;
  return rp && pg_perm(r, g, rp, P_READ) ? rp : NULL;
}
static size_t pg_accessible_count(const pgreq *r, const group *g) {
  size_t i, n = 0;
  for (i = 0; i < g->repo_count; ++i)
    if (pg_perm(r, g, &g->repos[i], P_READ))
      ++n;
  return n;
}
static int pg_null_blocked(const pgreq *r) { return !r->identity && blocked(pg_null_ident); }

/* ---- icons ----------------------------------------------------------------- */
static const char *pg_icon(const char *name) {
  int nf = G.use_nerdfonts;
  if (!strcmp(name, "sep")) return "\xe2\x80\xa2";
  if (!strcmp(name, "folder")) return nf ? "\xf3\xb0\x89\x96" : "\xf0\x9f\x97\x80";
  if (!strcmp(name, "file")) return nf ? "\xef\x83\xb6" : "\xf0\x9f\x97\x8e";
  if (!strcmp(name, "branch")) return nf ? "\xf3\xb0\x98\xac" : "\xe2\x91\x83";
  if (!strcmp(name, "commits")) return nf ? "\xf3\xb0\x8b\x9a" : "\xf0\x9f\x96\xb9";
  if (!strcmp(name, "tag")) return nf ? "\xf3\xb0\x93\xbc" : "\xe2\x8c\x86";
  if (!strcmp(name, "stats")) return nf ? "\xef\x88\x81" : "\xf0\x9f\x97\xa0";
  if (!strcmp(name, "heart")) return nf ? "\xf3\xb0\x8b\x91" : "\xe2\x99\xa5";
  if (!strcmp(name, "package")) return nf ? "\xf3\xb0\x8f\x97" : "\xe2\x97\x87";
  if (!strcmp(name, "work")) return nf ? "\xf3\xb1\x8c\xa3" : "\xe2\x98\xb8";
  return "";
}

/* ---- micron helpers --------------------------------------------------------- */
static void m_heading(sbuf *o, const char *text, int level) {
  while (level-- > 0)
    sb_addc(o, '>');
  sb_adds(o, text);
  sb_addc(o, '\n');
}
static void m_italic(sbuf *o, const char *text) {
  sb_adds(o, "`*");
  sb_adds(o, text);
  sb_adds(o, "`*");
}
static void m_escape(sbuf *o, const char *s) {
  for (; *s; ++s) {
    if (*s == '`')
      sb_addc(o, '\\');
    sb_addc(o, *s);
  }
}
static void m_divider(sbuf *o) { sb_adds(o, "-\xe2\x94\x80\n"); }
/* kind: 'b' m_link, 'r' m_link_r, 'e' m_link_e (remote). Fields follow as
 * key, value string pairs, ended by NULL. */
static void pg_link(sbuf *o, char kind, const char *label, const char *remote, const char *path, ...) {
  va_list ap;
  const char *k;
  int first = 1;
  const char *c;
  if (kind != 'r')
    sb_adds(o, "`!");
  sb_adds(o, "`[");
  for (c = label; *c; ++c)
    if (*c != '[' && *c != ']' && *c != '`')
      sb_addc(o, *c);
  sb_addc(o, '`');
  if (kind == 'e')
    sb_adds(o, remote);
  sb_addc(o, ':');
  sb_adds(o, path);
  va_start(ap, path);
  while ((k = va_arg(ap, const char *)) != NULL) {
    const char *v = va_arg(ap, const char *);
    sb_addc(o, first ? '`' : '|');
    first = 0;
    sb_adds(o, k);
    sb_addc(o, '=');
    url_quote_plus(o, v);
  }
  va_end(ap);
  sb_addc(o, ']');
  if (kind != 'r')
    sb_adds(o, "`!");
}
static const char *pg_itoa(long long v) {
  static char ring[8][32];
  static unsigned pos;
  char *s = ring[pos++ & 7u];
  snprintf(s, 32, "%lld", v);
  return s;
}

/* ---- text formats ------------------------------------------------------------- */
static void pg_prettysize(char *out, size_t cap, double num) {
  static const char *const units[] = {"", "K", "M", "G", "T", "P", "E", "Z"};
  size_t i;
  for (i = 0; i < 8; ++i) {
    if ((num < 0 ? -num : num) < 1000.0) {
      if (!units[i][0])
        snprintf(out, cap, "%.0f B", num);
      else
        snprintf(out, cap, "%.2f %sB", num, units[i]);
      return;
    }
    num /= 1000.0;
  }
  snprintf(out, cap, "%.2fYB", num);
}
/* prettytime(t, compact=True).split(" ")[0] */
static void pg_prettytime_first(char *out, size_t cap, double t) {
  long long s = (long long)t;
  if (s >= 86400)
    snprintf(out, cap, "%lldd", s / 86400);
  else if (s >= 3600)
    snprintf(out, cap, "%lldh", s / 3600);
  else if (s >= 60)
    snprintf(out, cap, "%lldm", s / 60);
  else if (s > 0)
    snprintf(out, cap, "%llds", s);
  else
    snprintf(out, cap, "0s");
}
/* prettytime(t), as shown in the footer */
static void pg_prettytime(char *out, size_t cap, double t) {
  double rounded = (double)(long long)(t * 100.0 + 0.5) / 100.0;
  char num[32];
  size_t n;
  if (rounded <= 0) {
    snprintf(out, cap, "0s");
    return;
  }
  snprintf(num, sizeof(num), "%.2f", rounded);
  n = strlen(num);
  while (n > 1 && num[n - 1] == '0' && num[n - 2] != '.')
    num[--n] = 0;
  snprintf(out, cap, "%ss", num);
}
static void pg_fmt_localtime(char *out, size_t cap, double ts, const char *fmt) {
  time_t t = (time_t)ts;
  struct tm tmv;
  localtime_r(&t, &tmv);
  strftime(out, cap, fmt, &tmv);
}
static void pg_relative_time(char *out, size_t cap, double timestamp) {
  double diff = pg_now() - timestamp;
  long long v;
  if (diff < 60)
    snprintf(out, cap, "just now");
  else if (diff < 3600) {
    v = (long long)(diff / 60);
    snprintf(out, cap, "%lld minute%s ago", v, v != 1 ? "s" : "");
  } else if (diff < 86400) {
    v = (long long)(diff / 3600);
    snprintf(out, cap, "%lld hour%s ago", v, v != 1 ? "s" : "");
  } else if (diff < 604800) {
    v = (long long)(diff / 86400);
    snprintf(out, cap, "%lld day%s ago", v, v != 1 ? "s" : "");
  } else if (diff < 2592000) {
    v = (long long)(diff / 604800);
    snprintf(out, cap, "%lld week%s ago", v, v != 1 ? "s" : "");
  } else if (diff < 31536000) {
    v = (long long)(diff / 2592000);
    snprintf(out, cap, "%lld month%s ago", v, v != 1 ? "s" : "");
  } else {
    v = (long long)(diff / 31536000);
    snprintf(out, cap, "%lld year%s ago", v, v != 1 ? "s" : "");
  }
}

/* ---- rendering -------------------------------------------------------------- */
static const char *pg_default_template(const char *name) {
  if (!strcmp(name, "front"))
    return "> Groups\n\n{PAGE_CONTENT}";
  if (!strcmp(name, "no_ident"))
    return ">>No Identity\n\nThis page requires identification, and none was received.\n";
  return "{PAGE_CONTENT}";
}
static int pg_known_template(const char *name) {
  static const char *const names[] = {"base", "front", "group", "repo", "releases", "release", "tree", "blob",
                                      "commits", "commit", "refs", "stats", "work", "work_doc", "no_ident"};
  size_t i;
  for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
    if (!strcmp(names[i], name))
      return 1;
  return 0;
}
/* get_template: the custom template of that name, malloc'd, or NULL */
static char *pg_get_template(const char *name) {
  char path[PATH_MAX + 64], *text;
  size_t n = 0;
  if (!pg_known_template(name))
    return NULL;
  snprintf(path, sizeof(path), "%s/templates/%s.mu", G.config_dir, name);
  if (!is_file(path))
    return NULL;
  text = malloc((256u << 10) + 1);
  if (!text)
    return NULL;
  if (access(path, X_OK) == 0) {
    char *argv[2] = {path, NULL};
    proc_result r = rngit_run(NULL, argv, text, 256u << 10, &n);
    if (r.status < 0) {
      free(text);
      return NULL;
    }
  } else {
    FILE *f = fopen(path, "rb");
    if (!f) {
      free(text);
      return NULL;
    }
    n = fread(text, 1, 256u << 10, f);
    fclose(f);
  }
  text[n] = 0;
  py_rstrip(text);
  if (!text[0]) {
    free(text);
    return NULL;
  }
  return text;
}
/* render_template: the finished page into out */
static void pg_render(sbuf *out, const char *page_content, const char *nav, const char *tmpl, double st) {
  char *tabs, *custom = NULL, *page, *base, *t1, *t2, gt[96], elapsed[48];
  tabs = str_replace(page_content ? page_content : "", "\t", PG_TAB);
  if (!tabs)
    return;
  if (tmpl && *tmpl)
    custom = pg_get_template(tmpl);
  if (custom) {
    page = str_replace(custom, "{PAGE_CONTENT}", tabs);
    free(custom);
  } else if (tmpl && *tmpl && pg_known_template(tmpl))
    page = str_replace(pg_default_template(tmpl), "{PAGE_CONTENT}", tabs);
  else
    page = md_dup(tabs, strlen(tabs));
  free(tabs);
  if (!page)
    return;
  base = pg_get_template("base");
  if (!base)
    base = md_dup("#!c=0\n> {NODE_NAME}\n\n{NAVIGATION}\n{PAGE_CONTENT}\n<\n-\n`a`F666`[Served by rngit {VERSION}`:/page/index.mu] - {GEN_TIME}`f",
                  strlen("#!c=0\n> {NODE_NAME}\n\n{NAVIGATION}\n{PAGE_CONTENT}\n<\n-\n`a`F666`[Served by rngit {VERSION}`:/page/index.mu] - {GEN_TIME}`f"));
  if (!base) {
    free(page);
    return;
  }
  t1 = str_replace(base, "{NODE_NAME}", G.node_name);
  free(base);
  t2 = str_replace(t1, "{VERSION}", PG_VERSION);
  free(t1);
  t1 = str_replace(t2, "{NAVIGATION}", nav ? nav : "");
  free(t2);
  pg_prettytime(elapsed, sizeof(elapsed), pg_now() - st);
  snprintf(gt, sizeof(gt), "Generated in %s", elapsed);
  t2 = str_replace(t1, "{GEN_TIME}", gt);
  free(t1);
  t1 = str_replace(t2, "{PAGE_CONTENT}", page);
  free(t2);
  free(page);
  if (t1) {
    sb_adds(out, t1);
    free(t1);
  }
}
static void pg_error_page(const pgreq *r, sbuf *page, const char *title, int level, const char *body, const char *nav,
                          const char *tmpl) {
  sbuf c;
  sb_init(&c);
  m_heading(&c, title, level);
  sb_adds(&c, body);
  pg_render(page, sb_str(&c), nav, tmpl, r->st);
  sb_free(&c);
}
static void pg_no_ident(const pgreq *r, sbuf *page, const char *nav) { pg_render(page, "", nav, "no_ident", r->st); }

/* ---- thanks ------------------------------------------------------------------ */
/* repository_thanks / release_thanks: the count file {"count": n}. As in the
 * reference the first call that creates the file answers 0 whatever was added. */
static long pg_thanks(const char *path, int add, const uint8_t link_id[16], const char *key) {
  uint8_t data[64];
  mp_out o;
  if (add && pg_thanks_seen(link_id, key))
    add = 0;
  if (!is_file(path)) {
    o = (mp_out){data, sizeof(data), 0, 0};
    mp_map(&o, 1);
    mp_cstr(&o, "count");
    mp_uint(&o, add ? 1 : 0);
    (void)write_atomic(path, (const char *)data, o.n);
    return 0;
  } else {
    FILE *f = fopen(path, "rb");
    size_t n = 0;
    val pool[8], root;
    reader rd;
    const val *c;
    long count;
    if (!f)
      return 0;
    n = fread(data, 1, sizeof(data), f);
    fclose(f);
    rd = (reader){data, data + n, pool, 0, 8};
    if (!parse(&rd, &root, 0) || !(c = map_get(&root, "count")) || c->type != V_UINT)
      return 0;
    count = (long)c->u;
    if (add)
      ++count;
    o = (mp_out){data, sizeof(data), 0, 0};
    mp_map(&o, 1);
    mp_cstr(&o, "count");
    mp_uint(&o, (uint64_t)count);
    (void)write_atomic(path, (const char *)data, o.n);
    return count;
  }
}

/* ---- releases (releases_list_data / release_data) --------------------------- */
typedef struct pg_rel {
  char tag[256], status[32], format[16], preview[2200];
  long long created;
  int artifacts;
} pg_rel;
static int pg_first_preview_line(const char *notes, char *out, size_t cap) {
  /* the first line of the text left after dropping heading and quote lines,
   * stripped: its leading white space goes, blank lines before it are skipped */
  char *copy = md_dup(notes, strlen(notes)), *line, *next;
  int found = 0;
  out[0] = 0;
  if (!copy)
    return 0;
  for (line = copy; line && !found; line = next) {
    char *nl = strchr(line, '\n');
    char *cr;
    if (nl) {
      *nl = 0;
      next = nl + 1;
    } else
      next = NULL;
    cr = strchr(line, '\r');
    if (cr)
      *cr = 0;
    if (line[0] == '#' || line[0] == '>')
      continue;
    {
      char *s = line;
      while (is_space_c(*s))
        ++s;
      if (*s) {
        char *e = s + strlen(s);
        while (e > s && is_space_c(e[-1]))
          *--e = 0;
        snprintf(out, cap, "%s", s);
        found = 1;
      }
    }
  }
  free(copy);
  return found;
}
/* the releases of a repository, newest first; also the latest published tag */
static pg_rel *pg_releases(const char *releases_path, size_t *count, char *latest, size_t latest_cap) {
  DIR *d = opendir(releases_path);
  struct dirent *e;
  pg_rel *rels = NULL;
  size_t n = 0, i, k;
  latest[0] = 0;
  *count = 0;
  if (!d)
    return NULL;
  rels = calloc(512, sizeof(pg_rel));
  if (!rels) {
    closedir(d);
    return NULL;
  }
  while ((e = readdir(d)) != NULL && n < 512) {
    char dir[PATH_MAX * 2], art[PATH_MAX * 2 + 16];
    meta m;
    pg_rel *x = &rels[n];
    char *notes;
    if (e->d_name[0] == '.')
      continue;
    snprintf(dir, sizeof(dir), "%s/%s", releases_path, e->d_name);
    if (!is_dir(dir) || !meta_read(dir, &m))
      continue;
    snprintf(x->tag, sizeof(x->tag), "%s", m.has_tag ? m.tag : e->d_name);
    snprintf(x->status, sizeof(x->status), "%s", m.status[0] ? m.status : "unknown");
    x->created = m.created;
    snprintf(x->format, sizeof(x->format), "markdown");
    notes = malloc(256u << 10);
    if (notes) {
      static const char *const names[] = {"RELEASE.md", "RELEASE.mu", "RELEASE.txt"};
      for (i = 0; i < 3; ++i) {
        char np[PATH_MAX * 2 + 16];
        snprintf(np, sizeof(np), "%s/%s", dir, names[i]);
        if (is_file(np)) {
          read_small(np, notes, 256u << 10);
          if (i == 1)
            snprintf(x->format, sizeof(x->format), "micron");
          else if (i == 2)
            snprintf(x->format, sizeof(x->format), "text");
          (void)pg_first_preview_line(notes, x->preview, sizeof(x->preview));
          break;
        }
      }
      free(notes);
    }
    snprintf(art, sizeof(art), "%s/artifacts", dir);
    x->artifacts = is_dir(art) ? count_files(art, 0) : 0;
    ++n;
  }
  closedir(d);
  /* newest first, stable */
  for (i = 1; i < n; ++i) {
    pg_rel t = rels[i];
    k = i;
    while (k > 0 && rels[k - 1].created < t.created) {
      rels[k] = rels[k - 1];
      --k;
    }
    rels[k] = t;
  }
  {
    char lt[256];
    if (latest_tag(releases_path, lt, sizeof(lt))) {
      for (i = 0; i < n; ++i)
        if (!strcmp(rels[i].tag, lt) && !strcmp(rels[i].status, "published"))
          snprintf(latest, latest_cap, "%s", lt);
    }
  }
  *count = n;
  return rels;
}
typedef struct pg_art {
  char name[256];
  long long size;
} pg_art;
static int pg_art_cmp(const void *a, const void *b) { return strcmp(((const pg_art *)a)->name, ((const pg_art *)b)->name); }

/* ---- the stats charts ----------------------------------------------------------- */
static void pg_rgb(const char *hex, int rgb[3]) {
  char b[3] = {0, 0, 0};
  int i;
  for (i = 0; i < 3; ++i) {
    b[0] = hex[2 * i];
    b[1] = hex[2 * i + 1];
    rgb[i] = (int)strtol(b, NULL, 16);
  }
}
static void pg_expand_color(const char *c, char out[7]) {
  if (strlen(c) == 3) {
    int i;
    for (i = 0; i < 3; ++i)
      out[2 * i] = out[2 * i + 1] = c[i];
    out[6] = 0;
  } else
    snprintf(out, 7, "%.6s", c);
}
static void pg_grad(char out[7], const int sec[3], const int pri[3], double t, double factor) {
  double m = t * factor;
  int i;
  if (m > 1)
    m = 1;
  for (i = 0; i < 3; ++i)
    snprintf(out + 2 * i, 3 - 0, "%02x", (int)(sec[i] + (pri[i] - sec[i]) * m));
}
static void pg_chart_labels(sbuf *o, int n, const char *first, const char *last) {
  char f[64], l[64];
  int mid = (n + 2) - 12 - 12, i;
  snprintf(f, sizeof(f), "%-12.12s", first);
  snprintf(l, sizeof(l), "%12.12s", last);
  sb_adds(o, CLR_DIM);
  sb_adds(o, f);
  sb_adds(o, "`f");
  for (i = 0; i < mid; ++i)
    sb_addc(o, ' ');
  sb_adds(o, CLR_DIM);
  sb_adds(o, l);
  sb_adds(o, "`f\n");
}
static void pg_render_chart(sbuf *o, const unsigned long long *data, int n, const char *first, const char *last,
                            const char *color, const char *secondary, double gradient_factor) {
  unsigned long long maxv = 0;
  int row, i, height = 10, pri[3], sec[3];
  char p6[7], s6[7], g1[7], g2[7];
  if (!gradient_factor)
    gradient_factor = 1.3;
  for (i = 0; i < n; ++i)
    if (data[i] > maxv)
      maxv = data[i];
  if (!n || !maxv) {
    sb_adds(o, "No data available\n");
    return;
  }
  pg_expand_color(color, p6);
  pg_expand_color(secondary, s6);
  pg_rgb(p6, pri);
  pg_rgb(s6, sec);
  sb_addf(o, "`FT%sPeak: %llu`f\n", p6, maxv);
  for (row = height; row > 0; --row) {
    double row_top = ((double)row / height) * (double)maxv, row_bottom = ((double)(row - 1) / height) * (double)maxv;
    double row_mid = (row_top + row_bottom) / 2, grad_top = (double)row / height, grad_mid = ((double)row - 0.5) / height;
    sb_adds(o, "\xe2\x94\x82");
    for (i = 0; i < n; ++i) {
      double v = (double)data[i];
      int upper = v >= row_top, lower = v >= row_mid || (row == 1 && data[i] > 0);
      if (!upper && !lower)
        sb_addc(o, ' ');
      else if (upper) {
        pg_grad(g1, sec, pri, grad_top, gradient_factor);
        pg_grad(g2, sec, pri, grad_mid, gradient_factor);
        sb_addf(o, "`FT%s`BT%s\xe2\x96\x80`f`b", g1, g2);
      } else {
        pg_grad(g1, sec, pri, grad_mid, gradient_factor);
        sb_addf(o, "`FT%s\xe2\x96\x84`f", g1);
      }
    }
    sb_addc(o, '\n');
  }
  sb_adds(o, "\xe2\x94\x94");
  for (i = 0; i < n; ++i)
    sb_adds(o, "\xe2\x94\x80");
  sb_adds(o, "\xe2\x94\x98\n");
  pg_chart_labels(o, n, first, last);
}
static void pg_render_combined(sbuf *o, const repo_stats *s, const char *first, const char *last) {
  static const char *const cats[4] = {"pushes", "fetches", "views", "downloads"};
  const unsigned long long *cat_data[4];
  const char *base[4] = {RCLR_PUSH, RCLR_FETCH, RCLR_VIEW, RCLR_DOWNLOAD};
  char col[4][7], e6[7];
  int c, i, row, n = s->lookback, height = 6, black[3] = {0, 0, 0}, rgb[3];
  const double dim = 0.87;
  cat_data[0] = s->daily[RS_PUSHES];
  cat_data[1] = s->daily[RS_FETCHES];
  cat_data[2] = s->daily[RS_VIEWS];
  cat_data[3] = s->daily[RS_COMBINED];
  for (c = 0; c < 4; ++c) {
    pg_expand_color(base[c], e6);
    pg_rgb(e6, rgb);
    pg_grad(col[c], black, rgb, dim, 1.0);
  }
  for (c = 0; c < 4; ++c) {
    char name[16];
    snprintf(name, sizeof(name), "%s", cats[c]);
    name[0] = (char)(name[0] - 32);
    if (c)
      sb_adds(o, "  ");
    sb_addf(o, "`FT%s`BT%s\xe2\x96\x88\xe2\x96\x88`f`b %s", col[c], col[c], name);
  }
  sb_adds(o, "\n\n");
  for (row = height; row > 0; --row) {
    double lower_min = (double)(row - 1) / height, lower_max = ((double)row - 0.5) / height;
    double upper_min = ((double)row - 0.5) / height, upper_max = (double)row / height;
    sb_adds(o, "\xe2\x94\x82");
    for (i = 0; i < n; ++i) {
      unsigned long long total = 0, cum = 0;
      double cs[4], ce[4];
      int upper_cat = -1, lower_cat = -1;
      for (c = 0; c < 4; ++c)
        total += cat_data[c][i];
      if (!total) {
        sb_addc(o, ' ');
        continue;
      }
      for (c = 0; c < 4; ++c) {
        cs[c] = (double)cum / (double)total;
        cum += cat_data[c][i];
        ce[c] = (double)cum / (double)total;
      }
      for (c = 0; c < 4; ++c)
        if (upper_min < ce[c] && upper_max > cs[c]) {
          upper_cat = c;
          break;
        }
      for (c = 0; c < 4; ++c)
        if (lower_min < ce[c] && lower_max > cs[c]) {
          lower_cat = c;
          break;
        }
      if (upper_cat < 0 && lower_cat < 0)
        sb_addc(o, ' ');
      else if (upper_cat == lower_cat)
        sb_addf(o, "`FT%s`BT%s\xe2\x96\x88`f`b", col[upper_cat], col[upper_cat]);
      else if (upper_cat >= 0 && lower_cat >= 0)
        sb_addf(o, "`FT%s`BT%s\xe2\x96\x80`f`b", col[upper_cat], col[lower_cat]);
      else if (upper_cat >= 0)
        sb_addf(o, "`FT%s\xe2\x96\x80`f", col[upper_cat]);
      else
        sb_addf(o, "`FT%s\xe2\x96\x84`f", col[lower_cat]);
    }
    sb_addc(o, '\n');
  }
  sb_adds(o, "\xe2\x94\x94");
  for (i = 0; i < n; ++i)
    sb_adds(o, "\xe2\x94\x80");
  sb_adds(o, "\xe2\x94\x98\n");
  {
    char f[16], l[16];
    int mid = (n + 2) - (int)u8_count(first, strlen(first) < 12 ? strlen(first) : 12) -
              (int)u8_count(last, strlen(last) < 12 ? strlen(last) : 12);
    snprintf(f, sizeof(f), "%.12s", first);
    snprintf(l, sizeof(l), "%.12s", last);
    sb_adds(o, CLR_DIM);
    sb_adds(o, f);
    for (i = 0; i < mid; ++i)
      sb_addc(o, ' ');
    sb_adds(o, l);
    sb_adds(o, "`f\n");
  }
}

/* ---- the pages ------------------------------------------------------------------ */

/* serve_front_page */
static void pg_front(const pgreq *rq, sbuf *page) {
  sbuf content, nav;
  size_t i, ng = 0;
  const group *order[MAX_GROUPS];
  sb_init(&content);
  sb_init(&nav);
  sb_adds(&nav, ">>\n");
  pg_link(&nav, 'b', "Node", NULL, "/page/index.mu", NULL);
  sb_adds(&nav, " /\n");
  for (i = 0; i < G.group_count; ++i)
    if (pg_accessible_count(rq, &G.groups[i]))
      order[ng++] = &G.groups[i];
  if (!ng)
    sb_adds(&content, ">>\nNo groups available\n");
  else {
    size_t a, b;
    for (a = 1; a < ng; ++a) {
      const group *t = order[a];
      b = a;
      while (b > 0 && strcmp(order[b - 1]->name, t->name) > 0) {
        order[b] = order[b - 1];
        --b;
      }
      order[b] = t;
    }
    for (i = 0; i < ng; ++i) {
      size_t cnt = pg_accessible_count(rq, order[i]);
      char label[600];
      snprintf(label, sizeof(label), "  %s %s", MD_BULLET, order[i]->name);
      pg_link(&content, 'b', label, NULL, "/page/group.mu", "g", order[i]->name, NULL);
      sb_addf(&content, " (%zu %s)\n", cnt, cnt == 1 ? "repository" : "repositories");
    }
  }
  stats_view_succeeded(NULL, NULL, rq->identity);
  if (pg_null_blocked(rq))
    pg_no_ident(rq, page, sb_str(&nav));
  else
    pg_render(page, sb_str(&content), sb_str(&nav), "front", rq->st);
  sb_free(&content);
  sb_free(&nav);
}
/* serve_group_page */
static void pg_group(const pgreq *rq, sbuf *page) {
  char gname[NAME_MAX_LEN * 2];
  sbuf content, nav;
  const group *g;
  size_t i, n = 0;
  const repo *list[MAX_REPOS];
  pg_get(rq, "var_g", gname, sizeof(gname), "");
  if (!gname[0]) {
    pg_error_page(rq, page, "Error", 2, "\nInvalid request\n", NULL, NULL);
    return;
  }
  sb_init(&content);
  sb_init(&nav);
  sb_adds(&nav, ">>\n");
  pg_link(&nav, 'b', "Node", NULL, "/page/index.mu", NULL);
  sb_addf(&nav, " / %s\n", gname);
  if (pg_null_blocked(rq)) {
    pg_no_ident(rq, page, sb_str(&nav));
    goto done;
  }
  g = find_group(gname);
  if (g)
    for (i = 0; i < g->repo_count; ++i)
      if (pg_perm(rq, g, &g->repos[i], P_READ))
        list[n++] = &g->repos[i];
  if (!g || !n) {
    m_heading(&content, "Group Not Found", 2);
    sb_adds(&content, "\nThe requested group was not found\n");
    pg_render(page, sb_str(&content), sb_str(&nav), NULL, rq->st);
    goto done;
  }
  {
    size_t a, b;
    for (a = 1; a < n; ++a) {
      const repo *t = list[a];
      b = a;
      while (b > 0 && strcmp(list[b - 1]->name, t->name) > 0) {
        list[b] = list[b - 1];
        --b;
      }
      list[b] = t;
    }
  }
  m_heading(&content, " Repositories", 1);
  sb_addc(&content, '\n');
  for (i = 0; i < n; ++i) {
    char desc[1024], label[600];
    snprintf(label, sizeof(label), "  %s %s", MD_BULLET, list[i]->name);
    pg_link(&content, 'b', label, NULL, "/page/repo.mu", "g", gname, "r", list[i]->name, NULL);
    if (pgit_description(list[i]->path, desc, sizeof(desc)))
      sb_addf(&content, " - %s\n", desc);
    else
      sb_addc(&content, '\n');
  }
  stats_view_succeeded(gname, NULL, rq->identity);
  pg_render(page, sb_str(&content), sb_str(&nav), "group", rq->st);
done:
  sb_free(&content);
  sb_free(&nav);
}

/* common head of the repository scoped pages */
typedef struct pgctx {
  char gname[NAME_MAX_LEN * 2], rname[NAME_MAX_LEN * 2], ref[1024];
  const group *g;
  const repo *r;
} pgctx;

static void pg_repo_page(pgreq *rq, sbuf *page) {
  pgctx c;
  sbuf content, nav;
  char ref[1024], hexd[33], *readme;
  int thanks, is_md = 0, heads = 0, tags = 0;
  sb_init(&content);
  sb_init(&nav);
  pg_get(rq, "var_g", c.gname, sizeof(c.gname), "");
  pg_get(rq, "var_r", c.rname, sizeof(c.rname), "");
  pg_get(rq, "var_ref", ref, sizeof(ref), "HEAD");
  thanks = pg_truthy(rq, "var_thanks");
  if (!c.gname[0] || !c.rname[0]) {
    pg_error_page(rq, page, "Error", 2, "\nInvalid request\n", NULL, NULL);
    goto done;
  }
  hex_string(pg_repo_dest, hexd);
  sb_adds(&nav, ">>\n");
  pg_link(&nav, 'b', "Node", NULL, "/page/index.mu", NULL);
  sb_adds(&nav, " / ");
  pg_link(&nav, 'b', c.gname, NULL, "/page/group.mu", "g", c.gname, NULL);
  sb_addf(&nav, " / %s %srns://%s/%s/%s`f\n", c.rname, CLR_DIM, hexd, c.gname, c.rname);
  c.r = pg_accessible_repo(rq, c.gname, c.rname, &c.g);
  if (pg_null_blocked(rq)) {
    pg_no_ident(rq, page, sb_str(&nav));
    goto done;
  }
  if (!c.r) {
    m_heading(&content, "Not Found", 1);
    sb_adds(&content, "\nThe requested repository was not found.\n");
    pg_render(page, sb_str(&content), sb_str(&nav), NULL, rq->st);
    goto done;
  }
  if (c.r->fork_src[0] || c.r->mirror_src[0]) {
    const char *source_type = c.r->fork_src[0] ? "fork" : "mirror", *source_url = c.r->fork_src[0] ? c.r->fork_src : c.r->mirror_src;
    sbuf link;
    char tmp[512], sync_time[32], desc[32], hdr[900];
    double ago;
    size_t indent, dl, i;
    sb_init(&link);
    if (strncasecmp(source_url, "rns://", 6) == 0 && G.net.node) {
      char copy[512], *parts[8];
      size_t np = 0;
      char *tok, *save = NULL;
      snprintf(copy, sizeof(copy), "%s", source_url);
      /* split("/") keeps empty parts: rns: "" HASH GROUP REPO */
      {
        char *p = copy;
        parts[np++] = p;
        while ((tok = strchr(p, '/')) != NULL && np < 8) {
          *tok = 0;
          p = tok + 1;
          parts[np++] = p;
        }
        (void)save;
      }
      if (np == 5 && strlen(parts[2]) == 32) {
        uint8_t dest[16];
        rnc_announce an;
        if (rngit_hex_decode(parts[2], dest, 16) && rnc_node_recall(G.net.node, dest, &an) == RNC_OK) {
          uint8_t nh[10], pd[16];
          if (rnc_destination_hash(PG_NODE_APP, &an.identity, nh, pd) == RNC_OK) {
            char ph[33];
            hex_string(pd, ph);
            pg_link(&link, 'e', source_url, ph, "/page/repo.mu", "g", parts[3], "r", parts[4], NULL);
          }
        }
      }
    }
    ago = pg_now() - (double)mirror_synced(c.r->path);
    if (ago < 0)
      ago = 0;
    pg_prettytime_first(sync_time, sizeof(sync_time), ago);
    snprintf(desc, sizeof(desc), "%sed from", source_type);
    desc[0] = (char)(desc[0] - 32);
    snprintf(tmp, sizeof(tmp), "Node / %s / %s", c.gname, c.rname);
    dl = strlen(desc);
    indent = u8_count(tmp, strlen(tmp)) > dl ? u8_count(tmp, strlen(tmp)) - dl : 0;
    snprintf(hdr, sizeof(hdr), "%s%s", CLR_DIM, desc);
    sb_adds(&nav, hdr);
    for (i = 0; i < indent; ++i)
      sb_addc(&nav, ' ');
    sb_addc(&nav, ' ');
    sb_adds(&nav, link.n ? sb_str(&link) : source_url);
    sb_addf(&nav, "`f `*%ssynced %s ago`f`*\n\n", CLR_DIM_H, sync_time);
    sb_free(&link);
  }
  {
    char desc[1024];
    if (pgit_description(c.r->path, desc, sizeof(desc)))
      sb_addf(&content, "%s\n\n", desc);
  }
  {
    char key[PATH_MAX + 16], resolved[72], active[PATH_MAX + 32], rpath[PATH_MAX + 16];
    long thanks_count, commits = 0, work_count = 0, releases_count = 0;
    DIR *d;
    struct dirent *e;
    size_t nrel = 0, i;
    pg_rel *rels;
    char latest[256], buf[256];
    const char *sep = pg_icon("sep");
    snprintf(key, sizeof(key), "%s.thanks", c.r->path);
    thanks_count = pg_thanks(key, thanks, rq->link_id, c.r->path);
    pgit_ref_counts(c.r->path, &heads, &tags);
    if (pgit_resolve(c.r->path, ref, resolved))
      commits = pgit_commit_count(c.r->path, resolved);
    snprintf(active, sizeof(active), "%s.work/active", c.r->path);
    d = opendir(active);
    while (d && (e = readdir(d)) != NULL) {
      char full[PATH_MAX * 2];
      const char *s = e->d_name;
      int digits = *s != 0;
      for (; *s; ++s)
        if (*s < '0' || *s > '9')
          digits = 0;
      snprintf(full, sizeof(full), "%s/%s", active, e->d_name);
      if (digits && is_dir(full))
        ++work_count;
    }
    if (d)
      closedir(d);
    snprintf(rpath, sizeof(rpath), "%s.releases", c.r->path);
    rels = pg_releases(rpath, &nrel, latest, sizeof(latest));
    for (i = 0; rels && i < nrel; ++i)
      if (!strcmp(rels[i].status, "published"))
        ++releases_count;
    free(rels);
    snprintf(buf, sizeof(buf), "%s Files", pg_icon("folder"));
    pg_link(&content, 'r', buf, NULL, "/page/tree.mu", "g", c.gname, "r", c.rname, "ref", "HEAD", NULL);
    sb_addf(&content, " %s ", sep);
    if (releases_count) {
      snprintf(buf, sizeof(buf), "%s Releases (%ld)", pg_icon("package"), releases_count);
      pg_link(&content, 'r', buf, NULL, "/page/releases.mu", "g", c.gname, "r", c.rname, NULL);
      sb_addf(&content, " %s ", sep);
    }
    snprintf(buf, sizeof(buf), "%s Work (%ld)", pg_icon("work"), work_count);
    pg_link(&content, 'r', buf, NULL, "/page/work.mu", "g", c.gname, "r", c.rname, NULL);
    sb_addf(&content, " %s ", sep);
    snprintf(buf, sizeof(buf), "%s Commits (%ld)", pg_icon("commits"), commits);
    pg_link(&content, 'r', buf, NULL, "/page/commits.mu", "g", c.gname, "r", c.rname, "ref", "HEAD", NULL);
    sb_addf(&content, " %s ", sep);
    snprintf(buf, sizeof(buf), "%s Branches (%d)", pg_icon("branch"), heads);
    pg_link(&content, 'r', buf, NULL, "/page/refs.mu", "g", c.gname, "r", c.rname, "type", "heads", NULL);
    sb_addf(&content, " %s ", sep);
    snprintf(buf, sizeof(buf), "%s Tags (%d)", pg_icon("tag"), tags);
    pg_link(&content, 'r', buf, NULL, "/page/refs.mu", "g", c.gname, "r", c.rname, "type", "tags", NULL);
    sb_addf(&content, " %s ", sep);
    snprintf(buf, sizeof(buf), "%s Thanks (%ld)", pg_icon("heart"), thanks_count);
    pg_link(&content, 'r', buf, NULL, "/page/repo.mu", "g", c.gname, "r", c.rname, "thanks", "y", NULL);
    if (pg_perm(rq, c.g, c.r, P_STATS)) {
      sb_addf(&content, " %s ", sep);
      snprintf(buf, sizeof(buf), "%s Stats", pg_icon("stats"));
      pg_link(&content, 'r', buf, NULL, "/page/stats.mu", "g", c.gname, "r", c.rname, NULL);
    }
    sb_adds(&content, "\n\n<");
  }
  readme = pgit_readme(c.r->path, &is_md);
  if (readme) {
    const char *t = readme;
    while (is_space_c(*t))
      ++t;
    if (*t != '#' && *t != '>')
      m_divider(&content);
    if (is_md) {
      md_conv mc;
      char scope[2400];
      snprintf(scope, sizeof(scope), ":/page/blob.mu`g=%s|r=%s|ref=%s|path=", c.gname, c.rname, ref);
      md_init(&mc, PG_MAX_RENDER_WIDTH, scope);
      md_format_block(&mc, readme, &content);
    } else {
      py_rstrip(readme);
      sb_addf(&content, "\n%s\n", readme);
    }
    free(readme);
  } else {
    m_divider(&content);
    sb_addc(&content, '\n');
    m_italic(&content, "No README file found in this repository.");
    sb_addc(&content, '\n');
  }
  stats_view_succeeded(c.gname, c.rname, rq->identity);
  pg_render(page, sb_str(&content), sb_str(&nav), "repo", rq->st);
done:
  sb_free(&content);
  sb_free(&nav);
}

/* the navigation common to tree and blob pages: Node / g / r / files / path... */
static void pg_path_crumbs(sbuf *nav, const char *g, const char *r, const char *ref, const char *path, int add_empty) {
  char tmp[3200], cur[3200] = "";
  size_t i = 0, total = 0;
  const char *s = path, *c;
  sb_adds(nav, ">>\n");
  pg_link(nav, 'b', "Node", NULL, "/page/index.mu", NULL);
  sb_adds(nav, " / ");
  pg_link(nav, 'b', g, NULL, "/page/group.mu", "g", g, NULL);
  sb_adds(nav, " / ");
  pg_link(nav, 'b', r, NULL, "/page/repo.mu", "g", g, "r", r, NULL);
  sb_adds(nav, " / ");
  pg_link(nav, 'b', "files", NULL, "/page/tree.mu", "g", g, "r", r, NULL);
  if (path && *path) {
    char *start, *slash;
    size_t n;
    /* path.strip("/").split("/") */
    while (*s == '/')
      ++s;
    snprintf(tmp, sizeof(tmp), "%s", s);
    n = strlen(tmp);
    while (n && tmp[n - 1] == '/')
      tmp[--n] = 0;
    for (c = tmp; *c; ++c)
      if (*c == '/')
        ++total;
    ++total;
    start = tmp;
    for (;;) {
      slash = strchr(start, '/');
      if (slash)
        *slash = 0;
      if (cur[0])
        strncat(cur, "/", sizeof(cur) - strlen(cur) - 1);
      strncat(cur, start, sizeof(cur) - strlen(cur) - 1);
      sb_adds(nav, " / ");
      if (i == total - 1)
        sb_adds(nav, start);
      else
        pg_link(nav, 'b', start, NULL, "/page/tree.mu", "g", g, "r", r, "ref", ref, "path", cur, NULL);
      ++i;
      if (!slash)
        break;
      start = slash + 1;
    }
  } else if (add_empty)
    sb_adds(nav, " / ");
  sb_addc(nav, '\n');
}

static void pg_tree_page(pgreq *rq, sbuf *page) {
  pgctx c;
  char path[3100], page_s[32], resolved[72];
  sbuf content, nav;
  tree_entry *entries = NULL;
  size_t n = 0, i;
  long page_num = 0;
  sb_init(&content);
  sb_init(&nav);
  pg_get(rq, "var_g", c.gname, sizeof(c.gname), "");
  pg_get(rq, "var_r", c.rname, sizeof(c.rname), "");
  pg_get(rq, "var_ref", c.ref, sizeof(c.ref), "HEAD");
  pg_get(rq, "var_path", path, sizeof(path), "");
  url_unquote_plus(path);
  pg_get(rq, "var_page", page_s, sizeof(page_s), "0");
  {
    char *end, *s = py_strip(page_s);
    page_num = strtol(s, &end, 10);
    if (end == s || *end || page_num < 0)
      page_num = 0;
    if (page_num > 1000000)
      page_num = 1000000;
  }
  if (pg_null_blocked(rq)) {
    pg_no_ident(rq, page, NULL);
    goto done;
  }
  c.r = pg_accessible_repo(rq, c.gname, c.rname, &c.g);
  if (!c.r) {
    m_heading(&content, "Not Found", 1);
    sb_adds(&content, "\n\nThe requested repository does not exist or you do not have access to it.\n");
    pg_render(page, sb_str(&content), NULL, NULL, rq->st);
    goto done;
  }
  if (!pgit_resolve(c.r->path, c.ref, resolved)) {
    m_heading(&content, "Error", 2);
    sb_addf(&content, "\n\nThe ref '%s' does not exist in this repository.\n\n", c.ref);
    pg_link(&content, 'b', "View All Refs", NULL, "/page/refs.mu", "g", c.gname, "r", c.rname, NULL);
    sb_addc(&content, '\n');
    pg_render(page, sb_str(&content), NULL, NULL, rq->st);
    goto done;
  }
  pg_path_crumbs(&nav, c.gname, c.rname, c.ref, path, 1);
  if (!pgit_tree_entries(c.r->path, resolved, path, &entries, &n))
    sb_adds(&content, "Error reading directory contents.\n");
  else if (!n)
    sb_adds(&content, "Empty directory.\n");
  else {
    const char *i_file = pg_icon("file"), *i_folder = pg_icon("folder");
    size_t start = (size_t)page_num * PG_TREE_ENTRIES_PER_PAGE, end = start + PG_TREE_ENTRIES_PER_PAGE;
    sbuf h;
    qsort(entries, n, sizeof(tree_entry), pgit_entry_cmp);
    if (end > n)
      end = n;
    sb_init(&h);
    sb_addf(&h, "Contents: %s (%.8s)", c.ref, resolved);
    m_heading(&content, sb_str(&h), 2);
    sb_free(&h);
    sb_addc(&content, '\n');
    if (n > PG_TREE_ENTRIES_PER_PAGE)
      sb_addf(&content, "%sShowing %zu-%zu of %zu entries`f\n\n", CLR_DIM, start + 1, end, n);
    if (path[0]) {
      char parent[3100], *slash, stripped[3100];
      char lbl[64];
      size_t pl;
      pgit_strip_slashes(path, stripped, sizeof(stripped));
      /* "/".join(tree_path.rstrip("/").split("/")[:-1]) keeps the path's own leading text */
      snprintf(parent, sizeof(parent), "%s", path);
      pl = strlen(parent);
      while (pl && parent[pl - 1] == '/')
        parent[--pl] = 0;
      slash = strrchr(parent, '/');
      if (slash)
        *slash = 0;
      else
        parent[0] = 0;
      sb_adds(&content, CLR_FOLDER);
      pg_link(&content, 'r', i_folder, NULL, "/page/tree.mu", "g", c.gname, "r", c.rname, "ref", c.ref, "path", parent, NULL);
      sb_adds(&content, "`f");
      snprintf(lbl, sizeof(lbl), " ../");
      pg_link(&content, 'r', lbl, NULL, "/page/tree.mu", "g", c.gname, "r", c.rname, "ref", c.ref, "path", parent, NULL);
      sb_addc(&content, '\n');
    }
    for (i = start; i < end; ++i) {
      const tree_entry *e = &entries[i];
      char sub[3300], lbl[1200], size_s[32];
      if (path[0])
        snprintf(sub, sizeof(sub), "%s/%s", path, e->name);
      else
        snprintf(sub, sizeof(sub), "%s", e->name);
      if (!strcmp(e->type, "tree")) {
        sb_adds(&content, CLR_FOLDER);
        pg_link(&content, 'r', i_folder, NULL, "/page/tree.mu", "g", c.gname, "r", c.rname, "ref", c.ref, "path", sub, NULL);
        sb_adds(&content, "`f");
        snprintf(lbl, sizeof(lbl), " %s/", e->name);
        pg_link(&content, 'r', lbl, NULL, "/page/tree.mu", "g", c.gname, "r", c.rname, "ref", c.ref, "path", sub, NULL);
        sb_addc(&content, '\n');
      } else if (!strcmp(e->type, "commit")) {
        sb_addf(&content, "%s\xe2\xa7\x89`f %s `F666(submodule)`f\n", CLR_FOLDER, e->name);
      } else if (!strcmp(e->type, "link")) {
        sb_addf(&content, "%s\xe2\x86\xb3`f %s `F666\xe2\x86\x92 ", CLR_FILE, e->name);
        m_escape(&content, e->link_target ? e->link_target : "unknown");
        sb_adds(&content, "`f\n");
      } else {
        pg_prettysize(size_s, sizeof(size_s), (double)e->size);
        sb_adds(&content, CLR_FILE);
        pg_link(&content, 'r', i_file, NULL, "/page/blob.mu", "g", c.gname, "r", c.rname, "ref", c.ref, "path", sub, NULL);
        sb_adds(&content, "`f");
        snprintf(lbl, sizeof(lbl), " %s", e->name);
        pg_link(&content, 'r', lbl, NULL, "/page/blob.mu", "g", c.gname, "r", c.rname, "ref", c.ref, "path", sub, NULL);
        sb_addf(&content, " `F666(%s)`f\n", size_s);
      }
    }
    if (n > PG_TREE_ENTRIES_PER_PAGE) {
      size_t total_pages = (n + PG_TREE_ENTRIES_PER_PAGE - 1) / PG_TREE_ENTRIES_PER_PAGE;
      int any = 0;
      sb_addc(&content, '\n');
      if (page_num > 0) {
        pg_link(&content, 'b', "\xc2\xab Previous", NULL, "/page/tree.mu", "g", c.gname, "r", c.rname, "ref", c.ref, "path", path,
                "page", pg_itoa(page_num - 1), NULL);
        any = 1;
      }
      if (any)
        sb_adds(&content, " | ");
      sb_addf(&content, "Page %ld of %zu", page_num + 1, total_pages);
      if (end < n) {
        sb_adds(&content, " | ");
        pg_link(&content, 'b', "Next \xc2\xbb", NULL, "/page/tree.mu", "g", c.gname, "r", c.rname, "ref", c.ref, "path", path,
                "page", pg_itoa(page_num + 1), NULL);
      }
      sb_addc(&content, '\n');
    }
  }
  stats_view_succeeded(c.gname, c.rname, rq->identity);
  pg_render(page, sb_str(&content), sb_str(&nav), "tree", rq->st);
done:
  pgit_entries_free(entries, n);
  sb_free(&content);
  sb_free(&nav);
}

#endif
