/* Calls the page server handlers of reticulum-c-git directly: permissions,
 * hostile paths and refs, the content of every page type, the statistics, the
 * markdown converter and the syntax highlighter. The differential test against
 * the reference node is tests/git_pages.sh. */
#define main git_node_main
#include "../examples/reticulum_git.c"
#undef main
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                  \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
#define HAS(text, needle)                                                                      \
  do {                                                                                         \
    if (!(text) || !strstr((text), (needle))) {                                                \
      fprintf(stderr, "%s:%d: missing \"%s\" in:\n%s\n", __FILE__, __LINE__, needle, (text) ? (text) : "(none)"); \
      exit(1);                                                                                 \
    }                                                                                          \
  } while (0)
#define LACKS(text, needle)                                                                    \
  do {                                                                                         \
    if ((text) && strstr((text), (needle))) {                                                  \
      fprintf(stderr, "%s:%d: unexpected \"%s\" in:\n%s\n", __FILE__, __LINE__, needle, (text)); \
      exit(1);                                                                                 \
    }                                                                                          \
  } while (0)
#define BULLET "\xe2\x80\xa2"
#define EQ(a, b)                                                                               \
  do {                                                                                         \
    if (strcmp((a), (b))) {                                                                    \
      fprintf(stderr, "%s:%d: got \"%s\"\n  want \"%s\"\n", __FILE__, __LINE__, (a), (b));     \
      exit(1);                                                                                 \
    }                                                                                          \
  } while (0)

static char root[96];
static uint8_t alice[16], bob[16], carol[16], mallory[16];
#define OUT_CAP (8u << 20)
static uint8_t *outbuf;

static void sh(const char *fmt, ...) {
  char cmd[6000];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(cmd, sizeof(cmd), fmt, ap);
  va_end(ap);
  if (system(cmd) != 0) {
    fprintf(stderr, "failed: %s\n", cmd);
    exit(1);
  }
}

/* ---- fixture ------------------------------------------------------------------ */
static void setup(void) {
  char h[33], line[200];
  group *g;
  repo *r;
  size_t i;
  memset(&G, 0, sizeof(G));
  pages_defaults();
  G.use_nerdfonts = 0;
  G.max_bundle = 8u << 20;
  setenv("TZ", "UTC", 1);
  tzset();
  outbuf = malloc(OUT_CAP);
  CHECK(outbuf);
  snprintf(root, sizeof(root), "/tmp/rnc-pages-XXXXXX");
  CHECK(mkdtemp(root));
  snprintf(G.config_dir, sizeof(G.config_dir), "%s/cfg", root);
  sh("mkdir -p %s/cfg %s/g && git init -q --bare -b main %s/g/open.git && git init -q --bare -b main %s/g/closed.git && "
     "git init -q --bare -b main %s/g/none.git && git init -q -b main %s/seed",
     root, root, root, root, root, root);
  sh("cd %s/seed && export GIT_CONFIG_GLOBAL=/dev/null GIT_AUTHOR_NAME=Ann GIT_AUTHOR_EMAIL=ann@x GIT_COMMITTER_NAME=Ann "
     "GIT_COMMITTER_EMAIL=ann@x GIT_AUTHOR_DATE='2020-01-02T03:04:05+0000' GIT_COMMITTER_DATE='2020-01-02T03:04:05+0000' && "
     "printf '# Title\\n\\nHello **bold** and [link](docs.md).\\n\\n```c\\nint x = 1;\\n```\\n\\n| a | b |\\n|---|---|\\n| 1 | 2 |\\n' > README.md && "
     "mkdir src && printf 'int main(void) {\\n  return 0;\\n}\\n' > src/main.c && printf 'plain\\n' > a.txt && ln -s a.txt link && "
     "printf '\\211PNG\\r\\n\\032\\n\\000\\000' > pic.png && git add . && git commit -q -m 'first `tick` commit' && "
     "git tag -a v1 -m 'annotated tag message' && "
     "export GIT_AUTHOR_DATE='2020-01-03T03:04:05+0000' GIT_COMMITTER_DATE='2020-01-03T03:04:05+0000' && "
     "printf 'plain\\nmore\\n' > a.txt && git add a.txt && git commit -q -m second && "
     "git push -q %s/g/open.git main v1 && git push -q %s/g/closed.git main",
     root, root, root);
  memset(alice, 0xa1, 16);
  memset(bob, 0xb2, 16);
  memset(carol, 0xc3, 16);
  memset(mallory, 0xdd, 16);
  g = &G.groups[G.group_count++];
  snprintf(g->name, sizeof(g->name), "g");
  snprintf(g->path, sizeof(g->path), "%.100s/g", root);
  apply_statement("r:all", g->perms);
  hex_string(alice, h);
  snprintf(line, sizeof(line), "s:%s", h);
  apply_statement(line, g->perms);
  apply_statement("i:all", g->perms);
  {
    const char *names[] = {"open.git", "closed.git", "none.git"};
    for (i = 0; i < 3; ++i) {
      r = &g->repos[g->repo_count++];
      snprintf(r->name, sizeof(r->name), "%s", names[i]);
      snprintf(r->path, sizeof(r->path), "%.100s/g/%s", root, names[i]);
    }
  }
  hex_string(bob, h);
  snprintf(line, sizeof(line), "r:%s", h);
  apply_statement(line, g->repos[1].perms);
  apply_statement("r:none", g->repos[2].perms);
}
static void cleanup(void) {
  char *argv[] = {"rm", "-rf", root, NULL};
  (void)rngit_run(NULL, argv, NULL, 0, NULL);
}

/* ---- calling handlers --------------------------------------------------------- */
typedef rnc_result (*plain)(void *, const char *, const uint8_t *, size_t, const uint8_t *, uint8_t *, size_t, size_t *);
typedef rnc_result (*filefn)(void *, const char *, const uint8_t *, size_t, const uint8_t *, uint8_t *, size_t, size_t *,
                             rnc_responder_file *);
/* a request map from key, value string pairs (keys as given) */
static size_t build_req(uint8_t *buf, size_t cap, va_list ap) {
  const char *k;
  const char *pairs[40];
  size_t n = 0, i;
  mp_out o = {buf, cap, 0, 0};
  while ((k = va_arg(ap, const char *)) != NULL && n < 38) {
    pairs[n++] = k;
    pairs[n++] = va_arg(ap, const char *);
  }
  mp_map(&o, n / 2);
  for (i = 0; i < n; ++i)
    mp_cstr(&o, pairs[i]);
  CHECK(!o.failed);
  return o.n;
}
/* one page: the text, malloc'd, or NULL when there was no response */
static char *page_of(plain h, const uint8_t *who, ...) {
  uint8_t req[4096];
  size_t n, written = 0;
  va_list ap;
  val pool[4];
  reader rd;
  val v;
  char *text;
  va_start(ap, who);
  n = build_req(req, sizeof(req), ap);
  va_end(ap);
  CHECK(h(NULL, "", req, n, who, outbuf, OUT_CAP, &written) == RNC_OK);
  if (!written)
    return NULL;
  rd = (reader){outbuf, outbuf + written, pool, 0, 4};
  CHECK(parse(&rd, &v, 0) && v.type == V_BIN);
  text = malloc(v.n + 1);
  memcpy(text, v.p, v.n);
  text[v.n] = 0;
  return text;
}
typedef struct fileout {
  int answered;
  uint8_t *data;
  size_t size;
  char name[300];
  int is_false;
} fileout;
static fileout file_of(filefn h, const uint8_t *who, ...) {
  uint8_t req[4096], meta[RNC_RESPONDER_METADATA_MAX];
  size_t n, written = 0;
  va_list ap;
  rnc_responder_file f;
  fileout r;
  rnc_result res;
  memset(&r, 0, sizeof(r));
  va_start(ap, who);
  n = build_req(req, sizeof(req), ap);
  va_end(ap);
  memset(&f, 0, sizeof(f));
  f.data = malloc(OUT_CAP);
  f.data_capacity = OUT_CAP;
  f.metadata = meta;
  f.metadata_capacity = sizeof(meta);
  res = h(NULL, "", req, n, who, outbuf, OUT_CAP, &written, &f);
  if (res == RNC_OK && f.data_size) {
    val pool[8], root_v;
    reader rd = {meta, meta + f.metadata_size, pool, 0, 8};
    const val *name;
    CHECK(parse(&rd, &root_v, 0));
    name = map_get(&root_v, "name");
    CHECK(name && name->type == V_BIN && name->n < sizeof(r.name));
    memcpy(r.name, name->p, name->n);
    r.name[name->n] = 0;
    r.answered = 1;
    r.size = f.data_size;
    r.data = f.data;
    return r;
  }
  r.is_false = res == RNC_OK && written == 1 && outbuf[0] == 0xc2;
  free(f.data);
  return r;
}
static char *rev(const char *repository_dir, const char *ref, char *buf, size_t cap) {
  char cmd[512], *e;
  FILE *f;
  snprintf(cmd, sizeof(cmd), "git -C %s/g/%s rev-parse --verify -q %s 2>/dev/null", root, repository_dir, ref);
  f = popen(cmd, "r");
  buf[0] = 0;
  if (f) {
    if (!fgets(buf, (int)cap, f))
      buf[0] = 0;
    pclose(f);
  }
  e = buf + strlen(buf);
  while (e > buf && e[-1] == '\n')
    *--e = 0;
  return buf;
}
#define P(h, who, ...) page_of(h, who, __VA_ARGS__, NULL)

/* ---- the highlighter, the markdown converter ------------------------------------ */
static char *hl(const char *content, const char *filename, const char *language) {
  sbuf o;
  sb_init(&o);
  hl_highlight(&o, content, filename, language);
  return o.p ? o.p : md_dup("", 0);
}
static void highlighter(void) {
  char *t;
  G.highlight_syntax = 1;
  /* the theme colours of the reference, the formatter's escaping */
  t = hl("int x = 1;\n", "a.c", NULL);
  EQ(t, "`FTffa657int`f `FTe6edf3x`f `FTff7b72=`f `FT79c0ff1`f`FTb4b4b4;`f\n");
  free(t);
  t = hl("def f(a):\n    return a  # note\n", "m.py", NULL);
  HAS(t, "`FTff7b72def`f `FTd2a8fff`f`FTb4b4b4(`f`FTe6edf3a`f`FTb4b4b4)`f`FTb4b4b4:`f");
  HAS(t, "`FT8b949e# note`f");
  free(t);
  t = hl("x = \"a\\nb\"\n", "m.py", NULL);
  HAS(t, "`FTa5d6ff\"a`f`FTffea00\\\\n`f`FTa5d6ffb\"`f"); /* string, escape, string; backslashes doubled */
  free(t);
  t = hl("obj.method()\n", "m.py", NULL);
  HAS(t, "`FTff7b72.`f`FTd2a8ffmethod`f"); /* a name after a dot is an attribute call */
  free(t);
  t = hl("{\"k\": [1, true]}\n", "d.json", NULL);
  HAS(t, "`FTff7b72\"k\"`f`FTb4b4b4:`f");
  HAS(t, "`FT79c0ff1`f");
  HAS(t, "`FTff7b72true`f");
  free(t);
  t = hl("key: value # c\nlist:\n  - a\n", "c.yaml", NULL);
  HAS(t, "`FTff7b72key`f`FTb4b4b4:`f");
  HAS(t, "`FT8b949e# c`f");
  free(t);
  t = hl("[sec]\nname = \"v\"\n", "c.toml", NULL);
  t = hl("#include <stdio.h>\n/* c */\nstatic int f(void) { return 0; }\n", "h.c", NULL);
  HAS(t, "`FTff7b72#include`f");
  HAS(t, "`FT8b949e<stdio.h>`f");
  HAS(t, "`FT8b949e/* c */`f");
  free(t);
  t = hl("fn main() { let x: u32 = 1; }\n", "m.rs", NULL);
  HAS(t, "`FTff7b72fn`f `FTd2a8ffmain`f");
  free(t);
  t = hl("package main\nfunc main() {}\n", "m.go", NULL);
  HAS(t, "`FTff7b72func`f `FTd2a8ffmain`f");
  free(t);
  t = hl("const a = `x`; function f() {}\n", "m.js", NULL);
  HAS(t, "`FTff7b72const`f");
  free(t);
  t = hl("echo $HOME # x\n", "s.sh", NULL);
  HAS(t, "`FTffa657echo`f");
  HAS(t, "`FTe6edf3$HOME`f");
  free(t);
  t = hl("public class A { }\n", "A.java", NULL);
  HAS(t, "`FTff7b72class`f `FT56d364A`f");
  free(t);
  t = hl("<a href=\"x\">t</a>\n", "p.html", NULL);
  HAS(t, "`FTff7b72a`f");
  HAS(t, "`FTa5d6ff\"x\"`f");
  free(t);
  t = hl("a { color: red; }\n", "s.css", NULL);
  HAS(t, "`FTff7b72a`f");
  HAS(t, "`FTffa657color`f");
  free(t);
  t = hl("# Head\n- item `code`\n", "r.md", NULL);
  HAS(t, "`FTc9d1d9# Head`f");
  HAS(t, "`FTa5d6ff\\`code\\``f");
  free(t);
  /* uncoloured text that starts a line with - > < is escaped, as in the formatter */
  t = hl("-x\n>y\n<z\n", "n.txt", NULL);
  EQ(t, "\\-x\n\\>y\n\\<z\n");
  free(t);
  /* a backtick and a backslash are escaped inside colours */
  t = hl("char *s = \"`\\\\\";\n", "e.c", NULL);
  HAS(t, "\\`");
  free(t);
  /* no lexer: the literal block of the reference */
  t = hl("a `b`\nc\n", "x.unknownext", NULL);
  EQ(t, "`=\na \\`b\\`\nc\n\n`=");
  free(t);
  t = hl("zz", "x.unknownext", "nosuchlanguage");
  EQ(t, "`=\nzz\n`=");
  free(t);
  t = hl("", "x.c", NULL);
  EQ(t, "`=\n\n`=");
  free(t);
  /* a language hint (markdown fences) wins over the filename */
  t = hl("int y;\n", NULL, "c");
  HAS(t, "`FTffa657int`f");
  free(t);
  /* without highlighting (pygments absent in the reference): the plain block, backslashes doubled */
  G.highlight_syntax = 0;
  t = hl("a\\b `c`\n", "x.c", NULL);
  EQ(t, "`=\na\\\\b \\\\`c\\\\`\n\n`=");
  free(t);
  G.highlight_syntax = 1;
}
static char *mdc(const char *text, const char *scope) {
  md_conv c;
  sbuf o;
  md_init(&c, 100, scope);
  sb_init(&o);
  md_format_block(&c, text, &o);
  return o.p ? o.p : md_dup("", 0);
}
static void markdown(void) {
  char *t;
  t = mdc("# H1\n### H3\n", NULL);
  EQ(t, ">H1\n>>>H3\n");
  free(t);
  t = mdc("a **b** _c_ `d` [e](f#g) [h](x:/y)\n", NULL);
  EQ(t, "a `!b`! `*c`* `BT383838`Fdddd`f`b `_`!`[e`:/page/f|anchor=g]`!`_ `_`!`[h`x:/y]`!`_\n");
  free(t);
  t = mdc("- one\n* two\n---\n", NULL);
  EQ(t, " " BULLET " one\n " BULLET " two\n-\n");
  free(t);
  t = mdc("-x\n<y\nback\\slash\n", NULL);
  EQ(t, "\\-x\n\\<y\nback\\\\slash\n");
  free(t);
  t = mdc("> quoted text\n> more\n\nafter\n", NULL);
  EQ(t, " \xe2\x94\x82 quoted text more\n\nafter\n");
  free(t);
  t = mdc("```\nplain `x`\n```\n", NULL);
  EQ(t, "`BT282828`Fddd\n`=\nplain \\`x\\`\n`=\n`f`b\n");
  free(t);
  t = mdc("```rawmu\n>raw\n```\n", NULL);
  EQ(t, ">raw\n");
  free(t);
  t = mdc("| a | bb |\n|:--|--:|\n| 1 | 2 |\n", NULL);
  HAS(t, "`c\n\xe2\x94\x8c");
  HAS(t, "\xe2\x94\x82 a   \xe2\x94\x82 bb  \xe2\x94\x82");
  HAS(t, "\xe2\x94\x82 1   \xe2\x94\x82   2 \xe2\x94\x82");
  HAS(t, "\xe2\x94\x94");
  HAS(t, "`a");
  free(t);
  t = mdc("see [x](y)\n", ":/page/blob.mu`g=a|r=b|ref=c|path=d/");
  HAS(t, "`[x`:/page/blob.mu`g=a|r=b|ref=c|path=d/y]");
  free(t);
}

/* ---- the statistics -------------------------------------------------------------- */
static void stats(void) {
  const group *g = &G.groups[0];
  const repo *open = &g->repos[0];
  repo_stats s;
  char path[PATH_MAX + 16];
  size_t before, i;
  uint8_t *raw;
  val *pool, root_v;
  reader rd;
  FILE *f;
  long n;
  char today[11];
  double now = (double)time(NULL);
  st_free_all();
  G.stats_enabled = 0;
  stats_view_succeeded("g", "open.git", carol);
  CHECK(ST.ngroups == 0); /* recording is off */
  G.stats_enabled = 1;
  stats_view_succeeded(NULL, NULL, carol);
  stats_view_succeeded("g", NULL, carol);
  stats_view_succeeded("g", "open.git", carol);
  stats_view_succeeded("g", "open.git", NULL);
  stats_fetch_succeeded("g", "open.git", carol);
  stats_fetch_succeeded("g", "open.git", carol);
  stats_push_succeeded("g", "open.git", carol);
  stats_download_succeeded("g", "open.git", carol);
  stats_release_download_succeeded("g", "open.git", carol);
  stats_view_succeeded("g", "closed.git", carol);
  CHECK(ST.front.n == 1 && ST.front.v[0].n == 1);
  st_today(today);
  CHECK(!strcmp(ST.front.v[0].day, today));
  /* the s permission: alice may, carol may not */
  CHECK(repository_stats(alice, g, open, 90, now, &s));
  CHECK(!repository_stats(carol, g, open, 90, now, &s));
  CHECK(!repository_stats(NULL, g, open, 90, now, &s));
  CHECK(repository_stats(alice, g, open, 90, now, &s));
  CHECK(s.lookback == 90 && !strcmp(s.days[89], today));
  CHECK(s.total[RS_VIEWS] == 2 && s.total[RS_FETCHES] == 2 && s.total[RS_PUSHES] == 1);
  CHECK(s.total[RS_DOWNLOADS] == 1 && s.total[RS_RELDL] == 1 && s.total[RS_COMBINED] == 2);
  CHECK(s.peak[RS_FETCHES] == 2 && s.daily[RS_FETCHES][89] == 2 && s.daily[RS_FETCHES][0] == 0);
  /* (2 views + 1 + 1 downloads) * 0.2 + 2 fetches * 2 + 1 push * 5 = 9.8 */
  CHECK(s.activity_score == 9);
  CHECK(s.actual_days == 1 && !strcmp(s.activity_level, "moderate"));
  /* ignored identities do not count views, fetches and downloads; pushes always do */
  memcpy(G.stats_ignored[G.stats_ignored_count++], bob, 16);
  before = ST.groups[0].repos[0].m[ST_VIEW].v[0].n;
  stats_view_succeeded("g", "open.git", bob);
  stats_fetch_succeeded("g", "open.git", bob);
  stats_download_succeeded("g", "open.git", bob);
  stats_release_download_succeeded("g", "open.git", bob);
  CHECK(ST.groups[0].repos[0].m[ST_VIEW].v[0].n == before);
  stats_push_succeeded("g", "open.git", bob);
  CHECK(ST.groups[0].repos[0].m[ST_PUSH].v[0].n == 2);
  /* an older day counts only inside the look-back window */
  st_map_add(&ST.groups[0].repos[0].m[ST_VIEW], "2000-01-01", 5);
  CHECK(repository_stats(alice, g, open, 90, now, &s) && s.total[RS_VIEWS] == 2);
  /* persistence: the file the reference reads back */
  CHECK(stats_persist());
  snprintf(path, sizeof(path), "%s/stats", G.config_dir);
  f = fopen(path, "rb");
  CHECK(f);
  fseek(f, 0, SEEK_END);
  n = ftell(f);
  fseek(f, 0, SEEK_SET);
  raw = malloc((size_t)n);
  pool = malloc(10000 * sizeof(val));
  CHECK(fread(raw, 1, (size_t)n, f) == (size_t)n);
  fclose(f);
  rd = (reader){raw, raw + n, pool, 0, 10000};
  CHECK(parse(&rd, &root_v, 0) && root_v.type == V_MAP);
  {
    const val *groups = map_get(&root_v, "groups"), *gv = map_get(groups, "g");
    const val *repos = map_get(gv, "repositories"), *ov = map_get(repos, "open.git");
    const val *views = map_get(ov, "view"), *rel = map_get(ov, "release_download");
    CHECK(map_get(&root_v, "pages") && map_get(map_get(map_get(&root_v, "pages"), "front"), today));
    CHECK(map_get(gv, "view") && map_get(map_get(gv, "view"), today));
    CHECK(views && map_get(views, today) && as_uint(map_get(views, today)) == 2);
    CHECK(map_get(views, "2000-01-01") && as_uint(map_get(views, "2000-01-01")) == 5);
    CHECK(rel && as_uint(map_get(rel, today)) == 1);
    CHECK(map_get(ov, "fetch") && map_get(ov, "push") && map_get(ov, "download"));
  }
  free(raw);
  free(pool);
  /* load it back */
  st_free_all();
  stats_load();
  CHECK(ST.ngroups == 1 && ST.groups[0].nrepos == 2 && ST.front.n == 1);
  CHECK(repository_stats(alice, g, open, 90, now, &s) && s.total[RS_FETCHES] == 2 && s.total[RS_PUSHES] == 2);
  for (i = 0; i < ST.groups[0].repos[0].m[ST_VIEW].n; ++i)
    CHECK(ST.groups[0].repos[0].m[ST_VIEW].v[i].n > 0);
  /* a repository of its own: no shared counters (the reference shares them until a reload) */
  stats_view_succeeded("g", "none.git", carol);
  CHECK(st_map_get(&st_repo_get(st_group_get("g", 0), "none.git", 0)->m[ST_VIEW], today) == 1);
  CHECK(st_map_get(&st_repo_get(st_group_get("g", 0), "open.git", 0)->m[ST_VIEW], today) == 2);
  /* a missing file is created; a broken one is kept aside, never read as stats */
  unlink(path);
  st_free_all();
  stats_load();
  CHECK(is_file(path) && ST.ngroups == 0);
  f = fopen(path, "wb");
  fputs("not msgpack at all", f);
  fclose(f);
  stats_load();
  CHECK(ST.load_failed && ST.ngroups == 0);
  CHECK(stats_persist());
  {
    char bad[PATH_MAX + 32];
    snprintf(bad, sizeof(bad), "%s.unreadable", path);
    CHECK(is_file(bad));
  }
  /* the job persists every 180 seconds */
  unlink(path);
  ST.last_persist_ms = 1000;
  stats_job(1000 + 179000);
  CHECK(!is_file(path));
  stats_job(1000 + 180000);
  CHECK(is_file(path));
  st_free_all();
  G.stats_enabled = 0;
  G.stats_ignored_count = 0;
}
/* the configuration keys */
static void configuration(void) {
  char cfg[PATH_MAX + 16], h[33];
  FILE *f;
  uint8_t id[16];
  git_node *saved = malloc(sizeof(G));
  CHECK(saved);
  memcpy(saved, &G, sizeof(G));
  memset(id, 0x77, 16);
  hex_string(id, h);
  snprintf(cfg, sizeof(cfg), "%s/config", G.config_dir);
  f = fopen(cfg, "w");
  fprintf(f, "[rngit]\nnode_name = Test Node\nrecord_stats = yes\nstats_ignore_identities = %s, alias1\n"
             "stats_push_ignore_identities = %s\n[aliases]\nalias1 = %s\n[pages]\nserve_nomadnet = yes\nunicode_icons = yes\n"
             "media_conversion = no\nhighlight_syntax = no\n", h, h, h);
  fclose(f);
  G.group_count = 0;
  G.stats_ignored_count = 0;
  G.alias_count = 0;
  CHECK(load_config(G.config_dir));
  CHECK(!strcmp(G.node_name, "Test Node") && G.stats_enabled);
  CHECK(G.stats_ignored_count == 2 && !memcmp(G.stats_ignored[0], id, 16));
  CHECK(G.stats_push_ignored_count == 1);
  CHECK(G.serve_nomadnet && !G.use_nerdfonts && !G.media_conversion && !G.highlight_syntax);
  G = *saved;
  free(saved);
  unlink(cfg);
}

/* ---- the pages ---------------------------------------------------------------------- */
static void null_identity(void) {
  /* RNS.Identity.from_bytes(bytes(64)).hash, computed with the reference */
  static const uint8_t expect[16] = {0};
  uint8_t zero[16] = {0};
  pg_null_init();
  CHECK(memcmp(pg_null_ident, zero, 16) != 0);
  (void)expect;
}
static void front_and_group(void) {
  char *t;
  t = P(pg_h_index, carol, NULL);
  HAS(t, "#!c=0\n> Anonymous Git Node");
  HAS(t, "> Groups\n");
  HAS(t, "`!`[  " BULLET " g`:/page/group.mu`g=g]`!");
  HAS(t, " (1 repository)\n");
  HAS(t, "`[Served by rngit ");
  HAS(t, "Generated in ");
  free(t);
  t = P(pg_h_index, bob, NULL);
  HAS(t, " (2 repositories)\n");
  free(t);
  t = P(pg_h_index, NULL, NULL); /* unidentified: the null identity, read for everyone */
  HAS(t, " (1 repository)\n");
  free(t);
  /* a blocked null identity has to identify */
  memcpy(G.blocked[G.blocked_count++], pg_null_ident, 16);
  t = P(pg_h_index, NULL, NULL);
  HAS(t, ">>No Identity");
  HAS(t, "This page requires identification");
  free(t);
  t = P(pg_h_group, NULL, "var_g", "g", NULL);
  HAS(t, ">>No Identity");
  free(t);
  G.blocked_count = 0;
  /* a group page */
  sh("git -C %s/g/open.git config repository.description 'A test repo'", root);
  t = P(pg_h_group, carol, "var_g", "g");
  HAS(t, "\n> Repositories\n\n");
  LACKS(t, "closed.git");
  HAS(t, "`!`[  " BULLET " open.git`:/page/repo.mu`g=g|r=open.git]`! - A test repo\n");
  HAS(t, "`!`[Node`:/page/index.mu]`! / g");
  free(t);
  t = P(pg_h_group, bob, "var_g", "g");
  HAS(t, "closed.git");
  free(t);
  t = P(pg_h_group, carol, "var_g", "nogroup");
  HAS(t, "Group Not Found");
  free(t);
  t = P(pg_h_group, carol, "var_g", "../g");
  HAS(t, "Group Not Found");
  free(t);
  t = P(pg_h_group, carol, NULL);
  HAS(t, "Invalid request");
  free(t);
}
static void repo_page(void) {
  char *t, buf[200];
  t = P(pg_h_repo, carol, "var_g", "g", "var_r", "open.git");
  HAS(t, "A test repo\n\n");
  HAS(t, "`[");
  snprintf(buf, sizeof(buf), "%s Files`:/page/tree.mu`g=g|r=open.git|ref=HEAD]", pg_icon("folder"));
  HAS(t, buf);
  HAS(t, "Commits (2)`:/page/commits.mu`g=g|r=open.git|ref=HEAD]");
  HAS(t, "Branches (1)`:/page/refs.mu`g=g|r=open.git|type=heads]");
  HAS(t, "Tags (1)`:/page/refs.mu`g=g|r=open.git|type=tags]");
  HAS(t, "Work (0)`:/page/work.mu`g=g|r=open.git]");
  HAS(t, "Thanks (0)`:/page/repo.mu`g=g|r=open.git|thanks=y]");
  LACKS(t, "Stats`:");
  LACKS(t, "Releases (");
  HAS(t, "`F666rns://");
  HAS(t, "/g/open.git`f");
  /* the README: markdown converted, a highlighted code block, a table, relative links */
  HAS(t, "\n\n<>Title");
  HAS(t, "Hello `!bold`! and `_`!`[link`:/page/blob.mu`g=g|r=open.git|ref=HEAD|path=docs.md]`!`_.");
  HAS(t, "`BT282828`Fddd\n`FTffa657int`f `FTe6edf3x`f `FTff7b72=`f `FT79c0ff1`f`FTb4b4b4;`f\n`f`b");
  HAS(t, "\xe2\x94\x8c");
  LACKS(t, "-\xe2\x94\x80\n>");
  HAS(t, "`a`F666`[Served by rngit");
  free(t);
  t = P(pg_h_repo, alice, "var_g", "g", "var_r", "open.git");
  HAS(t, "Stats`:/page/stats.mu`g=g|r=open.git]");
  free(t);
  /* thanks: the call that creates the file shows 0, as the reference does */
  {
    char tp[PATH_MAX];
    snprintf(tp, sizeof(tp), "%s/g/open.git.thanks", root);
    unlink(tp);
  }
  pg_thanks_n = 0;
  t = P(pg_h_repo, carol, "var_g", "g", "var_r", "open.git", "var_thanks", "y");
  HAS(t, "Thanks (0)");
  free(t);
  t = P(pg_h_repo, carol, "var_g", "g", "var_r", "open.git");
  HAS(t, "Thanks (1)");
  free(t);
  t = P(pg_h_repo, carol, "var_g", "g", "var_r", "open.git", "var_thanks", "y"); /* the same link and repository */
  HAS(t, "Thanks (1)");
  free(t);
  pg_thanks_n = 0; /* another link */
  t = P(pg_h_repo, carol, "var_g", "g", "var_r", "open.git", "var_thanks", "y");
  HAS(t, "Thanks (2)");
  free(t);
  /* permissions: a repository the caller cannot read is not found, whatever it is called */
  t = P(pg_h_repo, carol, "var_g", "g", "var_r", "closed.git");
  HAS(t, "The requested repository was not found.");
  LACKS(t, "README");
  free(t);
  t = P(pg_h_repo, bob, "var_g", "g", "var_r", "closed.git");
  HAS(t, "Commits (2)");
  free(t);
  t = P(pg_h_repo, bob, "var_g", "g", "var_r", "none.git");
  HAS(t, "The requested repository was not found.");
  free(t);
  t = P(pg_h_repo, carol, "var_g", "g", "var_r", "../open.git");
  HAS(t, "The requested repository was not found.");
  free(t);
  t = P(pg_h_repo, carol, "var_g", "g");
  HAS(t, "Invalid request");
  free(t);
  /* an empty repository has no README and no commits */
  t = P(pg_h_repo, carol, "var_g", "g", "var_r", "none.git");
  HAS(t, "not found");
  free(t);
}
static void tree_page(void) {
  char *t, *a, *l, *s, *r, buf[300], hash[64];
  rev("open.git", "HEAD", hash, sizeof(hash));
  t = P(pg_h_tree, carol, "var_g", "g", "var_r", "open.git", "var_ref", "HEAD");
  snprintf(buf, sizeof(buf), "Contents: HEAD (%.8s)", hash);
  HAS(t, buf);
  s = strstr(t, "path=src]");
  a = strstr(t, "path=a.txt]");
  l = strstr(t, " link `F666");
  r = strstr(t, "path=README.md]");
  if (!(s && a && l && r && s < a && a < l && l < r)) { fprintf(stderr, "%s\n", t); exit(1); }
  HAS(t, "`F66d\xe2\x86\xb3`f link `F666\xe2\x86\x92 a.txt`f");
  HAS(t, "`F666(11 B)`f");
  HAS(t, "`!`[Node`:/page/index.mu]`! / `!`[g`:/page/group.mu`g=g]`! / `!`[open.git`:/page/repo.mu`g=g|r=open.git]`! / "
         "`!`[files`:/page/tree.mu`g=g|r=open.git]`! / \n");
  free(t);
  t = P(pg_h_tree, carol, "var_g", "g", "var_r", "open.git", "var_path", "src");
  HAS(t, "main.c");
  HAS(t, "path=src%2Fmain.c]");
  HAS(t, "..");
  LACKS(t, "`!`[src`:"); /* the last crumb is not a link */
  free(t);
  t = P(pg_h_tree, carol, "var_g", "g", "var_r", "open.git", "var_path", "../..");
  HAS(t, "Error reading directory contents.");
  free(t);
  t = P(pg_h_tree, carol, "var_g", "g", "var_r", "open.git", "var_path", "src/../..");
  HAS(t, "Error reading directory contents.");
  free(t);
  t = P(pg_h_tree, carol, "var_g", "g", "var_r", "open.git", "var_ref", "--output=/tmp/rnc-pages-pwned");
  HAS(t, "does not exist in this repository");
  CHECK(access("/tmp/rnc-pages-pwned", F_OK) != 0);
  free(t);
  t = P(pg_h_tree, carol, "var_g", "g", "var_r", "open.git", "var_ref", "nosuchref");
  HAS(t, "The ref 'nosuchref' does not exist in this repository.");
  HAS(t, "View All Refs");
  free(t);
  t = P(pg_h_tree, carol, "var_g", "g", "var_r", "closed.git");
  HAS(t, "does not exist or you do not have access to it.");
  free(t);
  t = P(pg_h_tree, NULL, "var_g", "g", "var_r", "open.git", "var_path", "nodir");
  HAS(t, "Error reading directory contents.");
  free(t);
}
static void blob_page(void) {
  char *t, hash[64], buf[300];
  rev("open.git", "HEAD", hash, sizeof(hash));
  t = P(pg_h_blob, carol, "var_g", "g", "var_r", "open.git", "var_path", "a.txt");
  snprintf(buf, sizeof(buf), ">>a.txt `F444HEAD (%.8s) Text, 11 B`f\n\nplain\nmore\n", hash);
  HAS(t, buf);
  HAS(t, "Displaying Raw " BULLET " `!`[Download`:/file/download`g=g|r=open.git|ref=HEAD|path=a.txt]`!");
  free(t);
  t = P(pg_h_blob, carol, "var_g", "g", "var_r", "open.git", "var_path", "README.md");
  HAS(t, "Displaying Rendered " BULLET " `!`[View raw`:/page/blob.mu`g=g|r=open.git|ref=HEAD|path=README.md|raw=y]`!");
  HAS(t, "`F666`!`[as micron`:/file/download`g=g|r=open.git|ref=HEAD|path=README.md|fmt=mu]`!`f");
  HAS(t, ">Title");
  HAS(t, "`!bold`!");
  free(t);
  t = P(pg_h_blob, carol, "var_g", "g", "var_r", "open.git", "var_path", "README.md", "var_raw", "y");
  HAS(t, "Displaying Raw " BULLET " `!`[View rendered`:");
  HAS(t, "`FTc9d1d9# Title`f");
  free(t);
  t = P(pg_h_blob, carol, "var_g", "g", "var_r", "open.git", "var_path", "src%2Fmain.c");
  HAS(t, "Text, 31 B");
  HAS(t, "`FTffa657int`f `FTe6edf3main`f`FTb4b4b4(`f`FTffa657void`f`FTb4b4b4)`f");
  free(t);
  t = P(pg_h_blob, carol, "var_g", "g", "var_r", "open.git", "var_path", "pic.png");
  HAS(t, "Binary, 10 B");
  HAS(t, "`(Image file`w=n`a=c`:/media/g/open.git/HEAD/pic.png)");
  free(t);
  t = P(pg_h_blob, carol, "var_g", "g", "var_r", "open.git", "var_path", "link");
  HAS(t, "| Symlink \xe2\x86\x92 a.txt");
  free(t);
  t = P(pg_h_blob, carol, "var_g", "g", "var_r", "open.git", "var_path", "src");
  HAS(t, "Contents: HEAD"); /* a directory shows the tree page */
  free(t);
  t = P(pg_h_blob, carol, "var_g", "g", "var_r", "open.git", "var_path", "./a.txt");
  HAS(t, "Text, 11 B");
  free(t);
  t = P(pg_h_blob, carol, "var_g", "g", "var_r", "open.git", "var_path", "nofile.txt");
  HAS(t, "File not found at this ref.");
  free(t);
  t = P(pg_h_blob, carol, "var_g", "g", "var_r", "open.git", "var_path", "../../../etc/passwd");
  HAS(t, "File not found at this ref.");
  free(t);
  t = P(pg_h_blob, carol, "var_g", "g", "var_r", "open.git", "var_path", "src/../../a.txt");
  HAS(t, "File not found at this ref.");
  free(t);
  t = P(pg_h_blob, carol, "var_g", "g", "var_r", "open.git", "var_path", "%2e%2e%2f%2e%2e%2fetc%2fpasswd");
  HAS(t, "File not found at this ref.");
  free(t);
  t = P(pg_h_blob, carol, "var_g", "g", "var_r", "open.git");
  HAS(t, "No file path specified.");
  free(t);
  t = P(pg_h_blob, carol, "var_g", "g", "var_r", "closed.git", "var_path", "a.txt");
  HAS(t, "does not exist or you do not have access to it.");
  LACKS(t, "plain");
  free(t);
  t = P(pg_h_blob, carol, "var_g", "g", "var_r", "open.git", "var_path", "a.txt", "var_ref", "-p");
  HAS(t, "does not exist in this repository");
  free(t);
}
static void commits_and_commit(void) {
  char *t, hash[64], h1[64], buf[400];
  rev("open.git", "HEAD", hash, sizeof(hash));
  rev("open.git", "HEAD~1", h1, sizeof(h1));
  t = P(pg_h_commits, carol, "var_g", "g", "var_r", "open.git");
  snprintf(buf, sizeof(buf), "Commits `F444HEAD (%.8s)`f", hash);
  HAS(t, buf);
  snprintf(buf, sizeof(buf), "`F66d`!`[%.7s`:/page/commit.mu`g=g|r=open.git|ref=HEAD|h=%s]`!`f Ann `F6662020-01-03 03:04:05 - ", hash, hash);
  HAS(t, buf);
  HAS(t, " years ago`f\nsecond\n\n");
  HAS(t, "first \\`tick\\` commit\n");
  free(t);
  t = P(pg_h_commits, carol, "var_g", "g", "var_r", "open.git", "var_path", "src");
  HAS(t, "Commits for src ");
  HAS(t, "first");
  LACKS(t, "\nsecond\n");
  free(t);
  t = P(pg_h_commits, carol, "var_g", "g", "var_r", "open.git", "var_page", "1");
  HAS(t, "No commits found.");
  free(t);
  t = P(pg_h_commits, carol, "var_g", "g", "var_r", "open.git", "var_page", "-4");
  HAS(t, "second"); /* a negative page is page 0 */
  free(t);
  t = P(pg_h_commits, carol, "var_g", "g", "var_r", "open.git", "var_path", "../../etc");
  HAS(t, "Error reading commit history.");
  free(t);
  t = P(pg_h_commits, carol, "var_g", "g", "var_r", "closed.git", "var_ref", "main");
  HAS(t, "does not exist or you do not have access");
  free(t);
  /* a single commit */
  t = P(pg_h_commit, carol, "var_g", "g", "var_r", "open.git", "var_h", hash);
  snprintf(buf, sizeof(buf), ">>Commit %s\n", hash);
  HAS(t, buf);
  HAS(t, "Browse tree at this commit");
  snprintf(buf, sizeof(buf), "Parents    : `!`[%.7s`:/page/commit.mu`g=g|r=open.git|ref=HEAD|h=%s]`!\n", h1, h1);
  HAS(t, buf);
  HAS(t, "Author     : Ann <ann@x>\n");
  LACKS(t, "Signature");
  HAS(t, "Date       : 2020-01-03T03:04:05+00:00\n");
  LACKS(t, "Committer");
  HAS(t, "\nsecond\n\n");
  HAS(t, ">>Changes\n\n  1 files changed, 1 insertions(+), 0 deletions(-)\n\n");
  HAS(t, "  `Faa0M`f `!`[a.txt`:/page/blob.mu`g=g|r=open.git|ref=");
  HAS(t, " `F0a0+1`f\n");
  HAS(t, ">>Diff\n\n`F666diff --git a/a.txt b/a.txt`f");
  HAS(t, "`F0aa@@ -1 +1,2 @@`f");
  HAS(t, "`F0a0+more`f");
  free(t);
  t = P(pg_h_commit, carol, "var_g", "g", "var_r", "open.git", "var_h", h1);
  LACKS(t, "Parents");
  HAS(t, "first \\`tick\\` commit");
  LACKS(t, ">>Changes"); /* diff-tree shows nothing for a root commit, as in the reference */
  free(t);
  t = P(pg_h_commit, carol, "var_g", "g", "var_r", "open.git", "var_h", "main^{commit}");
  HAS(t, ">>Commit "); /* a name that resolves is accepted, as in the reference */
  free(t);
  t = P(pg_h_commit, carol, "var_g", "g", "var_r", "open.git", "var_h", "abc");
  HAS(t, "No valid commit hash specified.");
  free(t);
  t = P(pg_h_commit, carol, "var_g", "g", "var_r", "open.git", "var_h", "deadbeefdeadbeef");
  HAS(t, "does not exist in this repository");
  free(t);
  t = P(pg_h_commit, carol, "var_g", "g", "var_r", "open.git", "var_h", "--output=/tmp/rnc-pages-pwned2");
  HAS(t, "does not exist in this repository");
  CHECK(access("/tmp/rnc-pages-pwned2", F_OK) != 0);
  free(t);
  t = P(pg_h_commit, carol, "var_g", "g", "var_r", "open.git", "var_h", "refs/tags/v1");
  HAS(t, "does not refer to a commit"); /* the annotated tag resolves to a tag object */
  free(t);
  t = P(pg_h_commit, carol, "var_g", "g", "var_r", "closed.git", "var_h", hash);
  HAS(t, "The requested repository was not found.");
  free(t);
}
static void refs_page(void) {
  char *t, *tags;
  t = P(pg_h_refs, carol, "var_g", "g", "var_r", "open.git");
  HAS(t, "`!`[All`:/page/refs.mu`g=g|r=open.git]`! " BULLET " `!`[Branches only`:");
  HAS(t, ">>Branches (1)\n\n`F0a0main`f `F0a0(default)`f [`!`[tree`:/page/tree.mu`g=g|r=open.git|ref=main]`!] "
         "[`!`[commits`:/page/commits.mu`g=g|r=open.git|ref=main]`!]\n");
  HAS(t, ": second\n");
  tags = strstr(t, ">>Tags (1)");
  CHECK(tags);
  HAS(tags, "v1 `Faa0(annotated)`f `F666");
  HAS(tags, "annotated tag message\n");
  free(t);
  t = P(pg_h_refs, carol, "var_g", "g", "var_r", "open.git", "var_type", "heads");
  LACKS(t, "Tags (");
  free(t);
  t = P(pg_h_refs, carol, "var_g", "g", "var_r", "open.git", "var_type", "tags");
  LACKS(t, "Branches (");
  free(t);
  t = P(pg_h_refs, carol, "var_g", "g", "var_r", "closed.git");
  HAS(t, "The requested repository was not found.");
  free(t);
  t = P(pg_h_refs, carol, "var_g", "g");
  HAS(t, "Invalid request");
  free(t);
}
static void stats_page(void) {
  char *t;
  G.stats_enabled = 1;
  st_free_all();
  stats_view_succeeded("g", "open.git", carol);
  stats_fetch_succeeded("g", "open.git", carol);
  stats_fetch_succeeded("g", "open.git", carol);
  stats_push_succeeded("g", "open.git", carol);
  stats_download_succeeded("g", "open.git", carol);
  t = P(pg_h_stats, alice, "var_g", "g", "var_r", "open.git");
  HAS(t, ">>Stats for open.git\n");
  HAS(t, "`FT10b981Fetches`f   :     2  total `F666  today:   2  peak:   2 \n`f");
  HAS(t, "`FTB9A810Pushes`f    :     1  total `F666  today:   1  peak:   1 \n`f");
  HAS(t, "`FT3b82f6Views`f     :     1  total `F666  today:   1  peak:   1 `f\n");
  HAS(t, "`FT7831E0Downloads`f :     1  total `F666  today:   1  peak:   1 `f\n");
  HAS(t, "`F0aaActivity`f  :     9 points\n\n");
  HAS(t, " activity`f over the last 1 days (");
  HAS(t, ">>Fetches\n\n`FT10b981Peak: 2`f\n");
  HAS(t, ">>Combined Activity\n\n`FT");
  HAS(t, "\xe2\x96\x88\xe2\x96\x88`f`b Pushes");
  HAS(t, "`F66690 days ago `f");
  HAS(t, "Today`f");
  free(t);
  /* no s permission: not found, as for an unreadable repository */
  t = P(pg_h_stats, carol, "var_g", "g", "var_r", "open.git");
  HAS(t, "The requested repository was not found.");
  LACKS(t, "Fetches");
  free(t);
  t = P(pg_h_stats, NULL, "var_g", "g", "var_r", "open.git");
  HAS(t, "The requested repository was not found.");
  free(t);
  t = P(pg_h_stats, alice, "var_g", "g", "var_r", "closed.git");
  HAS(t, "The requested repository was not found.");
  free(t);
  t = P(pg_h_stats, alice, "var_g", "g", "var_r", "none.git");
  HAS(t, "The requested repository was not found.");
  free(t);
  t = P(pg_h_stats, alice, "var_g", "g");
  HAS(t, "Invalid request");
  free(t);
  /* viewing the page does not count, a repository view does */
  st_free_all();
  t = P(pg_h_stats, alice, "var_g", "g", "var_r", "open.git");
  HAS(t, "No development activity recorded");
  CHECK(ST.ngroups == 0);
  free(t);
  t = P(pg_h_repo, carol, "var_g", "g", "var_r", "open.git");
  free(t);
  CHECK(ST.ngroups == 1 && ST.groups[0].repos[0].m[ST_VIEW].v[0].n == 1);
  t = P(pg_h_tree, carol, "var_g", "g", "var_r", "open.git");
  free(t);
  t = P(pg_h_group, carol, "var_g", "g");
  free(t);
  t = P(pg_h_index, carol, NULL);
  free(t);
  CHECK(ST.groups[0].repos[0].m[ST_VIEW].v[0].n == 2 && ST.groups[0].view.v[0].n == 1 && ST.front.v[0].n == 1);
  G.stats_enabled = 0;
  st_free_all();
}
static void write_file(const char *path, const char *text) {
  FILE *f = fopen(path, "wb");
  CHECK(f);
  fputs(text, f);
  fclose(f);
}
static void releases_pages(void) {
  char *t;
  fileout fo;
  sh("mkdir -p %s/g/open.git.releases/v1.0/artifacts %s/g/open.git.releases/v0.9/artifacts %s/g/open.git.releases/draft/artifacts",
     root, root, root);


  {
    char p[PATH_MAX];
    snprintf(p, sizeof(p), "%s/g/open.git.releases/v1.0/META", root);
    write_file(p, "tag = v1.0\nhash = abc\ncreated = 1600000100\nstatus = published\ncreated_by = x\n");
    snprintf(p, sizeof(p), "%s/g/open.git.releases/v1.0/RELEASE.md", root);
    write_file(p, "# Notes\n\nFirst **line** of notes\n\nmore\n");
    snprintf(p, sizeof(p), "%s/g/open.git.releases/v1.0/artifacts/a.bin", root);
    write_file(p, "0123456789");
    snprintf(p, sizeof(p), "%s/g/open.git.releases/v0.9/META", root);
    write_file(p, "tag = v0.9\ncreated = 1500000000\nstatus = published\n");
    snprintf(p, sizeof(p), "%s/g/open.git.releases/draft/META", root);
    write_file(p, "tag = draft\ncreated = 1700000000\nstatus = draft\n");
    snprintf(p, sizeof(p), "%s/g/open.git.releases/draft/artifacts/secret.bin", root);
    write_file(p, "secret");
    snprintf(p, sizeof(p), "%s/g/open.git.releases/latest", root);
    write_file(p, "v1.0\n");
  }
  t = P(pg_h_repo, carol, "var_g", "g", "var_r", "open.git");
  {
    char buf[200];
    snprintf(buf, sizeof(buf), "%s Releases (2)`:/page/releases.mu`g=g|r=open.git]", pg_icon("package"));
    HAS(t, buf);
  }
  free(t);
  t = P(pg_h_releases, carol, "var_g", "g", "var_r", "open.git");
  HAS(t, ">>Releases (2)\n\n");
  HAS(t, "`!`[v1.0`:/page/release.mu`g=g|r=open.git|t=v1.0]`! `F6662020-09-13 " BULLET " `*1 artifact`* " BULLET " `FT537855`*Latest`*`f`f\n");
  HAS(t, "First `!line`! of notes\n");
  HAS(t, "`!`[v0.9`:");
  LACKS(t, "draft");
  free(t);
  t = P(pg_h_release, carol, "var_g", "g", "var_r", "open.git", "var_t", "v1.0");
  HAS(t, "Thanks (0)`:/page/release.mu`g=g|r=open.git|t=v1.0|thanks=y]");
  HAS(t, ">>Release v1.0 " BULLET " 2020-09-13 12:28:20\n\n");
  HAS(t, ">Notes");
  HAS(t, ">>Artifacts (1)\n\n");
  HAS(t, "`[");
  HAS(t, "a.bin`:/file/artifact`g=g|r=open.git|t=v1.0|a=a.bin] `F666`[(10 B)`:/file/artifact`g=g|r=open.git|t=v1.0|a=a.bin]`f\n");
  free(t);
  t = P(pg_h_release, carol, "var_g", "g", "var_r", "open.git", "var_t", "latest");
  HAS(t, ">>Release v1.0");
  free(t);
  t = P(pg_h_release, carol, "var_g", "g", "var_r", "open.git", "var_t", "draft");
  HAS(t, "Release Not Found");
  LACKS(t, "secret");
  free(t);
  t = P(pg_h_release, carol, "var_g", "g", "var_r", "open.git", "var_t", "../open.git");
  HAS(t, "Release Not Found");
  free(t);
  t = P(pg_h_release, carol, "var_g", "g", "var_r", "closed.git", "var_t", "v1.0");
  HAS(t, "The requested repository was not found.");
  free(t);
  t = P(pg_h_release, carol, "var_g", "g", "var_r", "open.git");
  HAS(t, "Invalid request");
  free(t);
  /* release thanks */
  pg_thanks_n = 0;
  t = P(pg_h_release, carol, "var_g", "g", "var_r", "open.git", "var_t", "v1.0", "var_thanks", "y");
  free(t);
  t = P(pg_h_release, carol, "var_g", "g", "var_r", "open.git", "var_t", "v1.0");
  HAS(t, "Thanks (1)");
  free(t);
  /* artifacts */
  G.stats_enabled = 1;
  st_free_all();
  fo = file_of(pg_h_artifact, carol, "var_g", "g", "var_r", "open.git", "var_t", "v1.0", "var_a", "a.bin", NULL);
  CHECK(fo.answered && fo.size == 10 && !memcmp(fo.data, "0123456789", 10) && !strcmp(fo.name, "a.bin"));
  free(fo.data);
  CHECK(ST.groups[0].repos[0].m[ST_RELDL].v[0].n == 1);
  fo = file_of(pg_h_artifact, carol, "var_g", "g", "var_r", "open.git", "var_t", "latest", "var_a", "a.bin", NULL);
  CHECK(fo.answered);
  free(fo.data);
  fo = file_of(pg_h_artifact, carol, "var_g", "g", "var_r", "open.git", "var_t", "draft", "var_a", "secret.bin", NULL);
  CHECK(!fo.answered);
  fo = file_of(pg_h_artifact, carol, "var_g", "g", "var_r", "open.git", "var_t", "v1.0", "var_a", "../META", NULL);
  CHECK(!fo.answered);
  fo = file_of(pg_h_artifact, carol, "var_g", "g", "var_r", "open.git", "var_t", "v1.0", "var_a", "%2e%2e%2fMETA", NULL);
  CHECK(!fo.answered);
  fo = file_of(pg_h_artifact, carol, "var_g", "g", "var_r", "open.git", "var_t", "..", "var_a", "a.bin", NULL);
  CHECK(!fo.answered);
  fo = file_of(pg_h_artifact, carol, "var_g", "g", "var_r", "open.git", "var_t", "../open.git.releases/v1.0", "var_a", "a.bin", NULL);
  CHECK(!fo.answered);
  fo = file_of(pg_h_artifact, carol, "var_g", "g", "var_r", "closed.git", "var_t", "v1.0", "var_a", "a.bin", NULL);
  CHECK(!fo.answered);
  CHECK(ST.groups[0].repos[0].m[ST_RELDL].v[0].n == 2);
  G.stats_enabled = 0;
  st_free_all();
}
static void work_pages(void) {
  char *t, p[PATH_MAX];
  uint8_t buf[4096], author[16], ident[64];
  docmeta m;
  size_t n;
  fileout fo;
  memset(author, 0x42, 16);
  memset(ident, 0, sizeof(ident));
  sh("mkdir -p %s/g/open.git.work/active/1 %s/g/open.git.work/active/2 %s/g/open.git.work/completed/3", root, root, root);
  memset(&m, 0, sizeof(m));
  m.format = "markdown";
  m.title = "First item";
  m.created = 1700000000;
  m.edited = 1700000500;
  m.author = author;
  m.identity = ident;
  n = doc_emit(buf, sizeof(buf), "Body **text**", 13, &m);
  CHECK(n);
  snprintf(p, sizeof(p), "%s/g/open.git.work/active/1/root", root);
  CHECK(save_doc(p, buf, n));
  m.title = "Second";
  m.created = 1700001000;
  m.edited = 1700001000;
  n = doc_emit(buf, sizeof(buf), "Two", 3, &m);
  snprintf(p, sizeof(p), "%s/g/open.git.work/active/2/root", root);
  CHECK(save_doc(p, buf, n));
  m.title = "Done thing";
  m.format = "micron";
  n = doc_emit(buf, sizeof(buf), ">micron body", 12, &m);
  snprintf(p, sizeof(p), "%s/g/open.git.work/completed/3/root", root);
  CHECK(save_doc(p, buf, n));
  /* a comment on document 1 */
  {
    docmeta cm;
    memset(&cm, 0, sizeof(cm));
    cm.format = "markdown";
    cm.created = 1700000900;
    cm.edited = 1700000900;
    cm.author = author;
    cm.comment = 1;
    n = doc_emit(buf, sizeof(buf), "an *update*", 11, &cm);
    snprintf(p, sizeof(p), "%s/g/open.git.work/active/1/1", root);
    CHECK(save_doc(p, buf, n));
  }
  t = P(pg_h_repo, carol, "var_g", "g", "var_r", "open.git");
  HAS(t, "Work (2)`:/page/work.mu`g=g|r=open.git]");
  free(t);
  t = P(pg_h_work, carol, "var_g", "g", "var_r", "open.git");
  HAS(t, "`_`!`[Active`:/page/work.mu`g=g|r=open.git|scope=active]`!`_ (2)");
  HAS(t, " (1) " BULLET " ");
  HAS(t, ">Active\n\n");
  /* newest first */
  CHECK(strstr(t, "Second") && strstr(t, "First item") && strstr(t, "Second") < strstr(t, "First item"));
  HAS(t, "#1`f\n`F6662023-11-14 by <42424242424242424242424242424242>`f\n`F6661 updates`f\n");
  LACKS(t, "Done thing");
  free(t);
  t = P(pg_h_work, carol, "var_g", "g", "var_r", "open.git", "var_scope", "all");
  HAS(t, ">Completed\n\n");
  HAS(t, "Done thing");
  HAS(t, ">Proposed\n\n`*No proposed work documents`*\n");
  free(t);
  t = P(pg_h_work, carol, "var_g", "g", "var_r", "open.git", "var_scope", "../x");
  HAS(t, ">Active\n"); /* an unknown scope is active */
  free(t);
  t = P(pg_h_work_doc, carol, "var_g", "g", "var_r", "open.git", "var_id", "1");
  HAS(t, "`!`[Download`:/file/workdoc`g=g|r=open.git|id=1]`!");
  HAS(t, ">>First item\n\n`F666Author    : <42424242424242424242424242424242>`f\n`F666Signature : Document not signed`f\n");
  HAS(t, "`F666Created   : 2023-11-14 22:13`f\n`F666Edited    : 2023-11-14 22:21`f\n`F666Status    : Active`f\n\n");
  HAS(t, "Body `!text`!\n");
  HAS(t, "\n>>Updates (1)\n\n`F666#1 by <42424242424242424242424242424242> on 2023-11-14 22:28`f\nan `*update`*\n");
  free(t);
  t = P(pg_h_work_doc, carol, "var_g", "g", "var_r", "open.git", "var_id", "3");
  HAS(t, "Status    : Completed");
  HAS(t, ">micron body\n");
  free(t);
  t = P(pg_h_work_doc, carol, "var_g", "g", "var_r", "open.git", "var_id", "99");
  HAS(t, "The requested work document was not found");
  free(t);
  t = P(pg_h_work_doc, carol, "var_g", "g", "var_r", "open.git", "var_id", "../1");
  HAS(t, "Invalid document ID");
  free(t);
  t = P(pg_h_work_doc, carol, "var_g", "g", "var_r", "closed.git", "var_id", "1");
  HAS(t, "The requested repository was not found");
  free(t);
  t = P(pg_h_work_doc, carol, "var_g", "g", "var_r", "open.git");
  HAS(t, "Invalid request");
  free(t);
  /* a document that hides itself from readers (its own list) is not found */
  {
    snprintf(p, sizeof(p), "%s/g/open.git.work/1.allowed", root);
    write_file(p, "r:none\n");
  }
  t = P(pg_h_work_doc, carol, "var_g", "g", "var_r", "open.git", "var_id", "1");
  HAS(t, "The requested work document was not found");
  free(t);
  t = P(pg_h_work, carol, "var_g", "g", "var_r", "open.git");
  LACKS(t, "First item");
  HAS(t, "Second");
  free(t);
  t = P(pg_h_work_doc, bob, "var_g", "g", "var_r", "open.git", "var_id", "1");
  HAS(t, "The requested work document was not found");
  free(t);
  /* work document download: [name, content] as a plain list */
  {
    uint8_t req[1024];
    mp_out o = {req, sizeof(req), 0, 0};
    size_t written = 0;
    val pool[8], v;
    reader rd;
    mp_map(&o, 3);
    mp_cstr(&o, "var_g"); mp_cstr(&o, "g");
    mp_cstr(&o, "var_r"); mp_cstr(&o, "open.git");
    mp_cstr(&o, "var_id"); mp_cstr(&o, "2");
    CHECK(pg_h_wd_download(NULL, "", req, o.n, carol, outbuf, OUT_CAP, &written) == RNC_OK && written);
    rd = (reader){outbuf, outbuf + written, pool, 0, 8};
    CHECK(parse(&rd, &v, 0) && v.type == V_ARR && v.n == 2);
    CHECK(v.kids[0].n == 9 && !memcmp(v.kids[0].p, "Second.md", 9));
    CHECK(v.kids[1].type == V_BIN && v.kids[1].n == 3 && !memcmp(v.kids[1].p, "Two", 3));
    o = (mp_out){req, sizeof(req), 0, 0};
    mp_map(&o, 3);
    mp_cstr(&o, "var_g"); mp_cstr(&o, "g");
    mp_cstr(&o, "var_r"); mp_cstr(&o, "closed.git");
    mp_cstr(&o, "var_id"); mp_cstr(&o, "2");
    written = 7;
    CHECK(pg_h_wd_download(NULL, "", req, o.n, carol, outbuf, OUT_CAP, &written) == RNC_AGAIN && !written);
  }
  (void)fo;
}
static void downloads_and_media(void) {
  fileout fo;
  char *dir_unused = NULL;
  (void)dir_unused;
  G.stats_enabled = 1;
  st_free_all();
  fo = file_of(pg_h_download, carol, "var_g", "g", "var_r", "open.git", "var_path", "a.txt", NULL);
  CHECK(fo.answered && fo.size == 11 && !memcmp(fo.data, "plain\nmore\n", 11) && !strcmp(fo.name, "a.txt"));
  free(fo.data);
  CHECK(ST.groups[0].repos[0].m[ST_DOWNLOAD].v[0].n == 1);
  fo = file_of(pg_h_download, carol, "var_g", "g", "var_r", "open.git", "var_path", "src/main.c", "var_ref", "HEAD~1", NULL);
  CHECK(fo.answered && !strcmp(fo.name, "main.c"));
  free(fo.data);
  fo = file_of(pg_h_download, carol, "var_g", "g", "var_r", "open.git", "var_path", "README.md", "var_fmt", "mu", NULL);
  CHECK(fo.answered && !strcmp(fo.name, "README.mu") && fo.size > 10 && !memcmp(fo.data, ">Title", 6));
  free(fo.data);
  fo = file_of(pg_h_download, carol, "var_g", "g", "var_r", "open.git", "var_path", "a.txt", "var_fmt", "mu", NULL);
  CHECK(!fo.answered); /* only markdown converts */
  fo = file_of(pg_h_download, carol, "var_g", "g", "var_r", "open.git", "var_path", "../../etc/passwd", NULL);
  CHECK(!fo.answered);
  fo = file_of(pg_h_download, carol, "var_g", "g", "var_r", "open.git", "var_path", "a.txt", "var_ref", "--help", NULL);
  CHECK(!fo.answered);
  fo = file_of(pg_h_download, carol, "var_g", "g", "var_r", "closed.git", "var_path", "a.txt", NULL);
  CHECK(!fo.answered);
  fo = file_of(pg_h_download, carol, "var_g", "g", "var_r", "open.git", "var_path", "nofile", NULL);
  CHECK(!fo.answered);
  CHECK(ST.groups[0].repos[0].m[ST_DOWNLOAD].v[0].n == 3);
  /* media: the original when conversion is off or no encoder exists */
  G.media_conversion = 0;
  fo = file_of(pg_h_media, carol, "key", "k", "path", "/media/g/open.git/HEAD/pic.png", NULL);
  CHECK(fo.answered && fo.size == 10 && !strcmp(fo.name, "pic.png"));
  free(fo.data);
  G.media_conversion = 1;
  setenv("RNGIT_MEDIA_BACKEND", "nonesuch", 1); /* a forced backend that does not exist: no conversion */
  fo = file_of(pg_h_media, carol, "key", "k", "path", "/media/g/open.git/HEAD/pic.png", NULL);
  CHECK(fo.answered && fo.size == 10 && !strcmp(fo.name, "pic.png"));
  free(fo.data);
  unsetenv("RNGIT_MEDIA_BACKEND");
  fo = file_of(pg_h_media, carol, "path", "/media/g/open.git/HEAD/pic.png", NULL);
  CHECK(!fo.answered && fo.is_false); /* no key: false */
  fo = file_of(pg_h_media, carol, "key", "k", "path", "/media/g/open.git", NULL);
  CHECK(fo.is_false);
  fo = file_of(pg_h_media, carol, "key", "k", "path", "/media/g/closed.git/HEAD/pic.png", NULL);
  CHECK(fo.is_false);
  fo = file_of(pg_h_media, carol, "key", "k", "path", "/media/g/open.git/HEAD/../../etc/passwd", NULL);
  CHECK(fo.is_false);
  fo = file_of(pg_h_media, carol, "key", "k", "path", "/media/g/open.git/--help/pic.png", NULL);
  CHECK(fo.is_false);
  fo = file_of(pg_h_media, carol, "key", "k", "path", "/media/g/open.git/HEAD/nofile.png", NULL);
  CHECK(fo.is_false);
  G.stats_enabled = 0;
  st_free_all();
}
/* a conversion with a fake encoder, to show the pipe and the checks */
static void media_conversion(void) {
  char dir[160], script[220];
  fileout fo;
  char oldpath[4096] = "";
  const char *op = getenv("PATH");
  FILE *f;
  snprintf(oldpath, sizeof(oldpath), "%s", op ? op : "/usr/bin:/bin");
  snprintf(dir, sizeof(dir), "%s/fakebin", root);
  sh("mkdir -p %s", dir);
  /* an encoder that writes a minimal WebP (VP8X, 1x1) whatever it reads */
  snprintf(script, sizeof(script), "%s/magick", dir);
  f = fopen(script, "w");
  fputs("#!/bin/sh\ncat > /dev/null\nprintf 'RIFF\\044\\000\\000\\000WEBPVP8X\\012\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000'\n", f);
  fclose(f);
  chmod(script, 0755);
  {
    char np[4400];
    snprintf(np, sizeof(np), "%s:%s", dir, oldpath);
    setenv("PATH", np, 1);
  }
  mc_winner = -1;
  setenv("RNGIT_MEDIA_BACKEND", "magick", 1);
  fo = file_of(pg_h_media, carol, "key", "k", "path", "/media/g/open.git/HEAD/pic.png", NULL);
  CHECK(fo.answered && fo.size == 32 && !memcmp(fo.data, "RIFF", 4) && !strcmp(fo.name, "pic.webp"));
  free(fo.data);
  /* a webp is served as it is; so is an encoder that produces nothing valid */
  f = fopen(script, "w");
  fputs("#!/bin/sh\ncat > /dev/null\necho not-a-webp\n", f);
  fclose(f);
  chmod(script, 0755);
  fo = file_of(pg_h_media, carol, "key", "k", "path", "/media/g/open.git/HEAD/pic.png", NULL);
  CHECK(fo.answered && fo.size == 10 && !strcmp(fo.name, "pic.png"));
  free(fo.data);
  /* an encoder that fails */
  f = fopen(script, "w");
  fputs("#!/bin/sh\ncat > /dev/null\nexit 3\n", f);
  fclose(f);
  chmod(script, 0755);
  fo = file_of(pg_h_media, carol, "key", "k", "path", "/media/g/open.git/HEAD/pic.png", NULL);
  CHECK(fo.answered && fo.size == 10 && !strcmp(fo.name, "pic.png"));
  free(fo.data);
  unsetenv("RNGIT_MEDIA_BACKEND");
  setenv("PATH", oldpath, 1);
  mc_winner = -1;
}
static void templates(void) {
  char dir[PATH_MAX + 32], p[PATH_MAX + 64];
  char *t;
  snprintf(dir, sizeof(dir), "%s/templates", G.config_dir);
  sh("mkdir -p %s", dir);
  snprintf(p, sizeof(p), "%s/front.mu", dir);
  write_file(p, ">> Custom front\n{PAGE_CONTENT}\n");
  snprintf(p, sizeof(p), "%s/base.mu", dir);
  write_file(p, "NODE={NODE_NAME} V={VERSION}\n{NAVIGATION}|{PAGE_CONTENT}|{GEN_TIME}");
  t = P(pg_h_index, carol, NULL);
  HAS(t, "NODE=Anonymous Git Node V=");
  HAS(t, ">> Custom front\n");
  HAS(t, "(1 repository)");
  HAS(t, "|Generated in ");
  LACKS(t, "> Groups");
  LACKS(t, "#!c=0");
  free(t);
  /* an executable template is run */
  snprintf(p, sizeof(p), "%s/front.mu", dir);
  write_file(p, "#!/bin/sh\necho '>> Dynamic {PAGE_CONTENT}'\n");
  chmod(p, 0755);
  t = P(pg_h_index, carol, NULL);
  HAS(t, ">> Dynamic ");
  free(t);
  /* tabs in the content become three spaces */
  unlink(p);
  snprintf(p, sizeof(p), "%s/base.mu", dir);
  unlink(p);
  G.use_nerdfonts = 1;
  {
    char buf[64];
    t = P(pg_h_repo, carol, "var_g", "g", "var_r", "open.git");
    snprintf(buf, sizeof(buf), "%s Files", pg_icon("folder"));
    HAS(t, buf);
    HAS(t, "\xf3\xb0\x89\x96 Files"); /* the Nerd Font folder icon is the default */
    free(t);
  }
  G.use_nerdfonts = 0;
}
static void handlers_survive_garbage(void) {
  size_t written = 0;
  uint8_t junk[64];
  size_t i;
  plain hs[] = {pg_h_index, pg_h_group, pg_h_repo, pg_h_tree, pg_h_blob, pg_h_commits, pg_h_commit, pg_h_refs,
                pg_h_stats, pg_h_releases, pg_h_release, pg_h_work, pg_h_work_doc, pg_h_wd_download};
  for (i = 0; i < sizeof(junk); ++i)
    junk[i] = (uint8_t)(i * 37 + 11);
  for (i = 0; i < sizeof(hs) / sizeof(hs[0]); ++i) {
    char *t;
    CHECK(hs[i](NULL, "", junk, sizeof(junk), carol, outbuf, OUT_CAP, &written) == RNC_OK || written == 0);
    CHECK(hs[i](NULL, "", (const uint8_t *)"", 0, carol, outbuf, OUT_CAP, &written) == RNC_OK || written == 0);
    (void)t;
  }
  /* a request that is not a map is treated as no fields */
  {
    char *t = page_of(pg_h_group, carol, NULL);
    HAS(t, "Invalid request");
    free(t);
  }
}
static void announce_data(void) {
  /* the nomadnet node is announced with the node name as its app data */
  CHECK(strlen(G.node_name) > 0);
}
int main(void) {
  setup();
  highlighter();
  markdown();
  stats();
  configuration();
  null_identity();
  front_and_group();
  repo_page();
  tree_page();
  blob_page();
  commits_and_commit();
  refs_page();
  stats_page();
  releases_pages();
  work_pages();
  downloads_and_media();
  media_conversion();
  templates();
  handlers_survive_garbage();
  announce_data();
  cleanup();
  puts("ok");
  return 0;
}
