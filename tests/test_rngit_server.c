/* Calls the request handlers of reticulum-c-git directly, with requests a
 * hostile or buggy client could send that a real git client never would. */
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

static char root[96];
static uint8_t alice[16], bob[16], carol[16], mallory[16];
static uint8_t out[1 << 16];
static size_t out_size;

static void sh(const char *fmt, ...) {
  char cmd[2048];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(cmd, sizeof(cmd), fmt, ap);
  va_end(ap);
  CHECK(system(cmd) == 0);
}
static void identities(void) {
  memset(alice, 0xa1, 16);
  memset(bob, 0xb2, 16);
  memset(carol, 0xc3, 16);
  memset(mallory, 0xdd, 16);
}
static void hex(const uint8_t id[16], char out_hex[33]) {
  size_t i;
  for (i = 0; i < 16; ++i)
    snprintf(out_hex + 2 * i, 3, "%02x", id[i]);
}
/* group "g": group-wide read for everyone, write for alice;
 * repository "open.git" inherits that; "closed.git" has its own list (read for
 * bob only) so the group's grants no longer apply; "none.git" denies everyone. */
static void setup(void) {
  char path[160], line[200], h[33];
  group *g;
  repo *r;
  memset(&G, 0, sizeof(G));
  G.max_bundle = 8u << 20;
  snprintf(root, sizeof(root), "/tmp/rnc-rngit-XXXXXX");
  CHECK(mkdtemp(root));
  snprintf(path, sizeof(path), "%s/g", root);
  CHECK(!mkdir(path, 0700));
  sh("git init -q --bare -b main %s/g/open.git && git init -q --bare -b main %s/g/closed.git", root, root);
  sh("git init -q --bare -b main %s/g/none.git && git init -q -b main %s/seed", root, root);
  sh("cd %s/seed && echo x > f && git add f && git -c user.name=t -c user.email=t@t commit -q -m one && "
     "git push -q %s/g/open.git main && git push -q %s/g/closed.git main",
     root, root, root);
  identities();
  g = &G.groups[G.group_count++];
  snprintf(g->name, sizeof(g->name), "g");
  snprintf(g->path, sizeof(g->path), "%.100s/g", root);
  apply_statement("r:all", g->perms);
  hex(alice, h);
  snprintf(line, sizeof(line), "w:%s", h);
  apply_statement(line, g->perms);
  {
    const char *names[] = {"open.git", "closed.git", "none.git"};
    size_t i;
    for (i = 0; i < 3; ++i) {
      r = &g->repos[g->repo_count++];
      snprintf(r->name, sizeof(r->name), "%s", names[i]);
      snprintf(r->path, sizeof(r->path), "%.100s/g/%s", root, names[i]);
    }
  }
  hex(bob, h);
  snprintf(line, sizeof(line), "r:%s", h);
  apply_statement(line, g->repos[1].perms);
  apply_statement("r:none", g->repos[2].perms);
}
static void cleanup(void) {
  char *argv[] = {"rm", "-rf", root, NULL};
  (void)rngit_run(NULL, argv, NULL, 0, NULL);
}
static int status(void) {
  val pool[4];
  reader rd = {out, out + out_size, pool, 0, 4};
  val v;
  CHECK(out_size && parse(&rd, &v, 0) && v.type == V_BIN && v.n);
  return v.p[0];
}
static const char *message(void) {
  static char text[256];
  val pool[4];
  reader rd = {out, out + out_size, pool, 0, 4};
  val v;
  CHECK(parse(&rd, &v, 0) && v.type == V_BIN && v.n);
  snprintf(text, sizeof(text), "%.*s", (int)(v.n - 1), (const char *)v.p + 1);
  return text;
}
static void begin(mp_out *o, size_t pairs, const char *repository) {
  *o = (mp_out){malloc(1 << 16), 1 << 16, 0, 0};
  mp_map(o, pairs);
  mp_uint(o, 0);
  mp_cstr(o, repository);
}
typedef rnc_result (*plain)(void *, const char *, const uint8_t *, size_t, const uint8_t *,
                            uint8_t *, size_t, size_t *);
static void call(plain h, mp_out *o, const uint8_t *who) {
  CHECK(!o->failed);
  out_size = 0;
  CHECK(h(NULL, "", o->p, o->n, who, out, sizeof(out), &out_size) == RNC_OK);
  free(o->p);
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

/* resolve_permission: repository entries override the group, "none" wins,
 * administrators pass, blocked identities never do. */
static void permissions(void) {
  const group *g = &G.groups[0];
  const repo *open = &g->repos[0], *closed = &g->repos[1], *none = &g->repos[2];
  CHECK(allowed(carol, g, open, P_READ));
  CHECK(!allowed(carol, g, open, P_WRITE));
  CHECK(allowed(alice, g, open, P_WRITE));
  CHECK(!allowed(carol, g, closed, P_READ) && allowed(bob, g, closed, P_READ));
  /* each permission falls back to the group on its own: closed.git lists no
   * writers, so the group's writer still applies */
  CHECK(allowed(alice, g, closed, P_WRITE) && !allowed(carol, g, closed, P_WRITE));
  CHECK(!allowed(alice, g, none, P_READ) && !allowed(carol, g, none, P_READ));
  CHECK(!allowed(alice, NULL, open, P_READ) && !allowed(alice, g, NULL, P_READ));
  memcpy(G.blocked[G.blocked_count++], alice, 16);
  CHECK(!allowed(alice, g, open, P_WRITE) && !allowed(alice, g, open, P_READ));
  G.blocked_count = 0;
  {
    char h[33], line[64];
    hex(carol, h);
    snprintf(line, sizeof(line), "adm:%s", h);
    apply_statement(line, G.groups[0].repos[2].perms);
    /* an administrator of the repository passes only where its own list is
     * not "none": the reference checks none first */
    CHECK(!allowed(carol, g, none, P_READ));
  }
}
static void unidentified_and_unknown(void) {
  mp_out o;
  begin(&o, 1, "g/open.git");
  mp_cstr(&o, "for_push");
  /* patch the map size: only the repository key counts */
  o.p[0] = 0x81;
  o.n = 0;
  mp_map(&o, 1);
  mp_uint(&o, 0);
  mp_cstr(&o, "g/open.git");
  call(handle_list, &o, NULL);
  CHECK(status() == GIT_RES_DISALLOWED && !strcmp(message(), "Not identified"));
  begin(&o, 1, "g/missing.git");
  o.n = 0;
  mp_map(&o, 1); mp_uint(&o, 0); mp_cstr(&o, "g/missing.git");
  call(handle_list, &o, carol);
  CHECK(status() == GIT_RES_NOT_FOUND && !strcmp(message(), "Not found"));
  /* a path that is not group/repository */
  o = (mp_out){malloc(256), 256, 0, 0};
  mp_map(&o, 1); mp_uint(&o, 0); mp_cstr(&o, "g/open.git/../x");
  call(handle_list, &o, carol);
  CHECK(status() == GIT_RES_NOT_FOUND);
  /* not a map */
  o = (mp_out){malloc(16), 16, 0, 0};
  mp_array(&o, 0);
  call(handle_list, &o, carol);
  CHECK(status() == GIT_RES_INVALID_REQ);
}
static void list_for_push(void) {
  mp_out o;
  o = (mp_out){malloc(256), 256, 0, 0};
  mp_map(&o, 2); mp_uint(&o, 0); mp_cstr(&o, "g/open.git"); mp_cstr(&o, "for_push"); mp_bool(&o, 1);
  call(handle_list, &o, carol); /* read only */
  CHECK(status() == GIT_RES_NOT_FOUND && !strcmp(message(), "Not allowed"));
  o = (mp_out){malloc(256), 256, 0, 0};
  mp_map(&o, 2); mp_uint(&o, 0); mp_cstr(&o, "g/open.git"); mp_cstr(&o, "for_push"); mp_bool(&o, 1);
  call(handle_list, &o, alice);
  CHECK(status() == GIT_RES_OK && strstr(message(), "refs/heads/main") && strstr(message(), "@refs/heads/main HEAD"));
  /* a read-only listing for a repository nobody may read */
  o = (mp_out){malloc(256), 256, 0, 0};
  mp_map(&o, 1); mp_uint(&o, 0); mp_cstr(&o, "g/none.git");
  call(handle_list, &o, alice);
  CHECK(status() == GIT_RES_NOT_FOUND);
}
/* The handlers are the last line of defence: they must refuse without the git
 * client's own list step in front of them. */
static void writes_need_write(void) {
  mp_out o;
  char before[128], after[128], sha[128], buf[128];
  rev("open.git", "main", before, sizeof(before));
  /* ref update without write permission */
  o = (mp_out){malloc(1 << 12), 1 << 12, 0, 0};
  mp_map(&o, 2); mp_uint(&o, 0); mp_cstr(&o, "g/open.git"); mp_cstr(&o, "operations");
  mp_array(&o, 1); mp_map(&o, 4);
  mp_cstr(&o, "action"); mp_cstr(&o, "update_ref");
  mp_cstr(&o, "ref"); mp_cstr(&o, "refs/heads/evil");
  mp_cstr(&o, "sha"); mp_cstr(&o, before);
  mp_cstr(&o, "force"); mp_bool(&o, 0);
  call(handle_push, &o, carol);
  CHECK(status() == GIT_RES_DISALLOWED);
  CHECK(!rev("open.git", "refs/heads/evil", buf, sizeof(buf))[0]);
  /* the same request from a writer works */
  o = (mp_out){malloc(1 << 12), 1 << 12, 0, 0};
  mp_map(&o, 2); mp_uint(&o, 0); mp_cstr(&o, "g/open.git"); mp_cstr(&o, "operations");
  mp_array(&o, 1); mp_map(&o, 4);
  mp_cstr(&o, "action"); mp_cstr(&o, "update_ref");
  mp_cstr(&o, "ref"); mp_cstr(&o, "refs/heads/good");
  mp_cstr(&o, "sha"); mp_cstr(&o, before);
  mp_cstr(&o, "force"); mp_bool(&o, 0);
  call(handle_push, &o, alice);
  CHECK(status() == GIT_RES_OK);
  CHECK(!strcmp(rev("open.git", "refs/heads/good", buf, sizeof(buf)), before));
  /* moving an existing ref needs force */
  strcpy(sha, before);
  sha[0] = sha[0] == 'a' ? 'b' : 'a'; /* a different, nonexistent object */
  o = (mp_out){malloc(1 << 12), 1 << 12, 0, 0};
  mp_map(&o, 2); mp_uint(&o, 0); mp_cstr(&o, "g/open.git"); mp_cstr(&o, "operations");
  mp_array(&o, 1); mp_map(&o, 4);
  mp_cstr(&o, "action"); mp_cstr(&o, "update_ref");
  mp_cstr(&o, "ref"); mp_cstr(&o, "refs/heads/good");
  mp_cstr(&o, "sha"); mp_cstr(&o, sha);
  mp_cstr(&o, "force"); mp_bool(&o, 0);
  call(handle_push, &o, alice);
  CHECK(status() == GIT_RES_REMOTE_FAIL && strstr(message(), "does not exist"));
  /* deletion without write permission */
  o = (mp_out){malloc(256), 256, 0, 0};
  mp_map(&o, 2); mp_uint(&o, 0); mp_cstr(&o, "g/open.git"); mp_cstr(&o, "ref"); mp_cstr(&o, "refs/heads/good");
  call(handle_delete, &o, carol);
  CHECK(status() == GIT_RES_DISALLOWED);
  CHECK(!strcmp(rev("open.git", "refs/heads/good", buf, sizeof(buf)), before));
  o = (mp_out){malloc(256), 256, 0, 0};
  mp_map(&o, 2); mp_uint(&o, 0); mp_cstr(&o, "g/open.git"); mp_cstr(&o, "ref"); mp_cstr(&o, "refs/heads/good");
  call(handle_delete, &o, alice);
  CHECK(status() == GIT_RES_OK);
  CHECK(!rev("open.git", "refs/heads/good", buf, sizeof(buf))[0]);
  rev("open.git", "main", after, sizeof(after));
  CHECK(!strcmp(before, after));
}
static void hostile_refs(void) {
  const char *bad[] = {"-refs/heads/x", "refs/heads/../x", "refs/heads/a:b", "refs/heads/a b",
                       "main", "refs/heads/a.lock", "refs/heads/a@{b"};
  size_t i;
  for (i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
    mp_out o = {malloc(1 << 12), 1 << 12, 0, 0};
    mp_map(&o, 2); mp_uint(&o, 0); mp_cstr(&o, "g/open.git"); mp_cstr(&o, "ref"); mp_cstr(&o, bad[i]);
    call(handle_delete, &o, alice);
    CHECK(status() == GIT_RES_INVALID_REQ);
  }
  /* a deletion must stay inside refs/ */
  {
    mp_out o = {malloc(256), 256, 0, 0};
    mp_map(&o, 2); mp_uint(&o, 0); mp_cstr(&o, "g/open.git"); mp_cstr(&o, "ref"); mp_cstr(&o, "HEAD/x");
    call(handle_delete, &o, alice);
    CHECK(status() == GIT_RES_INVALID_REQ);
  }
}
int main(void) {
  setup();
  permissions();
  unidentified_and_unknown();
  list_for_push();
  writes_need_write();
  hostile_refs();
  cleanup();
  return 0;
}
