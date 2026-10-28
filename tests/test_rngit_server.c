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
static uint8_t alice[16], bob[16], carol[16], mallory[16], dave[16];
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
  memset(dave, 0xd4, 16);
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
     "git push -q %s/g/open.git main && git push -q %s/g/closed.git main && "
     "git tag v1 && git push -q %s/g/open.git v1",
     root, root, root, root);
  identities();
  g = &G.groups[G.group_count++];
  snprintf(g->name, sizeof(g->name), "g");
  snprintf(g->path, sizeof(g->path), "%.100s/g", root);
  apply_statement("r:all", g->perms);
  hex(alice, h);
  snprintf(line, sizeof(line), "w:%s", h);
  apply_statement(line, g->perms);
  hex(alice, h);
  snprintf(line, sizeof(line), "rel:%s", h);
  apply_statement(line, g->perms);
  snprintf(line, sizeof(line), "i:%s", h);
  apply_statement(line, g->perms);
  apply_statement("p:all", g->perms);
  hex(bob, h);
  snprintf(line, sizeof(line), "c:%s", h);
  apply_statement(line, g->perms);
  hex(dave, h);
  snprintf(line, sizeof(line), "adm:%s", h);
  apply_statement(line, g->perms);
  {
    char a[33], b[33];
    hex(alice, a);
    hex(bob, b);
    snprintf(g->access, sizeof(g->access), "r:all, w:%s, rel:%s, i:%s, p:all, c:%s, adm:%s", a, a, a, b, h);
  }
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


/* The value after the status byte of a reply (a packed map or list). */
static val reply_pool[512], reply_value_root;
static const val *reply_value(void) {
  reader rd = {out, out + out_size, reply_pool, 0, 512}, in;
  val bin;
  CHECK(parse(&rd, &bin, 0) && bin.type == V_BIN && bin.n > 1 && bin.p[0] == 0);
  in = (reader){bin.p + 1, bin.p + bin.n, reply_pool + 256, 0, 256};
  CHECK(parse(&in, &reply_value_root, 0));
  return &reply_value_root;
}
static void make(const char *name, const uint8_t *who) {
  mp_out o = {malloc(256), 256, 0, 0};
  char repository[128];
  snprintf(repository, sizeof(repository), "g/%s", name);
  mp_map(&o, 1); mp_uint(&o, 0); mp_cstr(&o, repository);
  call(handle_create, &o, who);
}
static int exists(const char *name) {
  char path[200];
  struct stat st;
  snprintf(path, sizeof(path), "%.100s/g/%s", root, name);
  return !stat(path, &st);
}
static void file_text(const char *name, char *buf, size_t cap) {
  char path[200];
  FILE *f;
  size_t n = 0;
  snprintf(path, sizeof(path), "%.100s/g/%s", root, name);
  f = fopen(path, "r");
  buf[0] = 0;
  if (f) {
    n = fread(buf, 1, cap - 1, f);
    fclose(f);
  }
  buf[n] = 0;
}
static void creating(void) {
  char text[256], h[33];
  make("fresh.git", carol); /* may read, may not create */
  CHECK(status() == GIT_RES_DISALLOWED && !strcmp(message(), "Not allowed") && !exists("fresh.git"));
  make("fresh.git", NULL);
  CHECK(status() == GIT_RES_DISALLOWED && !strcmp(message(), "Not identified"));
  make("fresh.git", bob);
  CHECK(status() == GIT_RES_OK && exists("fresh.git/HEAD"));
  hex(bob, h);
  file_text("fresh.git.allowed", text, sizeof(text));
  CHECK(!strncmp(text, "adm:", 4) && !strncmp(text + 4, h, 32));
  /* the creator administers it: loaded and effective at once */
  CHECK(G.groups[0].repo_count == 4);
  CHECK(allowed(bob, &G.groups[0], &G.groups[0].repos[3], P_WRITE) == 0 ||
        allowed(bob, &G.groups[0], &G.groups[0].repos[3], P_ADMIN));
  make("fresh.git", bob);
  CHECK(status() == GIT_RES_DISALLOWED && !strcmp(message(), "Repository already exists"));
  make("fresh.git", mallory); /* cannot even read the group's create right */
  CHECK(status() == GIT_RES_DISALLOWED || status() == GIT_RES_NOT_FOUND);
  make("..", bob);
  CHECK(status() != GIT_RES_OK);
  make(".hidden.git", bob);
  CHECK(status() == GIT_RES_INVALID_REQ && !exists(".hidden.git"));
  {
    mp_out o = {malloc(256), 256, 0, 0};
    mp_map(&o, 1); mp_uint(&o, 0); mp_cstr(&o, "nogroup/x.git");
    call(handle_create, &o, bob);
    CHECK(status() == GIT_RES_NOT_FOUND);
  }
  /* a group administrator creates without a create entry of their own */
  make("dave.git", dave);
  CHECK(status() == GIT_RES_OK);
}
static void perm_request(mp_out *o, const char *op, const char *step, const char *target,
                         const char *content) {
  size_t pairs = 3 + (content != NULL);
  *o = (mp_out){malloc(1 << 14), 1 << 14, 0, 0};
  mp_map(o, pairs);
  mp_uint(o, op[0] == 'g' ? 2 : 0);
  mp_cstr(o, target);
  mp_cstr(o, "operation"); mp_cstr(o, op);
  mp_cstr(o, "step"); mp_cstr(o, step);
  if (content) {
    mp_cstr(o, "content");
    mp_cstr(o, content);
  }
}
static void permissions_management(void) {
  mp_out o;
  char text[512], h[33], content[200];
  /* group permissions: administrators only; others see nothing or are refused */
  perm_request(&o, "gperms", "get", "g", NULL);
  call(handle_perms, &o, carol);
  CHECK(status() == GIT_RES_DISALLOWED && !strcmp(message(), "Not allowed"));
  perm_request(&o, "gperms", "get", "g", NULL);
  call(handle_perms, &o, mallory); /* r:all lets mallory read, so the same refusal */
  CHECK(status() == GIT_RES_DISALLOWED);
  perm_request(&o, "gperms", "get", "nosuch", NULL);
  call(handle_perms, &o, dave);
  CHECK(status() == GIT_RES_NOT_FOUND);
  perm_request(&o, "gperms", "get", "g", NULL);
  call(handle_perms, &o, dave);
  CHECK(status() == GIT_RES_OK); /* no g.allowed yet: empty content */
  /* an invalid statement is refused with its line */
  perm_request(&o, "gperms", "set", "g", "# comment\nbogus\n");
  call(handle_perms, &o, dave);
  CHECK(status() == GIT_RES_INVALID_REQ && strstr(message(), "\"bogus\" on line 2"));
  /* a valid set is written and takes effect: carol can now write */
  hex(carol, h);
  snprintf(content, sizeof(content), "w:%s\n", h);
  perm_request(&o, "gperms", "set", "g", content);
  call(handle_perms, &o, carol);
  CHECK(status() == GIT_RES_DISALLOWED);
  CHECK(!allowed(carol, &G.groups[0], &G.groups[0].repos[0], P_WRITE));
  perm_request(&o, "gperms", "set", "g", content);
  call(handle_perms, &o, dave);
  CHECK(status() == GIT_RES_OK);
  file_text("../g.allowed", text, sizeof(text));
  CHECK(!strcmp(text, content));
  CHECK(allowed(carol, &G.groups[0], &G.groups[0].repos[0], P_WRITE));
  /* the config's own [access] statements still apply after the reload */
  CHECK(allowed(carol, &G.groups[0], &G.groups[0].repos[0], P_READ));
  /* an executable resolver can only be changed node-side */
  {
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "chmod +x %.100s/g.allowed", root);
    CHECK(!system(cmd));
    perm_request(&o, "gperms", "set", "g", "r:all\n");
    call(handle_perms, &o, dave);
    CHECK(status() == GIT_RES_DISALLOWED && strstr(message(), "node-side"));
    snprintf(cmd, sizeof(cmd), "chmod -x %.100s/g.allowed", root);
    CHECK(!system(cmd));
  }
  /* repository permissions: dave created dave.git, so is its administrator */
  perm_request(&o, "rperms", "get", "g/dave.git", NULL);
  call(handle_perms, &o, carol);
  CHECK(status() == GIT_RES_DISALLOWED);
  perm_request(&o, "rperms", "get", "g/dave.git", NULL);
  call(handle_perms, &o, dave);
  CHECK(status() == GIT_RES_OK && strstr(message(), "adm:"));
  perm_request(&o, "rperms", "set", "g/dave.git", "r:none\nbogus\n");
  call(handle_perms, &o, dave);
  CHECK(status() == GIT_RES_INVALID_REQ);
  perm_request(&o, "rperms", "set", "g/dave.git", "r:none\n");
  call(handle_perms, &o, dave);
  CHECK(status() == GIT_RES_OK);
  CHECK(!allowed(carol, &G.groups[0], &G.groups[0].repos[4], P_READ));
  /* bob administers fresh.git but, as the reference requires, setting also
   * needs administration of the group */
  perm_request(&o, "rperms", "set", "g/fresh.git", "r:all\n");
  call(handle_perms, &o, bob);
  CHECK(status() == GIT_RES_DISALLOWED);
  perm_request(&o, "nonsense", "get", "g", NULL);
  call(handle_perms, &o, dave);
  CHECK(status() == GIT_RES_INVALID_REQ);
}

typedef rnc_result (*filehandler)(void *, const char *, const uint8_t *, size_t, const uint8_t *,
                                  uint8_t *, size_t, size_t *, rnc_responder_file *);
static uint8_t file_data[1 << 20], file_meta[256];
static rnc_responder_file file_out = {file_data, sizeof(file_data), 0, file_meta, sizeof(file_meta), 0};
static void rel_call(mp_out *o, const uint8_t *who) {
  CHECK(!o->failed);
  out_size = 0;
  file_out.data_size = file_out.metadata_size = 0;
  CHECK(handle_release(NULL, "", o->p, o->n, who, out, sizeof(out), &out_size, &file_out) == RNC_OK);
  free(o->p);
}
static void rel_req(mp_out *o, const char *op, const char *step, const char *tag, const char *extra_key,
                    const char *extra_value) {
  size_t pairs = 2 + (step != NULL) + (tag != NULL) + (extra_key != NULL);
  *o = (mp_out){malloc(1 << 16), 1 << 16, 0, 0};
  mp_map(o, pairs);
  mp_uint(o, 0); mp_cstr(o, "g/open.git");
  mp_cstr(o, "operation"); mp_cstr(o, op);
  if (step) { mp_cstr(o, "step"); mp_cstr(o, step); }
  if (tag) { mp_cstr(o, "tag"); mp_cstr(o, tag); }
  if (extra_key) { mp_cstr(o, extra_key); mp_cstr(o, extra_value); }
}
static void releases(void) {
  mp_out o;
  /* readers can list (nothing yet) but not create */
  rel_req(&o, "list", NULL, NULL, NULL, NULL);
  rel_call(&o, carol);
  CHECK(status() == GIT_RES_OK);
  rel_req(&o, "create", "init", "v1", NULL, NULL);
  rel_call(&o, carol);
  CHECK(status() == GIT_RES_DISALLOWED);
  rel_req(&o, "create", "init", "nosuch", NULL, NULL);
  rel_call(&o, alice);
  CHECK(status() == GIT_RES_INVALID_REQ && strstr(message(), "does not exist"));
  rel_req(&o, "create", "init", "..", NULL, NULL);
  rel_call(&o, alice);
  CHECK(status() == GIT_RES_INVALID_REQ);
  rel_req(&o, "create", "init", "v1", "notes", "Fixed things\nin detail");
  rel_call(&o, alice);
  CHECK(status() == GIT_RES_OK);
  rel_req(&o, "create", "init", "v1", NULL, NULL);
  rel_call(&o, alice);
  CHECK(status() == GIT_RES_DISALLOWED && !strcmp(message(), "Release already exists"));
  /* an artifact needs a draft release; the data may be binary */
  {
    uint8_t blob[300];
    size_t i;
    mp_out a = {malloc(1 << 12), 1 << 12, 0, 0};
    for (i = 0; i < sizeof(blob); ++i)
      blob[i] = (uint8_t)(i * 7);
    mp_map(&a, 5);
    mp_uint(&a, 0); mp_cstr(&a, "g/open.git");
    mp_cstr(&a, "operation"); mp_cstr(&a, "create");
    mp_cstr(&a, "step"); mp_cstr(&a, "artifact");
    mp_cstr(&a, "tag"); mp_cstr(&a, "v1");
    mp_cstr(&a, "artifact_name"); mp_cstr(&a, "../evil");
    rel_call(&a, alice);
    CHECK(status() == GIT_RES_INVALID_REQ); /* the name would leave the artifacts directory (and has no data) */
    a = (mp_out){malloc(1 << 12), 1 << 12, 0, 0};
    mp_map(&a, 6);
    mp_uint(&a, 0); mp_cstr(&a, "g/open.git");
    mp_cstr(&a, "operation"); mp_cstr(&a, "create");
    mp_cstr(&a, "step"); mp_cstr(&a, "artifact");
    mp_cstr(&a, "tag"); mp_cstr(&a, "v1");
    mp_cstr(&a, "artifact_name"); mp_cstr(&a, "tool.bin");
    mp_cstr(&a, "artifact_data"); mp_bin(&a, blob, sizeof(blob));
    rel_call(&a, alice);
    CHECK(status() == GIT_RES_OK);
  }
  rel_req(&o, "create", "finalize", "v1", NULL, NULL);
  rel_call(&o, alice);
  CHECK(status() == GIT_RES_OK);
  rel_req(&o, "create", "finalize", "v1", NULL, NULL);
  rel_call(&o, alice);
  CHECK(status() == GIT_RES_DISALLOWED && strstr(message(), "finalized"));
  /* list and view show the published release as latest */
  rel_req(&o, "list", NULL, NULL, NULL, NULL);
  rel_call(&o, carol);
  CHECK(status() == GIT_RES_OK);
  {
    val pool[64];
    reader rd = {out, out + out_size, pool, 0, 64};
    val bin, listing;
    const val *rels, *latest;
    CHECK(parse(&rd, &bin, 0) && bin.type == V_BIN);
    {
      reader in = {bin.p + 1, bin.p + bin.n, pool, 0, 64};
      CHECK(parse(&in, &listing, 0) && listing.type == V_MAP);
    }
    rels = map_get(&listing, "releases");
    latest = map_get(&listing, "latest");
    CHECK(rels && rels->type == V_ARR && rels->n == 1);
    CHECK(latest && latest->type == V_STR && latest->n == 2 && !memcmp(latest->p, "v1", 2));
    CHECK(map_get(&rels->kids[0], "artifacts") && as_uint(map_get(&rels->kids[0], "artifacts")) == 1);
    CHECK(map_get(&rels->kids[0], "preview") && !memcmp(map_get(&rels->kids[0], "preview")->p, "Fixed things\nin detail", 22));
  }
  rel_req(&o, "view", NULL, "latest", NULL, NULL);
  rel_call(&o, carol);
  CHECK(status() == GIT_RES_OK);
  {
    const val *v = reply_value(), *arts = map_get(v, "artifacts"), *notes = map_get(v, "notes");
    CHECK(arts && arts->type == V_ARR && arts->n == 1 && as_uint(map_get(&arts->kids[0], "size")) == 300);
    CHECK(notes && notes->n == 22 && !memcmp(notes->p, "Fixed things\nin detail", 22));
    CHECK(map_get(v, "status") && !memcmp(map_get(v, "status")->p, "published", 9));
  }
  /* fetch answers with the file and its name as metadata */
  {
    mp_out f = {malloc(1 << 12), 1 << 12, 0, 0};
    mp_map(&f, 4);
    mp_uint(&f, 0); mp_cstr(&f, "g/open.git");
    mp_cstr(&f, "operation"); mp_cstr(&f, "fetch");
    mp_cstr(&f, "tag"); mp_cstr(&f, "latest");
    mp_cstr(&f, "artifact"); mp_cstr(&f, "tool.bin");
    rel_call(&f, carol);
    CHECK(file_out.data_size == 300 && file_out.metadata_size > 0);
    CHECK(file_data[1] == 7 && file_data[299] == (uint8_t)(299 * 7));
    f = (mp_out){malloc(1 << 12), 1 << 12, 0, 0};
    mp_map(&f, 4);
    mp_uint(&f, 0); mp_cstr(&f, "g/open.git");
    mp_cstr(&f, "operation"); mp_cstr(&f, "fetch");
    mp_cstr(&f, "tag"); mp_cstr(&f, "v1");
    mp_cstr(&f, "artifact"); mp_cstr(&f, "../../v1/META");
    rel_call(&f, carol);
    CHECK(status() == GIT_RES_INVALID_REQ && !file_out.data_size);
  }
  /* the reference would remove the releases directory's parent here */
  rel_req(&o, "delete", NULL, "..", NULL, NULL);
  rel_call(&o, alice);
  CHECK(status() == GIT_RES_INVALID_REQ && exists("open.git/HEAD"));
  rel_req(&o, "delete", NULL, "v1", NULL, NULL);
  rel_call(&o, carol);
  CHECK(status() == GIT_RES_DISALLOWED && exists("open.git.releases/v1"));
  rel_req(&o, "delete", NULL, "v1", NULL, NULL);
  rel_call(&o, alice);
  CHECK(status() == GIT_RES_OK && !exists("open.git.releases/v1"));
}

static rnc_identity wa, wb, wc, wd;
static void grant(const rnc_identity *id, const char *perm) {
  char h[33], line[64];
  hex(id->hash, h);
  snprintf(line, sizeof(line), "%s:%s", perm, h);
  apply_statement(line, G.groups[0].perms);
}
static void work_req(mp_out *o, const char *op, long doc_id, const char *title, const char *content,
                     const rnc_identity *signer, const char *scope, const char *step, const char *bad_sig) {
  uint8_t sig[64];
  size_t pairs = 2 + (doc_id > 0) + (title != NULL) + (content != NULL) + (signer != NULL || bad_sig != NULL) +
                 (scope != NULL) + (step != NULL);
  *o = (mp_out){malloc(1 << 16), 1 << 16, 0, 0};
  mp_map(o, pairs);
  mp_uint(o, 0); mp_cstr(o, "g/open.git");
  mp_cstr(o, "operation"); mp_cstr(o, op);
  if (doc_id > 0) { mp_cstr(o, "doc_id"); mp_uint(o, (uint64_t)doc_id); }
  if (title) { mp_cstr(o, "title"); mp_cstr(o, title); }
  if (content) { mp_cstr(o, "content"); mp_cstr(o, content); }
  if (signer) {
    CHECK(rnc_identity_sign(signer, content ? content : "", content ? strlen(content) : 0, sig) == RNC_OK);
    mp_cstr(o, "signature"); mp_bin(o, sig, 64);
  } else if (bad_sig) {
    memset(sig, 0x55, 64);
    mp_cstr(o, "signature"); mp_bin(o, sig, 64);
  }
  if (scope) { mp_cstr(o, "scope"); mp_cstr(o, scope); }
  if (step) { mp_cstr(o, "step"); mp_cstr(o, step); }
}
static void work_call(mp_out *o, const rnc_identity *who) {
  CHECK(!o->failed);
  test_identity = who;
  out_size = 0;
  CHECK(handle_work(NULL, "", o->p, o->n, who->hash, out, sizeof(out), &out_size) == RNC_OK);
  test_identity = NULL;
  free(o->p);
}
static void work_documents(void) {
  mp_out o;
  char h[33], text[300];
  const val *v;
  CHECK(rnc_identity_generate(&wa, rngit_random, NULL) == RNC_OK);
  CHECK(rnc_identity_generate(&wb, rngit_random, NULL) == RNC_OK);
  CHECK(rnc_identity_generate(&wc, rngit_random, NULL) == RNC_OK);
  CHECK(rnc_identity_generate(&wd, rngit_random, NULL) == RNC_OK);
  grant(&wa, "w"); grant(&wa, "i");
  grant(&wb, "i");
  grant(&wd, "adm");
  /* a signed document by a writer who may interact */
  work_req(&o, "create", 0, "Bug one", "It breaks", &wa, NULL, NULL, NULL);
  work_call(&o, &wa);
  CHECK(status() == GIT_RES_OK);
  v = reply_value();
  CHECK(as_uint(map_get(v, "id")) == 1 && map_get(v, "scope") && !memcmp(map_get(v, "scope")->p, "active", 6));
  work_req(&o, "create", 0, "Bug two", "x", NULL, NULL, NULL, "bad");
  work_call(&o, &wa);
  CHECK(status() == GIT_RES_INVALID_REQ && !strcmp(message(), "Invalid signature"));
  work_req(&o, "create", 0, "Bug two", "x", NULL, NULL, NULL, NULL);
  work_call(&o, &wa);
  CHECK(status() == GIT_RES_INVALID_REQ && !strcmp(message(), "No signature provided"));
  work_req(&o, "create", 0, "Bug three", "x", &wc, NULL, NULL, NULL);
  work_call(&o, &wc); /* a reader cannot create */
  CHECK(status() == GIT_RES_DISALLOWED);
  work_req(&o, "create", 0, "", "content", &wa, NULL, NULL, NULL);
  work_call(&o, &wa);
  CHECK(status() == GIT_RES_INVALID_REQ && !strcmp(message(), "Title is required"));
  /* list and view */
  work_req(&o, "list", 0, NULL, NULL, NULL, NULL, NULL, NULL);
  work_call(&o, &wc);
  CHECK(status() == GIT_RES_OK);
  v = reply_value();
  CHECK(map_get(v, "active")->n == 1 && map_get(v, "completed")->n == 0);
  CHECK(!memcmp(map_get(&map_get(v, "active")->kids[0], "title")->p, "Bug one", 7));
  work_req(&o, "view", 1, NULL, NULL, NULL, NULL, NULL, NULL);
  work_call(&o, &wc);
  CHECK(status() == GIT_RES_OK);
  v = reply_value();
  hex(wa.hash, h);
  CHECK(!memcmp(map_get(v, "content")->p, "It breaks", 9));
  CHECK(!memcmp(map_get(map_get(v, "meta"), "author")->p, h, 32));
  CHECK(map_get(map_get(v, "meta"), "signature")->type == V_BIN && map_get(map_get(v, "meta"), "signature")->n == 64);
  CHECK(map_get(map_get(v, "meta"), "identity")->n == 64);
  /* only the author edits, with a signature over the content as sent */
  work_req(&o, "edit", 1, NULL, "Now it fails twice", &wb, NULL, NULL, NULL);
  work_call(&o, &wb);
  CHECK(status() == GIT_RES_DISALLOWED); /* wb has no write */
  work_req(&o, "edit", 1, NULL, "Now it fails twice", &wa, NULL, NULL, NULL);
  work_call(&o, &wa);
  CHECK(status() == GIT_RES_OK);
  work_req(&o, "view", 1, NULL, NULL, NULL, NULL, NULL, NULL);
  work_call(&o, &wc);
  v = reply_value();
  CHECK(!memcmp(map_get(v, "content")->p, "Now it fails twice", 18) && !memcmp(map_get(map_get(v, "meta"), "title")->p, "Bug one", 7));
  /* comments need to interact */
  work_req(&o, "comment", 1, NULL, "me too", NULL, NULL, NULL, NULL);
  work_call(&o, &wb);
  CHECK(status() == GIT_RES_OK && as_uint(map_get(reply_value(), "id")) == 1);
  work_req(&o, "comment", 1, NULL, "me three", NULL, NULL, NULL, NULL);
  work_call(&o, &wc);
  CHECK(status() == GIT_RES_DISALLOWED);
  work_req(&o, "view", 1, NULL, NULL, NULL, NULL, NULL, NULL);
  work_call(&o, &wc);
  v = reply_value();
  CHECK(map_get(v, "comments")->n == 1 && !memcmp(map_get(&map_get(v, "comments")->kids[0], "content")->p, "me too", 6));
  /* anyone with propose may propose; the proposer owns it */
  work_req(&o, "propose", 0, "An idea", "Do the thing", &wc, NULL, NULL, NULL);
  work_call(&o, &wc);
  CHECK(status() == GIT_RES_OK && as_uint(map_get(reply_value(), "id")) == 2);
  file_text("open.git.work/2.allowed", text, sizeof(text));
  hex(wc.hash, h);
  CHECK(strstr(text, h) && strstr(text, "i:") && strstr(text, "w:"));
  /* completing and reactivating move the document between scopes */
  work_req(&o, "complete", 1, NULL, NULL, NULL, NULL, NULL, NULL);
  work_call(&o, &wb);
  CHECK(status() == GIT_RES_DISALLOWED); /* interact but no write: no manage rights */
  work_req(&o, "complete", 1, NULL, NULL, NULL, NULL, NULL, NULL);
  work_call(&o, &wa);
  CHECK(status() == GIT_RES_OK && !memcmp(map_get(reply_value(), "scope")->p, "completed", 9));
  work_req(&o, "list", 0, NULL, NULL, NULL, "all", NULL, NULL);
  work_call(&o, &wc);
  v = reply_value();
  CHECK(map_get(v, "active")->n == 0 && map_get(v, "completed")->n == 1 && map_get(v, "proposed")->n == 1);
  work_req(&o, "activate", 1, NULL, NULL, NULL, NULL, NULL, NULL);
  work_call(&o, &wa);
  CHECK(status() == GIT_RES_OK && !memcmp(map_get(reply_value(), "scope")->p, "active", 6));
  /* document permissions: administrators only */
  work_req(&o, "perms", 2, NULL, NULL, NULL, NULL, "get", NULL);
  work_call(&o, &wa);
  CHECK(status() == GIT_RES_DISALLOWED);
  work_req(&o, "perms", 2, NULL, "r:none\n", NULL, NULL, "set", NULL);
  work_call(&o, &wd);
  CHECK(status() == GIT_RES_OK);
  work_req(&o, "view", 2, NULL, NULL, NULL, NULL, NULL, NULL);
  work_call(&o, &wb); /* the document now hides itself from readers */
  CHECK(status() == GIT_RES_NOT_FOUND);
  work_req(&o, "perms", 2, NULL, "garbage\n", NULL, NULL, "set", NULL);
  work_call(&o, &wd);
  CHECK(status() == GIT_RES_INVALID_REQ);
  /* deleting: the author or an administrator */
  work_req(&o, "delete", 1, NULL, NULL, NULL, NULL, NULL, NULL);
  work_call(&o, &wb);
  CHECK(status() == GIT_RES_DISALLOWED); /* no manage right */
  work_req(&o, "delete", 1, NULL, NULL, NULL, NULL, NULL, NULL);
  work_call(&o, &wa);
  CHECK(status() == GIT_RES_OK && !exists("open.git.work/active/1"));
  work_req(&o, "view", 1, NULL, NULL, NULL, NULL, NULL, NULL);
  work_call(&o, &wa);
  CHECK(status() == GIT_RES_NOT_FOUND);
  /* a path-like document id is not a document */
  {
    mp_out w = {malloc(1 << 10), 1 << 10, 0, 0};
    mp_map(&w, 3);
    mp_uint(&w, 0); mp_cstr(&w, "g/open.git");
    mp_cstr(&w, "operation"); mp_cstr(&w, "view");
    mp_cstr(&w, "doc_id"); mp_cstr(&w, "../1");
    work_call(&w, &wa);
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
  creating();
  permissions_management();
  releases();
  work_documents();
  cleanup();
  return 0;
}
