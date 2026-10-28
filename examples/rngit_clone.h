/* Forks, mirrors and upstream sync for reticulum-c-git (included by
 * reticulum_git.c). The node fetches from another repository with git itself,
 * so an rns:// source goes through git-remote-rns. */
#ifndef RETICULUM_C_RNGIT_CLONE_H
#define RETICULUM_C_RNGIT_CLONE_H

static int git_config_get(const char *cwd, const char *key, char *out, size_t cap) {
  char *argv[] = {"git", "config", (char *)key, NULL};
  size_t n;
  char *e;
  proc_result r = rngit_run(cwd, argv, out, cap, &n);
  if (r.status != 0)
    return 0;
  e = out + strlen(out);
  while (e > out && (e[-1] == '\n' || e[-1] == ' ' || e[-1] == '\r'))
    *--e = 0;
  return 1;
}
static int git_config_set(const char *cwd, const char *key, const char *value) {
  char *argv[] = {"git", "config", (char *)key, (char *)value, NULL};
  return rngit_run(cwd, argv, NULL, 0, NULL).status == 0;
}
static void repo_kind_load(repo *r) {
  char type[32], source[512];
  r->fork_src[0] = r->mirror_src[0] = 0;
  if (!git_config_get(r->path, "repository.rngit.type", type, sizeof(type)))
    return;
  if (!git_config_get(r->path, "repository.rngit.upstream.source", source, sizeof(source)) || !*source)
    return;
  if (!strcmp(type, "fork"))
    snprintf(r->fork_src, sizeof(r->fork_src), "%s", source);
  else if (!strcmp(type, "mirror"))
    snprintf(r->mirror_src, sizeof(r->mirror_src), "%s", source);
}
static long mirror_synced(const char *path) {
  char value[64];
  if (!git_config_get(path, "repository.rngit.upstream.sync", value, sizeof(value)))
    return 0;
  return strtol(value, NULL, 10);
}
static int set_synced(const char *path) {
  char value[32];
  snprintf(value, sizeof(value), "%lld", (long long)time(NULL));
  return git_config_set(path, "repository.rngit.upstream.sync", value);
}
/* Points HEAD at the source's default branch, or at the first local branch. */
static int update_head_from_source(const char *repo_path, const char *source) {
  char out[2048], branch[512] = "";
  char *ls[] = {"git", "ls-remote", "--symref", (char *)source, "HEAD", NULL};
  size_t n;
  proc_result r;
  rngit_run_timeout_ms = 30000;
  r = rngit_run(NULL, ls, out, sizeof(out), &n);
  if (r.status == 0) {
    char *save = NULL, *line;
    for (line = strtok_r(out, "\n", &save); line; line = strtok_r(NULL, "\n", &save))
      if (!strncmp(line, "ref: refs/heads/", 16)) {
        char *tab = strchr(line, '\t');
        if (tab && !strcmp(tab + 1, "HEAD")) {
          *tab = 0;
          snprintf(branch, sizeof(branch), "%s", line + 5);
          break;
        }
      }
  }
  if (*branch) {
    char *show[] = {"git", "show-ref", "--verify", "--quiet", branch, NULL};
    if (rngit_run(repo_path, show, NULL, 0, NULL).status != 0)
      branch[0] = 0;
  }
  if (!*branch) {
    char *first[] = {"git", "for-each-ref", "--format=%(refname:short)", "refs/heads", "--count=1", NULL};
    char name[300];
    if (rngit_run(repo_path, first, name, sizeof(name), &n).status != 0)
      return 0;
    {
      char *e = name + strlen(name);
      while (e > name && (e[-1] == '\n' || e[-1] == ' ')) *--e = 0;
    }
    if (!*name)
      return 0;
    snprintf(branch, sizeof(branch), "refs/heads/%s", name);
  }
  {
    char *sym[] = {"git", "symbolic-ref", "HEAD", branch, NULL};
    return rngit_run(repo_path, sym, NULL, 0, NULL).status == 0;
  }
}
static int fetch_all_refs(const char *repo_path, const char *source) {
  char *fetch[] = {"git", "fetch", (char *)source, "+refs/*:refs/*", NULL};
  proc_result r = rngit_run(repo_path, fetch, NULL, 0, NULL);
  if (r.status != 0)
    log_line("Failed to fetch from %s: %s", source, r.err);
  return r.status == 0;
}
static int sync_upstream(repo *r, int is_mirror) {
  const char *source = is_mirror ? r->mirror_src : r->fork_src;
  log_line("Syncing %s %s", is_mirror ? "mirror" : "fork", r->name);
  if (!*source || !fetch_all_refs(r->path, source))
    return 0;
  /* a fork keeps its own HEAD; a mirror follows the source */
  if (is_mirror && !update_head_from_source(r->path, source))
    log_line("Could not update HEAD for mirror %s", r->name);
  (void)set_synced(r->path);
  return 1;
}

static const char *const clone_protocols[] = {"rns", "http", "https", "ssh"};
static int clone_source_allowed(const char *url) {
  size_t i, n = 0;
  char scheme[16];
  const char *p = strstr(url, "://");
  if (!p)
    return 0;
  n = (size_t)(p - url);
  if (n >= sizeof(scheme))
    return 0;
  for (i = 0; i < n; ++i)
    scheme[i] = url[i] >= 'A' && url[i] <= 'Z' ? (char)(url[i] + 32) : url[i];
  scheme[n] = 0;
  for (i = 0; i < sizeof(clone_protocols) / sizeof(clone_protocols[0]); ++i)
    if (!strcmp(scheme, clone_protocols[i]))
      return 1;
  return 0;
}
static rnc_result remote_clone(const uint8_t *request_data, size_t size, const uint8_t *identity,
                               uint8_t *out, size_t cap, size_t *written, const char *type) {
  val *pool = malloc(POOL_NODES * sizeof(val)), root;
  const val *repository, *source_v;
  char text[NAME_MAX_LEN * 2 + 2], source[1024], tmp[PATH_MAX], temp_repo[PATH_MAX + NAME_MAX_LEN + 2];
  char final_path[PATH_MAX], allowed_path[PATH_MAX + 16], line[64], hash[33], *slash;
  const char *name;
  group *g;
  int made = 0;
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
  repository = map_get_int(&root, GIT_IDX_REPOSITORY);
  if (!repository) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "No repository specified");
    goto done;
  }
  source_v = map_get(&root, "source");
  if (!source_v || (val_is_text(source_v) && !source_v->n)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "No source specified");
    goto done;
  }
  if (source_v->type != V_STR || !val_copy(source_v, source, sizeof(source))) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid source URL");
    goto done;
  }
  if (!clone_source_allowed(source)) {
    reply(out, cap, written, GIT_RES_DISALLOWED, "Prohibited source URL");
    goto done;
  }
  if (!val_copy(repository, text, sizeof(text)) || !(slash = strchr(text, '/')) ||
      strchr(slash + 1, '/') || strlen(text) > 256 || strlen(slash + 1) > 256 || !text[0] || !slash[1]) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    goto done;
  }
  *slash = 0;
  name = slash + 1;
  g = (group *)find_group(text);
  if (!g) {
    reply(out, cap, written, GIT_RES_NOT_FOUND, "Not found");
    goto done;
  }
  if (!group_allowed(identity, g, P_CREATE)) {
    reply(out, cap, written, group_allowed(identity, g, P_READ) ? GIT_RES_DISALLOWED : GIT_RES_NOT_FOUND,
          group_allowed(identity, g, P_READ) ? "Not allowed" : "Not found");
    goto done;
  }
  if (name[0] == '.' || snprintf(final_path, sizeof(final_path), "%s/%s", g->path, name) >= (int)sizeof(final_path)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    goto done;
  }
  {
    struct stat st;
    const repo *existing = find_repo(g, name);
    if (existing || !stat(final_path, &st)) {
      if (existing && allowed(identity, g, existing, P_READ))
        reply(out, cap, written, GIT_RES_DISALLOWED, "Repository already exists");
      else
        reply(out, cap, written, GIT_RES_NOT_FOUND, "Not found");
      goto done;
    }
  }
  if (g->repo_count >= MAX_REPOS) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Failed to register repository");
    goto done;
  }
  log_line("%sing %s to %s/%s", type, source, g->name, name);
  if (!make_tempdir(tmp, sizeof(tmp))) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
    goto done;
  }
  made = 1;
  snprintf(temp_repo, sizeof(temp_repo), "%s/%s", tmp, name);
  if (mkdir(temp_repo, 0755)) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
    goto done;
  }
  {
    char *init[] = {"git", "init", "--bare", NULL};
    char *fetch[] = {"git", "fetch", source, "+refs/*:refs/*", NULL};
    proc_result pr = rngit_run(temp_repo, init, NULL, 0, NULL);
    char msg[700];
    if (pr.status != 0) {
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Failed to initialize repository");
      goto done;
    }
    pr = rngit_run(temp_repo, fetch, NULL, 0, NULL);
    if (pr.status != 0) {
      log_line("Failed to fetch from %s: %s", source, pr.err);
      snprintf(msg, sizeof(msg), "Failed to fetch from source: %s", pr.err);
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, msg);
      goto done;
    }
    if (!update_head_from_source(temp_repo, source))
      log_line("Failed to update HEAD for repository cloned from %s", source);
    if (!git_config_set(temp_repo, "repository.rngit.type", type) ||
        !git_config_set(temp_repo, "repository.rngit.upstream.source", source) || !set_synced(temp_repo)) {
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Failed to configure repository type: git config failed");
      goto done;
    }
  }
  hex_string(identity, hash);
  snprintf(allowed_path, sizeof(allowed_path), "%s.allowed", final_path);
  snprintf(line, sizeof(line), "adm:%s", hash);
  if (!write_atomic(allowed_path, line, strlen(line))) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Could not initialize repository");
    goto done;
  }
  if (rename(temp_repo, final_path)) { /* another filesystem: move the tree */
    char *mv[] = {"mv", temp_repo, final_path, NULL};
    if (rngit_run(NULL, mv, NULL, 0, NULL).status != 0) {
      unlink(allowed_path);
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Could not write repository");
      goto done;
    }
  }
  {
    repo *r = &g->repos[g->repo_count++];
    memset(r, 0, sizeof(*r));
    snprintf(r->name, sizeof(r->name), "%s", name);
    snprintf(r->path, sizeof(r->path), "%s", final_path);
    reload_repo(r);
    repo_kind_load(r);
  }
  log_line("Repository %s/%s %sed successfully from %s", g->name, name, type, source);
  reply(out, cap, written, GIT_RES_OK, "");
done:
  if (made)
    remove_tree(tmp);
  free(pool);
  return RNC_OK;
}
static rnc_result handle_fork(void *context, const char *path, const uint8_t *request_data,
                              size_t size, const uint8_t *identity, uint8_t *out, size_t cap,
                              size_t *written) {
  (void)context; (void)path;
  return remote_clone(request_data, size, identity, out, cap, written, "fork");
}
static rnc_result handle_mirror(void *context, const char *path, const uint8_t *request_data,
                                size_t size, const uint8_t *identity, uint8_t *out, size_t cap,
                                size_t *written) {
  (void)context; (void)path;
  return remote_clone(request_data, size, identity, out, cap, written, "mirror");
}
static rnc_result handle_sync(void *context, const char *path, const uint8_t *request_data,
                              size_t size, const uint8_t *identity, uint8_t *out, size_t cap,
                              size_t *written) {
  val *pool = malloc(POOL_NODES * sizeof(val)), root;
  const group *g;
  const repo *r;
  (void)context; (void)path;
  if (!pool)
    return RNC_NO_SPACE;
  if (!parse_request(request_data, size, pool, &root)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    goto done;
  }
  if (!locate(&root, identity, &g, &r, out, cap, written))
    goto done;
  if (!r || !allowed(identity, g, r, P_READ)) {
    reply(out, cap, written, GIT_RES_NOT_FOUND, "Not found");
    goto done;
  }
  if (!allowed(identity, g, r, P_WRITE)) {
    reply(out, cap, written, GIT_RES_DISALLOWED, "Not allowed");
    goto done;
  }
  if (r->mirror_src[0]) {
    int ok = sync_upstream((repo *)r, 1);
    reply(out, cap, written, ok ? GIT_RES_OK : GIT_RES_REMOTE_FAIL, ok ? "" : "Mirror sync failed");
  } else if (r->fork_src[0]) {
    int ok = sync_upstream((repo *)r, 0);
    reply(out, cap, written, ok ? GIT_RES_OK : GIT_RES_REMOTE_FAIL, ok ? "" : "Fork sync failed");
  } else
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Repository is neither fork nor mirror");
done:
  free(pool);
  return RNC_OK;
}
/* Called from the main loop: mirrors past their interval are synced. */
static void sync_due_mirrors(void) {
  size_t gi, ri;
  if (!G.mirror_hours)
    return;
  for (gi = 0; gi < G.group_count; ++gi)
    for (ri = 0; ri < G.groups[gi].repo_count; ++ri) {
      repo *r = &G.groups[gi].repos[ri];
      if (r->mirror_src[0] && (long long)time(NULL) > mirror_synced(r->path) + (long long)G.mirror_hours * 3600)
        (void)sync_upstream(r, 1);
    }
}
#endif
