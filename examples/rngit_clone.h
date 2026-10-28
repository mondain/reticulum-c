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

/* ---- jobs: slow git work runs in a child process ------------------------------
 * A fork, mirror or sync can take minutes and may need this very node (an rns://
 * source on the same node is answered by it), so the request is answered later:
 * the handler defers its reply, a child process does the work, and the main loop
 * relays the child's result. The child only runs git; it never touches the
 * network state it inherited. */
#define MAX_JOBS 8
typedef struct job {
  int used;
  pid_t pid;
  int fd;
  rnc_responder_ticket ticket;
  int is_clone;
  group *g;
  char name[NAME_MAX_LEN], path[PATH_MAX], type[16], source[1024];
  char buf[800];
  size_t len;
} job;
static job jobs[MAX_JOBS];
static int job_for_path(const char *path) {
  size_t i;
  for (i = 0; i < MAX_JOBS; ++i)
    if (jobs[i].used && !strcmp(jobs[i].path, path))
      return 1;
  return 0;
}
/* Starts work(arg) in a child whose reply (status byte, text) comes back
 * through a pipe. Returns the job or NULL. */
static job *job_start(int (*work)(void *, char *, size_t), void *arg) {
  size_t i;
  int fds[2];
  pid_t pid;
  job *j = NULL;
  for (i = 0; i < MAX_JOBS && !j; ++i)
    if (!jobs[i].used)
      j = &jobs[i];
  if (!j || pipe(fds))
    return NULL;
  fflush(NULL);
  pid = fork();
  if (pid < 0) {
    close(fds[0]);
    close(fds[1]);
    return NULL;
  }
  if (!pid) {
    char message[700];
    int fd, status;
    size_t n;
    rngit_idle_hook = NULL;
    for (fd = 3; fd < 1024; ++fd)
      if (fd != fds[1])
        close(fd);
    message[0] = 0;
    status = work(arg, message, sizeof(message));
    n = strlen(message);
    {
      uint8_t out[800];
      out[0] = (uint8_t)status;
      memcpy(out + 1, message, n);
      if (write(fds[1], out, n + 1) < 0)
        _exit(1);
    }
    _exit(0);
  }
  close(fds[1]);
  fcntl(fds[0], F_SETFL, O_NONBLOCK);
  memset(j, 0, sizeof(*j));
  j->used = 1;
  j->pid = pid;
  j->fd = fds[0];
  return j;
}
static void job_finish(job *j, int ok_exit);
/* Called from the main loop. */
static void jobs_poll(void) {
  size_t i;
  for (i = 0; i < MAX_JOBS; ++i) {
    job *j = &jobs[i];
    int st = 0;
    ssize_t got;
    pid_t w;
    if (!j->used)
      continue;
    while ((got = read(j->fd, j->buf + j->len, sizeof(j->buf) - j->len)) > 0)
      j->len += (size_t)got;
    w = waitpid(j->pid, &st, WNOHANG);
    if (w == j->pid) {
      while ((got = read(j->fd, j->buf + j->len, sizeof(j->buf) - j->len)) > 0)
        j->len += (size_t)got;
      job_finish(j, WIFEXITED(st) && WEXITSTATUS(st) == 0);
    }
  }
}
static void job_finish(job *j, int ok_exit) {
  uint8_t out[1024];
  size_t written = 0;
  int status = j->len ? (uint8_t)j->buf[0] : GIT_RES_REMOTE_FAIL;
  char message[800];
  size_t n = j->len ? j->len - 1 : 0;
  if (!ok_exit || !j->len) {
    status = GIT_RES_REMOTE_FAIL;
    snprintf(message, sizeof(message), "Remote error");
  } else {
    memcpy(message, j->buf + 1, n);
    message[n] = 0;
  }
  if (j->is_clone && status == GIT_RES_OK && j->g->repo_count < MAX_REPOS) {
    repo *r = &j->g->repos[j->g->repo_count++];
    memset(r, 0, sizeof(*r));
    snprintf(r->name, sizeof(r->name), "%s", j->name);
    snprintf(r->path, sizeof(r->path), "%s", j->path);
    reload_repo(r);
    repo_kind_load(r);
    log_line("Repository %s/%s %sed successfully from %s", j->g->name, j->name, j->type, j->source);
  }
  close(j->fd);
  if (mp_status(out, sizeof(out), &written, (uint8_t)status, message) && G.net.responder)
    (void)rnc_responder_reply(G.net.responder, &j->ticket, out, written, rngit_monotonic_ms());
  memset(j, 0, sizeof(*j));
}

typedef struct clone_args {
  char source[1024], name[NAME_MAX_LEN], final_path[PATH_MAX], type[16], hash[33];
  char group_path[PATH_MAX];
} clone_args;
/* in the child: the whole fork or mirror */
static int clone_work(void *arg, char *message, size_t cap) {
  clone_args *a = arg;
  char tmp[PATH_MAX], temp_repo[PATH_MAX + NAME_MAX_LEN + 2], allowed_path[PATH_MAX + 16], line[64];
  char *init[] = {"git", "init", "--bare", NULL};
  char *fetch[] = {"git", "fetch", a->source, "+refs/*:refs/*", NULL};
  proc_result pr;
  int status = GIT_RES_REMOTE_FAIL;
  if (!make_tempdir(tmp, sizeof(tmp))) {
    snprintf(message, cap, "Remote error");
    return status;
  }
  snprintf(temp_repo, sizeof(temp_repo), "%s/%s", tmp, a->name);
  if (mkdir(temp_repo, 0755)) {
    snprintf(message, cap, "Remote error");
    goto done;
  }
  pr = rngit_run(temp_repo, init, NULL, 0, NULL);
  if (pr.status != 0) {
    snprintf(message, cap, "Failed to initialize repository");
    goto done;
  }
  pr = rngit_run(temp_repo, fetch, NULL, 0, NULL);
  if (pr.status != 0) {
    log_line("Failed to fetch from %s: %s", a->source, pr.err);
    snprintf(message, cap, "Failed to fetch from source: %.500s", pr.err);
    goto done;
  }
  if (!update_head_from_source(temp_repo, a->source))
    log_line("Failed to update HEAD for repository cloned from %s", a->source);
  if (!git_config_set(temp_repo, "repository.rngit.type", a->type) ||
      !git_config_set(temp_repo, "repository.rngit.upstream.source", a->source) || !set_synced(temp_repo)) {
    snprintf(message, cap, "Failed to configure repository type: git config failed");
    goto done;
  }
  snprintf(allowed_path, sizeof(allowed_path), "%s.allowed", a->final_path);
  snprintf(line, sizeof(line), "adm:%s", a->hash);
  if (!write_atomic(allowed_path, line, strlen(line))) {
    snprintf(message, cap, "Could not initialize repository");
    goto done;
  }
  if (rename(temp_repo, a->final_path)) { /* another filesystem: move the tree */
    char *mv[] = {"mv", temp_repo, a->final_path, NULL};
    if (rngit_run(NULL, mv, NULL, 0, NULL).status != 0) {
      unlink(allowed_path);
      snprintf(message, cap, "Could not write repository");
      goto done;
    }
  }
  message[0] = 0;
  status = GIT_RES_OK;
done:
  remove_tree(tmp);
  return status;
}
typedef struct sync_args {
  char path[PATH_MAX], source[1024];
  int is_mirror;
} sync_args;
static int sync_work(void *arg, char *message, size_t cap) {
  sync_args *a = arg;
  repo r;
  memset(&r, 0, sizeof(r));
  snprintf(r.name, sizeof(r.name), "%s", strrchr(a->path, '/') ? strrchr(a->path, '/') + 1 : a->path);
  snprintf(r.path, sizeof(r.path), "%s", a->path);
  snprintf(a->is_mirror ? r.mirror_src : r.fork_src, 512, "%s", a->source);
  if (sync_upstream(&r, a->is_mirror)) {
    message[0] = 0;
    return GIT_RES_OK;
  }
  snprintf(message, cap, "%s", a->is_mirror ? "Mirror sync failed" : "Fork sync failed");
  return GIT_RES_REMOTE_FAIL;
}
/* defer the reply and run work in a child; 0 when no job could start */
static job *spawn_deferred(int (*work)(void *, char *, size_t), void *arg) {
  rnc_responder_ticket ticket;
  job *j;
  if (!G.net.responder || rnc_responder_defer(G.net.responder, &ticket, 2u * 3600u * 1000u) != RNC_OK)
    return NULL;
  j = job_start(work, arg);
  if (!j)
    return NULL;
  j->ticket = ticket;
  return j;
}
static rnc_result remote_clone(const uint8_t *request_data, size_t size, const uint8_t *identity,
                               uint8_t *out, size_t cap, size_t *written, const char *type) {
  val *pool = malloc(POOL_NODES * sizeof(val)), root;
  const val *repository, *source_v;
  char text[NAME_MAX_LEN * 2 + 2], *slash;
  clone_args *args = calloc(1, sizeof(*args));
  const char *name;
  group *g;
  job *j;
  rnc_result result = RNC_OK;
  if (!pool || !args) {
    free(pool);
    free(args);
    return RNC_NO_SPACE;
  }
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
  if (source_v->type != V_STR || !val_copy(source_v, args->source, sizeof(args->source))) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid source URL");
    goto done;
  }
  if (!clone_source_allowed(args->source)) {
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
  if (name[0] == '.' || snprintf(args->final_path, sizeof(args->final_path), "%s/%s", g->path, name) >= (int)sizeof(args->final_path)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    goto done;
  }
  {
    struct stat st;
    const repo *existing = find_repo(g, name);
    if (existing || !stat(args->final_path, &st) || job_for_path(args->final_path)) {
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
  snprintf(args->name, sizeof(args->name), "%s", name);
  snprintf(args->type, sizeof(args->type), "%s", type);
  hex_string(identity, args->hash);
  log_line("%sing %s to %s/%s", type, args->source, g->name, name);
  j = spawn_deferred(clone_work, args);
  if (!j) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
    goto done;
  }
  j->is_clone = 1;
  j->g = g;
  snprintf(j->name, sizeof(j->name), "%s", name);
  snprintf(j->path, sizeof(j->path), "%s", args->final_path);
  snprintf(j->type, sizeof(j->type), "%s", type);
  snprintf(j->source, sizeof(j->source), "%s", args->source);
  result = RNC_AGAIN; /* the reply comes when the child is done */
done:
  free(args);
  free(pool);
  return result;
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
  sync_args *args = calloc(1, sizeof(*args));
  rnc_result result = RNC_OK;
  (void)context; (void)path;
  if (!pool || !args) {
    free(pool);
    free(args);
    return RNC_NO_SPACE;
  }
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
  if (!r->mirror_src[0] && !r->fork_src[0]) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Repository is neither fork nor mirror");
    goto done;
  }
  args->is_mirror = r->mirror_src[0] != 0;
  snprintf(args->path, sizeof(args->path), "%s", r->path);
  snprintf(args->source, sizeof(args->source), "%s", args->is_mirror ? r->mirror_src : r->fork_src);
  if (job_for_path(args->path)) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "A sync of this repository is already running");
    goto done;
  }
  {
    job *j = spawn_deferred(sync_work, args);
    if (!j) {
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
      goto done;
    }
    snprintf(j->path, sizeof(j->path), "%s", args->path);
  }
  result = RNC_AGAIN;
done:
  free(args);
  free(pool);
  return result;
}
/* Called from the main loop: mirrors past their interval are synced (by a
 * child, like a requested sync). */
static void sync_due_mirrors(void) {
  size_t gi, ri, busy = 0, k;
  if (!G.mirror_hours)
    return;
  for (k = 0; k < MAX_JOBS; ++k)
    busy += jobs[k].used;
  for (gi = 0; gi < G.group_count; ++gi)
    for (ri = 0; ri < G.groups[gi].repo_count && busy < MAX_JOBS / 2; ++ri) {
      repo *r = &G.groups[gi].repos[ri];
      sync_args a;
      job *j;
      if (!r->mirror_src[0] || job_for_path(r->path) ||
          (long long)time(NULL) <= mirror_synced(r->path) + (long long)G.mirror_hours * 3600)
        continue;
      memset(&a, 0, sizeof(a));
      a.is_mirror = 1;
      snprintf(a.path, sizeof(a.path), "%s", r->path);
      snprintf(a.source, sizeof(a.source), "%s", r->mirror_src);
      /* no request to answer: run it, and let the poll drop the result */
      j = job_start(sync_work, &a);
      if (j) {
        j->ticket.valid = 0;
        snprintf(j->path, sizeof(j->path), "%s", r->path);
        busy++;
      }
    }
}
#endif
