/* reticulum-c-git: a repository node compatible with the reference rngit.
 *
 *   reticulum-c-git --connect HOST:PORT [--config DIR] [--identity FILE]
 *                   [--print-identity]
 *
 * Serves bare repositories over Reticulum links under the destination
 * git.repositories, to the reference git-remote-rns helper (or
 * reticulum-c-git-remote): list, fetch (a git bundle sent as a Resource), push
 * (a bundle in the request) and ref deletion, with the reference's permission
 * model. It attaches to a node over TCP like the other tools. The config
 * directory (default ~/.rngit) holds the same `config` file as the reference:
 *
 *   [rngit]        announce_interval (minutes), blocked_identities, node_name,
 *                  max_bundle (MiB, 1 to 15, 8 by default: the largest bundle)
 *   [repositories] group = directory of NAME.git bare repositories
 *   [aliases]      name = identity hash
 *   [access]       group = r:all, w:HASH, ...
 *
 * plus group.allowed (next to the group directory) and NAME.allowed (next to a
 * repository) permission files, executable ones included. It serves list, fetch,
 * push and delete, repository creation, forks, mirrors and sync (run in child
 * processes, answered later), permission editing, releases, work documents,
 * statistics and, with `[pages] serve_nomadnet = yes`, the nomadnet page server
 * of the reference. A request that runs git is answered synchronously while the
 * node stays serviced, except forks, mirrors and syncs. */
#include "rngit_common.h"
#include <stdarg.h>
#include <dirent.h>

#define MAX_GROUPS 32
#define MAX_REPOS 256
#define MAX_IDS 64
#define NAME_MAX_LEN 256
#define DEFAULT_MAX_BUNDLE_MIB 8u
#define METADATA_OK_SIZE 3

enum perm { P_READ, P_WRITE, P_CREATE, P_STATS, P_RELEASE, P_INTERACT, P_PROPOSE, P_ADMIN, P_COUNT };

typedef struct perm_set {
  int none, all;
  uint8_t id[MAX_IDS][16];
  size_t count; /* identity entries; "all" and "none" count as entries too */
  size_t entries;
} perm_set;
typedef struct repo {
  char name[NAME_MAX_LEN];
  char path[PATH_MAX];
  char fork_src[512], mirror_src[512]; /* upstream of a fork or a mirror */
  perm_set perms[P_COUNT];
} repo;
typedef struct group {
  char name[NAME_MAX_LEN];
  char path[PATH_MAX];
  perm_set perms[P_COUNT];
  char access[1024]; /* the config's [access] statements for the group */
  repo repos[MAX_REPOS];
  size_t repo_count;
} group;
typedef struct alias {
  char name[64];
  uint8_t hash[16];
} alias;

typedef struct git_node {
  char config_dir[PATH_MAX];
  alias aliases[64];
  size_t alias_count;
  group groups[MAX_GROUPS];
  size_t group_count;
  uint8_t blocked[MAX_IDS][16];
  size_t blocked_count;
  unsigned announce_minutes;
  unsigned mirror_hours; /* mirror sync interval, 0 = never */
  size_t max_bundle;
  char node_name[256];
  int stats_enabled; /* [rngit] record_stats */
  uint8_t stats_ignored[MAX_IDS][16], stats_push_ignored[MAX_IDS][16];
  size_t stats_ignored_count, stats_push_ignored_count;
  int serve_nomadnet, use_nerdfonts, media_conversion, highlight_syntax; /* [pages] */
  rngit_node net;
} git_node;
static git_node G;

/* statistics hooks (rngit_stats.h), called where the reference calls
 * fetch_succeeded and push_succeeded */
static void stats_fetch_succeeded(const char *group, const char *repo, const uint8_t *identity);
static void stats_push_succeeded(const char *group, const char *repo, const uint8_t *identity);

static void log_line(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void log_line(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}

/* ---- permissions --------------------------------------------------------- */
static int resolve_alias(const char *name, uint8_t out[16]) {
  size_t i;
  for (i = 0; i < G.alias_count; ++i)
    if (!strcmp(G.aliases[i].name, name)) {
      memcpy(out, G.aliases[i].hash, 16);
      return 1;
    }
  return 0;
}
static void set_add_none(perm_set *s) { s->none = 1; s->entries++; }
static void set_add_all(perm_set *s) { s->all = 1; s->entries++; }
static void set_add_id(perm_set *s, const uint8_t id[16]) {
  size_t i;
  for (i = 0; i < s->count; ++i)
    if (!memcmp(s->id[i], id, 16))
      return;
  if (s->count < MAX_IDS) {
    memcpy(s->id[s->count++], id, 16);
    s->entries++;
  }
}
static int set_has(const perm_set *s, const uint8_t id[16]) {
  size_t i;
  for (i = 0; i < s->count; ++i)
    if (!memcmp(s->id[i], id, 16))
      return 1;
  return 0;
}
static int perm_from_name(const char *n, int *a, int *b) {
  /* a,b: the one or two permissions the abbreviation grants (-1 for none) */
  *a = *b = -1;
  if (!strcmp(n, "r") || !strcmp(n, "read")) *a = P_READ;
  else if (!strcmp(n, "w") || !strcmp(n, "write")) *a = P_WRITE;
  else if (!strcmp(n, "rw") || !strcmp(n, "readwrite")) { *a = P_READ; *b = P_WRITE; }
  else if (!strcmp(n, "c") || !strcmp(n, "create")) *a = P_CREATE;
  else if (!strcmp(n, "s") || !strcmp(n, "stats")) *a = P_STATS;
  else if (!strcmp(n, "rel") || !strcmp(n, "release")) *a = P_RELEASE;
  else if (!strcmp(n, "i") || !strcmp(n, "interact")) *a = P_INTERACT;
  else if (!strcmp(n, "p") || !strcmp(n, "propose")) *a = P_PROPOSE;
  else if (!strcmp(n, "adm") || !strcmp(n, "admin")) *a = P_ADMIN;
  return *a >= 0;
}
static void lower(char *s) {
  for (; *s; ++s)
    if (*s >= 'A' && *s <= 'Z')
      *s = (char)(*s + 32);
}
static char *trim(char *s) {
  char *e;
  while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
    ++s;
  e = s + strlen(s);
  while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n'))
    *--e = 0;
  return s;
}
/* One "perm:target" statement (parse_permission); applies it to sets. */
static void apply_statement(const char *text, perm_set sets[P_COUNT]) {
  char buf[160], *colon, *name, *target;
  int a, b;
  uint8_t id[16];
  if (strlen(text) >= sizeof(buf))
    return;
  strcpy(buf, text);
  colon = strchr(buf, ':');
  if (!colon || strchr(colon + 1, ':'))
    return;
  *colon = 0;
  name = trim(buf);
  target = colon + 1; /* the reference does not strip the target */
  lower(name);
  if (!perm_from_name(name, &a, &b))
    return;
  if (!strcmp(target, "n") || !strcmp(target, "none") || !strcmp(target, "nobody")) {
    set_add_none(&sets[a]);
    if (b >= 0) set_add_none(&sets[b]);
  } else if (!strcmp(target, "a") || !strcmp(target, "all") || !strcmp(target, "everyone")) {
    set_add_all(&sets[a]);
    if (b >= 0) set_add_all(&sets[b]);
  } else if (resolve_alias(target, id) || rngit_hex_decode(target, id, 16)) {
    set_add_id(&sets[a], id);
    if (b >= 0) set_add_id(&sets[b], id);
  } else
    log_line("Invalid identity hash \"%s\" in access permissions", target);
}
/* An .allowed file: statements one per line; an executable one is run and its
 * output used instead. */
static void load_allowed(const char *path, perm_set sets[P_COUNT]) {
  char *text = NULL, *line, *save = NULL;
  struct stat st;
  size_t n = 0;
  if (stat(path, &st) || !S_ISREG(st.st_mode))
    return;
  text = malloc(65536);
  if (!text)
    return;
  if (access(path, X_OK) == 0) {
    char *argv[2] = {(char *)path, NULL};
    (void)rngit_run(NULL, argv, text, 65536, &n);
  } else {
    FILE *f = fopen(path, "rb");
    if (f) {
      n = fread(text, 1, 65535, f);
      fclose(f);
    }
    text[n] = 0;
  }
  for (line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
    char *t = trim(line);
    if (*t && *t != '#')
      apply_statement(t, sets);
  }
  free(text);
}
static const group *find_group(const char *name) {
  size_t i;
  for (i = 0; i < G.group_count; ++i)
    if (!strcmp(G.groups[i].name, name))
      return &G.groups[i];
  return NULL;
}
static const repo *find_repo(const group *g, const char *name) {
  size_t i;
  for (i = 0; g && i < g->repo_count; ++i)
    if (!strcmp(g->repos[i].name, name))
      return &g->repos[i];
  return NULL;
}
static int blocked(const uint8_t id[16]) {
  size_t i;
  for (i = 0; i < G.blocked_count; ++i)
    if (!memcmp(G.blocked[i], id, 16))
      return 1;
  return 0;
}
/* resolve_permission, statement for statement. */
static int allowed(const uint8_t id[16], const group *g, const repo *r, int p) {
  const perm_set *rp, *gp, *ra, *ga;
  if (blocked(id) || !g || !r)
    return 0;
  rp = &r->perms[p];
  gp = &g->perms[p];
  ra = &r->perms[P_ADMIN];
  ga = &g->perms[P_ADMIN];
  if (rp->none) return 0;
  if (rp->all) return 1;
  if (set_has(rp, id)) return 1;
  if (set_has(ra, id)) return 1;
  if (rp->entries > 0) return 0;
  if (gp->none) return 0;
  if (gp->all) return 1;
  if (set_has(gp, id)) return 1;
  if (set_has(ga, id)) return 1;
  return 0;
}

/* ---- configuration ------------------------------------------------------- */
static void split_list(char *value, void (*fn)(const char *)) {
  char *save = NULL, *tok;
  for (tok = strtok_r(value, ",", &save); tok; tok = strtok_r(NULL, ",", &save))
    fn(trim(tok));
}
static group *cfg_group; /* the group an [access] line applies to */
static void access_statement(const char *s) {
  if (cfg_group)
    apply_statement(s, cfg_group->perms);
}
static void blocked_entry(const char *s) {
  uint8_t id[16];
  if ((resolve_alias(s, id) || rngit_hex_decode(s, id, 16)) && G.blocked_count < MAX_IDS)
    memcpy(G.blocked[G.blocked_count++], id, 16);
}
static int is_bare_git(const char *path) {
  char head[PATH_MAX + 8], cfg[PATH_MAX + 8];
  struct stat st;
  snprintf(head, sizeof(head), "%s/HEAD", path);
  snprintf(cfg, sizeof(cfg), "%s/config", path);
  return !stat(head, &st) && !stat(cfg, &st);
}
static void repo_kind_load(repo *r);
static void load_group(const char *name, const char *path) {
  group *g;
  DIR *d;
  struct dirent *e;
  char allowed_path[PATH_MAX + 16];
  if (G.group_count >= MAX_GROUPS || strlen(name) >= NAME_MAX_LEN || strlen(path) >= PATH_MAX)
    return;
  g = &G.groups[G.group_count];
  memset(g, 0, sizeof(*g));
  strcpy(g->name, name);
  strcpy(g->path, path);
  snprintf(allowed_path, sizeof(allowed_path), "%s.allowed", path);
  load_allowed(allowed_path, g->perms);
  cfg_group = g;
  G.group_count++;
  d = opendir(path);
  if (!d) {
    log_line("Cannot read repository group %s at %s", name, path);
    return;
  }
  while ((e = readdir(d)) != NULL && g->repo_count < MAX_REPOS) {
    char full[PATH_MAX * 2 + 4];
    size_t n = strlen(e->d_name);
    struct stat st;
    repo *r;
    if (e->d_name[0] == '.' || n >= NAME_MAX_LEN || (n > 5 && !strcmp(e->d_name + n - 5, ".work")) ||
        (n > 9 && !strcmp(e->d_name + n - 9, ".releases")))
      continue;
    if (snprintf(full, sizeof(full), "%s/%s", path, e->d_name) >= (int)sizeof(full) ||
        stat(full, &st) || !S_ISDIR(st.st_mode) || strlen(full) >= PATH_MAX)
      continue;
    if (!is_bare_git(full)) {
      log_line("The directory \"%s\" is not a bare git repository, skipping", full);
      continue;
    }
    r = &g->repos[g->repo_count++];
    memset(r, 0, sizeof(*r));
    strcpy(r->name, e->d_name);
    strcpy(r->path, full);
    snprintf(full, sizeof(full), "%s.allowed", r->path);
    load_allowed(full, r->perms);
    repo_kind_load(r);
  }
  closedir(d);
}
static char *expand_home(const char *p, char *out, size_t cap) {
  const char *home = getenv("HOME");
  if (p[0] == '~' && (p[1] == '/' || !p[1]) && home)
    snprintf(out, cap, "%s%s", home, p + 1);
  else
    snprintf(out, cap, "%s", p);
  return out;
}
/* ConfigObj as_bool: yes/true/on/1 and no/false/off/0 */
static int cfg_bool(const char *v, int dflt) {
  char b[16];
  size_t i;
  for (i = 0; v[i] && i < sizeof(b) - 1; ++i)
    b[i] = (char)(v[i] >= 'A' && v[i] <= 'Z' ? v[i] + 32 : v[i]);
  b[i] = 0;
  if (!strcmp(b, "yes") || !strcmp(b, "true") || !strcmp(b, "on") || !strcmp(b, "1"))
    return 1;
  if (!strcmp(b, "no") || !strcmp(b, "false") || !strcmp(b, "off") || !strcmp(b, "0"))
    return 0;
  return dflt;
}
static void ignore_entry_into(const char *s, uint8_t (*list)[16], size_t *count) {
  uint8_t id[16];
  if (strlen(s) == 32 && rngit_hex_decode(s, id, 16)) {
    if (*count < MAX_IDS)
      memcpy(list[(*count)++], id, 16);
  } else if (resolve_alias(s, id) && *count < MAX_IDS)
    memcpy(list[(*count)++], id, 16);
  else if (*s)
    log_line("Invalid identity hash for stats ignore: %s", s);
}
static void stats_ignore_entry(const char *s) { ignore_entry_into(s, G.stats_ignored, &G.stats_ignored_count); }
static void stats_push_ignore_entry(const char *s) {
  ignore_entry_into(s, G.stats_push_ignored, &G.stats_push_ignored_count);
}
static int load_config(const char *dir) {
  char path[PATH_MAX + 16], line[2048], section[64] = "", *t;
  char stats_ignore_text[2048] = "", stats_push_text[2048] = "";
  FILE *f;
  struct { char name[NAME_MAX_LEN]; char path[PATH_MAX]; } pending[MAX_GROUPS];
  size_t pending_count = 0, i;
  struct { char name[NAME_MAX_LEN]; char value[1024]; } access_lines[MAX_GROUPS];
  size_t access_count = 0;
  char blocked_text[2048] = "";
  snprintf(path, sizeof(path), "%s/config", dir);
  f = fopen(path, "r");
  if (!f) {
    log_line("Could not load the configuration at %s", path);
    return 0;
  }
  /* pass one: aliases first, so permissions and the blocklist resolve them */
  while (fgets(line, sizeof(line), f)) {
    char *eq;
    t = trim(line);
    if (*t == '#' || !*t)
      continue;
    if (*t == '[') {
      char *end = strchr(t, ']');
      if (end) {
        *end = 0;
        snprintf(section, sizeof(section), "%s", t + 1);
      }
      continue;
    }
    eq = strchr(t, '=');
    if (!eq)
      continue;
    *eq = 0;
    {
      char *key = trim(t), *value = trim(eq + 1);
      if (!strcmp(section, "aliases")) {
        uint8_t h[16];
        if (G.alias_count < 64 && strlen(key) < 64 && rngit_hex_decode(value, h, 16) &&
            strcmp(key, "all") && strcmp(key, "none")) {
          snprintf(G.aliases[G.alias_count].name, 64, "%s", key);
          memcpy(G.aliases[G.alias_count++].hash, h, 16);
        }
      } else if (!strcmp(section, "repositories")) {
        if (pending_count < MAX_GROUPS && strlen(key) < NAME_MAX_LEN) {
          snprintf(pending[pending_count].name, NAME_MAX_LEN, "%s", key);
          expand_home(value, pending[pending_count].path, PATH_MAX);
          pending_count++;
        }
      } else if (!strcmp(section, "access")) {
        if (access_count < MAX_GROUPS && strlen(key) < NAME_MAX_LEN) {
          snprintf(access_lines[access_count].name, NAME_MAX_LEN, "%s", key);
          snprintf(access_lines[access_count].value, 1024, "%s", value);
          access_count++;
        }
      } else if (!strcmp(section, "rngit")) {
        if (!strcmp(key, "announce_interval"))
          G.announce_minutes = (unsigned)strtoul(value, NULL, 10);
        else if (!strcmp(key, "mirror_interval"))
          G.mirror_hours = (unsigned)strtoul(value, NULL, 10);
        else if (!strcmp(key, "blocked_identities"))
          snprintf(blocked_text, sizeof(blocked_text), "%s", value);
        else if (!strcmp(key, "node_name"))
          snprintf(G.node_name, sizeof(G.node_name), "%s", value);
        else if (!strcmp(key, "record_stats"))
          G.stats_enabled = cfg_bool(value, 0);
        else if (!strcmp(key, "stats_ignore_identities"))
          snprintf(stats_ignore_text, sizeof(stats_ignore_text), "%s", value);
        else if (!strcmp(key, "stats_push_ignore_identities"))
          snprintf(stats_push_text, sizeof(stats_push_text), "%s", value);
        else if (!strcmp(key, "max_bundle")) {
          unsigned long mib = strtoul(value, NULL, 10);
          if (mib >= 1 && mib <= 15)
            G.max_bundle = (size_t)mib << 20;
        }
      } else if (!strcmp(section, "pages")) {
        if (!strcmp(key, "serve_nomadnet"))
          G.serve_nomadnet = cfg_bool(value, 0);
        else if (!strcmp(key, "unicode_icons"))
          G.use_nerdfonts = !cfg_bool(value, 0);
        else if (!strcmp(key, "media_conversion"))
          G.media_conversion = cfg_bool(value, 1);
        else if (!strcmp(key, "highlight_syntax"))
          G.highlight_syntax = cfg_bool(value, 1);
      }
    }
  }
  fclose(f);
  split_list(blocked_text, blocked_entry);
  split_list(stats_ignore_text, stats_ignore_entry);
  split_list(stats_push_text, stats_push_ignore_entry);
  for (i = 0; i < pending_count; ++i) {
    size_t k;
    struct stat st;
    if (stat(pending[i].path, &st) || !S_ISDIR(st.st_mode)) {
      log_line("The path \"%s\" for repository group \"%s\" does not exist, skipping",
               pending[i].path, pending[i].name);
      continue;
    }
    load_group(pending[i].name, pending[i].path);
    for (k = 0; k < access_count; ++k)
      if (!strcmp(access_lines[k].name, pending[i].name)) {
        snprintf(cfg_group->access, sizeof(cfg_group->access), "%s", access_lines[k].value);
        {
          char copy[1024];
          snprintf(copy, sizeof(copy), "%s", access_lines[k].value);
          split_list(copy, access_statement);
        }
      }
  }
  return 1;
}

/* ---- request handlers ---------------------------------------------------- */
static void reply(uint8_t *out, size_t cap, size_t *written, uint8_t status, const char *message) {
  if (!mp_status(out, cap, written, status, message))
    *written = 0;
}
typedef struct request {
  val *pool;
  val root;
  const val *repository;
  group *g;
  const repo *r;
} request;
#define POOL_NODES 8192
static int parse_request(const uint8_t *data, size_t size, val *pool, val *root) {
  reader rd = {data, data + size, pool, 0, POOL_NODES};
  return parse(&rd, root, 0) && root->type == V_MAP;
}
/* Common prologue: identified, a map, a valid group/repository. Writes the
 * refusal into the reply and returns 0 on failure. */
static int locate(const val *root, const uint8_t *identity, const group **g, const repo **r,
                  uint8_t *out, size_t cap, size_t *written) {
  const val *repository = map_get_int(root, GIT_IDX_REPOSITORY);
  char text[NAME_MAX_LEN * 2 + 2], *slash;
  if (!identity) {
    reply(out, cap, written, GIT_RES_DISALLOWED, "Not identified");
    return 0;
  }
  if (!repository) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "No repository specified");
    return 0;
  }
  *g = NULL;
  *r = NULL;
  if (val_copy(repository, text, sizeof(text)) && (slash = strchr(text, '/')) != NULL &&
      !strchr(slash + 1, '/')) {
    *slash = 0;
    if (strlen(text) <= 256 && strlen(slash + 1) <= 256) {
      *g = find_group(text);
      *r = find_repo(*g, slash + 1);
    }
  }
  return 1;
}
static rnc_result handle_list(void *context, const char *path, const uint8_t *request_data,
                              size_t size, const uint8_t *identity, uint8_t *out, size_t cap,
                              size_t *written) {
  val *pool = malloc(POOL_NODES * sizeof(val)), root;
  const group *g;
  const repo *r;
  const val *push;
  int for_push;
  char *refs = NULL;
  size_t n = 0;
  char head_path[PATH_MAX + 8], head[256] = "master", line[512];
  char *argv[] = {"git", "for-each-ref", "--format", "%(objectname) %(refname)", NULL};
  proc_result pr;
  (void)context; (void)path;
  if (!pool)
    return RNC_NO_SPACE;
  if (!parse_request(request_data, size, pool, &root)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    goto done;
  }
  if (!locate(&root, identity, &g, &r, out, cap, written))
    goto done;
  push = map_get(&root, "for_push");
  for_push = push && push->type == V_BOOL && push->u;
  if (!r || !allowed(identity, g, r, for_push ? P_WRITE : P_READ)) {
    reply(out, cap, written, GIT_RES_NOT_FOUND,
          r && allowed(identity, g, r, P_READ) ? "Not allowed" : "Not found");
    goto done;
  }
  snprintf(head_path, sizeof(head_path), "%s/HEAD", r->path);
  {
    FILE *f = fopen(head_path, "rb");
    if (f) {
      char text[300];
      size_t got = fread(text, 1, sizeof(text) - 1, f);
      fclose(f);
      text[got] = 0;
      if (!strncmp(text, "ref: ", 5)) {
        char *end = text + 5;
        while (*end && *end != '\n' && *end != '\r')
          ++end;
        *end = 0;
        snprintf(head, sizeof(head), "%s", text + 5);
        {
          char *s = head, *e = head + strlen(head);
          while (*s == ' ') ++s;
          while (e > s && e[-1] == ' ') *--e = 0;
          memmove(head, s, strlen(s) + 1);
        }
      }
    }
  }
  refs = malloc(cap < 1048576u ? cap : 1048576u);
  if (!refs) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
    goto done;
  }
  pr = rngit_run(r->path, argv, refs, (cap < 1048576u ? cap : 1048576u) - 64, &n);
  if (pr.status != 0) {
    log_line("Error while listing refs for %s/%s: %s", g->name, r->name, pr.err);
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Could not list refs");
    goto done;
  }
  /* refs, de-duplicated, then "@<head> HEAD" */
  {
    mp_out o = {out, cap, 0, 0};
    char *save = NULL, *l, *seen_end;
    size_t body = 0;
    char *body_buf = malloc(cap);
    char **seen = calloc(4096, sizeof(char *));
    size_t seen_n = 0, i;
    if (!body_buf || !seen) {
      free(body_buf); free(seen);
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
      goto done;
    }
    body_buf[body++] = 0; /* status byte */
    (void)seen_end;
    for (l = strtok_r(refs, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
      char *sp = strchr(l, ' '), *name;
      size_t len;
      int dup = 0;
      if (!sp)
        continue;
      name = sp + 1;
      for (i = 0; i < seen_n; ++i)
        if (!strcmp(seen[i], name)) { dup = 1; break; }
      if (dup || seen_n >= 4096)
        continue;
      seen[seen_n++] = name;
      len = strlen(l);
      if (body + len + 1 >= cap) {
        free(body_buf); free(seen);
        reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Could not list refs");
        goto done;
      }
      memcpy(body_buf + body, l, len);
      body += len;
      body_buf[body++] = '\n';
    }
    n = (size_t)snprintf(line, sizeof(line), "@%s HEAD\n", head);
    if (body + n >= cap) {
      free(body_buf); free(seen);
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Could not list refs");
      goto done;
    }
    memcpy(body_buf + body, line, n);
    body += n;
    mp_bin(&o, body_buf, body);
    *written = o.failed ? 0 : o.n;
    free(body_buf);
    free(seen);
  }
done:
  free(refs);
  free(pool);
  return RNC_OK;
}
static int make_tempdir(char *path, size_t cap) {
  const char *base = getenv("TMPDIR");
  snprintf(path, cap, "%s/rngit-XXXXXX", base && *base ? base : "/tmp");
  return mkdtemp(path) != NULL;
}
static void remove_tree(const char *dir) {
  char *argv[] = {"rm", "-rf", (char *)dir, NULL};
  (void)rngit_run(NULL, argv, NULL, 0, NULL);
}
static int object_exists(const char *cwd, const char *sha) {
  char *argv[] = {"git", "cat-file", "-t", (char *)sha, NULL};
  return rngit_run(cwd, argv, NULL, 0, NULL).status == 0;
}
/* argv builder for git invocations of bounded size */
typedef struct arglist {
  char *v[128];
  size_t n;
  char own[128][PATH_MAX > 512 ? PATH_MAX : 512];
} arglist;
static int arg_add(arglist *a, const char *text) {
  if (a->n + 1 >= 127 || strlen(text) >= sizeof(a->own[0]))
    return 0;
  strcpy(a->own[a->n], text);
  a->v[a->n] = a->own[a->n];
  a->n++;
  a->v[a->n] = NULL;
  return 1;
}
static rnc_result handle_fetch(void *context, const char *path, const uint8_t *request_data,
                               size_t size, const uint8_t *identity, uint8_t *out, size_t cap,
                               size_t *written, rnc_responder_file *file) {
  val *pool = malloc(POOL_NODES * sizeof(val)), root;
  const group *g;
  const repo *r;
  const val *refs, *have;
  arglist *args = calloc(1, sizeof(arglist));
  char tmp[PATH_MAX], bundle[PATH_MAX + 16], text[512];
  size_t i;
  int made = 0;
  (void)context; (void)path;
  if (!pool || !args) {
    free(pool); free(args);
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
  refs = map_get(&root, "refs");
  if (!refs || refs->type != V_ARR || !refs->n) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "No refs specified");
    goto done;
  }
  if (!make_tempdir(tmp, sizeof(tmp))) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
    goto done;
  }
  made = 1;
  snprintf(bundle, sizeof(bundle), "%s/fetch.bundle", tmp);
  arg_add(args, "git"); arg_add(args, "bundle"); arg_add(args, "create");
  arg_add(args, "--no-progress"); arg_add(args, bundle);
  /* every ref is checked before any is used */
  for (i = 0; i < refs->n; ++i) {
    const val *entry = &refs->kids[i], *name = map_get(entry, "ref");
    if (!name || !val_copy(name, text, sizeof(text)) || !rngit_san_ref(text)) {
      reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
      goto done;
    }
  }
  for (i = 0; i < refs->n; ++i) {
    const val *entry = &refs->kids[i], *name = map_get(entry, "ref"), *h = map_get(entry, "have");
    char sha[256], excl[258];
    (void)val_copy(name, text, sizeof(text));
    if (!arg_add(args, text)) {
      reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
      goto done;
    }
    if (h && val_is_text(h) && h->n) {
      if (!val_copy(h, sha, sizeof(sha)) || !rngit_san_sha(sha)) {
        reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid SHA");
        goto done;
      }
      if (object_exists(r->path, sha)) {
        snprintf(excl, sizeof(excl), "^%s", sha);
        arg_add(args, excl);
      } else
        log_line("Client have-sha %s not found in repository, skipping", sha);
    }
  }
  have = map_get(&root, "have");
  if (have && have->type == V_ARR)
    for (i = 0; i < have->n; ++i) {
      char sha[256], excl[258];
      if (!val_copy(&have->kids[i], sha, sizeof(sha)) || !rngit_san_sha(sha)) {
        reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid SHA");
        goto done;
      }
      if (object_exists(r->path, sha)) {
        snprintf(excl, sizeof(excl), "^%s", sha);
        if (!arg_add(args, excl)) {
          reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
          goto done;
        }
      } else
        log_line("Client have-sha %s not found in repository, skipping", sha);
    }
  {
    proc_result pr = rngit_run(r->path, args->v, NULL, 0, NULL);
    if (pr.status != 0) {
      char lowered[512];
      snprintf(lowered, sizeof(lowered), "%s", pr.err);
      lower(lowered);
      if (strstr(lowered, "empty bundle")) {
        reply(out, cap, written, GIT_RES_OK, "");
      } else {
        log_line("Error while fetching for %s/%s: %s", g->name, r->name, pr.err);
        reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Could not fetch refs");
      }
      goto done;
    }
  }
  {
    FILE *f = fopen(bundle, "rb");
    size_t got = 0, n;
    if (!f) {
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
      goto done;
    }
    while ((n = fread(file->data + got, 1, file->data_capacity - got, f)) > 0)
      got += n;
    if (!feof(f)) {
      fclose(f);
      log_line("Bundle for %s/%s is larger than max_bundle", g->name, r->name);
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
      goto done;
    }
    fclose(f);
    file->data_size = got;
    stats_fetch_succeeded(g->name, r->name, identity);
    file->metadata[0] = 0x81;
    file->metadata[1] = GIT_IDX_RESULT_CODE;
    file->metadata[2] = GIT_RES_OK;
    file->metadata_size = METADATA_OK_SIZE;
  }
done:
  if (made)
    remove_tree(tmp);
  free(args);
  free(pool);
  return RNC_OK;
}
static rnc_result handle_push(void *context, const char *path, const uint8_t *request_data,
                              size_t size, const uint8_t *identity, uint8_t *out, size_t cap,
                              size_t *written) {
  val *pool = malloc(POOL_NODES * sizeof(val)), root;
  const group *g;
  const repo *r;
  const val *bundle, *operations, *force;
  char local_ref[512], remote_ref[512];
  (void)context; (void)path;
  if (!pool)
    return RNC_NO_SPACE;
  if (!parse_request(request_data, size, pool, &root)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    goto done;
  }
  if (!locate(&root, identity, &g, &r, out, cap, written))
    goto done;
  if (!r || !allowed(identity, g, r, P_WRITE)) {
    reply(out, cap, written,
          r && allowed(identity, g, r, P_READ) ? GIT_RES_DISALLOWED : GIT_RES_NOT_FOUND,
          r && allowed(identity, g, r, P_READ) ? "Not allowed" : "Not found");
    goto done;
  }
  bundle = map_get(&root, "bundle");
  operations = map_get(&root, "operations");
  force = map_get(&root, "force");
  if (bundle && val_is_text(bundle) && bundle->n) {
    char tmp[PATH_MAX], file[PATH_MAX + 16], spec[1100];
    FILE *f;
    int ok;
    if (!val_copy(map_get(&root, "local_ref"), local_ref, sizeof(local_ref)) ||
        !val_copy(map_get(&root, "remote_ref"), remote_ref, sizeof(remote_ref)) ||
        !rngit_san_ref(local_ref) || !rngit_san_ref(remote_ref)) {
      reply(out, cap, written, GIT_RES_INVALID_REQ, "Missing ref specification");
      goto done;
    }
    if (!make_tempdir(tmp, sizeof(tmp))) {
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
      goto done;
    }
    snprintf(file, sizeof(file), "%s/push.bundle", tmp);
    f = fopen(file, "wb");
    ok = f && fwrite(bundle->p, 1, bundle->n, f) == bundle->n;
    if (f)
      ok = fclose(f) == 0 && ok;
    if (!ok) {
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
    } else {
      char *verify[] = {"git", "bundle", "verify", file, NULL};
      proc_result pr = rngit_run(r->path, verify, NULL, 0, NULL);
      if (pr.status != 0) {
        log_line("Bundle verification failed for %s:%s to %s/%s: %s", local_ref, remote_ref,
                 g->name, r->name, pr.err);
        reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Could not verify bundle");
      } else {
        char *fetch_plain[] = {"git", "fetch", file, spec, NULL};
        char *fetch_force[] = {"git", "fetch", file, spec, "--force", NULL};
        snprintf(spec, sizeof(spec), "%s:%s", local_ref, remote_ref);
        pr = rngit_run(r->path, force && force->type == V_BOOL && force->u ? fetch_force : fetch_plain,
                       NULL, 0, NULL);
        if (pr.status != 0) {
          log_line("Fetch of pushed bundle failed for %s/%s: %s", g->name, r->name, pr.err);
          reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Could not verify bundle");
        } else {
          stats_push_succeeded(g->name, r->name, identity);
          reply(out, cap, written, GIT_RES_OK, "");
        }
      }
    }
    remove_tree(tmp);
  } else if (operations && operations->type == V_ARR && operations->n) {
    size_t i;
    for (i = 0; i < operations->n; ++i) {
      const val *op = &operations->kids[i];
      char action[32], ref[512], sha[256], msg[600];
      const val *f = map_get(op, "force");
      int op_force = f && f->type == V_BOOL && f->u;
      char rev[256];
      size_t rn = 0;
      proc_result pr;
      if (!val_copy(map_get(op, "action"), action, sizeof(action)))
        action[0] = 0;
      if (strcmp(action, "update_ref")) {
        snprintf(msg, sizeof(msg), "Unknown operation: %s", action);
        reply(out, cap, written, GIT_RES_INVALID_REQ, msg);
        goto done;
      }
      if (!val_copy(map_get(op, "ref"), ref, sizeof(ref)) || !rngit_san_ref(ref) ||
          strncmp(ref, "refs/", 5)) {
        reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
        goto done;
      }
      if (!val_copy(map_get(op, "sha"), sha, sizeof(sha)) || !rngit_san_sha(sha)) {
        reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid SHA");
        goto done;
      }
      if (!object_exists(r->path, sha)) {
        snprintf(msg, sizeof(msg), "Object %s does not exist in repository", sha);
        reply(out, cap, written, GIT_RES_REMOTE_FAIL, msg);
        goto done;
      }
      {
        char *rp[] = {"git", "rev-parse", ref, NULL};
        pr = rngit_run(r->path, rp, rev, sizeof(rev), &rn);
        if (pr.status == 0) {
          char *e = rev + strlen(rev);
          while (e > rev && (e[-1] == '\n' || e[-1] == ' ')) *--e = 0;
          if (strcmp(rev, sha) && !op_force) {
            snprintf(msg, sizeof(msg), "Ref %s already exists at different SHA (force required)", ref);
            reply(out, cap, written, GIT_RES_DISALLOWED, msg);
            goto done;
          }
        }
      }
      {
        char *up[] = {"git", "update-ref", ref, sha, NULL};
        pr = rngit_run(r->path, up, NULL, 0, NULL);
        if (pr.status != 0) {
          log_line("Error while updating ref %s for %s/%s: %s", ref, g->name, r->name, pr.err);
          reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Could not update refs");
          goto done;
        }
      }
    }
    stats_push_succeeded(g->name, r->name, identity);
    reply(out, cap, written, GIT_RES_OK, "");
  } else
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request data");
done:
  free(pool);
  return RNC_OK;
}
static rnc_result handle_delete(void *context, const char *path, const uint8_t *request_data,
                                size_t size, const uint8_t *identity, uint8_t *out, size_t cap,
                                size_t *written) {
  val *pool = malloc(POOL_NODES * sizeof(val)), root;
  const group *g;
  const repo *r;
  char ref[512];
  (void)context; (void)path;
  if (!pool)
    return RNC_NO_SPACE;
  if (!parse_request(request_data, size, pool, &root)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    goto done;
  }
  if (!locate(&root, identity, &g, &r, out, cap, written))
    goto done;
  if (!r || !allowed(identity, g, r, P_WRITE)) {
    reply(out, cap, written,
          r && allowed(identity, g, r, P_READ) ? GIT_RES_DISALLOWED : GIT_RES_NOT_FOUND,
          r && allowed(identity, g, r, P_READ) ? "Not allowed" : "Not found");
    goto done;
  }
  if (!val_copy(map_get(&root, "ref"), ref, sizeof(ref)) || !rngit_san_ref(ref) ||
      strncmp(ref, "refs/", 5)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    goto done;
  }
  {
    char *del[] = {"git", "update-ref", "-d", ref, NULL};
    proc_result pr = rngit_run(r->path, del, NULL, 0, NULL);
    if (pr.status != 0) {
      log_line("Error while deleting ref %s for %s/%s: %s", ref, g->name, r->name, pr.err);
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Could not delete ref");
    } else {
      stats_push_succeeded(g->name, r->name, identity);
      reply(out, cap, written, GIT_RES_OK, "");
    }
  }
done:
  free(pool);
  return RNC_OK;
}

/* resolve_group_permission: the group's own lists only. */
static int group_allowed(const uint8_t id[16], const group *g, int p) {
  const perm_set *gp;
  if (!g)
    return 0;
  gp = &g->perms[p];
  if (gp->none) return 0;
  if (gp->all) return 1;
  if (set_has(gp, id)) return 1;
  if (set_has(&g->perms[P_ADMIN], id)) return 1;
  return 0;
}
static void reload_group(group *g) {
  char path[PATH_MAX + 16], copy[1024];
  size_t i;
  for (i = 0; i < P_COUNT; ++i)
    memset(&g->perms[i], 0, sizeof(g->perms[i]));
  snprintf(path, sizeof(path), "%s.allowed", g->path);
  load_allowed(path, g->perms);
  cfg_group = g;
  snprintf(copy, sizeof(copy), "%s", g->access);
  split_list(copy, access_statement);
}
static void reload_repo(repo *r) {
  char path[PATH_MAX + 16];
  size_t i;
  for (i = 0; i < P_COUNT; ++i)
    memset(&r->perms[i], 0, sizeof(r->perms[i]));
  snprintf(path, sizeof(path), "%s.allowed", r->path);
  load_allowed(path, r->perms);
}
static int write_atomic(const char *path, const char *text, size_t n) {
  char tmp[PATH_MAX + 16];
  FILE *f;
  int ok;
  snprintf(tmp, sizeof(tmp), "%s.tmp", path);
  f = fopen(tmp, "w");
  if (!f)
    return 0;
  ok = fwrite(text, 1, n, f) == n;
  ok = fclose(f) == 0 && ok;
  if (!ok || rename(tmp, path)) {
    unlink(tmp);
    return 0;
  }
  return 1;
}
static void hex_string(const uint8_t id[16], char out_hex[33]) {
  size_t i;
  for (i = 0; i < 16; ++i)
    snprintf(out_hex + 2 * i, 3, "%02x", id[i]);
}
static rnc_result handle_create(void *context, const char *path, const uint8_t *request_data,
                                size_t size, const uint8_t *identity, uint8_t *out, size_t cap,
                                size_t *written) {
  val *pool = malloc(POOL_NODES * sizeof(val)), root;
  const val *repository;
  char text[NAME_MAX_LEN * 2 + 2], *slash, full[PATH_MAX], allowed_path[PATH_MAX + 16];
  group *g;
  const char *name;
  int read_access, create_access;
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
  repository = map_get_int(&root, GIT_IDX_REPOSITORY);
  if (!repository) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "No repository specified");
    goto done;
  }
  if (!val_copy(repository, text, sizeof(text)) || !(slash = strchr(text, '/')) ||
      strchr(slash + 1, '/') || strlen(text) > 256 || strlen(slash + 1) > 256) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    goto done;
  }
  *slash = 0;
  name = slash + 1;
  if (!*text || !*name) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    goto done;
  }
  g = (group *)find_group(text);
  if (!g) {
    reply(out, cap, written, GIT_RES_NOT_FOUND, "Not found");
    goto done;
  }
  read_access = group_allowed(identity, g, P_READ);
  create_access = group_allowed(identity, g, P_CREATE);
  if (!create_access) {
    reply(out, cap, written, read_access ? GIT_RES_DISALLOWED : GIT_RES_NOT_FOUND,
          read_access ? "Not allowed" : "Not found");
    goto done;
  }
  /* stricter than the reference: no names that start with a dot (".", ".."
   * and hidden entries) */
  if (name[0] == '.') {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    goto done;
  }
  if (snprintf(full, sizeof(full), "%s/%s", g->path, name) >= (int)sizeof(full)) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    goto done;
  }
  {
    struct stat st;
    const repo *existing = find_repo(g, name);
    if (existing || !stat(full, &st)) {
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
  if (mkdir(full, 0755)) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Remote error");
    goto done;
  }
  {
    char *init[] = {"git", "init", "--bare", NULL};
    char *rm[] = {"rm", "-rf", full, NULL};
    char hash[33], line[64];
    repo *r;
    if (rngit_run(full, init, NULL, 0, NULL).status != 0) {
      (void)rngit_run(NULL, rm, NULL, 0, NULL);
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Could not initialize repository");
      goto done;
    }
    hex_string(identity, hash);
    snprintf(allowed_path, sizeof(allowed_path), "%s.allowed", full);
    snprintf(line, sizeof(line), "adm:%s", hash);
    if (!write_atomic(allowed_path, line, strlen(line))) {
      (void)rngit_run(NULL, rm, NULL, 0, NULL);
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Could not initialize repository");
      goto done;
    }
    r = &g->repos[g->repo_count++];
    memset(r, 0, sizeof(*r));
    snprintf(r->name, sizeof(r->name), "%s", name);
    snprintf(r->path, sizeof(r->path), "%s", full);
    reload_repo(r);
    repo_kind_load(r);
    log_line("Created repository %s/%s", g->name, name);
    reply(out, cap, written, GIT_RES_OK, "");
  }
done:
  free(pool);
  return RNC_OK;
}
/* Permission statements the reference accepts: "perm:target" per line, blank
 * and comment lines ignored. Returns 0 and the offending line on failure. */
static int valid_statements(const char *content, int *bad_line, char *bad, size_t bad_cap) {
  char *copy = strdup(content), *line;
  perm_set scratch[P_COUNT];
  int n = 0, ok = 1;
  if (!copy)
    return 0;
  /* strtok would skip empty lines and lose the numbering; walk by hand */
  line = copy;
  while (ok && line) {
    char *nl = strchr(line, '\n'), *t;
    if (nl)
      *nl = 0;
    ++n;
    t = trim(line);
    if (*t && *t != '#') {
      size_t before;
      memset(scratch, 0, sizeof(scratch));
      apply_statement(t, scratch);
      before = 0;
      {
        size_t i;
        for (i = 0; i < P_COUNT; ++i)
          before += scratch[i].entries;
      }
      if (!before) {
        ok = 0;
        *bad_line = n;
        snprintf(bad, bad_cap, "%s", t);
      }
    }
    line = nl ? nl + 1 : NULL;
  }
  free(copy);
  return ok;
}
static void perms_reply_content(uint8_t *out, size_t cap, size_t *written, const char *path) {
  char *text = malloc(65536);
  size_t n = 0;
  mp_out o = {out, cap, 0, 0};
  FILE *f = fopen(path, "r");
  if (!text) {
    reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Error getting permissions");
    return;
  }
  if (f) {
    n = fread(text, 1, 65535, f);
    fclose(f);
  }
  text[n] = 0;
  /* the reference packs {"content": text} after a status byte, all as one bin */
  {
    uint8_t body[65536 + 32];
    mp_out b = {body, sizeof(body), 0, 0};
    mp_byte(&b, GIT_RES_OK);
    mp_map(&b, 1);
    mp_cstr(&b, "content");
    mp_str(&b, text, n);
    mp_bin(&o, body, b.n);
    *written = b.failed || o.failed ? 0 : o.n;
  }
  free(text);
}
static rnc_result handle_perms(void *context, const char *path, const uint8_t *request_data,
                               size_t size, const uint8_t *identity, uint8_t *out, size_t cap,
                               size_t *written) {
  val *pool = malloc(POOL_NODES * sizeof(val)), root;
  char operation[16], step[16], target[NAME_MAX_LEN * 2 + 2], allowed_path[PATH_MAX + 16];
  const val *v;
  group *g = NULL;
  repo *r = NULL;
  int is_group;
  (void)context; (void)path;
  if (!pool)
    return RNC_NO_SPACE;
  if (!identity) {
    reply(out, cap, written, GIT_RES_DISALLOWED, "Not identified");
    goto done;
  }
  if (!parse_request(request_data, size, pool, &root) ||
      !val_copy(map_get(&root, "operation"), operation, sizeof(operation))) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    goto done;
  }
  is_group = !strcmp(operation, "gperms");
  if (!is_group && strcmp(operation, "rperms")) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    goto done;
  }
  v = map_get_int(&root, is_group ? GIT_IDX_GROUP : GIT_IDX_REPOSITORY);
  if (!v) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, is_group ? "No group specified" : "No repository specified");
    goto done;
  }
  if (val_copy(v, target, sizeof(target))) {
    if (is_group) {
      if (!strchr(target, '/') && strlen(target) <= 256)
        g = (group *)find_group(target);
    } else {
      char *slash = strchr(target, '/');
      if (slash && !strchr(slash + 1, '/') && strlen(target) <= 256 && strlen(slash + 1) <= 256) {
        *slash = 0;
        g = (group *)find_group(target);
        r = (repo *)find_repo(g, slash + 1);
      }
    }
  }
  if (is_group ? !g : !r) {
    reply(out, cap, written, GIT_RES_NOT_FOUND, "Not found");
    goto done;
  }
  /* who may ask: group administration, or administration of the repository */
  {
    int read_access = is_group ? group_allowed(identity, g, P_READ) : allowed(identity, g, r, P_READ);
    int admin_access = is_group ? group_allowed(identity, g, P_ADMIN) : allowed(identity, g, r, P_ADMIN);
    if (!is_group && !admin_access) {
      reply(out, cap, written, read_access ? GIT_RES_DISALLOWED : GIT_RES_NOT_FOUND,
            read_access ? "Not allowed" : "Not found");
      goto done;
    }
    /* the reference's dispatcher asks again, now needing read as well: an
     * administrator whose own read is set to none is locked out */
    if (!is_group && !read_access) {
      reply(out, cap, written, GIT_RES_NOT_FOUND, "Not found");
      goto done;
    }
    if (is_group && !read_access) {
      reply(out, cap, written, GIT_RES_NOT_FOUND, "Not found");
      goto done;
    }
    if (is_group && !admin_access) {
      reply(out, cap, written, GIT_RES_DISALLOWED, "Not allowed");
      goto done;
    }
  }
  if (!val_copy(map_get(&root, "step"), step, sizeof(step))) {
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid request");
    goto done;
  }
  snprintf(allowed_path, sizeof(allowed_path), "%s.allowed", is_group ? g->path : r->path);
  if (!strcmp(step, "get")) {
    perms_reply_content(out, cap, written, allowed_path);
  } else if (!strcmp(step, "set")) {
    const val *content = map_get(&root, "content");
    char *text = NULL;
    char bad[200];
    int bad_line = 0;
    /* the reference's repository set also needs administration of the group */
    if (!is_group && (!group_allowed(identity, g, P_READ) || !group_allowed(identity, g, P_ADMIN))) {
      reply(out, cap, written, group_allowed(identity, g, P_READ) ? GIT_RES_DISALLOWED : GIT_RES_NOT_FOUND,
            group_allowed(identity, g, P_READ) ? "Not allowed" : "Not found");
      goto done;
    }
    text = calloc(1, (content && val_is_text(content) ? content->n : 0) + 1);
    if (!text) {
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Error setting permissions");
      goto done;
    }
    if (content && val_is_text(content))
      memcpy(text, content->p, content->n);
    if (!valid_statements(text, &bad_line, bad, sizeof(bad))) {
      char msg[300];
      snprintf(msg, sizeof(msg), "Invalid permission \"%s\" on line %d", bad, bad_line);
      reply(out, cap, written, GIT_RES_INVALID_REQ, msg);
    } else if (access(allowed_path, X_OK) == 0) {
      reply(out, cap, written, GIT_RES_DISALLOWED,
            "Executable permission resolvers can only be modified node-side");
    } else if (!write_atomic(allowed_path, text, strlen(text))) {
      reply(out, cap, written, GIT_RES_REMOTE_FAIL, "Error setting permissions");
    } else {
      if (is_group)
        reload_group(g);
      else
        reload_repo(r);
      reply(out, cap, written, GIT_RES_OK, "");
    }
    free(text);
  } else
    reply(out, cap, written, GIT_RES_INVALID_REQ, "Invalid step");
done:
  free(pool);
  return RNC_OK;
}

#include "rngit_clone.h"
#include "rngit_release.h"
#include "rngit_work.h"
#include "rngit_stats.h"
#include "rngit_pages.h"
#include "rngit_pageviews.h"
#include "rngit_pageserve.h"

/* ---- main ---------------------------------------------------------------- */
static void idle_pump(void) {
  (void)rngit_pump(&G.net);
}
/* git runs `git-remote-rns` for rns:// sources: make sure it resolves to the
 * helper beside this binary, attached to the same node, using this node's
 * client identity. */
static void prepare_git_environment(const char *argv0, const char *connect) {
  char self[PATH_MAX], dir[PATH_MAX], link_dir[PATH_MAX + 32], link_path[PATH_MAX + 64], helper[PATH_MAX + 32];
  const char *path = getenv("PATH");
  ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
  char *slash;
  if (n < 0) {
    snprintf(self, sizeof(self), "%s", argv0);
    n = (ssize_t)strlen(self);
  } else
    self[n] = 0;
  snprintf(dir, sizeof(dir), "%s", self);
  slash = strrchr(dir, '/');
  if (slash)
    *slash = 0;
  else
    snprintf(dir, sizeof(dir), ".");
  snprintf(helper, sizeof(helper), "%s/reticulum-c-git-remote", dir);
  if (!getenv("RNGIT_CONNECT"))
    setenv("RNGIT_CONNECT", connect, 1);
  if (!getenv("RNGIT_CONFIG"))
    setenv("RNGIT_CONFIG", G.config_dir, 1);
  if (!is_file(helper))
    return;
  snprintf(link_dir, sizeof(link_dir), "%s/bin", G.config_dir);
  snprintf(link_path, sizeof(link_path), "%s/git-remote-rns", link_dir);
  if (!is_dir(link_dir))
    (void)mkdir(link_dir, 0755);
  unlink(link_path);
  if (!symlink(helper, link_path)) {
    char newpath[PATH_MAX * 3];
    snprintf(newpath, sizeof(newpath), "%s:%s", link_dir, path ? path : "/usr/bin:/bin");
    setenv("PATH", newpath, 1);
  }
}
static void usage(void) {
  fputs("usage: reticulum-c-git --connect HOST:PORT [--config DIR] [--identity FILE] [--print-identity]\n",
        stderr);
}
int main(int argc, char **argv) {
  const char *connect = NULL, *config = NULL, *identity = NULL;
  char default_config[PATH_MAX], identity_path[PATH_MAX + 32];
  int i, print_identity = 0;
  uint8_t destination[16];
  uint64_t last_announce = 0, last_mirror_check = 0;
  int announced = 0;
  G.max_bundle = (size_t)DEFAULT_MAX_BUNDLE_MIB << 20;
  G.mirror_hours = 24;
  pages_defaults();
  for (i = 1; i < argc; ++i) {
#define VALUE (i + 1 < argc ? argv[++i] : (usage(), exit(2), (char *)NULL))
    if (!strcmp(argv[i], "--connect"))
      connect = VALUE;
    else if (!strcmp(argv[i], "--config"))
      config = VALUE;
    else if (!strcmp(argv[i], "--identity"))
      identity = VALUE;
    else if (!strcmp(argv[i], "--print-identity"))
      print_identity = 1;
    else
      return usage(), 2;
  }
  if (!connect && !print_identity)
    return usage(), 2;
  if (!config) {
    const char *home = getenv("HOME");
    snprintf(default_config, sizeof(default_config), "%s/.rngit", home ? home : ".");
    config = default_config;
  }
  snprintf(G.config_dir, sizeof(G.config_dir), "%s", config);
  if (!identity) {
    snprintf(identity_path, sizeof(identity_path), "%s/repositories_identity", config);
    identity = identity_path;
  }
  signal(SIGINT, rngit_on_signal);
  signal(SIGTERM, rngit_on_signal);
  signal(SIGPIPE, SIG_IGN);
  if (print_identity) {
    rnc_identity id;
    if (rnc_host_identity_load(identity, rngit_random, NULL, &id) != RNC_OK)
      return 255;
    /* the destination needs a node to be derived; use a throwaway one */
    {
      rnc_node *node = rnc_node_new(&id, 0, rngit_random, NULL);
      if (!node || rnc_node_add_destination(node, &id, GIT_APP_NAME, NULL, 0, destination) != RNC_OK)
        return 255;
      rnc_node_free(node);
    }
    printf("Repository Node Identity  : <");
    for (i = 0; i < 16; ++i) printf("%02x", id.hash[i]);
    printf(">\nRepositories Destination  : <");
    for (i = 0; i < 16; ++i) printf("%02x", destination[i]);
    puts(">");
    rnc_identity_clear(&id);
    return 0;
  }
  if (!load_config(config))
    return 255;
  stats_load();
  if (!rngit_open_node(&G.net, connect, identity, "rngit link"))
    return 1;
  if (rnc_node_add_destination(G.net.node, &G.net.id, GIT_APP_NAME, NULL, 0, destination) != RNC_OK)
    return 1;
  G.net.responder = rnc_responder_new(G.net.node, G.max_bundle, rngit_random, NULL);
  if (!G.net.responder ||
      rnc_responder_add_destination(G.net.responder, &G.net.id, destination) != RNC_OK ||
      rnc_responder_register(G.net.responder, destination, GIT_PATH_LIST, RNC_SERVICE_ALLOW_ALL,
                             NULL, 0, handle_list, NULL) != RNC_OK ||
      rnc_responder_register_file(G.net.responder, destination, GIT_PATH_FETCH,
                                  RNC_SERVICE_ALLOW_ALL, NULL, 0, handle_fetch, NULL) != RNC_OK ||
      rnc_responder_register(G.net.responder, destination, GIT_PATH_PUSH, RNC_SERVICE_ALLOW_ALL,
                             NULL, 0, handle_push, NULL) != RNC_OK ||
      rnc_responder_register(G.net.responder, destination, GIT_PATH_DELETE, RNC_SERVICE_ALLOW_ALL,
                             NULL, 0, handle_delete, NULL) != RNC_OK ||
      rnc_responder_register(G.net.responder, destination, GIT_PATH_CREATE, RNC_SERVICE_ALLOW_ALL,
                             NULL, 0, handle_create, NULL) != RNC_OK ||
      rnc_responder_register(G.net.responder, destination, GIT_PATH_PERMS, RNC_SERVICE_ALLOW_ALL,
                             NULL, 0, handle_perms, NULL) != RNC_OK ||
      rnc_responder_register(G.net.responder, destination, GIT_PATH_FORK, RNC_SERVICE_ALLOW_ALL,
                             NULL, 0, handle_fork, NULL) != RNC_OK ||
      rnc_responder_register(G.net.responder, destination, GIT_PATH_MIRROR, RNC_SERVICE_ALLOW_ALL,
                             NULL, 0, handle_mirror, NULL) != RNC_OK ||
      rnc_responder_register(G.net.responder, destination, GIT_PATH_SYNC, RNC_SERVICE_ALLOW_ALL,
                             NULL, 0, handle_sync, NULL) != RNC_OK ||
      rnc_responder_register_file(G.net.responder, destination, GIT_PATH_RELEASE,
                                  RNC_SERVICE_ALLOW_ALL, NULL, 0, handle_release, NULL) != RNC_OK ||
      rnc_responder_register(G.net.responder, destination, GIT_PATH_WORK, RNC_SERVICE_ALLOW_ALL,
                             NULL, 0, handle_work, NULL) != RNC_OK) {
    fprintf(stderr, "Could not set up the repository destination\n");
    return 1;
  }
  memcpy(pg_repo_dest, destination, 16);
  if (G.serve_nomadnet && !pages_setup()) {
    fprintf(stderr, "Could not set up the page server destination\n");
    return 1;
  }
  prepare_git_environment(argv[0], connect);
  rngit_idle_hook = idle_pump;
  fputs("Reticulum Git Node listening on <", stdout);
  for (i = 0; i < 16; ++i) printf("%02x", destination[i]);
  puts(">");
  if (G.serve_nomadnet) {
    fputs("Git Nomad Network Node listening on <", stdout);
    for (i = 0; i < 16; ++i) printf("%02x", pg_node_dest[i]);
    puts(">");
  }
  fflush(stdout);
  while (!rngit_stopping) {
    uint64_t now = rngit_monotonic_ms();
    if (!rngit_pump(&G.net))
      break;
    jobs_poll();
    stats_job(now);
    if (now - last_mirror_check > 60000u) {
      last_mirror_check = now;
      sync_due_mirrors();
    }
    /* a second announce soon after the first covers a node that was still
     * bringing the link up */
    if (announced == 1 && now - last_announce > 5000u) {
      (void)rnc_node_announce(G.net.node, destination, (uint64_t)time(NULL), now);
      announced = 2;
    }
    if (!announced || (G.announce_minutes && now - last_announce > (uint64_t)G.announce_minutes * 60000u)) {
      rnc_host_status s;
      if (rnc_host_get_status(G.net.host, 1, &s) == RNC_OK && s.online) {
        (void)rnc_node_announce(G.net.node, destination, (uint64_t)time(NULL), now);
        if (G.serve_nomadnet)
          (void)rnc_node_announce(G.net.node, pg_node_dest, (uint64_t)time(NULL), now);
        announced = 1;
        last_announce = now;
      }
    }
  }
  (void)stats_persist();
  rngit_close_node(&G.net);
  st_free_all();
  return 0;
}
