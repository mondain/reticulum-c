/* Statistics of reticulum-c-git (included by reticulum_git.c): per day counts of
 * views, fetches, pushes, downloads and release downloads for every repository,
 * the reference's server.py record_* / repository_stats / __load_stats /
 * __persist_stats.
 *
 * The file CONFIG/stats is a MessagePack map, the same as the reference writes:
 *   {"pages": {"front": {DAY: n}},
 *    "groups": {GROUP: {"view": {DAY: n},
 *                       "repositories": {REPO: {"view": {}, "fetch": {}, "push": {},
 *                                               "download": {}, "release_download": {}}}}}}
 * with DAY as YYYY-MM-DD in local time. It is read at start and rewritten every
 * 180 seconds (and at exit).
 *
 * Unlike the reference, where all newly seen repositories share one set of
 * dictionaries until the file is reloaded (STATS_INIT_REPO is a class
 * attribute that is stored, not copied), every repository here has its own. */
#ifndef RETICULUM_C_RNGIT_STATS_H
#define RETICULUM_C_RNGIT_STATS_H

#define ST_DAY_MAX 4096u   /* day entries kept per counter */
#define ST_REPOS_MAX 8192u /* repositories (and groups) kept in total */
#define ST_FILE_MAX (3u << 20)
#define ST_PERSIST_SECONDS 180
enum { ST_VIEW, ST_FETCH, ST_PUSH, ST_DOWNLOAD, ST_RELDL, ST_KINDS };
static const char *const st_kind_name[ST_KINDS] = {"view", "fetch", "push", "download", "release_download"};

typedef struct st_day {
  char day[11];
  unsigned long long n;
} st_day;
typedef struct st_map {
  st_day *v;
  size_t n, cap;
} st_map;
typedef struct st_repo {
  char name[NAME_MAX_LEN];
  st_map m[ST_KINDS];
} st_repo;
typedef struct st_group {
  char name[NAME_MAX_LEN];
  st_map view;
  st_repo *repos;
  size_t nrepos, caprepos;
} st_group;
typedef struct st_state {
  st_map front;
  st_group *groups;
  size_t ngroups, capgroups, total;
  int dirty, load_failed;
  uint64_t last_persist_ms;
} st_state;
static st_state ST;

static void st_map_free(st_map *m) {
  free(m->v);
  memset(m, 0, sizeof(*m));
}
static void st_free_all(void) {
  size_t i, j, k;
  st_map_free(&ST.front);
  for (i = 0; i < ST.ngroups; ++i) {
    st_map_free(&ST.groups[i].view);
    for (j = 0; j < ST.groups[i].nrepos; ++j)
      for (k = 0; k < ST_KINDS; ++k)
        st_map_free(&ST.groups[i].repos[j].m[k]);
    free(ST.groups[i].repos);
  }
  free(ST.groups);
  memset(&ST, 0, sizeof(ST));
}
static void st_today(char out[11]) {
  time_t t = time(NULL);
  struct tm tmv;
  localtime_r(&t, &tmv);
  strftime(out, 11, "%Y-%m-%d", &tmv);
}
static unsigned long long st_map_get(const st_map *m, const char *day) {
  size_t i;
  for (i = 0; i < m->n; ++i)
    if (!strcmp(m->v[i].day, day))
      return m->v[i].n;
  return 0;
}
static int st_map_add(st_map *m, const char *day, unsigned long long by) {
  size_t i;
  for (i = 0; i < m->n; ++i)
    if (!strcmp(m->v[i].day, day)) {
      m->v[i].n += by;
      return 1;
    }
  if (m->n >= ST_DAY_MAX)
    return 0;
  if (m->n == m->cap) {
    size_t cap = m->cap ? m->cap * 2 : 8;
    st_day *nv = realloc(m->v, cap * sizeof(st_day));
    if (!nv)
      return 0;
    m->v = nv;
    m->cap = cap;
  }
  snprintf(m->v[m->n].day, 11, "%s", day);
  m->v[m->n].n = by;
  m->n++;
  return 1;
}
static st_group *st_group_get(const char *name, int create) {
  size_t i;
  for (i = 0; i < ST.ngroups; ++i)
    if (!strcmp(ST.groups[i].name, name))
      return &ST.groups[i];
  if (!create || strlen(name) >= NAME_MAX_LEN || ST.total >= ST_REPOS_MAX)
    return NULL;
  if (ST.ngroups == ST.capgroups) {
    size_t cap = ST.capgroups ? ST.capgroups * 2 : 8;
    st_group *ng = realloc(ST.groups, cap * sizeof(st_group));
    if (!ng)
      return NULL;
    ST.groups = ng;
    ST.capgroups = cap;
  }
  memset(&ST.groups[ST.ngroups], 0, sizeof(st_group));
  snprintf(ST.groups[ST.ngroups].name, NAME_MAX_LEN, "%s", name);
  ST.total++;
  return &ST.groups[ST.ngroups++];
}
static st_repo *st_repo_get(st_group *g, const char *name, int create) {
  size_t i;
  for (i = 0; i < g->nrepos; ++i)
    if (!strcmp(g->repos[i].name, name))
      return &g->repos[i];
  if (!create || strlen(name) >= NAME_MAX_LEN || ST.total >= ST_REPOS_MAX)
    return NULL;
  if (g->nrepos == g->caprepos) {
    size_t cap = g->caprepos ? g->caprepos * 2 : 8;
    st_repo *nr = realloc(g->repos, cap * sizeof(st_repo));
    if (!nr)
      return NULL;
    g->repos = nr;
    g->caprepos = cap;
  }
  memset(&g->repos[g->nrepos], 0, sizeof(st_repo));
  snprintf(g->repos[g->nrepos].name, NAME_MAX_LEN, "%s", name);
  ST.total++;
  return &g->repos[g->nrepos++];
}

/* ---- the record_* functions --------------------------------------------- */
static void st_record_front(void) {
  char day[11];
  st_today(day);
  ST.dirty |= st_map_add(&ST.front, day, 1);
}
static void st_record_group_view(const char *group) {
  char day[11];
  st_group *g = st_group_get(group, 1);
  st_today(day);
  if (g)
    ST.dirty |= st_map_add(&g->view, day, 1);
}
static void st_record_repo(const char *group, const char *repo, int kind) {
  char day[11];
  st_group *g = st_group_get(group, 1);
  st_repo *r = g ? st_repo_get(g, repo, 1) : NULL;
  st_today(day);
  if (r)
    ST.dirty |= st_map_add(&r->m[kind], day, 1);
}
static int st_ignored(const uint8_t *identity) {
  size_t i;
  for (i = 0; identity && i < G.stats_ignored_count; ++i)
    if (!memcmp(G.stats_ignored[i], identity, 16))
      return 1;
  return 0;
}
/* the *_succeeded hooks; identity is NULL for a caller that did not identify */
static void stats_view_succeeded(const char *group, const char *repo, const uint8_t *identity) {
  if (st_ignored(identity) || !G.stats_enabled)
    return;
  if (!group && !repo)
    st_record_front();
  else if (!repo)
    st_record_group_view(group);
  else
    st_record_repo(group, repo, ST_VIEW);
}
static void stats_fetch_succeeded(const char *group, const char *repo, const uint8_t *identity) {
  if (st_ignored(identity) || !G.stats_enabled)
    return;
  if (group && repo)
    st_record_repo(group, repo, ST_FETCH);
}
/* The reference reads stats_push_ignore_identities but never consults it. */
static void stats_push_succeeded(const char *group, const char *repo, const uint8_t *identity) {
  (void)identity;
  if (G.stats_enabled && group && repo)
    st_record_repo(group, repo, ST_PUSH);
}
static void stats_download_succeeded(const char *group, const char *repo, const uint8_t *identity) {
  if (st_ignored(identity) || !G.stats_enabled)
    return;
  if (group && repo)
    st_record_repo(group, repo, ST_DOWNLOAD);
}
static void stats_release_download_succeeded(const char *group, const char *repo, const uint8_t *identity) {
  if (st_ignored(identity) || !G.stats_enabled)
    return;
  if (group && repo)
    st_record_repo(group, repo, ST_RELDL);
}

/* ---- persistence -------------------------------------------------------- */
static void st_pack_map_head(mp_out *o, size_t n) {
  if (n < 16)
    mp_byte(o, (uint8_t)(0x80 | n));
  else if (n < 65536) {
    uint8_t b[3] = {0xde, (uint8_t)(n >> 8), (uint8_t)n};
    mp_put(o, b, 3);
  } else {
    uint8_t b[5] = {0xdf, (uint8_t)(n >> 24), (uint8_t)(n >> 16), (uint8_t)(n >> 8), (uint8_t)n};
    mp_put(o, b, 5);
  }
}
static void st_pack_days(mp_out *o, const st_map *m) {
  size_t i;
  st_pack_map_head(o, m->n);
  for (i = 0; i < m->n; ++i) {
    mp_cstr(o, m->v[i].day);
    mp_uint(o, m->v[i].n);
  }
}
static void st_pack(mp_out *o) {
  size_t i, j, k;
  st_pack_map_head(o, 2);
  mp_cstr(o, "pages");
  st_pack_map_head(o, 1);
  mp_cstr(o, "front");
  st_pack_days(o, &ST.front);
  mp_cstr(o, "groups");
  st_pack_map_head(o, ST.ngroups);
  for (i = 0; i < ST.ngroups; ++i) {
    const st_group *g = &ST.groups[i];
    mp_cstr(o, g->name);
    st_pack_map_head(o, 2);
    mp_cstr(o, "view");
    st_pack_days(o, &g->view);
    mp_cstr(o, "repositories");
    st_pack_map_head(o, g->nrepos);
    for (j = 0; j < g->nrepos; ++j) {
      mp_cstr(o, g->repos[j].name);
      st_pack_map_head(o, ST_KINDS);
      for (k = 0; k < ST_KINDS; ++k) {
        mp_cstr(o, st_kind_name[k]);
        st_pack_days(o, &g->repos[j].m[k]);
      }
    }
  }
}
/* Writes CONFIG/stats atomically (rename of stats.tmp). */
static int stats_persist(void) {
  char path[PATH_MAX + 16];
  size_t cap = 1u << 16;
  uint8_t *buf = NULL;
  mp_out o;
  int ok = 0;
  for (;;) {
    buf = malloc(cap);
    if (!buf)
      return 0;
    o = (mp_out){buf, cap, 0, 0};
    st_pack(&o);
    if (!o.failed)
      break;
    free(buf);
    if (cap > (64u << 20))
      return 0;
    cap *= 4;
  }
  snprintf(path, sizeof(path), "%s/stats", G.config_dir);
  if (ST.load_failed) {
    char bad[PATH_MAX + 32];
    snprintf(bad, sizeof(bad), "%s.unreadable", path);
    if (is_file(path) && !is_file(bad))
      (void)rename(path, bad);
    ST.load_failed = 0;
  }
  ok = write_atomic(path, (const char *)buf, o.n);
  if (!ok)
    log_line("Could not write stats file to %s", path);
  else
    ST.dirty = 0;
  free(buf);
  return ok;
}
static void st_load_days(const val *m, st_map *out) {
  size_t i;
  if (!m || m->type != V_MAP)
    return;
  for (i = 0; i < m->n; ++i) {
    const val *k = &m->kids[2 * i], *v = &m->kids[2 * i + 1];
    char day[64];
    if (!val_copy(k, day, sizeof(day)) || strlen(day) != 10)
      continue;
    if (v->type == V_UINT)
      (void)st_map_add(out, day, v->u);
    else if (v->type == V_INT && v->i > 0)
      (void)st_map_add(out, day, (unsigned long long)v->i);
  }
}
/* Reads CONFIG/stats; creates it when missing, as the reference does. */
static void stats_load(void) {
  char path[PATH_MAX + 16];
  FILE *f;
  struct stat sb;
  uint8_t *raw = NULL;
  val *pool = NULL, root;
  size_t n, i, j, k, nodes;
  reader rd;
  st_free_all();
  snprintf(path, sizeof(path), "%s/stats", G.config_dir);
  if (stat(path, &sb)) {
    (void)stats_persist();
    return;
  }
  if (sb.st_size <= 0 || (size_t)sb.st_size > ST_FILE_MAX) {
    log_line("Could not read stats file %s: unusable size", path);
    ST.load_failed = 1;
    return;
  }
  f = fopen(path, "rb");
  raw = malloc((size_t)sb.st_size);
  nodes = (size_t)sb.st_size < 400000u ? (size_t)sb.st_size + 8 : 400000u;
  pool = malloc(nodes * sizeof(val));
  if (!f || !raw || !pool) {
    if (f)
      fclose(f);
    goto fail;
  }
  n = fread(raw, 1, (size_t)sb.st_size, f);
  fclose(f);
  rd = (reader){raw, raw + n, pool, 0, nodes};
  if (!parse(&rd, &root, 0) || root.type != V_MAP)
    goto fail;
  {
    const val *pages = map_get(&root, "pages"), *groups = map_get(&root, "groups");
    st_load_days(map_get(pages, "front"), &ST.front);
    if (groups && groups->type == V_MAP)
      for (i = 0; i < groups->n; ++i) {
        const val *gk = &groups->kids[2 * i], *gv = &groups->kids[2 * i + 1], *repos;
        char gname[NAME_MAX_LEN + 8];
        st_group *g;
        if (!val_copy(gk, gname, sizeof(gname)) || !(g = st_group_get(gname, 1)))
          continue;
        st_load_days(map_get(gv, "view"), &g->view);
        repos = map_get(gv, "repositories");
        if (repos && repos->type == V_MAP)
          for (j = 0; j < repos->n; ++j) {
            char rname[NAME_MAX_LEN + 8];
            st_repo *r;
            if (!val_copy(&repos->kids[2 * j], rname, sizeof(rname)) || !(r = st_repo_get(g, rname, 1)))
              continue;
            for (k = 0; k < ST_KINDS; ++k)
              st_load_days(map_get(&repos->kids[2 * j + 1], st_kind_name[k]), &r->m[k]);
          }
      }
  }
  ST.dirty = 0;
  free(raw);
  free(pool);
  return;
fail:
  log_line("Could not read stats file %s", path);
  st_free_all();
  ST.load_failed = 1;
  free(raw);
  free(pool);
}
/* Called from the main loop: persist every 180 seconds. */
static void stats_job(uint64_t now_ms) {
  if (!ST.last_persist_ms)
    ST.last_persist_ms = now_ms;
  if (now_ms - ST.last_persist_ms >= (uint64_t)ST_PERSIST_SECONDS * 1000u) {
    ST.last_persist_ms = now_ms;
    (void)stats_persist();
  }
}

/* ---- repository_stats --------------------------------------------------- */
#define ST_LOOKBACK_MAX 366
enum { RS_VIEWS, RS_FETCHES, RS_PUSHES, RS_DOWNLOADS, RS_RELDL, RS_COMBINED, RS_SERIES };
typedef struct repo_stats {
  int lookback;
  char date_range[64];
  char days[ST_LOOKBACK_MAX][11];
  unsigned long long daily[RS_SERIES][ST_LOOKBACK_MAX];
  unsigned long long total[RS_SERIES], peak[RS_SERIES];
  int activity_score, actual_days;
  const char *activity_level;
} repo_stats;
/* Returns 0 when the caller lacks the stats permission (the reference returns
 * None). now is the unix time to count back from. */
static int repository_stats(const uint8_t *identity, const group *g, const repo *r, int lookback, double now,
                            repo_stats *s) {
  static const int kind_of[5] = {ST_VIEW, ST_FETCH, ST_PUSH, ST_DOWNLOAD, ST_RELDL};
  const st_map *maps[ST_KINDS] = {0};
  const st_group *sg = NULL;
  size_t i;
  int d, kk;
  double total_score;
  char earliest[11] = "";
  if (!identity || !allowed(identity, g, r, P_STATS) || lookback < 1 || lookback > ST_LOOKBACK_MAX)
    return 0;
  memset(s, 0, sizeof(*s));
  s->lookback = lookback;
  for (d = 0; d < lookback; ++d) {
    time_t t = (time_t)(now - (double)(lookback - 1 - d) * 86400.0);
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(s->days[d], 11, "%Y-%m-%d", &tmv);
  }
  {
    char a[16], b[16];
    time_t t0 = (time_t)(now - (double)(lookback - 1) * 86400.0), t1 = (time_t)now;
    struct tm m0, m1;
    localtime_r(&t0, &m0);
    localtime_r(&t1, &m1);
    strftime(a, sizeof(a), "%b %d", &m0);
    strftime(b, sizeof(b), "%b %d", &m1);
    snprintf(s->date_range, sizeof(s->date_range), "%s - %s", a, b);
  }
  for (i = 0; i < ST.ngroups; ++i)
    if (!strcmp(ST.groups[i].name, g->name))
      sg = &ST.groups[i];
  if (sg)
    for (i = 0; i < sg->nrepos; ++i)
      if (!strcmp(sg->repos[i].name, r->name))
        for (kk = 0; kk < ST_KINDS; ++kk)
          maps[kk] = &sg->repos[i].m[kk];
  for (kk = 0; kk < 5; ++kk)
    for (d = 0; d < lookback; ++d) {
      unsigned long long c = maps[kind_of[kk]] ? st_map_get(maps[kind_of[kk]], s->days[d]) : 0;
      s->daily[kk][d] = c;
      s->total[kk] += c;
      if (c > s->peak[kk])
        s->peak[kk] = c;
    }
  for (d = 0; d < lookback; ++d) {
    unsigned long long c = s->daily[RS_DOWNLOADS][d] + s->daily[RS_RELDL][d];
    s->daily[RS_COMBINED][d] = c;
    s->total[RS_COMBINED] += c;
    if (c > s->peak[RS_COMBINED])
      s->peak[RS_COMBINED] = c;
  }
  total_score = (double)(s->total[RS_VIEWS] + s->total[RS_DOWNLOADS] + s->total[RS_RELDL]) * 0.2 +
                (double)s->total[RS_FETCHES] * 2.0 + (double)s->total[RS_PUSHES] * 5;
  s->activity_score = (int)total_score;
  s->actual_days = lookback;
  for (kk = 0; kk < 3; ++kk) {
    const st_map *m = maps[kind_of[kk]];
    for (i = 0; m && i < m->n; ++i)
      if (m->v[i].n > 0 && (!earliest[0] || strcmp(m->v[i].day, earliest) < 0))
        snprintf(earliest, sizeof(earliest), "%s", m->v[i].day);
  }
  if (earliest[0]) {
    struct tm tmv;
    memset(&tmv, 0, sizeof(tmv));
    tmv.tm_isdst = -1;
    if (sscanf(earliest, "%d-%d-%d", &tmv.tm_year, &tmv.tm_mon, &tmv.tm_mday) == 3) {
      time_t ts;
      tmv.tm_year -= 1900;
      tmv.tm_mon -= 1;
      ts = mktime(&tmv);
      {
        double span = now - (double)ts;
        long long days = (long long)(span / 86400.0);
        if (span < 0 && span / 86400.0 != (double)days)
          days -= 1;
        s->actual_days = days + 1 > 1 ? (int)(days + 1) : 1;
      }
    }
  }
  if (s->actual_days > lookback)
    s->actual_days = lookback;
  {
    double daily_score = s->actual_days > 0 ? total_score / s->actual_days : 0;
    s->activity_level = daily_score == 0 ? "inactive" : daily_score < 3 ? "low" : daily_score < 10 ? "moderate" : "high";
  }
  return 1;
}

#endif
