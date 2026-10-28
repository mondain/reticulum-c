/* reticulum-c-git-remote: a git remote helper for rns:// URLs, compatible with
 * the reference git-remote-rns.
 *
 *   git clone rns://DESTINATION/GROUP/REPOSITORY
 *
 * Install it (or a link to it) as `git-remote-rns` on the PATH. git runs it as
 * `git-remote-rns REMOTE URL` and speaks the remote-helper protocol on its
 * standard input and output (capabilities, list, fetch, push, option). Objects
 * travel as git bundles over a Reticulum link to a repository node (the
 * reference rngit or reticulum-c-git).
 *
 * The node it attaches to comes from RNGIT_CONNECT=HOST:PORT or the `connect`
 * key of the [client] section of CONFIG/client_config. CONFIG is RNGIT_CONFIG
 * or ~/.rngit; it also holds client_identity (created on first use, this is
 * the identity the repository node sees) and an [aliases] section mapping names
 * to destination hashes. DESTINATION may be such an alias. Each request uses its
 * own link, where the reference keeps one open. */
#include "rngit_common.h"

#define PATH_TIMEOUT_MS 15000u
#define REQUEST_TIMEOUT_MS 1800000u
#define DEFAULT_BATCH 25u
#define MAX_REMOTE_REFS 4096
#define POOL_NODES 4096
#define MAX_BUNDLE_MIB 15u

typedef struct remote_ref {
  char name[512];
  char sha[65];
} remote_ref;
typedef struct client {
  rngit_node net;
  uint8_t destination[16];
  char repo_path[600];
  unsigned batch;
  remote_ref refs[MAX_REMOTE_REFS];
  size_t ref_count;
  int progress;
  size_t max_value;
} client;
static client *C;

static void abort_with(const char *reason) __attribute__((noreturn));
static void abort_with(const char *reason) {
  fprintf(stderr, "git-remote-rns failed: %s\n", reason);
  exit(255);
}

/* ---- configuration ------------------------------------------------------- */
static char *trim(char *s) {
  char *e;
  while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
    ++s;
  e = s + strlen(s);
  while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n'))
    *--e = 0;
  return s;
}
/* Looks up `key` in `section` of an ini file; returns 1 and copies the value. */
static int ini_get(const char *path, const char *section, const char *key, char *out,
                   size_t cap) {
  FILE *f = fopen(path, "r");
  char line[1024], current[64] = "";
  int found = 0;
  if (!f)
    return 0;
  while (!found && fgets(line, sizeof(line), f)) {
    char *t = trim(line), *eq;
    if (*t == '#' || !*t)
      continue;
    if (*t == '[') {
      char *end = strchr(t, ']');
      if (end) {
        *end = 0;
        snprintf(current, sizeof(current), "%s", t + 1);
      }
      continue;
    }
    eq = strchr(t, '=');
    if (!eq)
      continue;
    *eq = 0;
    if (!strcmp(current, section) && !strcmp(trim(t), key)) {
      snprintf(out, cap, "%s", trim(eq + 1));
      found = 1;
    }
  }
  fclose(f);
  return found;
}

/* ---- requests ------------------------------------------------------------ */
typedef struct response {
  uint8_t *data;
  size_t size;
  uint8_t meta[RNC_RESPONDER_METADATA_MAX];
  size_t meta_size;
} response;
static void settle(unsigned ms);
static int request(const char *path, const uint8_t *value, size_t value_size, response *out) {
  rnc_requester_result r;
  uint64_t started = rngit_monotonic_ms();
  free(out->data);
  memset(out, 0, sizeof(*out));
  out->data = malloc(C->max_value);
  if (!out->data)
    abort_with("out of memory");
  if (rnc_requester_start(C->net.requester, C->destination, &C->net.id, path, value,
                          value_size, 1, REQUEST_TIMEOUT_MS, (uint64_t)time(NULL),
                          rngit_monotonic_ms()) != RNC_OK)
    abort_with("Link not ready for request");
  while (!rngit_stopping) {
    rnc_result res;
    if (!rngit_pump(&C->net))
      abort_with("The node connection was lost");
    res = rnc_requester_poll_file(C->net.requester, &r, out->data, C->max_value, out->meta,
                                  sizeof(out->meta));
    if (res == RNC_OK) {
      if (r.status != RNC_REQUESTER_DONE)
        return 0;
      out->size = r.size;
      out->meta_size = r.metadata_size;
      settle(150);
      return 1;
    }
    if (res != RNC_AGAIN)
      abort_with("The response is too large");
    if (rngit_monotonic_ms() - started > REQUEST_TIMEOUT_MS + 5000u)
      return 0;
  }
  return 0;
}
/* Keeps the node running briefly so the closing of a request's link leaves the
 * socket; otherwise the repository node holds the link slot until it times out
 * and a long session runs out of slots. */
static void settle(unsigned ms) {
  uint64_t start = rngit_monotonic_ms();
  while (rngit_monotonic_ms() - start < ms && rngit_pump(&C->net)) {
  }
}
/* The reference's plain replies are a binary value: status byte, then text.
 * Returns the status and points *text at the message; -1 when it is not. */
static int plain_status(const response *r, const char **text, size_t *text_size) {
  val pool[4];
  reader rd = {r->data, r->data + r->size, pool, 0, 4};
  val v;
  if (r->meta_size || !parse(&rd, &v, 0) || v.type != V_BIN || !v.n)
    return -1;
  *text = (const char *)v.p + 1;
  *text_size = v.n - 1;
  return v.p[0];
}

/* ---- git helpers --------------------------------------------------------- */
static int git_ok(const char *a, const char *b, const char *c) {
  char *argv[5] = {"git", (char *)a, (char *)b, (char *)c, NULL};
  return rngit_run(NULL, argv, NULL, 0, NULL).status == 0;
}
static int local_object(const char *sha) {
  return git_ok("cat-file", "-t", sha);
}
static int rev_parse(const char *ref, char *sha, size_t cap) {
  char *argv[] = {"git", "rev-parse", (char *)ref, NULL};
  char out[256];
  size_t n;
  proc_result r = rngit_run(NULL, argv, out, sizeof(out), &n);
  char *e;
  if (r.status != 0)
    return 0;
  e = out + strlen(out);
  while (e > out && (e[-1] == '\n' || e[-1] == ' ')) *--e = 0;
  if (strlen(out) >= cap)
    return 0;
  strcpy(sha, out);
  return 1;
}
static void escape(const char *in, char *out, size_t cap) {
  size_t o = 0;
  const char *p;
  out[o++] = '"';
  for (p = in; *p && o + 6 < cap; ++p) {
    unsigned char c = (unsigned char)*p;
    if (c == '\\' || c == '"') { out[o++] = '\\'; out[o++] = (char)c; }
    else if (c == '\n') { out[o++] = '\\'; out[o++] = 'n'; }
    else if (c == '\t') { out[o++] = '\\'; out[o++] = 't'; }
    else if (c == '\r') { out[o++] = '\\'; out[o++] = 'r'; }
    else if (c < 32 || c > 126) o += (size_t)snprintf(out + o, 5, "\\x%02x", c);
    else out[o++] = (char)c;
  }
  out[o++] = '"';
  out[o] = 0;
}
static void push_error(const char *remote, const char *message) {
  char escaped[512];
  escape(message, escaped, sizeof(escaped));
  printf("error %s %s\n", remote, escaped);
  fflush(stdout);
}

/* ---- list ---------------------------------------------------------------- */
static void handle_list(int for_push) {
  uint8_t buf[512];
  mp_out o = {buf, sizeof(buf), 0, 0};
  response r = {0};
  const char *text;
  size_t n;
  int status;
  char *copy, *save = NULL, *line;
  mp_map(&o, 2);
  mp_uint(&o, GIT_IDX_REPOSITORY);
  mp_cstr(&o, C->repo_path);
  mp_cstr(&o, "for_push");
  mp_bool(&o, for_push);
  if (o.failed || !request(GIT_PATH_LIST, buf, o.n, &r))
    abort_with("Request failed or timed out");
  status = plain_status(&r, &text, &n);
  if (status < 0)
    abort_with("Invalid list response from server");
  if (status != 0) {
    char msg[300];
    snprintf(msg, sizeof(msg), "Server refused list: %.*s", (int)(n < 200 ? n : 200), text);
    abort_with(msg);
  }
  copy = malloc(n + 1);
  if (!copy)
    abort_with("out of memory");
  memcpy(copy, text, n);
  copy[n] = 0;
  C->ref_count = 0;
  {
    char *plain = malloc(n + 1);
    memcpy(plain, copy, n + 1);
    for (line = strtok_r(plain, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
      char *sp = strchr(trim(line), ' ');
      if (!sp)
        continue;
      *sp = 0;
      if (!strcmp(sp + 1, "HEAD") || C->ref_count >= MAX_REMOTE_REFS || strlen(sp + 1) >= 512 ||
          strlen(line) >= 65)
        continue;
      strcpy(C->refs[C->ref_count].sha, line);
      strcpy(C->refs[C->ref_count].name, sp + 1);
      C->ref_count++;
    }
    free(plain);
  }
  fwrite(copy, 1, n, stdout);
  fputs("\n", stdout);
  fflush(stdout);
  free(copy);
  free(r.data);
}

/* ---- fetch --------------------------------------------------------------- */
typedef struct pair {
  char sha[65];
  char ref[512];
} pair;
typedef struct push_item {
  char local[512], remote[512];
} push_item;
static int temp_file(char *path, size_t cap) {
  const char *base = getenv("TMPDIR");
  int fd;
  snprintf(path, cap, "%s/rngit-XXXXXX", base && *base ? base : "/tmp");
  fd = mkstemp(path);
  return fd;
}
static void process_fetch(pair *queue, size_t count) {
  size_t i, have_count = 0;
  char (*have)[65] = malloc(MAX_REMOTE_REFS * 65);
  size_t at = 0;
  if (!have)
    abort_with("out of memory");
  for (i = 0; i < C->ref_count; ++i)
    if (local_object(C->refs[i].sha))
      memcpy(have[have_count++], C->refs[i].sha, 65);
  while (at < count) {
    size_t batch = count - at < C->batch ? count - at : C->batch, k;
    size_t cap = 64 * 1024 + (batch + have_count) * 160;
    uint8_t *buf = malloc(cap);
    mp_out o;
    response r = {0};
    const char *text;
    size_t n;
    int status;
    if (!buf)
      abort_with("out of memory");
    o = (mp_out){buf, cap, 0, 0};
    mp_map(&o, have_count ? 3 : 2);
    mp_uint(&o, GIT_IDX_REPOSITORY);
    mp_cstr(&o, C->repo_path);
    mp_cstr(&o, "refs");
    mp_array(&o, batch);
    for (k = 0; k < batch; ++k) {
      char local[65];
      int with_have = rev_parse(queue[at + k].ref, local, sizeof(local)) &&
                      strcmp(local, queue[at + k].sha);
      mp_map(&o, with_have ? 3 : 2);
      mp_cstr(&o, "sha");
      mp_cstr(&o, queue[at + k].sha);
      mp_cstr(&o, "ref");
      mp_cstr(&o, queue[at + k].ref);
      if (with_have) {
        mp_cstr(&o, "have");
        mp_cstr(&o, local);
      }
    }
    if (have_count) {
      mp_cstr(&o, "have");
      mp_array(&o, have_count);
      for (k = 0; k < have_count; ++k)
        mp_cstr(&o, have[k]);
    }
    if (o.failed || !request(GIT_PATH_FETCH, buf, o.n, &r))
      abort_with("Request failed or timed out");
    free(buf);
    if (!r.size)
      abort_with("No data in fetch response for batch");
    if (!r.meta_size) {
      status = plain_status(&r, &text, &n);
      if (status < 0)
        abort_with("Invalid fetch response for batch");
      if (status != 0) {
        char msg[300];
        snprintf(msg, sizeof(msg), "Fetch failed for batch: %.*s", (int)(n < 200 ? n : 200), text);
        abort_with(msg);
      }
      /* empty bundle: the objects are already here */
    } else {
      val pool[4];
      reader rd = {r.meta, r.meta + r.meta_size, pool, 0, 4};
      val meta;
      char path[PATH_MAX];
      int fd;
      FILE *f;
      char *verify[] = {"git", "bundle", "verify", "-q", path, NULL};
      char *unbundle[] = {"git", "bundle", "unbundle", path, NULL};
      const val *code = NULL;
      if (!parse(&rd, &meta, 0) || !(code = map_get_int(&meta, GIT_IDX_RESULT_CODE)))
        abort_with("No result metadata on bundle response");
      if (code->type != V_UINT || code->u != 0)
        abort_with("Unknown remote state for batch ref fetch");
      fd = temp_file(path, sizeof(path));
      if (fd < 0 || !(f = fdopen(fd, "wb")) || fwrite(r.data, 1, r.size, f) != r.size ||
          fclose(f))
        abort_with("Could not store the received bundle");
      if (rngit_run(NULL, verify, NULL, 0, NULL).status != 0) {
        unlink(path);
        abort_with("Bundle verification failed for batch");
      }
      if (rngit_run(NULL, unbundle, NULL, 0, NULL).status != 0) {
        unlink(path);
        abort_with("Bundle unbundle failed for batch: Non-zero return code");
      }
      unlink(path);
    }
    free(r.data);
    at += batch;
  }
  free(have);
}

/* ---- push ---------------------------------------------------------------- */
static void process_push(push_item *queue, size_t count) {
  size_t i;
  for (i = 0; i < count; ++i) {
    const char *local = queue[i].local, *remote = queue[i].remote;
    char local_sha[65], path[PATH_MAX + 32], tmpdir[PATH_MAX];
    int force = 0, empty = 0;
    response r = {0};
    const char *text;
    size_t n, k;
    int status;
    uint8_t *buf;
    size_t cap;
    mp_out o;
    if (!*local) {
      uint8_t small[1024];
      o = (mp_out){small, sizeof(small), 0, 0};
      mp_map(&o, 2);
      mp_uint(&o, GIT_IDX_REPOSITORY);
      mp_cstr(&o, C->repo_path);
      mp_cstr(&o, "ref");
      mp_cstr(&o, remote);
      if (o.failed || !request(GIT_PATH_DELETE, small, o.n, &r)) {
        push_error(remote, "No response from server");
        continue;
      }
      status = plain_status(&r, &text, &n);
      if (status != 0) {
        char msg[300];
        snprintf(msg, sizeof(msg), "%.*s", (int)(n < 200 ? n : 200), status < 0 ? "No response from server" : text);
        push_error(remote, msg);
      } else
        printf("ok %s\n", remote), fflush(stdout);
      free(r.data);
      continue;
    }
    if (*local == '+') {
      force = 1;
      ++local;
    }
    if (!rev_parse(local, local_sha, sizeof(local_sha))) {
      char msg[600];
      snprintf(msg, sizeof(msg), "Could not resolve local ref %s", local);
      push_error(remote, msg);
      continue;
    }
    snprintf(tmpdir, sizeof(tmpdir), "%s/rngit-push-XXXXXX", getenv("TMPDIR") && *getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
    if (!mkdtemp(tmpdir))
      abort_with("Could not create a temporary directory");
    snprintf(path, sizeof(path), "%s/push.bundle", tmpdir);
    {
      char *argv[8 + MAX_REMOTE_REFS];
      char excl[MAX_REMOTE_REFS][68];
      size_t a = 0, ex = 0;
      proc_result pr;
      argv[a++] = "git"; argv[a++] = "bundle"; argv[a++] = "create";
      argv[a++] = path; argv[a++] = (char *)local;
      for (k = 0; k < C->ref_count; ++k)
        if (local_object(C->refs[k].sha)) {
          snprintf(excl[ex], sizeof(excl[ex]), "^%s", C->refs[k].sha);
          argv[a++] = excl[ex++];
        }
      argv[a] = NULL;
      pr = rngit_run(NULL, argv, NULL, 0, NULL);
      if (pr.status != 0) {
        char lowered[512];
        snprintf(lowered, sizeof(lowered), "%s", pr.err);
        for (k = 0; lowered[k]; ++k)
          if (lowered[k] >= 'A' && lowered[k] <= 'Z') lowered[k] = (char)(lowered[k] + 32);
        if (strstr(lowered, "empty bundle"))
          empty = 1;
        else {
          char *rm[] = {"rm", "-rf", tmpdir, NULL};
          (void)rngit_run(NULL, rm, NULL, 0, NULL);
          push_error(remote, "Bundle creation failed");
          continue;
        }
      }
    }
    if (!empty) {
      FILE *f = fopen(path, "rb");
      long size;
      uint8_t *bundle;
      if (!f) {
        push_error(remote, "Bundle creation failed");
        continue;
      }
      fseek(f, 0, SEEK_END);
      size = ftell(f);
      fseek(f, 0, SEEK_SET);
      bundle = malloc((size_t)size + 1);
      if (!bundle || size < 0 || fread(bundle, 1, (size_t)size, f) != (size_t)size)
        abort_with("Could not read the bundle");
      fclose(f);
      cap = (size_t)size + 4096;
      buf = malloc(cap);
      if (!buf)
        abort_with("out of memory");
      o = (mp_out){buf, cap, 0, 0};
      mp_map(&o, 5);
      mp_uint(&o, GIT_IDX_REPOSITORY);
      mp_cstr(&o, C->repo_path);
      mp_cstr(&o, "local_ref");
      mp_cstr(&o, local);
      mp_cstr(&o, "remote_ref");
      mp_cstr(&o, remote);
      mp_cstr(&o, "force");
      mp_bool(&o, force);
      mp_cstr(&o, "bundle");
      mp_bin(&o, bundle, (size_t)size);
      free(bundle);
      if (o.failed || (size_t)size + 1024 > C->max_value) {
        free(buf);
        push_error(remote, "The bundle is larger than this client or node accepts");
        {
          char *rm[] = {"rm", "-rf", tmpdir, NULL};
          (void)rngit_run(NULL, rm, NULL, 0, NULL);
        }
        continue;
      }
      if (!request(GIT_PATH_PUSH, buf, o.n, &r)) {
        free(buf);
        push_error(remote, "No response from server");
        {
          char *rm[] = {"rm", "-rf", tmpdir, NULL};
          (void)rngit_run(NULL, rm, NULL, 0, NULL);
        }
        continue;
      }
      free(buf);
    } else {
      uint8_t small[2048];
      o = (mp_out){small, sizeof(small), 0, 0};
      mp_map(&o, 2);
      mp_uint(&o, GIT_IDX_REPOSITORY);
      mp_cstr(&o, C->repo_path);
      mp_cstr(&o, "operations");
      mp_array(&o, 1);
      mp_map(&o, 4);
      mp_cstr(&o, "action");
      mp_cstr(&o, "update_ref");
      mp_cstr(&o, "ref");
      mp_cstr(&o, remote);
      mp_cstr(&o, "sha");
      mp_cstr(&o, local_sha);
      mp_cstr(&o, "force");
      mp_bool(&o, force);
      if (o.failed || !request(GIT_PATH_PUSH, small, o.n, &r)) {
        push_error(remote, "No response from server");
        continue;
      }
    }
    {
      char *rm[] = {"rm", "-rf", tmpdir, NULL};
      (void)rngit_run(NULL, rm, NULL, 0, NULL);
    }
    status = plain_status(&r, &text, &n);
    if (status != 0) {
      char msg[300];
      if (status < 0)
        snprintf(msg, sizeof(msg), "No response from server");
      else
        snprintf(msg, sizeof(msg), "%.*s", (int)(n < 200 ? n : 200), text);
      push_error(remote, msg);
    } else {
      printf("ok %s\n", remote);
      fflush(stdout);
    }
    free(r.data);
  }
}

/* ---- the helper protocol ------------------------------------------------- */
static void run_helper(void) {
  char *line = NULL;
  size_t cap = 0;
  pair *fetches = calloc(4096, sizeof(pair));
  push_item *pushes = calloc(4096, sizeof(push_item));
  size_t nf = 0, np = 0;
  if (!fetches || !pushes)
    abort_with("out of memory");
  while (getline(&line, &cap, stdin) > 0) {
    char *t = trim(line);
    if (!strcmp(t, "capabilities")) {
      fputs("list\nfetch\npush\noption\n\n", stdout);
      fflush(stdout);
    } else if (!strcmp(t, "list"))
      handle_list(0);
    else if (!strncmp(t, "list ", 5))
      handle_list(1);
    else if (!strncmp(t, "option", 6)) {
      char name[64] = "", value[64] = "";
      sscanf(t, "option %63s %63s", name, value);
      if (!strcmp(name, "progress")) {
        C->progress = !strcmp(value, "true") || !strcmp(value, "1") || !strcmp(value, "yes");
        fputs("ok\n", stdout);
      } else
        fputs("unsupported\n", stdout);
      fflush(stdout);
    } else if (!strncmp(t, "fetch", 5)) {
      char sha[65], ref[512];
      if (sscanf(t, "fetch %64s %511s", sha, ref) == 2 && nf < 4096) {
        size_t i;
        int dup = 0;
        for (i = 0; i < nf; ++i)
          if (!strcmp(fetches[i].sha, sha) && !strcmp(fetches[i].ref, ref))
            dup = 1;
        if (!dup) {
          strcpy(fetches[nf].sha, sha);
          strcpy(fetches[nf].ref, ref);
          nf++;
        }
      }
      np = 0;
    } else if (!strncmp(t, "push", 4)) {
      char spec[1100], *colon;
      if (sscanf(t, "push %1099s", spec) == 1 && np < 4096 && (colon = strchr(spec, ':')) != NULL) {
        *colon = 0;
        if (strlen(spec) >= sizeof(pushes[np].local) || strlen(colon + 1) >= sizeof(pushes[np].remote))
          abort_with("A ref name is too long");
        strcpy(pushes[np].local, spec);
        strcpy(pushes[np].remote, colon + 1);
        np++;
      }
      nf = 0;
    } else if (!*t) {
      if (nf)
        process_fetch(fetches, nf);
      if (np)
        process_push(pushes, np);
      nf = np = 0;
      fputs("\n", stdout);
      fflush(stdout);
    } else {
      char msg[300];
      snprintf(msg, sizeof(msg), "Unknown Git command: %.200s", t);
      abort_with(msg);
    }
  }
  free(line);
  free(fetches);
  free(pushes);
}

int main(int argc, char **argv) {
  char config[PATH_MAX], path[PATH_MAX + 32], connect[300], value[300], target[300];
  const char *url, *env, *hash, *slash;
  size_t hash_len;
  char *group_end;
  if (argc < 3) {
    fputs("Usage: git-remote-rns <remote-name> <url>\n", stderr);
    return 1;
  }
  url = argv[2];
  if (strncmp(url, "rns://", 6)) {
    fputs("Invalid URL scheme. Must be rns://\n", stderr);
    return 1;
  }
  C = calloc(1, sizeof(*C));
  if (!C)
    return 1;
  C->batch = DEFAULT_BATCH;
  C->max_value = (size_t)MAX_BUNDLE_MIB << 20;
  hash = url + 6;
  slash = strchr(hash, '/');
  if (!slash || !(group_end = strchr(slash + 1, '/')) || !group_end[1]) {
    fputs("Invalid URL format. Use rns://<hash>/<group>/<repo>\n", stderr);
    return 1;
  }
  hash_len = (size_t)(slash - hash);
  if (hash_len >= sizeof(target))
    return 1;
  memcpy(target, hash, hash_len);
  target[hash_len] = 0;
  if (snprintf(C->repo_path, sizeof(C->repo_path), "%s", slash + 1) >= (int)sizeof(C->repo_path))
    return 1;
  env = getenv("RNGIT_CONFIG");
  if (env && *env)
    snprintf(config, sizeof(config), "%s", env);
  else
    snprintf(config, sizeof(config), "%s/.rngit", getenv("HOME") ? getenv("HOME") : ".");
  snprintf(path, sizeof(path), "%s/client_config", config);
  if (ini_get(path, "client", "ref_batch_size", value, sizeof(value))) {
    unsigned long b = strtoul(value, NULL, 10);
    if (b >= 1 && b <= 1024)
      C->batch = (unsigned)b;
  }
  if (!rngit_hex_decode(target, C->destination, 16)) {
    if (!ini_get(path, "aliases", target, value, sizeof(value)) ||
        !rngit_hex_decode(value, C->destination, 16)) {
      fprintf(stderr, "git-remote-rns failed: Invalid destination hash: %s\n", target);
      return 255;
    }
  }
  env = getenv("RNGIT_CONNECT");
  if (env && *env)
    snprintf(connect, sizeof(connect), "%s", env);
  else if (!ini_get(path, "client", "connect", connect, sizeof(connect))) {
    fputs("git-remote-rns failed: no node to attach to; set RNGIT_CONNECT=HOST:PORT or connect in client_config\n",
          stderr);
    return 255;
  }
  snprintf(path, sizeof(path), "%s/client_identity", config);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, rngit_on_signal);
  signal(SIGTERM, rngit_on_signal);
  {
    struct stat st;
    if (stat(config, &st) && mkdir(config, 0700) && errno != EEXIST) {
      fprintf(stderr, "git-remote-rns failed: cannot create %s\n", config);
      return 255;
    }
  }
  if (!rngit_open_node(&C->net, connect, path, "rngit link"))
    return 255;
  C->net.requester =
      rnc_requester_new(C->net.node, C->max_value, rngit_random, NULL);
  if (!C->net.requester)
    abort_with("Could not set up the request client");
  fputs("Requesting path...", stderr);
  if (rnc_host_await_path(C->net.host, C->destination, PATH_TIMEOUT_MS, NULL, NULL) != RNC_OK) {
    fputs("\n", stderr);
    abort_with("Could not resolve path to the repository node");
  }
  fputs("\rPath resolved     \n", stderr);
  run_helper();
  settle(300);
  rngit_close_node(&C->net);
  return 0;
}
