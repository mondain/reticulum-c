/* reticulum-c-git-admin: manage repositories on a repository node (the
 * reference's `rngit create` and permission editing).
 *
 *   reticulum-c-git-admin --connect HOST:PORT [--config DIR] COMMAND ...
 *
 *   create   rns://DESTINATION/GROUP/REPOSITORY
 *   gperms   rns://DESTINATION/GROUP        get | set FILE|-
 *   rperms   rns://DESTINATION/GROUP/REPO   get | set FILE|-
 *
 * `get` prints the permission file; `set` replaces it with FILE (or standard
 * input for -), where each line is `r:HASH`, `w:HASH`, `rw:HASH`, `c:`, `s:`,
 * `rel:`, `i:`, `p:` or `adm:`, HASH being an identity hash, `all` or `none`.
 * Where the reference opens an editor, this takes the text from a file, so it
 * works in scripts. The identity is CONFIG/client_identity (RNGIT_CONFIG or
 * ~/.rngit), the same one git-remote-rns uses. */
#include "rngit_common.h"

#define PATH_TIMEOUT_MS 15000u

static char *trim(char *s) {
  char *e;
  while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
    ++s;
  e = s + strlen(s);
  while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n'))
    *--e = 0;
  return s;
}
static int ini_get(const char *path, const char *section, const char *key, char *out, size_t cap) {
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
static int fail(const char *message) {
  fprintf(stderr, "reticulum-c-git-admin: %s\n", message);
  return 1;
}
static int check_status(const rngit_response *r, const char *what) {
  const uint8_t *text;
  size_t n;
  int status = rngit_plain(r, &text, &n);
  char msg[300];
  if (status == 0)
    return 1;
  if (status < 0)
    snprintf(msg, sizeof(msg), "No response from remote");
  else if (status == GIT_RES_NOT_FOUND && !n)
    snprintf(msg, sizeof(msg), "Not found");
  else
    snprintf(msg, sizeof(msg), "%s: %.*s", what, (int)(n < 200 ? n : 200), (const char *)text);
  fprintf(stderr, "reticulum-c-git-admin: %s\n", msg);
  return 0;
}
static char *read_all(const char *file, size_t *n) {
  FILE *f = !strcmp(file, "-") ? stdin : fopen(file, "rb");
  char *buf = malloc(65536);
  *n = 0;
  if (!f || !buf)
    return NULL;
  *n = fread(buf, 1, 65535, f);
  buf[*n] = 0;
  if (f != stdin)
    fclose(f);
  return buf;
}
int main(int argc, char **argv) {
  const char *connect = NULL, *command = NULL, *url = NULL, *step = NULL, *file = NULL;
  char config[PATH_MAX], path[PATH_MAX + 32], connect_buf[300], value[300], target[300], *slash;
  const char *env;
  int i, positional = 0;
  rngit_client *c;
  uint8_t *buf;
  mp_out o;
  rngit_response r;
  const char *hash, *rest;
  size_t cap = 1 << 17;
  int rc = 1;
  for (i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--connect") && i + 1 < argc)
      connect = argv[++i];
    else if (!strcmp(argv[i], "--config") && i + 1 < argc)
      setenv("RNGIT_CONFIG", argv[++i], 1);
    else if (positional == 0) { command = argv[i]; positional++; }
    else if (positional == 1) { url = argv[i]; positional++; }
    else if (positional == 2) { step = argv[i]; positional++; }
    else if (positional == 3) { file = argv[i]; positional++; }
    else
      goto usage;
  }
  if (!command || !url || strncmp(url, "rns://", 6))
    goto usage;
  if (strcmp(command, "create") && strcmp(command, "gperms") && strcmp(command, "rperms"))
    goto usage;
  if (strcmp(command, "create") && (!step || (strcmp(step, "get") && strcmp(step, "set")) ||
                                    (!strcmp(step, "set") && !file)))
    goto usage;
  env = getenv("RNGIT_CONFIG");
  if (env && *env)
    snprintf(config, sizeof(config), "%s", env);
  else
    snprintf(config, sizeof(config), "%s/.rngit", getenv("HOME") ? getenv("HOME") : ".");
  snprintf(path, sizeof(path), "%s/client_config", config);
  hash = url + 6;
  slash = strchr(hash, '/');
  if (!slash || !slash[1])
    return fail("Invalid number of URL components");
  rest = slash + 1;
  if ((size_t)(slash - hash) >= sizeof(target))
    return fail("Invalid destination hash");
  memcpy(target, hash, (size_t)(slash - hash));
  target[slash - hash] = 0;
  c = calloc(1, sizeof(*c));
  buf = malloc(cap);
  if (!c || !buf)
    return fail("out of memory");
  c->max_value = 1 << 20;
  if (!rngit_hex_decode(target, c->destination, 16) &&
      (!ini_get(path, "aliases", target, value, sizeof(value)) ||
       !rngit_hex_decode(value, c->destination, 16)))
    return fail("Invalid destination hash");
  if (!connect) {
    env = getenv("RNGIT_CONNECT");
    if (env && *env)
      connect = env;
    else if (ini_get(path, "client", "connect", connect_buf, sizeof(connect_buf)))
      connect = connect_buf;
    else
      return fail("no node to attach to; use --connect HOST:PORT, RNGIT_CONNECT or connect in client_config");
  }
  snprintf(path, sizeof(path), "%s/client_identity", config);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, rngit_on_signal);
  signal(SIGTERM, rngit_on_signal);
  {
    struct stat st;
    if (stat(config, &st) && mkdir(config, 0700) && errno != EEXIST)
      return fail("cannot create the configuration directory");
  }
  if (!rngit_open_node(&c->net, connect, path, "rngit admin link"))
    return 1;
  c->net.requester = rnc_requester_new(c->net.node, c->max_value, rngit_random, NULL);
  if (!c->net.requester)
    return fail("Could not set up the request client");
  if (rnc_host_await_path(c->net.host, c->destination, PATH_TIMEOUT_MS, NULL, NULL) != RNC_OK) {
    rc = fail("Could not resolve path to the repository node");
    goto out;
  }
  o = (mp_out){buf, cap, 0, 0};
  if (!strcmp(command, "create")) {
    mp_map(&o, 1);
    mp_uint(&o, GIT_IDX_REPOSITORY);
    mp_cstr(&o, rest);
    if (o.failed || !rngit_request(c, GIT_PATH_CREATE, buf, o.n, 120000, &r)) {
      rc = fail("No response from remote");
      goto out;
    }
    if (check_status(&r, "Remote error")) {
      printf("Repository %s created\n", rest);
      rc = 0;
    }
    free(r.data);
  } else {
    int is_group = command[0] == 'g';
    char *content = NULL;
    size_t content_size = 0;
    if (!strcmp(step, "set") && !(content = read_all(file, &content_size))) {
      rc = fail("Could not read the permission file");
      goto out;
    }
    mp_map(&o, content ? 4 : 3);
    mp_uint(&o, is_group ? GIT_IDX_GROUP : GIT_IDX_REPOSITORY);
    mp_cstr(&o, rest);
    mp_cstr(&o, "operation");
    mp_cstr(&o, command);
    mp_cstr(&o, "step");
    mp_cstr(&o, step);
    if (content) {
      mp_cstr(&o, "content");
      mp_str(&o, content, content_size);
    }
    free(content);
    if (o.failed || !rngit_request(c, GIT_PATH_PERMS, buf, o.n, 120000, &r)) {
      rc = fail("No response from remote");
      goto out;
    }
    if (check_status(&r, "Remote error")) {
      if (!strcmp(step, "get")) {
        /* status byte, then {"content": text} */
        val pool[8];
        reader rd = {r.data, r.data + r.size, pool, 0, 8};
        val bin;
        if (parse(&rd, &bin, 0) && bin.type == V_BIN && bin.n > 1) {
          reader inner = {bin.p + 1, bin.p + bin.n, pool, 0, 8};
          val map;
          const val *text;
          if (parse(&inner, &map, 0) && (text = map_get(&map, "content")) != NULL && val_is_text(text))
            fwrite(text->p, 1, text->n, stdout);
        }
      } else
        printf("Permissions updated for %s\n", rest);
      rc = 0;
    }
    free(r.data);
  }
out:
  rngit_close_node(&c->net);
  return rc;
usage:
  fputs("usage: reticulum-c-git-admin --connect HOST:PORT [--config DIR] create URL\n"
        "       reticulum-c-git-admin ... gperms|rperms URL get\n"
        "       reticulum-c-git-admin ... gperms|rperms URL set FILE|-\n",
        stderr);
  return 2;
}
