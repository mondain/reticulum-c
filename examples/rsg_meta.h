/* Signed-message metadata for rnid (-E, --meta-spec, --meta): the part of ConfigObj and its validator that rnid
 * uses, ported to C.
 *
 * The reference reads a metadata file with ConfigObj, checks it against an optional spec with the validator,
 * and puts the resulting dict into the signed envelope next to "signer" and "pubkey". What is covered here:
 *
 *   file    comments (#), [section] and [[nested]] sections, key = value (keys and values may be quoted with
 *           ' or "), comma separated lists (a trailing comma makes a one item list, a lone comma an empty one),
 *           inline comments. Not covered: triple-quoted and continued values, include files, %(name)s
 *           interpolation, the encoding and BOM handling.
 *   spec    the same syntax, each value a check: string, integer, float, boolean, option, list, int_list,
 *           float_list, bool_list, string_list (and "" to pass a value through), with min/max/default
 *           (default=None, default=list(a, b)). As in the reference, which reads the spec with lists switched
 *           on, a check with a comma in it must be quoted: count = "integer(0, 100)". Not covered: ip_addr,
 *           tuple, mixed_list, __many__, custom checks.
 *
 * Anything outside that is refused with a message rather than guessed at. Order matters for the signature:
 * a section's plain values come first in file order, then its subsections, and defaults added by the spec
 * follow the values already there, exactly as ConfigObj's dict() yields them. */
#ifndef RETICULUM_C_RSG_META_H
#define RETICULUM_C_RSG_META_H
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <reticulum_c/rnc_ipc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { MV_STR = 1, MV_INT, MV_FLOAT, MV_BOOL, MV_NIL, MV_LIST, MV_SECTION } mv_type;
typedef struct mv {
  mv_type type;
  char *key, *str;
  long long i;
  double f;
  int b;
  struct mv **kid;
  size_t n, cap;
} mv;

static mv *mv_new(mv_type type, const char *key) {
  mv *m = calloc(1, sizeof(*m));
  if (!m)
    return NULL;
  m->type = type;
  if (key && !(m->key = strdup(key))) {
    free(m);
    return NULL;
  }
  return m;
}
static void mv_free(mv *m) {
  size_t i;
  if (!m)
    return;
  for (i = 0; i < m->n; ++i)
    mv_free(m->kid[i]);
  free(m->kid);
  free(m->key);
  free(m->str);
  free(m);
}
static int mv_add(mv *parent, mv *child) {
  if (parent->n == parent->cap) {
    size_t cap = parent->cap ? parent->cap * 2 : 8;
    mv **grown = realloc(parent->kid, cap * sizeof(*grown));
    if (!grown)
      return 0;
    parent->kid = grown;
    parent->cap = cap;
  }
  parent->kid[parent->n++] = child;
  return 1;
}
static mv *mv_find(const mv *section, const char *key) {
  size_t i;
  for (i = 0; i < section->n; ++i)
    if (section->kid[i]->key && !strcmp(section->kid[i]->key, key))
      return section->kid[i];
  return NULL;
}
static mv *mv_string(const char *key, const char *text, size_t n) {
  mv *m = mv_new(MV_STR, key);
  if (!m)
    return NULL;
  m->str = malloc(n + 1);
  if (!m->str) {
    mv_free(m);
    return NULL;
  }
  memcpy(m->str, text, n);
  m->str[n] = 0;
  return m;
}
/* Records a message (fmt may hold one %s for `a`), prefixed with the line number when there is one; returns 0. */
static int meta_fail(char *err, size_t cap, const char *fmt, const char *a, long line) {
  if (err && cap) {
    char text[200];
    (void)snprintf(text, sizeof(text), fmt, a ? a : "");
    if (line > 0)
      (void)snprintf(err, cap, "line %ld: %s", line, text);
    else
      (void)snprintf(err, cap, "%s", text);
  }
  return 0;
}
static int utf8_valid(const unsigned char *s, size_t n) {
  size_t i = 0;
  while (i < n) {
    unsigned char c = s[i];
    size_t extra;
    if (c < 0x80)
      extra = 0;
    else if (c >= 0xc2 && c <= 0xdf)
      extra = 1;
    else if (c >= 0xe0 && c <= 0xef)
      extra = 2;
    else if (c >= 0xf0 && c <= 0xf4)
      extra = 3;
    else
      return 0;
    {
      size_t k;
      for (k = 1; k <= extra; ++k)
        if (i + k >= n || (s[i + k] & 0xc0) != 0x80)
          return 0;
      /* no overlong forms, surrogates or values past U+10FFFF */
      if (extra >= 2 && ((c == 0xe0 && s[i + 1] < 0xa0) || (c == 0xed && s[i + 1] >= 0xa0) ||
                         (c == 0xf0 && s[i + 1] < 0x90) || (c == 0xf4 && s[i + 1] >= 0x90)))
        return 0;
    }
    i += extra + 1;
  }
  return 1;
}

/* ---- parsing ------------------------------------------------------------- */
static const char *skip_ws(const char *p, const char *end) {
  while (p < end && (*p == ' ' || *p == '\t'))
    ++p;
  return p;
}
/* A value in list mode: one string, or a list when a comma appears outside quotes. */
static mv *parse_value(const char *key, const char *p, const char *end, char *err, size_t cap, long line) {
  mv *list = NULL, *single = NULL;
  int commas = 0;
  if (end - p >= 3 && (!strncmp(p, "'''", 3) || !strncmp(p, "\"\"\"", 3))) {
    meta_fail(err, cap, "triple-quoted values are not supported", "", line);
    return NULL;
  }
  if (end - p == 1 && *p == ',') { /* a lone comma is an empty list */
    list = mv_new(MV_LIST, key);
    return list;
  }
  for (;;) {
    const char *item = p, *stop;
    size_t len;
    mv *s;
    int quoted = 0;
    p = skip_ws(p, end);
    item = p;
    if (p >= end || *p == '#') { /* nothing left: an empty last item */
      len = 0;
      stop = p;
    } else if (*p == '"' || *p == '\'') {
      const char *q = memchr(p + 1, *p, (size_t)(end - p - 1));
      if (!q) {
        meta_fail(err, cap, "unterminated quote in value", "", line);
        goto fail;
      }
      item = p + 1;
      len = (size_t)(q - item);
      p = q + 1;
      quoted = 1;
      stop = p;
    } else if (*p == ',') {
      meta_fail(err, cap, "unexpected comma in value", "", line);
      goto fail;
    } else {
      stop = p;
      while (stop < end && *stop != ',' && *stop != '#')
        ++stop;
      len = (size_t)(stop - item);
      while (len && (item[len - 1] == ' ' || item[len - 1] == '\t'))
        --len;
      p = stop;
    }
    (void)quoted;
    p = skip_ws(p, end);
    if (p < end && *p == ',') { /* an item followed by a comma: this is a list */
      commas = 1;
      if (!list && !(list = mv_new(MV_LIST, key)))
        goto fail;
      if (!(s = mv_string(NULL, item, len)) || !mv_add(list, s))
        goto fail;
      ++p;
      continue;
    }
    if (p < end && *p != '#') {
      meta_fail(err, cap, "unexpected text after a quoted value", "", line);
      goto fail;
    }
    /* the last item (an empty one after a trailing comma is not added) */
    if (commas) {
      if (len || quoted) {
        if (!(s = mv_string(NULL, item, len)) || !mv_add(list, s))
          goto fail;
      }
      return list;
    }
    single = mv_string(key, item, len);
    return single;
  }
fail:
  mv_free(list);
  mv_free(single);
  return NULL;
}
/* Reads a quoted or bare name from p; sets *next past it (and past the quotes). */
static char *parse_name(const char *p, const char *limit, const char **next) {
  char *name;
  size_t len;
  if (p < limit && (*p == '"' || *p == '\'')) {
    const char *q = memchr(p + 1, *p, (size_t)(limit - p - 1));
    if (!q)
      return NULL;
    len = (size_t)(q - p - 1);
    name = malloc(len + 1);
    if (!name)
      return NULL;
    memcpy(name, p + 1, len);
    name[len] = 0;
    *next = q + 1;
    return name;
  }
  len = (size_t)(limit - p);
  while (len && (p[len - 1] == ' ' || p[len - 1] == '\t'))
    --len;
  name = malloc(len + 1);
  if (!name)
    return NULL;
  memcpy(name, p, len);
  name[len] = 0;
  *next = limit;
  return name;
}
/* Parses a ConfigObj file (a metadata file or a spec, both with lists switched on, as the reference loads them).
 * Returns 1 and a section tree in *out, or 0 with a message in err. */
static int meta_parse(const char *text, size_t size, mv **out, char *err, size_t cap) {
  mv *root = mv_new(MV_SECTION, NULL), *stack[16];
  size_t depth = 0, pos = 0;
  long line_no = 0;
  if (!root)
    return 0;
  if (!utf8_valid((const unsigned char *)text, size)) {
    meta_fail(err, cap, "the file is not valid UTF-8", "", 0);
    mv_free(root);
    return 0;
  }
  stack[0] = root;
  while (pos < size) {
    const char *line = text + pos, *end, *s, *e;
    size_t eol = pos;
    while (eol < size && text[eol] != '\n')
      ++eol;
    end = text + eol;
    pos = eol + 1;
    ++line_no;
    s = line;
    e = end;
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r'))
      --e;
    s = skip_ws(s, e);
    if (s >= e || *s == '#')
      continue;
    if (*s == '[') { /* a section marker */
      size_t opens = 0, closes = 0;
      const char *p = s, *name_end = NULL;
      char *name;
      mv *section, *parent;
      while (p < e && *p == '[') {
        ++opens;
        ++p;
        p = skip_ws(p, e);
      }
      if (p < e && (*p == '"' || *p == '\'')) {
        const char *q = memchr(p + 1, *p, (size_t)(e - p - 1));
        if (!q) {
          meta_fail(err, cap, "bad section name", "", line_no);
          goto fail;
        }
        name_end = q + 1;
      } else {
        const char *k;
        for (k = p; k < e; ++k)
          if (*k == ']')
            break;
        if (k == e) {
          meta_fail(err, cap, "unterminated section marker", "", line_no);
          goto fail;
        }
        name_end = k;
      }
      name = parse_name(p, name_end, &name_end);
      if (!name || !*name) {
        free(name);
        meta_fail(err, cap, "empty section name", "", line_no);
        goto fail;
      }
      p = name_end;
      while (p < e && (*p == ']' || *p == ' ' || *p == '\t')) {
        closes += *p == ']';
        ++p;
      }
      if (p < e && *p != '#') {
        free(name);
        meta_fail(err, cap, "text after a section marker", "", line_no);
        goto fail;
      }
      if (opens != closes || opens > 15 || opens > depth + 1) {
        free(name);
        meta_fail(err, cap, "mismatched or too deeply nested section marker", "", line_no);
        goto fail;
      }
      depth = opens;
      parent = stack[depth - 1];
      if (mv_find(parent, name)) {
        free(name);
        meta_fail(err, cap, "duplicate section or key name", "", line_no);
        goto fail;
      }
      section = mv_new(MV_SECTION, name);
      free(name);
      if (!section || !mv_add(parent, section)) {
        mv_free(section);
        goto fail;
      }
      stack[depth] = section;
      continue;
    }
    { /* key = value */
      const char *p = s, *eq, *value;
      char *key;
      mv *item, *parent = stack[depth];
      if (*p == '"' || *p == '\'') {
        const char *q = memchr(p + 1, *p, (size_t)(e - p - 1));
        if (!q) {
          meta_fail(err, cap, "unterminated quote in key", "", line_no);
          goto fail;
        }
        eq = skip_ws(q + 1, e);
        if (eq >= e || *eq != '=') {
          meta_fail(err, cap, "no = after the key", "", line_no);
          goto fail;
        }
        key = parse_name(p, q + 1, &value);
      } else {
        eq = memchr(p, '=', (size_t)(e - p));
        if (!eq || eq == p) {
          meta_fail(err, cap, "not a section marker or key = value", "", line_no);
          goto fail;
        }
        key = parse_name(p, eq, &value);
      }
      if (!key)
        goto fail;
      value = skip_ws(eq + 1, e);
      if (mv_find(parent, key)) {
        free(key);
        meta_fail(err, cap, "duplicate section or key name", "", line_no);
        goto fail;
      }
      item = parse_value(key, value, e, err, cap, line_no);
      free(key);
      if (!item)
        goto fail;
      if (!mv_add(parent, item)) {
        mv_free(item);
        goto fail;
      }
    }
  }
  *out = root;
  return 1;
fail:
  mv_free(root);
  return 0;
}

/* ---- the validator ---------------------------------------------------------- */
typedef struct check {
  char name[24];
  char *pos[8]; /* positional arguments */
  size_t pos_count;
  char *min, *max;
  char *default_str;      /* default as written, NULL when there is none */
  char **default_list;    /* default=list(...) */
  size_t default_list_count;
  int has_default_list;
} check;
static void check_free(check *c) {
  size_t i;
  for (i = 0; i < c->pos_count; ++i)
    free(c->pos[i]);
  free(c->min);
  free(c->max);
  free(c->default_str);
  for (i = 0; i < c->default_list_count; ++i)
    free(c->default_list[i]);
  free(c->default_list);
}
static char *unquote_dup(const char *s, size_t n, int keep_quoted_none) {
  while (n && (*s == ' ' || *s == '\t')) {
    ++s;
    --n;
  }
  while (n && (s[n - 1] == ' ' || s[n - 1] == '\t'))
    --n;
  if (n >= 2 && (*s == '"' || *s == '\'') && s[n - 1] == *s && !(keep_quoted_none && n == 6 && !strncmp(s + 1, "None", 4))) {
    ++s;
    n -= 2;
  }
  {
    char *r = malloc(n + 1);
    if (!r)
      return NULL;
    memcpy(r, s, n);
    r[n] = 0;
    return r;
  }
}
/* Splits "a, 'b,c', key=list(x, y)" at top-level commas. */
static size_t split_args(const char *s, size_t n, const char **starts, size_t *lens, size_t max) {
  size_t count = 0, i = 0, from = 0;
  int depth = 0;
  char quote = 0;
  for (i = 0; i <= n; ++i) {
    char c = i < n ? s[i] : ',';
    if (quote) {
      if (c == quote)
        quote = 0;
    } else if (c == '"' || c == '\'')
      quote = c;
    else if (c == '(')
      ++depth;
    else if (c == ')')
      --depth;
    else if (c == ',' && depth == 0) {
      if (count < max) {
        starts[count] = s + from;
        lens[count] = i - from;
        ++count;
      }
      from = i + 1;
    }
  }
  return count;
}
/* Parses "integer(min=0, max=5, default=3)". Returns 0 with a message for syntax this port does not cover. */
static int check_parse(const char *spec, check *c, char *err, size_t cap) {
  const char *open = strchr(spec, '('), *close = strrchr(spec, ')');
  size_t name_len = open ? (size_t)(open - spec) : strlen(spec), i, n, count;
  const char *starts[24];
  size_t lens[24];
  memset(c, 0, sizeof(*c));
  while (name_len && isspace((unsigned char)spec[name_len - 1]))
    --name_len;
  if (name_len >= sizeof(c->name)) {
    meta_fail(err, cap, "unknown check \"%s\"", spec, 0);
    return 0;
  }
  memcpy(c->name, spec, name_len);
  if (!open)
    return 1;
  if (!close || close < open) {
    meta_fail(err, cap, "bad syntax in check \"%s\"", spec, 0);
    return 0;
  }
  n = (size_t)(close - open - 1);
  count = split_args(open + 1, n, starts, lens, 24);
  if (count == 1 && lens[0] == 0)
    count = 0;
  for (i = 0; i < count; ++i) {
    const char *a = starts[i];
    size_t al = lens[i], k = 0;
    while (al && isspace((unsigned char)*a)) {
      ++a;
      --al;
    }
    while (k < al && (isalnum((unsigned char)a[k]) || a[k] == '_'))
      ++k;
    if (k && k < al && !isdigit((unsigned char)a[0])) {
      size_t j = k;
      while (j < al && isspace((unsigned char)a[j]))
        ++j;
      if (j < al && a[j] == '=') { /* name=value */
        char key[16];
        const char *v = a + j + 1;
        size_t vl = al - j - 1;
        while (vl && isspace((unsigned char)*v)) {
          ++v;
          --vl;
        }
        if (k >= sizeof(key)) {
          meta_fail(err, cap, "bad argument in check \"%s\"", spec, 0);
          return 0;
        }
        memcpy(key, a, k);
        key[k] = 0;
        if (vl > 5 && !strncmp(v, "list(", 5) && v[vl - 1] == ')' && !strcmp(key, "default")) {
          const char *ms[24];
          size_t ml[24], m, mc = split_args(v + 5, vl - 6, ms, ml, 24);
          if (mc == 1 && ml[0] == 0)
            mc = 0;
          c->default_list = calloc(mc ? mc : 1, sizeof(char *));
          if (!c->default_list)
            return 0;
          for (m = 0; m < mc; ++m)
            c->default_list[m] = unquote_dup(ms[m], ml[m], 0);
          c->default_list_count = mc;
          c->has_default_list = 1;
        } else if (!strcmp(key, "default")) {
          free(c->default_str);
          c->default_str = unquote_dup(v, vl, 1);
        } else if (!strcmp(key, "min")) {
          free(c->min);
          c->min = unquote_dup(v, vl, 1);
        } else if (!strcmp(key, "max")) {
          free(c->max);
          c->max = unquote_dup(v, vl, 1);
        } else {
          meta_fail(err, cap, "unsupported argument \"%s\" in a check", key, 0);
          return 0;
        }
        continue;
      }
    }
    if (c->pos_count >= 8) {
      meta_fail(err, cap, "too many arguments in check \"%s\"", spec, 0);
      return 0;
    }
    c->pos[c->pos_count++] = unquote_dup(a, al, 0);
  }
  return 1;
}
/* Python's int(): optional sign, digits with single underscores between them, surrounding space. */
static int py_int(const char *s, long long *out) {
  const char *p = s;
  int neg = 0, digits = 0, prev_us = 1;
  long long v = 0;
  while (isspace((unsigned char)*p))
    ++p;
  if (*p == '+' || *p == '-')
    neg = *p++ == '-';
  for (; *p; ++p) {
    if (isdigit((unsigned char)*p)) {
      if (v > (long long)(0x7fffffffffffffffLL - (*p - '0')) / 10)
        return 0;
      v = v * 10 + (*p - '0');
      digits = 1;
      prev_us = 0;
    } else if (*p == '_' && !prev_us && p[1] && isdigit((unsigned char)p[1]))
      prev_us = 1;
    else
      break;
  }
  while (isspace((unsigned char)*p))
    ++p;
  if (!digits || *p)
    return 0;
  *out = neg ? -v : v;
  return 1;
}
static int py_float(const char *s, double *out) {
  char buf[128], *end;
  size_t n = 0;
  const char *p;
  for (p = s; *p && n + 1 < sizeof(buf); ++p)
    if (*p != '_')
      buf[n++] = *p;
  buf[n] = 0;
  if (!n || strpbrk(buf, "xXpP"))
    return 0;
  errno = 0;
  *out = strtod(buf, &end);
  while (isspace((unsigned char)*end))
    ++end;
  return end != buf && !*end;
}
static int param_int(const char *s, int *has, long long *v) {
  *has = s != NULL;
  return !s || py_int(s, v);
}
static int param_float(const char *s, int *has, double *v) {
  *has = s != NULL;
  return !s || py_float(s, v);
}
/* Converts one config node to what `c` says. `in` is a string or a list of strings; returns a new node or NULL. */
static mv *check_apply(const check *c, const mv *in, const char *key) {
  const char *name = c->name;
  int is_list_check = !strcmp(name, "list") || !strcmp(name, "int_list") || !strcmp(name, "float_list") ||
                      !strcmp(name, "bool_list") || !strcmp(name, "string_list");
  mv *out = NULL;
  if (!*name || !strcmp(name, "pass")) { /* the empty check passes a value through */
    out = mv_new(in->type, key);
    if (!out)
      return NULL;
    if (in->str && !(out->str = strdup(in->str))) {
      mv_free(out);
      return NULL;
    }
    out->i = in->i;
    out->f = in->f;
    out->b = in->b;
    {
      size_t k;
      for (k = 0; k < in->n; ++k) {
        mv *copy = check_apply(c, in->kid[k], NULL);
        if (!copy || !mv_add(out, copy)) {
          mv_free(copy);
          mv_free(out);
          return NULL;
        }
      }
    }
    return out;
  }
  if (is_list_check) {
    long long lo = 0, hi = 0;
    int has_lo, has_hi;
    size_t k;
    check item;
    memset(&item, 0, sizeof(item)); /* the element check has no limits of its own */
    if (in->type != MV_LIST || !param_int(c->min, &has_lo, &lo) || !param_int(c->max, &has_hi, &hi))
      return NULL;
    if ((has_lo && (long long)in->n < lo) || (has_hi && (long long)in->n > hi))
      return NULL;
    out = mv_new(MV_LIST, key);
    if (!out)
      return NULL;
    strcpy(item.name, !strcmp(name, "int_list") ? "integer" : !strcmp(name, "float_list") ? "float"
                       : !strcmp(name, "bool_list") ? "boolean" : "string");
    for (k = 0; k < in->n; ++k) {
      mv *converted;
      if (!strcmp(name, "list")) {
        converted = mv_string(NULL, in->kid[k]->str ? in->kid[k]->str : "", in->kid[k]->str ? strlen(in->kid[k]->str) : 0);
      } else if (in->kid[k]->type != MV_STR)
        converted = NULL;
      else
        converted = check_apply(&item, in->kid[k], NULL);
      if (!converted || !mv_add(out, converted)) {
        mv_free(converted);
        mv_free(out);
        return NULL;
      }
    }
    return out;
  }
  if (in->type != MV_STR)
    return NULL;
  if (!strcmp(name, "integer")) {
    long long v, lo = 0, hi = 0;
    int has_lo, has_hi;
    if (!param_int(c->min, &has_lo, &lo) || !param_int(c->max, &has_hi, &hi) || !py_int(in->str, &v) ||
        (has_lo && v < lo) || (has_hi && v > hi))
      return NULL;
    out = mv_new(MV_INT, key);
    if (out)
      out->i = v;
  } else if (!strcmp(name, "float")) {
    double v, lo = 0, hi = 0;
    int has_lo, has_hi;
    if (!param_float(c->min, &has_lo, &lo) || !param_float(c->max, &has_hi, &hi) || !py_float(in->str, &v) ||
        (has_lo && v < lo) || (has_hi && v > hi))
      return NULL;
    out = mv_new(MV_FLOAT, key);
    if (out)
      out->f = v;
  } else if (!strcmp(name, "boolean")) {
    char lower[8];
    size_t k, n = strlen(in->str);
    int v;
    if (n >= sizeof(lower))
      return NULL;
    for (k = 0; k <= n; ++k)
      lower[k] = (char)tolower((unsigned char)in->str[k]);
    if (!strcmp(lower, "on") || !strcmp(lower, "1") || !strcmp(lower, "true") || !strcmp(lower, "yes"))
      v = 1;
    else if (!strcmp(lower, "off") || !strcmp(lower, "0") || !strcmp(lower, "false") || !strcmp(lower, "no"))
      v = 0;
    else
      return NULL;
    out = mv_new(MV_BOOL, key);
    if (out)
      out->b = v;
  } else if (!strcmp(name, "string")) {
    long long lo = 0, hi = 0, chars = 0;
    int has_lo, has_hi;
    const unsigned char *u;
    if (!param_int(c->min, &has_lo, &lo) || !param_int(c->max, &has_hi, &hi))
      return NULL;
    for (u = (const unsigned char *)in->str; *u; ++u)
      chars += (*u & 0xc0) != 0x80; /* Python counts characters, not bytes */
    if ((has_lo && chars < lo) || (has_hi && chars > hi))
      return NULL;
    out = mv_string(key, in->str, strlen(in->str));
  } else if (!strcmp(name, "option")) {
    size_t k;
    for (k = 0; k < c->pos_count; ++k)
      if (!strcmp(c->pos[k], in->str))
        break;
    if (k == c->pos_count)
      return NULL;
    out = mv_string(key, in->str, strlen(in->str));
  }
  return out;
}
static int check_supported(const char *name) {
  static const char *known[] = {"", "pass", "integer", "float", "boolean", "string", "option", "list", "int_list",
                                "float_list", "bool_list", "string_list"};
  size_t k;
  for (k = 0; k < sizeof(known) / sizeof(*known); ++k)
    if (!strcmp(name, known[k]))
      return 1;
  return 0;
}
/* Replaces `section`'s child `old` with `fresh` (same position), or appends it. */
static int mv_put(mv *section, mv *old, mv *fresh) {
  size_t i;
  if (!old)
    return mv_add(section, fresh);
  for (i = 0; i < section->n; ++i)
    if (section->kid[i] == old) {
      mv_free(old);
      section->kid[i] = fresh;
      return 1;
    }
  return 0;
}
/* Validates `cfg` against `spec` in place: values become typed, missing ones take their defaults. Returns 1 when
 * everything passes, 0 with a message otherwise (the reference only says the metadata did not validate). */
static int meta_validate(mv *cfg, const mv *spec, char *err, size_t cap) {
  size_t i;
  int ok = 1;
  /* sections the spec has and the file lacks are created empty, so their defaults apply */
  for (i = 0; i < spec->n; ++i) {
    const mv *s = spec->kid[i];
    if (s->type == MV_SECTION) {
      mv *have;
      if (!strcmp(s->key, "__many__")) {
        meta_fail(err, cap, "__many__ in a spec is not supported", "", 0);
        return 0;
      }
      have = mv_find(cfg, s->key);
      if (!have) {
        have = mv_new(MV_SECTION, s->key);
        if (!have || !mv_add(cfg, have)) {
          mv_free(have);
          return 0;
        }
      }
    }
  }
  for (i = 0; i < spec->n; ++i) {
    const mv *s = spec->kid[i];
    mv *have = s->key ? mv_find(cfg, s->key) : NULL;
    check c;
    mv *fresh;
    if (s->type == MV_SECTION) {
      if (have->type != MV_SECTION) {
        meta_fail(err, cap, "\"%s\" was given as a single value, the spec has a section", s->key, 0);
        ok = 0;
      } else if (!meta_validate(have, s, err, cap))
        ok = 0;
      continue;
    }
    if (!strcmp(s->key, "__many__")) {
      meta_fail(err, cap, "__many__ in a spec is not supported", "", 0);
      return 0;
    }
    if (have && have->type == MV_SECTION) {
      meta_fail(err, cap, "\"%s\" was given as a section, the spec has a value", s->key, 0);
      ok = 0;
      continue;
    }
    if (s->type != MV_STR) { /* an unquoted comma in a check makes it a list; the reference fails on that too */
      meta_fail(err, cap, "the check for \"%s\" holds an unquoted comma: put the whole check in quotes", s->key, 0);
      return 0;
    }
    if (!check_parse(s->str, &c, err, cap))
      return 0;
    if (!check_supported(c.name)) {
      meta_fail(err, cap, "the check \"%s\" is not supported here", c.name, 0);
      check_free(&c);
      return 0;
    }
    if (!have) { /* missing: the default, or a failure */
      mv src = {0};
      if (c.has_default_list) {
        size_t k;
        src.type = MV_LIST;
        for (k = 0; k < c.default_list_count; ++k) {
          mv *item = mv_string(NULL, c.default_list[k], strlen(c.default_list[k]));
          if (!item || !mv_add(&src, item)) {
            mv_free(item);
            check_free(&c);
            return 0;
          }
        }
        fresh = check_apply(&c, &src, s->key);
        for (k = 0; k < src.n; ++k)
          mv_free(src.kid[k]);
        free(src.kid);
      } else if (c.default_str && !strcmp(c.default_str, "None")) {
        fresh = mv_new(MV_NIL, s->key);
      } else if (c.default_str) {
        src.type = MV_STR;
        src.str = c.default_str;
        fresh = check_apply(&c, &src, s->key);
      } else {
        meta_fail(err, cap, "\"%s\" is missing and has no default", s->key, 0);
        check_free(&c);
        ok = 0;
        continue;
      }
    } else
      fresh = check_apply(&c, have, s->key);
    if (!fresh) {
      meta_fail(err, cap, "\"%s\" does not pass its check", s->key, 0);
      check_free(&c);
      ok = 0;
      continue;
    }
    check_free(&c);
    if (!mv_put(cfg, have, fresh)) {
      mv_free(fresh);
      return 0;
    }
  }
  return ok;
}

/* ---- msgpack ------------------------------------------------------------- */
/* The dict ConfigObj hands out: a section's plain values first, then its subsections, each in file order. */
static size_t mv_visible(const mv *section, const char *skip1, const char *skip2) {
  size_t i, n = 0;
  for (i = 0; i < section->n; ++i)
    n += !(skip1 && !strcmp(section->kid[i]->key, skip1)) && !(skip2 && !strcmp(section->kid[i]->key, skip2));
  return n;
}
static int mv_pack(rnc_rpc_writer *w, const mv *m);
static int mv_pack_entries(rnc_rpc_writer *w, const mv *section, const char *skip1, const char *skip2) {
  size_t i;
  int pass;
  for (pass = 0; pass < 2; ++pass)
    for (i = 0; i < section->n; ++i) {
      const mv *k = section->kid[i];
      if ((k->type == MV_SECTION) != (pass == 1) || (skip1 && !strcmp(k->key, skip1)) || (skip2 && !strcmp(k->key, skip2)))
        continue;
      if (rnc_rpc_write_string(w, k->key) != RNC_OK || !mv_pack(w, k))
        return 0;
    }
  return 1;
}
static int mv_pack(rnc_rpc_writer *w, const mv *m) {
  size_t i;
  switch (m->type) {
  case MV_STR:
    return rnc_rpc_write_string(w, m->str) == RNC_OK;
  case MV_INT:
    return (m->i >= 0 ? rnc_rpc_write_uint(w, (uint64_t)m->i) : rnc_rpc_write_int(w, m->i)) == RNC_OK;
  case MV_FLOAT:
    return rnc_rpc_write_real(w, m->f) == RNC_OK;
  case MV_BOOL:
    return rnc_rpc_write_bool(w, m->b) == RNC_OK;
  case MV_NIL:
    return rnc_rpc_write_nil(w) == RNC_OK;
  case MV_LIST:
    if (rnc_rpc_write_array(w, m->n) != RNC_OK)
      return 0;
    for (i = 0; i < m->n; ++i)
      if (!mv_pack(w, m->kid[i]))
        return 0;
    return 1;
  case MV_SECTION:
    return rnc_rpc_write_map(w, m->n) == RNC_OK && mv_pack_entries(w, m, NULL, NULL);
  }
  return 0;
}
#endif
