/* Markdown to micron for the page server of reticulum-c-git (included by
 * reticulum_git.c): util.py's MarkdownToMicron, line for line. The reference
 * uses Python regular expressions; they are written out as scanners here
 * (headings, rules, lists, quotes, fences, tables and the inline links, code,
 * bold and italic). Where Python's \s matches Unicode white space this matches
 * ASCII white space. */
#ifndef RETICULUM_C_RNGIT_MD_H
#define RETICULUM_C_RNGIT_MD_H

#define MD_BULLET "\xe2\x80\xa2" /* U+2022 */
#define MD_CODE_BG "`BT282828"
#define MD_CODE_BG_INLINE "`BT383838"
#define MD_CODE_FG "`Fddd"
#define MD_CODE_RESET "`f`b"
#define MD_TABLE_MIN_COL 3

typedef struct md_conv {
  int max_width;
  char url_scope[1024];
} md_conv;
static void md_init(md_conv *c, int max_width, const char *url_scope) {
  c->max_width = max_width;
  snprintf(c->url_scope, sizeof(c->url_scope), "%s", url_scope && *url_scope ? url_scope : ":/page/");
}

/* ---- a list of strings -------------------------------------------------- */
typedef struct strlist {
  char **v;
  size_t n, cap;
} strlist;
static void sl_free(strlist *l) {
  size_t i;
  for (i = 0; i < l->n; ++i)
    free(l->v[i]);
  free(l->v);
  memset(l, 0, sizeof(*l));
}
static char *md_dup(const char *s, size_t n) {
  char *d = malloc(n + 1);
  if (d) {
    memcpy(d, s, n);
    d[n] = 0;
  }
  return d;
}
static int sl_push_n(strlist *l, const char *s, size_t n) {
  if (l->n == l->cap) {
    size_t cap = l->cap ? l->cap * 2 : 16;
    char **nv = realloc(l->v, cap * sizeof(char *));
    if (!nv)
      return 0;
    l->v = nv;
    l->cap = cap;
  }
  l->v[l->n] = md_dup(s, n);
  if (!l->v[l->n])
    return 0;
  l->n++;
  return 1;
}
static int sl_push(strlist *l, const char *s) { return sl_push_n(l, s, strlen(s)); }
static void sl_clear(strlist *l) {
  size_t i;
  for (i = 0; i < l->n; ++i)
    free(l->v[i]);
  l->n = 0;
}

/* ---- widths ------------------------------------------------------------- */
static int md_display_width(const char *s, size_t n) {
  size_t i = 0;
  int w = 0;
  size_t cps = 0;
  int bad = 0;
  if (getenv("RNGIT_NO_WCWIDTH"))
    return (int)u8_count(s, n);
  while (i < n) {
    size_t l;
    int cw = u8_cell_width(u8_decode(s + i, &l));
    if (cw < 0)
      bad = 1;
    else
      w += cw;
    ++cps;
    i += l;
  }
  return bad ? (int)cps : w;
}
/* remove every match of "`" + one of marks + exactly `hex` hex digits */
static void md_strip_color(sbuf *o, const char *s, int with_T) {
  size_t i = 0, n = strlen(s);
  while (i < n) {
    if (s[i] == '`' && i + 1 < n && (s[i + 1] == 'F' || s[i + 1] == 'B')) {
      size_t k = i + 2, need = with_T ? 6 : 3, h = 0;
      if (with_T) {
        if (k < n && s[k] == 'T')
          ++k;
        else
          goto keep;
      }
      while (k < n && h < need && hexval(s[k]) >= 0) {
        ++k;
        ++h;
      }
      if (h == need) {
        i = k;
        continue;
      }
    }
  keep:
    sb_addc(o, s[i++]);
  }
}
static int md_visible_width(const char *text) {
  sbuf a, b, c;
  size_t i, n;
  int w;
  sb_init(&a);
  sb_init(&b);
  sb_init(&c);
  a.limit = b.limit = c.limit = 8u << 20;
  md_strip_color(&a, text, 0);
  md_strip_color(&b, sb_str(&a), 1);
  n = b.n;
  for (i = 0; i < n; ++i) {
    char ch = b.p[i];
    if (ch == '`' && i + 1 < n && strchr("!*_=", b.p[i + 1]) && b.p[i + 1]) {
      ++i;
      continue;
    }
    if (ch == '`' && i + 1 < n && (b.p[i + 1] == 'f' || b.p[i + 1] == 'b')) {
      /* "`f`b", "`f" and "`b" are all removed */
      ++i;
      continue;
    }
    sb_addc(&c, ch);
  }
  w = md_display_width(sb_str(&c), c.n);
  sb_free(&a);
  sb_free(&b);
  sb_free(&c);
  return w;
}

/* ---- inline ------------------------------------------------------------- */
static int md_is_space(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'; }
static void md_escape_literals(sbuf *o, const char *s, size_t n) {
  size_t i;
  for (i = 0; i < n; ++i) {
    if (s[i] == '`')
      sb_addc(o, '\\');
    sb_addc(o, s[i]);
  }
}
/* replacements of emphasis: `**x**` `__x__` (bold) then `*x*` `_x_` (italic). */
static void md_emph(const char *s, int bold, sbuf *o) {
  size_t i = 0, n = strlen(s);
  while (i < n) {
    char c = s[i];
    size_t dl = bold ? 2 : 1, j;
    int match = 0;
    if ((c == '*' || c == '_') && (bold ? (i + 1 < n && s[i + 1] == c) : 1)) {
      /* content: one or more characters (not newline), then the closer */
      j = i + dl;
      if (j < n && s[j] != '\n') {
        size_t k = j + 1;
        while (k < n && s[k - 1] != '\n') {
          if (bold ? (k + 1 < n && s[k] == c && s[k + 1] == c) : s[k] == c) {
            match = 1;
            break;
          }
          if (s[k] == '\n')
            break;
          ++k;
        }
        if (match) {
          sb_adds(o, bold ? "`!" : "`*");
          sb_add(o, s + j, k - j);
          sb_adds(o, bold ? "`!" : "`*");
          i = k + dl;
          continue;
        }
      }
    }
    sb_addc(o, c);
    ++i;
  }
}
typedef struct md_ph {
  char *text, *url;
} md_ph;
static void md_format_inline(const md_conv *c, const char *in, sbuf *out) {
  sbuf s1, s2, s3, s4;
  md_ph *links = NULL, *codes = NULL;
  size_t nl = 0, nc = 0, i, n = strlen(in);
  sb_init(&s1);
  sb_init(&s2);
  sb_init(&s3);
  sb_init(&s4);
  s1.limit = s2.limit = s3.limit = s4.limit = 8u << 20;
  links = calloc(n / 4 + 2, sizeof(md_ph));
  codes = calloc(n / 2 + 2, sizeof(md_ph));
  if (!links || !codes) {
    free(links);
    free(codes);
    sb_adds(out, in);
    return;
  }
  /* links: [text](url) */
  for (i = 0; i < n;) {
    if (in[i] == '[') {
      size_t j = i + 1;
      while (j < n && in[j] != ']')
        ++j;
      if (j < n && j > i + 1 && j + 1 < n && in[j + 1] == '(') {
        size_t k = j + 2;
        while (k < n && in[k] != ')')
          ++k;
        if (k < n && k > j + 2) {
          links[nl].text = md_dup(in + i + 1, j - i - 1);
          links[nl].url = md_dup(in + j + 2, k - j - 2);
          sb_addf(&s1, "\x01LINK%zu\x01", nl);
          ++nl;
          i = k + 1;
          continue;
        }
      }
    }
    sb_addc(&s1, in[i++]);
  }
  /* inline code */
  n = s1.n;
  for (i = 0; i < n;) {
    if (s1.p[i] == '`') {
      size_t j = i + 1;
      while (j < n && s1.p[j] != '`')
        ++j;
      if (j < n && j > i + 1) {
        codes[nc].text = md_dup(s1.p + i + 1, j - i - 1);
        sb_addf(&s2, "\x01" "CODE%zu\x01", nc);
        ++nc;
        i = j + 1;
        continue;
      }
    }
    sb_addc(&s2, s1.p[i++]);
  }
  md_emph(sb_str(&s2), 1, &s3);
  md_emph(sb_str(&s3), 0, &s4);
  /* restore links, then code */
  {
    sbuf r1, r2;
    const char *t = sb_str(&s4);
    size_t tn = strlen(t);
    sb_init(&r1);
    sb_init(&r2);
    r1.limit = r2.limit = 8u << 20;
    for (i = 0; i < tn;) {
      if (t[i] == '\x01' && !strncmp(t + i + 1, "LINK", 4)) {
        char *end;
        size_t idx = strtoul(t + i + 5, &end, 10);
        if (end != t + i + 5 && *end == '\x01' && idx < nl) {
          char *url = links[idx].url, *hash, *anchor = NULL;
          sbuf full, text;
          sb_init(&full);
          sb_init(&text);
          hash = strchr(url, '#');
          if (hash) {
            char *h2;
            *hash = 0;
            anchor = hash + 1;
            h2 = strchr(anchor, '#');
            if (h2)
              *h2 = 0;
          }
          if (!strstr(url, ":/")) {
            sb_adds(&full, c->url_scope);
            sb_adds(&full, url);
            if (anchor && *anchor) {
              sb_adds(&full, "|anchor=");
              sb_adds(&full, anchor);
            }
          } else
            sb_adds(&full, url);
          {
            const char *x;
            for (x = links[idx].text; *x; ++x)
              if (*x != '`')
                sb_addc(&text, *x);
          }
          sb_addf(&r1, "`_`!`[%s`%s]`!`_", sb_str(&text), sb_str(&full));
          sb_free(&full);
          sb_free(&text);
          i = (size_t)(end - t) + 1;
          continue;
        }
      }
      sb_addc(&r1, t[i++]);
    }
    tn = r1.n;
    for (i = 0; i < tn;) {
      if (r1.p[i] == '\x01' && !strncmp(r1.p + i + 1, "CODE", 4)) {
        char *end;
        size_t idx = strtoul(r1.p + i + 5, &end, 10);
        if (end != r1.p + i + 5 && *end == '\x01' && idx < nc) {
          sb_adds(&r2, MD_CODE_BG_INLINE MD_CODE_FG);
          md_escape_literals(&r2, codes[idx].text, strlen(codes[idx].text));
          sb_adds(&r2, MD_CODE_RESET);
          i = (size_t)(end - r1.p) + 1;
          continue;
        }
      }
      sb_addc(&r2, r1.p[i++]);
    }
    sb_adds(out, sb_str(&r2));
    sb_free(&r1);
    sb_free(&r2);
  }
  for (i = 0; i < nl; ++i) {
    free(links[i].text);
    free(links[i].url);
  }
  for (i = 0; i < nc; ++i)
    free(codes[i].text);
  free(links);
  free(codes);
  sb_free(&s1);
  sb_free(&s2);
  sb_free(&s3);
  sb_free(&s4);
}

/* ---- line level recognisers --------------------------------------------- */
/* the rule: ^(\s*)(---+|===+|\*\*\*+|___+)\s*$ */
static int md_is_hr(const char *l) {
  size_t i = 0, n, run;
  char c;
  while (md_is_space(l[i]))
    ++i;
  c = l[i];
  if (c != '-' && c != '=' && c != '*' && c != '_')
    return 0;
  for (run = 0; l[i + run] == c; ++run)
    ;
  if (run < 3)
    return 0;
  n = i + run;
  while (md_is_space(l[n]))
    ++n;
  return l[n] == 0;
}
/* After a marker: one or more white space characters then at least one
 * character; returns the start of the content or NULL. A line of only white
 * space after the marker still matches when it has two or more of them (the
 * regex gives one back to `.+`). */
static const char *md_after_ws_plus(const char *p) {
  size_t k = 0, len;
  while (md_is_space(p[k]))
    ++k;
  if (!k)
    return NULL;
  len = strlen(p + k);
  if (len)
    return p + k;
  return k >= 2 ? p + k - 1 : NULL;
}
/* ^(#{1,6})\s+(.+)$ */
static int md_is_header(const char *l, int *level, const char **content) {
  size_t h = 0;
  while (l[h] == '#')
    ++h;
  if (h < 1 || h > 6)
    return 0;
  *content = md_after_ws_plus(l + h);
  *level = (int)h;
  return *content != NULL;
}
/* ^(\s*)([-*+])\s+(.+)$ */
static int md_is_list(const char *l, size_t *indent_n, const char **content) {
  size_t i = 0;
  while (md_is_space(l[i]))
    ++i;
  if (l[i] != '-' && l[i] != '*' && l[i] != '+')
    return 0;
  *indent_n = i;
  *content = md_after_ws_plus(l + i + 1);
  return *content != NULL;
}
static void md_format_line(const md_conv *c, const char *line_in, sbuf *out) {
  sbuf esc, work;
  const char *l, *content;
  size_t i, indent_n;
  int level;
  sb_init(&esc);
  sb_init(&work);
  esc.limit = work.limit = 8u << 20;
  for (i = 0; line_in[i]; ++i) {
    if (line_in[i] == '\\')
      sb_addc(&esc, '\\');
    sb_addc(&esc, line_in[i]);
  }
  l = sb_str(&esc);
  if (l[0] == '-' && strncmp(l, "---", 3) && strncmp(l, "- ", 2))
    sb_addc(&work, '\\');
  if (l[0] == '<')
    sb_addc(&work, '\\');
  sb_adds(&work, l);
  l = sb_str(&work);
  if (md_is_hr(l)) {
    sb_addc(out, '-');
  } else if (md_is_header(l, &level, &content)) {
    for (i = 0; i < (size_t)level; ++i)
      sb_addc(out, '>');
    md_format_inline(c, content, out);
  } else if (md_is_list(l, &indent_n, &content)) {
    sb_add(out, l, indent_n);
    sb_addc(out, ' ');
    sb_adds(out, MD_BULLET " ");
    md_format_inline(c, content, out);
  } else
    md_format_inline(c, l, out);
  sb_free(&esc);
  sb_free(&work);
}

/* ---- tables ------------------------------------------------------------- */
static int md_is_table_row(const char *line) {
  const char *p = line, *end;
  size_t n = strlen(line);
  int lead_pipe = 0;
  if (!strchr(line, '|'))
    return 0;
  while (md_is_space(*p))
    ++p;
  if (*p == '|') {
    lead_pipe = 1;
    ++p;
  }
  end = line + n;
  while (end > p && md_is_space(end[-1]))
    --end;
  if (end > p && end[-1] == '|')
    --end;
  if (end <= p) {
    /* the regex gives the optional pipes back until the content is not empty */
    return lead_pipe || end > p || memchr(line, '|', n) != NULL;
  }
  return memchr(p, '|', (size_t)(end - p)) != NULL || lead_pipe;
}
static int md_is_table_sep(const char *line) {
  /* ^\s*\|?(?:\s*:?-+:?\s*\|)+\s*$ */
  const char *p = line;
  int cells = 0;
  if (!strchr(line, '|'))
    return 0;
  while (md_is_space(*p))
    ++p;
  if (*p == '|')
    ++p;
  for (;;) {
    const char *q = p;
    int dashes = 0;
    while (md_is_space(*q))
      ++q;
    if (*q == ':')
      ++q;
    while (*q == '-') {
      ++q;
      ++dashes;
    }
    if (!dashes)
      break;
    if (*q == ':')
      ++q;
    while (md_is_space(*q))
      ++q;
    if (*q != '|')
      break;
    ++q;
    ++cells;
    p = q;
  }
  if (!cells)
    return 0;
  while (md_is_space(*p))
    ++p;
  return *p == 0;
}
static void md_parse_row(const char *line_in, strlist *cells) {
  char *line = md_dup(line_in, strlen(line_in)), *p, *cur;
  sbuf cell;
  int esc = 0;
  size_t n;
  if (!line)
    return;
  p = py_strip(line);
  if (*p == '|')
    ++p;
  n = strlen(p);
  if (n && p[n - 1] == '|')
    p[n - 1] = 0;
  sb_init(&cell);
  cell.limit = 1u << 20;
  for (cur = p; *cur; ++cur) {
    if (esc) {
      sb_addc(&cell, *cur);
      esc = 0;
    } else if (*cur == '\\')
      esc = 1;
    else if (*cur == '|') {
      char *t = md_dup(sb_str(&cell), cell.n);
      if (t) {
        sl_push(cells, py_strip(t));
        free(t);
      }
      sb_clear(&cell);
    } else
      sb_addc(&cell, *cur);
  }
  {
    char *t = md_dup(sb_str(&cell), cell.n);
    if (t) {
      sl_push(cells, py_strip(t));
      free(t);
    }
  }
  sb_free(&cell);
  free(line);
}
static char md_align_of(const char *cell_in) {
  char buf[256], *c;
  size_t n;
  snprintf(buf, sizeof(buf), "%s", cell_in);
  c = py_strip(buf);
  n = strlen(c);
  if (n && c[0] == ':' && c[n - 1] == ':')
    return 'c';
  if (n && c[n - 1] == ':')
    return 'r';
  return 'l';
}
/* text[:cps] by code points */
static size_t md_cp_prefix_bytes(const char *s, size_t cps) { return u8_prefix(s, cps); }
static char *md_truncate_cell(const char *text, int width) {
  size_t cps, tp, bytes;
  sbuf o;
  int fg = 0, bg = 0;
  char active[8] = "";
  size_t i;
  if (md_visible_width(text) <= width)
    return md_dup(text, strlen(text));
  cps = u8_count(text, strlen(text));
  tp = cps;
  while (tp > 0) {
    char *t;
    int w;
    bytes = md_cp_prefix_bytes(text, tp);
    t = md_dup(text, bytes);
    w = t ? md_visible_width(t) : 0;
    free(t);
    if (w >= width)
      --tp;
    else
      break;
  }
  bytes = md_cp_prefix_bytes(text, tp);
  sb_init(&o);
  o.limit = 1u << 20;
  sb_add(&o, text, bytes);
  /* find which tags are left open in the truncated text */
  for (i = 0; i < bytes;) {
    if (text[i] == '`' && i + 1 < bytes) {
      char t = text[i + 1];
      if (strchr("!*_=", t) && t) {
        char *at = strchr(active, t);
        if (at)
          memmove(at, at + 1, strlen(at));
        else if (strlen(active) < sizeof(active) - 1)
          active[strlen(active)] = t, active[strlen(active) + 1] = 0;
        i += 2;
        continue;
      } else if (t == 'f') {
        fg = 0;
        i += 2;
        continue;
      } else if (t == 'b') {
        bg = 0;
        i += 2;
        continue;
      } else if (t == 'F' || t == 'B') {
        if (t == 'F')
          fg = 1;
        else
          bg = 1;
        i += (i + 2 < bytes && text[i + 2] == 'T') ? 8 : 5;
        continue;
      }
    }
    ++i;
  }
  if (fg)
    sb_adds(&o, "`f");
  if (bg)
    sb_adds(&o, "`b");
  for (i = 0; active[i]; ++i) {
    sb_addc(&o, '`');
    sb_addc(&o, active[i]);
  }
  sb_adds(&o, "\xe2\x80\xa6");
  return o.p;
}
static void md_pad_cell(const char *text_in, int width, char align, sbuf *out) {
  char *text = md_truncate_cell(text_in, width);
  int w, pad, left, right;
  if (!text)
    return;
  w = md_visible_width(text);
  pad = width - w;
  if (pad < 0)
    pad = 0;
  if (align == 'r') {
    left = pad;
    right = 0;
  } else if (align == 'c') {
    left = pad / 2;
    right = pad - left;
  } else {
    left = 0;
    right = pad;
  }
  while (left-- > 0)
    sb_addc(out, ' ');
  sb_adds(out, text);
  while (right-- > 0)
    sb_addc(out, ' ');
  free(text);
}
static void md_repeat(sbuf *o, const char *s, int n) {
  while (n-- > 0)
    sb_adds(o, s);
}
static void md_format_table(const md_conv *c, char **rows, size_t nrows, strlist *result) {
  strlist header = {0}, aligns_raw = {0};
  strlist *data = NULL;
  char *aligns = NULL;
  int *widths = NULL;
  size_t ncols, i, k, ndata = nrows - 2;
  sbuf line;
  md_parse_row(rows[0], &header);
  md_parse_row(rows[1], &aligns_raw);
  ncols = header.n;
  aligns = malloc(ncols + 1);
  widths = calloc(ncols + 1, sizeof(int));
  data = calloc(ndata + 1, sizeof(strlist));
  if (!aligns || !widths || !data || !ncols)
    goto out;
  for (i = 0; i < ncols; ++i)
    aligns[i] = i < aligns_raw.n ? md_align_of(aligns_raw.v[i]) : 'l';
  for (i = 0; i < ndata; ++i) {
    md_parse_row(rows[i + 2], &data[i]);
    while (data[i].n < ncols)
      sl_push(&data[i], "");
    while (data[i].n > ncols) {
      free(data[i].v[--data[i].n]);
    }
  }
  for (k = 0; k <= ndata; ++k) {
    strlist *row = k == 0 ? &header : &data[k - 1];
    for (i = 0; i < ncols; ++i) {
      sbuf f;
      int w;
      sb_init(&f);
      f.limit = 4u << 20;
      md_format_inline(c, row->v[i], &f);
      w = md_visible_width(sb_str(&f));
      if (w > widths[i])
        widths[i] = w;
      sb_free(&f);
    }
  }
  for (i = 0; i < ncols; ++i)
    if (widths[i] < MD_TABLE_MIN_COL)
      widths[i] = MD_TABLE_MIN_COL;
  {
    long total = (long)(ncols * 3 + 1);
    for (i = 0; i < ncols; ++i)
      total += widths[i];
    if (total > c->max_width) {
      long excess = total - c->max_width;
      size_t *idx = malloc(ncols * sizeof(size_t));
      if (idx) {
        size_t a, b;
        for (i = 0; i < ncols; ++i)
          idx[i] = i;
        /* stable sort by width, widest first */
        for (a = 1; a < ncols; ++a) {
          size_t t = idx[a];
          b = a;
          while (b > 0 && widths[idx[b - 1]] < widths[t]) {
            idx[b] = idx[b - 1];
            --b;
          }
          idx[b] = t;
        }
        for (a = 0; a < ncols && excess > 0; ++a) {
          long red = widths[idx[a]] - MD_TABLE_MIN_COL;
          if (excess < red)
            red = excess;
          widths[idx[a]] -= (int)red;
          excess -= red;
        }
        free(idx);
      }
    }
  }
  sl_push(result, "`c");
  sb_init(&line);
  line.limit = 4u << 20;
  /* top border */
  sb_adds(&line, "\xe2\x94\x8c");
  for (i = 0; i < ncols; ++i) {
    md_repeat(&line, "\xe2\x94\x80", widths[i] + 2);
    sb_adds(&line, i + 1 < ncols ? "\xe2\x94\xac" : "\xe2\x94\x90");
  }
  sl_push(result, sb_str(&line));
  /* header */
  sb_clear(&line);
  sb_adds(&line, "\xe2\x94\x82");
  for (i = 0; i < ncols; ++i) {
    sbuf f;
    sb_init(&f);
    f.limit = 4u << 20;
    md_format_inline(c, header.v[i], &f);
    sb_addc(&line, ' ');
    md_pad_cell(sb_str(&f), widths[i], 'l', &line);
    sb_adds(&line, " \xe2\x94\x82");
    sb_free(&f);
  }
  {
    sbuf esc;
    sb_init(&esc);
    esc.limit = 4u << 20;
    md_escape_literals(&esc, sb_str(&line), line.n);
    sl_push(result, sb_str(&esc));
    sb_free(&esc);
  }
  /* separator */
  sb_clear(&line);
  sb_adds(&line, "\xe2\x94\x9c");
  for (i = 0; i < ncols; ++i) {
    md_repeat(&line, "\xe2\x94\x80", widths[i] + 2);
    sb_adds(&line, i + 1 < ncols ? "\xe2\x94\xbc" : "\xe2\x94\xa4");
  }
  sl_push(result, sb_str(&line));
  for (k = 0; k < ndata; ++k) {
    sb_clear(&line);
    sb_adds(&line, "\xe2\x94\x82");
    for (i = 0; i < ncols; ++i) {
      sbuf f;
      sb_init(&f);
      f.limit = 4u << 20;
      md_format_inline(c, data[k].v[i], &f);
      sb_addc(&line, ' ');
      md_pad_cell(sb_str(&f), widths[i], aligns[i], &line);
      sb_adds(&line, " \xe2\x94\x82");
      sb_free(&f);
    }
    sl_push(result, sb_str(&line));
  }
  sb_clear(&line);
  sb_adds(&line, "\xe2\x94\x94");
  for (i = 0; i < ncols; ++i) {
    md_repeat(&line, "\xe2\x94\x80", widths[i] + 2);
    sb_adds(&line, i + 1 < ncols ? "\xe2\x94\xb4" : "\xe2\x94\x98");
  }
  sl_push(result, sb_str(&line));
  sl_push(result, "`a");
  sb_free(&line);
out:
  sl_free(&header);
  sl_free(&aligns_raw);
  if (data)
    for (i = 0; i < ndata; ++i)
      sl_free(&data[i]);
  free(data);
  free(aligns);
  free(widths);
}

/* ---- wrapping (block quotes) -------------------------------------------- */
static void md_wrap_text(const char *text, int width, strlist *lines) {
  sbuf cur;
  int cur_w = 0;
  const char *p = text;
  if (!*text) {
    sl_push(lines, "");
    return;
  }
  sb_init(&cur);
  cur.limit = 4u << 20;
  while (*p || 0) {
    const char *e = strchr(p, ' ');
    size_t wl = e ? (size_t)(e - p) : strlen(p);
    char *word;
    int ww;
    if (!wl) {
      if (!e)
        break;
      p = e + 1;
      continue;
    }
    word = md_dup(p, wl);
    if (!word)
      break;
    ww = md_visible_width(word);
    if (ww > width) {
      const char *rem = word;
      if (cur.n) {
        sl_push(lines, sb_str(&cur));
        sb_clear(&cur);
        cur_w = 0;
      }
      while (*rem) {
        size_t cps = u8_count(rem, strlen(rem)), lo = 1, hi = cps, fit = 0;
        while (lo <= hi) {
          size_t mid = (lo + hi) / 2, b = md_cp_prefix_bytes(rem, mid);
          char *t = md_dup(rem, b);
          int w = t ? md_visible_width(t) : 1 << 30;
          free(t);
          if (w <= width) {
            fit = mid;
            lo = mid + 1;
          } else
            hi = mid - 1;
        }
        if (!fit)
          fit = 1;
        {
          size_t b = md_cp_prefix_bytes(rem, fit);
          sl_push_n(lines, rem, b);
          rem += b;
        }
      }
    } else {
      int space = cur.n ? 1 : 0;
      if (cur_w + space + ww <= width) {
        if (cur.n) {
          sb_addc(&cur, ' ');
          sb_adds(&cur, word);
          cur_w += space + ww;
        } else {
          sb_adds(&cur, word);
          cur_w = ww;
        }
      } else {
        sl_push(lines, sb_str(&cur));
        sb_clear(&cur);
        sb_adds(&cur, word);
        cur_w = ww;
      }
    }
    free(word);
    if (!e)
      break;
    p = e + 1;
  }
  if (cur.n)
    sl_push(lines, sb_str(&cur));
  if (!lines->n)
    sl_push(lines, "");
  sb_free(&cur);
}

/* ---- the block converter ------------------------------------------------ */
static void md_flush_quote(const md_conv *c, strlist *quote, strlist *result) {
  sbuf para, fmt;
  strlist wrapped = {0};
  size_t i;
  int eff;
  if (!quote->n)
    return;
  sb_init(&para);
  sb_init(&fmt);
  para.limit = fmt.limit = 4u << 20;
  for (i = 0; i < quote->n; ++i) {
    if (i)
      sb_addc(&para, ' ');
    sb_adds(&para, quote->v[i]);
  }
  md_format_inline(c, sb_str(&para), &fmt);
  eff = c->max_width - 3;
  if (eff < 1)
    eff = 1;
  md_wrap_text(sb_str(&fmt), eff, &wrapped);
  for (i = 0; i < wrapped.n; ++i) {
    sbuf l;
    sb_init(&l);
    sb_adds(&l, " \xe2\x94\x82 ");
    sb_adds(&l, wrapped.v[i]);
    sl_push(result, sb_str(&l));
    sb_free(&l);
  }
  sl_free(&wrapped);
  sb_free(&para);
  sb_free(&fmt);
  sl_clear(quote);
}
static void md_flush_table(const md_conv *c, strlist *table, strlist *result) {
  size_t i;
  if (!table->n)
    return;
  if (table->n >= 2 && md_is_table_sep(table->v[1]))
    md_format_table(c, table->v, table->n, result);
  else
    for (i = 0; i < table->n; ++i) {
      sbuf l;
      sb_init(&l);
      l.limit = 4u << 20;
      md_format_line(c, table->v[i], &l);
      sl_push(result, sb_str(&l));
      sb_free(&l);
    }
  sl_clear(table);
}
static void md_flush_code(strlist *code, const char *lang, strlist *result) {
  sbuf content, hl;
  size_t i;
  if (!code->n)
    return;
  sb_init(&content);
  sb_init(&hl);
  content.limit = hl.limit = 4u << 20;
  for (i = 0; i < code->n; ++i) {
    if (i)
      sb_addc(&content, '\n');
    sb_adds(&content, code->v[i]);
  }
  if (lang && *lang) {
    if (!strcasecmp(lang, "rawmu"))
      sl_push(result, sb_str(&content));
    else {
      hl_highlight(&hl, sb_str(&content), NULL, lang);
      sl_push(result, MD_CODE_BG MD_CODE_FG);
      sl_push(result, sb_str(&hl));
      sl_push(result, MD_CODE_RESET);
    }
  } else {
    sbuf esc;
    sb_init(&esc);
    esc.limit = 4u << 20;
    md_escape_literals(&esc, sb_str(&content), content.n);
    sl_push(result, MD_CODE_BG MD_CODE_FG);
    sl_push(result, "`=");
    sl_push(result, sb_str(&esc));
    sl_push(result, "`=");
    sl_push(result, MD_CODE_RESET);
    sb_free(&esc);
  }
  sb_free(&content);
  sb_free(&hl);
  sl_clear(code);
}
/* ^(\s*)```(.*)$ : the language hint when the line is a fence */
static int md_is_fence(const char *l, const char **lang) {
  size_t i = 0;
  while (md_is_space(l[i]))
    ++i;
  if (strncmp(l + i, "```", 3))
    return 0;
  *lang = l + i + 3;
  return 1;
}
/* MarkdownToMicron.format_block */
static void md_format_block(const md_conv *c, const char *text, sbuf *out) {
  strlist result = {0}, quote = {0}, table = {0}, code = {0};
  char *copy = md_dup(text, strlen(text)), *line, *next;
  int in_code = 0, in_table = 0, in_quote = 0;
  char lang[64] = "";
  size_t i;
  if (!copy)
    return;
  for (line = copy; line; line = next) {
    const char *hint;
    char *nl = strchr(line, '\n');
    if (nl) {
      *nl = 0;
      next = nl + 1;
    } else
      next = NULL;
    if (md_is_fence(line, &hint)) {
      md_flush_quote(c, &quote, &result);
      in_quote = 0;
      md_flush_table(c, &table, &result);
      in_table = 0;
      if (!in_code) {
        char *h = md_dup(hint, strlen(hint));
        in_code = 1;
        lang[0] = 0;
        if (h) {
          snprintf(lang, sizeof(lang), "%s", py_strip(h));
          free(h);
        }
        sl_clear(&code);
      } else {
        md_flush_code(&code, lang, &result);
        in_code = 0;
        lang[0] = 0;
      }
      continue;
    }
    if (in_code) {
      sl_push(&code, line);
      continue;
    }
    if (line[0] == '>') {
      const char *q = line + 1;
      if (md_is_space(*q))
        ++q;
      if (!in_quote) {
        md_flush_table(c, &table, &result);
        in_table = 0;
        in_quote = 1;
        sl_clear(&quote);
      }
      sl_push(&quote, q);
      continue;
    }
    if (in_quote) {
      char *t = md_dup(line, strlen(line));
      int blank = t && !*py_strip(t);
      free(t);
      md_flush_quote(c, &quote, &result);
      in_quote = 0;
      if (!blank) {
        if (md_is_table_row(line)) {
          in_table = 1;
          sl_clear(&table);
          sl_push(&table, line);
        } else {
          sbuf l;
          sb_init(&l);
          l.limit = 4u << 20;
          md_format_line(c, line, &l);
          sl_push(&result, sb_str(&l));
          sb_free(&l);
        }
      } else
        sl_push(&result, "");
      continue;
    }
    if (md_is_table_row(line)) {
      if (!in_table) {
        in_table = 1;
        sl_clear(&table);
      }
      sl_push(&table, line);
    } else {
      sbuf l;
      if (in_table) {
        md_flush_table(c, &table, &result);
        in_table = 0;
      }
      sb_init(&l);
      l.limit = 4u << 20;
      md_format_line(c, line, &l);
      sl_push(&result, sb_str(&l));
      sb_free(&l);
    }
  }
  if (in_quote)
    md_flush_quote(c, &quote, &result);
  if (in_table)
    md_flush_table(c, &table, &result);
  if (in_code)
    md_flush_code(&code, lang, &result);
  for (i = 0; i < result.n; ++i) {
    if (i)
      sb_addc(out, '\n');
    sb_adds(out, result.v[i]);
  }
  sl_free(&result);
  sl_free(&quote);
  sl_free(&table);
  sl_free(&code);
  free(copy);
}

#endif
