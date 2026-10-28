/* Text helpers for the page server of reticulum-c-git: a bounded growing string
 * buffer, UTF-8 code point handling, and the percent coding the reference uses
 * for micron link fields (urllib.parse quote_plus / unquote_plus). Included by
 * reticulum_git.c after rngit_common.h. */
#ifndef RETICULUM_C_RNGIT_TEXT_H
#define RETICULUM_C_RNGIT_TEXT_H
#include <stdarg.h>
#include <strings.h>

/* ---- sbuf: a NUL terminated string that grows up to a hard limit. Once the
 * limit is hit further appends are dropped and `over` is set, so a hostile or
 * huge repository cannot make a page use unbounded memory. ---------------- */
#define SBUF_LIMIT (3u << 20)
typedef struct sbuf {
  char *p;
  size_t n, cap, limit;
  int over;
} sbuf;
static void sb_init(sbuf *b) {
  memset(b, 0, sizeof(*b));
  b->limit = SBUF_LIMIT;
}
static void sb_free(sbuf *b) {
  free(b->p);
  memset(b, 0, sizeof(*b));
}
static int sb_reserve(sbuf *b, size_t extra) {
  size_t need = b->n + extra + 1;
  if (b->over)
    return 0;
  if (!b->limit)
    b->limit = SBUF_LIMIT;
  if (need > b->limit + 1) {
    b->over = 1;
    return 0;
  }
  if (need > b->cap) {
    size_t cap = b->cap ? b->cap : 256;
    char *np;
    while (cap < need)
      cap *= 2;
    np = realloc(b->p, cap);
    if (!np) {
      b->over = 1;
      return 0;
    }
    b->p = np;
    b->cap = cap;
  }
  return 1;
}
static void sb_add(sbuf *b, const char *s, size_t n) {
  if (!n || !sb_reserve(b, n))
    return;
  memcpy(b->p + b->n, s, n);
  b->n += n;
  b->p[b->n] = 0;
}
static void sb_adds(sbuf *b, const char *s) { sb_add(b, s, strlen(s)); }
static void sb_addc(sbuf *b, char c) { sb_add(b, &c, 1); }
static void sb_addf(sbuf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void sb_addf(sbuf *b, const char *fmt, ...) {
  char tmp[1024];
  va_list ap, ap2;
  int n;
  va_start(ap, fmt);
  va_copy(ap2, ap);
  n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
  va_end(ap);
  if (n >= 0 && (size_t)n < sizeof(tmp))
    sb_add(b, tmp, (size_t)n);
  else if (n >= 0) {
    char *big = malloc((size_t)n + 1);
    if (big) {
      vsnprintf(big, (size_t)n + 1, fmt, ap2);
      sb_add(b, big, (size_t)n);
      free(big);
    } else
      b->over = 1;
  }
  va_end(ap2);
}
static const char *sb_str(const sbuf *b) { return b->p ? b->p : ""; }
static void sb_clear(sbuf *b) {
  b->n = 0;
  if (b->p)
    b->p[0] = 0;
}

/* replace every occurrence of `what` in `s` with `with` (str.replace) */
static char *str_replace(const char *s, const char *what, const char *with) {
  sbuf o;
  size_t wl = strlen(what);
  const char *at;
  sb_init(&o);
  o.limit = 16u << 20;
  while (wl && (at = strstr(s, what)) != NULL) {
    sb_add(&o, s, (size_t)(at - s));
    sb_adds(&o, with);
    s = at + wl;
  }
  sb_adds(&o, s);
  if (!o.p) {
    o.p = malloc(1);
    if (o.p)
      o.p[0] = 0;
  }
  return o.p;
}

/* ---- UTF-8 -------------------------------------------------------------- */
static size_t u8_len(unsigned char c) {
  return c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 1;
}
/* number of code points in the first n bytes */
static size_t u8_count(const char *s, size_t n) {
  size_t i = 0, c = 0;
  while (i < n) {
    i += u8_len((unsigned char)s[i]);
    ++c;
  }
  return c;
}
/* byte length of the first `cps` code points of s (NUL terminated) */
static size_t u8_prefix(const char *s, size_t cps) {
  size_t i = 0;
  while (cps && s[i]) {
    size_t l = u8_len((unsigned char)s[i]), k;
    for (k = 1; k < l; ++k)
      if (!s[i + k]) {
        l = k;
        break;
      }
    i += l;
    --cps;
  }
  return i;
}
/* Decodes one code point at s (NUL terminated string); *len = bytes used. */
static unsigned u8_decode(const char *s, size_t *len) {
  unsigned char c = (unsigned char)s[0];
  size_t l = u8_len(c), k;
  unsigned cp;
  if (l == 1) {
    *len = 1;
    return c;
  }
  cp = l == 2 ? c & 0x1fu : l == 3 ? c & 0x0fu : c & 7u;
  for (k = 1; k < l; ++k) {
    if (((unsigned char)s[k] & 0xc0) != 0x80) {
      *len = 1;
      return c;
    }
    cp = cp << 6 | ((unsigned char)s[k] & 0x3fu);
  }
  *len = l;
  return cp;
}
/* The terminal cell width of one code point, as the wcwidth module reports it
 * for the common ranges: combining marks 0, East Asian wide and emoji 2. The
 * reference falls back to a plain code point count when wcwidth is not
 * installed, which is the behaviour when RNGIT_NO_WCWIDTH is set. */
static int u8_cell_width(unsigned cp) {
  if (cp == 0)
    return 0;
  if (cp < 32 || (cp >= 0x7f && cp < 0xa0))
    return -1;
  if ((cp >= 0x300 && cp <= 0x36f) || (cp >= 0x200b && cp <= 0x200f) || (cp >= 0xfe00 && cp <= 0xfe0f) ||
      (cp >= 0x20d0 && cp <= 0x20ff))
    return 0;
  if ((cp >= 0x1100 && cp <= 0x115f) || (cp >= 0x2e80 && cp <= 0xa4cf && cp != 0x303f) ||
      (cp >= 0xac00 && cp <= 0xd7a3) || (cp >= 0xf900 && cp <= 0xfaff) || (cp >= 0xfe30 && cp <= 0xfe6f) ||
      (cp >= 0xff00 && cp <= 0xff60) || (cp >= 0xffe0 && cp <= 0xffe6) || (cp >= 0x1f300 && cp <= 0x1f64f) ||
      (cp >= 0x1f900 && cp <= 0x1f9ff) || (cp >= 0x20000 && cp <= 0x3fffd))
    return 2;
  return 1;
}

/* ---- percent coding ----------------------------------------------------- */
/* quote_plus of the UTF-8 bytes: unreserved characters stay, space is "+". */
static void url_quote_plus(sbuf *o, const char *s) {
  static const char hexd[] = "0123456789ABCDEF";
  for (; *s; ++s) {
    unsigned char c = (unsigned char)*s;
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' ||
        c == '-' || c == '~')
      sb_addc(o, (char)c);
    else if (c == ' ')
      sb_addc(o, '+');
    else {
      sb_addc(o, '%');
      sb_addc(o, hexd[c >> 4]);
      sb_addc(o, hexd[c & 15]);
    }
  }
}
static int hexval(char c) {
  return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}
/* unquote_plus in place: "+" becomes a space, %XX the byte. */
static void url_unquote_plus(char *s) {
  char *w = s;
  for (; *s; ++s) {
    if (*s == '+')
      *w++ = ' ';
    else if (*s == '%' && hexval(s[1]) >= 0 && hexval(s[2]) >= 0) {
      *w++ = (char)(hexval(s[1]) << 4 | hexval(s[2]));
      s += 2;
    } else
      *w++ = *s;
  }
  *w = 0;
}

/* ---- small string helpers ---------------------------------------------- */
static int starts_with(const char *s, const char *prefix) { return !strncmp(s, prefix, strlen(prefix)); }
static int is_space_c(char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}
/* Python str.strip() on ASCII whitespace; returns the start, NUL-terminates. */
static char *py_strip(char *s) {
  char *e;
  while (is_space_c(*s))
    ++s;
  e = s + strlen(s);
  while (e > s && is_space_c(e[-1]))
    *--e = 0;
  return s;
}
static void py_rstrip(char *s) {
  char *e = s + strlen(s);
  while (e > s && is_space_c(e[-1]))
    *--e = 0;
}

#endif
