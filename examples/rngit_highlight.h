/* Syntax highlighting for the page server of reticulum-c-git (included by
 * reticulum_git.c), the counterpart of the reference's highlight.py.
 *
 * The reference feeds pygments tokens to a MicronFormatter. pygments is a
 * Python module and cannot be used here, so this file carries a compact
 * tokeniser of its own and the formatter is ported statement for statement:
 * the same theme colours, the same `FT<rrggbb> ... `f runs, the same escaping,
 * the same trailing newline handling. What differs is token CLASSIFICATION:
 * pygments knows hundreds of lexers and tells, for example, a function name from
 * a plain name by deeper grammar than a scanner of a few hundred lines can.
 * Here a language is chosen by file extension (or the language hint of a
 * markdown fence) from: C/C++, Python, JavaScript/TypeScript, shell, JSON,
 * YAML, TOML/INI, Markdown, Rust, Go, Java, HTML/XML and CSS; anything else is
 * shown as plain text, as the reference does without a lexer.
 *
 * `[pages] highlight_syntax = no` (or RNGIT_HIGHLIGHT=plain in the
 * environment) selects the behaviour of the reference when pygments is not
 * installed: a literal block of the text. */
#ifndef RETICULUM_C_RNGIT_HIGHLIGHT_H
#define RETICULUM_C_RNGIT_HIGHLIGHT_H

enum hl_tok {
  T_TEXT, T_WS, T_KW, T_KWT, T_NAME, T_FUNC, T_BUILTIN, T_CLASS, T_DECOR, T_NS, T_ATTR, T_TAG, T_PSEUDO,
  T_STR, T_DOC, T_ESC, T_INTERP, T_NUM, T_OP, T_DOT, T_PUNCT, T_COMMENT, T_PREPROC, T_HEAD, T_INS, T_DEL,
  T_TOKENS
};
/* the theme of highlight.py */
static const char *hl_color(int t) {
  switch (t) {
  case T_KW: case T_PSEUDO: case T_OP: case T_DOT: case T_PREPROC: case T_TAG: return "ff7b72";
  case T_KWT: case T_BUILTIN: return "ffa657";
  case T_NAME: case T_ATTR: return "e6edf3";
  case T_FUNC: return "d2a8ff";
  case T_CLASS: return "56d364";
  case T_DECOR: return "f0883e";
  case T_NS: case T_INS: return "7ee787";
  case T_STR: return "a5d6ff";
  case T_DOC: case T_COMMENT: return "8b949e";
  case T_ESC: return "ffea00";
  case T_INTERP: return "ffd700";
  case T_NUM: return "79c0ff";
  case T_PUNCT: return "b4b4b4";
  case T_HEAD: return "c9d1d9";
  case T_DEL: return "f85149";
  default: return NULL; /* text, whitespace */
  }
}
static int hl_is_name(int t) {
  return t == T_NAME || t == T_FUNC || t == T_BUILTIN || t == T_CLASS || t == T_DECOR || t == T_NS ||
         t == T_ATTR || t == T_TAG || t == T_PSEUDO;
}

/* ---- the MicronFormatter ------------------------------------------------- */
typedef struct hl_fmt {
  sbuf *out;
  int prev_dot, last_break;
} hl_fmt;
static void hl_escape_value(sbuf *o, const char *s, size_t n) {
  size_t i;
  for (i = 0; i < n; ++i) {
    if (s[i] == '\\' || s[i] == '`')
      sb_addc(o, '\\');
    sb_addc(o, s[i]);
  }
}
static int hl_esc_start(char c) { return c == '-' || c == '>' || c == '<'; }
static void hl_emit(hl_fmt *f, int t, const char *v, size_t n) {
  sbuf *o = f->out;
  int ends_break;
  if (!n)
    return;
  ends_break = v[n - 1] == '\n';
  if (f->prev_dot && hl_is_name(t)) {
    sb_adds(o, "`FT");
    sb_adds(o, "d2a8ff");
    hl_escape_value(o, v, n);
    sb_adds(o, "`f");
  } else {
    const char *color = hl_color(t);
    sbuf esc;
    char *e;
    size_t en;
    sb_init(&esc);
    esc.limit = n * 2 + 16;
    hl_escape_value(&esc, v, n);
    e = esc.p ? esc.p : (char *)"";
    en = esc.n;
    if (color) {
      int ilb = 0, tlb = 0;
      if (en && e[0] == '\n') {
        ilb = 1;
        ++e;
        --en;
      }
      if (en && e[en - 1] == '\n') {
        tlb = 1;
        --en;
      }
      if (ilb)
        sb_addc(o, '\n');
      if (en) {
        sb_adds(o, "`FT");
        sb_adds(o, color);
        sb_add(o, e, en);
        sb_adds(o, "`f");
      }
      if (tlb)
        sb_addc(o, '\n');
    } else {
      if (memchr(e, '\n', en)) {
        /* splitlines: more than one line gets each line checked */
        size_t lines = 0, i, start = 0;
        for (i = 0; i < en; ++i)
          if (e[i] == '\n')
            ++lines;
        if (en && e[en - 1] != '\n')
          ++lines;
        if (lines > 1) {
          int first = 1;
          for (i = 0; i <= en; ++i)
            if (i == en || e[i] == '\n') {
              size_t len = i - start;
              if (i == en && len == 0)
                break;
              if (!first)
                sb_addc(o, '\n');
              if (len && hl_esc_start(e[start]))
                sb_addc(o, '\\');
              sb_add(o, e + start, len);
              first = 0;
              start = i + 1;
            }
          if (e[en - 1] == '\n')
            sb_addc(o, '\n');
        } else
          sb_add(o, e, en);
      } else {
        if (f->last_break && en && hl_esc_start(e[0]))
          sb_addc(o, '\\');
        sb_add(o, e, en);
      }
    }
    sb_free(&esc);
  }
  f->prev_dot = t == T_DOT;
  f->last_break = ends_break;
}

/* ---- languages ----------------------------------------------------------- */
enum {
  HL_C_COMMENT = 1,   /* // and the block comments */
  HL_HASH_COMMENT = 2,
  HL_PREPROC = 4,     /* #include / #define at line start */
  HL_SQ_STR = 8,      /* 'x' is a string (otherwise a char literal) */
  HL_BACKTICK_STR = 16,
  HL_TRIPLE = 32,     /* triple quoted strings, docstrings */
  HL_AT_DECOR = 64,
  HL_DOLLAR_VAR = 128,
  HL_FSTRING = 256,
  HL_DOT_OP = 512,    /* "." is an operator token (attribute colouring) */
  HL_DASH_COMMENT = 1024
};
typedef struct hl_lang {
  const char *name;
  unsigned flags;
  const char *kw, *kwt, *kwc, *opw, *builtin, *pseudo, *defw, *classw;
} hl_lang;
static const hl_lang hl_langs[] = {
    {"c", HL_C_COMMENT | HL_PREPROC,
     "auto break case const continue default do else enum extern for goto if inline register restrict return "
     "sizeof static struct switch typedef union volatile while _Alignas _Atomic _Generic _Noreturn "
     "_Static_assert _Thread_local",
     "int long float double char short signed unsigned void bool size_t ssize_t uint8_t uint16_t uint32_t "
     "uint64_t int8_t int16_t int32_t int64_t FILE _Bool _Complex",
     "NULL true false", "", "printf malloc free memcpy memset strlen", "", "", "struct union enum"},
    {"cpp", HL_C_COMMENT | HL_PREPROC,
     "alignas alignof auto break case catch class const constexpr const_cast continue default delete do "
     "dynamic_cast else enum explicit export extern for friend goto if inline mutable namespace new noexcept "
     "operator private protected public register reinterpret_cast return sizeof static static_assert "
     "static_cast struct switch template this throw try typedef typeid typename union using virtual "
     "volatile while override final",
     "int long float double char short signed unsigned void bool wchar_t size_t string vector auto",
     "nullptr NULL true false", "and or not xor", "std cout cin endl", "", "", "class struct union enum"},
    {"python", HL_HASH_COMMENT | HL_SQ_STR | HL_TRIPLE | HL_AT_DECOR | HL_FSTRING | HL_DOT_OP,
     "assert async await break class continue def del elif else except finally for global if lambda nonlocal "
     "pass raise return try while with yield import from as",
     "", "True False None", "and or not in is",
     "abs all any bin bool bytes callable chr dict dir enumerate eval exec filter float format frozenset "
     "getattr hasattr hash hex id input int isinstance issubclass iter len list map max min next object oct "
     "open ord pow print property range repr reversed round set setattr slice sorted staticmethod str sum "
     "super tuple type vars zip Exception ValueError TypeError KeyError OSError",
     "self cls", "def", "class"},
    {"javascript", HL_C_COMMENT | HL_SQ_STR | HL_BACKTICK_STR | HL_DOT_OP,
     "async await break case catch class const continue debugger default delete do else export extends "
     "finally for function if import in instanceof let new of return static super switch this throw try "
     "typeof var void while with yield from as interface type enum implements public private protected "
     "readonly declare namespace abstract",
     "number string boolean any never unknown", "true false null undefined NaN Infinity", "",
     "console document window Math JSON Object Array Promise Map Set parseInt parseFloat require module "
     "exports", "", "function", "class interface"},
    {"shell", HL_HASH_COMMENT | HL_SQ_STR | HL_DOLLAR_VAR | HL_BACKTICK_STR,
     "if then else elif fi for while until do done case esac in function select time", "", "", "",
     "echo cd ls pwd export unset read printf test set shift exit return source alias eval exec trap kill "
     "wait cat grep sed awk cp mv rm mkdir chmod chown find xargs sort head tail wc", "", "function", ""},
    {"rust", HL_C_COMMENT | HL_DOT_OP,
     "as async await break const continue crate dyn else enum extern fn for if impl in let loop match mod "
     "move mut pub ref return self Self static struct super trait type unsafe use where while",
     "i8 i16 i32 i64 i128 isize u8 u16 u32 u64 u128 usize f32 f64 bool char str String Vec Option Result Box",
     "true false None Some Ok Err", "", "println print format vec panic assert assert_eq", "", "fn",
     "struct enum trait type"},
    {"go", HL_C_COMMENT | HL_BACKTICK_STR | HL_DOT_OP,
     "break case chan const continue default defer else fallthrough for func go goto if import interface map "
     "package range return select struct switch type var",
     "bool byte complex64 complex128 error float32 float64 int int8 int16 int32 int64 rune string uint uint8 "
     "uint16 uint32 uint64 uintptr", "true false nil iota", "",
     "append cap close copy delete len make new panic print println recover", "", "func", "struct interface type"},
    {"java", HL_C_COMMENT | HL_AT_DECOR | HL_DOT_OP,
     "abstract assert break case catch class const continue default do else enum extends final finally for "
     "goto if implements import instanceof interface native new package private protected public return "
     "static strictfp super switch synchronized this throw throws transient try volatile while var record",
     "boolean byte char double float int long short void String", "true false null", "", "System", "", "",
     "class interface enum record"},
    {NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL}};

static int hl_word_in(const char *list, const char *w, size_t n) {
  const char *p = list;
  while (list && *p) {
    const char *e = strchr(p, ' ');
    size_t l = e ? (size_t)(e - p) : strlen(p);
    if (l == n && !strncmp(p, w, n))
      return 1;
    if (!e)
      break;
    p = e + 1;
  }
  return 0;
}
static int hl_ident_start(unsigned char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c >= 0x80; }
static int hl_ident_char(unsigned char c) { return hl_ident_start(c) || (c >= '0' && c <= '9'); }

/* strings: body up to the closing quote, escapes split out */
static size_t hl_string(hl_fmt *f, const char *s, size_t n, size_t i, char q, int triple, int fstr, int doc) {
  size_t start = i, j = i + (triple ? 3 : 1);
  int base = doc ? T_DOC : T_STR;
  size_t seg = start;
  while (j < n) {
    if (s[j] == '\\' && j + 1 < n && !doc) {
      size_t el = 2;
      if (j > seg)
        hl_emit(f, base, s + seg, j - seg);
      if (s[j + 1] == 'x' && j + 3 < n)
        el = 4;
      else if (s[j + 1] == 'u' && j + 5 < n)
        el = 6;
      hl_emit(f, T_ESC, s + j, el > n - j ? n - j : el);
      j += el > n - j ? n - j : el;
      seg = j;
      continue;
    }
    if (s[j] == '\\' && j + 1 < n) {
      j += 2;
      continue;
    }
    if (fstr && s[j] == '{' && j + 1 < n && s[j + 1] != '{') {
      size_t k = j + 1;
      while (k < n && s[k] != '}' && s[k] != '\n')
        ++k;
      if (k < n && s[k] == '}') {
        if (j > seg)
          hl_emit(f, base, s + seg, j - seg);
        hl_emit(f, T_INTERP, s + j, k + 1 - j);
        j = k + 1;
        seg = j;
        continue;
      }
    }
    if (triple && s[j] == q && j + 2 < n && s[j + 1] == q && s[j + 2] == q) {
      j += 3;
      break;
    }
    if (!triple && s[j] == q) {
      ++j;
      break;
    }
    if (!triple && s[j] == '\n')
      break; /* unterminated: stop at the line end */
    ++j;
  }
  if (j > n)
    j = n;
  if (j > seg)
    hl_emit(f, base, s + seg, j - seg);
  return j;
}

static void hl_scan_code(hl_fmt *f, const hl_lang *L, const char *s, size_t n) {
  size_t i = 0;
  int expect_func = 0, expect_class = 0, line_start = 1;
  while (i < n) {
    unsigned char c = (unsigned char)s[i];
    size_t j;
    if (c == '\n') {
      hl_emit(f, T_WS, "\n", 1);
      ++i;
      line_start = 1;
      continue;
    }
    if (c == ' ' || c == '\t' || c == '\r' || c == '\f') {
      for (j = i; j < n && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r' || s[j] == '\f'); ++j)
        ;
      hl_emit(f, T_WS, s + i, j - i);
      i = j;
      continue;
    }
    if ((L->flags & HL_PREPROC) && line_start && c == '#') {
      size_t k = i + 1;
      while (k < n && (s[k] == ' ' || s[k] == '\t'))
        ++k;
      if (n - k >= 7 && !strncmp(s + k, "include", 7)) {
        size_t e = k + 7, a;
        hl_emit(f, T_PREPROC, s + i, e - i);
        for (a = e; a < n && (s[a] == ' ' || s[a] == '\t'); ++a)
          ;
        if (a > e)
          hl_emit(f, T_WS, s + e, a - e);
        for (e = a; e < n && s[e] != '\n'; ++e)
          ;
        hl_emit(f, T_COMMENT, s + a, e - a);
        i = e;
        continue;
      }
      for (j = i; j < n && s[j] != '\n'; ++j) {
        if (s[j] == '\\' && j + 1 < n && s[j + 1] == '\n')
          ++j;
      }
      hl_emit(f, T_PREPROC, s + i, j - i);
      i = j;
      continue;
    }
    line_start = 0;
    if ((L->flags & HL_C_COMMENT) && c == '/' && i + 1 < n && s[i + 1] == '/') {
      for (j = i; j < n && s[j] != '\n'; ++j)
        ;
      hl_emit(f, T_COMMENT, s + i, j - i);
      i = j;
      continue;
    }
    if ((L->flags & HL_C_COMMENT) && c == '/' && i + 1 < n && s[i + 1] == '*') {
      j = i + 2;
      while (j + 1 < n && !(s[j] == '*' && s[j + 1] == '/'))
        ++j;
      j = j + 1 < n ? j + 2 : n;
      /* a comment spanning lines is emitted line by line */
      {
        size_t a = i, k;
        for (k = i; k < j; ++k)
          if (s[k] == '\n') {
            hl_emit(f, T_COMMENT, s + a, k - a);
            hl_emit(f, T_WS, "\n", 1);
            a = k + 1;
          }
        hl_emit(f, T_COMMENT, s + a, j - a);
      }
      i = j;
      continue;
    }
    if ((L->flags & HL_HASH_COMMENT) && c == '#') {
      for (j = i; j < n && s[j] != '\n'; ++j)
        ;
      hl_emit(f, T_COMMENT, s + i, j - i);
      i = j;
      continue;
    }
    /* strings (with a prefix such as f, r, b for Python) */
    {
      size_t pre = 0;
      int fs = 0;
      if ((L->flags & HL_FSTRING) && hl_ident_start(c)) {
        size_t k = i;
        while (k < n && k < i + 3 && (s[k] == 'f' || s[k] == 'r' || s[k] == 'b' || s[k] == 'u' || s[k] == 'F' ||
                                       s[k] == 'R' || s[k] == 'B' || s[k] == 'U'))
          ++k;
        if (k > i && k < n && (s[k] == '"' || s[k] == '\'')) {
          pre = k - i;
          for (j = i; j < k; ++j)
            if (s[j] == 'f' || s[j] == 'F')
              fs = 1;
        }
      }
      {
        char q = s[i + pre];
        int is_q = q == '"' || ((L->flags & HL_SQ_STR) && q == '\'') || ((L->flags & HL_BACKTICK_STR) && q == '`') ||
                   (!(L->flags & HL_SQ_STR) && q == '\'');
        if (is_q && (pre || !hl_ident_start(c))) {
          int triple = (L->flags & HL_TRIPLE) && i + pre + 2 < n && s[i + pre + 1] == q && s[i + pre + 2] == q;
          size_t k;
          if (pre)
            hl_emit(f, T_STR, s + i, pre);
          k = hl_string(f, s, n, i + pre, q, triple, fs || (L->flags & HL_BACKTICK_STR && q == '`' && 0), triple && !fs);
          i = k;
          continue;
        }
      }
    }
    if (c >= '0' && c <= '9') {
      j = i;
      if (c == '0' && j + 1 < n && (s[j + 1] == 'x' || s[j + 1] == 'X' || s[j + 1] == 'b' || s[j + 1] == 'o')) {
        j += 2;
        while (j < n && (hl_ident_char((unsigned char)s[j])))
          ++j;
      } else {
        while (j < n && ((s[j] >= '0' && s[j] <= '9') || s[j] == '_' || s[j] == '.' || s[j] == 'e' || s[j] == 'E' ||
                         ((s[j] == '+' || s[j] == '-') && (s[j - 1] == 'e' || s[j - 1] == 'E')) ||
                         (hl_ident_start((unsigned char)s[j]) && j > i && (s[j] == 'f' || s[j] == 'F' || s[j] == 'u' ||
                                                                            s[j] == 'U' || s[j] == 'l' || s[j] == 'L'))))
          ++j;
      }
      hl_emit(f, T_NUM, s + i, j - i);
      i = j;
      continue;
    }
    if ((L->flags & HL_AT_DECOR) && c == '@' && i + 1 < n && hl_ident_start((unsigned char)s[i + 1])) {
      for (j = i + 1; j < n && (hl_ident_char((unsigned char)s[j]) || s[j] == '.'); ++j)
        ;
      hl_emit(f, T_DECOR, s + i, j - i);
      i = j;
      continue;
    }
    if ((L->flags & HL_DOLLAR_VAR) && c == '$') {
      j = i + 1;
      if (j < n && s[j] == '{') {
        while (j < n && s[j] != '}')
          ++j;
        if (j < n)
          ++j;
      } else if (j < n && s[j] == '(') {
        hl_emit(f, T_PUNCT, "$(", 2);
        i += 2;
        continue;
      } else
        while (j < n && (hl_ident_char((unsigned char)s[j]) || s[j] == '?' || s[j] == '@' || s[j] == '#'))
          ++j;
      hl_emit(f, T_NAME, s + i, j - i);
      i = j;
      continue;
    }
    if (hl_ident_start(c)) {
      int t = T_NAME;
      for (j = i; j < n && hl_ident_char((unsigned char)s[j]); ++j)
        ;
      if (expect_func)
        t = T_FUNC;
      else if (expect_class)
        t = T_CLASS;
      else if (hl_word_in(L->kwc, s + i, j - i))
        t = T_KW;
      else if (hl_word_in(L->opw, s + i, j - i))
        t = T_OP;
      else if (hl_word_in(L->kw, s + i, j - i))
        t = T_KW;
      else if (hl_word_in(L->kwt, s + i, j - i))
        t = T_KWT;
      else if (hl_word_in(L->pseudo, s + i, j - i))
        t = T_PSEUDO;
      else if (hl_word_in(L->builtin, s + i, j - i))
        t = T_BUILTIN;
      expect_func = expect_class = 0;
      if (t == T_KW || t == T_KWT) {
        if (hl_word_in(L->defw, s + i, j - i))
          expect_func = 1;
        if (hl_word_in(L->classw, s + i, j - i))
          expect_class = 1;
      }
      hl_emit(f, t, s + i, j - i);
      i = j;
      continue;
    }
    /* operators and punctuation */
    if (strchr("{}[]();,:", (char)c) && !(c == ':' && 0)) {
      hl_emit(f, T_PUNCT, s + i, 1);
      ++i;
      continue;
    }
    if (c == '.') {
      if (L->flags & HL_DOT_OP)
        hl_emit(f, T_DOT, s + i, 1);
      else
        hl_emit(f, T_PUNCT, s + i, 1);
      ++i;
      continue;
    }
    if (strchr("+-*/%=<>!&|^~?@\\", (char)c)) {
      for (j = i; j < n && strchr("+-*/%=<>!&|^~?", (char)s[j]); ++j)
        ;
      if (j == i)
        j = i + 1;
      hl_emit(f, T_OP, s + i, j - i);
      i = j;
      continue;
    }
    hl_emit(f, T_TEXT, s + i, 1);
    ++i;
  }
}

/* JSON */
static void hl_scan_json(hl_fmt *f, const char *s, size_t n) {
  size_t i = 0, j;
  while (i < n) {
    unsigned char c = (unsigned char)s[i];
    if (c == '\n') { hl_emit(f, T_WS, "\n", 1); ++i; continue; }
    if (c == ' ' || c == '\t' || c == '\r') {
      for (j = i; j < n && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r'); ++j)
        ;
      hl_emit(f, T_WS, s + i, j - i);
      i = j;
      continue;
    }
    if (c == '"') {
      size_t k = i + 1;
      int key;
      while (k < n && s[k] != '"' && s[k] != '\n')
        k += s[k] == '\\' && k + 1 < n ? 2 : 1;
      if (k < n && s[k] == '"')
        ++k;
      for (j = k; j < n && (s[j] == ' ' || s[j] == '\t'); ++j)
        ;
      key = j < n && s[j] == ':';
      hl_emit(f, key ? T_TAG : T_STR, s + i, k - i);
      i = k;
      continue;
    }
    if ((c >= '0' && c <= '9') || (c == '-' && i + 1 < n && s[i + 1] >= '0' && s[i + 1] <= '9')) {
      for (j = i + 1; j < n && ((s[j] >= '0' && s[j] <= '9') || s[j] == '.' || s[j] == 'e' || s[j] == 'E' ||
                                s[j] == '+' || s[j] == '-'); ++j)
        ;
      hl_emit(f, T_NUM, s + i, j - i);
      i = j;
      continue;
    }
    if (hl_ident_start(c)) {
      for (j = i; j < n && hl_ident_char((unsigned char)s[j]); ++j)
        ;
      hl_emit(f, hl_word_in("true false null", s + i, j - i) ? T_KW : T_TEXT, s + i, j - i);
      i = j;
      continue;
    }
    if (strchr("{}[],:", (char)c)) { hl_emit(f, T_PUNCT, s + i, 1); ++i; continue; }
    hl_emit(f, T_TEXT, s + i, 1);
    ++i;
  }
}

/* line oriented formats: YAML, TOML, INI, Markdown */
static void hl_value(hl_fmt *f, const char *s, size_t n) {
  /* the right-hand side of "key: value" / "key = value" */
  size_t i = 0, j;
  while (i < n) {
    unsigned char c = (unsigned char)s[i];
    if (c == ' ' || c == '\t') {
      for (j = i; j < n && (s[j] == ' ' || s[j] == '\t'); ++j)
        ;
      hl_emit(f, T_WS, s + i, j - i);
      i = j;
    } else if (c == '#' && (i == 0 || s[i - 1] == ' ' || s[i - 1] == '\t')) {
      hl_emit(f, T_COMMENT, s + i, n - i);
      return;
    } else if (c == '"' || c == '\'') {
      size_t k = i + 1;
      while (k < n && s[k] != (char)c)
        k += s[k] == '\\' && c == '"' && k + 1 < n ? 2 : 1;
      if (k < n)
        ++k;
      hl_emit(f, T_STR, s + i, k - i);
      i = k;
    } else if ((c >= '0' && c <= '9') || (c == '-' && i + 1 < n && s[i + 1] >= '0' && s[i + 1] <= '9')) {
      for (j = i + 1; j < n && ((s[j] >= '0' && s[j] <= '9') || s[j] == '.' || s[j] == '_'); ++j)
        ;
      hl_emit(f, (j < n && hl_ident_start((unsigned char)s[j])) ? T_TEXT : T_NUM, s + i, j - i);
      i = j;
    } else if (hl_ident_start(c)) {
      for (j = i; j < n && s[j] != ' ' && s[j] != '\t' && s[j] != ',' && s[j] != ']' && s[j] != '}' && s[j] != '#'; ++j)
        ;
      hl_emit(f, hl_word_in("true false null yes no on off True False None ~", s + i, j - i) ? T_KW : T_TEXT, s + i, j - i);
      i = j;
    } else if (strchr("[]{},", (char)c)) {
      hl_emit(f, T_PUNCT, s + i, 1);
      ++i;
    } else {
      hl_emit(f, T_TEXT, s + i, 1);
      ++i;
    }
  }
}
static void hl_scan_kv(hl_fmt *f, const char *s, size_t n, int sep_char, int ini) {
  size_t i = 0;
  while (i < n) {
    size_t e = i, ws;
    while (e < n && s[e] != '\n')
      ++e;
    /* the line is s[i..e) */
    ws = i;
    while (ws < e && (s[ws] == ' ' || s[ws] == '\t'))
      ++ws;
    if (ws > i)
      hl_emit(f, T_WS, s + i, ws - i);
    if (ws < e) {
      char c = s[ws];
      if (c == '#' || (ini && c == ';')) {
        hl_emit(f, T_COMMENT, s + ws, e - ws);
      } else if (c == '[' && ini) {
        hl_emit(f, T_KW, s + ws, e - ws);
      } else if (c == '-' && !ini && ws + 1 < e && s[ws + 1] == ' ') {
        hl_emit(f, T_PUNCT, "-", 1);
        {
          /* "- key: value" or "- value" */
          size_t k = ws + 1;
          while (k < e && s[k] == ' ')
            ++k;
          hl_emit(f, T_WS, s + ws + 1, k - ws - 1);
          {
            size_t col = k;
            while (col < e && s[col] != ':' && s[col] != '#')
              ++col;
            if (col < e && s[col] == ':' && (col + 1 == e || s[col + 1] == ' ')) {
              hl_emit(f, T_TAG, s + k, col - k);
              hl_emit(f, T_PUNCT, ":", 1);
              hl_value(f, s + col + 1, e - col - 1);
            } else
              hl_value(f, s + k, e - k);
          }
        }
      } else {
        size_t col = ws;
        int quoted = 0;
        while (col < e) {
          if (s[col] == '"' || s[col] == '\'')
            quoted = !quoted;
          if (!quoted && s[col] == sep_char && (sep_char == '=' || col + 1 == e || s[col + 1] == ' '))
            break;
          ++col;
        }
        if (col < e) {
          size_t ke = col;
          while (ke > ws && (s[ke - 1] == ' ' || s[ke - 1] == '\t'))
            --ke;
          hl_emit(f, ini ? T_ATTR : T_TAG, s + ws, ke - ws);
          if (ke < col)
            hl_emit(f, T_WS, s + ke, col - ke);
          hl_emit(f, sep_char == '=' ? T_OP : T_PUNCT, s + col, 1);
          hl_value(f, s + col + 1, e - col - 1);
        } else
          hl_value(f, s + ws, e - ws);
      }
    }
    if (e < n)
      hl_emit(f, T_WS, "\n", 1);
    i = e + 1;
  }
}
static void hl_scan_markdown(hl_fmt *f, const char *s, size_t n) {
  size_t i = 0;
  int fence = 0;
  while (i < n) {
    size_t e = i, k;
    while (e < n && s[e] != '\n')
      ++e;
    if (e - i >= 3 && !strncmp(s + i, "```", 3)) {
      fence = !fence;
      hl_emit(f, T_STR, s + i, e - i);
    } else if (fence)
      hl_emit(f, T_STR, s + i, e - i);
    else if (s[i] == '#') {
      hl_emit(f, T_HEAD, s + i, e - i);
    } else {
      k = i;
      while (k < e) {
        if (s[k] == '`') {
          size_t c2 = k + 1;
          while (c2 < e && s[c2] != '`')
            ++c2;
          if (c2 < e) {
            hl_emit(f, T_STR, s + k, c2 + 1 - k);
            k = c2 + 1;
            continue;
          }
        }
        if ((s[k] == '-' || s[k] == '*' || s[k] == '+') && k == i && k + 1 < e && s[k + 1] == ' ') {
          hl_emit(f, T_KW, s + k, 1);
          ++k;
          continue;
        }
        {
          size_t m = k;
          while (m < e && s[m] != '`' && !(m == i && (s[m] == '-' || s[m] == '*' || s[m] == '+')))
            ++m;
          if (m == k)
            m = k + 1;
          hl_emit(f, T_TEXT, s + k, m - k);
          k = m;
        }
      }
    }
    if (e < n)
      hl_emit(f, T_WS, "\n", 1);
    i = e + 1;
  }
}
/* HTML / XML and CSS */
static void hl_scan_html(hl_fmt *f, const char *s, size_t n) {
  size_t i = 0, j;
  while (i < n) {
    if (s[i] == '\n') { hl_emit(f, T_WS, "\n", 1); ++i; continue; }
    if (s[i] == '<' && i + 3 < n && !strncmp(s + i, "<!--", 4)) {
      j = i + 4;
      while (j + 2 < n && strncmp(s + j, "-->", 3))
        ++j;
      j = j + 2 < n ? j + 3 : n;
      {
        size_t a = i, k;
        for (k = i; k < j; ++k)
          if (s[k] == '\n') {
            hl_emit(f, T_COMMENT, s + a, k - a);
            hl_emit(f, T_WS, "\n", 1);
            a = k + 1;
          }
        hl_emit(f, T_COMMENT, s + a, j - a);
      }
      i = j;
    } else if (s[i] == '<' && i + 1 < n && (hl_ident_start((unsigned char)s[i + 1]) || s[i + 1] == '/' || s[i + 1] == '!' || s[i + 1] == '?')) {
      size_t k = i + 1;
      hl_emit(f, T_PUNCT, "<", 1);
      if (k < n && (s[k] == '/' || s[k] == '!' || s[k] == '?')) {
        hl_emit(f, T_PUNCT, s + k, 1);
        ++k;
      }
      for (j = k; j < n && (hl_ident_char((unsigned char)s[j]) || s[j] == '-' || s[j] == ':'); ++j)
        ;
      hl_emit(f, T_TAG, s + k, j - k);
      i = j;
      while (i < n && s[i] != '>') {
        if (s[i] == '\n') { hl_emit(f, T_WS, "\n", 1); ++i; }
        else if (s[i] == ' ' || s[i] == '\t' || s[i] == '\r') {
          for (j = i; j < n && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r'); ++j)
            ;
          hl_emit(f, T_WS, s + i, j - i);
          i = j;
        } else if (s[i] == '"' || s[i] == '\'') {
          for (j = i + 1; j < n && s[j] != s[i]; ++j)
            ;
          if (j < n)
            ++j;
          hl_emit(f, T_STR, s + i, j - i);
          i = j;
        } else if (s[i] == '=' || s[i] == '/') {
          hl_emit(f, T_OP, s + i, 1);
          ++i;
        } else {
          for (j = i; j < n && s[j] != '>' && s[j] != '=' && s[j] != ' ' && s[j] != '\n' && s[j] != '\t' && s[j] != '/' && s[j] != '"' && s[j] != '\''; ++j)
            ;
          if (j == i)
            j = i + 1;
          hl_emit(f, T_ATTR, s + i, j - i);
          i = j;
        }
      }
      if (i < n) {
        hl_emit(f, T_PUNCT, ">", 1);
        ++i;
      }
    } else {
      for (j = i; j < n && s[j] != '<' && s[j] != '\n'; ++j)
        ;
      if (j == i)
        j = i + 1;
      hl_emit(f, T_TEXT, s + i, j - i);
      i = j;
    }
  }
}
static void hl_scan_css(hl_fmt *f, const char *s, size_t n) {
  size_t i = 0, j;
  int in_block = 0;
  while (i < n) {
    unsigned char c = (unsigned char)s[i];
    if (c == '\n') { hl_emit(f, T_WS, "\n", 1); ++i; continue; }
    if (c == ' ' || c == '\t' || c == '\r') {
      for (j = i; j < n && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r'); ++j)
        ;
      hl_emit(f, T_WS, s + i, j - i);
      i = j;
    } else if (c == '/' && i + 1 < n && s[i + 1] == '*') {
      j = i + 2;
      while (j + 1 < n && !(s[j] == '*' && s[j + 1] == '/'))
        ++j;
      j = j + 1 < n ? j + 2 : n;
      {
        size_t a = i, k;
        for (k = i; k < j; ++k)
          if (s[k] == '\n') {
            hl_emit(f, T_COMMENT, s + a, k - a);
            hl_emit(f, T_WS, "\n", 1);
            a = k + 1;
          }
        hl_emit(f, T_COMMENT, s + a, j - a);
      }
      i = j;
    } else if (c == '{') { in_block = 1; hl_emit(f, T_PUNCT, "{", 1); ++i; }
    else if (c == '}') { in_block = 0; hl_emit(f, T_PUNCT, "}", 1); ++i; }
    else if (c == '"' || c == '\'') {
      for (j = i + 1; j < n && s[j] != (char)c && s[j] != '\n'; ++j)
        ;
      if (j < n && s[j] == (char)c)
        ++j;
      hl_emit(f, T_STR, s + i, j - i);
      i = j;
    } else if (strchr(";:,()", (char)c)) { hl_emit(f, T_PUNCT, s + i, 1); ++i; }
    else if (c >= '0' && c <= '9') {
      for (j = i; j < n && ((s[j] >= '0' && s[j] <= '9') || s[j] == '.' || hl_ident_start((unsigned char)s[j]) || s[j] == '%'); ++j)
        ;
      hl_emit(f, T_NUM, s + i, j - i);
      i = j;
    } else if (c == '#' && in_block) {
      for (j = i + 1; j < n && hl_ident_char((unsigned char)s[j]); ++j)
        ;
      hl_emit(f, T_NUM, s + i, j - i);
      i = j;
    } else if (hl_ident_start(c) || c == '.' || c == '#' || c == '@' || c == '-' || c == '*' || c == '&' || c == '>') {
      for (j = i + 1; j < n && (hl_ident_char((unsigned char)s[j]) || s[j] == '-'); ++j)
        ;
      if (in_block) {
        size_t k = j;
        while (k < n && (s[k] == ' ' || s[k] == '\t'))
          ++k;
        hl_emit(f, k < n && s[k] == ':' ? T_BUILTIN : T_NAME, s + i, j - i);
      } else
        hl_emit(f, c == '@' ? T_KW : T_TAG, s + i, j - i);
      i = j;
    } else {
      hl_emit(f, T_TEXT, s + i, 1);
      ++i;
    }
  }
}

/* ---- choosing a language ------------------------------------------------- */
enum { HLK_NONE, HLK_CODE, HLK_JSON, HLK_YAML, HLK_TOML, HLK_INI, HLK_MD, HLK_HTML, HLK_CSS, HLK_TEXT };
typedef struct hl_sel {
  int kind;
  const hl_lang *lang;
} hl_sel;
static const hl_lang *hl_lang_named(const char *n) {
  size_t i;
  for (i = 0; hl_langs[i].name; ++i)
    if (!strcmp(hl_langs[i].name, n))
      return &hl_langs[i];
  return NULL;
}
static hl_sel hl_select_name(const char *name) {
  hl_sel s = {HLK_NONE, NULL};
  char n[40];
  size_t i;
  for (i = 0; name[i] && i < sizeof(n) - 1; ++i)
    n[i] = (char)(name[i] >= 'A' && name[i] <= 'Z' ? name[i] + 32 : name[i]);
  n[i] = 0;
  if (!strcmp(n, "env") || !strcmp(n, "environment"))
    snprintf(n, sizeof(n), "bash");
#define HLE(a, b) (!strcmp(n, a) || !strcmp(n, b))
  if (HLE("c", "h")) s = (hl_sel){HLK_CODE, hl_lang_named("c")};
  else if (HLE("cpp", "c++") || HLE("cxx", "cc") || HLE("hpp", "hh") || !strcmp(n, "hxx")) s = (hl_sel){HLK_CODE, hl_lang_named("cpp")};
  else if (HLE("python", "py") || HLE("python3", "py3")) s = (hl_sel){HLK_CODE, hl_lang_named("python")};
  else if (HLE("javascript", "js") || HLE("typescript", "ts") || HLE("jsx", "tsx") || HLE("mjs", "cjs") || !strcmp(n, "node")) s = (hl_sel){HLK_CODE, hl_lang_named("javascript")};
  else if (HLE("bash", "sh") || HLE("shell", "zsh") || HLE("console", "shell-session")) s = (hl_sel){HLK_CODE, hl_lang_named("shell")};
  else if (HLE("rust", "rs")) s = (hl_sel){HLK_CODE, hl_lang_named("rust")};
  else if (HLE("go", "golang")) s = (hl_sel){HLK_CODE, hl_lang_named("go")};
  else if (!strcmp(n, "java")) s = (hl_sel){HLK_CODE, hl_lang_named("java")};
  else if (!strcmp(n, "json")) s.kind = HLK_JSON;
  else if (HLE("yaml", "yml")) s.kind = HLK_YAML;
  else if (!strcmp(n, "toml")) s.kind = HLK_TOML;
  else if (HLE("ini", "cfg") || !strcmp(n, "conf")) s.kind = HLK_INI;
  else if (HLE("markdown", "md")) s.kind = HLK_MD;
  else if (HLE("html", "xml") || HLE("htm", "svg") || HLE("xhtml", "xsl")) s.kind = HLK_HTML;
  else if (!strcmp(n, "css")) s.kind = HLK_CSS;
  else if (HLE("txt", "text")) s.kind = HLK_TEXT;
#undef HLE
  return s;
}
static hl_sel hl_select_filename(const char *path) {
  const char *base = strrchr(path, '/'), *dot;
  hl_sel none = {HLK_NONE, NULL};
  base = base ? base + 1 : path;
  if (!strcmp(base, "Makefile") || !strcmp(base, "CMakeLists.txt"))
    return none;
  if (!strcmp(base, "Dockerfile"))
    return none;
  dot = strrchr(base, '.');
  if (!dot || dot == base)
    return none;
  return hl_select_name(dot + 1);
}

static int hl_plain_only(void) {
  const char *e = getenv("RNGIT_HIGHLIGHT");
  return (e && !strcmp(e, "plain")) || !G.highlight_syntax;
}
/* "`=\n" + escaped text + "\n`=" (SyntaxHighlighter._plain_text) */
static void hl_plain_text(sbuf *o, const char *s, size_t n, int double_backslash) {
  size_t i;
  sb_adds(o, "`=\n");
  for (i = 0; i < n; ++i) {
    if (s[i] == '`') {
      if (double_backslash)
        sb_addc(o, '\\');
      sb_addc(o, '\\');
    }
    if (s[i] == '\\' && double_backslash)
      sb_addc(o, '\\');
    sb_addc(o, s[i]);
  }
  sb_adds(o, "\n`=");
}
/* SyntaxHighlighter.highlight(content, filename, language): appends to out. */
static void hl_highlight(sbuf *out, const char *content, const char *filename, const char *language) {
  hl_sel sel = {HLK_NONE, NULL};
  size_t n = strlen(content), a = 0, b;
  hl_fmt f;
  sbuf tmp;
  if (!n) {
    hl_plain_text(out, content, 0, 0);
    return;
  }
  if (hl_plain_only()) {
    /* pygments missing: _plain_text(content).replace("\\", "\\\\") */
    hl_plain_text(out, content, n, 1);
    return;
  }
  if (language && *language)
    sel = hl_select_name(language);
  if (sel.kind == HLK_NONE && filename && *filename)
    sel = hl_select_filename(filename);
  if (sel.kind == HLK_NONE) {
    hl_plain_text(out, content, n, 0);
    return;
  }
  /* pygments strips leading and trailing newlines, then ensures one at the end */
  b = n;
  while (a < b && content[a] == '\n')
    ++a;
  while (b > a && content[b - 1] == '\n')
    --b;
  sb_init(&tmp);
  tmp.limit = out->limit;
  f.out = &tmp;
  f.prev_dot = 0;
  f.last_break = 1;
  {
    char *src = malloc(b - a + 2);
    size_t m = b - a;
    if (!src) {
      sb_free(&tmp);
      hl_plain_text(out, content, n, 0);
      return;
    }
    memcpy(src, content + a, m);
    src[m++] = '\n';
    src[m] = 0;
    switch (sel.kind) {
    case HLK_CODE: hl_scan_code(&f, sel.lang, src, m); break;
    case HLK_JSON: hl_scan_json(&f, src, m); break;
    case HLK_YAML: hl_scan_kv(&f, src, m, ':', 0); break;
    case HLK_TOML: hl_scan_kv(&f, src, m, '=', 0); break;
    case HLK_INI: hl_scan_kv(&f, src, m, '=', 1); break;
    case HLK_MD: hl_scan_markdown(&f, src, m); break;
    case HLK_HTML: hl_scan_html(&f, src, m); break;
    case HLK_CSS: hl_scan_css(&f, src, m); break;
    case HLK_TEXT: hl_emit(&f, T_TEXT, src, m); break;
    default: break;
    }
    free(src);
  }
  /* highlighted.endswith("\n") and not content.endswith("\n"): drop one */
  if (tmp.n && tmp.p[tmp.n - 1] == '\n' && content[n - 1] != '\n')
    tmp.n--;
  sb_add(out, tmp.p ? tmp.p : "", tmp.n);
  sb_free(&tmp);
}

#endif
