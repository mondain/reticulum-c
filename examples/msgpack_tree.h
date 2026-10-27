#ifndef RETICULUM_C_EXAMPLE_MSGPACK_H
#define RETICULUM_C_EXAMPLE_MSGPACK_H
/* Small MessagePack reader shared by the example tools: parses one value into
 * a tree of nodes taken from a caller-supplied pool. Nothing is copied; STR and
 * BIN nodes point into the input. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ---- MessagePack values ------------------------------------------------- */
typedef enum { V_NIL, V_BOOL, V_INT, V_UINT, V_REAL, V_STR, V_BIN, V_ARR, V_MAP } vtype;
typedef struct val {
  vtype type;
  int64_t i;
  uint64_t u;
  double d;
  const uint8_t *p;
  size_t n; /* byte length for STR/BIN, element count for ARR, pairs for MAP */
  struct val *kids;
} val;
typedef struct reader {
  const uint8_t *p, *end;
  val *pool;
  size_t used, cap; /* nodes available in pool */
} reader;
static inline int take(reader *r, size_t n, const uint8_t **out) {
  if ((size_t)(r->end - r->p) < n)
    return 0;
  *out = r->p;
  r->p += n;
  return 1;
}
static inline int take_uint(reader *r, size_t bytes, uint64_t *out) {
  const uint8_t *b;
  size_t i;
  if (!take(r, bytes, &b))
    return 0;
  *out = 0;
  for (i = 0; i < bytes; ++i)
    *out = (*out << 8) | b[i];
  return 1;
}
static inline int parse(reader *r, val *out, unsigned depth) {
  const uint8_t *b;
  uint64_t n = 0;
  size_t i, per = 1;
  uint8_t tag;
  if (depth > 12 || !take(r, 1, &b))
    return 0;
  tag = b[0];
  memset(out, 0, sizeof(*out));
  if (tag <= 0x7f) {
    out->type = V_UINT;
    out->u = tag;
    return 1;
  }
  if (tag >= 0xe0) {
    out->type = V_INT;
    out->i = (int8_t)tag;
    return 1;
  }
  if ((tag & 0xe0) == 0xa0) {
    out->type = V_STR;
    out->n = tag & 0x1fu;
    return take(r, out->n, &out->p);
  }
  if ((tag & 0xf0) == 0x90 || (tag & 0xf0) == 0x80) {
    out->type = (tag & 0xf0) == 0x90 ? V_ARR : V_MAP;
    n = tag & 0x0fu;
    goto container;
  }
  switch (tag) {
  case 0xc0:
    out->type = V_NIL;
    return 1;
  case 0xc2:
  case 0xc3:
    out->type = V_BOOL;
    out->u = tag == 0xc3;
    return 1;
  case 0xc4:
  case 0xc5:
  case 0xc6:
    out->type = V_BIN;
    if (!take_uint(r, 1u << (tag - 0xc4), &n))
      return 0;
    out->n = (size_t)n;
    return take(r, out->n, &out->p);
  case 0xd9:
  case 0xda:
  case 0xdb:
    out->type = V_STR;
    if (!take_uint(r, 1u << (tag - 0xd9), &n))
      return 0;
    out->n = (size_t)n;
    return take(r, out->n, &out->p);
  case 0xca: {
    uint64_t bits;
    uint32_t b32;
    float f;
    if (!take_uint(r, 4, &bits))
      return 0;
    b32 = (uint32_t)bits;
    memcpy(&f, &b32, 4);
    out->type = V_REAL;
    out->d = f;
    return 1;
  }
  case 0xcb: {
    uint64_t bits;
    if (!take_uint(r, 8, &bits))
      return 0;
    memcpy(&out->d, &bits, 8);
    out->type = V_REAL;
    return 1;
  }
  case 0xcc:
  case 0xcd:
  case 0xce:
  case 0xcf:
    out->type = V_UINT;
    return take_uint(r, 1u << (tag - 0xcc), &out->u);
  case 0xd0:
  case 0xd1:
  case 0xd2:
  case 0xd3: {
    size_t bytes = 1u << (tag - 0xd0);
    uint64_t raw;
    if (!take_uint(r, bytes, &raw))
      return 0;
    out->type = V_INT;
    out->i = bytes == 1   ? (int8_t)raw
             : bytes == 2 ? (int16_t)raw
             : bytes == 4 ? (int32_t)raw
                          : (int64_t)raw;
    return 1;
  }
  case 0xdc:
  case 0xdd:
    out->type = V_ARR;
    if (!take_uint(r, tag == 0xdc ? 2 : 4, &n))
      return 0;
    goto container;
  case 0xde:
  case 0xdf:
    out->type = V_MAP;
    if (!take_uint(r, tag == 0xde ? 2 : 4, &n))
      return 0;
    goto container;
  default:
    return 0;
  }
container:
  per = out->type == V_MAP ? 2 : 1;
  if (n > r->cap || r->used + n * per > r->cap)
    return 0;
  out->n = (size_t)n;
  out->kids = r->pool + r->used;
  r->used += (size_t)n * per;
  for (i = 0; i < n * per; ++i)
    if (!parse(r, &out->kids[i], depth + 1))
      return 0;
  return 1;
}
static inline const val *map_get(const val *m, const char *key) {
  size_t i;
  if (!m || m->type != V_MAP)
    return NULL;
  for (i = 0; i < m->n; ++i) {
    const val *k = &m->kids[2 * i];
    if (k->type == V_STR && k->n == strlen(key) && !memcmp(k->p, key, k->n))
      return &m->kids[2 * i + 1];
  }
  return NULL;
}
static inline double as_double(const val *v) {
  if (!v)
    return 0;
  switch (v->type) {
  case V_REAL:
    return v->d;
  case V_INT:
    return (double)v->i;
  case V_UINT:
    return (double)v->u;
  default:
    return 0;
  }
}
static inline uint64_t as_uint(const val *v) {
  if (!v)
    return 0;
  if (v->type == V_UINT || v->type == V_BOOL)
    return v->u;
  if (v->type == V_INT && v->i > 0)
    return (uint64_t)v->i;
  if (v->type == V_REAL && v->d > 0)
    return (uint64_t)v->d;
  return 0;
}
#endif
