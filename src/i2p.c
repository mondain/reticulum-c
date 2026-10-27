#include <reticulum_c/rnc_i2p.h>
#include <string.h>

static const char alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";

rnc_result rnc_i2p_b64_encode(const uint8_t *data, size_t size, char *out,
                              size_t capacity) {
  size_t i, w = 0;
  if (!out || (!data && size))
    return RNC_INVALID;
  if (capacity < (size + 2u) / 3u * 4u + 1u)
    return RNC_NO_SPACE;
  for (i = 0; i < size; i += 3) {
    uint32_t v = (uint32_t)data[i] << 16;
    size_t left = size - i;
    if (left > 1)
      v |= (uint32_t)data[i + 1] << 8;
    if (left > 2)
      v |= data[i + 2];
    out[w++] = alphabet[v >> 18 & 63u];
    out[w++] = alphabet[v >> 12 & 63u];
    out[w++] = left > 1 ? alphabet[v >> 6 & 63u] : '=';
    out[w++] = left > 2 ? alphabet[v & 63u] : '=';
  }
  out[w] = 0;
  return RNC_OK;
}

static int b64_value(char c) {
  const char *p = c ? strchr(alphabet, c) : NULL;
  return p ? (int)(p - alphabet) : -1;
}

rnc_result rnc_i2p_b64_decode(const char *text, uint8_t *out, size_t capacity,
                              size_t *written) {
  size_t n, i, w = 0;
  if (!text || !written || (!out && capacity))
    return RNC_INVALID;
  n = strlen(text);
  if (n % 4u)
    return RNC_INVALID;
  for (i = 0; i < n; i += 4) {
    int a = b64_value(text[i]), b = b64_value(text[i + 1]),
        c = text[i + 2] == '=' ? 0 : b64_value(text[i + 2]),
        d = text[i + 3] == '=' ? 0 : b64_value(text[i + 3]);
    size_t take = 3;
    uint32_t v;
    if (a < 0 || b < 0 || c < 0 || d < 0)
      return RNC_INVALID;
    if (text[i + 3] == '=') {
      if (i + 4 != n)
        return RNC_INVALID;
      take = text[i + 2] == '=' ? 1u : 2u;
    } else if (text[i + 2] == '=')
      return RNC_INVALID;
    if (w + take > capacity)
      return RNC_NO_SPACE;
    v = (uint32_t)a << 18 | (uint32_t)b << 12 | (uint32_t)c << 6 | (uint32_t)d;
    out[w++] = (uint8_t)(v >> 16);
    if (take > 1)
      out[w++] = (uint8_t)(v >> 8);
    if (take > 2)
      out[w++] = (uint8_t)v;
  }
  *written = w;
  return RNC_OK;
}

rnc_result rnc_i2p_destination_size(const uint8_t *data, size_t size,
                                    size_t *destination_size) {
  size_t total;
  if (!data || !destination_size || size < 387u)
    return RNC_INVALID;
  total = 387u + ((size_t)data[385] << 8 | data[386]);
  if (total > size)
    return RNC_INVALID;
  *destination_size = total;
  return RNC_OK;
}

rnc_result rnc_i2p_b32(const uint8_t *destination, size_t size,
                       char out[RNC_I2P_B32_SIZE]) {
  static const char base32[] = "abcdefghijklmnopqrstuvwxyz234567";
  uint8_t hash[32];
  size_t i, w = 0;
  uint32_t bits = 0, count = 0;
  rnc_result r;
  if (!destination || !out)
    return RNC_INVALID;
  r = rnc_hash(destination, size, hash);
  if (r != RNC_OK)
    return r;
  for (i = 0; i < 32; ++i) {
    bits = bits << 8 | hash[i];
    count += 8;
    while (count >= 5) {
      out[w++] = base32[bits >> (count - 5) & 31u];
      count -= 5;
    }
  }
  if (count)
    out[w++] = base32[bits << (5 - count) & 31u];
  out[w] = 0;
  return RNC_OK;
}

rnc_result rnc_i2p_private_to_public(const char *private_key, char *out,
                                     size_t capacity) {
  uint8_t key[1024];
  size_t n, destination;
  rnc_result r = rnc_i2p_b64_decode(private_key, key, sizeof(key), &n);
  if (r != RNC_OK)
    return r;
  r = rnc_i2p_destination_size(key, n, &destination);
  if (r != RNC_OK)
    return r;
  return rnc_i2p_b64_encode(key, destination, out, capacity);
}

/* Next blank-separated token of the reply, honouring double quotes after '='.
 */
static const char *token(const char *p, const char **start, size_t *length) {
  int quoted = 0;
  while (*p == ' ')
    ++p;
  if (!*p)
    return NULL;
  *start = p;
  while (*p && (quoted || *p != ' ')) {
    if (*p == '"')
      quoted = !quoted;
    ++p;
  }
  *length = (size_t)(p - *start);
  return p;
}

rnc_result rnc_i2p_reply_parse(const char *line, rnc_i2p_reply *out) {
  const char *p = line, *start, *end;
  size_t n;
  if (!line || !out)
    return RNC_INVALID;
  memset(out, 0, sizeof(*out));
  if (strlen(line) >= sizeof(out->line))
    return RNC_NO_SPACE;
  strcpy(out->line, line);
  p = token(out->line, &start, &n);
  if (!p || n >= sizeof(out->topic))
    return RNC_INVALID;
  memcpy(out->topic, start, n);
  p = token(p, &start, &n);
  if (!p || n >= sizeof(out->action) || memchr(start, '=', n))
    return RNC_INVALID;
  memcpy(out->action, start, n);
  for (end = p; (end = token(end, &start, &n)) != NULL;)
    if (n == 9 && !memcmp(start, "RESULT=OK", 9))
      out->ok = 1;
  return RNC_OK;
}

rnc_result rnc_i2p_reply_value(const rnc_i2p_reply *reply, const char *key,
                               char *out, size_t capacity) {
  const char *p, *start;
  size_t n, klen;
  if (!reply || !key || !out || !capacity)
    return RNC_INVALID;
  klen = strlen(key);
  p = token(reply->line, &start, &n);
  p = p ? token(p, &start, &n) : NULL;
  while (p && (p = token(p, &start, &n)) != NULL) {
    if (n > klen && start[klen] == '=' && !memcmp(start, key, klen)) {
      const char *v = start + klen + 1;
      size_t vl = n - klen - 1;
      if (vl >= 2 && v[0] == '"' && v[vl - 1] == '"') {
        ++v;
        vl -= 2;
      }
      if (vl >= capacity)
        return RNC_NO_SPACE;
      memcpy(out, v, vl);
      out[vl] = 0;
      return RNC_OK;
    }
  }
  return RNC_STATE;
}
