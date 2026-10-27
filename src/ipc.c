#include "service_msgpack.h"
#include <float.h>
#include <math.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <reticulum_c/rnc_ipc.h>
#include <stdlib.h>
#include <string.h>
_Static_assert(sizeof(double) == 8 && DBL_MANT_DIG == 53,
               "IEEE binary64 required");
enum rpc_state {
  RPC_NEW,
  RPC_CHALLENGE,
  RPC_RESPONSE,
  RPC_WELCOME,
  RPC_READY,
  RPC_DEAD
};
typedef struct rpc_event_info {
  rnc_rpc_event_type type;
  rnc_result reason;
  size_t size;
} rpc_event_info;
struct rnc_rpc {
  enum rpc_state state;
  int server;
  uint8_t key[RNC_RPC_KEY_MAX], challenge[48], header[12];
  size_t key_size, limit, stride, head, count, header_size, header_needed,
      input_size, input_needed;
  uint64_t now, started;
  rnc_random_fn random;
  void *random_context;
  rpc_event_info events[RNC_RPC_EVENTS];
  uint8_t storage[];
};
static void put32(uint8_t *p, uint32_t n) {
  p[0] = (uint8_t)(n >> 24);
  p[1] = (uint8_t)(n >> 16);
  p[2] = (uint8_t)(n >> 8);
  p[3] = (uint8_t)n;
}
static uint32_t get32(const uint8_t *p) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
         p[3];
}
static int room(const rnc_rpc *r, size_t n) {
  return n <= RNC_RPC_EVENTS - r->count;
}
static uint8_t *input_buffer(rnc_rpc *r) {
  return r->storage + RNC_RPC_EVENTS * r->stride;
}
static void event(rnc_rpc *r, rnc_rpc_event_type type, rnc_result reason,
                  const void *data, size_t size) {
  size_t slot = (r->head + r->count) % RNC_RPC_EVENTS;
  r->events[slot].type = type;
  r->events[slot].reason = reason;
  r->events[slot].size = size;
  if (size)
    memcpy(r->storage + slot * r->stride, data, size);
  r->count++;
}
static void send_bytes(rnc_rpc *r, const void *data, size_t size) {
  size_t slot = (r->head + r->count) % RNC_RPC_EVENTS;
  uint8_t *out = r->storage + slot * r->stride;
  put32(out, (uint32_t)size);
  if (size)
    memcpy(out + 4, data, size);
  r->events[slot].type = RNC_RPC_SEND;
  r->events[slot].reason = RNC_OK;
  r->events[slot].size = size + 4;
  r->count++;
}
static void close_reason(rnc_rpc *r, rnc_result reason, int reject) {
  OPENSSL_cleanse(r->storage, (RNC_RPC_EVENTS + 1u) * r->stride);
  memset(r->events, 0, sizeof(r->events));
  r->head = r->count = 0;
  OPENSSL_cleanse(r->key, sizeof(r->key));
  OPENSSL_cleanse(r->challenge, sizeof(r->challenge));
  r->state = RPC_DEAD;
  if (reject)
    send_bytes(r, "#FAILURE#", 9);
  event(r, RNC_RPC_CLOSED, reason, NULL, 0);
}
static const char *digest_name(const uint8_t *p, size_t n, size_t *prefix) {
  static const struct {
    const char *wire, *openssl;
  } names[] = {{"md5", "MD5"},
               {"sha256", "SHA256"},
               {"sha384", "SHA384"},
               {"sha3_256", "SHA3-256"},
               {"sha3_384", "SHA3-384"}};
  size_t i, len;
  *prefix = 0;
  if (n == 16 || n == 20)
    return "MD5";
  for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    len = strlen(names[i].wire);
    if (n >= len + 2 && p[0] == '{' && p[len + 1] == '}' &&
        !memcmp(p + 1, names[i].wire, len)) {
      *prefix = len + 2;
      return names[i].openssl;
    }
  }
  return NULL;
}
static rnc_result response(rnc_rpc *r, const uint8_t *message, size_t size,
                           uint8_t output[80], size_t *written) {
  size_t prefix, n = 64;
  const char *digest = digest_name(message, size, &prefix);
  if (!digest)
    return RNC_AUTH;
  if (prefix)
    memcpy(output, message, prefix);
  if (!EVP_Q_mac(NULL, "HMAC", NULL, digest, NULL, r->key, r->key_size, message,
                 size, output + prefix, 80 - prefix, &n))
    return RNC_CRYPTO;
  *written = prefix + n;
  return RNC_OK;
}
static rnc_result verify_response(rnc_rpc *r, const uint8_t *value,
                                  size_t size) {
  uint8_t expected[64];
  size_t prefix, n = 64;
  const char *digest = digest_name(value, size, &prefix);
  rnc_result status = RNC_AUTH;
  if (!digest)
    return RNC_AUTH;
  if (!EVP_Q_mac(NULL, "HMAC", NULL, digest, NULL, r->key, r->key_size,
                 r->challenge, sizeof(r->challenge), expected, sizeof(expected),
                 &n))
    return RNC_CRYPTO;
  if (size - prefix == n && !CRYPTO_memcmp(expected, value + prefix, n))
    status = RNC_OK;
  OPENSSL_cleanse(expected, sizeof(expected));
  return status;
}
static rnc_result challenge(rnc_rpc *r) {
  uint8_t data[59], fresh[48];
  rnc_result status;
  memcpy(fresh, "{sha256}", 8);
  status = r->random(r->random_context, fresh + 8, 40);
  if (status == RNC_OK) {
    memcpy(data, "#CHALLENGE#", 11);
    memcpy(data + 11, fresh, 48);
    send_bytes(r, data, sizeof(data));
    memcpy(r->challenge, fresh, 48);
    r->state = RPC_RESPONSE;
  }
  OPENSSL_cleanse(fresh, sizeof(fresh));
  return status;
}
static rnc_result process(rnc_rpc *r, const uint8_t *p, size_t n) {
  uint8_t answer[80];
  size_t written;
  rnc_result status = RNC_OK;
  if (r->state == RPC_READY) {
    event(r, RNC_RPC_MESSAGE, RNC_OK, p, n);
    return RNC_OK;
  }
  if (r->state == RPC_CHALLENGE) {
    if (n < 31 || n > 256 || memcmp(p, "#CHALLENGE#", 11))
      return RNC_AUTH;
    status = response(r, p + 11, n - 11, answer, &written);
    if (status == RNC_OK) {
      send_bytes(r, answer, written);
      r->state = RPC_WELCOME;
    }
    OPENSSL_cleanse(answer, sizeof(answer));
    return status;
  }
  if (r->state == RPC_RESPONSE) {
    status = verify_response(r, p, n);
    if (status != RNC_OK)
      return status;
    send_bytes(r, "#WELCOME#", 9);
    if (r->server)
      r->state = RPC_CHALLENGE;
    else {
      r->state = RPC_READY;
      event(r, RNC_RPC_AUTHENTICATED, RNC_OK, NULL, 0);
    }
    return RNC_OK;
  }
  if (r->state == RPC_WELCOME) {
    if (n != 9 || memcmp(p, "#WELCOME#", 9))
      return RNC_AUTH;
    if (r->server) {
      r->state = RPC_READY;
      event(r, RNC_RPC_AUTHENTICATED, RNC_OK, NULL, 0);
      return RNC_OK;
    }
    return challenge(r);
  }
  return RNC_STATE;
}
rnc_rpc *rnc_rpc_new(const void *key, size_t key_size, int server,
                     rnc_random_fn random, void *context, size_t limit) {
  rnc_rpc *r;
  size_t stride;
  if (!key || !key_size || key_size > RNC_RPC_KEY_MAX || !random ||
      (server != 0 && server != 1) || limit > RNC_RPC_MESSAGE_MAX)
    return NULL;
  if (!limit)
    limit = RNC_RPC_MESSAGE_MAX;
  stride = (limit > 256 ? limit : 256) + 12;
  r = calloc(1, sizeof(*r) + (RNC_RPC_EVENTS + 1u) * stride);
  if (r) {
    memcpy(r->key, key, key_size);
    r->key_size = key_size;
    r->server = server;
    r->random = random;
    r->random_context = context;
    r->limit = limit;
    r->stride = stride;
    r->header_needed = 4;
  }
  return r;
}
void rnc_rpc_free(rnc_rpc *r) {
  if (r) {
    size_t size = sizeof(*r) + (RNC_RPC_EVENTS + 1u) * r->stride;
    OPENSSL_cleanse(r, size);
    free(r);
  }
}
rnc_result rnc_rpc_key(const rnc_identity *identity, uint8_t key[32]) {
  if (!identity || !identity->has_private || !key)
    return RNC_INVALID;
  return rnc_hash(identity->private_key, 64, key);
}
rnc_result rnc_rpc_start(rnc_rpc *r, uint64_t now) {
  rnc_result status = RNC_OK;
  if (!r || now < r->now)
    return RNC_INVALID;
  if (r->state != RPC_NEW)
    return RNC_STATE;
  if (r->server)
    status = challenge(r);
  else
    r->state = RPC_CHALLENGE;
  if (status == RNC_OK)
    r->started = r->now = now;
  return status;
}
rnc_result rnc_rpc_input(rnc_rpc *r, const uint8_t *data, size_t size,
                         size_t *consumed, uint64_t now) {
  size_t take, offset = 0;
  rnc_result status;
  if (consumed)
    *consumed = 0;
  if (!r || (!data && size) || !consumed || now < r->now)
    return RNC_INVALID;
  if (r->state == RPC_NEW || r->state == RPC_DEAD)
    return RNC_STATE;
  if (r->state != RPC_READY && now - r->started >= 30000u) {
    r->now = now;
    close_reason(r, RNC_TIMEOUT, 0);
    return RNC_TIMEOUT;
  }
  while (offset < size) {
    if (!room(r, 2)) {
      *consumed = offset;
      return RNC_AGAIN;
    }
    if (r->header_size < r->header_needed) {
      take = r->header_needed - r->header_size;
      if (take > size - offset)
        take = size - offset;
      memcpy(r->header + r->header_size, data + offset, take);
      r->header_size += take;
      offset += take;
      if (r->header_size < r->header_needed)
        break;
      if (r->header_needed == 4) {
        uint32_t n = get32(r->header);
        if (n == UINT32_MAX) {
          r->header_needed = 12;
          continue;
        }
        if (n > INT32_MAX) {
          status = RNC_PROTOCOL;
          goto failed;
        }
        r->input_needed = n;
      } else {
        uint64_t n = 0;
        size_t i;
        for (i = 4; i < 12; i++)
          n = (n << 8) | r->header[i];
        if (n > RNC_RPC_MESSAGE_MAX) {
          status = RNC_PROTOCOL;
          goto failed;
        }
        r->input_needed = (size_t)n;
      }
      if (r->input_needed > (r->state == RPC_READY ? r->limit : 256u)) {
        status = RNC_PROTOCOL;
        goto failed;
      }
    }
    take = r->input_needed - r->input_size;
    if (take > size - offset)
      take = size - offset;
    if (take)
      memcpy(input_buffer(r) + r->input_size, data + offset, take);
    r->input_size += take;
    offset += take;
    if (r->input_size < r->input_needed)
      break;
    status = process(r, input_buffer(r), r->input_size);
    OPENSSL_cleanse(input_buffer(r), r->input_size);
    r->header_size = r->input_size = r->input_needed = 0;
    r->header_needed = 4;
    if (status != RNC_OK)
      goto failed;
  }
  r->now = now;
  *consumed = offset;
  return RNC_OK;
failed:
  r->now = now;
  *consumed = offset;
  close_reason(r, status, r->state != RPC_READY);
  return status;
}
rnc_result rnc_rpc_send(rnc_rpc *r, const void *payload, size_t size,
                        uint64_t now) {
  if (!r || (!payload && size) || size > r->limit || now < r->now)
    return RNC_INVALID;
  if (r->state != RPC_READY)
    return RNC_STATE;
  if (!room(r, 1))
    return RNC_AGAIN;
  send_bytes(r, payload, size);
  r->now = now;
  return RNC_OK;
}
rnc_result rnc_rpc_poll(rnc_rpc *r, rnc_rpc_event *out) {
  rpc_event_info *e;
  if (!r || !out)
    return RNC_INVALID;
  if (!r->count)
    return RNC_AGAIN;
  e = &r->events[r->head];
  memset(out, 0, sizeof(*out));
  out->type = e->type;
  out->reason = e->reason;
  out->size = e->size;
  if (e->size)
    memcpy(out->data, r->storage + r->head * r->stride, e->size);
  OPENSSL_cleanse(r->storage + r->head * r->stride, r->stride);
  memset(e, 0, sizeof(*e));
  r->head = (r->head + 1u) % RNC_RPC_EVENTS;
  r->count--;
  return RNC_OK;
}
rnc_result rnc_rpc_tick(rnc_rpc *r, uint64_t now) {
  if (!r || now < r->now)
    return RNC_INVALID;
  r->now = now;
  if (r->state != RPC_NEW && r->state != RPC_READY && r->state != RPC_DEAD &&
      now - r->started >= 30000u)
    close_reason(r, RNC_TIMEOUT, 0);
  return RNC_OK;
}
rnc_result rnc_rpc_close(rnc_rpc *r) {
  if (!r)
    return RNC_INVALID;
  if (r->state != RPC_DEAD)
    close_reason(r, RNC_OK, 0);
  return RNC_OK;
}
int rnc_rpc_is_authenticated(const rnc_rpc *r) {
  return r && r->state == RPC_READY;
}

static int map_count(rmp *r, uint64_t *n) {
  const uint8_t *p;
  if (!rmp_take(r, 1, &p))
    return 0;
  if ((*p & 0xf0) == 0x80) {
    *n = *p & 15;
    return 1;
  }
  return (*p == 0xde || *p == 0xdf) && rmp_num(r, *p == 0xde ? 2 : 4, n);
}
static int positive(rmp *r, uint64_t *n) {
  rmp save = *r;
  const uint8_t *p;
  size_t bytes;
  if (rmp_uint(r, n))
    return 1;
  *r = save;
  if (!rmp_take(r, 1, &p) || *p < 0xd0 || *p > 0xd3)
    return 0;
  bytes = (size_t)1u << (*p - 0xd0);
  if (!rmp_num(r, bytes, n))
    return 0;
  return !(*n & (UINT64_C(1) << (bytes * 8u - 1u)));
}
rnc_result rnc_rpc_decode_query(const void *payload, size_t size,
                                rnc_rpc_query *query) {
  static const struct {
    const char *name;
    rnc_rpc_query_type type;
    int destination;
  } methods[] = {
      {"interface_stats", RNC_RPC_INTERFACE_STATS, 0},
      {"path_table", RNC_RPC_PATH_TABLE, 0},
      {"link_count", RNC_RPC_LINK_COUNT, 0},
      {"active_link_count", RNC_RPC_ACTIVE_LINK_COUNT, 0},
      {"next_hop", RNC_RPC_NEXT_HOP, 1},
      {"next_hop_if_name", RNC_RPC_NEXT_HOP_IF_NAME, 1},
      {"first_hop_timeout", RNC_RPC_FIRST_HOP_TIMEOUT, 1},
      {"lowest_interface_bitrate", RNC_RPC_LOWEST_INTERFACE_BITRATE, 0},
      {"medium_path_timeout", RNC_RPC_MEDIUM_PATH_TIMEOUT, 0},
      {"rate_table", RNC_RPC_RATE_TABLE, 0},
      {"blackholed_identities", RNC_RPC_BLACKHOLED_IDENTITIES, 0}};
  rmp r = {payload, size, 0};
  rnc_rpc_query out = {0};
  const uint8_t *key, *value;
  size_t n, vn, i, j;
  uint64_t count, hops;
  unsigned seen = 0, bit;
  char method[64] = {0};
  if (!payload || !query || !size || size > RNC_RPC_MESSAGE_MAX)
    return RNC_INVALID;
  if (!map_count(&r, &count) || !count || count > 8)
    return RNC_PROTOCOL;
  for (i = 0; i < count; i++) {
    if (!rmp_len(&r, 1, &n) || !rmp_take(&r, n, &key))
      return RNC_PROTOCOL;
    if (n == 3 && !memcmp(key, "get", 3))
      bit = 1;
    else if (n == 16 && !memcmp(key, "destination_hash", 16))
      bit = 2;
    else if (n == 8 && !memcmp(key, "max_hops", 8))
      bit = 4;
    else
      return RNC_UNSUPPORTED;
    if (seen & bit)
      return RNC_PROTOCOL;
    seen |= bit;
    if (bit == 1) {
      if (!rmp_len(&r, 1, &vn) || !vn || vn >= sizeof(method) ||
          !rmp_take(&r, vn, &value))
        return RNC_PROTOCOL;
      memcpy(method, value, vn);
      if (memchr(method, 0, vn))
        return RNC_PROTOCOL;
    } else if (bit == 2) {
      if (!rmp_bin(&r, &value, &vn) || vn != 16)
        return RNC_PROTOCOL;
      memcpy(out.destination_hash, value, 16);
      out.has_destination = 1;
    } else {
      if (r.i < r.n && r.p[r.i] == 0xc0)
        r.i++;
      else {
        if (!positive(&r, &hops) || hops > 128)
          return RNC_PROTOCOL;
        out.has_max_hops = 1;
        out.max_hops = (uint32_t)hops;
      }
    }
  }
  if (!(seen & 1) || r.i != r.n)
    return RNC_PROTOCOL;
  for (j = 0; j < sizeof(methods) / sizeof(methods[0]); j++)
    if (!strcmp(method, methods[j].name)) {
      if (methods[j].destination && !out.has_destination)
        return RNC_PROTOCOL;
      out.type = methods[j].type;
      *query = out;
      return RNC_OK;
    }
  return RNC_UNSUPPORTED;
}
static rnc_result writer_error(rnc_rpc_writer *w, rnc_result result) {
  if (w && w->status == RNC_OK)
    w->status = result;
  return result;
}
void rnc_rpc_writer_init(rnc_rpc_writer *w, void *output, size_t capacity) {
  if (!w)
    return;
  memset(w, 0, sizeof(*w));
  w->data = output;
  w->capacity = capacity;
  w->depth = 1;
  w->remaining[0] = 1;
  if ((!output && capacity) || capacity > RNC_RPC_MESSAGE_MAX)
    w->status = RNC_INVALID;
}
static rnc_result append(rnc_rpc_writer *w, const void *head, size_t hn,
                         const void *data, size_t n, size_t children) {
  if (!w)
    return RNC_INVALID;
  if (w->status != RNC_OK)
    return w->status;
  while (w->depth && w->remaining[w->depth - 1] == 0)
    w->depth--;
  if (!w->depth)
    return writer_error(w, RNC_STATE);
  if (children && w->depth == RNC_RPC_WRITER_DEPTH)
    return writer_error(w, RNC_NO_SPACE);
  if (hn > w->capacity - w->size || n > w->capacity - w->size - hn)
    return writer_error(w, RNC_NO_SPACE);
  memcpy(w->data + w->size, head, hn);
  if (n)
    memcpy(w->data + w->size + hn, data, n);
  w->size += hn + n;
  w->remaining[w->depth - 1]--;
  if (children)
    w->remaining[w->depth++] = children;
  return RNC_OK;
}
static rnc_result container(rnc_rpc_writer *w, size_t n, int map) {
  uint8_t b[5];
  size_t h;
  if (n > RNC_RPC_MESSAGE_MAX / (map ? 2u : 1u))
    return writer_error(w, RNC_INVALID);
  if (n < 16) {
    b[0] = (uint8_t)((map ? 0x80 : 0x90) | n);
    h = 1;
  } else if (n <= UINT16_MAX) {
    b[0] = (uint8_t)(map ? 0xde : 0xdc);
    b[1] = (uint8_t)(n >> 8);
    b[2] = (uint8_t)n;
    h = 3;
  } else {
    b[0] = (uint8_t)(map ? 0xdf : 0xdd);
    put32(b + 1, (uint32_t)n);
    h = 5;
  }
  return append(w, b, h, NULL, 0, n * (map ? 2u : 1u));
}
rnc_result rnc_rpc_write_map(rnc_rpc_writer *w, size_t n) {
  return container(w, n, 1);
}
rnc_result rnc_rpc_write_array(rnc_rpc_writer *w, size_t n) {
  return container(w, n, 0);
}
rnc_result rnc_rpc_write_uint(rnc_rpc_writer *w, uint64_t value) {
  uint8_t b[9];
  size_t n = rmp_put_uint(b, value);
  return append(w, b, n, NULL, 0, 0);
}
rnc_result rnc_rpc_write_int(rnc_rpc_writer *w, int64_t value) {
  uint8_t b[9];
  size_t n, i;
  uint64_t bits;
  if (value >= 0)
    return rnc_rpc_write_uint(w, (uint64_t)value);
  if (value >= -32) {
    b[0] = (uint8_t)value;
    return append(w, b, 1, NULL, 0, 0);
  }
  n = value >= INT8_MIN    ? 1
      : value >= INT16_MIN ? 2
      : value >= INT32_MIN ? 4
                           : 8;
  b[0] = (uint8_t)(n == 1 ? 0xd0 : n == 2 ? 0xd1 : n == 4 ? 0xd2 : 0xd3);
  bits = (uint64_t)value;
  for (i = 0; i < n; i++)
    b[n - i] = (uint8_t)(bits >> (8 * i));
  return append(w, b, n + 1, NULL, 0, 0);
}
rnc_result rnc_rpc_write_real(rnc_rpc_writer *w, double value) {
  uint8_t b[9];
  uint64_t bits;
  size_t i;
  if (!isfinite(value))
    return writer_error(w, RNC_INVALID);
  memcpy(&bits, &value, 8);
  b[0] = 0xcb;
  for (i = 0; i < 8; i++)
    b[8 - i] = (uint8_t)(bits >> (8 * i));
  return append(w, b, 9, NULL, 0, 0);
}
static int utf8(const uint8_t *p, size_t n) {
  size_t i = 0, j, len;
  uint32_t code, min;
  while (i < n) {
    uint8_t c = p[i++];
    if (c < 0x80)
      continue;
    if (c >= 0xc2 && c <= 0xdf) {
      len = 1;
      code = c & 31;
      min = 0x80;
    } else if (c >= 0xe0 && c <= 0xef) {
      len = 2;
      code = c & 15;
      min = 0x800;
    } else if (c >= 0xf0 && c <= 0xf4) {
      len = 3;
      code = c & 7;
      min = 0x10000;
    } else
      return 0;
    if (len > n - i)
      return 0;
    for (j = 0; j < len; j++) {
      if ((p[i] & 0xc0) != 0x80)
        return 0;
      code = (code << 6) | (p[i++] & 63);
    }
    if (code < min || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff))
      return 0;
  }
  return 1;
}
rnc_result rnc_rpc_write_string(rnc_rpc_writer *w, const char *value) {
  uint8_t b[5];
  size_t n, h;
  if (!value)
    return writer_error(w, RNC_INVALID);
  n = strlen(value);
  if (n > RNC_RPC_MESSAGE_MAX || !utf8((const uint8_t *)value, n))
    return writer_error(w, RNC_INVALID);
  if (n < 32) {
    b[0] = (uint8_t)(0xa0 | n);
    h = 1;
  } else if (n <= 255) {
    b[0] = 0xd9;
    b[1] = (uint8_t)n;
    h = 2;
  } else {
    b[0] = 0xda;
    b[1] = (uint8_t)(n >> 8);
    b[2] = (uint8_t)n;
    h = 3;
  }
  return append(w, b, h, value, n, 0);
}
rnc_result rnc_rpc_write_bin(rnc_rpc_writer *w, const void *value, size_t n) {
  uint8_t b[5];
  size_t h;
  if ((!value && n) || n > RNC_RPC_MESSAGE_MAX)
    return writer_error(w, RNC_INVALID);
  if (n <= 255) {
    b[0] = 0xc4;
    b[1] = (uint8_t)n;
    h = 2;
  } else if (n <= 65535) {
    b[0] = 0xc5;
    b[1] = (uint8_t)(n >> 8);
    b[2] = (uint8_t)n;
    h = 3;
  } else {
    b[0] = 0xc6;
    put32(b + 1, (uint32_t)n);
    h = 5;
  }
  return append(w, b, h, value, n, 0);
}
rnc_result rnc_rpc_write_bool(rnc_rpc_writer *w, int value) {
  uint8_t b;
  if (value != 0 && value != 1)
    return writer_error(w, RNC_INVALID);
  b = (uint8_t)(value ? 0xc3 : 0xc2);
  return append(w, &b, 1, NULL, 0, 0);
}
rnc_result rnc_rpc_write_nil(rnc_rpc_writer *w) {
  uint8_t b = 0xc0;
  return append(w, &b, 1, NULL, 0, 0);
}
rnc_result rnc_rpc_writer_finish(rnc_rpc_writer *w, size_t *written) {
  if (written)
    *written = 0;
  if (!w || !written)
    return RNC_INVALID;
  if (w->status != RNC_OK)
    return w->status;
  while (w->depth && !w->remaining[w->depth - 1])
    w->depth--;
  if (w->depth)
    return writer_error(w, RNC_PROTOCOL);
  *written = w->size;
  return RNC_OK;
}
