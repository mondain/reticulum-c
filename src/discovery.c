#include "service_msgpack.h"
#include <ctype.h>
#include <openssl/crypto.h>
#include <reticulum_c/rnc_discovery.h>
#include <reticulum_c/rnc_ipc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
  K_TYPE = 0x00,
  K_TRANSPORT = 0x01,
  K_REACHABLE_ON = 0x02,
  K_LATITUDE = 0x03,
  K_LONGITUDE = 0x04,
  K_HEIGHT = 0x05,
  K_PORT = 0x06,
  K_IFAC_NETNAME = 0x07,
  K_IFAC_NETKEY = 0x08,
  K_FREQUENCY = 0x09,
  K_BANDWIDTH = 0x0a,
  K_SPREADING_FACTOR = 0x0b,
  K_CODING_RATE = 0x0c,
  K_MODULATION = 0x0d,
  K_CHANNEL = 0x0e,
  K_OPERATOR = 0xf0,
  K_NAME = 0xff,
  K_TRANSPORT_ID = 0xfe,
  K_IMPL = 0xfd,
  K_VERSION = 0xfc
};
typedef enum { T_NONE, T_TCP, T_I2P, T_RNODE, T_WEAVE, T_KISS, T_OTHER } kind_t;
static kind_t kind_of(const char *type) {
  if (!strcmp(type, "BackboneInterface") || !strcmp(type, "TCPServerInterface"))
    return T_TCP;
  if (!strcmp(type, "I2PInterface"))
    return T_I2P;
  if (!strcmp(type, "RNodeInterface"))
    return T_RNODE;
  if (!strcmp(type, "WeaveInterface"))
    return T_WEAVE;
  if (!strcmp(type, "KISSInterface"))
    return T_KISS;
  if (!strcmp(type, "TCPClientInterface"))
    return T_OTHER; /* announced types the listener accepts but never stores */
  return T_NONE;
}
/* ---- packing ---- */
static void key(rnc_rpc_writer *w, unsigned k) { (void)rnc_rpc_write_uint(w, k); }
static void key_text(rnc_rpc_writer *w, unsigned k, const char *v) {
  key(w, k);
  (void)rnc_rpc_write_string(w, v);
}
static void key_real_or_nil(rnc_rpc_writer *w, unsigned k, int has, double v) {
  key(w, k);
  if (has)
    (void)rnc_rpc_write_real(w, v);
  else
    (void)rnc_rpc_write_nil(w);
}
static void key_uint_or_nil(rnc_rpc_writer *w, unsigned k, int has, uint64_t v) {
  key(w, k);
  if (has)
    (void)rnc_rpc_write_uint(w, v);
  else
    (void)rnc_rpc_write_nil(w);
}
rnc_result rnc_discovery_pack(const rnc_discovery_info *info, uint8_t *output,
                              size_t capacity, size_t *written) {
  rnc_rpc_writer w;
  kind_t kind;
  size_t pairs = 7; /* type, transport, id, name, latitude, longitude, height */
  rnc_result r;
  if (written)
    *written = 0;
  if (!info || !output || !written)
    return RNC_INVALID;
  kind = kind_of(info->type);
  if (kind == T_NONE || kind == T_OTHER || !info->name[0])
    return RNC_INVALID;
  if ((kind == T_TCP && (!info->reachable_on[0] || !info->has_port)) ||
      (kind == T_RNODE && !(info->has_frequency && info->has_bandwidth &&
                            info->spreading_factor && info->coding_rate)))
    return RNC_INVALID;
  pairs += info->impl_name[0] ? 1u : 0u;
  pairs += info->version[0] ? 1u : 0u;
  pairs += info->has_operator ? 1u : 0u;
  pairs += kind == T_TCP ? 2u : kind == T_I2P ? (info->reachable_on[0] ? 1u : 0u)
         : kind == T_RNODE ? 4u : kind == T_WEAVE ? 4u : kind == T_KISS ? 3u : 0u;
  pairs += info->ifac_netname[0] ? 1u : 0u;
  pairs += info->ifac_netkey[0] ? 1u : 0u;
  rnc_rpc_writer_init(&w, output, capacity);
  (void)rnc_rpc_write_map(&w, pairs);
  key_text(&w, K_TYPE, info->type);
  key(&w, K_TRANSPORT);
  (void)rnc_rpc_write_bool(&w, info->transport);
  key(&w, K_TRANSPORT_ID);
  (void)rnc_rpc_write_bin(&w, info->transport_id, 16);
  if (info->impl_name[0])
    key_text(&w, K_IMPL, info->impl_name);
  if (info->version[0])
    key_text(&w, K_VERSION, info->version);
  key_text(&w, K_NAME, info->name);
  key_real_or_nil(&w, K_LATITUDE, info->has_latitude, info->latitude);
  key_real_or_nil(&w, K_LONGITUDE, info->has_longitude, info->longitude);
  key_real_or_nil(&w, K_HEIGHT, info->has_height, info->height);
  if (info->has_operator) {
    key(&w, K_OPERATOR);
    (void)rnc_rpc_write_bin(&w, info->operator_address, 16);
  }
  switch (kind) {
  case T_TCP:
    key_text(&w, K_REACHABLE_ON, info->reachable_on);
    key_uint_or_nil(&w, K_PORT, 1, info->port);
    break;
  case T_I2P:
    if (info->reachable_on[0])
      key_text(&w, K_REACHABLE_ON, info->reachable_on);
    break;
  case T_RNODE:
    key_uint_or_nil(&w, K_FREQUENCY, 1, info->frequency);
    key_uint_or_nil(&w, K_BANDWIDTH, 1, info->bandwidth);
    key_uint_or_nil(&w, K_SPREADING_FACTOR, 1, info->spreading_factor);
    key_uint_or_nil(&w, K_CODING_RATE, 1, info->coding_rate);
    break;
  case T_WEAVE:
    key_uint_or_nil(&w, K_FREQUENCY, info->has_frequency, info->frequency);
    key_uint_or_nil(&w, K_BANDWIDTH, info->has_bandwidth, info->bandwidth);
    key_uint_or_nil(&w, K_CHANNEL, info->has_channel, info->channel);
    key_uint_or_nil(&w, K_MODULATION, info->has_modulation,
                    (uint64_t)strtoull(info->modulation, NULL, 10));
    break;
  case T_KISS:
    key_uint_or_nil(&w, K_FREQUENCY, info->has_frequency, info->frequency);
    key_uint_or_nil(&w, K_BANDWIDTH, info->has_bandwidth, info->bandwidth);
    key(&w, K_MODULATION);
    if (info->has_modulation)
      (void)rnc_rpc_write_string(&w, info->modulation);
    else
      (void)rnc_rpc_write_nil(&w);
    break;
  default:
    break;
  }
  if (info->ifac_netname[0])
    key_text(&w, K_IFAC_NETNAME, info->ifac_netname);
  if (info->ifac_netkey[0])
    key_text(&w, K_IFAC_NETKEY, info->ifac_netkey);
  r = rnc_rpc_writer_finish(&w, written);
  if (r != RNC_OK) {
    *written = 0;
    return r == RNC_NO_SPACE || r == RNC_INVALID ? RNC_NO_SPACE : r;
  }
  return RNC_OK;
}
rnc_result rnc_discovery_announce_data(const rnc_discovery_info *info,
                                       unsigned stamp_cost,
                                       const rnc_identity *encrypt_to,
                                       rnc_random_fn random, void *random_context,
                                       uint8_t *output, size_t capacity,
                                       size_t *written) {
  uint8_t packed[RNC_DISCOVERY_PAYLOAD_MAX], infohash[32], body[RNC_DISCOVERY_PAYLOAD_MAX];
  size_t n = 0, body_size, encrypted = 0;
  rnc_result r;
  if (written)
    *written = 0;
  if (!info || !output || !written || !random)
    return RNC_INVALID;
  r = rnc_discovery_pack(info, packed, sizeof(packed) - RNC_STAMP_SIZE, &n);
  if (r != RNC_OK)
    return r;
  if (rnc_hash(packed, n, infohash) != RNC_OK)
    return RNC_CRYPTO;
  memcpy(body, packed, n);
  r = rnc_stamp_generate(infohash, 32, RNC_DISCOVERY_STAMP_ROUNDS, stamp_cost,
                         random, random_context, 0, body + n);
  if (r != RNC_OK)
    return r;
  body_size = n + RNC_STAMP_SIZE;
  if (encrypt_to) {
    uint8_t token[RNC_DISCOVERY_PAYLOAD_MAX + 128];
    r = rnc_identity_encrypt(encrypt_to, body, body_size, random,
                             random_context, token, sizeof(token), &encrypted);
    if (r != RNC_OK)
      return r;
    if (capacity < 1 + encrypted)
      return RNC_NO_SPACE;
    output[0] = RNC_DISCOVERY_FLAG_ENCRYPTED;
    memcpy(output + 1, token, encrypted);
    *written = 1 + encrypted;
    return RNC_OK;
  }
  if (capacity < 1 + body_size)
    return RNC_NO_SPACE;
  output[0] = 0;
  memcpy(output + 1, body, body_size);
  *written = 1 + body_size;
  return RNC_OK;
}
/* ---- parsing ---- */
static int take_text(rmp *r, char *out, size_t capacity) {
  const uint8_t *p;
  size_t n, i;
  if (!rmp_len(r, 1, &n) || !rmp_take(r, n, &p) || n >= capacity)
    return 0;
  for (i = 0; i < n; i++)
    if (!p[i])
      return 0;
  memcpy(out, p, n);
  out[n] = 0;
  return 1;
}
/* float64/float32 (or nil, reported through *has) */
static int take_real_or_nil(rmp *r, int *has, double *value) {
  uint64_t bits;
  if (r->i >= r->n)
    return 0;
  if (r->p[r->i] == 0xc0) {
    r->i++;
    *has = 0;
    return 1;
  }
  if (r->p[r->i] == 0xcb) {
    r->i++;
    if (!rmp_num(r, 8, &bits))
      return 0;
    memcpy(value, &bits, 8);
  } else if (r->p[r->i] == 0xca) {
    uint32_t b32;
    float f;
    r->i++;
    if (!rmp_num(r, 4, &bits))
      return 0;
    b32 = (uint32_t)bits;
    memcpy(&f, &b32, 4);
    *value = f;
  } else
    return 0;
  *has = *value == *value; /* NaN is not a coordinate */
  return *has;
}
static int take_uint_or_nil(rmp *r, int *has, uint64_t *value) {
  if (r->i < r->n && r->p[r->i] == 0xc0) {
    r->i++;
    *has = 0;
    return 1;
  }
  *has = 1;
  return rmp_uint(r, value);
}
static int take_bool(rmp *r, int *value) {
  if (r->i >= r->n || (r->p[r->i] != 0xc2 && r->p[r->i] != 0xc3))
    return 0;
  *value = r->p[r->i++] == 0xc3;
  return 1;
}
static rnc_result decode_info(const uint8_t *packed, size_t size,
                              rnc_discovery_info *out) {
  rmp r = {packed, size, 0};
  rnc_discovery_info info;
  const uint8_t *p;
  size_t pairs, i, n;
  unsigned seen_lo = 0, seen_hi = 0;
  const uint8_t m = r.n ? r.p[0] : 0;
  uint64_t v;
  int has;
  kind_t kind;
  memset(&info, 0, sizeof(info));
  r.i = 1;
  if ((m & 0xf0) == 0x80)
    pairs = m & 15u;
  else if (m == 0xde && rmp_num(&r, 2, &v))
    pairs = (size_t)v;
  else
    return RNC_PROTOCOL;
  if (pairs > 64)
    return RNC_PROTOCOL;
  for (i = 0; i < pairs; i++) {
    uint64_t k;
    if (!rmp_uint(&r, &k) || k > 0xff)
      return RNC_PROTOCOL;
    if (k < 16)
      seen_lo |= 1u << k;
    else if (k >= 0xf0)
      seen_hi |= 1u << (k - 0xf0);
    switch (k) {
    case K_TYPE:
      if (!take_text(&r, info.type, sizeof(info.type)))
        return RNC_PROTOCOL;
      break;
    case K_TRANSPORT:
      if (!take_bool(&r, &info.transport))
        return RNC_PROTOCOL;
      break;
    case K_TRANSPORT_ID:
      if (!rmp_bin(&r, &p, &n) || n != 16)
        return RNC_PROTOCOL;
      memcpy(info.transport_id, p, 16);
      break;
    case K_IMPL:
      if (!take_text(&r, info.impl_name, sizeof(info.impl_name)))
        return RNC_PROTOCOL;
      break;
    case K_VERSION:
      if (!take_text(&r, info.version, sizeof(info.version)))
        return RNC_PROTOCOL;
      break;
    case K_NAME:
      if (!take_text(&r, info.name, sizeof(info.name)))
        return RNC_PROTOCOL;
      break;
    case K_LATITUDE:
      if (!take_real_or_nil(&r, &info.has_latitude, &info.latitude) &&
          info.has_latitude)
        return RNC_PROTOCOL;
      break;
    case K_LONGITUDE:
      if (!take_real_or_nil(&r, &info.has_longitude, &info.longitude) &&
          info.has_longitude)
        return RNC_PROTOCOL;
      break;
    case K_HEIGHT:
      if (!take_real_or_nil(&r, &info.has_height, &info.height) &&
          info.has_height)
        return RNC_PROTOCOL;
      break;
    case K_OPERATOR:
      if (r.i < r.n && r.p[r.i] == 0xc0)
        r.i++;
      else if (rmp_bin(&r, &p, &n)) {
        if (n == 16) {
          memcpy(info.operator_address, p, 16);
          info.has_operator = 1;
        }
      } else
        return RNC_PROTOCOL;
      break;
    case K_REACHABLE_ON:
      if (!take_text(&r, info.reachable_on, sizeof(info.reachable_on)))
        return RNC_PROTOCOL;
      break;
    case K_PORT:
      if (!take_uint_or_nil(&r, &has, &v) || (has && v > 0xffff))
        return RNC_PROTOCOL;
      info.has_port = has;
      info.port = (uint32_t)v;
      break;
    case K_FREQUENCY:
    case K_BANDWIDTH:
    case K_CHANNEL:
      if (!take_uint_or_nil(&r, &has, &v) || (has && v > UINT32_MAX))
        return RNC_PROTOCOL;
      if (k == K_FREQUENCY) {
        info.has_frequency = has;
        info.frequency = (uint32_t)v;
      } else if (k == K_BANDWIDTH) {
        info.has_bandwidth = has;
        info.bandwidth = (uint32_t)v;
      } else {
        info.has_channel = has;
        info.channel = (uint32_t)v;
      }
      break;
    case K_SPREADING_FACTOR:
    case K_CODING_RATE:
      if (!take_uint_or_nil(&r, &has, &v) || (has && v > 255))
        return RNC_PROTOCOL;
      if (k == K_SPREADING_FACTOR)
        info.spreading_factor = (unsigned)v;
      else
        info.coding_rate = (unsigned)v;
      break;
    case K_MODULATION:
      if (r.i < r.n && r.p[r.i] == 0xc0)
        r.i++;
      else if (r.i < r.n && ((r.p[r.i] & 0xe0) == 0xa0 ||
                             (r.p[r.i] >= 0xd9 && r.p[r.i] <= 0xdb))) {
        if (!take_text(&r, info.modulation, sizeof(info.modulation)))
          return RNC_PROTOCOL;
        info.has_modulation = 1;
      } else if (rmp_uint(&r, &v)) {
        (void)snprintf(info.modulation, sizeof(info.modulation), "%llu",
                       (unsigned long long)v);
        info.has_modulation = 1;
      } else
        return RNC_PROTOCOL;
      break;
    case K_IFAC_NETNAME:
    case K_IFAC_NETKEY: {
      char text[64];
      if (r.i < r.n && r.p[r.i] == 0xc0) {
        r.i++;
        break;
      }
      if (!take_text(&r, text, sizeof(text)))
        return RNC_PROTOCOL;
      memcpy(k == K_IFAC_NETNAME ? info.ifac_netname : info.ifac_netkey, text,
             sizeof(text));
      break;
    }
    default:
      if (!rmp_skip_depth(&r, 0))
        return RNC_PROTOCOL;
      break;
    }
  }
  if (r.i != r.n)
    return RNC_PROTOCOL;
  /* fields the reference reads without a default */
  kind = kind_of(info.type);
  if (kind == T_NONE || !(seen_lo & (1u << K_TRANSPORT)) ||
      !(seen_lo & (1u << K_LATITUDE)) || !(seen_lo & (1u << K_LONGITUDE)) ||
      !(seen_lo & (1u << K_HEIGHT)) || !(seen_hi & (1u << 0x0e)) /* 0xfe */ ||
      !(seen_hi & (1u << 0x0f)) /* 0xff */)
    return RNC_PROTOCOL;
  if (info.reachable_on[0] && !rnc_discovery_is_ip_address(info.reachable_on) &&
      !rnc_discovery_is_hostname(info.reachable_on))
    return RNC_PROTOCOL;
  if (kind == T_TCP && (!(seen_lo & (1u << K_REACHABLE_ON)) ||
                        !(seen_lo & (1u << K_PORT)) || !info.has_port))
    return RNC_PROTOCOL;
  if (kind == T_I2P && !(seen_lo & (1u << K_REACHABLE_ON)))
    return RNC_PROTOCOL;
  if (kind == T_RNODE &&
      (!(seen_lo & (1u << K_FREQUENCY)) || !(seen_lo & (1u << K_BANDWIDTH)) ||
       !(seen_lo & (1u << K_SPREADING_FACTOR)) ||
       !(seen_lo & (1u << K_CODING_RATE))))
    return RNC_PROTOCOL;
  if (kind == T_WEAVE &&
      (!(seen_lo & (1u << K_FREQUENCY)) || !(seen_lo & (1u << K_BANDWIDTH)) ||
       !(seen_lo & (1u << K_CHANNEL)) || !(seen_lo & (1u << K_MODULATION))))
    return RNC_PROTOCOL;
  if (kind == T_KISS &&
      (!(seen_lo & (1u << K_FREQUENCY)) || !(seen_lo & (1u << K_BANDWIDTH)) ||
       !(seen_lo & (1u << K_MODULATION))))
    return RNC_PROTOCOL;
  {
    char clean[96];
    rnc_discovery_sanitize_name(info.name, clean, sizeof(clean));
    if (clean[0])
      memcpy(info.name, clean, sizeof(clean));
    else
      (void)snprintf(info.name, sizeof(info.name), "Discovered %s", info.type);
  }
  *out = info;
  return RNC_OK;
}
rnc_result rnc_discovery_parse(const uint8_t *app_data, size_t size,
                               unsigned required_value,
                               const rnc_identity *network_identity,
                               rnc_discovery_info *info,
                               uint8_t stamp[RNC_STAMP_SIZE], unsigned *value) {
  uint8_t plain[RNC_DISCOVERY_PAYLOAD_MAX + 128], infohash[32];
  uint8_t *workblock;
  const uint8_t *body;
  size_t body_size, packed_size, work_size;
  unsigned got;
  rnc_discovery_info decoded;
  rnc_result r;
  int valid;
  if (!app_data || !info || !stamp || !value || size <= RNC_STAMP_SIZE + 1u ||
      size > RNC_DISCOVERY_PAYLOAD_MAX)
    return RNC_PROTOCOL;
  body = app_data + 1;
  body_size = size - 1;
  if (app_data[0] & RNC_DISCOVERY_FLAG_ENCRYPTED) {
    if (!network_identity || !network_identity->has_private)
      return RNC_STATE;
    if (rnc_identity_decrypt(network_identity, body, body_size, plain,
                             sizeof(plain), &body_size) != RNC_OK)
      return RNC_STATE;
    body = plain;
    if (body_size <= RNC_STAMP_SIZE)
      return RNC_PROTOCOL;
  }
  packed_size = body_size - RNC_STAMP_SIZE;
  if (rnc_hash(body, packed_size, infohash) != RNC_OK)
    return RNC_CRYPTO;
  work_size = (size_t)RNC_DISCOVERY_STAMP_ROUNDS * RNC_STAMP_ROUND_SIZE;
  workblock = malloc(work_size);
  if (!workblock)
    return RNC_NO_SPACE;
  r = rnc_stamp_workblock(infohash, 32, RNC_DISCOVERY_STAMP_ROUNDS, workblock,
                          work_size, &work_size);
  if (r != RNC_OK) {
    free(workblock);
    return r;
  }
  got = rnc_stamp_value(workblock, work_size, body + packed_size);
  valid = rnc_stamp_valid(workblock, work_size, body + packed_size,
                          required_value);
  free(workblock);
  if (!valid || got < required_value)
    return RNC_AUTH;
  r = decode_info(body, packed_size, &decoded);
  if (r != RNC_OK)
    return r;
  *info = decoded;
  memcpy(stamp, body + packed_size, RNC_STAMP_SIZE);
  *value = got;
  return RNC_OK;
}
/* ---- helpers ---- */
static int ipv4(const char *s, size_t n) {
  size_t i = 0;
  int groups = 0;
  while (i <= n) {
    size_t start = i;
    unsigned v = 0;
    while (i < n && isdigit((unsigned char)s[i]))
      v = v * 10u + (unsigned)(s[i++] - '0'), v = v > 999 ? 999 : v;
    if (i == start || i - start > 3 || v > 255 || (i - start > 1 && s[start] == '0'))
      return 0;
    groups++;
    if (i == n)
      break;
    if (s[i] != '.')
      return 0;
    i++;
  }
  return groups == 4;
}
static int ipv6(const char *s, size_t n) {
  size_t i = 0, groups = 0, tail_words = 0;
  int compressed = 0;
  size_t end = n;
  const char *zone = memchr(s, '%', n);
  if (zone) {
    if (zone + 1 >= s + n)
      return 0;
    end = (size_t)(zone - s);
  }
  if (!end)
    return 0;
  if (end >= 2 && s[0] == ':' && s[1] == ':') {
    compressed = 1;
    i = 2;
    if (i == end)
      return 1;
  } else if (s[0] == ':')
    return 0;
  while (i < end) {
    size_t start = i;
    while (i < end && isxdigit((unsigned char)s[i]))
      i++;
    if (i < end && s[i] == '.' && i > start) {
      /* embedded IPv4 occupies the last two words */
      if (!ipv4(s + start, end - start))
        return 0;
      tail_words = 2;
      groups += 2;
      i = end;
      break;
    }
    if (i == start || i - start > 4)
      return 0;
    groups++;
    if (i == end)
      break;
    if (s[i] != ':')
      return 0;
    i++;
    if (i < end && s[i] == ':') {
      if (compressed)
        return 0;
      compressed = 1;
      i++;
      if (i == end)
        break;
    } else if (i == end)
      return 0;
  }
  (void)tail_words;
  return compressed ? groups <= 7 : groups == 8;
}
int rnc_discovery_is_ip_address(const char *text) {
  size_t n;
  if (!text || !*text)
    return 0;
  n = strlen(text);
  return strchr(text, ':') ? ipv6(text, n) : ipv4(text, n);
}
int rnc_discovery_is_hostname(const char *text) {
  size_t n, i, label = 0, last = 0;
  int all_digits = 1;
  if (!text || !*text)
    return 0;
  n = strlen(text);
  if (text[n - 1] == '.')
    n--;
  if (!n || n > 253)
    return 0;
  for (i = 0; i <= n; i++) {
    if (i == n || text[i] == '.') {
      if (!label || label > 63 || text[last] == '-' || text[i - 1] == '-')
        return 0;
      if (i == n && all_digits)
        return 0; /* a final all-numeric label makes it an address */
      last = i + 1;
      label = 0;
      all_digits = 1;
      continue;
    }
    if (!isalnum((unsigned char)text[i]) && text[i] != '-')
      return 0;
    if (!isdigit((unsigned char)text[i]))
      all_digits = 0;
    label++;
  }
  return 1;
}
static void fold_spaces(char *s, size_t run) {
  size_t r = 0, w = 0, n = strlen(s);
  while (r < n) {
    size_t k = 0;
    while (k < run && r + k < n && s[r + k] == ' ')
      k++;
    if (k == run) {
      s[w++] = ' ';
      r += run;
    } else
      s[w++] = s[r++];
  }
  s[w] = 0;
}
void rnc_discovery_sanitize_name(const char *name, char *out, size_t capacity) {
  size_t n = 0, start, end;
  static const size_t runs[3] = {5, 3, 2};
  unsigned i;
  if (!out || !capacity)
    return;
  out[0] = 0;
  if (!name)
    return;
  for (; *name && n + 1 < capacity; name++)
    if ((unsigned char)*name < 128)
      out[n++] = *name;
  out[n] = 0;
  start = 0;
  while (out[start] && isspace((unsigned char)out[start]))
    start++;
  end = strlen(out);
  while (end > start && isspace((unsigned char)out[end - 1]))
    end--;
  memmove(out, out + start, end - start);
  out[end - start] = 0;
  for (i = 0; i < 3; i++)
    fold_spaces(out, runs[i]);
  start = 0;
  while (out[start] && !isalnum((unsigned char)out[start]))
    start++;
  end = strlen(out);
  while (end > start && !isalnum((unsigned char)out[end - 1]) &&
         out[end - 1] != ')')
    end--;
  memmove(out, out + start, end - start);
  out[end - start] = 0;
}
rnc_result rnc_discovery_hash(const rnc_discovery_info *info, uint8_t hash[32]) {
  char material[16 * 2 + 96 + 1];
  size_t i;
  if (!info || !hash)
    return RNC_INVALID;
  for (i = 0; i < 16; i++)
    (void)snprintf(material + 2 * i, 3, "%02x", info->transport_id[i]);
  (void)snprintf(material + 32, sizeof(material) - 32, "%s", info->name);
  return rnc_hash(material, strlen(material), hash);
}
rnc_result rnc_discovery_endpoint_hash(const rnc_discovery_info *info,
                                       uint8_t hash[32]) {
  char material[160];
  int n;
  if (!info || !hash)
    return RNC_INVALID;
  n = snprintf(material, sizeof(material), "%s", info->reachable_on);
  if (info->has_port && n > 0 && (size_t)n < sizeof(material))
    n += snprintf(material + n, sizeof(material) - (size_t)n, ":%u",
                  (unsigned)info->port);
  if (n < 0 || (size_t)n >= sizeof(material))
    return RNC_INVALID;
  return rnc_hash(material, (size_t)n, hash);
}

/* ---- records ---- */
static void hex_text(const uint8_t *in, size_t n, char *out) {
  size_t i;
  for (i = 0; i < n; i++)
    (void)snprintf(out + 2 * i, 3, "%02x", in[i]);
}
rnc_result rnc_discovery_config_entry(const rnc_discovery_info *info,
                                      int use_backbone, char *out,
                                      size_t capacity) {
  char identity[16 * 2 + 1], network[96], passphrase[96], text[768];
  kind_t kind;
  int n;
  if (!info || !out || !capacity)
    return RNC_INVALID;
  kind = kind_of(info->type);
  hex_text(info->transport_id, 16, identity);
  network[0] = passphrase[0] = 0;
  if (info->ifac_netname[0])
    (void)snprintf(network, sizeof(network), "\n  network_name = %s",
                   info->ifac_netname);
  if (info->ifac_netkey[0])
    (void)snprintf(passphrase, sizeof(passphrase), "\n  passphrase = %s",
                   info->ifac_netkey);
  switch (kind) {
  case T_TCP:
    n = snprintf(text, sizeof(text),
                 "[[%s]]\n  type = %s\n  enabled = yes\n  %s = %s\n  "
                 "target_port = %u\n  transport_identity = %s%s%s",
                 info->name, use_backbone ? "BackboneInterface" : "TCPClientInterface",
                 use_backbone ? "remote" : "target_host", info->reachable_on,
                 (unsigned)info->port, identity, network, passphrase);
    break;
  case T_I2P:
    n = snprintf(text, sizeof(text),
                 "[[%s]]\n  type = I2PInterface\n  enabled = yes\n  peers = "
                 "%s.b32.i2p\n  transport_identity = %s%s%s",
                 info->name, info->reachable_on, identity, network, passphrase);
    break;
  case T_RNODE:
    n = snprintf(text, sizeof(text),
                 "[[%s]]\n  type = RNodeInterface\n  enabled = yes\n  port = "
                 "\n  frequency = %u\n  bandwidth = %u\n  spreadingfactor = "
                 "%u\n  codingrate = %u\n  txpower = %s%s",
                 info->name, (unsigned)info->frequency,
                 (unsigned)info->bandwidth, info->spreading_factor,
                 info->coding_rate, network, passphrase);
    break;
  case T_WEAVE:
    n = snprintf(text, sizeof(text),
                 "[[%s]]\n  type = WeaveInterface\n  enabled = yes\n  port = "
                 "%s%s",
                 info->name, network, passphrase);
    break;
  case T_KISS:
    n = snprintf(text, sizeof(text),
                 "[[%s]]\n  type = KISSInterface\n  enabled = yes\n  port = "
                 "\n  # Frequency: %u\n  # Bandwidth: %u\n  # Modulation: "
                 "%s\n  transport_identity = %s%s%s",
                 info->name, (unsigned)info->frequency,
                 (unsigned)info->bandwidth, info->modulation, identity,
                 network, passphrase);
    /* the reference writes the identity line without a newline before it */
    break;
  default:
    return RNC_INVALID;
  }
  if (n < 0 || (size_t)n >= sizeof(text) || (size_t)n >= capacity)
    return RNC_NO_SPACE;
  memcpy(out, text, (size_t)n + 1);
  return RNC_OK;
}
static void put_key(rnc_rpc_writer *w, const char *k) { (void)rnc_rpc_write_string(w, k); }
static void put_text_or_nil(rnc_rpc_writer *w, const char *k, const char *v) {
  put_key(w, k);
  if (v[0])
    (void)rnc_rpc_write_string(w, v);
  else
    (void)rnc_rpc_write_nil(w);
}
static void put_real_or_nil(rnc_rpc_writer *w, const char *k, int has, double v) {
  put_key(w, k);
  if (has)
    (void)rnc_rpc_write_real(w, v);
  else
    (void)rnc_rpc_write_nil(w);
}
static void put_uint(rnc_rpc_writer *w, const char *k, uint64_t v) {
  put_key(w, k);
  (void)rnc_rpc_write_uint(w, v);
}
rnc_result rnc_discovery_record_pack(const rnc_discovery_record *rec,
                                     uint8_t *output, size_t capacity,
                                     size_t *written) {
  rnc_rpc_writer w;
  const rnc_discovery_info *i;
  char tid[33], nid[33], operator_hex[33];
  uint8_t dhash[32];
  kind_t kind;
  size_t pairs = 16; /* common keys, see below */
  rnc_result r;
  if (written)
    *written = 0;
  if (!rec || !output || !written)
    return RNC_INVALID;
  i = &rec->info;
  kind = kind_of(i->type);
  if (kind == T_NONE || kind == T_OTHER)
    return RNC_INVALID;
  if (rnc_discovery_hash(i, dhash) != RNC_OK)
    return RNC_CRYPTO;
  hex_text(i->transport_id, 16, tid);
  hex_text(rec->network_id, 16, nid);
  /* type, impl_name, version, transport, name, received, stamp, value,
   * transport_id, network_id, hops, latitude, longitude, height,
   * config_entry, discovery_hash */
  pairs += 3; /* discovered, last_heard, heard_count */
  pairs += i->ifac_netname[0] ? 1u : 0u;
  pairs += i->ifac_netkey[0] ? 1u : 0u;
  pairs += i->has_operator ? 1u : 0u;
  pairs += kind == T_TCP ? 2u : kind == T_I2P ? 1u : kind == T_RNODE ? 4u
         : kind == T_WEAVE ? 4u : kind == T_KISS ? 3u : 0u;
  rnc_rpc_writer_init(&w, output, capacity);
  (void)rnc_rpc_write_map(&w, pairs);
  put_key(&w, "type");
  (void)rnc_rpc_write_string(&w, i->type);
  put_text_or_nil(&w, "impl_name", i->impl_name);
  put_text_or_nil(&w, "version", i->version);
  put_key(&w, "transport");
  (void)rnc_rpc_write_bool(&w, i->transport);
  put_key(&w, "name");
  (void)rnc_rpc_write_string(&w, i->name);
  put_key(&w, "received");
  (void)rnc_rpc_write_real(&w, rec->received);
  put_key(&w, "stamp");
  (void)rnc_rpc_write_bin(&w, rec->stamp, RNC_STAMP_SIZE);
  put_uint(&w, "value", rec->value);
  put_key(&w, "transport_id");
  (void)rnc_rpc_write_string(&w, tid);
  put_key(&w, "network_id");
  (void)rnc_rpc_write_string(&w, nid);
  put_uint(&w, "hops", rec->hops);
  put_real_or_nil(&w, "latitude", i->has_latitude, i->latitude);
  put_real_or_nil(&w, "longitude", i->has_longitude, i->longitude);
  put_real_or_nil(&w, "height", i->has_height, i->height);
  if (i->ifac_netname[0]) {
    put_key(&w, "ifac_netname");
    (void)rnc_rpc_write_string(&w, i->ifac_netname);
  }
  if (i->ifac_netkey[0]) {
    put_key(&w, "ifac_netkey");
    (void)rnc_rpc_write_string(&w, i->ifac_netkey);
  }
  switch (kind) {
  case T_TCP:
    put_key(&w, "reachable_on");
    (void)rnc_rpc_write_string(&w, i->reachable_on);
    put_uint(&w, "port", i->port);
    break;
  case T_I2P:
    put_key(&w, "reachable_on");
    (void)rnc_rpc_write_string(&w, i->reachable_on);
    break;
  case T_RNODE:
    put_uint(&w, "frequency", i->frequency);
    put_uint(&w, "bandwidth", i->bandwidth);
    put_uint(&w, "sf", i->spreading_factor);
    put_uint(&w, "cr", i->coding_rate);
    break;
  case T_WEAVE:
    put_key(&w, "frequency");
    (void)rnc_rpc_write_uint(&w, i->frequency);
    put_key(&w, "bandwidth");
    (void)rnc_rpc_write_uint(&w, i->bandwidth);
    put_key(&w, "channel");
    (void)rnc_rpc_write_uint(&w, i->channel);
    put_key(&w, "modulation");
    (void)rnc_rpc_write_uint(&w, (uint64_t)strtoull(i->modulation, NULL, 10));
    break;
  case T_KISS:
    put_uint(&w, "frequency", i->frequency);
    put_uint(&w, "bandwidth", i->bandwidth);
    put_key(&w, "modulation");
    (void)rnc_rpc_write_string(&w, i->modulation);
    break;
  default:
    break;
  }
  put_key(&w, "config_entry");
  (void)rnc_rpc_write_string(&w, rec->config_entry);
  put_key(&w, "discovery_hash");
  (void)rnc_rpc_write_bin(&w, dhash, 32);
  if (i->has_operator) {
    hex_text(i->operator_address, 16, operator_hex);
    put_key(&w, "operator_lxmf_address");
    (void)rnc_rpc_write_string(&w, operator_hex);
  }
  put_key(&w, "discovered");
  (void)rnc_rpc_write_real(&w, rec->discovered);
  put_key(&w, "last_heard");
  (void)rnc_rpc_write_real(&w, rec->last_heard);
  put_uint(&w, "heard_count", rec->heard_count);
  r = rnc_rpc_writer_finish(&w, written);
  if (r != RNC_OK) {
    *written = 0;
    return r == RNC_NO_SPACE || r == RNC_INVALID ? RNC_NO_SPACE : r;
  }
  return RNC_OK;
}
static int number_value(rmp *r, double *value) {
  uint64_t bits;
  if (r->i >= r->n)
    return 0;
  if (r->p[r->i] == 0xcb) {
    r->i++;
    if (!rmp_num(r, 8, &bits))
      return 0;
    memcpy(value, &bits, 8);
    return *value == *value;
  }
  if (r->p[r->i] == 0xca) {
    uint32_t b32;
    float f;
    r->i++;
    if (!rmp_num(r, 4, &bits))
      return 0;
    b32 = (uint32_t)bits;
    memcpy(&f, &b32, 4);
    *value = f;
    return 1;
  }
  if (rmp_uint(r, &bits)) {
    *value = (double)bits;
    return 1;
  }
  return 0;
}
static int hex_bytes(const char *text, uint8_t *out, size_t n) {
  size_t i;
  if (strlen(text) != 2 * n)
    return 0;
  for (i = 0; i < n; i++) {
    unsigned v;
    if (!isxdigit((unsigned char)text[2 * i]) ||
        !isxdigit((unsigned char)text[2 * i + 1]) ||
        sscanf(text + 2 * i, "%2x", &v) != 1)
      return 0;
    out[i] = (uint8_t)v;
  }
  return 1;
}
rnc_result rnc_discovery_record_unpack(const uint8_t *data, size_t size,
                                       rnc_discovery_record *out) {
  rmp r = {data, size, 0};
  rnc_discovery_record rec;
  size_t pairs, i, n;
  uint64_t v;
  const uint8_t *p;
  char name[40], text[8];
  if (!data || !out || !size)
    return RNC_INVALID;
  memset(&rec, 0, sizeof(rec));
  if ((data[0] & 0xf0) == 0x80) {
    pairs = data[0] & 15u;
    r.i = 1;
  } else if (data[0] == 0xde) {
    r.i = 1;
    if (!rmp_num(&r, 2, &v))
      return RNC_PROTOCOL;
    pairs = (size_t)v;
  } else
    return RNC_PROTOCOL;
  (void)text;
  for (i = 0; i < pairs; i++) {
    int has, t;
    double d;
    if (!take_text(&r, name, sizeof(name)))
      return RNC_PROTOCOL;
    if (!strcmp(name, "type")) {
      if (!take_text(&r, rec.info.type, sizeof(rec.info.type)))
        return RNC_PROTOCOL;
    } else if (!strcmp(name, "impl_name") || !strcmp(name, "version")) {
      char *dst = name[0] == 'i' ? rec.info.impl_name : rec.info.version;
      size_t cap = name[0] == 'i' ? sizeof(rec.info.impl_name)
                                  : sizeof(rec.info.version);
      if (r.i < r.n && r.p[r.i] == 0xc0)
        r.i++;
      else if (!take_text(&r, dst, cap))
        return RNC_PROTOCOL;
    } else if (!strcmp(name, "transport")) {
      if (!take_bool(&r, &t))
        return RNC_PROTOCOL;
      rec.info.transport = t;
    } else if (!strcmp(name, "name")) {
      if (!take_text(&r, rec.info.name, sizeof(rec.info.name)))
        return RNC_PROTOCOL;
    } else if (!strcmp(name, "received")) {
      if (!number_value(&r, &rec.received))
        return RNC_PROTOCOL;
    } else if (!strcmp(name, "discovered")) {
      if (!number_value(&r, &rec.discovered))
        return RNC_PROTOCOL;
    } else if (!strcmp(name, "last_heard")) {
      if (!number_value(&r, &rec.last_heard))
        return RNC_PROTOCOL;
    } else if (!strcmp(name, "stamp")) {
      if (!rmp_bin(&r, &p, &n) || n != RNC_STAMP_SIZE)
        return RNC_PROTOCOL;
      memcpy(rec.stamp, p, n);
    } else if (!strcmp(name, "value") || !strcmp(name, "hops") ||
               !strcmp(name, "heard_count") || !strcmp(name, "port") ||
               !strcmp(name, "frequency") || !strcmp(name, "bandwidth") ||
               !strcmp(name, "channel") || !strcmp(name, "sf") ||
               !strcmp(name, "cr")) {
      if (!take_uint_or_nil(&r, &has, &v) || v > UINT32_MAX)
        return RNC_PROTOCOL;
      if (!strcmp(name, "value"))
        rec.value = (unsigned)v;
      else if (!strcmp(name, "hops"))
        rec.hops = (unsigned)v;
      else if (!strcmp(name, "heard_count"))
        rec.heard_count = (uint32_t)v;
      else if (!strcmp(name, "port")) {
        rec.info.has_port = has;
        rec.info.port = (uint32_t)v;
      } else if (!strcmp(name, "frequency")) {
        rec.info.has_frequency = has;
        rec.info.frequency = (uint32_t)v;
      } else if (!strcmp(name, "bandwidth")) {
        rec.info.has_bandwidth = has;
        rec.info.bandwidth = (uint32_t)v;
      } else if (!strcmp(name, "channel")) {
        rec.info.has_channel = has;
        rec.info.channel = (uint32_t)v;
      } else if (!strcmp(name, "sf"))
        rec.info.spreading_factor = (unsigned)v;
      else
        rec.info.coding_rate = (unsigned)v;
    } else if (!strcmp(name, "transport_id") || !strcmp(name, "network_id") ||
               !strcmp(name, "operator_lxmf_address")) {
      char hex[40];
      if (!take_text(&r, hex, sizeof(hex)))
        return RNC_PROTOCOL;
      if (name[0] == 't') {
        if (!hex_bytes(hex, rec.info.transport_id, 16))
          return RNC_PROTOCOL;
      } else if (name[0] == 'n') {
        if (!hex_bytes(hex, rec.network_id, 16))
          return RNC_PROTOCOL;
      } else if (hex_bytes(hex, rec.info.operator_address, 16))
        rec.info.has_operator = 1;
    } else if (!strcmp(name, "latitude")) {
      if (!take_real_or_nil(&r, &rec.info.has_latitude, &d) && rec.info.has_latitude)
        return RNC_PROTOCOL;
      rec.info.latitude = d;
    } else if (!strcmp(name, "longitude")) {
      if (!take_real_or_nil(&r, &rec.info.has_longitude, &d) && rec.info.has_longitude)
        return RNC_PROTOCOL;
      rec.info.longitude = d;
    } else if (!strcmp(name, "height")) {
      if (!take_real_or_nil(&r, &rec.info.has_height, &d) && rec.info.has_height)
        return RNC_PROTOCOL;
      rec.info.height = d;
    } else if (!strcmp(name, "ifac_netname") || !strcmp(name, "ifac_netkey")) {
      char *dst = !strcmp(name, "ifac_netname") ? rec.info.ifac_netname
                                                 : rec.info.ifac_netkey;
      if (r.i < r.n && r.p[r.i] == 0xc0)
        r.i++;
      else if (!take_text(&r, dst, 64))
        return RNC_PROTOCOL;
    } else if (!strcmp(name, "reachable_on")) {
      if (!take_text(&r, rec.info.reachable_on, sizeof(rec.info.reachable_on)))
        return RNC_PROTOCOL;
    } else if (!strcmp(name, "config_entry")) {
      if (!take_text(&r, rec.config_entry, sizeof(rec.config_entry)))
        return RNC_PROTOCOL;
    } else if (!strcmp(name, "modulation")) {
      if (r.i < r.n && r.p[r.i] == 0xc0)
        r.i++;
      else if (r.i < r.n && ((r.p[r.i] & 0xe0) == 0xa0 ||
                             (r.p[r.i] >= 0xd9 && r.p[r.i] <= 0xdb))) {
        if (!take_text(&r, rec.info.modulation, sizeof(rec.info.modulation)))
          return RNC_PROTOCOL;
        rec.info.has_modulation = 1;
      } else if (rmp_uint(&r, &v)) {
        (void)snprintf(rec.info.modulation, sizeof(rec.info.modulation), "%llu",
                       (unsigned long long)v);
        rec.info.has_modulation = 1;
      } else
        return RNC_PROTOCOL;
    } else if (!rmp_skip_depth(&r, 0))
      return RNC_PROTOCOL;
  }
  if (r.i != r.n || kind_of(rec.info.type) == T_NONE || !rec.info.name[0])
    return RNC_PROTOCOL;
  rec.info.has_frequency |= rec.info.frequency != 0;
  rec.info.has_bandwidth |= rec.info.bandwidth != 0;
  *out = rec;
  return RNC_OK;
}
int rnc_discovery_status(double delta) {
  if (delta > RNC_DISCOVERY_THRESHOLD_REMOVE)
    return -1;
  if (delta > RNC_DISCOVERY_THRESHOLD_STALE)
    return RNC_DISCOVERY_STATUS_STALE;
  if (delta > RNC_DISCOVERY_THRESHOLD_UNKNOWN)
    return RNC_DISCOVERY_STATUS_UNKNOWN;
  return RNC_DISCOVERY_STATUS_AVAILABLE;
}
