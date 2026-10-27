#include "service_msgpack.h"
#ifdef RNC_HAVE_BZIP2
#include <bzlib.h>
#endif
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <reticulum_c/rnc_log.h>
#include <reticulum_c/rnc_resource.h>
#include <stdlib.h>
#include <string.h>
#define RESOURCE_WINDOW 4u
#define RESOURCE_MIN_WINDOW 2u
#define RESOURCE_SLOW_WINDOW 10u      /* ceiling by default (WINDOW_MAX_SLOW) */
#define RESOURCE_VERY_SLOW_WINDOW 4u
#define RESOURCE_PEER_MAX_WINDOW 75u  /* WINDOW_MAX_FAST */
#define RESOURCE_WINDOW_FLEXIBILITY 4u
#define RESOURCE_FAST_ROUNDS 4u       /* FAST_RATE_THRESHOLD */
#define RESOURCE_VERY_SLOW_ROUNDS 2u
#define RESOURCE_RATE_FAST 6250u      /* bytes/s: 50 kbit/s */
#define RESOURCE_RATE_VERY_SLOW 250u  /* bytes/s: 2 kbit/s */
#define RESOURCE_PACKET_HEADER 19u
/* Timeouts, from the reference's Resource watchdog (times in ms). */
#define RESOURCE_PART_FACTOR 4u           /* until the first part arrives */
#define RESOURCE_PART_FACTOR_AFTER_RTT 2u
#define RESOURCE_RETRY_GRACE_MS 250u
#define RESOURCE_PER_RETRY_MS 500u
#define RESOURCE_TRAFFIC_FACTOR 6u        /* link traffic timeout factor */
#define RESOURCE_MAX_RETRIES 16u
#define RESOURCE_SENDER_GRACE_MS 10000u
#define RESOURCE_PROCESSING_GRACE_MS 1000u
#define RESOURCE_PROOF_FACTOR 3u
/* Link set-up bytes: request, proof and RTT packet; seeds the rate estimate */
#define RESOURCE_ESTABLISHMENT_COST 287u
#define RESOURCE_COLLISION_GUARD                                               \
  (2u * RESOURCE_PEER_MAX_WINDOW + RNC_RESOURCE_MAP_BATCH)
#define RESOURCE_LIMIT (16u * 1024u * 1024u)
enum resource_state {
  RES_IDLE,
  RES_TX_ADV,
  RES_TX_DATA,
  RES_TX_PROOF,
  RES_RX_DATA,
  RES_RX_NEXT,
  RES_DONE,
  RES_FAILED
};
typedef struct resource_adv {
  size_t transfer, total, parts, index, segments, map_size;
  unsigned flags;
  uint8_t hash[32], original[32], random[4], request[16],
      map[RNC_RESOURCE_MAP_BATCH * 4];
  int request_set;
} resource_adv;
typedef struct proof_record {
  uint8_t data[64], packet_hash[32];
} proof_record;
struct rnc_resource {
  rnc_link *link;
  rnc_random_fn random;
  void *random_context;
  size_t limit, sdu;
  enum resource_state state;
  int outgoing, compress;
  resource_adv adv;
  uint8_t *data, *wire, *map, *received, *sent, *wanted;
  size_t wire_capacity, data_size, assembled, metadata_size, metadata_prefix;
  size_t known, received_count, sent_count, window, request_end, send_cursor;
  size_t window_max, window_min, rx_bytes, rx_bytes_at_request, request_bytes;
  unsigned fast_rounds, very_slow_rounds;
  uint64_t request_sent, data_rate, response_rate;
  unsigned part_factor;
  int round_seen, waiting_hmu;
  size_t hmu_segment, receiver_min_consecutive;
  int advertise_pending, request_pending, hmu_pending, cancel_pending,
      cache_pending, proof_pending;
  uint8_t cached_proof[64], cache_hash[32];
  proof_record *proofs;
  size_t proof_count, proof_capacity;
  uint64_t now, last_activity;
  unsigned retries;
  int progress_pending, terminal_pending;
  rnc_result reason;
};
static rnc_result digest2(const void *a, size_t an, const void *b, size_t bn,
                          uint8_t out[32]) {
  EVP_MD_CTX *c = EVP_MD_CTX_new();
  unsigned n = 0;
  int ok = c && EVP_DigestInit_ex(c, EVP_sha256(), NULL) == 1 &&
           EVP_DigestUpdate(c, a, an) == 1 && EVP_DigestUpdate(c, b, bn) == 1 &&
           EVP_DigestFinal_ex(c, out, &n) == 1 && n == 32;
  EVP_MD_CTX_free(c);
  return ok ? RNC_OK : RNC_CRYPTO;
}
static void clear_segment(rnc_resource *r) {
  if (r->wire) {
    OPENSSL_cleanse(r->wire, r->wire_capacity);
    free(r->wire);
  }
  free(r->map);
  free(r->received);
  free(r->sent);
  free(r->wanted);
  r->wire = r->map = r->received = r->sent = r->wanted = NULL;
  r->wire_capacity = r->known = r->received_count = r->sent_count = 0;
  r->advertise_pending = r->request_pending = r->hmu_pending =
      r->cache_pending = 0;
  r->send_cursor = r->receiver_min_consecutive = 0;
}
static void clear_transfer(rnc_resource *r) {
  clear_segment(r);
  if (r->data) {
    OPENSSL_cleanse(r->data, r->data_size);
    free(r->data);
  }
  r->data = NULL;
  r->data_size = r->assembled = r->metadata_size = r->metadata_prefix = 0;
  r->proof_count = 0;
  r->progress_pending = r->terminal_pending = r->proof_pending =
      r->cancel_pending = 0;
  r->retries = 0;
  r->reason = RNC_OK;
}
/* What the next incoming resource on this link starts from. */
static void remember_receive_state(const rnc_resource *r) {
  rnc_link_set_last_resource_window(r->link, r->window);
  if (r->data_rate)
    rnc_link_set_last_resource_eifr(r->link, r->data_rate * 8u);
}
static void fail(rnc_resource *r, rnc_result reason, int notify) {
  rnc_logf(RNC_LOG_WARNING, "resource", "%s transfer failed (reason %d, %zu of %zu parts)",
           r->outgoing ? "outgoing" : "incoming", (int)reason, r->received_count,
           r->adv.parts);
  if (!r->outgoing && r->window)
    remember_receive_state(r);
  r->state = RES_FAILED;
  r->reason = reason;
  r->terminal_pending = 1;
  r->progress_pending = 0;
  r->cancel_pending = notify;
  r->advertise_pending = r->request_pending = r->hmu_pending =
      r->cache_pending = r->proof_pending = 0;
  if (r->wanted)
    memset(r->wanted, 0, r->adv.parts);
}
static int active(const rnc_resource *r) {
  return r->state != RES_IDLE && r->state != RES_DONE && r->state != RES_FAILED;
}
static rnc_result parse_adv(const uint8_t *data, size_t size, resource_adv *a) {
  rmp p = {data, size, 0};
  const uint8_t *key, *v;
  size_t n, i, j;
  uint64_t x;
  unsigned fields = 0, bit;
  resource_adv q = {0};
  if (!data || !size || size > RNC_LINK_MDU || data[p.i++] != 0x8b)
    return RNC_PROTOCOL;
  for (i = 0; i < 11; i++) {
    if (!rmp_len(&p, 1, &n) || n != 1 || !rmp_take(&p, 1, &key))
      return RNC_PROTOCOL;
    switch (*key) {
    case 't':
      bit = 0;
      break;
    case 'd':
      bit = 1;
      break;
    case 'n':
      bit = 2;
      break;
    case 'h':
      bit = 3;
      break;
    case 'r':
      bit = 4;
      break;
    case 'o':
      bit = 5;
      break;
    case 'i':
      bit = 6;
      break;
    case 'l':
      bit = 7;
      break;
    case 'q':
      bit = 8;
      break;
    case 'f':
      bit = 9;
      break;
    case 'm':
      bit = 10;
      break;
    default:
      return RNC_PROTOCOL;
    }
    if (fields & (1u << bit))
      return RNC_PROTOCOL;
    fields |= 1u << bit;
    if (bit == 3 || bit == 4 || bit == 5 || bit == 10) {
      if (!rmp_bin(&p, &v, &n))
        return RNC_PROTOCOL;
      if (bit == 3 || bit == 5) {
        if (n != 32)
          return RNC_PROTOCOL;
        memcpy(bit == 3 ? q.hash : q.original, v, 32);
      } else if (bit == 4) {
        if (n != 4)
          return RNC_PROTOCOL;
        memcpy(q.random, v, 4);
      } else {
        if (n > sizeof(q.map) || n % 4)
          return RNC_PROTOCOL;
        q.map_size = n;
        memcpy(q.map, v, n);
      }
    } else if (bit == 8) {
      if (p.i < p.n && p.p[p.i] == 0xc0)
        p.i++;
      else {
        if (!rmp_bin(&p, &v, &n) || n != 16)
          return RNC_PROTOCOL;
        memcpy(q.request, v, 16);
        q.request_set = 1;
      }
    } else {
      if (!rmp_uint(&p, &x) || x > SIZE_MAX)
        return RNC_PROTOCOL;
      switch (bit) {
      case 0:
        q.transfer = (size_t)x;
        break;
      case 1:
        q.total = (size_t)x;
        break;
      case 2:
        q.parts = (size_t)x;
        break;
      case 6:
        q.index = (size_t)x;
        break;
      case 7:
        q.segments = (size_t)x;
        break;
      case 9:
        if (x > 63)
          return RNC_PROTOCOL;
        q.flags = (unsigned)x;
        break;
      default:
        return RNC_PROTOCOL;
      }
    }
  }
  if (p.i != size || fields != 0x7ff || !(q.flags & 1) ||
      ((q.flags & 24) == 24) || ((q.flags & 24) != 0) != q.request_set ||
      q.transfer < 64 || q.transfer > RNC_RESOURCE_SEGMENT_MAX + 68u ||
      !q.parts ||
      q.parts > (q.transfer + RNC_RESOURCE_SDU - 1u) / RNC_RESOURCE_SDU ||
      q.parts <
          (q.transfer + RNC_RESOURCE_MAX_SDU - 1u) / RNC_RESOURCE_MAX_SDU ||
      !q.index || !q.segments || q.index > q.segments ||
      q.segments !=
          1u + (q.total ? q.total - 1u : 0u) / RNC_RESOURCE_SEGMENT_MAX ||
      ((q.flags & 4) != 0) != (q.segments > 1) ||
      q.map_size != 4u * (q.parts < RNC_RESOURCE_MAP_BATCH
                              ? q.parts
                              : RNC_RESOURCE_MAP_BATCH) ||
      ((q.flags & 32) && q.total < 4))
    return RNC_PROTOCOL;
  size_t segment_size = q.total - (q.index - 1u) * RNC_RESOURCE_SEGMENT_MAX;
  if (segment_size > RNC_RESOURCE_SEGMENT_MAX)
    segment_size = RNC_RESOURCE_SEGMENT_MAX;
  size_t maximum_wire = 48u + ((segment_size + 4u) / 16u + 1u) * 16u;
  if (q.transfer > maximum_wire ||
      (!(q.flags & 2u) && q.transfer != maximum_wire))
    return RNC_PROTOCOL;
  if (q.index == 1 && CRYPTO_memcmp(q.hash, q.original, 32))
    return RNC_PROTOCOL;
  for (i = 0; i < q.map_size / 4; i++)
    for (j = 0; j < i; j++)
      if (!memcmp(q.map + 4 * i, q.map + 4 * j, 4))
        return RNC_PROTOCOL;
  *a = q;
  return RNC_OK;
}
static size_t pack_adv(const resource_adv *a, uint8_t out[RNC_LINK_MDU]) {
  uint8_t b[512];
  size_t n = 0;
  b[n++] = 0x8b;
#define K(c)                                                                   \
  do {                                                                         \
    b[n++] = 0xa1;                                                             \
    b[n++] = (uint8_t)(c);                                                     \
  } while (0)
#define U(c, v)                                                                \
  do {                                                                         \
    K(c);                                                                      \
    n += rmp_put_uint(b + n, (v));                                             \
  } while (0)
#define B(c, p, z)                                                             \
  do {                                                                         \
    K(c);                                                                      \
    n += rmp_put_bin(b + n, (p), (z));                                         \
  } while (0)
  U('t', a->transfer);
  U('d', a->total);
  U('n', a->parts);
  B('h', a->hash, 32);
  B('r', a->random, 4);
  B('o', a->original, 32);
  U('i', a->index);
  U('l', a->segments);
  K('q');
  if (a->request_set)
    n += rmp_put_bin(b + n, a->request, 16);
  else
    b[n++] = 0xc0;
  U('f', a->flags);
  B('m', a->map, a->map_size);
#undef K
#undef U
#undef B
  if (n > RNC_LINK_MDU)
    return 0;
  memcpy(out, b, n);
  return n;
}
static rnc_result allocate_segment(rnc_resource *r, size_t wire_size,
                                   size_t parts) {
  r->wire = calloc(wire_size ? wire_size : 1, 1);
  r->map = calloc(parts, 4);
  r->received = calloc(parts, 1);
  r->sent = calloc(parts, 1);
  r->wanted = calloc(parts, 1);
  if (!r->wire || !r->map || !r->received || !r->sent || !r->wanted) {
    clear_segment(r);
    return RNC_NO_SPACE;
  }
  r->wire_capacity = wire_size;
  return RNC_OK;
}
static rnc_result prepare_segment(rnc_resource *r) {
  size_t off = (r->adv.index - 1u) * RNC_RESOURCE_SEGMENT_MAX,
         len = r->data_size - off, n, compressed_n, parts, i, j;
#ifdef RNC_HAVE_BZIP2
  unsigned int bzsize;
#endif
  uint8_t *packed, *compressed, digest[32], random_prefix[4];
  rnc_result result;
  unsigned retry;
  if (len > RNC_RESOURCE_SEGMENT_MAX)
    len = RNC_RESOURCE_SEGMENT_MAX;
  clear_segment(r);
  packed = malloc(len + 4u);
  compressed = malloc(len + len / 100u + 601u);
  if (!packed || !compressed) {
    free(packed);
    free(compressed);
    return RNC_NO_SPACE;
  }
  compressed_n = len;
#ifdef RNC_HAVE_BZIP2
  if (r->compress && len) {
    bzsize = (unsigned int)(len + len / 100u + 601u);
    if (BZ2_bzBuffToBuffCompress((char *)compressed, &bzsize,
                                 (char *)r->data + off, (unsigned int)len, 9, 0,
                                 30) == BZ_OK &&
        bzsize < len)
      compressed_n = bzsize;
  }
#endif
  if (compressed_n < len) {
    r->adv.flags |= 2;
    memcpy(packed + 4, compressed, compressed_n);
  } else {
    r->adv.flags &= ~2u;
    memcpy(packed + 4, r->data + off, len);
  }
  result = r->random(r->random_context, random_prefix, 4);
  if (result != RNC_OK)
    goto done;
  memcpy(packed, random_prefix, 4);
  n = 48u + ((compressed_n + 4u) / 16u + 1u) * 16u;
  parts = (n + r->sdu - 1u) / r->sdu;
  result = allocate_segment(r, n, parts);
  if (result != RNC_OK)
    goto done;
  result = rnc_link_encrypt(r->link, packed, compressed_n + 4u, r->wire, n, &n);
  if (result != RNC_OK)
    goto done;
  r->adv.transfer = n;
  r->adv.parts = parts;
  r->adv.map_size =
      4u * (parts < RNC_RESOURCE_MAP_BATCH ? parts : RNC_RESOURCE_MAP_BATCH);
  for (retry = 0; retry < 8; retry++) {
    result = r->random(r->random_context, r->adv.random, 4);
    if (result != RNC_OK)
      goto done;
    result = digest2(r->data + off, len, r->adv.random, 4, r->adv.hash);
    if (result != RNC_OK)
      goto done;
    for (i = 0; i < parts; i++) {
      size_t z = n - i * r->sdu;
      if (z > r->sdu)
        z = r->sdu;
      result = digest2(r->wire + i * r->sdu, z, r->adv.random, 4, digest);
      if (result != RNC_OK)
        goto done;
      for (j = i > RESOURCE_COLLISION_GUARD ? i - RESOURCE_COLLISION_GUARD : 0;
           j < i; j++)
        if (!memcmp(digest, r->map + 4 * j, 4))
          break;
      if (j < i)
        break;
      memcpy(r->map + 4 * i, digest, 4);
    }
    if (i == parts)
      break;
  }
  if (retry == 8) {
    result = RNC_CRYPTO;
    goto done;
  }
  if (r->adv.index == 1)
    memcpy(r->adv.original, r->adv.hash, 32);
  memcpy(r->adv.map, r->map, r->adv.map_size);
  r->known = parts;
  r->advertise_pending = 1;
  r->state = RES_TX_ADV;
  r->window = RESOURCE_WINDOW;
  r->retries = 0;
  result = RNC_OK;
done:
  OPENSSL_cleanse(packed, len + 4u);
  free(packed);
  free(compressed);
  return result;
}
rnc_resource *rnc_resource_new(rnc_link *link, size_t max_size,
                               rnc_random_fn random, void *ctx) {
  rnc_resource *r;
  if (!link || !random || max_size > RESOURCE_LIMIT)
    return NULL;
  if (!max_size)
    max_size = RNC_RESOURCE_DEFAULT_LIMIT;
  r = calloc(1, sizeof(*r));
  if (!r)
    return NULL;
  r->link = link;
  r->sdu = rnc_link_mtu(link) - 36u;
  r->limit = max_size;
  r->random = random;
  r->random_context = ctx;
  r->proof_capacity =
      (max_size + RNC_RESOURCE_SEGMENT_MAX - 1u) / RNC_RESOURCE_SEGMENT_MAX;
  r->proofs = calloc(r->proof_capacity, sizeof(*r->proofs));
  if (!r->proofs) {
    free(r);
    return NULL;
  }
  return r;
}
void rnc_resource_free(rnc_resource *r) {
  if (r) {
    clear_transfer(r);
    free(r->proofs);
    OPENSSL_cleanse(r, sizeof(*r));
    free(r);
  }
}
static rnc_result resource_send_prepared(rnc_resource *r, const void *data,
                                         size_t size,
                                         const rnc_resource_options *o,
                                         uint64_t now) {
  rnc_resource_options empty = {0};
  rnc_result result;
  size_t prefix;
  if (!r || (!data && size) || now < r->now)
    return RNC_INVALID;
  if (active(r))
    return RNC_AGAIN;
  if (!rnc_link_is_active(r->link))
    return RNC_STATE;
  if (!o)
    o = &empty;
  if (o->metadata_size && (!o->metadata || o->metadata_size > 0xffffffu ||
                           !rmp_value(o->metadata, o->metadata_size)))
    return RNC_INVALID;
#ifndef RNC_HAVE_BZIP2
  if (o->compress)
    return RNC_UNSUPPORTED;
#endif
  prefix = o->metadata_size ? o->metadata_size + 3u : 0;
  if (size > r->limit || prefix > r->limit - size)
    return RNC_NO_SPACE;
  clear_transfer(r);
  r->sdu = rnc_link_mtu(r->link) - 36u;
  memset(&r->adv, 0, sizeof(r->adv));
  r->data_size = size + prefix;
  r->data = malloc(r->data_size ? r->data_size : 1);
  if (!r->data)
    return RNC_NO_SPACE;
  if (prefix) {
    r->data[0] = (uint8_t)(o->metadata_size >> 16);
    r->data[1] = (uint8_t)(o->metadata_size >> 8);
    r->data[2] = (uint8_t)o->metadata_size;
    memcpy(r->data + 3, o->metadata, o->metadata_size);
  }
  if (size)
    memcpy(r->data + prefix, data, size);
  r->outgoing = 1;
  r->compress = o->compress;
  r->adv.total = r->data_size;
  r->adv.index = 1;
  r->adv.segments =
      ((r->data_size ? r->data_size : 1) + RNC_RESOURCE_SEGMENT_MAX - 1u) /
      RNC_RESOURCE_SEGMENT_MAX;
  r->adv.flags = 1u | (o->compress ? 2u : 0u) |
                 (r->adv.segments > 1 ? 4u : 0u) | (prefix ? 32u : 0u);
  if (o->request_id) {
    memcpy(r->adv.request, o->request_id, 16);
    r->adv.request_set = 1;
    r->adv.flags |= o->is_response ? 16u : 8u;
  }
  result = prepare_segment(r);
  if (result != RNC_OK) {
    clear_transfer(r);
    r->state = RES_IDLE;
    return result;
  }
  r->now = r->last_activity = now;
  return RNC_OK;
}
static rnc_result resource_accept_prepared(rnc_resource *r, const uint8_t *data,
                                           size_t size, uint64_t now) {
  resource_adv a;
  rnc_result result;
  int next;
  if (!r || now < r->now)
    return RNC_INVALID;
  result = parse_adv(data, size, &a);
  if (result != RNC_OK)
    return result;
#ifndef RNC_HAVE_BZIP2
  if (a.flags & 2)
    return RNC_UNSUPPORTED;
#endif
  size_t negotiated_sdu = rnc_link_mtu(r->link) - 36u;
  if (a.parts != (a.transfer + negotiated_sdu - 1u) / negotiated_sdu)
    return RNC_PROTOCOL;
  if (a.total > r->limit)
    return RNC_NO_SPACE;
  if (!rnc_link_is_active(r->link))
    return RNC_STATE;
  if (!r->outgoing &&
      (r->state == RES_RX_DATA || r->state == RES_RX_NEXT ||
       r->state == RES_DONE) &&
      !memcmp(a.hash, r->adv.hash, 32)) {
    if (r->state == RES_RX_DATA)
      r->request_pending = 1;
    else {
      memcpy(r->cached_proof, r->proofs[r->proof_count - 1].data, 64);
      r->proof_pending = 1;
    }
    r->now = now;
    return RNC_OK;
  }
  next = r->state == RES_RX_NEXT;
  if (next) {
    if (a.index != r->adv.index + 1u || a.total != r->adv.total ||
        a.segments != r->adv.segments ||
        memcmp(a.original, r->adv.original, 32) ||
        a.request_set != r->adv.request_set ||
        ((a.flags ^ r->adv.flags) & (4u | 8u | 16u | 32u)) ||
        (a.request_set && memcmp(a.request, r->adv.request, 16)))
      return RNC_PROTOCOL;
  } else {
    if (active(r))
      return RNC_AGAIN;
    if (a.index != 1)
      return RNC_PROTOCOL;
  }
  if (next)
    clear_segment(r);
  else {
    clear_transfer(r);
    r->data = malloc(a.total ? a.total : 1);
    if (!r->data)
      return RNC_NO_SPACE;
    r->data_size = a.total;
  }
  result = allocate_segment(r, a.transfer, a.parts);
  if (result != RNC_OK) {
    fail(r, result, 0);
    return result;
  }
  r->sdu = negotiated_sdu;
  r->adv = a;
  r->outgoing = 0;
  r->known = a.map_size / 4;
  memcpy(r->map, a.map, a.map_size);
  r->window = rnc_link_last_resource_window(r->link);
  if (!r->window)
    r->window = RESOURCE_WINDOW;
  r->window_max = RESOURCE_SLOW_WINDOW;
  r->window_min = RESOURCE_MIN_WINDOW;
  r->fast_rounds = r->very_slow_rounds = 0;
  r->rx_bytes = r->rx_bytes_at_request = 0;
  r->round_seen = 0;
  r->data_rate = r->response_rate = 0;
  r->part_factor = RESOURCE_PART_FACTOR;
  r->waiting_hmu = 0;
  r->request_pending = 1;
  r->state = RES_RX_DATA;
  r->now = r->last_activity = now;
  r->retries = 0;
  return RNC_OK;
}
/* Prepare new transfers separately so allocation/crypto failures leave an old
 * completed transfer readable and its receipt cache intact. */
static void commit_transfer(rnc_resource *r, rnc_resource *prepared) {
  rnc_resource old = *r;
  *r = *prepared;
  *prepared = old;
  rnc_resource_free(prepared);
}
rnc_result rnc_resource_send(rnc_resource *r, const void *data, size_t size,
                             const rnc_resource_options *options,
                             uint64_t now) {
  rnc_resource *prepared;
  rnc_result result;
  if (!r || now < r->now)
    return RNC_INVALID;
  if (active(r))
    return RNC_AGAIN;
  prepared = rnc_resource_new(r->link, r->limit, r->random, r->random_context);
  if (!prepared)
    return RNC_NO_SPACE;
  prepared->now = r->now;
  result = resource_send_prepared(prepared, data, size, options, now);
  if (result == RNC_OK)
    commit_transfer(r, prepared);
  else
    rnc_resource_free(prepared);
  return result;
}
rnc_result rnc_resource_accept(rnc_resource *r, const uint8_t *data,
                               size_t size, uint64_t now) {
  resource_adv a;
  rnc_resource *prepared;
  rnc_result result;
  if (!r || now < r->now)
    return RNC_INVALID;
  result = parse_adv(data, size, &a);
  if (result != RNC_OK)
    return result;
  if (active(r) || (!r->outgoing && r->state == RES_DONE &&
                    !memcmp(a.hash, r->adv.hash, 32)))
    return resource_accept_prepared(r, data, size, now);
  prepared = rnc_resource_new(r->link, r->limit, r->random, r->random_context);
  if (!prepared)
    return RNC_NO_SPACE;
  prepared->now = r->now;
  result = resource_accept_prepared(prepared, data, size, now);
  if (result == RNC_OK)
    commit_transfer(r, prepared);
  else
    rnc_resource_free(prepared);
  return result;
}
static rnc_result proof_hash(rnc_resource *r, const uint8_t data[64],
                             uint8_t hash[32]) {
  rnc_packet p = {0};
  p.flags = 15;
  p.context = 5;
  p.data_size = 64;
  memcpy(p.data, data, 64);
  if (rnc_link_address(r->link, p.destination) != RNC_OK)
    return RNC_STATE;
  return rnc_packet_hash(&p, hash);
}
static rnc_result finish_segment(rnc_resource *r) {
  uint8_t *plain, *uncompressed, digest[32], proof[64];
  size_t n = 0, len, expected = r->data_size - r->assembled;
#ifdef RNC_HAVE_BZIP2
  unsigned int cap;
#endif
  rnc_result result;
  if (expected > RNC_RESOURCE_SEGMENT_MAX)
    expected = RNC_RESOURCE_SEGMENT_MAX;
  plain = malloc(r->adv.transfer);
  uncompressed = malloc(expected ? expected : 1);
  if (!plain || !uncompressed) {
    free(plain);
    free(uncompressed);
    return RNC_NO_SPACE;
  }
  result = rnc_link_decrypt(r->link, r->wire, r->adv.transfer, plain,
                            r->adv.transfer, &n);
  if (result != RNC_OK)
    goto done;
  if (n < 4) {
    result = RNC_AUTH;
    goto done;
  }
  if (r->adv.flags & 2) {
#ifdef RNC_HAVE_BZIP2
    cap = (unsigned int)expected;
    int bz = BZ2_bzBuffToBuffDecompress((char *)uncompressed, &cap,
                                        (char *)plain + 4,
                                        (unsigned int)(n - 4), 0, 0);
    if (bz != BZ_OK || cap != expected) {
      result = RNC_AUTH;
      goto done;
    }
    len = cap;
#else
    result = RNC_UNSUPPORTED;
    goto done;
#endif
  } else {
    len = n - 4;
    if (len != expected) {
      result = RNC_AUTH;
      goto done;
    }
    if (len)
      memcpy(uncompressed, plain + 4, len);
  }
  result = digest2(uncompressed, len, r->adv.random, 4, digest);
  if (result != RNC_OK)
    goto done;
  if (CRYPTO_memcmp(digest, r->adv.hash, 32)) {
    result = RNC_AUTH;
    goto done;
  }
  memcpy(proof, r->adv.hash, 32);
  result = digest2(uncompressed, len, r->adv.hash, 32, proof + 32);
  if (result != RNC_OK)
    goto done;
  if (r->proof_count == r->proof_capacity) {
    result = RNC_NO_SPACE;
    goto done;
  }
  memcpy(r->proofs[r->proof_count].data, proof, 64);
  result = proof_hash(r, proof, r->proofs[r->proof_count].packet_hash);
  if (result != RNC_OK)
    goto done;
  if (len)
    memcpy(r->data + r->assembled, uncompressed, len);
  r->assembled += len;
  r->proof_count++;
  memcpy(r->cached_proof, proof, 64);
  r->proof_pending = 1;
  r->request_pending = 0;
  r->state = RES_RX_NEXT;
  if (r->adv.index == r->adv.segments) {
    if (r->assembled != r->data_size) {
      result = RNC_AUTH;
      goto done;
    }
    if (r->adv.flags & 32) {
      if (r->data_size < 3) {
        result = RNC_PROTOCOL;
        goto done;
      }
      r->metadata_size =
          ((size_t)r->data[0] << 16) | ((size_t)r->data[1] << 8) | r->data[2];
      if (!r->metadata_size || r->metadata_size > r->data_size - 3u ||
          !rmp_value(r->data + 3, r->metadata_size)) {
        result = RNC_PROTOCOL;
        goto done;
      }
      r->metadata_prefix = r->metadata_size + 3u;
    }
    r->state = RES_DONE;
    r->terminal_pending = 1;
    r->reason = RNC_OK;
  }
  result = RNC_OK;
done:
  OPENSSL_cleanse(plain, r->adv.transfer);
  free(plain);
  OPENSSL_cleanse(uncompressed, expected);
  free(uncompressed);
  return result;
}
static rnc_result handle_part(rnc_resource *r, const uint8_t *data,
                              size_t size) {
  uint8_t digest[32];
  size_t i, expected;
  rnc_result result;
  if (r->outgoing || !(r->state == RES_RX_DATA || r->state == RES_RX_NEXT ||
                       r->state == RES_DONE))
    return RNC_AGAIN;
  if (!size || size > r->sdu)
    return RNC_PROTOCOL;
  result = digest2(data, size, r->adv.random, 4, digest);
  if (result != RNC_OK)
    return result;
  size_t start = 0, end;
  if (r->state == RES_RX_DATA) {
    while (start < r->known && r->received[start])
      start++;
  } else
    start = r->known > r->window ? r->known - r->window : 0;
  end = start + r->window;
  if (end > r->known)
    end = r->known;
  for (i = start; i < end; i++)
    if (!memcmp(digest, r->map + 4 * i, 4))
      break;
  if (i == end)
    return RNC_AGAIN;
  if (r->state != RES_RX_DATA) {
    memcpy(r->cached_proof, r->proofs[r->proof_count - 1u].data, 64);
    r->proof_pending = 1;
    return RNC_OK;
  }
  expected = r->adv.transfer - i * r->sdu;
  if (expected > r->sdu)
    expected = r->sdu;
  if (size != expected)
    return RNC_PROTOCOL;
  if (r->received[i])
    return memcmp(r->wire + i * r->sdu, data, size) ? RNC_PROTOCOL : RNC_OK;
  memcpy(r->wire + i * r->sdu, data, size);
  r->received[i] = 1;
  r->received_count++;
  r->rx_bytes += size;
  r->progress_pending = 1;
  r->retries = 0;
  if (!r->round_seen) {
    /* first part of a round: request and part size over the time between them */
    uint64_t rtt = r->now > r->request_sent ? r->now - r->request_sent : 0;
    r->round_seen = 1;
    r->part_factor = RESOURCE_PART_FACTOR_AFTER_RTT;
    if (rtt && r->request_sent) {
      size_t rate = ((RESOURCE_PACKET_HEADER + size + r->request_bytes) * 1000u) / rtt;
      r->response_rate = rate ? rate : 1;
      if (rate > RESOURCE_RATE_FAST && r->fast_rounds < RESOURCE_FAST_ROUNDS &&
          ++r->fast_rounds == RESOURCE_FAST_ROUNDS)
        r->window_max = RESOURCE_PEER_MAX_WINDOW;
    }
  }
  if (r->received_count == r->adv.parts) {
    remember_receive_state(r);
    result = finish_segment(r);
    if (result != RNC_OK)
      fail(r, result, 1);
    return result;
  }
  for (i = 0; i < r->request_end; i++)
    if (!r->received[i])
      break;
  if (i == r->request_end) {
    uint64_t rtt = r->now > r->request_sent ? r->now - r->request_sent : 0;
    r->request_pending = 1;
    if (r->window < r->window_max) {
      r->window++;
      if (r->window - r->window_min > RESOURCE_WINDOW_FLEXIBILITY - 1)
        r->window_min++;
    }
    if (rtt && r->request_sent) {
      size_t rate = (size_t)(((r->rx_bytes - r->rx_bytes_at_request) * 1000u) / rtt);
      r->data_rate = rate ? rate : 1;
      if (rate > RESOURCE_RATE_FAST && r->fast_rounds < RESOURCE_FAST_ROUNDS &&
          ++r->fast_rounds == RESOURCE_FAST_ROUNDS)
        r->window_max = RESOURCE_PEER_MAX_WINDOW;
      if (!r->fast_rounds && rate < RESOURCE_RATE_VERY_SLOW &&
          r->very_slow_rounds < RESOURCE_VERY_SLOW_ROUNDS &&
          ++r->very_slow_rounds == RESOURCE_VERY_SLOW_ROUNDS)
        r->window_max = RESOURCE_VERY_SLOW_WINDOW;
    }
  }
  return RNC_OK;
}
static rnc_result handle_request(rnc_resource *r, const uint8_t *p, size_t n) {
  size_t pad, i, j, k, count, parts[100],
      segment = 0, search_start = r->receiver_min_consecutive, search_end;
  int hmu;
  if (!r->outgoing || !(r->state == RES_TX_ADV || r->state == RES_TX_DATA ||
                        r->state == RES_TX_PROOF))
    return RNC_AGAIN;
  if (n < 33 || (p[0] != 0 && p[0] != 255))
    return RNC_PROTOCOL;
  hmu = p[0] == 255;
  pad = hmu ? 5 : 1;
  if (n < pad + 32 || (n - pad - 32) % 4)
    return RNC_PROTOCOL;
  if (CRYPTO_memcmp(p + pad, r->adv.hash, 32))
    return RNC_AGAIN;
  count = (n - pad - 32) / 4;
  if (count > 100)
    return RNC_PROTOCOL;
  search_end = search_start + RESOURCE_COLLISION_GUARD;
  if (search_end > r->adv.parts)
    search_end = r->adv.parts;
  for (i = 0; i < count; i++) {
    for (j = search_start; j < search_end; j++)
      if (!memcmp(p + pad + 32 + 4 * i, r->map + 4 * j, 4))
        break;
    if (j == search_end)
      return RNC_PROTOCOL;
    for (k = 0; k < i; k++)
      if (parts[k] == j)
        return RNC_PROTOCOL;
    parts[i] = j;
  }
  if (hmu) {
    for (j = search_start; j < search_end; j++)
      if (!memcmp(p + 1, r->map + 4 * j, 4))
        break;
    if (j == search_end || (j + 1u) % RNC_RESOURCE_MAP_BATCH ||
        j + 1u == r->adv.parts)
      return RNC_PROTOCOL;
    segment = (j + 1u) / RNC_RESOURCE_MAP_BATCH;
    if (r->hmu_pending && r->hmu_segment != segment)
      return RNC_AGAIN;
  }
  for (i = 0; i < count; i++)
    r->wanted[parts[i]] = 1;
  if (hmu) {
    r->hmu_pending = 1;
    r->hmu_segment = segment;
    size_t minimum = segment * RNC_RESOURCE_MAP_BATCH - 1u;
    minimum = minimum > RESOURCE_PEER_MAX_WINDOW
                  ? minimum - RESOURCE_PEER_MAX_WINDOW
                  : 0;
    if (minimum > r->receiver_min_consecutive)
      r->receiver_min_consecutive = minimum;
  }
  r->state = RES_TX_DATA;
  r->advertise_pending = 0;
  r->retries = 0;
  return RNC_OK;
}
static rnc_result handle_hmu(rnc_resource *r, const uint8_t *p, size_t n) {
  rmp m;
  const uint8_t *map;
  size_t count, start, i, j;
  uint64_t seg;
  if (r->outgoing || r->state != RES_RX_DATA)
    return RNC_AGAIN;
  if (n < 36)
    return RNC_PROTOCOL;
  if (CRYPTO_memcmp(p, r->adv.hash, 32))
    return RNC_AGAIN;
  m.p = p + 32;
  m.n = n - 32;
  m.i = 0;
  if (m.p[m.i++] != 0x92 || !rmp_uint(&m, &seg) || !rmp_bin(&m, &map, &count) ||
      m.i != m.n || !count || count % 4 || count > 4 * RNC_RESOURCE_MAP_BATCH ||
      seg > SIZE_MAX / RNC_RESOURCE_MAP_BATCH)
    return RNC_PROTOCOL;
  start = (size_t)seg * RNC_RESOURCE_MAP_BATCH;
  count /= 4;
  if (start > r->adv.parts || count > r->adv.parts - start)
    return RNC_PROTOCOL;
  if (start < r->known) {
    if (count > r->known - start ||
        CRYPTO_memcmp(r->map + 4 * start, map, 4 * count))
      return RNC_PROTOCOL;
    r->request_pending = 1;
    return RNC_OK;
  }
  if (start != r->known)
    return RNC_PROTOCOL;
  for (i = 0; i < count; i++)
    for (j = start + i > 224 ? start + i - 224 : 0; j < start + i; j++)
      if (!memcmp(map + 4 * i,
                  j < start ? r->map + 4 * j : map + 4 * (j - start), 4))
        return RNC_PROTOCOL;
  memcpy(r->map + 4 * start, map, 4 * count);
  r->known += count;
  r->request_pending = 1;
  r->retries = 0;
  r->waiting_hmu = 0;
  return RNC_OK;
}
rnc_result rnc_resource_input(rnc_resource *r, const rnc_link_event *e,
                              uint64_t now) {
  const uint8_t *p;
  size_t n, i;
  rnc_result result = RNC_AGAIN;
  uint8_t context;
  if (!r || !e || now < r->now)
    return RNC_INVALID;
  if (e->type == RNC_LINK_CLOSED) {
    if (active(r))
      fail(r, e->reason == RNC_OK ? RNC_STATE : e->reason, 0);
    return RNC_OK;
  }
  if (e->type != RNC_LINK_PACKET && e->type != RNC_LINK_RESOURCE_PACKET)
    return RNC_AGAIN;
  context = e->context;
  p = e->type == RNC_LINK_PACKET ? e->data : e->packet.data;
  n = e->type == RNC_LINK_PACKET ? e->size : e->packet.data_size;
  if (context == 1 && e->type == RNC_LINK_RESOURCE_PACKET &&
      ((e->packet.flags & 3u) == RNC_DATA))
    result = handle_part(r, p, n);
  else if (context == 3 && e->type == RNC_LINK_PACKET)
    result = handle_request(r, p, n);
  else if (context == 4 && e->type == RNC_LINK_PACKET)
    result = handle_hmu(r, p, n);
  else if (context == 5 && e->type == RNC_LINK_RESOURCE_PACKET &&
           ((e->packet.flags & 3u) == RNC_PROOF)) {
    uint8_t expected[32];
    size_t off, len;
    if (!r->outgoing || !active(r))
      return RNC_AGAIN;
    if (n != 64)
      return RNC_PROTOCOL;
    if (CRYPTO_memcmp(p, r->adv.hash, 32))
      return RNC_AGAIN;
    off = (r->adv.index - 1u) * RNC_RESOURCE_SEGMENT_MAX;
    len = r->data_size - off;
    if (len > RNC_RESOURCE_SEGMENT_MAX)
      len = RNC_RESOURCE_SEGMENT_MAX;
    result = digest2(r->data + off, len, r->adv.hash, 32, expected);
    if (result != RNC_OK)
      return result;
    if (CRYPTO_memcmp(expected, p + 32, 32))
      return RNC_AUTH;
    r->assembled = off + len;
    if (r->adv.index < r->adv.segments) {
      r->adv.index++;
      result = prepare_segment(r);
      if (result != RNC_OK)
        fail(r, result, 1);
    } else {
      r->state = RES_DONE;
      r->terminal_pending = 1;
      r->progress_pending = 0;
      r->reason = RNC_OK;
      result = RNC_OK;
    }
  } else if (context == 8 && e->type == RNC_LINK_RESOURCE_PACKET) {
    if (n != 32)
      return RNC_PROTOCOL;
    for (i = 0; i < r->proof_count; i++)
      if (!CRYPTO_memcmp(p, r->proofs[i].packet_hash, 32)) {
        memcpy(r->cached_proof, r->proofs[i].data, 64);
        r->proof_pending = 1;
        result = RNC_OK;
        break;
      }
  } else if ((context == 6 || context == 7) && e->type == RNC_LINK_PACKET) {
    if (n != 32)
      return RNC_PROTOCOL;
    if (!active(r) || r->outgoing != (context == 7) ||
        CRYPTO_memcmp(p, r->adv.hash, 32))
      return RNC_AGAIN;
    fail(r, RNC_STATE, 0);
    result = RNC_OK;
  }
  if (result == RNC_OK) {
    r->now = r->last_activity = now;
  }
  return result;
}
static rnc_result send_request(rnc_resource *r, uint64_t now) {
  uint8_t p[RNC_LINK_MDU];
  size_t i, start = 0, n = 1, count = 0, last = 0;
  int hmu = 0;
  rnc_result result;
  while (start < r->adv.parts && r->received[start])
    start++;
  for (i = start; i < r->adv.parts && i < start + r->window; i++) {
    if (i >= r->known) {
      hmu = 1;
      break;
    }
    if (!r->received[i])
      count++;
  }
  p[0] = hmu ? 255 : 0;
  if (hmu) {
    if (!r->known)
      return RNC_PROTOCOL;
    memcpy(p + 1, r->map + 4 * (r->known - 1u), 4);
    n += 4;
  }
  memcpy(p + n, r->adv.hash, 32);
  n += 32;
  for (i = start; i < r->adv.parts && i < start + r->window && i < r->known;
       i++) {
    if (!r->received[i]) {
      memcpy(p + n, r->map + 4 * i, 4);
      n += 4;
    }
    last = i + 1;
  }
  if (!count && !hmu)
    return RNC_OK;
  result = rnc_link_send_packet(r->link, 3, p, n, now);
  if (result == RNC_OK) {
    r->request_pending = 0;
    r->request_end = last;
    r->last_activity = now;
    r->request_sent = now;
    /* encrypted token: IV, PKCS7-padded body, HMAC; plus the packet header */
    r->request_bytes = RESOURCE_PACKET_HEADER + 16u + ((n / 16u) + 1u) * 16u + 32u;
    r->rx_bytes_at_request = r->rx_bytes;
    r->round_seen = 0;
    r->waiting_hmu = hmu;
  }
  return result;
}
rnc_result rnc_resource_pump(rnc_resource *r, uint64_t now) {
  rnc_result result;
  uint8_t p[RNC_LINK_MDU];
  size_t n, i;
  if (!r || now < r->now)
    return RNC_INVALID;
  if (!rnc_link_is_active(r->link)) {
    if (active(r))
      fail(r, RNC_STATE, 0);
    return RNC_STATE;
  }
  if (r->cancel_pending) {
    result = rnc_link_send_packet(r->link, r->outgoing ? 6 : 7, r->adv.hash, 32,
                                  now);
    if (result == RNC_AGAIN)
      return RNC_OK;
    if (result != RNC_OK)
      return result;
    r->cancel_pending = 0;
  }
  if (r->proof_pending) {
    result = rnc_link_send_resource_packet(r->link, RNC_PROOF, 5,
                                           r->cached_proof, 64, now);
    if (result == RNC_AGAIN)
      return RNC_OK;
    if (result != RNC_OK)
      return result;
    r->proof_pending = 0;
  }
  if (r->advertise_pending) {
    n = pack_adv(&r->adv, p);
    if (!n)
      return RNC_NO_SPACE;
    result = rnc_link_send_packet(r->link, 2, p, n, now);
    if (result == RNC_AGAIN)
      return RNC_OK;
    if (result != RNC_OK)
      return result;
    r->advertise_pending = 0;
    r->last_activity = now;
  }
  if (r->request_pending) {
    result = send_request(r, now);
    if (result == RNC_AGAIN)
      return RNC_OK;
    if (result != RNC_OK)
      return result;
  }
  if (r->outgoing && active(r) && r->wanted) {
    for (i = 0; i < r->adv.parts; i++)
      if (r->wanted[i]) {
        n = r->adv.transfer - i * r->sdu;
        if (n > r->sdu)
          n = r->sdu;
        result = rnc_link_send_resource_packet(r->link, RNC_DATA, 1,
                                               r->wire + i * r->sdu, n, now);
        if (result == RNC_AGAIN)
          return RNC_OK;
        if (result != RNC_OK)
          return result;
        r->wanted[i] = 0;
        if (!r->sent[i]) {
          r->sent[i] = 1;
          r->sent_count++;
        }
        r->last_activity = now;
        r->progress_pending = 1;
      }
  }
  if (r->hmu_pending) {
    size_t start = r->hmu_segment * RNC_RESOURCE_MAP_BATCH,
           count = r->adv.parts - start;
    if (count > RNC_RESOURCE_MAP_BATCH)
      count = RNC_RESOURCE_MAP_BATCH;
    memcpy(p, r->adv.hash, 32);
    p[32] = 0x92;
    n = 33;
    n += rmp_put_uint(p + n, r->hmu_segment);
    n += rmp_put_bin(p + n, r->map + 4 * start, count * 4);
    result = rnc_link_send_packet(r->link, 4, p, n, now);
    if (result == RNC_AGAIN)
      return RNC_OK;
    if (result != RNC_OK)
      return result;
    r->hmu_pending = 0;
    r->last_activity = now;
  }
  if (r->outgoing && r->state == RES_TX_DATA && r->sent_count == r->adv.parts) {
    r->state = RES_TX_PROOF;
    r->retries = 0;
  }
  if (r->cache_pending) {
    result = rnc_link_send_resource_packet(r->link, RNC_DATA, 8, r->cache_hash,
                                           32, now);
    if (result == RNC_AGAIN)
      return RNC_OK;
    if (result != RNC_OK)
      return result;
    r->cache_pending = 0;
    r->last_activity = now;
  }
  r->now = now;
  return RNC_OK;
}
/* Expected inflight rate in bits/s: the measured data rate, else the previous
 * resource's, else the link set-up cost over the link RTT (update_eifr). */
static uint64_t resource_eifr_bps(uint64_t data_rate_bytes, uint64_t previous_bps,
                                  uint64_t cost_bytes, uint64_t rtt_ms) {
  uint64_t bps;
  if (data_rate_bytes)
    return data_rate_bytes * 8u;
  if (previous_bps)
    return previous_bps;
  if (!rtt_ms)
    rtt_ms = 1;
  bps = cost_bytes * 8000u / rtt_ms;
  return bps ? bps : 1;
}
/* How long the receiver waits for outstanding parts before asking again. */
static uint64_t resource_part_timeout_ms(size_t sdu, size_t outstanding,
                                         uint64_t eifr_bps, int have_response_rate,
                                         unsigned factor, int waiting_hmu,
                                         unsigned retries_used) {
  uint64_t numerator, extra = (uint64_t)retries_used * RESOURCE_PER_RETRY_MS;
  if (!eifr_bps)
    eifr_bps = 1;
  if (have_response_rate)
    numerator = (uint64_t)factor * outstanding * sdu * 8000u +
                (waiting_hmu || !outstanding ? (uint64_t)sdu * 28000u : 0u);
  else
    numerator = (uint64_t)factor * 3u * sdu * 1000u;
  return (numerator + eifr_bps / 2u) / eifr_bps + RESOURCE_RETRY_GRACE_MS + extra;
}
static uint64_t resource_sender_timeout_ms(enum resource_state state,
                                           uint64_t rtt_ms) {
  uint64_t max_extra = 0, k;
  switch (state) {
  case RES_TX_ADV:
    return rtt_ms * RESOURCE_TRAFFIC_FACTOR + RESOURCE_PROCESSING_GRACE_MS;
  case RES_TX_DATA:
    for (k = 0; k < RESOURCE_MAX_RETRIES; k++)
      max_extra += (k + 1u) * RESOURCE_PER_RETRY_MS;
    return rtt_ms * RESOURCE_TRAFFIC_FACTOR * RESOURCE_MAX_RETRIES +
           RESOURCE_SENDER_GRACE_MS + max_extra;
  default: /* waiting for the proof */
    return rtt_ms * RESOURCE_PROOF_FACTOR + RESOURCE_SENDER_GRACE_MS;
  }
}
static uint64_t resource_timeout_ms(const rnc_resource *r) {
  uint64_t rtt = 0;
  size_t i, outstanding = 0;
  (void)rnc_link_rtt(r->link, &rtt);
  if (r->state != RES_RX_DATA)
    return resource_sender_timeout_ms(r->state, rtt);
  for (i = 0; i < r->request_end && i < r->adv.parts; i++)
    if (!r->received[i])
      outstanding++;
  return resource_part_timeout_ms(
      r->sdu, outstanding,
      resource_eifr_bps(r->data_rate, rnc_link_last_resource_eifr(r->link),
                        RESOURCE_ESTABLISHMENT_COST, rtt),
      r->response_rate != 0, r->part_factor, r->waiting_hmu, r->retries);
}
rnc_result rnc_resource_tick(rnc_resource *r, uint64_t now) {
  if (!r || now < r->now)
    return RNC_INVALID;
  if (!active(r)) {
    r->now = now;
    return RNC_OK;
  }
  if (!rnc_link_is_active(r->link)) {
    fail(r, RNC_STATE, 0);
    r->now = now;
    return RNC_OK;
  }
  if (now - r->last_activity >= resource_timeout_ms(r)) {
    unsigned max = r->state == RES_TX_ADV ? 4u : RESOURCE_MAX_RETRIES;
    if (r->state == RES_TX_DATA) { /* the receiver stopped asking: give up */
      fail(r, RNC_TIMEOUT, 1);
      r->now = now;
      return RNC_OK;
    }
    if (r->retries++ >= max) {
      fail(r, RNC_TIMEOUT, 1);
      r->now = now;
      return RNC_OK;
    }
    if (r->state == RES_TX_ADV)
      r->advertise_pending = 1;
    else if (r->state == RES_RX_DATA) {
      r->request_pending = 1;
      r->waiting_hmu = 0;
      /* a timed-out round: back off the window and its ceiling */
      if (r->window > r->window_min) {
        r->window--;
        if (r->window_max > r->window_min) {
          r->window_max--;
          if (r->window_max - r->window > RESOURCE_WINDOW_FLEXIBILITY - 1)
            r->window_max--;
        }
      }
    }
    else if (r->state == RES_TX_PROOF) {
      uint8_t proof[64];
      size_t off = (r->adv.index - 1u) * RNC_RESOURCE_SEGMENT_MAX,
             len = r->data_size - off;
      rnc_result result;
      if (len > RNC_RESOURCE_SEGMENT_MAX)
        len = RNC_RESOURCE_SEGMENT_MAX;
      memcpy(proof, r->adv.hash, 32);
      result = digest2(r->data + off, len, r->adv.hash, 32, proof + 32);
      if (result != RNC_OK)
        return result;
      result = proof_hash(r, proof, r->cache_hash);
      if (result != RNC_OK)
        return result;
      r->cache_pending = 1;
    }
    r->last_activity = now;
  }
  r->now = now;
  return RNC_OK;
}
rnc_result rnc_resource_cancel(rnc_resource *r, uint64_t now) {
  if (!r || now < r->now)
    return RNC_INVALID;
  if (active(r))
    fail(r, RNC_STATE, 1);
  r->now = now;
  return RNC_OK;
}
rnc_result rnc_resource_poll(rnc_resource *r, rnc_resource_event *e) {
  if (!r || !e)
    return RNC_INVALID;
  if (!r->terminal_pending && !r->progress_pending)
    return RNC_AGAIN;
  memset(e, 0, sizeof(*e));
  e->type = r->terminal_pending ? (r->state == RES_DONE ? RNC_RESOURCE_COMPLETE
                                                        : RNC_RESOURCE_FAILED)
                                : RNC_RESOURCE_PROGRESS;
  if (r->terminal_pending)
    r->terminal_pending = 0;
  else
    r->progress_pending = 0;
  e->reason = r->reason;
  e->outgoing = r->outgoing;
  memcpy(e->hash, r->adv.hash, 32);
  memcpy(e->original_hash, r->adv.original, 32);
  e->has_request_id = r->adv.request_set;
  e->is_response = (r->adv.flags & 16) != 0;
  if (e->has_request_id)
    memcpy(e->request_id, r->adv.request, 16);
  e->total = r->data_size;
  e->transferred = r->assembled;
  if (active(r) && r->adv.transfer) {
    size_t segment = r->data_size - r->assembled;
    size_t wire_progress =
        (r->outgoing ? r->sent_count : r->received_count) * r->sdu;
    if (segment > RNC_RESOURCE_SEGMENT_MAX)
      segment = RNC_RESOURCE_SEGMENT_MAX;
    if (wire_progress > r->adv.transfer)
      wire_progress = r->adv.transfer;
    e->transferred +=
        (size_t)((uint64_t)wire_progress * segment / r->adv.transfer);
  }
  return RNC_OK;
}
rnc_result rnc_resource_read(const rnc_resource *r, void *data, size_t cap,
                             size_t *written) {
  size_t n;
  if (written)
    *written = 0;
  if (!r || !written || (!data && cap))
    return RNC_INVALID;
  if (r->outgoing || r->state != RES_DONE)
    return RNC_STATE;
  n = r->data_size - r->metadata_prefix;
  if (cap < n)
    return RNC_NO_SPACE;
  if (n)
    memcpy(data, r->data + r->metadata_prefix, n);
  *written = n;
  return RNC_OK;
}
size_t rnc_resource_data_size(const rnc_resource *r) {
  if (!r || r->outgoing || r->state != RES_DONE)
    return 0;
  return r->data_size - r->metadata_prefix;
}
rnc_result rnc_resource_metadata(const rnc_resource *r, void *data, size_t cap,
                                 size_t *written) {
  if (written)
    *written = 0;
  if (!r || !written || (!data && cap))
    return RNC_INVALID;
  if (r->outgoing || r->state != RES_DONE)
    return RNC_STATE;
  if (cap < r->metadata_size)
    return RNC_NO_SPACE;
  if (r->metadata_size)
    memcpy(data, r->data + 3, r->metadata_size);
  *written = r->metadata_size;
  return RNC_OK;
}
int rnc_resource_is_complete(const rnc_resource *r) {
  return r && r->state == RES_DONE;
}
rnc_result rnc_resource_inspect(const uint8_t *data, size_t size,
                                size_t *transfer, size_t *total,
                                uint8_t hash[32], uint8_t original[32],
                                uint8_t request[16], int *has_request,
                                int *response) {
  resource_adv a;
  rnc_result result;
  if (!transfer || !total || !hash || !original || !request || !has_request ||
      !response)
    return RNC_INVALID;
  result = parse_adv(data, size, &a);
  if (result != RNC_OK)
    return result;
  *transfer = a.transfer;
  *total = a.total;
  memcpy(hash, a.hash, 32);
  memcpy(original, a.original, 32);
  memcpy(request, a.request, 16);
  *has_request = a.request_set;
  *response = (a.flags & 16) != 0;
  return RNC_OK;
}

size_t rnc_resource_window(const rnc_resource *r) {
  return r && !r->outgoing && active(r) ? r->window : 0;
}
size_t rnc_resource_window_max(const rnc_resource *r) {
  return r && !r->outgoing && active(r) ? r->window_max : 0;
}
