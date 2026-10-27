#include "service_msgpack.h"
#include <openssl/crypto.h>
#include <reticulum_c/rnc_link.h>
#include <reticulum_c/rnc_resource.h>
#include <reticulum_c/rnc_service.h>
#include <reticulum_c/rnc_transfer.h>
#include <stdlib.h>
#include <string.h>

#define FETCH_PATH "fetch_file"
#define REQ_FETCH_NOT_ALLOWED 0xf0u
#define CLOSE_GRACE_MS 2000u
#define PATH_MAX_BYTES 1024u

/* One link with the three engines rncp needs: a request service (fetch_file)
 * and one Resource each way for the files themselves. */
typedef struct conn {
  rnc_link *link;
  rnc_service *service;
  rnc_resource *rx, *tx;
  uint8_t id[16];
} conn;
static int conn_open(conn *c, rnc_node *node, size_t max_size,
                     rnc_random_fn random, void *context) {
  (void)node;
  memset(c, 0, sizeof(*c));
  c->link = rnc_link_new(random, context);
  if (!c->link)
    return 0;
  c->service = rnc_service_new(c->link, 4096, random, context);
  c->rx = rnc_resource_new(c->link, max_size + 4096u, random, context);
  c->tx = rnc_resource_new(c->link, max_size + 4096u, random, context);
  if (!c->service || !c->rx || !c->tx) {
    rnc_resource_free(c->rx);
    rnc_resource_free(c->tx);
    rnc_service_free(c->service);
    rnc_link_free(c->link);
    memset(c, 0, sizeof(*c));
    return 0;
  }
  return 1;
}
static void conn_close(conn *c, rnc_node *node) {
  if (!c->link)
    return;
  (void)rnc_node_unbind_link(node, c->id);
  rnc_resource_free(c->rx);
  rnc_resource_free(c->tx);
  rnc_service_free(c->service);
  rnc_link_free(c->link);
  memset(c, 0, sizeof(*c));
}
/* {"name": <bytes>} as rncp attaches to every file */
static size_t metadata_encode(const uint8_t *name, size_t n, uint8_t *out) {
  size_t i = 0;
  out[i++] = 0x81;
  out[i++] = 0xa4;
  memcpy(out + i, "name", 4);
  i += 4;
  return i + rmp_put_bin(out + i, name, n);
}
static int metadata_name(const uint8_t *meta, size_t size, const uint8_t **name,
                         size_t *n) {
  rmp r = {meta, size, 0};
  const uint8_t *key;
  size_t klen, pairs, k;
  if (!size || (meta[0] & 0xf0) != 0x80)
    return 0;
  pairs = meta[0] & 0x0f;
  r.i = 1;
  for (k = 0; k < pairs; k++) {
    if (!rmp_len(&r, 1, &klen) || !rmp_take(&r, klen, &key))
      return 0;
    if (klen == 4 && !memcmp(key, "name", 4)) {
      size_t save = r.i;
      if (rmp_bin(&r, name, n) && *n && *n <= RNC_TRANSFER_NAME_MAX)
        return 1;
      r.i = save;
      if (rmp_len(&r, 1, n) && rmp_take(&r, *n, name) && *n &&
          *n <= RNC_TRANSFER_NAME_MAX)
        return 1;
      return 0;
    }
    if (!rmp_skip_depth(&r, 0))
      return 0;
  }
  return 0;
}
/* a complete incoming file: data and its name */
static int take_file(conn *c, uint8_t **data, size_t *size, uint8_t *name,
                     size_t *name_size) {
  uint8_t meta[512];
  size_t meta_size = 0, n;
  const uint8_t *nm;
  size_t nmn;
  if (rnc_resource_metadata(c->rx, meta, sizeof(meta), &meta_size) != RNC_OK ||
      !metadata_name(meta, meta_size, &nm, &nmn))
    return 0;
  memcpy(name, nm, nmn);
  *name_size = nmn;
  n = rnc_resource_data_size(c->rx);
  *data = malloc(n ? n : 1);
  if (!*data)
    return 0;
  if (rnc_resource_read(c->rx, *data, n, size) != RNC_OK) {
    free(*data);
    *data = NULL;
    return 0;
  }
  return 1;
}

/* ---- listener ----------------------------------------------------------- */
typedef struct listener_slot {
  int used, closing;
  conn c;
  uint8_t remote[16];
  int identified;
} listener_slot;
struct rnc_transfer_listener {
  rnc_node *node;
  rnc_identity identity;
  uint8_t destination[16];
  rnc_transfer_config config;
  rnc_random_fn random;
  void *random_context;
  uint8_t *scratch;
  listener_slot slots[RNC_TRANSFER_LINKS];
};
rnc_transfer_listener *rnc_transfer_listener_new(
    rnc_node *node, const rnc_identity *identity, const uint8_t destination[16],
    const rnc_transfer_config *config, rnc_random_fn random,
    void *random_context) {
  rnc_transfer_listener *l;
  if (!node || !identity || !identity->has_private || !destination || !config ||
      !random || config->allowed_count > RNC_TRANSFER_ALLOWED ||
      config->max_size > RNC_TRANSFER_MAX_SIZE)
    return NULL;
  l = calloc(1, sizeof(*l));
  if (!l)
    return NULL;
  l->node = node;
  l->identity = *identity;
  memcpy(l->destination, destination, 16);
  l->config = *config;
  if (!l->config.max_size)
    l->config.max_size = RNC_TRANSFER_DEFAULT_LIMIT;
  l->random = random;
  l->random_context = random_context;
  l->scratch = malloc(PATH_MAX_BYTES + 16u);
  if (!l->scratch) {
    free(l);
    return NULL;
  }
  return l;
}
static void slot_release(rnc_transfer_listener *l, listener_slot *s) {
  if (!s->used)
    return;
  conn_close(&s->c, l->node);
  OPENSSL_cleanse(s, sizeof(*s));
}
void rnc_transfer_listener_free(rnc_transfer_listener *l) {
  size_t i;
  if (!l)
    return;
  for (i = 0; i < RNC_TRANSFER_LINKS; i++)
    slot_release(l, &l->slots[i]);
  free(l->scratch);
  OPENSSL_cleanse(l, sizeof(*l));
  free(l);
}
size_t rnc_transfer_listener_link_count(const rnc_transfer_listener *l) {
  size_t i, n = 0;
  if (!l)
    return 0;
  for (i = 0; i < RNC_TRANSFER_LINKS; i++)
    n += l->slots[i].used;
  return n;
}
static int listed(const rnc_transfer_listener *l, const uint8_t hash[16]) {
  size_t i;
  for (i = 0; i < l->config.allowed_count; i++)
    if (!CRYPTO_memcmp(l->config.allowed[i], hash, 16))
      return 1;
  return 0;
}
static int authorized(const rnc_transfer_listener *l, const listener_slot *s) {
  return l->config.allow_all || (s->identified && listed(l, s->remote));
}
static rnc_result accept_link(rnc_transfer_listener *l,
                              const rnc_node_event *event, uint64_t now) {
  listener_slot *s = NULL;
  size_t i;
  rnc_result result;
  for (i = 0; i < RNC_TRANSFER_LINKS; i++)
    if (!l->slots[i].used) {
      s = &l->slots[i];
      break;
    }
  if (!s)
    return RNC_NO_SPACE;
  memset(s, 0, sizeof(*s));
  if (!conn_open(&s->c, l->node, l->config.max_size, l->random,
                 l->random_context))
    return RNC_NO_SPACE;
  result = rnc_link_configure_mtu(
      s->c.link, rnc_node_link_mtu_on(l->node, event->interface_id));
  if (result == RNC_OK)
    result = rnc_link_accept(s->c.link, &l->identity, l->destination,
                             &event->packet, now);
  if (result == RNC_OK)
    result = rnc_link_address(s->c.link, s->c.id);
  if (result == RNC_OK)
    result = rnc_node_bind_link_on(l->node, s->c.id, event->interface_id);
  if (result == RNC_OK && l->config.fetch)
    result = rnc_service_register(s->c.service, FETCH_PATH,
                                  RNC_SERVICE_ALLOW_ALL, NULL, 0);
  if (result != RNC_OK) {
    conn_close(&s->c, l->node);
    OPENSSL_cleanse(s, sizeof(*s));
    return result;
  }
  s->used = 1;
  return RNC_OK;
}
rnc_result rnc_transfer_listener_input(rnc_transfer_listener *l,
                                       const rnc_node_event *event,
                                       uint64_t unix_seconds, uint64_t now_ms) {
  const rnc_packet *p;
  size_t i;
  rnc_result result;
  (void)unix_seconds;
  if (!l || !event)
    return RNC_INVALID;
  if (event->type != RNC_NODE_LOCAL)
    return RNC_AGAIN;
  p = &event->packet;
  if ((p->flags & 3u) == RNC_LINKREQUEST)
    return memcmp(p->destination, l->destination, 16)
               ? RNC_AGAIN
               : accept_link(l, event, now_ms);
  for (i = 0; i < RNC_TRANSFER_LINKS; i++)
    if (l->slots[i].used && !memcmp(l->slots[i].c.id, p->destination, 16)) {
      result = rnc_link_input(l->slots[i].c.link, p, now_ms);
      return result == RNC_AGAIN ? RNC_NO_SPACE : result;
    }
  return RNC_AGAIN;
}
static void listener_requests(rnc_transfer_listener *l, listener_slot *s,
                              uint64_t now) {
  rnc_service_event event;
  size_t got;
  while (rnc_service_poll(s->c.service, &event, l->scratch, PATH_MAX_BYTES,
                          &got) == RNC_OK) {
    rmp r = {l->scratch, got, 0};
    const uint8_t *path;
    size_t n, name_size = 0, size = 0;
    uint8_t name[RNC_TRANSFER_NAME_MAX], *data = NULL, answer[2];
    size_t answer_size = 1;
    int found;
    if (event.type != RNC_SERVICE_REQUEST || !authorized(l, s))
      continue; /* the reference stays silent for unauthorised fetches */
    if (!rmp_len(&r, 1, &n) || !rmp_take(&r, n, &path) || r.i != r.n) {
      answer[0] = 0xc2;
      (void)rnc_service_respond(s->c.service, event.request_id, answer, 1, now);
      continue;
    }
    found = l->config.fetch(l->config.context, path, n,
                            s->identified ? s->remote : NULL, &data, &size,
                            name, &name_size);
    answer[0] = 0xc2; /* False: not found */
    if (found == RNC_FETCH_NOT_ALLOWED) {
      answer[0] = 0xcc;
      answer[1] = REQ_FETCH_NOT_ALLOWED;
      answer_size = 2;
    } else if (found == RNC_FETCH_FOUND && data && name_size &&
               name_size <= RNC_TRANSFER_NAME_MAX) {
      uint8_t meta[RNC_TRANSFER_NAME_MAX + 16];
      rnc_resource_options o = {0};
      o.compress = 1;
      o.metadata = meta;
      o.metadata_size = metadata_encode(name, name_size, meta);
      if (rnc_resource_send(s->c.tx, data, size, &o, now) == RNC_OK)
        answer[0] = 0xc3;
    }
    if (data) {
      OPENSSL_cleanse(data, size);
      free(data);
    }
    (void)rnc_service_respond(s->c.service, event.request_id, answer,
                              answer_size, now);
  }
}
/* Admit a plain (non-request) Resource advertisement if the sender is allowed. */
static rnc_result listener_dispatch(rnc_transfer_listener *l, listener_slot *s,
                                    const rnc_link_event *le, uint64_t now) {
  rnc_result r = rnc_service_input(s->c.service, le, now);
  if (r != RNC_AGAIN)
    return r;
  if (le->type == RNC_LINK_PACKET && le->context == 2) {
    if (!authorized(l, s))
      return RNC_OK;
    return rnc_resource_accept(s->c.rx, le->data, le->size, now);
  }
  if (le->type == RNC_LINK_PACKET || le->type == RNC_LINK_RESOURCE_PACKET) {
    rnc_result a = rnc_resource_input(s->c.rx, le, now),
               b = rnc_resource_input(s->c.tx, le, now);
    return a == RNC_OK || b == RNC_OK ? RNC_OK : RNC_AGAIN;
  }
  return RNC_AGAIN;
}
rnc_result rnc_transfer_listener_tick(rnc_transfer_listener *l,
                                      uint64_t unix_seconds, uint64_t now_ms) {
  size_t i;
  if (!l)
    return RNC_INVALID;
  for (i = 0; i < RNC_TRANSFER_LINKS; i++) {
    listener_slot *s = &l->slots[i];
    rnc_link_event le;
    rnc_resource_event re;
    int closed = 0;
    if (!s->used)
      continue;
    (void)rnc_link_tick(s->c.link, now_ms);
    while (rnc_link_poll(s->c.link, &le) == RNC_OK) {
      if (le.type == RNC_LINK_SEND)
        (void)rnc_node_send(l->node, &le.packet, unix_seconds, now_ms);
      else if (le.type == RNC_LINK_IDENTIFIED) {
        s->identified = 1;
        memcpy(s->remote, le.identity_hash, 16);
        if (!l->config.allow_all && !listed(l, s->remote))
          (void)rnc_link_close(s->c.link, now_ms);
      } else if (le.type == RNC_LINK_PACKET ||
                 le.type == RNC_LINK_RESOURCE_PACKET ||
                 le.type == RNC_LINK_CLOSED) {
        (void)listener_dispatch(l, s, &le, now_ms);
        if (le.type == RNC_LINK_CLOSED)
          closed = 1;
      }
    }
    if (!closed) {
      (void)rnc_resource_pump(s->c.rx, now_ms);
      (void)rnc_resource_pump(s->c.tx, now_ms);
      (void)rnc_resource_tick(s->c.rx, now_ms);
      (void)rnc_resource_tick(s->c.tx, now_ms);
      (void)rnc_service_pump(s->c.service, now_ms);
      (void)rnc_service_tick(s->c.service, now_ms);
      listener_requests(l, s, now_ms);
      while (rnc_resource_poll(s->c.rx, &re) == RNC_OK)
        if (re.type == RNC_RESOURCE_COMPLETE && l->config.received) {
          uint8_t *data = NULL, name[RNC_TRANSFER_NAME_MAX];
          size_t size = 0, name_size = 0;
          if (take_file(&s->c, &data, &size, name, &name_size)) {
            (void)l->config.received(l->config.context,
                                     s->identified ? s->remote : NULL, name,
                                     name_size, data, size);
            OPENSSL_cleanse(data, size);
            free(data);
          }
        }
      while (rnc_resource_poll(s->c.tx, &re) == RNC_OK) {
      }
      while (rnc_link_poll(s->c.link, &le) == RNC_OK)
        if (le.type == RNC_LINK_SEND)
          (void)rnc_node_send(l->node, &le.packet, unix_seconds, now_ms);
        else if (le.type == RNC_LINK_CLOSED)
          closed = 1;
    }
    if (closed)
      slot_release(l, s);
  }
  return RNC_OK;
}

/* ---- client ------------------------------------------------------------- */
enum job_kind { JOB_SEND = 1, JOB_FETCH };
enum job_state { JOB_OPENING = 1, JOB_RUNNING, JOB_CLOSING };
typedef struct client_job {
  int used, finished, released, started;
  enum job_kind kind;
  enum job_state state;
  conn c;
  uint8_t destination[16];
  rnc_identity identity;
  uint8_t *input; /* send: the file; fetch: the requested path */
  size_t input_size;
  uint8_t name[RNC_TRANSFER_NAME_MAX];
  size_t name_size;
  uint32_t tag;
  uint64_t deadline, close_deadline;
  rnc_transfer_status status;
  uint8_t *output;
  size_t output_size;
  double progress;
} client_job;
struct rnc_transfer_client {
  rnc_node *node;
  size_t max_size;
  rnc_random_fn random;
  void *random_context;
  client_job jobs[RNC_TRANSFER_JOBS];
};
rnc_transfer_client *rnc_transfer_client_new(rnc_node *node, size_t max_size,
                                             rnc_random_fn random,
                                             void *random_context) {
  rnc_transfer_client *c;
  if (!node || !random || max_size > RNC_TRANSFER_MAX_SIZE)
    return NULL;
  c = calloc(1, sizeof(*c));
  if (!c)
    return NULL;
  c->node = node;
  c->max_size = max_size ? max_size : RNC_TRANSFER_DEFAULT_LIMIT;
  c->random = random;
  c->random_context = random_context;
  return c;
}
static void job_release_link(rnc_transfer_client *c, client_job *j) {
  if (j->released)
    return;
  conn_close(&j->c, c->node);
  j->released = 1;
}
static void job_clear(rnc_transfer_client *c, client_job *j) {
  job_release_link(c, j);
  if (j->input)
    OPENSSL_cleanse(j->input, j->input_size);
  free(j->input);
  if (j->output)
    OPENSSL_cleanse(j->output, j->output_size);
  free(j->output);
  OPENSSL_cleanse(j, sizeof(*j));
}
void rnc_transfer_client_free(rnc_transfer_client *c) {
  size_t i;
  if (!c)
    return;
  for (i = 0; i < RNC_TRANSFER_JOBS; i++)
    if (c->jobs[i].used)
      job_clear(c, &c->jobs[i]);
  free(c);
}
static rnc_result job_start(rnc_transfer_client *c, enum job_kind kind,
                            const uint8_t destination[16],
                            const rnc_identity *identity, const uint8_t *name,
                            size_t name_size, const void *input, size_t size,
                            uint32_t tag, uint64_t timeout, uint64_t now) {
  client_job *j = NULL;
  rnc_route route;
  rnc_result result;
  size_t i;
  if (!c || !destination || !identity || !identity->has_private || !timeout ||
      timeout > UINT64_MAX - now || (size && !input) ||
      (kind == JOB_SEND && (!name || !name_size || name_size > RNC_TRANSFER_NAME_MAX ||
                            size > c->max_size)) ||
      (kind == JOB_FETCH && (!size || size > PATH_MAX_BYTES)))
    return RNC_INVALID;
  for (i = 0; i < RNC_TRANSFER_JOBS; i++)
    if (!c->jobs[i].used) {
      j = &c->jobs[i];
      break;
    }
  if (!j)
    return RNC_AGAIN;
  if (rnc_node_lookup(c->node, destination, now, &route) != RNC_OK)
    return RNC_STATE;
  memset(j, 0, sizeof(*j));
  if (!conn_open(&j->c, c->node, c->max_size, c->random, c->random_context)) {
    OPENSSL_cleanse(j, sizeof(*j));
    return RNC_NO_SPACE;
  }
  j->input = malloc(size ? size : 1);
  if (!j->input) {
    result = RNC_NO_SPACE;
    goto fail;
  }
  result = rnc_link_configure_mtu(
      j->c.link, rnc_node_link_mtu_to(c->node, destination, now));
  if (result == RNC_OK)
    result = rnc_link_open(j->c.link, &route.announce, now);
  if (result == RNC_OK)
    result = rnc_link_address(j->c.link, j->c.id);
  if (result == RNC_OK)
    result = rnc_node_bind_link_on(c->node, j->c.id, route.interface_id);
  if (result != RNC_OK)
    goto fail;
  if (size)
    memcpy(j->input, input, size);
  j->input_size = size;
  if (kind == JOB_SEND) {
    memcpy(j->name, name, name_size);
    j->name_size = name_size;
  }
  memcpy(j->destination, destination, 16);
  j->identity = *identity;
  j->kind = kind;
  j->tag = tag;
  j->deadline = now + timeout;
  j->state = JOB_OPENING;
  j->used = 1;
  return RNC_OK;
fail:
  conn_close(&j->c, c->node);
  free(j->input);
  OPENSSL_cleanse(j, sizeof(*j));
  return result;
}
rnc_result rnc_transfer_send(rnc_transfer_client *c,
                             const uint8_t destination[16],
                             const rnc_identity *identity, const uint8_t *name,
                             size_t name_size, const void *data, size_t size,
                             uint32_t tag, uint64_t timeout_ms,
                             uint64_t unix_seconds, uint64_t now_ms) {
  (void)unix_seconds;
  return job_start(c, JOB_SEND, destination, identity, name, name_size, data,
                   size, tag, timeout_ms, now_ms);
}
rnc_result rnc_transfer_fetch(rnc_transfer_client *c,
                              const uint8_t destination[16],
                              const rnc_identity *identity, const uint8_t *path,
                              size_t path_size, uint32_t tag,
                              uint64_t timeout_ms, uint64_t unix_seconds,
                              uint64_t now_ms) {
  (void)unix_seconds;
  return job_start(c, JOB_FETCH, destination, identity, NULL, 0, path,
                   path_size, tag, timeout_ms, now_ms);
}
rnc_result rnc_transfer_client_input(rnc_transfer_client *c,
                                     const rnc_node_event *event,
                                     uint64_t unix_seconds, uint64_t now_ms) {
  size_t i;
  rnc_result result;
  (void)unix_seconds;
  if (!c || !event)
    return RNC_INVALID;
  if (event->type != RNC_NODE_LOCAL)
    return RNC_AGAIN;
  for (i = 0; i < RNC_TRANSFER_JOBS; i++) {
    client_job *j = &c->jobs[i];
    if (j->used && !j->released &&
        !memcmp(j->c.id, event->packet.destination, 16)) {
      result = rnc_link_input(j->c.link, &event->packet, now_ms);
      return result == RNC_AGAIN ? RNC_NO_SPACE : RNC_OK;
    }
  }
  return RNC_AGAIN;
}
static void job_finish(client_job *j, rnc_transfer_status status,
                       uint64_t now) {
  if (j->finished)
    return;
  j->finished = 1;
  j->status = status;
  j->state = JOB_CLOSING;
  j->close_deadline = now + CLOSE_GRACE_MS;
  (void)rnc_link_close(j->c.link, now);
}
static void job_resource_events(client_job *j, rnc_resource *res, uint64_t now) {
  rnc_resource_event re;
  while (rnc_resource_poll(res, &re) == RNC_OK) {
    if (re.type == RNC_RESOURCE_PROGRESS && re.total) {
      double v = (double)re.transferred / (double)re.total;
      if (v > j->progress)
        j->progress = v > 1.0 ? 1.0 : v;
    } else if (re.type == RNC_RESOURCE_FAILED)
      job_finish(j, RNC_TRANSFER_FAILED, now);
    else if (re.type == RNC_RESOURCE_COMPLETE && !j->finished) {
      j->progress = 1.0;
      if (j->kind == JOB_SEND && re.outgoing)
        job_finish(j, RNC_TRANSFER_DONE, now);
      else if (j->kind == JOB_FETCH && !re.outgoing) {
        uint8_t *data = NULL;
        size_t size = 0;
        if (take_file(&j->c, &data, &size, j->name, &j->name_size)) {
          j->output = data;
          j->output_size = size;
          job_finish(j, RNC_TRANSFER_DONE, now);
        } else
          job_finish(j, RNC_TRANSFER_FAILED, now);
      }
    }
  }
}
static void job_response(client_job *j, const uint8_t *value, size_t size,
                         uint64_t now) {
  if (j->finished || !size)
    return;
  if (value[0] == 0xc2 || value[0] == 0xc0)
    job_finish(j, RNC_TRANSFER_NOT_FOUND, now);
  else if (value[0] == 0xcc && size == 2 && value[1] == REQ_FETCH_NOT_ALLOWED)
    job_finish(j, RNC_TRANSFER_NOT_ALLOWED, now);
  /* True: the file follows as a Resource */
}
rnc_result rnc_transfer_client_tick(rnc_transfer_client *c,
                                    uint64_t unix_seconds, uint64_t now_ms) {
  size_t i;
  uint8_t scratch[64];
  if (!c)
    return RNC_INVALID;
  for (i = 0; i < RNC_TRANSFER_JOBS; i++) {
    client_job *j = &c->jobs[i];
    rnc_link_event le;
    int closed = 0;
    if (!j->used || j->released)
      continue;
    if (j->state != JOB_CLOSING && now_ms >= j->deadline)
      job_finish(j, RNC_TRANSFER_FAILED, now_ms);
    (void)rnc_link_tick(j->c.link, now_ms);
    while (rnc_link_poll(j->c.link, &le) == RNC_OK) {
      if (le.type == RNC_LINK_SEND)
        (void)rnc_node_send(c->node, &le.packet, unix_seconds, now_ms);
      else if (le.type == RNC_LINK_PACKET ||
               le.type == RNC_LINK_RESOURCE_PACKET ||
               le.type == RNC_LINK_CLOSED) {
        rnc_result r = rnc_service_input(j->c.service, &le, now_ms);
        if (r == RNC_AGAIN && le.type == RNC_LINK_PACKET && le.context == 2) {
          if (j->kind == JOB_FETCH)
            (void)rnc_resource_accept(j->c.rx, le.data, le.size, now_ms);
        } else if (r == RNC_AGAIN) {
          (void)rnc_resource_input(j->c.rx, &le, now_ms);
          (void)rnc_resource_input(j->c.tx, &le, now_ms);
        }
        if (le.type == RNC_LINK_CLOSED)
          closed = 1;
      }
    }
    if (j->state == JOB_OPENING && rnc_link_is_active(j->c.link)) {
      (void)rnc_link_identify(j->c.link, &j->identity, now_ms);
      if (j->kind == JOB_SEND) {
        uint8_t meta[RNC_TRANSFER_NAME_MAX + 16];
        rnc_resource_options o = {0};
        o.compress = 1;
        o.metadata = meta;
        o.metadata_size = metadata_encode(j->name, j->name_size, meta);
        if (rnc_resource_send(j->c.tx, j->input, j->input_size, &o, now_ms) ==
            RNC_OK)
          j->state = JOB_RUNNING;
        else
          job_finish(j, RNC_TRANSFER_FAILED, now_ms);
      } else {
        uint8_t request[PATH_MAX_BYTES + 8], id[16];
        size_t n = 0;
        if (j->input_size < 32)
          request[n++] = (uint8_t)(0xa0 | j->input_size);
        else if (j->input_size < 256) {
          request[n++] = 0xd9;
          request[n++] = (uint8_t)j->input_size;
        } else {
          request[n++] = 0xda;
          request[n++] = (uint8_t)(j->input_size >> 8);
          request[n++] = (uint8_t)j->input_size;
        }
        memcpy(request + n, j->input, j->input_size);
        n += j->input_size;
        if (rnc_service_request(j->c.service, FETCH_PATH, request, n,
                                (double)unix_seconds, now_ms,
                                j->deadline > now_ms ? j->deadline - now_ms : 1,
                                id) == RNC_OK)
          j->state = JOB_RUNNING;
        else
          job_finish(j, RNC_TRANSFER_FAILED, now_ms);
      }
    }
    if (j->state != JOB_CLOSING) {
      rnc_service_event se;
      size_t got;
      (void)rnc_resource_pump(j->c.rx, now_ms);
      (void)rnc_resource_pump(j->c.tx, now_ms);
      (void)rnc_resource_tick(j->c.rx, now_ms);
      (void)rnc_resource_tick(j->c.tx, now_ms);
      (void)rnc_service_pump(j->c.service, now_ms);
      (void)rnc_service_tick(j->c.service, now_ms);
      job_resource_events(j, j->c.rx, now_ms);
      job_resource_events(j, j->c.tx, now_ms);
      while (rnc_service_poll(j->c.service, &se, scratch, sizeof(scratch),
                              &got) == RNC_OK) {
        if (se.type == RNC_SERVICE_RESPONSE)
          job_response(j, scratch, got, now_ms);
        else if (se.type == RNC_SERVICE_TIMEOUT || se.type == RNC_SERVICE_FAILED)
          job_finish(j, RNC_TRANSFER_FAILED, now_ms);
      }
    }
    while (rnc_link_poll(j->c.link, &le) == RNC_OK) {
      if (le.type == RNC_LINK_SEND)
        (void)rnc_node_send(c->node, &le.packet, unix_seconds, now_ms);
      else if (le.type == RNC_LINK_CLOSED)
        closed = 1;
    }
    if (closed && !j->finished)
      job_finish(j, RNC_TRANSFER_FAILED, now_ms);
    if (j->state == JOB_CLOSING && (closed || now_ms >= j->close_deadline))
      job_release_link(c, j);
  }
  return RNC_OK;
}
rnc_result rnc_transfer_client_progress(const rnc_transfer_client *c,
                                        uint32_t tag, double *progress) {
  size_t i;
  if (!c || !progress)
    return RNC_INVALID;
  for (i = 0; i < RNC_TRANSFER_JOBS; i++)
    if (c->jobs[i].used && c->jobs[i].tag == tag) {
      *progress = c->jobs[i].progress;
      return RNC_OK;
    }
  return RNC_STATE;
}
rnc_result rnc_transfer_client_poll(rnc_transfer_client *c,
                                    rnc_transfer_result *result, void *data,
                                    size_t capacity) {
  size_t i;
  if (!c || !result)
    return RNC_INVALID;
  for (i = 0; i < RNC_TRANSFER_JOBS; i++) {
    client_job *j = &c->jobs[i];
    if (!j->used || !j->finished || !j->released)
      continue;
    memset(result, 0, sizeof(*result));
    result->tag = j->tag;
    result->status = j->status;
    memcpy(result->destination, j->destination, 16);
    if (j->kind == JOB_FETCH && j->status == RNC_TRANSFER_DONE) {
      memcpy(result->name, j->name, j->name_size);
      result->name_size = j->name_size;
      result->size = j->output_size;
    }
    if (result->size > capacity || (result->size && !data))
      return RNC_NO_SPACE;
    if (result->size)
      memcpy(data, j->output, result->size);
    job_clear(c, j);
    return RNC_OK;
  }
  return RNC_AGAIN;
}
