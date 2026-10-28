#include <openssl/crypto.h>
#include <reticulum_c/rnc_link.h>
#include <reticulum_c/rnc_responder.h>
#include <stdlib.h>
#include <string.h>

#define RESPONDER_PATH_MAX 64u
typedef struct responder_handler {
  int used;
  char path[RESPONDER_PATH_MAX];
  uint8_t hash[16];
  rnc_service_policy policy;
  uint8_t allowed[RNC_SERVICE_ALLOWLIST][16];
  size_t allowed_count;
  rnc_responder_handler function;
  rnc_responder_file_handler file_function;
  void *context;
} responder_handler;
typedef struct responder_destination {
  int used;
  rnc_identity identity;
  uint8_t destination[16];
  size_t max_request;
  responder_handler handlers[RNC_RESPONDER_HANDLERS];
} responder_destination;
typedef struct responder_slot {
  int used;
  rnc_link *link;
  rnc_service *service;
  uint8_t id[16];
  size_t destination;
  int release_pending;
} responder_slot;
struct rnc_responder {
  rnc_node *node;
  size_t max_value;
  rnc_random_fn random;
  void *random_context;
  uint8_t *request, *response, *file_data, *file_meta;
  responder_destination destinations[RNC_RESPONDER_DESTINATIONS];
  responder_slot slots[RNC_RESPONDER_LINKS];
  int busy;
  uint64_t now;
  responder_slot *current;
  rnc_service_event current_event;
};
rnc_responder *rnc_responder_new(rnc_node *node, size_t max_value,
                                 rnc_random_fn random, void *random_context) {
  rnc_responder *r;
  if (!node || !random)
    return NULL;
  r = calloc(1, sizeof(*r));
  if (!r)
    return NULL;
  r->node = node;
  r->max_value = max_value ? max_value : 1048576u;
  r->random = random;
  r->random_context = random_context;
  r->request = malloc(r->max_value);
  r->response = malloc(r->max_value);
  if (!r->request || !r->response) {
    free(r->request);
    free(r->response);
    free(r);
    return NULL;
  }
  return r;
}
static void slot_release(rnc_responder *r, responder_slot *s) {
  if (!s->used)
    return;
  (void)rnc_node_unbind_link(r->node, s->id);
  rnc_service_free(s->service);
  rnc_link_free(s->link);
  OPENSSL_cleanse(s, sizeof(*s));
}
void rnc_responder_free(rnc_responder *r) {
  size_t i;
  if (!r)
    return;
  for (i = 0; i < RNC_RESPONDER_LINKS; i++)
    slot_release(r, &r->slots[i]);
  OPENSSL_cleanse(r->request, r->max_value);
  OPENSSL_cleanse(r->response, r->max_value);
  if (r->file_data)
    OPENSSL_cleanse(r->file_data, r->max_value);
  free(r->request);
  free(r->response);
  free(r->file_data);
  free(r->file_meta);
  OPENSSL_cleanse(r, sizeof(*r));
  free(r);
}
static responder_destination *find_destination(rnc_responder *r,
                                               const uint8_t destination[16]) {
  size_t i;
  for (i = 0; i < RNC_RESPONDER_DESTINATIONS; i++)
    if (r->destinations[i].used &&
        !memcmp(r->destinations[i].destination, destination, 16))
      return &r->destinations[i];
  return NULL;
}
rnc_result rnc_responder_add_destination(rnc_responder *r,
                                         const rnc_identity *identity,
                                         const uint8_t destination[16]) {
  size_t i;
  if (!r || !identity || !identity->has_private || !destination)
    return RNC_INVALID;
  if (find_destination(r, destination))
    return RNC_STATE;
  for (i = 0; i < RNC_RESPONDER_DESTINATIONS; i++)
    if (!r->destinations[i].used) {
      memset(&r->destinations[i], 0, sizeof(r->destinations[i]));
      r->destinations[i].used = 1;
      r->destinations[i].max_request = RNC_SERVICE_NO_LIMIT;
      r->destinations[i].identity = *identity;
      memcpy(r->destinations[i].destination, destination, 16);
      return RNC_OK;
    }
  return RNC_NO_SPACE;
}
static rnc_result register_handler(rnc_responder *r,
                                   const uint8_t destination[16],
                                   const char *path, rnc_service_policy policy,
                                   const uint8_t (*allowed)[16],
                                   size_t allowed_count,
                                   rnc_responder_handler handler,
                                   rnc_responder_file_handler file_handler,
                                   void *context) {
  responder_destination *d;
  responder_handler *h = NULL;
  uint8_t full[32];
  size_t i, n;
  if (!r || !destination || !path || !*path || (!handler && !file_handler) ||
      policy < RNC_SERVICE_ALLOW_NONE || policy > RNC_SERVICE_ALLOW_LIST ||
      allowed_count > RNC_SERVICE_ALLOWLIST || (!allowed && allowed_count) ||
      (policy != RNC_SERVICE_ALLOW_LIST && allowed_count))
    return RNC_INVALID;
  n = strlen(path);
  if (n >= RESPONDER_PATH_MAX)
    return RNC_INVALID;
  d = find_destination(r, destination);
  if (!d)
    return RNC_STATE;
  if (rnc_hash(path, n, full) != RNC_OK)
    return RNC_CRYPTO;
  for (i = 0; i < RNC_RESPONDER_HANDLERS; i++) {
    if (d->handlers[i].used && !memcmp(d->handlers[i].hash, full, 16)) {
      h = &d->handlers[i];
      break;
    }
    if (!d->handlers[i].used && !h)
      h = &d->handlers[i];
  }
  if (!h)
    return RNC_NO_SPACE;
  memset(h, 0, sizeof(*h));
  h->used = 1;
  memcpy(h->path, path, n);
  memcpy(h->hash, full, 16);
  h->policy = policy;
  h->allowed_count = allowed_count;
  if (allowed_count)
    memcpy(h->allowed, allowed, allowed_count * 16);
  h->function = handler;
  h->file_function = file_handler;
  h->context = context;
  return RNC_OK;
}
rnc_result rnc_responder_register(rnc_responder *r,
                                  const uint8_t destination[16],
                                  const char *path, rnc_service_policy policy,
                                  const uint8_t (*allowed)[16],
                                  size_t allowed_count,
                                  rnc_responder_handler handler,
                                  void *context) {
  if (!handler)
    return RNC_INVALID;
  return register_handler(r, destination, path, policy, allowed, allowed_count,
                          handler, NULL, context);
}
rnc_result rnc_responder_register_file(
    rnc_responder *r, const uint8_t destination[16], const char *path,
    rnc_service_policy policy, const uint8_t (*allowed)[16],
    size_t allowed_count, rnc_responder_file_handler handler, void *context) {
  if (!handler)
    return RNC_INVALID;
  if (r && !r->file_data) {
    r->file_data = malloc(r->max_value);
    r->file_meta = malloc(RNC_RESPONDER_METADATA_MAX);
    if (!r->file_data || !r->file_meta) {
      free(r->file_data);
      free(r->file_meta);
      r->file_data = r->file_meta = NULL;
      return RNC_NO_SPACE;
    }
  }
  return register_handler(r, destination, path, policy, allowed, allowed_count,
                          NULL, handler, context);
}
rnc_result rnc_responder_set_max_request_size(rnc_responder *r,
                                              const uint8_t destination[16],
                                              size_t max_size) {
  responder_destination *d;
  size_t i;
  if (!r || !destination)
    return RNC_INVALID;
  d = find_destination(r, destination);
  if (!d)
    return RNC_STATE;
  d->max_request = max_size;
  for (i = 0; i < RNC_RESPONDER_LINKS; i++)
    if (r->slots[i].used && &r->destinations[r->slots[i].destination] == d)
      (void)rnc_service_set_max_request_size(r->slots[i].service, max_size);
  return RNC_OK;
}
size_t rnc_responder_link_count(const rnc_responder *r) {
  size_t i, n = 0;
  if (!r)
    return 0;
  for (i = 0; i < RNC_RESPONDER_LINKS; i++)
    n += r->slots[i].used;
  return n;
}
static rnc_result accept_link(rnc_responder *r, responder_destination *d,
                              const rnc_node_event *event, uint64_t now) {
  responder_slot *s = NULL;
  size_t i;
  rnc_result result;
  for (i = 0; i < RNC_RESPONDER_LINKS; i++)
    if (!r->slots[i].used) {
      s = &r->slots[i];
      break;
    }
  if (!s)
    return RNC_NO_SPACE;
  memset(s, 0, sizeof(*s));
  s->link = rnc_link_new(r->random, r->random_context);
  s->service = s->link ? rnc_service_new(s->link, r->max_value, r->random,
                                         r->random_context)
                       : NULL;
  if (!s->service) {
    rnc_link_free(s->link);
    memset(s, 0, sizeof(*s));
    return RNC_NO_SPACE;
  }
  result = rnc_link_configure_mtu(
      s->link, rnc_node_link_mtu_on(r->node, event->interface_id));
  if (result == RNC_OK)
    result = rnc_link_accept(s->link, &d->identity, d->destination,
                             &event->packet, now);
  if (result == RNC_OK)
    result = rnc_link_address(s->link, s->id);
  if (result == RNC_OK)
    result = rnc_node_bind_link_on(r->node, s->id, event->interface_id);
  for (i = 0; result == RNC_OK && i < RNC_RESPONDER_HANDLERS; i++)
    if (d->handlers[i].used)
      result = rnc_service_register(s->service, d->handlers[i].path,
                                    d->handlers[i].policy,
                                    d->handlers[i].allowed_count
                                        ? (const uint8_t(*)[16])d->handlers[i]
                                              .allowed
                                        : NULL,
                                    d->handlers[i].allowed_count);
  if (result != RNC_OK) {
    rnc_service_free(s->service);
    rnc_link_free(s->link);
    (void)rnc_node_unbind_link(r->node, s->id);
    OPENSSL_cleanse(s, sizeof(*s));
    return result;
  }
  (void)rnc_service_set_max_request_size(s->service, d->max_request);
  s->used = 1;
  s->destination = (size_t)(d - r->destinations);
  return RNC_OK;
}
rnc_result rnc_responder_input(rnc_responder *r, const rnc_node_event *event,
                               uint64_t unix_seconds, uint64_t now_ms) {
  const rnc_packet *p;
  size_t i;
  rnc_result result;
  (void)unix_seconds;
  if (!r || !event)
    return RNC_INVALID;
  if (now_ms > r->now)
    r->now = now_ms;
  if (event->type != RNC_NODE_LOCAL)
    return RNC_AGAIN;
  p = &event->packet;
  if ((p->flags & 3u) == RNC_LINKREQUEST) {
    responder_destination *d = find_destination(r, p->destination);
    return d ? accept_link(r, d, event, now_ms) : RNC_AGAIN;
  }
  for (i = 0; i < RNC_RESPONDER_LINKS; i++)
    if (r->slots[i].used && !memcmp(r->slots[i].id, p->destination, 16)) {
      result = rnc_link_input(r->slots[i].link, p, now_ms);
      return result == RNC_AGAIN ? RNC_NO_SPACE : result;
    }
  return RNC_AGAIN;
}
static void run_requests(rnc_responder *r, responder_slot *s, uint64_t now) {
  rnc_service_event event;
  size_t got;
  while (rnc_service_poll(s->service, &event, r->request, r->max_value,
                          &got) == RNC_OK) {
    responder_destination *d = &r->destinations[s->destination];
    size_t i, written = 0;
    if (event.type != RNC_SERVICE_REQUEST)
      continue;
    for (i = 0; i < RNC_RESPONDER_HANDLERS; i++)
      if (d->handlers[i].used &&
          !memcmp(d->handlers[i].hash, event.path_hash, 16)) {
        rnc_result result;
        rnc_responder_file file = {r->file_data, r->file_data ? r->max_value : 0, 0,
                                   r->file_meta, r->file_meta ? RNC_RESPONDER_METADATA_MAX : 0, 0};
        const uint8_t *who = event.identified ? event.identity_hash : NULL;
        r->busy = 1;
        r->current = s;
        r->current_event = event;
        if (d->handlers[i].file_function)
          result = d->handlers[i].file_function(
              d->handlers[i].context, d->handlers[i].path, r->request, got, who,
              r->response, r->max_value, &written, &file);
        else
          result = d->handlers[i].function(
              d->handlers[i].context, d->handlers[i].path, r->request, got, who,
              r->response, r->max_value, &written);
        r->busy = 0;
        r->current = NULL;
        if (r->now > now) /* a handler that kept the node running moved time on */
          now = r->now;
        if (s->release_pending) {
          slot_release(r, s);
          return;
        }
        if (result == RNC_OK && file.data_size && file.metadata_size &&
            file.data_size <= r->max_value &&
            file.metadata_size <= RNC_RESPONDER_METADATA_MAX)
          (void)rnc_service_respond_file(s->service, event.request_id,
                                         file.data, file.data_size,
                                         file.metadata, file.metadata_size,
                                         now);
        else if (result == RNC_OK && written) {
          (void)rnc_service_respond(s->service, event.request_id, r->response,
                                    written, now);
        }
        break;
      }
  }
}
rnc_result rnc_responder_tick(rnc_responder *r, uint64_t unix_seconds,
                              uint64_t now_ms) {
  size_t i;
  if (!r)
    return RNC_INVALID;
  if (now_ms > r->now)
    r->now = now_ms;
  for (i = 0; i < RNC_RESPONDER_LINKS; i++) {
    responder_slot *s = &r->slots[i];
    rnc_link_event le;
    int closed = 0;
    if (!s->used)
      continue;
    (void)rnc_link_tick(s->link, now_ms);
    while (rnc_link_poll(s->link, &le) == RNC_OK) {
      if (le.type == RNC_LINK_SEND)
        (void)rnc_node_send(r->node, &le.packet, unix_seconds, now_ms);
      else if (le.type == RNC_LINK_PACKET ||
               le.type == RNC_LINK_RESOURCE_PACKET ||
               le.type == RNC_LINK_CLOSED) {
        (void)rnc_service_input(s->service, &le, now_ms);
        if (le.type == RNC_LINK_CLOSED)
          closed = 1;
      }
    }
    if (!closed) {
      (void)rnc_service_pump(s->service, now_ms);
      (void)rnc_service_tick(s->service, now_ms);
      if (!r->busy)
        run_requests(r, s, now_ms);
      if (r->now > now_ms) /* a handler kept the node running meanwhile */
        now_ms = r->now;
      /* answers queue link packets; send them without waiting a tick */
      while (rnc_link_poll(s->link, &le) == RNC_OK)
        if (le.type == RNC_LINK_SEND)
          (void)rnc_node_send(r->node, &le.packet, unix_seconds, now_ms);
    }
    if (closed) {
      if (r->busy && r->current == s)
        s->release_pending = 1;
      else
        slot_release(r, s);
    }
  }
  return RNC_OK;
}
rnc_result rnc_responder_defer(rnc_responder *r, rnc_responder_ticket *t,
                               uint64_t lifetime_ms) {
  if (!r || !t || !lifetime_ms)
    return RNC_INVALID;
  if (!r->busy || !r->current)
    return RNC_STATE;
  if (rnc_service_extend_request(r->current->service, r->current_event.request_id,
                                 lifetime_ms, r->now) != RNC_OK)
    return RNC_STATE;
  memcpy(t->link_id, r->current->id, 16);
  memcpy(t->request_id, r->current_event.request_id, 16);
  t->valid = 1;
  return RNC_OK;
}
rnc_result rnc_responder_reply(rnc_responder *r, rnc_responder_ticket *t,
                               const void *value, size_t n, uint64_t now_ms) {
  size_t i;
  rnc_result result;
  if (!r || !t || !value || !n)
    return RNC_INVALID;
  if (!t->valid)
    return RNC_STATE;
  if (now_ms > r->now)
    r->now = now_ms;
  for (i = 0; i < RNC_RESPONDER_LINKS; i++)
    if (r->slots[i].used && !memcmp(r->slots[i].id, t->link_id, 16)) {
      result = rnc_service_respond(r->slots[i].service, t->request_id, value, n,
                                   r->now);
      if (result == RNC_OK)
        t->valid = 0;
      return result;
    }
  return RNC_STATE;
}
rnc_result rnc_responder_request_identity(const rnc_responder *r,
                                          rnc_identity *identity) {
  if (!r || !identity)
    return RNC_INVALID;
  if (!r->busy || !r->current_event.identified)
    return RNC_STATE;
  return rnc_identity_from_public(identity, r->current_event.identity_public_key);
}
