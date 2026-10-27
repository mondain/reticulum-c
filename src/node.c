#include <openssl/crypto.h>
#include <reticulum_c/rnc_node.h>
#include <reticulum_c/rnc_security.h>
#include <stdlib.h>
#include <string.h>
#define NODE_QUEUE 64u
#define NODE_HASHES 256u
#define NODE_REVERSE 128u
#define NODE_REQUESTS 32u
#define PATH_LIFETIME UINT64_C(604800000)
#define PACKET_LIFETIME UINT64_C(300000)
#define REQUEST_LIFETIME UINT64_C(15000)
#define NODE_ANNOUNCES 64u
#define NODE_RATES 128u
/* PATHFINDER_G (5s grace) + PATHFINDER_RW (0.5s window) before the one retry. */
#define ANNOUNCE_RETRY_MS UINT64_C(5500)
#define LOCAL_REBROADCASTS_MAX 2u
#define NODE_HELD 32u
#define FREQ_SAMPLES 48u
#define FREQ_DECAY_MS UINT64_C(10000)
typedef struct node_freq {
  uint64_t t[FREQ_SAMPLES];
  size_t head, count;
} node_freq;
typedef struct node_interface {
  uint32_t id, bitrate;
  size_t mtu;
  int local;
  rnc_interface_mode mode;
  uint32_t cap, rate_target, rate_grace, rate_penalty;
  int recursive;
  rnc_ingress_policy ingress;
  uint64_t created, announce_after;
  node_freq ia, ip, op;
  int ic_active, pr_active;
  unsigned pr_cooldown;
  uint64_t ic_activated, ic_sustained, ic_held_release, pr_activated,
      pr_sustained;
} node_interface;
typedef struct node_held {
  int used;
  uint32_t iface;
  uint8_t destination[16], hops;
  rnc_packet packet;
} node_held;
typedef struct node_announce {
  int used;
  uint8_t destination[16], hops;
  uint32_t ingress;
  unsigned heard;
  uint64_t retry_at;
  rnc_packet packet;
} node_announce;
typedef struct node_rate {
  int used;
  uint8_t destination[16];
  unsigned violations;
  uint64_t last, blocked_until, touched;
} node_rate;
typedef struct node_route {
  int used;
  rnc_route route;
  rnc_packet packet;
} node_route;
typedef struct node_destination {
  int used, type, has_ratchet, proof;
  uint8_t ratchet[32];
  rnc_identity identity;
  char name[128];
  uint8_t address[16], app[316];
  size_t size;
} node_destination;
typedef struct node_hash {
  uint8_t hash[32];
  uint64_t expiry;
} node_hash;
typedef struct node_reverse {
  int used;
  uint8_t hash[32];
  uint32_t in, out;
  rnc_identity signer;
  uint64_t expiry;
} node_reverse;
typedef struct node_link {
  int used, local, active;
  uint8_t id[16];
  uint32_t in, out;
  uint8_t in_hops, out_hops;
  rnc_identity signer;
  uint64_t expiry;
} node_link;
typedef struct node_receipt {
  int used;
  uint8_t hash[32];
  rnc_identity signer;
  uint64_t sent, expiry;
} node_receipt;
typedef struct node_request {
  int used, pending;
  uint8_t destination[16], tag[16];
  size_t tag_size;
  uint32_t ingress;
  uint64_t expiry;
} node_request;
typedef struct node_queued {
  int used;
  uint32_t iface;
  rnc_packet packet;
  uint64_t due;
} node_queued;
struct rnc_node {
  uint8_t id[16];
  int transport;
  rnc_random_fn random;
  void *random_context;
  uint64_t now;
  node_interface interfaces[RNC_NODE_INTERFACES];
  node_route routes[RNC_NODE_ROUTES];
  node_destination destinations[RNC_NODE_DESTINATIONS];
  node_link links[RNC_NODE_LINKS];
  node_hash hashes[NODE_HASHES];
  size_t next_hash;
  node_reverse reverse[NODE_REVERSE];
  node_request requests[NODE_REQUESTS];
  node_receipt receipts[RNC_NODE_RECEIPTS];
  node_announce announces[NODE_ANNOUNCES];
  node_held held[NODE_HELD];
  const rnc_packet *input_packet;
  int releasing;
  node_rate rates[NODE_RATES];
  node_queued queued[NODE_QUEUE];
  rnc_node_event events[RNC_NODE_EVENTS];
  size_t head, count;
};
static uint64_t after(uint64_t now, uint64_t delay) {
  return UINT64_MAX - now < delay ? UINT64_MAX : now + delay;
}
static int same(const uint8_t *a, const uint8_t *b) {
  return !memcmp(a, b, 16);
}
static rnc_result path_address(uint8_t out[16]) {
  uint8_t hash[32];
  rnc_result r = rnc_hash("rnstransport.path.request",
                          sizeof("rnstransport.path.request") - 1u, hash);
  if (r == RNC_OK)
    r = rnc_hash(hash, 10, hash);
  if (r == RNC_OK)
    memcpy(out, hash, 16);
  return r;
}
rnc_result rnc_path_request_create(const uint8_t destination[16],
                                   const uint8_t transport[16],
                                   const uint8_t *tag, size_t tag_size,
                                   rnc_packet *packet) {
  rnc_packet p = {0};
  rnc_result r;
  if (!destination || !tag || !tag_size || tag_size > 16 || !packet)
    return RNC_INVALID;
  /* Without a transport ID at most16 tag bytes are unambiguously encoded. */
  r = path_address(p.destination);
  if (r != RNC_OK)
    return r;
  p.flags = 8;
  memcpy(p.data, destination, 16);
  p.data_size = 16;
  if (transport) {
    memcpy(p.data + 16, transport, 16);
    p.data_size += 16;
  }
  memcpy(p.data + p.data_size, tag, tag_size);
  p.data_size += tag_size;
  *packet = p;
  return RNC_OK;
}
rnc_result rnc_path_request_decode(const rnc_packet *packet,
                                   rnc_path_request *request) {
  rnc_path_request q = {0};
  uint8_t address[16];
  size_t offset;
  rnc_result r;
  if (!packet || !request)
    return RNC_INVALID;
  r = path_address(address);
  if (r != RNC_OK)
    return r;
  if ((packet->flags & 0x8fu) != 8 || packet->context ||
      !same(address, packet->destination) || packet->data_size < 17 ||
      packet->data_size > sizeof(packet->data))
    return RNC_PROTOCOL;
  memcpy(q.destination, packet->data, 16);
  offset = packet->data_size > 32 ? 32 : 16;
  if (offset == 32) {
    q.has_transport = 1;
    memcpy(q.transport_id, packet->data + 16, 16);
  }
  q.tag_size = packet->data_size - offset;
  if (q.tag_size > 16)
    q.tag_size = 16;
  memcpy(q.tag, packet->data + offset, q.tag_size);
  *request = q;
  return RNC_OK;
}
static node_interface *interface(rnc_node *n, uint32_t id) {
  size_t i;
  for (i = 0; i < RNC_NODE_INTERFACES; i++)
    if (n->interfaces[i].id == id && id)
      return &n->interfaces[i];
  return NULL;
}
static size_t interface_count(const rnc_node *n) {
  size_t i, c = 0;
  for (i = 0; i < RNC_NODE_INTERFACES; i++)
    c += n->interfaces[i].id != 0;
  return c;
}
static node_route *route_find(rnc_node *n, const uint8_t address[16],
                              uint64_t now) {
  size_t i;
  for (i = 0; i < RNC_NODE_ROUTES; i++)
    if (n->routes[i].used && n->routes[i].route.expires_ms > now &&
        same(n->routes[i].route.destination, address))
      return &n->routes[i];
  return NULL;
}
static node_destination *destination_find(rnc_node *n,
                                          const uint8_t address[16]) {
  size_t i;
  for (i = 0; i < RNC_NODE_DESTINATIONS; i++)
    if (n->destinations[i].used && same(n->destinations[i].address, address))
      return &n->destinations[i];
  return NULL;
}
static node_link *link_find(rnc_node *n, const uint8_t address[16]) {
  size_t i;
  for (i = 0; i < RNC_NODE_LINKS; i++)
    if (n->links[i].used && same(n->links[i].id, address))
      return &n->links[i];
  return NULL;
}
static rnc_node_event *emit(rnc_node *n, rnc_node_event_type type,
                            uint32_t iface, const rnc_packet *packet) {
  rnc_node_event *e = &n->events[(n->head + n->count) % RNC_NODE_EVENTS];
  memset(e, 0, sizeof(*e));
  e->type = type;
  e->interface_id = iface;
  if (packet)
    e->packet = *packet;
  n->count++;
  return e;
}
static int room(const rnc_node *n, size_t wanted) {
  return wanted <= RNC_NODE_EVENTS - n->count;
}
static size_t queue_free(const rnc_node *n) {
  size_t i, c = 0;
  for (i = 0; i < NODE_QUEUE; i++)
    c += !n->queued[i].used;
  return c;
}
/* Build a delivery proof: destination is the truncated packet hash and the
 * payload is [hash +] Ed25519 signature of the full hash. */
static rnc_result make_proof(const node_destination *d, const rnc_packet *p,
                             int implicit, rnc_packet *proof) {
  uint8_t hash[32], sig[64];
  rnc_packet out = {0};
  rnc_result r = rnc_packet_hash(p, hash);
  if (r == RNC_OK)
    r = rnc_identity_sign(&d->identity, hash, 32, sig);
  if (r != RNC_OK)
    return r;
  out.flags = (uint8_t)RNC_PROOF;
  memcpy(out.destination, hash, 16);
  if (implicit) {
    memcpy(out.data, sig, 64);
    out.data_size = 64;
  } else {
    memcpy(out.data, hash, 32);
    memcpy(out.data + 32, sig, 64);
    out.data_size = 96;
  }
  *proof = out;
  return RNC_OK;
}
/* Returns 1 and queues a RECEIPT event when a tracked packet matches. */
static int receipt_complete(rnc_node *n, const rnc_packet *proof,
                            uint64_t now) {
  size_t i;
  for (i = 0; i < RNC_NODE_RECEIPTS; i++) {
    node_receipt *t = &n->receipts[i];
    rnc_node_event *e;
    if (!t->used || memcmp(t->hash, proof->destination, 16))
      continue;
    e = emit(n, RNC_NODE_RECEIPT, 0, NULL);
    memcpy(e->receipt_hash, t->hash, 32);
    e->receipt_status = RNC_RECEIPT_DELIVERED;
    e->rtt_ms = now - t->sent;
    t->used = 0;
    return 1;
  }
  return 0;
}
static int duplicate(const rnc_node *n, const uint8_t hash[32], uint64_t now) {
  size_t i;
  for (i = 0; i < NODE_HASHES; i++)
    if (n->hashes[i].expiry > now && !memcmp(hash, n->hashes[i].hash, 32))
      return 1;
  return 0;
}
static void remember(rnc_node *n, const uint8_t hash[32], uint64_t now) {
  node_hash *h = &n->hashes[n->next_hash++ % NODE_HASHES];
  memcpy(h->hash, hash, 32);
  h->expiry = after(now, PACKET_LIFETIME);
}
static void queue(rnc_node *n, uint32_t iface, const rnc_packet *p,
                  uint64_t due) {
  size_t i;
  for (i = 0; i < NODE_QUEUE; i++)
    if (!n->queued[i].used) {
      n->queued[i].used = 1;
      n->queued[i].iface = iface;
      n->queued[i].packet = *p;
      n->queued[i].due = due;
      return;
    }
}
static void broadcast(rnc_node *n, const rnc_packet *p, uint32_t except) {
  size_t i;
  for (i = 0; i < RNC_NODE_INTERFACES; i++)
    if (n->interfaces[i].id && n->interfaces[i].id != except)
      emit(n, RNC_NODE_SEND, n->interfaces[i].id, p);
}
rnc_node *rnc_node_new(const rnc_identity *identity, int transport,
                       rnc_random_fn random, void *context) {
  rnc_node *n;
  if (!identity || !random)
    return NULL;
  n = calloc(1, sizeof(*n));
  if (n) {
    memcpy(n->id, identity->hash, 16);
    n->transport = !!transport;
    n->random = random;
    n->random_context = context;
  }
  return n;
}
void rnc_node_free(rnc_node *n) {
  if (n) {
    OPENSSL_cleanse(n, sizeof(*n));
    free(n);
  }
}
rnc_result rnc_node_add_interface(rnc_node *n, uint32_t id, uint32_t bitrate) {
  size_t i;
  if (!n || !id || !bitrate)
    return RNC_INVALID;
  if (interface(n, id))
    return RNC_STATE;
  for (i = 0; i < RNC_NODE_INTERFACES; i++)
    if (!n->interfaces[i].id) {
      n->interfaces[i].id = id;
      n->interfaces[i].bitrate = bitrate;
      n->interfaces[i].mtu = RNC_MTU;
      n->interfaces[i].mode = RNC_MODE_FULL;
      n->interfaces[i].cap = 0;
      n->interfaces[i].rate_target = n->interfaces[i].rate_grace = 0;
      n->interfaces[i].rate_penalty = 0;
      n->interfaces[i].recursive = 0;
      memset(&n->interfaces[i].ingress, 0, sizeof(n->interfaces[i].ingress));
      n->interfaces[i].created = n->now;
      memset(&n->interfaces[i].ia, 0, sizeof(node_freq));
      memset(&n->interfaces[i].ip, 0, sizeof(node_freq));
      memset(&n->interfaces[i].op, 0, sizeof(node_freq));
      n->interfaces[i].ic_active = n->interfaces[i].pr_active = 0;
      return RNC_OK;
    }
  return RNC_NO_SPACE;
}
rnc_result rnc_node_interface_mtu(rnc_node *n, uint32_t id, size_t mtu) {
  node_interface *iface;
  size_t i;
  if (!n || !id || mtu < RNC_MTU || mtu > RNC_MAX_MTU)
    return RNC_INVALID;
  iface = interface(n, id);
  if (!iface)
    return RNC_STATE;
  for (i = 0; i < RNC_NODE_LINKS; i++)
    if (n->links[i].used && (n->links[i].in == id || n->links[i].out == id))
      return RNC_STATE;
  iface->mtu = mtu;
  return RNC_OK;
}
rnc_result rnc_node_local_interface(rnc_node *n, uint32_t id, int local) {
  node_interface *iface;
  size_t i;
  if (!n || !id)
    return RNC_INVALID;
  iface = interface(n, id);
  if (!iface)
    return RNC_STATE;
  for (i = 0; i < RNC_NODE_ROUTES; i++)
    if (n->routes[i].used && n->routes[i].route.interface_id == id)
      return RNC_STATE;
  for (i = 0; i < RNC_NODE_LINKS; i++)
    if (n->links[i].used && (n->links[i].in == id || n->links[i].out == id))
      return RNC_STATE;
  iface->local = !!local;
  return RNC_OK;
}
rnc_result rnc_node_interface_policy(rnc_node *n, uint32_t id,
                                     const rnc_interface_policy *policy) {
  node_interface *i;
  if (!n || !policy || policy->mode > RNC_MODE_BOUNDARY ||
      policy->announce_cap_permille > 1000u)
    return RNC_INVALID;
  i = interface(n, id);
  if (!i)
    return RNC_STATE;
  i->mode = policy->mode;
  i->cap = policy->announce_cap_permille;
  i->rate_target = policy->announce_rate_target;
  i->rate_grace = policy->announce_rate_grace;
  i->rate_penalty = policy->announce_rate_penalty;
  i->recursive = policy->recursive_path_requests != 0;
  i->ingress = policy->ingress;
  return RNC_OK;
}
rnc_result rnc_node_remove_interface(rnc_node *n, uint32_t id) {
  node_interface *iface;
  size_t i;
  if (!n || !id)
    return RNC_INVALID;
  iface = interface(n, id);
  if (!iface)
    return RNC_STATE;
  memset(iface, 0, sizeof(*iface));
  for (i = 0; i < RNC_NODE_ROUTES; i++)
    if (n->routes[i].route.interface_id == id)
      n->routes[i].used = 0;
  for (i = 0; i < RNC_NODE_LINKS; i++)
    if (n->links[i].in == id || n->links[i].out == id)
      n->links[i].used = 0;
  for (i = 0; i < NODE_REVERSE; i++)
    if (n->reverse[i].in == id || n->reverse[i].out == id)
      n->reverse[i].used = 0;
  for (i = 0; i < NODE_REQUESTS; i++)
    if (n->requests[i].ingress == id)
      n->requests[i].used = 0;
  for (i = 0; i < NODE_QUEUE; i++)
    if (n->queued[i].iface == id)
      n->queued[i].used = 0;
  /* Already-polled SEND events belong to the host; unpolled events are
   * filtered. */
  for (i = 0; i < n->count; i++) {
    rnc_node_event *e = &n->events[(n->head + i) % RNC_NODE_EVENTS];
    if (e->interface_id == id)
      e->interface_id = 0;
  }
  return RNC_OK;
}
rnc_result rnc_node_add_destination_ex(rnc_node *n,
                                       const rnc_identity *identity, int type,
                                       const char *name, const void *app,
                                       size_t size, uint8_t address[16]) {
  node_destination d = {0};
  uint8_t name_hash[10];
  size_t i;
  rnc_result r;
  if (!n || !name || strlen(name) >= sizeof(d.name) || (!app && size) ||
      size > sizeof(d.app) || !address || type < RNC_SINGLE || type > RNC_PLAIN)
    return RNC_INVALID;
  if (type == RNC_SINGLE && (!identity || !identity->has_private))
    return RNC_INVALID;
  if (type == RNC_GROUP && !identity)
    return RNC_INVALID;
  if (type == RNC_PLAIN && identity)
    return RNC_INVALID;
  if (type != RNC_SINGLE && size)
    return RNC_INVALID;
  if (type == RNC_PLAIN)
    r = rnc_plain_destination_hash(name, d.address);
  else
    r = rnc_destination_hash(name, identity, name_hash, d.address);
  if (r != RNC_OK)
    return r;
  if (destination_find(n, d.address))
    return RNC_STATE;
  for (i = 0; i < RNC_NODE_DESTINATIONS && n->destinations[i].used; i++) {
  }
  if (i == RNC_NODE_DESTINATIONS)
    return RNC_NO_SPACE;
  d.used = 1;
  d.type = type;
  if (type == RNC_SINGLE)
    d.identity = *identity;
  else if (identity) {
    r = rnc_identity_from_public(&d.identity, identity->public_key);
    if (r != RNC_OK)
      return r;
  }
  strcpy(d.name, name);
  if (size)
    memcpy(d.app, app, size);
  d.size = size;
  n->destinations[i] = d;
  memcpy(address, d.address, 16);
  OPENSSL_cleanse(&d, sizeof(d));
  return RNC_OK;
}
rnc_result rnc_node_add_destination(rnc_node *n, const rnc_identity *identity,
                                    const char *name, const void *app,
                                    size_t size, uint8_t address[16]) {
  return rnc_node_add_destination_ex(n, identity, RNC_SINGLE, name, app, size,
                                     address);
}
rnc_result rnc_node_set_ratchet(rnc_node *n, const uint8_t address[16],
                                const uint8_t key[32]) {
  node_destination *d;
  if (!n || !address)
    return RNC_INVALID;
  d = destination_find(n, address);
  if (!d || d->type != RNC_SINGLE)
    return RNC_STATE;
  if (key && d->size > 284)
    return RNC_NO_SPACE;
  d->has_ratchet = key != NULL;
  if (key)
    memcpy(d->ratchet, key, 32);
  else
    OPENSSL_cleanse(d->ratchet, 32);
  return RNC_OK;
}
static rnc_result destination_announce(rnc_node *n, node_destination *d,
                                       uint64_t unix_seconds, rnc_packet *p) {
  if (d->has_ratchet)
    return rnc_announce_create_ratchet(&d->identity, d->name, d->ratchet,
                                       d->app, d->size, unix_seconds, n->random,
                                       n->random_context, p);
  return rnc_announce_create(&d->identity, d->name, d->app, d->size,
                             unix_seconds, n->random, n->random_context, p);
}
rnc_result rnc_node_announce(rnc_node *n, const uint8_t destination[16],
                             uint64_t unix_seconds, uint64_t now) {
  node_destination *d;
  rnc_packet p;
  size_t i;
  rnc_result r;
  if (!n || !destination || now < n->now)
    return RNC_INVALID;
  d = destination_find(n, destination);
  if (!d || d->type != RNC_SINGLE)
    return RNC_STATE;
  if (queue_free(n) < interface_count(n))
    return RNC_AGAIN;
  r = destination_announce(n, d, unix_seconds, &p);
  if (r != RNC_OK)
    return r;
  for (i = 0; i < RNC_NODE_INTERFACES; i++)
    if (n->interfaces[i].id && n->interfaces[i].mode != RNC_MODE_ACCESS_POINT)
      queue(n, n->interfaces[i].id, &p, now);
  n->now = now;
  return RNC_OK;
}
rnc_result rnc_node_lookup(const rnc_node *n, const uint8_t address[16],
                           uint64_t now, rnc_route *route) {
  size_t i;
  if (!n || !address || !route || now < n->now)
    return RNC_INVALID;
  for (i = 0; i < RNC_NODE_ROUTES; i++)
    if (n->routes[i].used && n->routes[i].route.expires_ms > now &&
        same(n->routes[i].route.destination, address)) {
      *route = n->routes[i].route;
      return RNC_OK;
    }
  return RNC_AGAIN;
}
rnc_result rnc_node_poll(rnc_node *n, rnc_node_event *event) {
  if (!n || !event)
    return RNC_INVALID;
  while (n->count) {
    rnc_node_event e = n->events[n->head];
    memset(&n->events[n->head], 0, sizeof(e));
    n->head = (n->head + 1) % RNC_NODE_EVENTS;
    n->count--;
    if (!e.interface_id && e.type != RNC_NODE_RECEIPT)
      continue;
    *event = e;
    return RNC_OK;
  }
  return RNC_AGAIN;
}
rnc_result rnc_node_bind_link(rnc_node *n, const uint8_t id[16]) {
  size_t i;
  if (!n || !id)
    return RNC_INVALID;
  if (link_find(n, id))
    return RNC_STATE;
  for (i = 0; i < RNC_NODE_LINKS; i++)
    if (!n->links[i].used) {
      n->links[i].used = n->links[i].local = n->links[i].active = 1;
      memcpy(n->links[i].id, id, 16);
      return RNC_OK;
    }
  return RNC_NO_SPACE;
}
rnc_result rnc_node_bind_link_on(rnc_node *n, const uint8_t id[16],
                                 uint32_t iface) {
  rnc_result r;
  if (!n || !id || !interface(n, iface))
    return RNC_INVALID;
  r = rnc_node_bind_link(n, id);
  if (r == RNC_OK)
    link_find(n, id)->out = iface;
  return r;
}
rnc_result rnc_node_unbind_link(rnc_node *n, const uint8_t id[16]) {
  node_link *l;
  if (!n || !id)
    return RNC_INVALID;
  l = link_find(n, id);
  if (!l)
    return RNC_STATE;
  OPENSSL_cleanse(l, sizeof(*l));
  return RNC_OK;
}
static uint64_t announce_time(const rnc_announce *a) {
  size_t i;
  uint64_t t = 0;
  for (i = 5; i < 10; i++)
    t = (t << 8) | a->random_hash[i];
  return t;
}
static void relay_announce(rnc_node *n, rnc_packet *p) {
  p->flags = (uint8_t)((p->flags & 0x2fu) | 0x50u);
  memcpy(p->transport_id, n->id, 16);
}
static int mode_allows(rnc_interface_mode from, rnc_interface_mode to) {
  if (to == RNC_MODE_ACCESS_POINT)
    return 0;
  if (to == RNC_MODE_ROAMING)
    return from != RNC_MODE_ROAMING && from != RNC_MODE_BOUNDARY;
  if (to == RNC_MODE_BOUNDARY)
    return from != RNC_MODE_ROAMING;
  return 1;
}
static uint64_t path_lifetime(const rnc_node *n, uint32_t iface) {
  const node_interface *i = NULL;
  size_t k;
  for (k = 0; k < RNC_NODE_INTERFACES; k++)
    if (n->interfaces[k].id == iface)
      i = &n->interfaces[k];
  if (i && i->mode == RNC_MODE_ACCESS_POINT)
    return UINT64_C(86400000);
  if (i && i->mode == RNC_MODE_ROAMING)
    return UINT64_C(21600000);
  return PATH_LIFETIME;
}
static int relay_target(rnc_node *n, uint32_t ingress, uint32_t target) {
  return (n->transport || interface(n, ingress)->local ||
          interface(n, target)->local) &&
         mode_allows(interface(n, ingress)->mode, interface(n, target)->mode);
}
static size_t relay_count(rnc_node *n, uint32_t ingress) {
  size_t i, c = 0;
  for (i = 0; i < RNC_NODE_INTERFACES; i++)
    if (n->interfaces[i].id && relay_target(n, ingress, n->interfaces[i].id))
      c++;
  return c;
}
/* Reference-compatible event-frequency tracking and burst control (manual
 * 8.18-8.20). Timestamps are caller milliseconds. */
static void freq_add(node_freq *f, uint64_t now) {
  if (f->count == FREQ_SAMPLES) {
    f->head = (f->head + 1) % FREQ_SAMPLES;
    f->count--;
  }
  f->t[(f->head + f->count++) % FREQ_SAMPLES] = now;
}
static double freq_hz(node_freq *f, uint64_t now, size_t min_samples,
                      size_t extra) {
  size_t n = f->count + extra;
  uint64_t span;
  if (f->count <= min_samples)
    return 0.0;
  span = now - f->t[f->head];
  if (span > FREQ_DECAY_MS) {
    f->head = (f->head + 1) % FREQ_SAMPLES;
    f->count--;
  }
  return span ? (double)n * 1000.0 / (double)span : 0.0;
}
static uint64_t ic_ms(uint32_t seconds, uint32_t fallback) {
  return (uint64_t)(seconds ? seconds : fallback) * 1000u;
}
static double ic_hz(uint32_t mhz, uint32_t fallback_mhz) {
  return (double)(mhz ? mhz : fallback_mhz) / 1000.0;
}
static int ic_young(const node_interface *i, uint64_t now) {
  return now - i->created < ic_ms(i->ingress.new_time_s, 7200u);
}
static double announce_threshold(const node_interface *i, uint64_t now) {
  return ic_young(i, now) ? ic_hz(i->ingress.burst_freq_new_mhz, 3000u)
                          : ic_hz(i->ingress.burst_freq_mhz, 10000u);
}
static int ingress_limit(node_interface *i, uint64_t now) {
  double thr = announce_threshold(i, now), hz;
  uint64_t hold = ic_ms(i->ingress.burst_hold_s, 15u);
  if (i->ingress.disabled)
    return 0;
  hz = freq_hz(&i->ia, now, 2, 0);
  if (i->ic_active) {
    if (hz < thr && now > i->ic_activated + hold &&
        now > i->ic_sustained + hold) {
      if (i->ia.count >= 2)
        i->ic_active = 0;
    } else if (hz >= thr)
      i->ic_sustained = now;
    return 1;
  }
  if (hz > thr) {
    i->ic_active = 1;
    i->ic_activated = i->ic_sustained = now;
    i->ic_held_release = now + ic_ms(i->ingress.burst_penalty_s, 15u);
    return 1;
  }
  return 0;
}
static int ingress_limit_pr(node_interface *i, uint64_t now) {
  double thr = ic_young(i, now) ? ic_hz(i->ingress.pr_burst_freq_new_mhz, 3000u)
                                : ic_hz(i->ingress.pr_burst_freq_mhz, 8000u);
  double hz;
  uint64_t hold = ic_ms(i->ingress.burst_hold_s, 15u);
  if (i->ingress.disabled)
    return 0;
  hz = freq_hz(&i->ip, now, 2, 0);
  if (i->pr_active) {
    if (hz < thr && now > i->pr_activated + hold &&
        now > i->pr_sustained + hold) {
      if (i->pr_cooldown == 0)
        i->pr_active = 0;
      else
        i->pr_cooldown--;
    } else {
      i->pr_cooldown = 3;
      if (hz >= thr)
        i->pr_sustained = now;
    }
    return 1;
  }
  if (hz > thr) {
    i->pr_active = 1;
    i->pr_activated = i->pr_sustained = now;
    i->pr_cooldown = 3;
    return 1;
  }
  return 0;
}
static int egress_limit_pr(node_interface *i, uint64_t now) {
  if (i->ingress.disabled)
    return 0;
  return freq_hz(&i->op, now, 1, 1) > ic_hz(i->ingress.ec_pr_freq_mhz, 5000u) &&
         i->op.count >= 2;
}
static void hold_announce(rnc_node *n, uint32_t iface, const rnc_packet *wire,
                          uint8_t hops) {
  size_t i, free_slot = NODE_HELD, mine = 0;
  const node_interface *f = interface(n, iface);
  size_t limit = f->ingress.max_held ? f->ingress.max_held : 256u;
  if (hops >= 127)
    return;
  for (i = 0; i < NODE_HELD; i++) {
    if (!n->held[i].used) {
      free_slot = i;
      continue;
    }
    if (n->held[i].iface == iface) {
      if (same(n->held[i].destination, wire->destination)) {
        n->held[i].packet = *wire;
        n->held[i].hops = hops;
        return;
      }
      mine++;
    }
  }
  if (free_slot == NODE_HELD || mine >= limit)
    return;
  n->held[free_slot].used = 1;
  n->held[free_slot].iface = iface;
  n->held[free_slot].hops = hops;
  memcpy(n->held[free_slot].destination, wire->destination, 16);
  n->held[free_slot].packet = *wire;
}
/* Whether an announce for an unknown destination may be processed now. */
static int path_request_pending(const rnc_node *n, const uint8_t d[16],
                                uint64_t now) {
  size_t i;
  for (i = 0; i < NODE_REQUESTS; i++)
    if (n->requests[i].used && n->requests[i].expiry > now &&
        same(n->requests[i].destination, d))
      return 1;
  return 0;
}
/* Reference-compatible per-destination announce rate table. Returns nonzero
 * when the announce must not be rebroadcast. Paths are learned regardless. */
static int rate_blocked(rnc_node *n, const node_interface *iface,
                        const uint8_t destination[16], uint64_t now) {
  node_rate *r = NULL, *oldest = &n->rates[0];
  uint64_t target = (uint64_t)iface->rate_target * 1000u;
  size_t i;
  if (!iface->rate_target)
    return 0;
  for (i = 0; i < NODE_RATES; i++) {
    if (n->rates[i].used && same(n->rates[i].destination, destination)) {
      r = &n->rates[i];
      break;
    }
    if (!n->rates[i].used || n->rates[i].touched < oldest->touched)
      oldest = &n->rates[i];
  }
  if (!r) {
    r = oldest;
    memset(r, 0, sizeof(*r));
    r->used = 1;
    memcpy(r->destination, destination, 16);
    r->last = r->touched = now;
    return 0;
  }
  r->touched = now;
  if (now <= r->blocked_until)
    return 1;
  if (now - r->last < target)
    r->violations++;
  else if (r->violations)
    r->violations--;
  if (r->violations > iface->rate_grace) {
    r->blocked_until = after(after(r->last, target),
                             (uint64_t)iface->rate_penalty * 1000u);
    return 1;
  }
  r->last = now;
  return 0;
}
/* Another node rebroadcast an announce we have scheduled for retransmission. */
static void heard_rebroadcast(rnc_node *n, const rnc_packet *p, uint64_t now) {
  size_t i;
  if (!(p->flags & 0x40u))
    return;
  for (i = 0; i < NODE_ANNOUNCES; i++) {
    node_announce *a = &n->announces[i];
    if (!a->used || !same(a->destination, p->destination))
      continue;
    if (p->hops == (uint8_t)(a->hops + 1u) && ++a->heard >= LOCAL_REBROADCASTS_MAX)
      a->used = 0;
    else if (p->hops == (uint8_t)(a->hops + 2u) && now < a->retry_at)
      a->used = 0;
    return;
  }
}
static void schedule_retry(rnc_node *n, const rnc_packet *relay,
                           uint32_t ingress, uint64_t due) {
  size_t i;
  for (i = 0; i < NODE_ANNOUNCES; i++)
    if (!n->announces[i].used || same(n->announces[i].destination, relay->destination)) {
      node_announce *a = &n->announces[i];
      memset(a, 0, sizeof(*a));
      a->used = 1;
      memcpy(a->destination, relay->destination, 16);
      a->hops = relay->hops;
      a->ingress = ingress;
      a->retry_at = after(due, ANNOUNCE_RETRY_MS);
      a->packet = *relay;
      return;
    }
}
/* The single retransmission; skipped if the path or ingress is gone, or the
 * queue is full (retried on the next tick). */
static void announce_retry(rnc_node *n, node_announce *a, uint64_t now) {
  size_t k, targets = relay_count(n, a->ingress);
  if (!interface(n, a->ingress) || !route_find(n, a->destination, now)) {
    a->used = 0;
    return;
  }
  if (queue_free(n) < targets)
    return;
  for (k = 0; k < RNC_NODE_INTERFACES; k++)
    if (n->interfaces[k].id && relay_target(n, a->ingress, n->interfaces[k].id))
      queue(n, n->interfaces[k].id, &a->packet, now);
  a->used = 0;
}
static rnc_result announced(rnc_node *n, uint32_t ingress, rnc_packet *p,
                            uint64_t unix_seconds, uint64_t now) {
  rnc_announce a;
  rnc_result r;
  node_route *route;
  node_route fresh = {0};
  uint64_t stamp;
  size_t i, slot = RNC_NODE_ROUTES, answers = 0,
            targets = relay_count(n, ingress);
  uint8_t jitter[2];
  int update;
  r = rnc_announce_verify(p, &a);
  if (r != RNC_OK)
    return r;
  if (destination_find(n, p->destination) &&
      destination_find(n, p->destination)->type == RNC_SINGLE)
    return RNC_OK;
  if (n->transport)
    heard_rebroadcast(n, p, now);
  if (!n->releasing) {
    node_interface *in = interface(n, ingress);
    freq_add(&in->ia, now);
    if (!route_find(n, p->destination, now) &&
        !path_request_pending(n, p->destination, now) &&
        ingress_limit(in, now)) {
      if (n->input_packet)
        hold_announce(n, ingress, n->input_packet, p->hops);
      return RNC_OK;
    }
  }
  stamp = announce_time(&a);
  if (stamp > unix_seconds && stamp - unix_seconds > 300)
    return RNC_PROTOCOL;
  route = route_find(n, p->destination, now);
  update = !route || stamp > route->route.announced_at;
  if (route && !memcmp(a.random_hash, route->route.announce.random_hash, 10))
    update = 0;
  for (i = 0; i < NODE_REQUESTS; i++)
    if (n->requests[i].used && n->requests[i].pending &&
        n->requests[i].expiry > now && n->requests[i].ingress != ingress &&
        same(n->requests[i].destination, p->destination))
      answers++;
  if (queue_free(n) < answers + ((update && p->context == 0) ? targets : 0))
    return RNC_AGAIN;

  if (update) {
    if (route)
      slot = (size_t)(route - n->routes);
    else
      for (i = 0; i < RNC_NODE_ROUTES; i++)
        if (!n->routes[i].used || n->routes[i].route.expires_ms <= now) {
          slot = i;
          break;
        }
    if (slot == RNC_NODE_ROUTES)
      return RNC_AGAIN;
    if (targets && p->context == 0) {
      if (queue_free(n) < targets)
        return RNC_AGAIN;
      r = n->random(n->random_context, jitter, 2);
      if (r != RNC_OK)
        return r;
    }
    fresh.used = 1;
    fresh.route.announce = a;
    fresh.packet = *p;
    fresh.route.interface_id = ingress;
    fresh.route.hops = p->hops;
    fresh.route.announced_at = stamp;
    fresh.route.expires_ms = after(now, path_lifetime(n, ingress));
    memcpy(fresh.route.destination, p->destination, 16);
    memcpy(fresh.route.next_hop,
           (p->flags & 0x40) ? p->transport_id : p->destination, 16);
    n->routes[slot] = fresh;
    emit(n, RNC_NODE_ANNOUNCE, ingress, p)->route = fresh.route;
    if (targets && p->context == 0 &&
        !rate_blocked(n, interface(n, ingress), p->destination, now)) {
      rnc_packet relay = *p;
      uint64_t due = after(now, ((unsigned)jitter[0] * 256 + jitter[1]) % 501u);
      relay_announce(n, &relay);
      for (i = 0; i < RNC_NODE_INTERFACES; i++)
        if (n->interfaces[i].id &&
            relay_target(n, ingress, n->interfaces[i].id))
          queue(n, n->interfaces[i].id, &relay, due);
      if (!interface(n, ingress)->local)
        schedule_retry(n, &relay, ingress, due);
    }
  }
  /* A cached PATH_RESPONSE can satisfy pending requests even if route data is
   * already known; it never causes unsolicited flooding. */
  for (i = 0; i < NODE_REQUESTS; i++)
    if (n->requests[i].used && n->requests[i].pending &&
        n->requests[i].expiry > now &&
        same(n->requests[i].destination, p->destination)) {
      rnc_packet relay = *p;
      relay.context = 11;
      relay_announce(n, &relay);
      if (n->requests[i].ingress != ingress)
        emit(n, RNC_NODE_SEND, n->requests[i].ingress, &relay);
      n->requests[i].used = 0;
    }
  return RNC_OK;
}
static rnc_result requested(rnc_node *n, uint32_t ingress,
                            const rnc_packet *packet, uint64_t unix_seconds,
                            uint64_t now) {
  rnc_path_request request;
  node_destination *d;
  node_route *route;
  rnc_packet reply;
  node_request entry = {0};
  size_t i, slot = NODE_REQUESTS;
  int pr_limited, filtered = 0;
  rnc_result r;
  r = rnc_path_request_decode(packet, &request);
  if (r != RNC_OK)
    return r;
  for (i = 0; i < NODE_REQUESTS; i++) {
    if (n->requests[i].used && n->requests[i].expiry > now &&
        same(n->requests[i].destination, request.destination) &&
        n->requests[i].tag_size == request.tag_size &&
        !memcmp(n->requests[i].tag, request.tag, request.tag_size))
      return RNC_OK;
    if (!n->requests[i].used || n->requests[i].expiry <= now)
      slot = i;
  }
  freq_add(&interface(n, ingress)->ip, now);
  pr_limited = ingress_limit_pr(interface(n, ingress), now);
  d = destination_find(n, request.destination);
  if (d && d->type != RNC_SINGLE)
    d = NULL;
  route = route_find(n, request.destination, now);
  if (route && !n->transport && !interface(n, ingress)->local &&
      !interface(n, route->route.interface_id)->local)
    route = NULL;
  if (!d && !route) {
    /* Unknown destination: only interfaces that discover paths for their
     * clients search other interfaces (reference Transport.path_request). */
    const node_interface *in = interface(n, ingress);
    int search = in->local || in->recursive || in->mode == RNC_MODE_GATEWAY ||
                 in->mode == RNC_MODE_ACCESS_POINT ||
                 in->mode == RNC_MODE_ROAMING ||
                 in->mode == RNC_MODE_BOUNDARY;
    filtered = !in->local && !in->recursive && in->mode == RNC_MODE_BOUNDARY;
    if (!search || pr_limited || !n->transport || !relay_count(n, ingress))
      return RNC_OK;
  }
  if (slot == NODE_REQUESTS)
    return RNC_AGAIN;
  if (d || route) {
    if (!queue_free(n))
      return RNC_AGAIN;
    if (d) {
      r = destination_announce(n, d, unix_seconds, &reply);
      if (r != RNC_OK)
        return r;
    } else {
      if (request.has_transport &&
          same(route->route.next_hop, request.transport_id))
        return RNC_OK;
      reply = route->packet;
      relay_announce(n, &reply);
    }
    reply.context = 11;
    queue(n, ingress, &reply, now);
  } else {
    r = rnc_path_request_create(request.destination, n->id, request.tag,
                                request.tag_size, &reply);
    if (r != RNC_OK)
      return r;
    entry.pending = 1;
    for (i = 0; i < RNC_NODE_INTERFACES; i++) {
      node_interface *out = &n->interfaces[i];
      if (out->id && out->id != ingress &&
          relay_target(n, ingress, out->id) &&
          (!filtered || out->mode == RNC_MODE_BOUNDARY ||
           out->mode == RNC_MODE_GATEWAY || out->local) &&
          !egress_limit_pr(out, now)) {
        emit(n, RNC_NODE_SEND, out->id, &reply);
        freq_add(&out->op, now);
      }
    }
  }
  entry.used = 1;
  entry.ingress = ingress;
  entry.expiry = after(now, REQUEST_LIFETIME);
  memcpy(entry.destination, request.destination, 16);
  memcpy(entry.tag, request.tag, request.tag_size);
  entry.tag_size = request.tag_size;
  n->requests[slot] = entry;
  return RNC_OK;
}
rnc_result rnc_node_request_path(rnc_node *n, const uint8_t address[16],
                                 uint64_t now) {
  uint8_t tag[16];
  rnc_packet p;
  rnc_result r;
  if (!n || !address || now < n->now)
    return RNC_INVALID;
  if (!room(n, interface_count(n)))
    return RNC_AGAIN;
  r = n->random(n->random_context, tag, 16);
  if (r == RNC_OK)
    r = rnc_path_request_create(address, n->transport ? n->id : NULL, tag, 16,
                                &p);
  if (r != RNC_OK)
    return r;
  broadcast(n, &p, 0);
  n->now = now;
  return RNC_OK;
}
static rnc_result proof_link(node_link *l, const rnc_packet *p) {
  uint8_t signed_data[83];
  size_t size;
  if (p->data_size != 96 && p->data_size != 99)
    return RNC_PROTOCOL;
  memcpy(signed_data, l->id, 16);
  memcpy(signed_data + 16, p->data + 64, 32);
  memcpy(signed_data + 48, l->signer.public_key + 32, 32);
  size = 80;
  if (p->data_size == 99) {
    memcpy(signed_data + 80, p->data + 96, 3);
    size += 3;
  }
  return rnc_identity_verify(&l->signer, signed_data, size, p->data);
}
static rnc_result link_id(const rnc_packet *p, uint8_t id[16]) {
  rnc_packet q = *p;
  uint8_t hash[32];
  rnc_result r;
  if (p->data_size != 64 && p->data_size != 67)
    return RNC_PROTOCOL;
  q.data_size = 64;
  r = rnc_packet_hash(&q, hash);
  if (r == RNC_OK)
    memcpy(id, hash, 16);
  return r;
}
static rnc_result forward(rnc_node *n, uint32_t ingress, rnc_packet *p,
                          uint64_t now) {
  node_route *route = route_find(n, p->destination, now);
  rnc_packet out = *p;
  size_t i, slot;
  uint8_t id[16], hash[32];
  rnc_result r;
  unsigned type = p->flags & 3u;
  if (!route)
    return RNC_AGAIN;
  if (p->data_size > RNC_MTU - (route->route.hops > 1 ? 35u : 19u))
    return RNC_NO_SPACE;
  if (type == RNC_LINKREQUEST) {
    if (p->data_size == 67) {
      size_t desired = ((size_t)(out.data[64] & 0x1fu) << 16) |
                       ((size_t)out.data[65] << 8) | out.data[66];
      size_t cap = interface(n, route->route.interface_id)->mtu;
      if (ingress && interface(n, ingress)->mtu < cap)
        cap = interface(n, ingress)->mtu;
      if (desired > cap) {
        out.data[64] = (uint8_t)((out.data[64] & 0xe0u) | (cap >> 16));
        out.data[65] = (uint8_t)(cap >> 8);
        out.data[66] = (uint8_t)cap;
      }
    }
    r = link_id(p, id);
    if (r != RNC_OK)
      return r;
    if (ingress) {
      node_link *l = link_find(n, id);
      if (l)
        return RNC_OK;
      slot = RNC_NODE_LINKS;
      for (i = 0; i < RNC_NODE_LINKS; i++)
        if (!n->links[i].used) {
          slot = i;
          break;
        }
      if (slot == RNC_NODE_LINKS)
        return RNC_AGAIN;
      l = &n->links[slot];
      l->used = 1;
      memcpy(l->id, id, 16);
      l->in = ingress;
      l->out = route->route.interface_id;
      l->in_hops = p->hops;
      l->out_hops = route->route.hops;
      l->signer = route->route.announce.identity;
      l->expiry = after(now, 30000u);
    }
  } else if (type == RNC_DATA && ((p->flags >> 2) & 3u) == RNC_SINGLE) {
    node_reverse *v = NULL;
    r = rnc_packet_hash(p, hash);
    if (r != RNC_OK)
      return r;
    for (i = 0; i < NODE_REVERSE; i++)
      if (n->reverse[i].used && n->reverse[i].expiry > now &&
          !memcmp(n->reverse[i].hash, hash, 32)) {
        v = &n->reverse[i];
        break;
      }
    if (!v) {
      for (i = 0; i < NODE_REVERSE; i++)
        if (!n->reverse[i].used || n->reverse[i].expiry <= now) {
          v = &n->reverse[i];
          break;
        }
      if (!v)
        return RNC_AGAIN;
      memset(v, 0, sizeof(*v));
      v->used = 1;
      memcpy(v->hash, hash, 32);
      v->in = ingress;
      v->out = route->route.interface_id;
      v->signer = route->route.announce.identity;
      v->expiry = after(now, PACKET_LIFETIME);
    }
  }
  if (route->route.hops > 1) {
    out.flags = (uint8_t)((out.flags & 0x2fu) | 0x50u);
    memcpy(out.transport_id, route->route.next_hop, 16);
  } else {
    out.flags &= 0x2fu;
    memset(out.transport_id, 0, 16);
  }
  emit(n, RNC_NODE_SEND, route->route.interface_id, &out);
  return RNC_OK;
}
rnc_result rnc_node_send(rnc_node *n, const rnc_packet *packet,
                         uint64_t unix_seconds, uint64_t now) {
  rnc_packet p;
  uint8_t raw[RNC_MAX_MTU];
  size_t size;
  rnc_result r;
  node_link *l;
  (void)unix_seconds;
  if (!n || !packet || now < n->now)
    return RNC_INVALID;
  r = rnc_packet_encode(packet, raw, sizeof(raw), &size);
  if (r != RNC_OK)
    return r;
  if (!room(n, interface_count(n) + 1))
    return RNC_AGAIN;
  p = *packet;
  p.hops = 0;
  l = link_find(n, p.destination);
  if (l && l->local) {
    if (l->out) {
      if (size > interface(n, l->out)->mtu)
        return RNC_NO_SPACE;
      emit(n, RNC_NODE_SEND, l->out, &p);
    } else
      broadcast(n, &p, 0);
    r = RNC_OK;
  } else if (((p.flags >> 2) & 3u) == RNC_SINGLE &&
             (p.flags & 3u) != RNC_ANNOUNCE) {
    r = forward(n, 0, &p, now);
  } else {
    broadcast(n, &p, 0);
    r = RNC_OK;
  }
  if (r == RNC_OK)
    n->now = now;
  return r;
}
rnc_result rnc_node_set_proof_strategy(rnc_node *n,
                                       const uint8_t address[16],
                                       rnc_proof_strategy strategy) {
  node_destination *d;
  if (!n || !address || strategy < RNC_PROVE_NONE || strategy > RNC_PROVE_ALL)
    return RNC_INVALID;
  d = destination_find(n, address);
  if (!d || d->type != RNC_SINGLE)
    return RNC_STATE;
  d->proof = (int)strategy;
  return RNC_OK;
}
rnc_result rnc_node_prove(rnc_node *n, const uint8_t address[16],
                          const rnc_packet *packet, uint32_t interface_id,
                          int implicit, uint64_t unix_seconds, uint64_t now) {
  node_destination *d;
  rnc_packet proof;
  rnc_result r;
  (void)unix_seconds;
  if (!n || !address || !packet || now < n->now ||
      !interface(n, interface_id))
    return RNC_INVALID;
  d = destination_find(n, address);
  if (!d || d->type != RNC_SINGLE || !d->identity.has_private ||
      (packet->flags & 3u) != RNC_DATA || !same(packet->destination, address))
    return RNC_STATE;
  if (!room(n, 1))
    return RNC_AGAIN;
  r = make_proof(d, packet, implicit != 0, &proof);
  if (r != RNC_OK)
    return r;
  emit(n, RNC_NODE_SEND, interface_id, &proof);
  n->now = now;
  return RNC_OK;
}
rnc_result rnc_node_send_tracked(rnc_node *n, const rnc_packet *packet,
                                 uint64_t timeout, uint64_t unix_seconds,
                                 uint64_t now, uint8_t hash[32]) {
  node_receipt *t = NULL;
  node_route *route;
  uint8_t digest[32];
  size_t i;
  rnc_result r;
  if (!n || !packet || !hash || !timeout || now < n->now)
    return RNC_INVALID;
  if ((packet->flags & 3u) != RNC_DATA ||
      ((packet->flags >> 2) & 3u) != RNC_SINGLE)
    return RNC_UNSUPPORTED;
  route = route_find(n, packet->destination, now);
  if (!route)
    return RNC_STATE;
  for (i = 0; i < RNC_NODE_RECEIPTS; i++)
    if (!n->receipts[i].used) {
      t = &n->receipts[i];
      break;
    }
  if (!t)
    return RNC_AGAIN;
  r = rnc_packet_hash(packet, digest);
  if (r != RNC_OK)
    return r;
  r = rnc_node_send(n, packet, unix_seconds, now);
  if (r != RNC_OK)
    return r;
  memset(t, 0, sizeof(*t));
  t->used = 1;
  memcpy(t->hash, digest, 32);
  t->signer = route->route.announce.identity;
  t->sent = now;
  t->expiry = after(now, timeout);
  memcpy(hash, digest, 32);
  return RNC_OK;
}
rnc_result rnc_node_input(rnc_node *n, uint32_t ingress,
                          const rnc_packet *packet, uint64_t unix_seconds,
                          uint64_t now) {
  rnc_packet p;
  uint8_t raw[RNC_MAX_MTU], address[16], hash[32];
  size_t size, i;
  rnc_result r;
  node_link *l;
  unsigned type, destination;
  if (!n || !packet || !interface(n, ingress) || now < n->now)
    return RNC_INVALID;
  r = rnc_packet_encode(packet, raw, sizeof(raw), &size);
  if (r != RNC_OK)
    return r;
  if (size > interface(n, ingress)->mtu)
    return RNC_PROTOCOL;
  if (!room(n, interface_count(n) + NODE_REQUESTS + 2u))
    return RNC_AGAIN;
  p = *packet;
  if (p.hops >= 127)
    return RNC_PROTOCOL;
  if (!interface(n, ingress)->local)
    p.hops++;
  type = p.flags & 3u;
  destination = (p.flags >> 2) & 3u;
  if (type == RNC_ANNOUNCE) {
    n->input_packet = packet;
    r = announced(n, ingress, &p, unix_seconds, now);
    n->input_packet = NULL;
  } else if (destination == RNC_PLAIN) {
    r = path_address(address);
    if (r != RNC_OK)
      return r;
    if (same(address, p.destination))
      r = requested(n, ingress, &p, unix_seconds, now);
    else {
      for (i = 0; i < RNC_NODE_INTERFACES; i++)
        if (n->interfaces[i].id && n->interfaces[i].id != ingress &&
            (interface(n, ingress)->local || n->interfaces[i].local))
          emit(n, RNC_NODE_SEND, n->interfaces[i].id, &p);
      emit(n, RNC_NODE_LOCAL, ingress, &p);
      r = RNC_OK;
    }
  } else if ((p.flags & 0x40u) && !same(p.transport_id, n->id))
    r = RNC_OK;
  else if ((l = link_find(n, p.destination)) != NULL) {
    if (l->local) {
      if (l->out && l->out != ingress)
        return RNC_PROTOCOL;
      emit(n, RNC_NODE_LOCAL, ingress, &p);
      r = RNC_OK;
    } else if (type == RNC_PROOF && p.context == 255) {
      if (ingress != l->out || p.hops != l->out_hops)
        return RNC_PROTOCOL;
      r = proof_link(l, &p);
      if (r != RNC_OK)
        return r;
      l->active = 1;
      l->expiry = after(now, 180000u);
      emit(n, RNC_NODE_SEND, l->in, &p);
    } else if (l->active) {
      uint32_t out = 0;
      if (ingress == l->in && p.hops == l->in_hops)
        out = l->out;
      else if (ingress == l->out && p.hops == l->out_hops)
        out = l->in;
      if (!out)
        return RNC_PROTOCOL;
      if (size > interface(n, out)->mtu)
        return RNC_NO_SPACE;
      emit(n, RNC_NODE_SEND, out, &p);
      /* This extends routing liveness; endpoints authenticate opaque tokens. */
      l->expiry = after(now, 180000u);
      r = RNC_OK;
    } else
      r = RNC_STATE;
  } else if (type == RNC_PROOF && p.context == 0) {
    r = RNC_OK;
    for (i = 0; i < NODE_REVERSE; i++) {
      node_reverse *v = &n->reverse[i];
      if (!v->used || v->expiry <= now || !same(v->hash, p.destination))
        continue;
      if (v->out != ingress)
        return RNC_PROTOCOL;
      if (p.data_size == 96) {
        if (memcmp(v->hash, p.data, 32))
          return RNC_AUTH;
        r = rnc_identity_verify(&v->signer, v->hash, 32, p.data + 32);
      } else if (p.data_size == 64)
        r = rnc_identity_verify(&v->signer, v->hash, 32, p.data);
      else
        return RNC_PROTOCOL;
      if (r == RNC_OK) {
        if (v->in)
          emit(n, RNC_NODE_SEND, v->in, &p);
        else if (!receipt_complete(n, &p, now))
          emit(n, RNC_NODE_LOCAL, ingress, &p);
      }
      break;
    }
  } else if (destination_find(n, p.destination) &&
             destination_find(n, p.destination)->type == (int)destination) {
    node_destination *d = destination_find(n, p.destination);
    emit(n, RNC_NODE_LOCAL, ingress, &p);
    r = RNC_OK;
    if (type == RNC_DATA && destination == RNC_SINGLE &&
        d->proof == RNC_PROVE_ALL && d->identity.has_private) {
      rnc_packet proof;
      r = make_proof(d, &p, 1, &proof);
      if (r == RNC_OK)
        emit(n, RNC_NODE_SEND, ingress, &proof);
    }
  } else if (destination == RNC_SINGLE &&
             ((n->transport && (p.flags & 0x40u)) ||
              interface(n, ingress)->local ||
              (route_find(n, p.destination, now) &&
               interface(n,
                         route_find(n, p.destination, now)->route.interface_id)
                   ->local))) {
    if (!route_find(n, p.destination, now)) {
      n->now = now;
      return RNC_OK;
    }

    r = rnc_packet_hash(&p, hash);
    if (r != RNC_OK)
      return r;
    if (duplicate(n, hash, now))
      return RNC_OK;
    r = forward(n, ingress, &p, now);
    if (r == RNC_OK)
      remember(n, hash, now);
  } else
    r = RNC_OK;
  if (r == RNC_OK)
    n->now = now;
  return r;
}
rnc_result rnc_node_tick(rnc_node *n, uint64_t unix_seconds, uint64_t now) {
  size_t i, j;
  if (!n || now < n->now)
    return RNC_INVALID;
  for (i = 0; i < RNC_NODE_ROUTES; i++)
    if (n->routes[i].used && n->routes[i].route.expires_ms <= now)
      n->routes[i].used = 0;
  for (i = 0; i < RNC_NODE_LINKS; i++)
    if (n->links[i].used && !n->links[i].local && n->links[i].expiry <= now)
      n->links[i].used = 0;
  for (i = 0; i < NODE_REVERSE; i++)
    if (n->reverse[i].used && n->reverse[i].expiry <= now)
      n->reverse[i].used = 0;
  for (i = 0; i < NODE_REQUESTS; i++)
    if (n->requests[i].used && n->requests[i].expiry <= now)
      n->requests[i].used = 0;
  for (i = 0; i < RNC_NODE_INTERFACES; i++) {
    node_interface *in = &n->interfaces[i];
    size_t k, best = NODE_HELD, count = 0;
    rnc_result r;
    if (!in->id)
      continue;
    (void)ingress_limit(in, now);
    (void)ingress_limit_pr(in, now);
    for (k = 0; k < NODE_HELD; k++)
      if (n->held[k].used && n->held[k].iface == in->id) {
        count++;
        if (best == NODE_HELD || n->held[k].hops < n->held[best].hops)
          best = k;
      }
    if (!count || now <= in->ic_held_release ||
        !(freq_hz(&in->ia, now, 2, 0) < announce_threshold(in, now)))
      continue;
    {
      rnc_packet wire = n->held[best].packet;
      n->releasing = 1;
      r = rnc_node_input(n, in->id, &wire, unix_seconds, now);
      n->releasing = 0;
      if (r == RNC_AGAIN)
        continue;
      n->held[best].used = 0;
      in->ic_held_release = now + ic_ms(in->ingress.held_release_interval_s, 5u);
    }
  }
  for (i = 0; i < NODE_ANNOUNCES; i++) {
    node_announce *a = &n->announces[i];
    if (a->used && a->retry_at <= now)
      announce_retry(n, a, now);
  }
  for (i = 0; i < RNC_NODE_RECEIPTS && room(n, 1); i++)
    if (n->receipts[i].used && n->receipts[i].expiry <= now) {
      rnc_node_event *e = emit(n, RNC_NODE_RECEIPT, 0, NULL);
      memcpy(e->receipt_hash, n->receipts[i].hash, 32);
      e->receipt_status = RNC_RECEIPT_FAILED;
      e->rtt_ms = now - n->receipts[i].sent;
      n->receipts[i].used = 0;
    }
  for (i = 0; i < RNC_NODE_INTERFACES && room(n, 1); i++) {
    node_interface *iface = &n->interfaces[i];
    size_t best = NODE_QUEUE, wire;
    uint8_t raw[RNC_MTU];
    uint64_t wait;
    if (!iface->id || iface->announce_after > now)
      continue;
    for (j = 0; j < NODE_QUEUE; j++)
      if (n->queued[j].used && n->queued[j].iface == iface->id &&
          n->queued[j].due <= now &&
          (best == NODE_QUEUE ||
           n->queued[j].packet.hops < n->queued[best].packet.hops))
        best = j;
    if (best == NODE_QUEUE)
      continue;
    if (rnc_packet_encode(&n->queued[best].packet, raw, sizeof(raw), &wire) !=
        RNC_OK)
      return RNC_PROTOCOL;
    /* Default 2 percent announce bandwidth, rounded up in milliseconds. */
    wait = ((uint64_t)wire * UINT64_C(8000000) +
            (uint64_t)iface->bitrate * (iface->cap ? iface->cap : 20u) - 1u) /
           ((uint64_t)iface->bitrate * (iface->cap ? iface->cap : 20u));
    emit(n, RNC_NODE_SEND, iface->id, &n->queued[best].packet);
    n->queued[best].used = 0;
    iface->announce_after = after(now, wait);
  }
  n->now = now;
  return RNC_OK;
}

/* Checkpoints contain signed announces and an owner signature. The host owns
 * their file/transaction policy; importing cannot create application
 * privileges. */
static void state_u64(uint8_t *p, uint64_t v) {
  size_t i;
  for (i = 0; i < 8; i++)
    p[7 - i] = (uint8_t)(v >> (i * 8));
}
static uint64_t state_read64(const uint8_t *p) {
  uint64_t v = 0;
  size_t i;
  for (i = 0; i < 8; i++)
    v = (v << 8) | p[i];
  return v;
}
static void state_u32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}
static uint32_t state_read32(const uint8_t *p) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
         p[3];
}
size_t rnc_node_link_count(const rnc_node *n, int active_only) {
  size_t i, count = 0;
  if (!n)
    return 0;
  for (i = 0; i < RNC_NODE_LINKS; i++)
    if (n->links[i].used && (!active_only || n->links[i].active))
      count++;
  return count;
}
rnc_result rnc_node_route_at(const rnc_node *n, size_t ordinal, uint64_t now,
                             rnc_route *route) {
  size_t i;
  if (!n || !route || now < n->now)
    return RNC_INVALID;
  for (i = 0; i < RNC_NODE_ROUTES; i++)
    if (n->routes[i].used && n->routes[i].route.expires_ms > now) {
      if (!ordinal) {
        *route = n->routes[i].route;
        return RNC_OK;
      }
      ordinal--;
    }
  return RNC_AGAIN;
}
rnc_result rnc_node_state_export(const rnc_node *n, const rnc_identity *owner,
                                 uint64_t unix_seconds, uint64_t now,
                                 void *output, size_t capacity,
                                 size_t *written) {
  uint8_t *state;
  size_t i, count = 0, need = 32 + 64, at = 32;
  uint8_t raw[RNC_MAX_MTU];
  size_t size;
  rnc_result r;
  if (written)
    *written = 0;
  if (!n || !owner || !owner->has_private || !same(n->id, owner->hash) ||
      now < n->now || unix_seconds > UINT64_C(0xffffffffff) || !output ||
      !written)
    return RNC_INVALID;
  for (i = 0; i < RNC_NODE_ROUTES; i++)
    if (n->routes[i].used && n->routes[i].route.expires_ms > now) {
      r = rnc_packet_encode(&n->routes[i].packet, raw, sizeof(raw), &size);
      if (r != RNC_OK)
        return r;
      need += 14 + size;
      count++;
    }
  if (capacity < need)
    return RNC_NO_SPACE;
  state = calloc(1, need);
  if (!state)
    return RNC_NO_SPACE;
  memcpy(state, "RNCS", 4);
  state[4] = 1;
  memcpy(state + 6, n->id, 16);
  state_u64(state + 22, unix_seconds);
  state[30] = (uint8_t)(count >> 8);
  state[31] = (uint8_t)count;
  for (i = 0; i < RNC_NODE_ROUTES; i++)
    if (n->routes[i].used && n->routes[i].route.expires_ms > now) {
      const node_route *entry = &n->routes[i];
      uint64_t seconds = (entry->route.expires_ms - now + 999u) / 1000u;
      r = rnc_packet_encode(&entry->packet, raw, sizeof(raw), &size);
      if (r != RNC_OK) {
        free(state);
        return r;
      }
      state_u32(state + at, entry->route.interface_id);
      state_u64(state + at + 4, after(unix_seconds, seconds));
      state[at + 12] = (uint8_t)(size >> 8);
      state[at + 13] = (uint8_t)size;
      memcpy(state + at + 14, raw, size);
      at += 14 + size;
    }
  r = rnc_identity_sign(owner, state, at, state + at);
  if (r == RNC_OK) {
    memcpy(output, state, need);
    *written = need;
  }
  free(state);
  return r;
}
rnc_result rnc_node_state_import(rnc_node *n, const rnc_identity *owner,
                                 uint64_t unix_seconds, uint64_t now,
                                 const void *input, size_t size) {
  const uint8_t *state = input;
  node_route *routes;
  size_t i, j, count, at = 32, used = 0;
  uint64_t exported;
  rnc_result r;
  if (!n || !owner || !same(n->id, owner->hash) || now < n->now ||
      unix_seconds > UINT64_C(0xffffffffff) || !input)
    return RNC_INVALID;
  if (size < 96 || size > 96 + RNC_NODE_ROUTES * (14 + RNC_MTU))
    return RNC_PROTOCOL;
  if (memcmp(state, "RNCS", 4) || state[4] != 1 || state[5] ||
      !same(state + 6, n->id))
    return RNC_PROTOCOL;
  r = rnc_identity_verify(owner, state, size - 64, state + size - 64);
  if (r != RNC_OK)
    return r;
  exported = state_read64(state + 22);
  if (exported > unix_seconds)
    return RNC_INVALID;
  count = (size_t)state[30] * 256 + state[31];
  if (count > RNC_NODE_ROUTES)
    return RNC_PROTOCOL;
  if (n->count)
    return RNC_STATE;
  for (i = 0; i < RNC_NODE_ROUTES; i++)
    if (n->routes[i].used)
      return RNC_STATE;
  for (i = 0; i < RNC_NODE_LINKS; i++)
    if (n->links[i].used)
      return RNC_STATE;
  for (i = 0; i < NODE_QUEUE; i++)
    if (n->queued[i].used)
      return RNC_STATE;
  routes = calloc(RNC_NODE_ROUTES, sizeof(*routes));
  if (!routes)
    return RNC_NO_SPACE;
  for (i = 0; i < count; i++) {
    uint32_t iface;
    uint64_t expires, remaining;
    size_t wire;
    node_route entry = {0};
    if (size - 64 - at < 14) {
      r = RNC_PROTOCOL;
      goto done;
    }
    iface = state_read32(state + at);
    expires = state_read64(state + at + 4);
    wire = (size_t)state[at + 12] * 256 + state[at + 13];
    at += 14;
    if (wire > size - 64 - at || wire > RNC_MTU) {
      r = RNC_PROTOCOL;
      goto done;
    }
    r = rnc_packet_decode(state + at, wire, &entry.packet);
    if (r != RNC_OK)
      goto done;
    at += wire;
    if (entry.packet.hops >= 128 ||
        (!entry.packet.hops && interface(n, iface) &&
         !interface(n, iface)->local)) {
      r = RNC_PROTOCOL;
      goto done;
    }
    r = rnc_announce_verify(&entry.packet, &entry.route.announce);
    if (r != RNC_OK)
      goto done;
    if (expires <= unix_seconds || !interface(n, iface))
      continue;
    remaining = expires - unix_seconds;
    if (remaining > PATH_LIFETIME / 1000u)
      remaining = PATH_LIFETIME / 1000u;
    entry.used = 1;
    entry.route.interface_id = iface;
    entry.route.hops = entry.packet.hops;
    entry.route.expires_ms = after(now, remaining * 1000);
    entry.route.announced_at = announce_time(&entry.route.announce);
    memcpy(entry.route.destination, entry.packet.destination, 16);
    memcpy(entry.route.next_hop,
           (entry.packet.flags & 0x40u) ? entry.packet.transport_id
                                        : entry.packet.destination,
           16);
    for (j = 0; j < used; j++)
      if (same(routes[j].route.destination, entry.route.destination)) {
        r = RNC_PROTOCOL;
        goto done;
      }
    routes[used++] = entry;
  }
  if (at != size - 64) {
    r = RNC_PROTOCOL;
    goto done;
  }
  memcpy(n->routes, routes, RNC_NODE_ROUTES * sizeof(*routes));
  n->now = now;
  r = RNC_OK;
done:
  free(routes);
  return r;
}
