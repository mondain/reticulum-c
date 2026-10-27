#include "service_msgpack.h"
#include <float.h>
#include <math.h>
#include <openssl/crypto.h>
#include <reticulum_c/rnc_service.h>
#include <stdlib.h>
#include <string.h>
_Static_assert(sizeof(double) == 8 && DBL_MANT_DIG == 53, "IEEE binary64 required");
typedef struct service_handler {
    int used;
    uint8_t hash[16];
    rnc_service_policy policy;
    size_t count;
    uint8_t allowed[RNC_SERVICE_ALLOWLIST][16];
} service_handler;
typedef struct service_pending {
    int used, timed_out;
    uint8_t id[16];
    uint64_t deadline;
    rnc_request_state state;
    double progress;
} service_pending;
typedef struct service_queued {
    rnc_service_event event;
    uint8_t *data;
} service_queued;
struct rnc_service {
    rnc_link *link;
    rnc_resource *tx, *rx;
    size_t max_value, max_request;
    uint64_t now;
    service_handler handlers[RNC_SERVICE_HANDLERS];
    service_pending pending[RNC_SERVICE_PENDING], incoming[RNC_SERVICE_PENDING];
    uint8_t recent[64][16];
    size_t recent_count, recent_next;
    service_queued events[RNC_SERVICE_EVENTS];
    size_t head, count;
    int rx_ready, rx_response, rx_binding, tx_request;
    uint8_t rx_id[16], tx_id[16];
};
static rnc_result path_hash(const char *path, uint8_t hash[16]) {
    uint8_t full[32];
    size_t n;
    if (!path || !*path)
        return RNC_INVALID;
    n = strlen(path);
    if (n > 4096)
        return RNC_INVALID;
    if (rnc_hash(path, n, full) != RNC_OK)
        return RNC_CRYPTO;
    memcpy(hash, full, 16);
    return RNC_OK;
}
static int slot(service_pending *p, const uint8_t *id) {
    size_t i;
    for (i = 0; i < RNC_SERVICE_PENDING; i++)
        if (p[i].used && !memcmp(p[i].id, id, 16))
            return (int)i;
    return -1;
}
static int seen_request(const rnc_service *s, const uint8_t id[16]) {
    for (size_t i = 0; i < s->recent_count; i++)
        if (!CRYPTO_memcmp(s->recent[i], id, 16))
            return 1;
    return 0;
}
static void remember_request(rnc_service *s, const uint8_t id[16]) {
    if (seen_request(s, id))
        return;
    memcpy(s->recent[s->recent_next], id, 16);
    s->recent_next = (s->recent_next + 1u) % 64u;
    if (s->recent_count < 64u)
        s->recent_count++;
}
static int empty_slot(service_pending *p) {
    size_t i;
    for (i = 0; i < RNC_SERVICE_PENDING; i++)
        if (!p[i].used)
            return (int)i;
    return -1;
}
static rnc_result queue(rnc_service *s, const rnc_service_event *e, const uint8_t *data, size_t n) {
    service_queued *q;
    uint8_t *copy = NULL;
    if (s->count == RNC_SERVICE_EVENTS)
        return RNC_AGAIN;
    if (n) {
        copy = malloc(n);
        if (!copy)
            return RNC_NO_SPACE;
        memcpy(copy, data, n);
    }
    q = &s->events[(s->head + s->count) % RNC_SERVICE_EVENTS];
    q->event = *e;
    q->event.data_size = n;
    q->data = copy;
    s->count++;
    return RNC_OK;
}
static int array(rmp *p, uint64_t expected) {
    const uint8_t *b;
    uint64_t n;
    if (!rmp_take(p, 1, &b))
        return 0;
    if ((*b & 0xf0) == 0x90)
        n = *b & 15;
    else if (*b == 0xdc || *b == 0xdd) {
        if (!rmp_num(p, *b == 0xdc ? 2 : 4, &n))
            return 0;
    } else
        return 0;
    return n == expected;
}
static int timestamp(rmp *p, double *v) {
    const uint8_t *b;
    uint64_t bits;
    uint32_t small;
    float f;
    rmp backup = *p;
    if (!rmp_take(p, 1, &b))
        return 0;
    if (*b == 0xcb) {
        if (!rmp_num(p, 8, &bits))
            return 0;
        memcpy(v, &bits, 8);
    } else if (*b == 0xca) {
        if (!rmp_num(p, 4, &bits))
            return 0;
        small = (uint32_t)bits;
        memcpy(&f, &small, 4);
        *v = f;
    } else {
        *p = backup;
        if (!rmp_uint(p, &bits))
            return 0;
        *v = (double)bits;
    }
    return isfinite(*v) && *v >= 0;
}
static size_t put_time(uint8_t *p, double v) {
    uint64_t bits;
    size_t i;
    memcpy(&bits, &v, 8);
    p[0] = 0xcb;
    for (i = 0; i < 8; i++)
        p[8 - i] = (uint8_t)(bits >> (i * 8));
    return 9;
}
rnc_service *rnc_service_new(rnc_link *link, size_t max_value, rnc_random_fn random, void *ctx) {
    rnc_service *s;
    if (!link || !random || max_value > 16u * 1024u * 1024u - 64u)
        return NULL;
    if (!max_value)
        max_value = 1024u * 1024u;
    s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;
    s->link = link;
    s->max_value = max_value;
    s->max_request = RNC_SERVICE_NO_LIMIT;
    s->tx = rnc_resource_new(link, max_value + 64u, random, ctx);
    s->rx = rnc_resource_new(link, max_value + 64u, random, ctx);
    if (!s->tx || !s->rx) {
        rnc_service_free(s);
        return NULL;
    }
    return s;
}
void rnc_service_free(rnc_service *s) {
    size_t i;
    if (!s)
        return;
    for (i = 0; i < RNC_SERVICE_EVENTS; i++) {
        if (s->events[i].data) {
            OPENSSL_cleanse(s->events[i].data, s->events[i].event.data_size);
            free(s->events[i].data);
        }
    }
    rnc_resource_free(s->tx);
    rnc_resource_free(s->rx);
    OPENSSL_cleanse(s, sizeof(*s));
    free(s);
}
rnc_result rnc_service_register(rnc_service *s, const char *path, rnc_service_policy policy,
                                const uint8_t (*allowed)[16], size_t count) {
    uint8_t hash[16];
    size_t i, empty = RNC_SERVICE_HANDLERS;
    rnc_result r;
    if (!s || policy < RNC_SERVICE_ALLOW_NONE || policy > RNC_SERVICE_ALLOW_LIST ||
        count > RNC_SERVICE_ALLOWLIST || (!allowed && count) ||
        (policy != RNC_SERVICE_ALLOW_LIST && count))
        return RNC_INVALID;
    r = path_hash(path, hash);
    if (r != RNC_OK)
        return r;
    for (i = 0; i < RNC_SERVICE_HANDLERS; i++) {
        if (s->handlers[i].used && !memcmp(s->handlers[i].hash, hash, 16)) {
            empty = i;
            break;
        }
        if (!s->handlers[i].used)
            empty = i;
    }
    if (empty == RNC_SERVICE_HANDLERS)
        return RNC_NO_SPACE;
    memset(&s->handlers[empty], 0, sizeof(s->handlers[empty]));
    s->handlers[empty].used = 1;
    s->handlers[empty].policy = policy;
    s->handlers[empty].count = count;
    memcpy(s->handlers[empty].hash, hash, 16);
    if (count)
        memcpy(s->handlers[empty].allowed, allowed, count * 16);
    return RNC_OK;
}
rnc_result rnc_service_unregister(rnc_service *s, const char *path) {
    uint8_t hash[16];
    size_t i;
    rnc_result r;
    if (!s)
        return RNC_INVALID;
    r = path_hash(path, hash);
    if (r != RNC_OK)
        return r;
    for (i = 0; i < RNC_SERVICE_HANDLERS; i++)
        if (s->handlers[i].used && !memcmp(hash, s->handlers[i].hash, 16)) {
            OPENSSL_cleanse(&s->handlers[i], sizeof(s->handlers[i]));
            return RNC_OK;
        }
    return RNC_AGAIN;
}
rnc_result rnc_service_request(rnc_service *s, const char *path, const void *value, size_t n,
                               double unix_seconds, uint64_t now, uint64_t timeout,
                               uint8_t id[16]) {
    uint8_t ph[16], hash[32], *p;
    size_t size;
    int index;
    rnc_result result;
    rnc_resource_options o = {0};
    if (!s || !id || !value || !n || n > s->max_value || !rmp_value(value, n) ||
        !isfinite(unix_seconds) || unix_seconds < 0 || now < s->now || !timeout ||
        timeout > UINT64_MAX - now)
        return RNC_INVALID;
    if (!rnc_link_is_active(s->link))
        return RNC_STATE;
    result = path_hash(path, ph);
    if (result != RNC_OK)
        return result;
    index = empty_slot(s->pending);
    if (index < 0)
        return RNC_AGAIN;
    p = malloc(n + 28u);
    if (!p)
        return RNC_NO_SPACE;
    p[0] = 0x93;
    size = 1 + put_time(p + 1, unix_seconds);
    size += rmp_put_bin(p + size, ph, 16);
    memcpy(p + size, value, n);
    size += n;
    if (size <= rnc_link_mdu(s->link))
        result = rnc_link_send_packet_hashed(s->link, 9, p, size, now, hash);
    else {
        result = rnc_hash(p, size, hash);
        if (result == RNC_OK) {
            o.request_id = hash;
            result = rnc_resource_send(s->tx, p, size, &o, now);
            if (result == RNC_OK) {
                memcpy(s->tx_id, hash, 16);
                s->tx_request = 1;
            }
        }
    }
    OPENSSL_cleanse(p, n + 28u);
    free(p);
    if (result != RNC_OK)
        return result;
    s->pending[index].used = 1;
    s->pending[index].state = RNC_REQUEST_SENT;
    s->pending[index].progress = 0;
    s->pending[index].deadline = now + timeout;
    memcpy(s->pending[index].id, hash, 16);
    memcpy(id, hash, 16);
    s->now = now;
    return RNC_OK;
}
rnc_result rnc_service_respond(rnc_service *s, const uint8_t id[16], const void *value, size_t n,
                               uint64_t now) {
    uint8_t *p;
    size_t size;
    int index;
    rnc_result result;
    rnc_resource_options o = {0};
    if (!s || !id || !value || !n || n > s->max_value || !rmp_value(value, n) || now < s->now)
        return RNC_INVALID;
    if (!rnc_link_is_active(s->link))
        return RNC_STATE;
    index = slot(s->incoming, id);
    if (index < 0 || now >= s->incoming[index].deadline)
        return RNC_STATE;
    p = malloc(n + 19u);
    if (!p)
        return RNC_NO_SPACE;
    p[0] = 0x92;
    size = 1 + rmp_put_bin(p + 1, id, 16);
    memcpy(p + size, value, n);
    size += n;
    if (size <= rnc_link_mdu(s->link))
        result = rnc_link_send_packet(s->link, 10, p, size, now);
    else {
        o.request_id = id;
        o.is_response = 1;
        result = rnc_resource_send(s->tx, p, size, &o, now);
        if (result == RNC_OK) {
            memcpy(s->tx_id, id, 16);
            s->tx_request = 0;
        }
    }
    OPENSSL_cleanse(p, n + 19u);
    free(p);
    if (result == RNC_OK) {
        remember_request(s, id);
        OPENSSL_cleanse(&s->incoming[index], sizeof(s->incoming[index]));
        s->now = now;
    }
    return result;
}
static rnc_result accept_request(rnc_service *s, const uint8_t id[16], const uint8_t *p, size_t n,
                                 uint64_t now) {
    rmp m = {p, n, 0};
    const uint8_t *path;
    size_t path_size, start, i, j;
    int allowed = 0, index;
    rnc_identity remote;
    service_handler *h = NULL;
    rnc_service_event e = {0};
    rnc_result result;
    if (n > s->max_request)
        return RNC_OK; /* over the destination's request size limit */
    if (!array(&m, 3) || !timestamp(&m, &e.requested_at) || !rmp_bin(&m, &path, &path_size) ||
        path_size != 16)
        return RNC_PROTOCOL;
    start = m.i;
    if (!rmp_skip_depth(&m, 0) || m.i != m.n || m.i - start > s->max_value)
        return RNC_PROTOCOL;
    if (seen_request(s, id) || slot(s->incoming, id) >= 0)
        return RNC_OK;
    for (i = 0; i < RNC_SERVICE_HANDLERS; i++)
        if (s->handlers[i].used && !memcmp(s->handlers[i].hash, path, 16)) {
            h = &s->handlers[i];
            break;
        }
    if (!h)
        return RNC_OK;
    e.identified = rnc_link_remote_identity(s->link, &remote) == RNC_OK;
    if (e.identified)
        memcpy(e.identity_hash, remote.hash, 16);
    if (h->policy == RNC_SERVICE_ALLOW_ALL)
        allowed = 1;
    else if (h->policy == RNC_SERVICE_ALLOW_IDENTIFIED)
        allowed = e.identified;
    else if (h->policy == RNC_SERVICE_ALLOW_LIST && e.identified)
        for (j = 0; j < h->count; j++)
            if (!memcmp(remote.hash, h->allowed[j], 16)) {
                allowed = 1;
                break;
            }
    memcpy(e.request_id, id, 16);
    memcpy(e.path_hash, path, 16);
    e.type = allowed ? RNC_SERVICE_REQUEST : RNC_SERVICE_DENIED;
    e.reason = allowed ? RNC_OK : RNC_AUTH;
    if (!allowed) {
        result = queue(s, &e, NULL, 0);
        if (result == RNC_OK)
            remember_request(s, id);
        return result;
    }
    index = empty_slot(s->incoming);
    if (index < 0)
        return RNC_AGAIN;
    result = queue(s, &e, p + start, n - start);
    if (result == RNC_OK) {
        s->incoming[index].used = 1;
        memcpy(s->incoming[index].id, id, 16);
        s->incoming[index].deadline = now > UINT64_MAX - 30000u ? UINT64_MAX : now + 30000u;
    }
    return result;
}
static rnc_result accept_response(rnc_service *s, const uint8_t *binding, const uint8_t *p,
                                  size_t n, uint64_t now) {
    rmp m = {p, n, 0};
    const uint8_t *id;
    size_t idn, start;
    int index;
    rnc_service_event e = {0};
    rnc_result result;
    if (!array(&m, 2) || !rmp_bin(&m, &id, &idn) || idn != 16)
        return RNC_PROTOCOL;
    start = m.i;
    if (!rmp_skip_depth(&m, 0) || m.i != m.n || m.i - start > s->max_value)
        return RNC_PROTOCOL;
    if (binding && CRYPTO_memcmp(id, binding, 16))
        return RNC_AUTH;
    index = slot(s->pending, id);
    if (index < 0)
        return RNC_OK; /* Authenticated late/unknown responses are discarded. */
    if (s->pending[index].timed_out || now >= s->pending[index].deadline) {
        s->pending[index].timed_out = 1;
        return RNC_OK;
    }
    e.type = RNC_SERVICE_RESPONSE;
    memcpy(e.request_id, id, 16);
    result = queue(s, &e, p + start, n - start);
    if (result == RNC_OK)
        OPENSSL_cleanse(&s->pending[index], sizeof(s->pending[index]));
    return result;
}
rnc_result rnc_service_input(rnc_service *s, const rnc_link_event *e, uint64_t now) {
    rnc_result result = RNC_AGAIN;
    uint8_t hash[32];
    if (!s || !e || now < s->now)
        return RNC_INVALID;
    if (e->type == RNC_LINK_PACKET && e->context == 9) {
        result = rnc_packet_hash(&e->packet, hash);
        if (result == RNC_OK)
            result = accept_request(s, hash, e->data, e->size, now);
    } else if (e->type == RNC_LINK_PACKET && e->context == 10)
        result = accept_response(s, NULL, e->data, e->size, now);
    else if (e->type == RNC_LINK_PACKET && e->context == 2) {
        size_t wire, total;
        uint8_t original[32], id[16];
        int q, response;
        result = rnc_resource_inspect(e->data, e->size, &wire, &total, hash, original, id, &q,
                                      &response);
        if (result != RNC_OK)
            return result;
        if (!q)
            return RNC_AGAIN;
        if (!response && total > s->max_request)
            return RNC_OK; /* a request too big for the destination */
        if (response) {
            int index = slot(s->pending, id);
            if (index < 0)
                return RNC_AGAIN;
            if (s->pending[index].timed_out || now >= s->pending[index].deadline) {
                s->pending[index].timed_out = 1;
                return RNC_OK;
            }
        }
        if (s->rx_ready)
            return RNC_AGAIN;
        if (s->rx_binding && (s->rx_response != response || CRYPTO_memcmp(s->rx_id, id, 16)))
            return RNC_AGAIN;
        result = rnc_resource_accept(s->rx, e->data, e->size, now);
        /* A completed advertisement only replays its cached Resource proof;
         * it produces no new completion event to release a service binding. */
        if (result == RNC_OK && !rnc_resource_is_complete(s->rx)) {
            s->rx_response = response;
            s->rx_binding = 1;
            memcpy(s->rx_id, id, 16);
            if (response) {
                int p = slot(s->pending, id);
                if (p >= 0)
                    s->pending[p].state = RNC_REQUEST_RECEIVING;
            }
        }
    } else {
        rnc_result a = rnc_resource_input(s->tx, e, now), b = rnc_resource_input(s->rx, e, now);
        if (a != RNC_OK && a != RNC_AGAIN)
            return a;
        if (b != RNC_OK && b != RNC_AGAIN)
            return b;
        result = a == RNC_OK || b == RNC_OK ? RNC_OK : RNC_AGAIN;
    }
    if (e->type == RNC_LINK_CLOSED) {
        size_t i;
        for (i = 0; i < RNC_SERVICE_PENDING; i++)
            if (s->pending[i].used)
                s->pending[i].timed_out = 1;
    }
    if (result == RNC_OK)
        s->now = now;
    return result;
}
rnc_result rnc_service_request_state(const rnc_service *s, const uint8_t id[16],
                                     rnc_request_state *state, double *progress) {
    size_t i;
    if (!s || !id || !state)
        return RNC_INVALID;
    for (i = 0; i < RNC_SERVICE_PENDING; i++)
        if (s->pending[i].used && !CRYPTO_memcmp(s->pending[i].id, id, 16)) {
            *state = s->pending[i].timed_out ? RNC_REQUEST_FAILED : s->pending[i].state;
            if (progress)
                *progress = s->pending[i].progress;
            return RNC_OK;
        }
    return RNC_STATE;
}
rnc_result rnc_service_set_max_request_size(rnc_service *s, size_t max_size) {
    if (!s)
        return RNC_INVALID;
    s->max_request = max_size;
    return RNC_OK;
}
rnc_result rnc_service_pump(rnc_service *s, uint64_t now) {
    rnc_resource_event re;
    rnc_result result;
    size_t i;
    if (!s || now < s->now)
        return RNC_INVALID;
    if (rnc_link_is_active(s->link)) {
        result = rnc_resource_pump(s->tx, now);
        if (result != RNC_OK)
            return result;
        result = rnc_resource_pump(s->rx, now);
        if (result != RNC_OK)
            return result;
    }
    while (rnc_resource_poll(s->tx, &re) == RNC_OK) {
        int index = slot(s->pending, s->tx_id);
        if (re.type == RNC_RESOURCE_FAILED) {
            if (s->tx_request && index >= 0)
                s->pending[index].timed_out = 1;
        } else if (re.type == RNC_RESOURCE_COMPLETE && s->tx_request &&
                   index >= 0 && s->pending[index].state == RNC_REQUEST_SENT)
            s->pending[index].state = RNC_REQUEST_DELIVERED;
    }
    while (rnc_resource_poll(s->rx, &re) == RNC_OK) {
        if (re.type == RNC_RESOURCE_PROGRESS && s->rx_binding && s->rx_response &&
            re.total) {
            int index = slot(s->pending, s->rx_id);
            if (index >= 0 && s->pending[index].state != RNC_REQUEST_FAILED) {
                double v = (double)re.transferred / (double)re.total;
                s->pending[index].state = RNC_REQUEST_RECEIVING;
                if (v > s->pending[index].progress)
                    s->pending[index].progress = v > 1.0 ? 1.0 : v;
            }
        }
        if (re.type == RNC_RESOURCE_COMPLETE)
            s->rx_ready = 1;
        else if (re.type == RNC_RESOURCE_FAILED)
            s->rx_binding = 0;
    }
    if (s->rx_ready) {
        uint8_t *p = malloc(s->max_value + 64u), hash[32];
        size_t n;
        if (!p)
            return RNC_NO_SPACE;
        result = rnc_resource_read(s->rx, p, s->max_value + 64u, &n);
        if (result == RNC_OK) {
            if (s->rx_response)
                result = accept_response(s, s->rx_id, p, n, now);
            else {
                result = rnc_hash(p, n, hash);
                if (result == RNC_OK && CRYPTO_memcmp(hash, s->rx_id, 16))
                    result = RNC_AUTH;
                if (result == RNC_OK)
                    result = accept_request(s, s->rx_id, p, n, now);
            }
        }
        OPENSSL_cleanse(p, s->max_value + 64u);
        free(p);
        if (result == RNC_AGAIN)
            return RNC_OK;
        /* Completed input is consumed even when its service envelope is
         * rejected. Only backpressure retains it for a later pump. */
        s->rx_ready = 0;
        s->rx_binding = 0;
        if (result != RNC_OK)
            return result;
    }
    for (i = 0; i < RNC_SERVICE_PENDING; i++)
        if (s->pending[i].used && s->pending[i].timed_out) {
            rnc_service_event e = {0};
            e.type = RNC_SERVICE_TIMEOUT;
            e.reason = RNC_TIMEOUT;
            memcpy(e.request_id, s->pending[i].id, 16);
            result = queue(s, &e, NULL, 0);
            if (result == RNC_AGAIN)
                break;
            if (result != RNC_OK)
                return result;
            OPENSSL_cleanse(&s->pending[i], sizeof(s->pending[i]));
        }
    s->now = now;
    return RNC_OK;
}
rnc_result rnc_service_tick(rnc_service *s, uint64_t now) {
    size_t i;
    rnc_result result;
    if (!s || now < s->now)
        return RNC_INVALID;
    result = rnc_resource_tick(s->tx, now);
    if (result != RNC_OK)
        return result;
    result = rnc_resource_tick(s->rx, now);
    if (result != RNC_OK)
        return result;
    for (i = 0; i < RNC_SERVICE_PENDING; i++) {
        if (s->pending[i].used && now >= s->pending[i].deadline)
            s->pending[i].timed_out = 1;
        if (s->incoming[i].used && now >= s->incoming[i].deadline) {
            remember_request(s, s->incoming[i].id);
            OPENSSL_cleanse(&s->incoming[i], sizeof(s->incoming[i]));
        }
    }
    s->now = now;
    return rnc_service_pump(s, now);
}
rnc_result rnc_service_poll(rnc_service *s, rnc_service_event *event, void *value, size_t cap,
                            size_t *written) {
    service_queued *q;
    if (written)
        *written = 0;
    if (!s || !event || !written || (!value && cap))
        return RNC_INVALID;
    if (!s->count)
        return RNC_AGAIN;
    q = &s->events[s->head];
    if (cap < q->event.data_size) {
        *written = q->event.data_size;
        return RNC_NO_SPACE;
    }
    *event = q->event;
    if (q->event.data_size)
        memcpy(value, q->data, q->event.data_size);
    *written = q->event.data_size;
    if (q->data) {
        OPENSSL_cleanse(q->data, q->event.data_size);
        free(q->data);
    }
    memset(q, 0, sizeof(*q));
    s->head = (s->head + 1u) % RNC_SERVICE_EVENTS;
    s->count--;
    return RNC_OK;
}
