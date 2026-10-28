/*
 * Memory footprint report (a tool, not a pass/fail test unless a budget is given).
 *
 * Prints sizeof() of the large public/internal structs for the configured capacity
 * profile, then builds a "device": one node with destinations, a responder and two
 * ACTIVE incoming links (each with its service), against a client node that is NOT
 * counted. Heap is measured with a counting malloc wrapper (linked with
 * -Wl,--wrap=malloc,calloc,realloc,free) so only the device's allocations are
 * included. Usage: footprint [budget_bytes]   (exit 1 when over budget)
 */
#include "../src/internal.h"
#include <reticulum_c/rnc_link.h>
#include <reticulum_c/rnc_responder.h>
#include <reticulum_c/rnc_service.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- counting allocator: 16 byte header = {size, counted-flag} ---- */
typedef struct hdr {
    size_t size;
    size_t counted;
} hdr;
static int counting;
static size_t live, peak, blocks;
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
void __real_free(void *);
static void account(hdr *h, size_t size) {
    h->size = size;
    h->counted = (size_t)counting;
    if (counting) {
        live += size;
        blocks++;
        if (live > peak)
            peak = live;
    }
}
void *__wrap_malloc(size_t n) {
    hdr *h = __real_malloc(n + sizeof(hdr));
    if (!h)
        return NULL;
    account(h, n);
    return h + 1;
}
void *__wrap_calloc(size_t a, size_t b) {
    void *p = __wrap_malloc(a * b);
    if (p)
        memset(p, 0, a * b);
    return p;
}
void __wrap_free(void *p) {
    hdr *h;
    if (!p)
        return;
    h = (hdr *)p - 1;
    if (h->counted) {
        live -= h->size;
        blocks--;
    }
    __real_free(h);
}
void *__wrap_realloc(void *p, size_t n) {
    void *q;
    hdr *h;
    if (!p)
        return __wrap_malloc(n);
    h = (hdr *)p - 1;
    q = __wrap_malloc(n);
    if (!q)
        return NULL;
    memcpy(q, p, h->size < n ? h->size : n);
    __wrap_free(p);
    return q;
}

#define CHECK(x)                                                                         \
    do {                                                                                 \
        if (!(x)) {                                                                      \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                      \
            exit(2);                                                                     \
        }                                                                                \
    } while (0)
#define UNIX 1700000000u
static uint32_t seed = 5;
static rnc_result rng(void *ctx, uint8_t *p, size_t n) {
    size_t i;
    (void)ctx;
    for (i = 0; i < n; i++) {
        seed = seed * 1664525u + 1013904223u;
        p[i] = (uint8_t)(seed >> 24);
    }
    return RNC_OK;
}
static rnc_result echo(void *context, const char *path, const uint8_t *request, size_t size,
                       const uint8_t *identity, uint8_t *response, size_t capacity,
                       size_t *written) {
    (void)context; (void)path; (void)identity;
    if (size > capacity)
        return RNC_NO_SPACE;
    memcpy(response, request, size);
    *written = size;
    return RNC_OK;
}

#define CLIENTS 2
static rnc_node *client, *server;
static rnc_responder *responder;
static rnc_link *link_[CLIENTS];
static rnc_service *service_[CLIENTS];
static uint64_t now = 1000;

static void pump(unsigned steps) {
    unsigned i, c;
    static rnc_link_event le;
    static rnc_node_event e;
    for (i = 0; i < steps; i++) {
        now += 10;
        CHECK(rnc_node_tick(client, UNIX, now) == RNC_OK);
        counting = 1;
        CHECK(rnc_node_tick(server, UNIX, now) == RNC_OK);
        CHECK(rnc_responder_tick(responder, UNIX, now) == RNC_OK);
        counting = 0;
        for (c = 0; c < CLIENTS; c++) {
            if (!link_[c])
                continue;
            CHECK(rnc_link_tick(link_[c], now) == RNC_OK);
            while (rnc_link_poll(link_[c], &le) == RNC_OK) {
                if (le.type == RNC_LINK_SEND)
                    CHECK(rnc_node_send(client, &le.packet, UNIX, now) == RNC_OK);
                else if (le.type == RNC_LINK_PACKET || le.type == RNC_LINK_RESOURCE_PACKET ||
                         le.type == RNC_LINK_CLOSED) {
                    rnc_result r = rnc_service_input(service_[c], &le, now);
                    CHECK(r == RNC_OK || r == RNC_AGAIN);
                }
            }
            CHECK(rnc_service_pump(service_[c], now) == RNC_OK);
            CHECK(rnc_service_tick(service_[c], now) == RNC_OK);
        }
        while (rnc_node_poll(client, &e) == RNC_OK) {
            if (e.type == RNC_NODE_SEND) {
                counting = 1;
                CHECK(rnc_node_input(server, 1, &e.packet, UNIX, now) == RNC_OK);
                counting = 0;
            } else if (e.type == RNC_NODE_LOCAL) {
                for (c = 0; c < CLIENTS; c++) {
                    uint8_t a[16];
                    if (link_[c] && rnc_link_address(link_[c], a) == RNC_OK &&
                        !memcmp(a, e.packet.destination, 16))
                        CHECK(rnc_link_input(link_[c], &e.packet, now) == RNC_OK);
                }
            }
        }
        counting = 1;
        while (rnc_node_poll(server, &e) == RNC_OK) {
            if (e.type == RNC_NODE_SEND) {
                counting = 0;
                CHECK(rnc_node_input(client, 1, &e.packet, UNIX, now) == RNC_OK);
                counting = 1;
            } else if (e.type == RNC_NODE_LOCAL) {
                rnc_result r = rnc_responder_input(responder, &e, UNIX, now);
                CHECK(r == RNC_OK || r == RNC_AGAIN);
            }
        }
        counting = 0;
    }
}

static void sizes(void) {
    printf("profile: %s\n",
#ifdef RNC_PROFILE_MCU
           "mcu"
#else
           "host (default)"
#endif
    );
    printf("RNC_MTU=%u RNC_MAX_MTU=%u RNC_LINK_MAX_MDU=%u RNC_RESOURCE_MAX_SDU=%u\n", (unsigned)RNC_MTU,
           (unsigned)RNC_MAX_MTU, (unsigned)RNC_LINK_MAX_MDU, (unsigned)RNC_RESOURCE_MAX_SDU);
    printf("RNC_NODE_ROUTES=%u KNOWN=%u LINKS=%u EVENTS=%u DESTINATIONS=%u RECEIPTS=%u TUNNELS=%u\n",
           (unsigned)RNC_NODE_ROUTES, (unsigned)RNC_NODE_KNOWN, (unsigned)RNC_NODE_LINKS,
           (unsigned)RNC_NODE_EVENTS, (unsigned)RNC_NODE_DESTINATIONS, (unsigned)RNC_NODE_RECEIPTS,
           (unsigned)RNC_NODE_TUNNELS);
    printf("RNC_LINK_EVENTS=%u CHANNEL_RX_WINDOW=%u CHANNEL_TX_MAX=%u RESPONDER_LINKS=%u SERVICE_EVENTS=%u\n",
           (unsigned)RNC_LINK_EVENTS, (unsigned)RNC_CHANNEL_RX_WINDOW, (unsigned)RNC_CHANNEL_TX_MAX,
           (unsigned)RNC_RESPONDER_LINKS, (unsigned)RNC_SERVICE_EVENTS);
    printf("sizeof: rnc_packet=%zu rnc_announce=%zu rnc_route=%zu rnc_node_event=%zu rnc_link_event=%zu\n",
           sizeof(rnc_packet), sizeof(rnc_announce), sizeof(rnc_route), sizeof(rnc_node_event),
           sizeof(rnc_link_event));
    printf("sizeof: rnc_link=%zu rnc_tx_message=%zu rnc_rx_message=%zu rnc_service_event=%zu rnc_identity=%zu rnc_hdlc=%zu\n",
           sizeof(struct rnc_link), sizeof(rnc_tx_message), sizeof(rnc_rx_message),
           sizeof(rnc_service_event), sizeof(rnc_identity), sizeof(rnc_hdlc));
}

int main(int argc, char **argv) {
    rnc_identity client_id, server_id, extra;
    uint8_t destination[16], extra_dest[16];
    rnc_packet announce;
    rnc_route route;
    rnc_node_event e;
    size_t after_node, after_dest, after_responder, after_links;
    unsigned c;
    size_t budget = argc > 1 ? (size_t)strtoul(argv[1], NULL, 10) : 0;

    sizes();
    CHECK(rnc_identity_generate(&client_id, rng, NULL) == RNC_OK);
    CHECK(rnc_identity_generate(&server_id, rng, NULL) == RNC_OK);
    CHECK(rnc_identity_generate(&extra, rng, NULL) == RNC_OK);
    client = rnc_node_new(&client_id, 0, rng, NULL);
    CHECK(client && rnc_node_add_interface(client, 1, 1000000) == RNC_OK);

    counting = 1;
    server = rnc_node_new(&server_id, 0, rng, NULL);
    CHECK(server && rnc_node_add_interface(server, 1, 1000000) == RNC_OK);
    after_node = live;
    CHECK(rnc_node_add_destination(server, &server_id, "test.responder", NULL, 0, destination) == RNC_OK);
    CHECK(rnc_node_add_destination(server, &extra, "test.other", NULL, 0, extra_dest) == RNC_OK);
    after_dest = live;
    responder = rnc_responder_new(server, 1024, rng, NULL);
    CHECK(responder);
    CHECK(rnc_responder_add_destination(responder, &server_id, destination) == RNC_OK);
    CHECK(rnc_responder_register(responder, destination, "/echo", RNC_SERVICE_ALLOW_ALL, NULL, 0, echo, NULL) == RNC_OK);
    after_responder = live;
    counting = 0;

    now = 1000;
    CHECK(rnc_node_announce(server, destination, UNIX, now) == RNC_OK);
    counting = 1;
    CHECK(rnc_node_tick(server, UNIX, now) == RNC_OK);
    while (rnc_node_poll(server, &e) == RNC_OK)
        if (e.type == RNC_NODE_SEND) {
            announce = e.packet;
            counting = 0;
            { rnc_result rr = rnc_node_input(client, 1, &announce, UNIX, now); if (rr != RNC_OK) fprintf(stderr, "announce input -> %d\n", (int)rr); CHECK(rr == RNC_OK); }
            counting = 1;
        }
    counting = 0;
    CHECK(rnc_node_lookup(client, destination, now, &route) == RNC_OK);
    for (c = 0; c < CLIENTS; c++) {
        uint8_t address[16];
        link_[c] = rnc_link_new(rng, NULL);
        CHECK(link_[c]);
        CHECK(rnc_link_open(link_[c], &route.announce, now) == RNC_OK);
        CHECK(rnc_link_address(link_[c], address) == RNC_OK);
        CHECK(rnc_node_bind_link_on(client, address, 1) == RNC_OK);
        service_[c] = rnc_service_new(link_[c], 1024, rng, NULL);
        CHECK(service_[c]);
        pump(80);
        CHECK(rnc_link_is_active(link_[c]));
    }
    after_links = live;
    CHECK(rnc_responder_link_count(responder) == CLIENTS);
    /* one request round trip, to include steady-state allocations */
    {
        uint8_t id[16];
        const uint8_t value[] = {0x92, 0x01, 0xa2, 'o', 'k'};
        CHECK(rnc_service_request(service_[0], "/echo", value, sizeof(value), UNIX, now, 5000, id) == RNC_OK);
        pump(60);
    }
    printf("heap (device side only, bytes):\n");
    printf("  node + interface                : %zu\n", after_node);
    printf("  + 2 destinations                : %zu\n", after_dest);
    printf("  + responder (max_value 1024)    : %zu\n", after_responder);
    printf("  + 2 active links w/ services    : %zu\n", after_links);
    printf("  live after one request          : %zu\n", live);
    printf("  peak                            : %zu  (%zu blocks live)\n", peak, blocks);

    counting = 1;
    rnc_responder_free(responder);
    rnc_node_free(server);
    counting = 0;
    for (c = 0; c < CLIENTS; c++) {
        rnc_service_free(service_[c]);
        rnc_link_free(link_[c]);
    }
    rnc_node_free(client);
    if (live) {
        fprintf(stderr, "leak: %zu bytes still counted\n", live);
        return 2;
    }
    if (budget && peak > budget) {
        fprintf(stderr, "over budget: peak %zu > %zu\n", peak, budget);
        return 1;
    }
    return 0;
}
