#include <reticulum_c/rnc_resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x)                                                                                   \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                                \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)
typedef struct rng {
    uint32_t s;
} rng;
static rnc_result random_bytes(void *context, uint8_t *p, size_t n) {
    rng *r = context;
    size_t i;
    for (i = 0; i < n; i++) {
        r->s ^= r->s << 13;
        r->s ^= r->s >> 17;
        r->s ^= r->s << 5;
        p[i] = (uint8_t)r->s;
    }
    return RNC_OK;
}
typedef struct pair {
    rnc_link *a, *b;
    rnc_resource *tx, *rx;
    rng ar, br, rr;
    unsigned txcomplete, rxcomplete, failed, parts, hmus;
    int drop_part, drop_proof, drop_adv, reverse, duplicate_hmu;
    uint64_t now;
} pair;
static rnc_packet outgoing(rnc_link *l) {
    rnc_link_event e;
    while (rnc_link_poll(l, &e) == RNC_OK)
        if (e.type == RNC_LINK_SEND)
            return e.packet;
    CHECK(0);
    {
        rnc_packet p = {0};
        return p;
    }
}
static void init_with_mtu(pair *p, size_t limit, size_t mtu) {
    uint8_t key[64];
    rnc_identity id;
    rnc_announce a;
    rnc_packet pkt;
    size_t i;
    memset(p, 0, sizeof(*p));
    p->ar.s = 123;
    p->br.s = 456;
    p->rr.s = 789;
    p->now = 100;
    for (i = 0; i < 64; i++) {
        key[i] = (uint8_t)i;
    }
    CHECK(rnc_identity_from_private(&id, key) == RNC_OK);
    CHECK(rnc_announce_create(&id, "reticulum_c.resource", NULL, 0, 1700000000, random_bytes,
                              &p->rr, &pkt) == RNC_OK);
    CHECK(rnc_announce_verify(&pkt, &a) == RNC_OK);
    p->a = rnc_link_new(random_bytes, &p->ar);
    p->b = rnc_link_new(random_bytes, &p->br);
    CHECK(p->a && p->b);
    CHECK(rnc_link_configure_mtu(p->a, mtu) == RNC_OK);
    CHECK(rnc_link_configure_mtu(p->b, mtu) == RNC_OK);
    CHECK(rnc_link_open(p->a, &a, p->now) == RNC_OK);
    pkt = outgoing(p->a);
    CHECK(rnc_link_accept(p->b, &id, a.destination, &pkt, ++p->now) == RNC_OK);
    pkt = outgoing(p->b);
    CHECK(rnc_link_input(p->a, &pkt, ++p->now) == RNC_OK);
    pkt = outgoing(p->a);
    CHECK(rnc_link_input(p->b, &pkt, ++p->now) == RNC_OK);
    {
        rnc_link_event e;
        while (rnc_link_poll(p->a, &e) == RNC_OK) {
        }
        while (rnc_link_poll(p->b, &e) == RNC_OK) {
        }
    }
    p->tx = rnc_resource_new(p->a, limit, random_bytes, &p->ar);
    p->rx = rnc_resource_new(p->b, limit, random_bytes, &p->br);
    CHECK(p->tx && p->rx);
    rnc_identity_clear(&id);
}
static void init(pair *p, size_t limit) { init_with_mtu(p, limit, RNC_MTU); }
static void finish(pair *p) {
    rnc_resource_free(p->tx);
    rnc_resource_free(p->rx);
    rnc_link_free(p->a);
    rnc_link_free(p->b);
}
static void transfer(pair *p, rnc_link *from, rnc_link *to, rnc_resource *receiver, int forward) {
    rnc_link_event e;
    rnc_packet pending[64];
    size_t n = 0, i;
    while (rnc_link_poll(from, &e) == RNC_OK) {
        if (e.type == RNC_LINK_SEND) {
            if (e.packet.context == 1) {
                p->parts++;
                if (forward && p->drop_part) {
                    p->drop_part = 0;
                    continue;
                }
            }
            if (e.packet.context == 4)
                p->hmus++;
            if (e.packet.context == 5 && !forward && p->drop_proof) {
                p->drop_proof = 0;
                continue;
            }
            if (e.packet.context == 2 && forward && p->drop_adv) {
                p->drop_adv = 0;
                continue;
            }
            CHECK(n < 64);
            pending[n++] = e.packet;
            if (e.packet.context == 4 && p->duplicate_hmu) {
                CHECK(n < 64);
                pending[n++] = e.packet;
            }
        } else if (e.type == RNC_LINK_PACKET || e.type == RNC_LINK_RESOURCE_PACKET) {
            rnc_result r;
            if (e.type == RNC_LINK_PACKET && e.context == 2)
                r = rnc_resource_accept(receiver, e.data, e.size, p->now);
            else
                r = rnc_resource_input(receiver, &e, p->now);
            CHECK(r == RNC_OK || r == RNC_AGAIN);
        }
    }
    for (i = 0; i < n; i++) {
        size_t j = p->reverse ? n - i - 1 : i;
        CHECK(rnc_link_input(to, &pending[j], p->now) == RNC_OK);
    }
}
static void events(pair *p, rnc_resource *r, int outgoing_) {
    rnc_resource_event e;
    while (rnc_resource_poll(r, &e) == RNC_OK) {
        if (e.type == RNC_RESOURCE_COMPLETE) {
            if (outgoing_)
                p->txcomplete++;
            else
                p->rxcomplete++;
        }
        if (e.type == RNC_RESOURCE_FAILED)
            p->failed++;
    }
}
static void run(pair *p, unsigned limit) {
    unsigned i;
    for (i = 0; i < limit && (!p->txcomplete || !p->rxcomplete); i++) {
        CHECK(rnc_resource_pump(p->tx, p->now) == RNC_OK);
        CHECK(rnc_resource_pump(p->rx, p->now) == RNC_OK);
        transfer(p, p->a, p->b, p->tx, 1);
        transfer(p, p->b, p->a, p->rx, 0);
        events(p, p->tx, 1);
        events(p, p->rx, 0);
        p->now += 10;
        CHECK(rnc_resource_tick(p->tx, p->now) == RNC_OK);
        CHECK(rnc_resource_tick(p->rx, p->now) == RNC_OK);
    }
    CHECK(p->txcomplete == 1 && p->rxcomplete == 1 && !p->failed);
}
static void transfer_test(void) {
    pair p;
    uint8_t data[50000], copy[50000];
    size_t n;
    rng r = {0xadef1234};
    random_bytes(&r, data, sizeof(data));
    init(&p, 100000);
    p.reverse = 1;
    p.duplicate_hmu = 1;
    p.drop_part = p.drop_proof = p.drop_adv = 1;
    CHECK(rnc_resource_send(p.tx, data, sizeof(data), NULL, p.now) == RNC_OK);
    CHECK(rnc_resource_send(p.tx, data, sizeof(data), NULL, p.now) == RNC_AGAIN);
    run(&p, 5000);
    CHECK(p.parts > 100 && p.hmus > 0);
    CHECK(rnc_resource_read(p.rx, copy, sizeof(copy), &n) == RNC_OK && n == sizeof(data) &&
          !memcmp(data, copy, n));
    CHECK(rnc_resource_read(p.tx, copy, sizeof(copy), &n) == RNC_STATE);
    finish(&p);
}
static void compression_test(void) {
    pair p;
    uint8_t data[50000] = {0}, copy[50000], meta[] = {0x81, 0xa1, 'x', 0x2a}, out[16],
            qid[16] = {42};
    size_t n;
    rnc_resource_options o = {1, meta, sizeof(meta), qid, 1};
    init(&p, 100000);
    CHECK(rnc_resource_send(p.tx, data, sizeof(data), &o, p.now) == RNC_OK);
    run(&p, 5000);
    CHECK(p.parts < 10);
    CHECK(rnc_resource_read(p.rx, copy, sizeof(copy), &n) == RNC_OK && n == sizeof(data) &&
          !memcmp(data, copy, n));
    CHECK(rnc_resource_metadata(p.rx, out, sizeof(out), &n) == RNC_OK && n == sizeof(meta) &&
          !memcmp(meta, out, n));
    finish(&p);
}
static void segments_test(void) {
    pair p;
    size_t length = RNC_RESOURCE_SEGMENT_MAX + 10000, n;
    uint8_t *data = malloc(length), *copy = malloc(length);
    rng r = {2468};
    CHECK(data && copy);
    random_bytes(&r, data, length);
    init(&p, length + 1000);
    CHECK(rnc_resource_send(p.tx, data, length, NULL, p.now) == RNC_OK);
    run(&p, 40000);
    CHECK(rnc_resource_read(p.rx, copy, length, &n) == RNC_OK && n == length &&
          !memcmp(data, copy, n));
    finish(&p);
    free(data);
    free(copy);
}
static void invalid_test(void) {
    pair p;
    uint8_t d[600] = {0}, copy[16] = {0x7a};
    size_t n = 99;
    rnc_link_event e;
    init(&p, 1000);
    CHECK(rnc_resource_send(p.tx, d, 1001, NULL, p.now) == RNC_NO_SPACE);
    CHECK(rnc_resource_accept(p.rx, (const uint8_t *)"bad", 3, p.now) == RNC_PROTOCOL);
    CHECK(rnc_resource_read(p.rx, copy, sizeof(copy), &n) == RNC_STATE && n == 0 &&
          copy[0] == 0x7a);
    CHECK(rnc_resource_send(p.tx, d, sizeof(d), NULL, p.now) == RNC_OK);
    CHECK(rnc_resource_pump(p.tx, p.now) == RNC_OK);
    {
        rnc_packet pkt = outgoing(p.a);
        CHECK(rnc_link_input(p.b, &pkt, p.now) == RNC_OK);
    }
    CHECK(rnc_link_poll(p.b, &e) == RNC_OK && e.context == 2);
    e.data[0] = 0xff;
    CHECK(rnc_resource_accept(p.rx, e.data, e.size, p.now) != RNC_OK);
    finish(&p);
}
static void cancel_test(void) {
    pair p;
    uint8_t d[1000] = {0};
    init(&p, 10000);
    CHECK(rnc_resource_send(p.tx, d, sizeof(d), NULL, p.now) == RNC_OK);
    CHECK(rnc_resource_cancel(p.tx, p.now) == RNC_OK);
    CHECK(rnc_resource_pump(p.tx, p.now) == RNC_OK);
    events(&p, p.tx, 1);
    CHECK(p.failed == 1 && p.txcomplete == 0);
    CHECK(rnc_resource_cancel(p.tx, p.now) == RNC_OK);
    finish(&p);
}

static void quota_test(void) {
    pair p;
    uint8_t wire[431], hash[32], maps[74 * 4];
    size_t n = 0, i;
    memset(hash, 3, sizeof(hash));
    memset(maps, 0, sizeof(maps));
    for (i = 0; i < 74; i++)
        maps[4 * i] = (uint8_t)i;
    wire[n++] = 0x8b;
#define KEY(k)                                                                                     \
    do {                                                                                           \
        wire[n++] = 0xa1;                                                                          \
        wire[n++] = (k);                                                                           \
    } while (0)
#define NUM(k, v)                                                                                  \
    do {                                                                                           \
        KEY(k);                                                                                    \
        wire[n++] = 0xce;                                                                          \
        uint32_t z = (v);                                                                          \
        wire[n++] = (uint8_t)(z >> 24);                                                            \
        wire[n++] = (uint8_t)(z >> 16);                                                            \
        wire[n++] = (uint8_t)(z >> 8);                                                             \
        wire[n++] = (uint8_t)z;                                                                    \
    } while (0)
#define BIN(k, b, z)                                                                               \
    do {                                                                                           \
        KEY(k);                                                                                    \
        size_t length = (z);                                                                       \
        wire[n++] = 0xc5;                                                                          \
        wire[n++] = (uint8_t)(length >> 8);                                                        \
        wire[n++] = (uint8_t)length;                                                               \
        memcpy(wire + n, (b), length);                                                             \
        n += length;                                                                               \
    } while (0)
    NUM('t', 1048639);
    NUM('d', 1);
    NUM('n', (1048639 + 463) / 464);
    BIN('h', hash, 32);
    BIN('r', hash, 4);
    BIN('o', hash, 32);
    NUM('i', 1);
    NUM('l', 1);
    KEY('q');
    wire[n++] = 0xc0;
    NUM('f', 1);
    BIN('m', maps, sizeof(maps));
#undef KEY
#undef NUM
#undef BIN
    CHECK(n <= sizeof(wire));
    init(&p, 1);
    CHECK(rnc_resource_accept(p.rx, wire, n, p.now) == RNC_PROTOCOL);
    finish(&p);
}
int main(int argc, char **argv) {
    CHECK(argc == 2);
    if (!strcmp(argv[1], "transfer"))
        transfer_test();
    else if (!strcmp(argv[1], "compression"))
        compression_test();
    else if (!strcmp(argv[1], "segments"))
        segments_test();
    else if (!strcmp(argv[1], "invalid"))
        invalid_test();
    else if (!strcmp(argv[1], "quota"))
        quota_test();
    else if (!strcmp(argv[1], "cancel"))
        cancel_test();
    else
        CHECK(0);
    return 0;
}
