#include <reticulum_c/rnc_buffer.h>
#include <reticulum_c/rnc_link.h>
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
typedef struct random_state {
    uint32_t value;
} random_state;
static rnc_result random_bytes(void *ctx, uint8_t *p, size_t n) {
    random_state *s = ctx;
    for (size_t i = 0; i < n; i++) {
        s->value ^= s->value << 13;
        s->value ^= s->value >> 17;
        s->value ^= s->value << 5;
        p[i] = (uint8_t)s->value;
    }
    return RNC_OK;
}
typedef struct mtu_pair {
    rnc_link *a, *b;
    random_state ar, br;
    rnc_identity identity;
    rnc_announce announce;
    rnc_packet request, proof;
    uint64_t now;
} mtu_pair;
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
static void init(mtu_pair *p, size_t amtu, size_t bmtu) {
    uint8_t key[64];
    rnc_packet a;
    memset(p, 0, sizeof(*p));
    p->ar.value = 123;
    p->br.value = 456;
    p->now = 100;
    for (size_t i = 0; i < 64; i++)
        key[i] = (uint8_t)i;
    CHECK(rnc_identity_from_private(&p->identity, key) == RNC_OK);
    CHECK(rnc_announce_create(&p->identity, "reticulum_c.mtu", NULL, 0, 1700000000, random_bytes,
                              &p->ar, &a) == RNC_OK);
    CHECK(rnc_announce_verify(&a, &p->announce) == RNC_OK);
    p->a = rnc_link_new(random_bytes, &p->ar);
    p->b = rnc_link_new(random_bytes, &p->br);
    CHECK(p->a && p->b);
    CHECK(rnc_link_configure_mtu(p->a, amtu) == RNC_OK);
    CHECK(rnc_link_configure_mtu(p->b, bmtu) == RNC_OK);
    CHECK(rnc_link_open(p->a, &p->announce, p->now) == RNC_OK);
    p->request = outgoing(p->a);
}
static void establish(mtu_pair *p) {
    rnc_packet rtt;
    rnc_link_event e;
    CHECK(rnc_link_accept(p->b, &p->identity, p->announce.destination, &p->request, ++p->now) ==
          RNC_OK);
    p->proof = outgoing(p->b);
    CHECK(rnc_link_input(p->a, &p->proof, ++p->now) == RNC_OK);
    rtt = outgoing(p->a);
    CHECK(rnc_link_input(p->b, &rtt, ++p->now) == RNC_OK);
    while (rnc_link_poll(p->a, &e) == RNC_OK) {
    }
    while (rnc_link_poll(p->b, &e) == RNC_OK) {
    }
    CHECK(rnc_link_is_active(p->a) && rnc_link_is_active(p->b));
}
static void finish(mtu_pair *p) {
    rnc_link_free(p->a);
    rnc_link_free(p->b);
    rnc_identity_clear(&p->identity);
}
static void negotiation_test(void) {
    mtu_pair p;
    uint8_t data[RNC_LINK_MAX_MDU], hash[32];
    rnc_packet packet;
    rnc_link_event e;
    memset(data, 0x7e, sizeof(data));
    init(&p, 4096, 2048);
    CHECK(p.request.data[65] == 0x10 && p.request.data[66] == 0);
    establish(&p);
    CHECK(rnc_link_mtu(p.a) == 2048 && rnc_link_mtu(p.b) == 2048);
    CHECK(rnc_link_mdu(p.a) == 1967 && rnc_link_channel_mdu(p.a) == 1961);
    CHECK(rnc_link_configure_mtu(p.a, 500) == RNC_STATE);
    CHECK(rnc_link_send(p.a, 42, data, rnc_link_channel_mdu(p.a), p.now) == RNC_OK);
    packet = outgoing(p.a);
    CHECK(packet.data_size > 480 && packet.data_size + 19 <= 2048);
    CHECK(rnc_packet_hash(&packet, hash) == RNC_OK);
    CHECK(rnc_link_input(p.b, &packet, p.now) == RNC_OK);
    packet = outgoing(p.b);
    CHECK(rnc_link_input(p.a, &packet, p.now) == RNC_OK);
    CHECK(rnc_link_poll(p.b, &e) == RNC_OK && e.type == RNC_LINK_MESSAGE && e.size == 1961 &&
          !memcmp(e.data, data, e.size));
    CHECK(rnc_link_send_packet(p.a, 0, data, rnc_link_mdu(p.a) + 1, p.now) == RNC_INVALID);
    finish(&p);
}
static void full_test(void) {
    mtu_pair p;
    uint8_t data[RNC_LINK_MAX_MDU];
    rnc_packet first, retry, proof;
    rnc_link_event e;
    memset(data, 0x7d, sizeof(data));
    init(&p, 4096, 4096);
    establish(&p);
    CHECK(rnc_link_mtu(p.a) == 4096 && rnc_link_mdu(p.a) == 4015);
    CHECK(rnc_link_send(p.a, 0x1234, data, RNC_CHANNEL_MAX_MDU, p.now) == RNC_OK);
    first = outgoing(p.a);
    CHECK(first.data_size == 4064);
    CHECK(rnc_link_input(p.b, &first, p.now) == RNC_OK);
    proof = outgoing(p.b);
    CHECK(rnc_link_poll(p.b, &e) == RNC_OK && e.size == RNC_CHANNEL_MAX_MDU &&
          !memcmp(e.data, data, e.size));
    CHECK(rnc_link_tick(p.a, p.now + 1000) == RNC_OK);
    retry = outgoing(p.a);
    CHECK(retry.data_size == first.data_size && memcmp(retry.data, first.data, first.data_size));
    CHECK(rnc_link_input(p.b, &retry, p.now + 1000) == RNC_OK);
    (void)outgoing(p.b);
    CHECK(rnc_link_poll(p.b, &e) == RNC_AGAIN);
    CHECK(rnc_link_input(p.a, &proof, p.now + 1000) == RNC_OK);
    CHECK(rnc_link_poll(p.a, &e) == RNC_OK && e.type == RNC_LINK_DELIVERED);
    finish(&p);
}
static void downgrade_test(void) {
    mtu_pair p;
    uint8_t data[500] = {0};
    init(&p, 4096, 500);
    establish(&p);
    CHECK(rnc_link_mtu(p.a) == 500 && rnc_link_mdu(p.a) == 431);
    CHECK(rnc_link_send(p.a, 1, data, 426, p.now) == RNC_INVALID);
    CHECK(rnc_link_send_resource_packet(p.a, RNC_DATA, 1, data, 465, p.now) == RNC_INVALID);
    finish(&p);
}
static void bounds_test(void) {
    mtu_pair p;
    rnc_packet proof;
    uint8_t data[500] = {0};
    rnc_link_event e;
    init(&p, 500, 500);
    CHECK(rnc_link_configure_mtu(p.b, 499) == RNC_INVALID);
    CHECK(rnc_link_configure_mtu(p.b, 4097) == RNC_INVALID);
    CHECK(rnc_link_send_packet(p.a, 0, data, 1, p.now) == RNC_STATE);
    CHECK(rnc_link_accept(p.b, &p.identity, p.announce.destination, &p.request, ++p.now) == RNC_OK);
    proof = outgoing(p.b);
    proof.data[97] = 0x10;
    proof.data[98] = 0;
    CHECK(rnc_link_input(p.a, &proof, ++p.now) != RNC_OK && !rnc_link_is_active(p.a));
    CHECK(rnc_link_mtu(p.a) == 500);
    finish(&p);
    init(&p, 4096, 4096);
    establish(&p);
    proof.flags = RNC_LINK << 2;
    proof.context = 0;
    memcpy(proof.destination, p.a ? p.request.destination : data, 16);
    proof.data_size = RNC_MAX_MTU - 18u;
    CHECK(rnc_packet_hash(&proof, data) != RNC_OK);
    CHECK(rnc_link_poll(p.a, &e) == RNC_AGAIN);
    finish(&p);
}
static void framing_test(void) {
    rnc_packet p = {0}, q;
    uint8_t wire[RNC_MAX_MTU], framed[RNC_HDLC_MAX], decoded[RNC_MAX_MTU];
    size_t n, f, d;
    rnc_hdlc h = {0};
    p.flags = RNC_LINK << 2;
    p.data_size = RNC_MAX_MTU - 19u;
    memset(p.data, 0x7e, p.data_size);
    CHECK(rnc_packet_encode(&p, wire, sizeof(wire), &n) == RNC_OK && n == RNC_MAX_MTU);
    CHECK(rnc_packet_decode(wire, n, &q) == RNC_OK && q.data_size == p.data_size);
    CHECK(rnc_hdlc_encode(wire, n, framed, sizeof(framed), &f) == RNC_OK);
    int got = 0;
    for (size_t i = 0; i < f; i++)
        if (rnc_hdlc_feed(&h, framed[i], decoded, sizeof(decoded), &d) == RNC_OK) {
            CHECK(d == n && !memcmp(decoded, wire, n));
            got++;
        }
    CHECK(got == 1);
    p.flags = RNC_SINGLE << 2;
    CHECK(rnc_packet_encode(&p, wire, sizeof(wire), &n) == RNC_INVALID);
    p.flags = RNC_LINK << 2;
    p.data_size = RNC_MAX_MTU - 18u;
    CHECK(rnc_packet_encode(&p, wire, sizeof(wire), &n) == RNC_INVALID);
}
static void stream_test(void) {
    mtu_pair p;
    uint8_t data[4007], output[4007];
    size_t consumed, n;
    int eof;
    rnc_link_event event;
    memset(data, 0x63, sizeof(data));
    init(&p, 4096, 4096);
    establish(&p);
    rnc_stream *writer = rnc_stream_new(42, 5000), *reader = rnc_stream_new(42, 5000);
    CHECK(writer && reader);
    CHECK(rnc_stream_write(writer, p.a, data, sizeof(data), 1, 0, &consumed, p.now) == RNC_OK);
    CHECK(consumed == sizeof(data));
    rnc_packet packet = outgoing(p.a);
    CHECK(packet.data_size > 4000 && rnc_link_input(p.b, &packet, p.now) == RNC_OK);
    packet = outgoing(p.b);
    CHECK(rnc_link_input(p.a, &packet, p.now) == RNC_OK);
    CHECK(rnc_link_poll(p.b, &event) == RNC_OK && event.type == RNC_LINK_MESSAGE);
    CHECK(rnc_stream_input(reader, &event) == RNC_OK);
    CHECK(rnc_stream_read(reader, output, sizeof(output), &n, &eof) == RNC_OK &&
          n == sizeof(data) && eof && !memcmp(data, output, n));
    rnc_stream_free(writer);
    rnc_stream_free(reader);
    finish(&p);
}
int main(int argc, char **argv) {
    CHECK(argc == 2);
    if (!strcmp(argv[1], "negotiation"))
        negotiation_test();
    else if (!strcmp(argv[1], "full"))
        full_test();
    else if (!strcmp(argv[1], "downgrade"))
        downgrade_test();
    else if (!strcmp(argv[1], "bounds"))
        bounds_test();
    else if (!strcmp(argv[1], "stream"))
        stream_test();
    else if (!strcmp(argv[1], "framing"))
        framing_test();
    else
        CHECK(0);
    return 0;
}
