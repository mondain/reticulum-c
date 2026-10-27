#include <reticulum_c/rnc_link.h>
#include "../src/internal.h" /* Boundary setup without adding test-only public API. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
typedef struct random_state { unsigned value; } random_state;
static rnc_result random_bytes(void *context, uint8_t *out, size_t size) {
    random_state *state = context; size_t i;
    for (i = 0; i < size; ++i) out[i] = (uint8_t)(state->value++);
    return RNC_OK;
}
typedef struct pair {
    rnc_link *client, *server;
    rnc_identity identity, client_identity;
    random_state cr, sr, ar;
    rnc_announce announce;
} pair;
static void init(pair *p) {
    uint8_t key[64]; size_t i; rnc_packet announce;
    memset(p, 0, sizeof(*p)); p->sr.value = 64; p->ar.value = 128;
    for (i = 0; i < 64; ++i) key[i] = (uint8_t)i;
    CHECK(rnc_identity_from_private(&p->identity, key) == RNC_OK);
    for (i = 0; i < 64; ++i) key[i] = (uint8_t)(i+128);
    CHECK(rnc_identity_from_private(&p->client_identity, key) == RNC_OK);
    CHECK(rnc_announce_create(&p->identity, "reticulum_c.link.v1", NULL, 0, 1700000000,
        random_bytes, &p->ar, &announce) == RNC_OK);
    CHECK(rnc_announce_verify(&announce, &p->announce) == RNC_OK);
    p->client = rnc_link_new(random_bytes, &p->cr);
    p->server = rnc_link_new(random_bytes, &p->sr);
    CHECK(p->client && p->server);
}
static rnc_packet outgoing(rnc_link *link) {
    rnc_link_event event;
    while (rnc_link_poll(link, &event) == RNC_OK) if (event.type == RNC_LINK_SEND) return event.packet;
    CHECK(0); { rnc_packet empty = {0}; return empty; }
}
static unsigned count(rnc_link *link, rnc_link_event_type type) {
    rnc_link_event event; unsigned found = 0;
    while (rnc_link_poll(link, &event) == RNC_OK) if (event.type == type) ++found;
    return found;
}
static void establish(pair *p) {
    rnc_packet request, proof, rtt, identity; rnc_identity remote;
    CHECK(rnc_link_open(p->client, &p->announce, 100) == RNC_OK);
    request = outgoing(p->client);
    CHECK(request.flags == 2 && request.data_size == 67 && request.data[64] == 0x20 && request.data[65] == 1 && request.data[66] == 0xf4);
    CHECK(rnc_link_accept(p->server, &p->identity, p->announce.destination, &request, 101) == RNC_OK);
    CHECK(!rnc_link_is_active(p->client) && !rnc_link_is_active(p->server));
    proof = outgoing(p->server);
    CHECK(proof.flags == 15 && proof.context == 255 && proof.data_size == 99);
    proof.destination[0] ^= 1;
    CHECK(rnc_link_input(p->client, &proof, 102) == RNC_PROTOCOL);
    proof.destination[0] ^= 1; proof.data_size = 98;
    CHECK(rnc_link_input(p->client, &proof, 102) == RNC_PROTOCOL);
    proof.data_size = 99; proof.data[96] = 0x40;
    CHECK(rnc_link_input(p->client, &proof, 102) == RNC_UNSUPPORTED);
    proof.data[96] = 0x20;
    proof.data[0] ^= 1;
    CHECK(rnc_link_input(p->client, &proof, 102) == RNC_AUTH && !rnc_link_is_active(p->client));
    proof.data[0] ^= 1;
    CHECK(rnc_link_input(p->client, &proof, 102) == RNC_OK);
    CHECK(rnc_link_is_active(p->client));
    CHECK(rnc_link_remote_identity(p->client, &remote) == RNC_OK && !remote.has_private);
    CHECK(!memcmp(remote.hash, p->identity.hash, 16));
    rtt = outgoing(p->client);
    CHECK(rtt.context == 254 && rtt.data_size >= 64);
    CHECK(rnc_link_input(p->server, &rtt, 103) == RNC_OK && rnc_link_is_active(p->server));
    CHECK(count(p->client, RNC_LINK_ACTIVE) == 1);
    CHECK(count(p->server, RNC_LINK_ACTIVE) == 1);
    CHECK(rnc_link_remote_identity(p->server, &remote) == RNC_AGAIN);
    CHECK(rnc_link_identify(p->client, &p->client_identity, 104) == RNC_OK);
    identity = outgoing(p->client);
    CHECK(identity.context == 251);
    identity.data[20] ^= 1;
    CHECK(rnc_link_input(p->server, &identity, 104) == RNC_AUTH);
    identity.data[20] ^= 1;
    CHECK(rnc_link_input(p->server, &identity, 104) == RNC_OK);
    CHECK(rnc_link_remote_identity(p->server, &remote) == RNC_OK && !remote.has_private);
    CHECK(!memcmp(remote.hash, p->client_identity.hash, 16));
    CHECK(count(p->server, RNC_LINK_IDENTIFIED) == 1);
    {
        uint8_t plain[RNC_LINK_MDU]; size_t size;
        CHECK(rnc_token_open(p->client->key, identity.data, identity.data_size, plain, sizeof(plain), &size) == RNC_OK);
        plain[127] ^= 1;
        CHECK(rnc_link_seal(p->client, 251, plain, size, &identity) == RNC_OK);
        CHECK(rnc_link_input(p->server, &identity, 104) == RNC_AUTH);
        CHECK(count(p->server, RNC_LINK_IDENTIFIED) == 0);
    }
}
static void finish(pair *p) {
    rnc_link_free(p->client); rnc_link_free(p->server);
    rnc_identity_clear(&p->identity); rnc_identity_clear(&p->client_identity);
}
static void handshake_test(void) {
    pair p; rnc_packet close; init(&p); establish(&p);
    CHECK(rnc_link_close(p.client, 105) == RNC_OK && !rnc_link_is_active(p.client));
    close = outgoing(p.client);
    CHECK(close.context == 252);
    CHECK(rnc_link_input(p.server, &close, 106) == RNC_OK && !rnc_link_is_active(p.server));
    CHECK(count(p.server, RNC_LINK_CLOSED) == 1);
    CHECK(rnc_link_send(p.client, 1, "x", 1, 106) == RNC_STATE);
    finish(&p);
}
static void reliability_test(void) {
    pair p; rnc_packet first, second, proof1, proof0, retry; rnc_link_event event;
    unsigned messages = 0; init(&p); establish(&p);
    CHECK(rnc_link_send(p.client, 0x4348, "first", 5, 110) == RNC_OK);
    first = outgoing(p.client);
    CHECK(rnc_link_send(p.client, 0x4348, "second", 6, 110) == RNC_OK);
    second = outgoing(p.client);
    CHECK(rnc_link_send(p.client, 0x4348, "third", 5, 110) == RNC_AGAIN);
    CHECK(rnc_link_input(p.server, &second, 111) == RNC_OK);
    proof1 = outgoing(p.server);
    CHECK(count(p.server, RNC_LINK_MESSAGE) == 0);
    CHECK(rnc_link_input(p.server, &first, 112) == RNC_OK);
    proof0 = outgoing(p.server);
    while (rnc_link_poll(p.server, &event) == RNC_OK) if (event.type == RNC_LINK_MESSAGE) {
        CHECK(event.sequence == messages && event.message_type == 0x4348);
        CHECK(event.size == (messages ? 6u : 5u));
        CHECK(!memcmp(event.data, messages ? "second" : "first", event.size)); ++messages;
    }
    CHECK(messages == 2);
    proof0.data[95] ^= 1;
    CHECK(rnc_link_input(p.client, &proof0, 113) == RNC_AUTH);
    proof0.data[95] ^= 1;
    CHECK(rnc_link_input(p.client, &proof0, 113) == RNC_OK);
    CHECK(count(p.client, RNC_LINK_DELIVERED) == 1);
    CHECK(rnc_link_tick(p.client, 1000) == RNC_OK);
    retry = outgoing(p.client);
    CHECK(memcmp(retry.data, second.data, second.data_size));
    CHECK(rnc_link_input(p.server, &retry, 1001) == RNC_OK);
    (void)outgoing(p.server);
    CHECK(count(p.server, RNC_LINK_MESSAGE) == 0);
    /* An earlier valid proof still concludes a retransmitted message. */
    CHECK(rnc_link_input(p.client, &proof1, 1002) == RNC_OK);
    CHECK(count(p.client, RNC_LINK_DELIVERED) == 1);
    CHECK(rnc_link_send(p.client, 0x4348, "third", 5, 1003) == RNC_OK);
    finish(&p);
}
static void establish_with_rtt(pair *p, uint64_t rtt_ms);
static void lifecycle_test(void) {
    pair p; rnc_packet request; unsigned i; init(&p);
    CHECK(rnc_link_open(p.client, &p.announce, 100) == RNC_OK);
    request = outgoing(p.client); request.destination[0] ^= 1;
    CHECK(rnc_link_accept(p.server, &p.identity, p.announce.destination, &request, 101) == RNC_PROTOCOL);
    request.destination[0] ^= 1; request.data[64] = 0x40;
    CHECK(rnc_link_accept(p.server, &p.identity, p.announce.destination, &request, 101) == RNC_UNSUPPORTED);
    request.data[64] = 0x20; request.data[66] = 0xf3;
    CHECK(rnc_link_accept(p.server, &p.identity, p.announce.destination, &request, 101) == RNC_UNSUPPORTED);
    request.data[66] = 0xf4; request.data_size = 66;
    CHECK(rnc_link_accept(p.server, &p.identity, p.announce.destination, &request, 101) == RNC_PROTOCOL);
    CHECK(rnc_link_tick(p.client, 99) == RNC_INVALID);
    CHECK(rnc_link_tick(p.client, 30100) == RNC_OK);
    CHECK(count(p.client, RNC_LINK_CLOSED) == 1); finish(&p);
    /* A slow link (large keepalive) so channel retries, not staleness, end it. */
    init(&p); establish_with_rtt(&p, 5000);
    CHECK(rnc_link_send(p.client, 1, "lost", 4, 5200) == RNC_OK);
    (void)outgoing(p.client);
    {
        unsigned closed = 0, resends = 0;
        rnc_link_event event;
        for (i = 1; i <= 400 && rnc_link_is_active(p.client); ++i) {
            CHECK(rnc_link_tick(p.client, 5200u + i * 1000u) == RNC_OK);
            while (rnc_link_poll(p.client, &event) == RNC_OK) {
                resends += event.type == RNC_LINK_SEND && event.packet.context == 14;
                closed += event.type == RNC_LINK_CLOSED;
            }
        }
        CHECK(closed == 1 && resends == 4);
    }
    CHECK(!rnc_link_is_active(p.client)); finish(&p);
}
static void keepalive_test(void) {
    pair p; rnc_packet ping, pong; uint64_t now; init(&p); establish(&p);
    for (now = 30100; now <= 300100; now += 30000) {
        CHECK(rnc_link_tick(p.client, now) == RNC_OK);
        CHECK(rnc_link_is_active(p.client)); ping = outgoing(p.client);
        CHECK(ping.context == 250 && ping.data_size == 1 && ping.data[0] == 0xff);
        CHECK(rnc_link_input(p.server, &ping, now) == RNC_OK); pong = outgoing(p.server);
        CHECK(pong.data[0] == 0xfe && rnc_link_input(p.client, &pong, now) == RNC_OK);
        CHECK(rnc_link_tick(p.server, now) == RNC_OK && rnc_link_is_active(p.server));
    }
    /* Wrong-role bytes never extend liveness; a silent peer still expires. */
    ping.data[0] = 0xfe;
    CHECK(rnc_link_input(p.server, &ping, 470100) == RNC_PROTOCOL);
    CHECK(rnc_link_tick(p.server, 480100) == RNC_OK && rnc_link_status_of(p.server) == RNC_LINK_STATUS_STALE);
    CHECK(rnc_link_tick(p.client, 480100) == RNC_OK && rnc_link_status_of(p.client) == RNC_LINK_STATUS_STALE);
    CHECK(rnc_link_tick(p.server, 490000) == RNC_OK && !rnc_link_is_active(p.server));
    CHECK(rnc_link_tick(p.client, 490000) == RNC_OK && !rnc_link_is_active(p.client));
    finish(&p);
}
static void boundaries_test(void) {
    pair p; rnc_packet data, proof; rnc_link_event event; rnc_identity remote;
    rnc_link snapshot; uint8_t payload[RNC_CHANNEL_MDU]; unsigned i, entropy;
    init(&p); establish(&p); memset(payload, 0xa5, sizeof(payload));
    p.client->tx_next = p.server->rx_next = 65535;
    CHECK(rnc_link_send(p.client, 0x4348, payload, sizeof(payload)+1u, 110) == RNC_INVALID);
    CHECK(rnc_link_send(p.client, 0x4348, payload, sizeof(payload), 110) == RNC_OK);
    data = outgoing(p.client);
    CHECK(data.data_size == 480);
    /* A full event queue must reject without consuming sequence, RNG or clock. */
    for (i = 0; i < RNC_LINK_EVENTS; ++i) CHECK(rnc_link_identify(p.client, &p.client_identity, 110) == RNC_OK);
    snapshot = *p.client; entropy = p.cr.value;
    CHECK(rnc_link_send(p.client, 1, "x", 1, 111) == RNC_AGAIN);
    CHECK(!memcmp(&snapshot, p.client, sizeof(snapshot)) && entropy == p.cr.value);
    (void)count(p.client, RNC_LINK_SEND);
    for (i = 0; i < 15; ++i) (void)rnc_emit(p.server, RNC_LINK_ACTIVE);
    snapshot = *p.server;
    CHECK(rnc_link_input(p.server, &data, 111) == RNC_AGAIN);
    CHECK(!memcmp(&snapshot, p.server, sizeof(snapshot)));
    (void)count(p.server, RNC_LINK_ACTIVE);
    CHECK(rnc_link_input(p.server, &data, 111) == RNC_OK); proof = outgoing(p.server);
    CHECK(rnc_link_poll(p.server, &event) == RNC_OK && event.type == RNC_LINK_MESSAGE);
    CHECK(event.sequence == 65535 && event.size == sizeof(payload) && !memcmp(event.data, payload, sizeof(payload)));
    CHECK(rnc_link_input(p.client, &proof, 112) == RNC_OK);
    (void)count(p.client, RNC_LINK_DELIVERED);
    CHECK(rnc_link_send(p.client, 1, "wrap", 4, 113) == RNC_OK); data = outgoing(p.client);
    CHECK(rnc_link_input(p.server, &data, 114) == RNC_OK); (void)outgoing(p.server);
    CHECK(rnc_link_poll(p.server, &event) == RNC_OK && event.sequence == 0 && event.size == 4);
    /* An authenticated packet outside the receive window must get no proof. */
    p.client->tx_next = (uint16_t)(p.server->rx_next+RNC_CHANNEL_RX_WINDOW);
    CHECK(rnc_link_send(p.client, 1, "far", 3, 115) == RNC_OK); data = outgoing(p.client);
    snapshot = *p.server;
    CHECK(rnc_link_input(p.server, &data, 116) == RNC_PROTOCOL);
    CHECK(!memcmp(&snapshot, p.server, sizeof(snapshot)));
    /* A valid different principal cannot replace a link's established identity. */
    CHECK(rnc_link_identify(p.client, &p.identity, 117) == RNC_OK); data = outgoing(p.client);
    CHECK(rnc_link_input(p.server, &data, 118) == RNC_AUTH);
    CHECK(rnc_link_remote_identity(p.server, &remote) == RNC_OK && !memcmp(remote.hash, p.client_identity.hash, 16));
    finish(&p);
}
/* Establish with a chosen link-request round trip so the measured RTT is known. */
static void establish_with_rtt(pair *p, uint64_t rtt_ms) {
    rnc_packet request, proof, rtt;
    CHECK(rnc_link_open(p->client, &p->announce, 100) == RNC_OK);
    request = outgoing(p->client);
    CHECK(rnc_link_accept(p->server, &p->identity, p->announce.destination, &request, 101) == RNC_OK);
    proof = outgoing(p->server);
    CHECK(rnc_link_input(p->client, &proof, 100 + rtt_ms) == RNC_OK);
    rtt = outgoing(p->client);
    CHECK(rnc_link_input(p->server, &rtt, 101 + rtt_ms) == RNC_OK);
    (void)count(p->client, RNC_LINK_ACTIVE); (void)count(p->server, RNC_LINK_ACTIVE);
}
static unsigned sends(rnc_link *link) { return count(link, RNC_LINK_SEND); }
/* Keepalive scales with RTT (RTT * 360/1.75 s, clamped to 5..360 s). */
static void keepalive_scale_test(void) {
    pair p; init(&p); establish_with_rtt(&p, 2);
    CHECK(rnc_link_keepalive_ms(p.client) == 5000u);
    finish(&p);
    init(&p); establish_with_rtt(&p, 1000);
    CHECK(rnc_link_keepalive_ms(p.client) == 205714u);
    finish(&p);
    init(&p); establish_with_rtt(&p, 5000);
    CHECK(rnc_link_keepalive_ms(p.client) == 360000u);
    finish(&p);
}
/* Quiet fast link: ping after one keepalive, STALE after two, teardown after
 * the RTT-derived grace; any inbound traffic revives a stale link. */
static void stale_test(void) {
    pair p; rnc_packet pong; rnc_link_event event; init(&p); establish_with_rtt(&p, 2);
    CHECK(rnc_link_status_of(p.client) == RNC_LINK_STATUS_ACTIVE);
    CHECK(rnc_link_tick(p.client, 3000) == RNC_OK && sends(p.client) == 0);
    CHECK(rnc_link_tick(p.client, 5200) == RNC_OK && sends(p.client) == 1);
    CHECK(rnc_link_status_of(p.client) == RNC_LINK_STATUS_ACTIVE);
    CHECK(rnc_link_tick(p.client, 10200) == RNC_OK);
    CHECK(rnc_link_status_of(p.client) == RNC_LINK_STATUS_STALE && rnc_link_is_active(p.client));
    (void)sends(p.client);
    /* A reply from the peer returns the link to ACTIVE. */
    {
        rnc_packet ping = {0};
        ping.flags = 12; ping.context = 250; ping.data_size = 1; ping.data[0] = 0xfe;
        memcpy(ping.destination, p.client->address, 16);
        CHECK(rnc_link_input(p.client, &ping, 10300) == RNC_OK);
        (void)pong;
    }
    CHECK(rnc_link_status_of(p.client) == RNC_LINK_STATUS_ACTIVE);
    CHECK(rnc_link_tick(p.client, 20400) == RNC_OK);
    CHECK(rnc_link_status_of(p.client) == RNC_LINK_STATUS_STALE);
    (void)sends(p.client);
    /* Grace is RTT*4 + 5 s after becoming stale. */
    CHECK(rnc_link_tick(p.client, 25400) == RNC_OK && rnc_link_is_active(p.client));
    CHECK(rnc_link_tick(p.client, 25420) == RNC_OK);
    CHECK(!rnc_link_is_active(p.client));
    CHECK(rnc_link_status_of(p.client) == RNC_LINK_STATUS_CLOSED);
    CHECK(rnc_link_teardown_reason(p.client) == RNC_TEARDOWN_TIMEOUT);
    CHECK(rnc_link_poll(p.client, &event) == RNC_OK && event.type == RNC_LINK_SEND && event.packet.context == 252);
    CHECK(rnc_link_poll(p.client, &event) == RNC_OK && event.type == RNC_LINK_CLOSED && event.reason == RNC_TIMEOUT);
    finish(&p);
}
static void reasons_test(void) {
    pair p; rnc_packet close; init(&p); establish(&p);
    CHECK(rnc_link_teardown_reason(p.client) == RNC_TEARDOWN_NONE);
    CHECK(rnc_link_close(p.client, 200) == RNC_OK);
    CHECK(rnc_link_teardown_reason(p.client) == RNC_TEARDOWN_INITIATOR_CLOSED);
    close = outgoing(p.client);
    CHECK(rnc_link_input(p.server, &close, 201) == RNC_OK);
    CHECK(rnc_link_teardown_reason(p.server) == RNC_TEARDOWN_INITIATOR_CLOSED);
    CHECK(rnc_link_status_of(p.server) == RNC_LINK_STATUS_CLOSED);
    finish(&p);
    init(&p); establish(&p);
    CHECK(rnc_link_close(p.server, 200) == RNC_OK);
    CHECK(rnc_link_teardown_reason(p.server) == RNC_TEARDOWN_DESTINATION_CLOSED);
    close = outgoing(p.server);
    CHECK(rnc_link_input(p.client, &close, 201) == RNC_OK);
    CHECK(rnc_link_teardown_reason(p.client) == RNC_TEARDOWN_DESTINATION_CLOSED);
    finish(&p);
}
/* Establishment timeout follows hop count and first-hop time. */
static void establishment_test(void) {
    pair p; init(&p);
    CHECK(rnc_link_configure_establishment(p.client, 3, 4000) == RNC_OK);
    CHECK(rnc_link_open(p.client, &p.announce, 100) == RNC_OK);
    CHECK(rnc_link_status_of(p.client) == RNC_LINK_STATUS_PENDING);
    CHECK(rnc_link_tick(p.client, 100 + 21999) == RNC_OK && rnc_link_status_of(p.client) == RNC_LINK_STATUS_PENDING);
    CHECK(rnc_link_tick(p.client, 100 + 22000) == RNC_OK);
    CHECK(rnc_link_status_of(p.client) == RNC_LINK_STATUS_CLOSED);
    CHECK(rnc_link_teardown_reason(p.client) == RNC_TEARDOWN_TIMEOUT);
    finish(&p);
    init(&p);
    CHECK(rnc_link_configure_establishment(p.client, 0, 0) == RNC_OK);
    CHECK(rnc_link_open(p.client, &p.announce, 100) == RNC_OK);
    CHECK(rnc_link_tick(p.client, 100 + 5999) == RNC_OK && rnc_link_status_of(p.client) == RNC_LINK_STATUS_PENDING);
    CHECK(rnc_link_tick(p.client, 100 + 6000) == RNC_OK && rnc_link_status_of(p.client) == RNC_LINK_STATUS_CLOSED);
    finish(&p);
}
/* Age and idle getters distinguish control traffic from application data. */
static void getters_test(void) {
    pair p; uint64_t value; init(&p); establish_with_rtt(&p, 2);
    CHECK(rnc_link_rtt(p.client, &value) == RNC_OK && value == 2);
    CHECK(rnc_link_age_ms(p.client, 1102, &value) == RNC_OK && value == 1000);
    CHECK(rnc_link_no_inbound_ms(p.client, 2102) == 2000u);
    CHECK(rnc_link_no_outbound_ms(p.client, 2102) >= 1999u);
    /* mode: AES-256-CBC, 1 in the reference's numbering */
    CHECK(rnc_link_mode(p.client) == 1u && rnc_link_mode(p.server) == 1u);
    /* establishment rate: request (86 bytes) and proof (118) over the RTT */
    CHECK(rnc_link_establishment_rate(p.client, &value) == RNC_OK &&
          value == 204u * 8u * 1000u / 2u);
    CHECK(rnc_link_establishment_rate(p.server, &value) == RNC_OK && value > 0);
    /* data idle time counts application data, in both directions */
    CHECK(rnc_link_no_data_ms(p.client, 502) == 400u);
    CHECK(rnc_link_send_packet(p.client, 0, "x", 1, 600) == RNC_OK);
    {
        rnc_packet data = outgoing(p.client);
        CHECK(rnc_link_no_data_ms(p.client, 700) == 100u);
        CHECK(rnc_link_no_data_ms(p.server, 650) == 547u); /* since activation at 103 */
        CHECK(rnc_link_input(p.server, &data, 650) == RNC_OK);
        CHECK(rnc_link_no_data_ms(p.server, 700) == 50u);
    }
    finish(&p);
    init(&p);
    CHECK(rnc_link_rtt(p.client, &value) == RNC_STATE);
    CHECK(rnc_link_age_ms(p.client, 10, &value) == RNC_STATE);
    CHECK(rnc_link_establishment_rate(p.client, &value) == RNC_STATE);
    finish(&p);
}
int main(int argc, char **argv) {
    CHECK(argc == 2);
    if (!strcmp(argv[1], "handshake")) handshake_test();
    else if (!strcmp(argv[1], "reliability")) reliability_test();
    else if (!strcmp(argv[1], "lifecycle")) lifecycle_test();
    else if (!strcmp(argv[1], "keepalive")) keepalive_test();
    else if (!strcmp(argv[1], "boundaries")) boundaries_test();
    else if (!strcmp(argv[1], "keepalive_scale")) keepalive_scale_test();
    else if (!strcmp(argv[1], "stale")) stale_test();
    else if (!strcmp(argv[1], "reasons")) reasons_test();
    else if (!strcmp(argv[1], "establishment")) establishment_test();
    else if (!strcmp(argv[1], "getters")) getters_test();
    else CHECK(0);
    puts("native C link test passed"); return 0;
}
