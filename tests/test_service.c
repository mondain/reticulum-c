#define main resource_test_main
#include "test_resource.c"
#undef main
#include <reticulum_c/rnc_service.h>
typedef struct spair {
    pair links;
    rnc_service *a, *b;
    unsigned requests, responses, timeouts, denied;
    uint8_t id[16];
    uint8_t *value;
    size_t size;
    rnc_link_event bulk_advertisement;
} spair;
static void sinit(spair *s, size_t limit, rnc_service_policy policy) {
    memset(s, 0, sizeof(*s));
    init(&s->links, limit + 100);
    s->a = rnc_service_new(s->links.a, limit, random_bytes, &s->links.ar);
    s->b = rnc_service_new(s->links.b, limit, random_bytes, &s->links.br);
    CHECK(s->a && s->b);
    CHECK(rnc_service_register(s->b, "/echo", policy, NULL, 0) == RNC_OK);
}
static void sfinish(spair *s) {
    rnc_service_free(s->a);
    rnc_service_free(s->b);
    finish(&s->links);
}
static void swire(spair *s, rnc_link *from, rnc_link *to, rnc_service *service) {
    rnc_link_event e;
    while (rnc_link_poll(from, &e) == RNC_OK) {
        if (e.type == RNC_LINK_SEND)
            CHECK(rnc_link_input(to, &e.packet, s->links.now) == RNC_OK);
        else if (e.type == RNC_LINK_PACKET || e.type == RNC_LINK_RESOURCE_PACKET) {
            rnc_result r = rnc_service_input(service, &e, s->links.now);
            CHECK(r == RNC_OK || r == RNC_AGAIN);
            if (service == s->b && e.type == RNC_LINK_PACKET && e.context == 2)
                s->bulk_advertisement = e;
        }
    }
}
static void sevents(spair *s, rnc_service *service, int server) {
    rnc_service_event e;
    uint8_t *buf = malloc(s->size + 100);
    size_t n;
    CHECK(buf);
    while (rnc_service_poll(service, &e, buf, s->size + 100, &n) == RNC_OK) {
        if (e.type == RNC_SERVICE_REQUEST) {
            CHECK(server && n == s->size && !memcmp(buf, s->value, n));
            CHECK(!memcmp(e.request_id, s->id, 16));
            s->requests++;
            CHECK(rnc_service_respond(service, e.request_id, buf, n, s->links.now) == RNC_OK);
        } else if (e.type == RNC_SERVICE_RESPONSE) {
            CHECK(!server && n == s->size && !memcmp(buf, s->value, n) &&
                  !memcmp(e.request_id, s->id, 16));
            s->responses++;
        } else if (e.type == RNC_SERVICE_TIMEOUT)
            s->timeouts++;
        else if (e.type == RNC_SERVICE_DENIED)
            s->denied++;
        else
            CHECK(0);
    }
    free(buf);
}
static void srun(spair *s, unsigned limit) {
    unsigned i;
    for (i = 0; i < limit && !s->responses; i++) {
        CHECK(rnc_service_pump(s->a, s->links.now) == RNC_OK);
        CHECK(rnc_service_pump(s->b, s->links.now) == RNC_OK);
        swire(s, s->links.a, s->links.b, s->a);
        swire(s, s->links.b, s->links.a, s->b);
        sevents(s, s->b, 1);
        sevents(s, s->a, 0);
        s->links.now += 10;
        CHECK(rnc_service_tick(s->a, s->links.now) == RNC_OK);
        CHECK(rnc_service_tick(s->b, s->links.now) == RNC_OK);
    }
}
static void inline_test(void) {
    spair s;
    uint8_t v[] = {0x92, 0xa3, 'h', 'e', 'y', 42};
    sinit(&s, 1000, RNC_SERVICE_ALLOW_ALL);
    s.value = v;
    s.size = sizeof(v);
    CHECK(rnc_service_request(s.a, "/echo", v, sizeof(v), 1700000000.25, s.links.now, 30000,
                              s.id) == RNC_OK);
    srun(&s, 100);
    CHECK(s.requests == 1 && s.responses == 1 && !s.timeouts);
    CHECK(rnc_service_respond(s.b, s.id, v, sizeof(v), s.links.now) == RNC_STATE);
    sfinish(&s);
}
static void bulk_test(void) {
    spair s;
    size_t i;
    sinit(&s, 60000, RNC_SERVICE_ALLOW_ALL);
    s.size = 50003;
    s.value = malloc(s.size);
    CHECK(s.value);
    s.value[0] = 0xc5;
    s.value[1] = (uint8_t)(50000 >> 8);
    s.value[2] = (uint8_t)50000;
    for (i = 3; i < s.size; i++)
        s.value[i] = (uint8_t)(i * 73u);
    CHECK(rnc_service_request(s.a, "/echo", s.value, s.size, 1700000000, s.links.now, 30000,
                              s.id) == RNC_OK);
    srun(&s, 5000);
    CHECK(s.requests == 1 && s.responses == 1 && !s.timeouts);
    free(s.value);
    sfinish(&s);
}
static void denial_test(void) {
    spair s;
    uint8_t v = 0xc0;
    sinit(&s, 1000, RNC_SERVICE_ALLOW_IDENTIFIED);
    s.value = &v;
    s.size = 1;
    CHECK(rnc_service_request(s.a, "/echo", &v, 1, 1700000000, s.links.now, 100, s.id) == RNC_OK);
    srun(&s, 30);
    CHECK(!s.requests && !s.responses && s.timeouts == 1 && s.denied == 1);
    sfinish(&s);
}
static void bounds_test(void) {
    spair s;
    uint8_t invalid[] = {0x92, 1}, id[16] = {42};
    rnc_service_event e;
    rnc_link_event ev = {0};
    size_t n = 9;
    sinit(&s, 100, RNC_SERVICE_ALLOW_ALL);
    CHECK(rnc_service_request(s.a, "/echo", invalid, sizeof(invalid), 1700000000, s.links.now, 100,
                              id) == RNC_INVALID &&
          id[0] == 42);
    CHECK(rnc_service_request(s.a, "/echo", invalid, 1, 1700000000, s.links.now, 0, id) ==
          RNC_INVALID);
    CHECK(rnc_service_poll(s.a, &e, NULL, 0, &n) == RNC_AGAIN && n == 0);
    uint8_t nil = 0xc0;
    CHECK(rnc_link_send_packet(s.links.a, 9, &nil, 1, s.links.now) == RNC_OK);
    rnc_packet bad = outgoing(s.links.a);
    CHECK(rnc_link_input(s.links.b, &bad, s.links.now) == RNC_OK);
    CHECK(rnc_link_poll(s.links.b, &ev) == RNC_OK);
    CHECK(rnc_service_input(s.b, &ev, s.links.now) == RNC_PROTOCOL);
    sfinish(&s);
}

static void replay_test(void) {
    spair s;
    uint8_t nil = 0xc0, out[64];
    size_t n;
    rnc_link_event request, response;
    rnc_service_event event;
    sinit(&s, 1000, RNC_SERVICE_ALLOW_ALL);
    CHECK(rnc_service_request(s.a, "/echo", &nil, 1, 1000, s.links.now, 10, s.id) == RNC_OK);
    rnc_packet packet = outgoing(s.links.a);
    CHECK(rnc_link_input(s.links.b, &packet, s.links.now + 1) == RNC_OK);
    CHECK(rnc_link_poll(s.links.b, &request) == RNC_OK);
    CHECK(rnc_service_input(s.b, &request, s.links.now + 1) == RNC_OK);
    CHECK(rnc_service_poll(s.b, &event, out, sizeof(out), &n) == RNC_OK &&
          event.type == RNC_SERVICE_REQUEST);
    CHECK(rnc_service_respond(s.b, event.request_id, &nil, 1, s.links.now + 1) == RNC_OK);
    packet = outgoing(s.links.b);
    CHECK(rnc_link_input(s.links.a, &packet, s.links.now + 20) == RNC_OK);
    CHECK(rnc_link_poll(s.links.a, &response) == RNC_OK);
    CHECK(rnc_service_input(s.a, &response, s.links.now + 20) == RNC_OK);
    CHECK(rnc_service_poll(s.a, &event, out, sizeof(out), &n) == RNC_AGAIN);
    CHECK(rnc_service_pump(s.a, s.links.now + 20) == RNC_OK);
    CHECK(rnc_service_poll(s.a, &event, out, sizeof(out), &n) == RNC_OK &&
          event.type == RNC_SERVICE_TIMEOUT);
    CHECK(rnc_service_input(s.b, &request, s.links.now + 21) == RNC_OK);
    CHECK(rnc_service_poll(s.b, &event, out, sizeof(out), &n) == RNC_AGAIN);
    sfinish(&s);
}
static void recovery_test(void) {
    for (unsigned wrong_binding = 0; wrong_binding < 2; wrong_binding++) {
        spair s;
        uint8_t malformed[600] = {0x91}, hash[32], value[5003];
        rnc_resource_options options = {0};
        unsigned rejected = 0, completed = 0;
        sinit(&s, 10000, RNC_SERVICE_ALLOW_ALL);
        CHECK(rnc_hash(malformed, sizeof(malformed), hash) == RNC_OK);
        hash[0] ^= (uint8_t)wrong_binding;
        options.request_id = hash;
        CHECK(rnc_resource_send(s.links.tx, malformed, sizeof(malformed), &options,
                                s.links.now) == RNC_OK);
        for (unsigned i = 0; i < 1000 && !completed; i++) {
            rnc_link_event e;
            rnc_resource_event re;
            rnc_result result;
            CHECK(rnc_resource_pump(s.links.tx, s.links.now) == RNC_OK);
            result = rnc_service_pump(s.b, s.links.now);
            if (result == (wrong_binding ? RNC_AUTH : RNC_PROTOCOL))
                rejected++;
            else
                CHECK(result == RNC_OK);
            while (rnc_link_poll(s.links.a, &e) == RNC_OK) {
                if (e.type == RNC_LINK_SEND)
                    CHECK(rnc_link_input(s.links.b, &e.packet, s.links.now) == RNC_OK);
                else if (e.type == RNC_LINK_PACKET || e.type == RNC_LINK_RESOURCE_PACKET) {
                    result = rnc_resource_input(s.links.tx, &e, s.links.now);
                    CHECK(result == RNC_OK || result == RNC_AGAIN);
                }
            }
            swire(&s, s.links.b, s.links.a, s.b);
            while (rnc_resource_poll(s.links.tx, &re) == RNC_OK) {
                CHECK(re.type != RNC_RESOURCE_FAILED);
                if (re.type == RNC_RESOURCE_COMPLETE)
                    completed++;
            }
            s.links.now++;
        }
        if (completed != 1 || rejected != 1)
            fprintf(stderr, "bulk recovery: completed=%u rejected=%u binding=%u\n",
                    completed, rejected, wrong_binding);
        CHECK(completed == 1 && rejected == 1);
        /* A rejected completed envelope must not poison the next pump or
         * prevent a fresh bulk request on this same authenticated link. */
        CHECK(rnc_service_pump(s.b, s.links.now) == RNC_OK);
        value[0] = 0xc5;
        value[1] = (uint8_t)(5000 >> 8);
        value[2] = (uint8_t)5000;
        for (size_t i = 3; i < sizeof(value); i++)
            value[i] = (uint8_t)(i * 73u);
        s.value = value;
        s.size = sizeof(value);
        CHECK(rnc_service_request(s.a, "/echo", value, sizeof(value), 1700000000,
                                  s.links.now, 30000, s.id) == RNC_OK);
        srun(&s, 2000);
        CHECK(s.requests == 1 && s.responses == 1 && !s.timeouts);
        sfinish(&s);
    }
}
static void backpressure_test(void) {
    spair s;
    uint8_t nil = 0xc0, value[1003], out[sizeof(value)];
    rnc_service_event event;
    size_t n;
    sinit(&s, 10000, RNC_SERVICE_ALLOW_NONE);
    for (unsigned i = 0; i < RNC_SERVICE_EVENTS; i++) {
        CHECK(rnc_service_request(s.a, "/echo", &nil, 1, 1700000000 + i,
                                  s.links.now, 30000, s.id) == RNC_OK);
        swire(&s, s.links.a, s.links.b, s.a);
        swire(&s, s.links.b, s.links.a, s.b);
    }
    /* Retire the fixture's unanswered requests, keeping the receiver's full
     * event queue and the same authenticated link. */
    rnc_service_free(s.a);
    s.a = rnc_service_new(s.links.a, 10000, random_bytes, &s.links.ar);
    CHECK(s.a && rnc_service_register(s.b, "/echo", RNC_SERVICE_ALLOW_ALL,
                                     NULL, 0) == RNC_OK);
    value[0] = 0xc5;
    value[1] = (uint8_t)(1000 >> 8);
    value[2] = (uint8_t)1000;
    memset(value + 3, 0x42, sizeof(value) - 3);
    s.value = value;
    s.size = sizeof(value);
    CHECK(rnc_service_request(s.a, "/echo", value, sizeof(value), 1700000100,
                              s.links.now, 30000, s.id) == RNC_OK);
    for (unsigned i = 0; i < 100; i++) {
        CHECK(rnc_service_pump(s.a, s.links.now) == RNC_OK);
        CHECK(rnc_service_pump(s.b, s.links.now) == RNC_OK);
        swire(&s, s.links.a, s.links.b, s.a);
        swire(&s, s.links.b, s.links.a, s.b);
        s.links.now++;
    }
    CHECK(rnc_service_poll(s.b, &event, out, sizeof(out), &n) == RNC_OK &&
          event.type == RNC_SERVICE_DENIED);
    s.denied++;
    srun(&s, 1000);
    CHECK(s.requests == 1 && s.responses == 1 && s.denied == RNC_SERVICE_EVENTS &&
          !s.timeouts);
    sfinish(&s);
}
static void bulk_replay_test(void) {
    spair s;
    uint8_t value[1003];
    sinit(&s, 10000, RNC_SERVICE_ALLOW_ALL);
    value[0] = 0xc5;
    value[1] = (uint8_t)(1000 >> 8);
    value[2] = (uint8_t)1000;
    memset(value + 3, 0x42, sizeof(value) - 3);
    s.value = value;
    s.size = sizeof(value);
    CHECK(rnc_service_request(s.a, "/echo", value, sizeof(value), 1700000000,
                              s.links.now, 30000, s.id) == RNC_OK);
    srun(&s, 1000);
    CHECK(s.requests == 1 && s.responses == 1 && s.bulk_advertisement.context == 2);
    /* A completed Resource advertisement may be repeated to recover a lost
     * proof. Replaying the receipt must not acquire a new service RX binding. */
    CHECK(rnc_service_input(s.b, &s.bulk_advertisement, s.links.now) == RNC_OK);
    CHECK(rnc_service_pump(s.b, s.links.now) == RNC_OK);
    s.responses = 0;
    CHECK(rnc_service_request(s.a, "/echo", value, sizeof(value), 1700000001,
                              s.links.now, 30000, s.id) == RNC_OK);
    srun(&s, 1000);
    CHECK(s.requests == 2 && s.responses == 1 && !s.timeouts);
    sfinish(&s);
}
int main(int argc, char **argv) {
    CHECK(argc == 2);
    if (!strcmp(argv[1], "inline"))
        inline_test();
    else if (!strcmp(argv[1], "bulk"))
        bulk_test();
    else if (!strcmp(argv[1], "denial"))
        denial_test();
    else if (!strcmp(argv[1], "replay"))
        replay_test();
    else if (!strcmp(argv[1], "bounds"))
        bounds_test();
    else if (!strcmp(argv[1], "recovery"))
        recovery_test();
    else if (!strcmp(argv[1], "backpressure"))
        backpressure_test();
    else if (!strcmp(argv[1], "bulk_replay"))
        bulk_replay_test();
    else
        CHECK(0);
    return 0;
}
