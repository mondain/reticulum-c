#define _POSIX_C_SOURCE 200809L
/* Optional C harness. The unmodified external Leviculum library is the oracle. */
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <leviculum.h>
#include <openssl/rand.h>
#include <poll.h>
#include <pthread.h>
#include <reticulum_c/rnc_link.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static void fail(const char *file, int line, const char *expression);
#define CHECK(x)                                                                                             \
    do {                                                                                                     \
        if (!(x))                                                                                            \
            fail(__FILE__, __LINE__, #x);                                                                    \
    } while (0)
#define TX_CAPACITY (64u * RNC_HDLC_MAX)
static const char outgoing_text[] = "native-c-to-leviculum", incoming_text[] = "leviculum-to-native-c";
typedef struct peer {
    rnc_link *link;
    rnc_identity own, remote;
    rnc_hdlc framing;
    leviculum_t *node;
    lev_identity_t *identity;
    lev_link_t *oracle_link;
    pthread_t worker;
    atomic_int connected;
    int worker_started, connect_result, connect_stage, server, loss, started, active, identified;
    char connect_error[256];
    int messages, delivered, oracle_messages, oracle_identified, oracle_closed, reply_sent, closing;
    unsigned outgoing_packets, incoming_packets, proofs, dropped_data, dropped_proof;
    uint8_t destination[16], name[10], tx[TX_CAPACITY];
    size_t queued;
    int listener, fd;
    char directory[256];
} peer;
static peer *instance;
static uint64_t milliseconds(void) {
    struct timespec now;
    CHECK(!clock_gettime(CLOCK_MONOTONIC, &now));
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}
static void remove_tree(const char *path) {
    struct stat info;
    DIR *dir;
    struct dirent *entry;
    if (lstat(path, &info))
        return;
    if (!S_ISDIR(info.st_mode)) {
        (void)unlink(path);
        return;
    }
    dir = opendir(path);
    if (!dir)
        return;
    while ((entry = readdir(dir))) {
        char child[2048];
        int size;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        size = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        if (size > 0 && (size_t)size < sizeof(child))
            remove_tree(child);
    }
    closedir(dir);
    (void)rmdir(path);
}
static void cleanup(void) {
    peer *p = instance;
    if (!p)
        return;
    if (p->worker_started)
        (void)pthread_join(p->worker, NULL);
    if (p->oracle_link)
        lev_link_free(p->oracle_link);
    if (p->node) {
        (void)lev_stop(p->node);
        lev_free(p->node);
    }
    if (p->identity)
        lev_identity_free(p->identity);
    if (p->fd >= 0)
        close(p->fd);
    if (p->listener >= 0)
        close(p->listener);
    rnc_link_free(p->link);
    rnc_identity_clear(&p->own);
    rnc_identity_clear(&p->remote);
    if (*p->directory)
        remove_tree(p->directory);
    free(p);
    instance = NULL;
}
static void fail(const char *file, int line, const char *expression) {
    const char *detail = lev_last_error();
    fprintf(stderr, "%s:%d: %s; oracle: %s\n", file, line, expression,
            detail ? detail : "no thread-local error detail");
    if (instance && instance->connect_result != LEV_OK)
        fprintf(stderr, "connect stage=%d code=%d detail=%s\n", instance->connect_stage,
                instance->connect_result, instance->connect_error);
    /* C atexit runs after Rust TLS destruction; release the oracle explicitly. */
    cleanup();
    exit(1);
}
static rnc_result random_bytes(void *context, uint8_t *out, size_t size) {
    (void)context;
    return size <= 500 && RAND_priv_bytes(out, (int)size) == 1 ? RNC_OK : RNC_CRYPTO;
}
static void nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    CHECK(flags >= 0 && !fcntl(fd, F_SETFL, flags | O_NONBLOCK));
}
static void enqueue(peer *p, const rnc_packet *packet) {
    uint8_t raw[RNC_MTU];
    size_t size, framed;
    CHECK(rnc_packet_encode(packet, raw, sizeof(raw), &size) == RNC_OK);
    CHECK(rnc_hdlc_encode(raw, size, p->tx + p->queued, sizeof(p->tx) - p->queued, &framed) == RNC_OK);
    p->queued += framed;
}
static void drain(peer *p) {
    rnc_link_event event;
    while (rnc_link_poll(p->link, &event) == RNC_OK) {
        if (event.type == RNC_LINK_SEND) {
            if (event.packet.context == 14)
                ++p->outgoing_packets;
            enqueue(p, &event.packet);
        } else if (event.type == RNC_LINK_ACTIVE) {
            CHECK(!p->active);
            p->active = 1;
            if (!p->server)
                CHECK(rnc_link_identify(p->link, &p->own, milliseconds()) == RNC_OK);
        } else if (event.type == RNC_LINK_IDENTIFIED) {
            CHECK(!p->identified);
            p->identified = 1;
            CHECK(!memcmp(event.identity_hash, p->remote.hash, 16));
        } else if (event.type == RNC_LINK_MESSAGE) {
            CHECK(p->messages++ == 0 && event.message_type == 0 && event.sequence == 0 &&
                  event.size == sizeof(incoming_text) - 1u && !memcmp(event.data, incoming_text, event.size));
        } else if (event.type == RNC_LINK_DELIVERED) {
            CHECK(event.sequence == 0);
            ++p->delivered;
        } else if (event.type == RNC_LINK_CLOSED)
            CHECK(p->closing && event.reason == RNC_OK);
    }
}
static void receive_packet(peer *p, const uint8_t *raw, size_t size) {
    rnc_packet packet;
    CHECK(rnc_packet_decode(raw, size, &packet) == RNC_OK);
    if (!p->started && !p->server && (packet.flags & 15u) == RNC_ANNOUNCE) {
        rnc_announce announce;
        CHECK(rnc_announce_verify(&packet, &announce) == RNC_OK);
        if (memcmp(announce.name_hash, p->name, 10))
            return;
        CHECK(!memcmp(announce.identity.hash, p->remote.hash, 16));
        CHECK(rnc_link_open(p->link, &announce, milliseconds()) == RNC_OK);
        p->started = 1;
    } else if (!p->started && p->server && (packet.flags & 15u) == RNC_LINKREQUEST &&
               !memcmp(packet.destination, p->destination, 16)) {
        CHECK(rnc_link_accept(p->link, &p->own, p->destination, &packet, milliseconds()) == RNC_OK);
        p->started = 1;
    } else if (p->started && !p->closing) {
        uint8_t address[16];
        rnc_result result;
        CHECK(rnc_link_address(p->link, address) == RNC_OK);
        if (memcmp(address, packet.destination, 16))
            return;
        if ((packet.flags & 15u) == 15 && packet.context == 0) {
            ++p->proofs;
            if (p->loss && !p->dropped_proof++)
                return;
        }
        if ((packet.flags & 15u) == 12 && packet.context == 14) {
            ++p->incoming_packets;
            if (p->loss && !p->dropped_data++)
                return;
        }
        result = rnc_link_input(p->link, &packet, milliseconds());
        /* Unknown/duplicate proof hashes do not change protocol state. */
        if (result == RNC_AUTH && (packet.flags & 15u) == 15 && packet.context == 0)
            return;
        if (result != RNC_OK)
            fprintf(stderr, "RNC input flags=%u context=%u bytes=%zu result=%d\n", packet.flags,
                    packet.context, packet.data_size, result);
        CHECK(result == RNC_OK);
    }
    drain(p);
}
/* Only this worker performs blocking connect/identify. The main thread keeps
 * routing RNC packets and drains the external node's event queue. */
static void *connect_peer(void *context) {
    peer *p = context;
    uint8_t address[16];
    size_t size;
    p->connect_stage = 1;
    p->connect_result = lev_connect(p->node, p->destination, 5000, &p->oracle_link);
    if (p->connect_result == LEV_OK) {
        p->connect_stage = 2;
        p->connect_result = lev_link_id(p->oracle_link, address, sizeof(address), &size);
        if (p->connect_result == LEV_OK && size == 16) {
            p->connect_stage = 3;
            p->connect_result = lev_link_identify(p->node, address, p->identity, 5000);
        }
    }
    if (p->connect_result != LEV_OK) {
        const char *detail = lev_last_error();
        snprintf(p->connect_error, sizeof(p->connect_error), "%s", detail ? detail : "no detail");
    }
    atomic_store_explicit(&p->connected, 1, memory_order_release);
    return NULL;
}
static void oracle_events(peer *p) {
    lev_event_t *event = NULL;
    CHECK(lev_next_event(p->node, &event) == LEV_OK);
    while (event) {
        int type = lev_event_type(event);
        if (type == LEV_EVENT_LINK_ESTABLISHED || type == LEV_EVENT_LINK_MESSAGE ||
            type == LEV_EVENT_LINK_IDENTIFIED || type == LEV_EVENT_LINK_CLOSED) {
            uint8_t address[16], expected[16];
            size_t size;
            CHECK(lev_event_link_id(event, address, sizeof(address), &size) == LEV_OK && size == 16);
            CHECK(rnc_link_address(p->link, expected) == RNC_OK && !memcmp(address, expected, 16));
            if (type == LEV_EVENT_LINK_ESTABLISHED && !p->server)
                CHECK(lev_accept_link(p->node, address, 1000, &p->oracle_link) == LEV_OK);
            if (type == LEV_EVENT_LINK_MESSAGE) {
                uint8_t data[425];
                uint16_t message_type, sequence;
                CHECK(p->oracle_messages++ == 0);
                CHECK(lev_event_data(event, data, sizeof(data), &size) == LEV_OK &&
                      size == sizeof(outgoing_text) - 1u && !memcmp(data, outgoing_text, size));
                CHECK(lev_event_msgtype(event, &message_type) == LEV_OK && message_type == 0);
                CHECK(lev_event_sequence(event, &sequence) == LEV_OK && sequence == 0);
            } else if (type == LEV_EVENT_LINK_IDENTIFIED) {
                uint8_t hash[16];
                CHECK(!p->server && p->oracle_identified++ == 0);
                CHECK(lev_event_data(event, hash, sizeof(hash), &size) == LEV_OK && size == 16 &&
                      !memcmp(hash, p->own.hash, 16));
            } else if (type == LEV_EVENT_LINK_CLOSED) {
                int reason;
                CHECK(p->closing);
                CHECK(lev_event_close_reason(event, &reason) == LEV_OK);
                CHECK(reason == LEV_CLOSE_NORMAL || reason == LEV_CLOSE_PEER_CLOSED);
                ++p->oracle_closed;
            }
        }
        lev_event_free(event);
        event = NULL;
        CHECK(lev_next_event(p->node, &event) == LEV_OK);
    }
}
int main(int argc, char **argv) {
    peer *p;
    lev_builder_t *builder;
    lev_destination_t *destination = NULL;
    struct sockaddr_in address = {0};
    socklen_t address_size = sizeof(address);
    char endpoint[64];
    uint8_t public_key[64];
    size_t size;
    uint64_t deadline, announce_at = 0;
    int sent = 0;
    CHECK(argc == 2 &&
          (!strcmp(argv[1], "client") || !strcmp(argv[1], "server") || !strcmp(argv[1], "loss")));
    p = calloc(1, sizeof(*p));
    CHECK(p);
    instance = p;
    p->listener = p->fd = -1;
    atomic_init(&p->connected, 0);
    p->server = !strcmp(argv[1], "server");
    p->loss = !strcmp(argv[1], "loss");
    CHECK(rnc_identity_generate(&p->own, random_bytes, NULL) == RNC_OK);
    p->link = rnc_link_new(random_bytes, NULL);
    CHECK(p->link);
    CHECK(rnc_destination_hash("reticulum_c.interop.channel", &p->own, p->name, p->destination) == RNC_OK);
    CHECK(lev_init() == LEV_OK);
    p->identity = lev_identity_generate();
    CHECK(p->identity);
    CHECK(lev_identity_public_key(p->identity, public_key, sizeof(public_key), &size) == LEV_OK &&
          size == 64);
    CHECK(rnc_identity_from_public(&p->remote, public_key) == RNC_OK);
    strcpy(p->directory, "/tmp/reticulum-leviculum-XXXXXX");
    CHECK(mkdtemp(p->directory));
    p->listener = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(p->listener >= 0);
    nonblocking(p->listener);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(!bind(p->listener, (struct sockaddr *)&address, sizeof(address)) && !listen(p->listener, 1));
    CHECK(!getsockname(p->listener, (struct sockaddr *)&address, &address_size));
    snprintf(endpoint, sizeof(endpoint), "127.0.0.1:%u", (unsigned)ntohs(address.sin_port));
    builder = lev_builder_new();
    CHECK(builder);
    CHECK(lev_builder_identity(builder, p->identity) == LEV_OK &&
          lev_builder_storage_path(builder, p->directory) == LEV_OK);
    CHECK(lev_builder_enable_transport(builder, 0) == LEV_OK &&
          lev_builder_add_tcp_client(builder, endpoint) == LEV_OK);
    p->node = lev_builder_build(builder);
    lev_builder_free(builder);
    CHECK(p->node && lev_start(p->node) == LEV_OK);
    if (!p->server) {
        const char *aspects[] = {"interop", "channel"};
        destination =
            lev_destination_new(p->identity, LEV_DIRECTION_IN, LEV_DEST_SINGLE, "reticulum_c", aspects, 2);
        CHECK(destination);
        CHECK(lev_destination_set_proof_strategy(destination, LEV_PROOF_ALL) == LEV_OK);
        CHECK(lev_register_destination(p->node, destination) == LEV_OK);
        lev_destination_free(destination);
    }
    deadline = milliseconds() + 20000;
    while (milliseconds() < deadline) {
        uint64_t now = milliseconds();
        struct pollfd fds[3] = {{p->fd < 0 ? p->listener : -1, POLLIN, 0},
                                {p->fd, POLLIN | (p->queued ? POLLOUT : 0), 0},
                                {lev_event_fd(p->node), POLLIN, 0}};
        CHECK(poll(fds, 3, 20) >= 0);
        if (fds[0].revents & POLLIN) {
            p->fd = accept(p->listener, NULL, NULL);
            CHECK(p->fd >= 0);
            nonblocking(p->fd);
        }
        if (fds[1].revents & POLLOUT) {
            ssize_t n = send(p->fd, p->tx, p->queued, 0);
            if (n < 0)
                CHECK(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR);
            else {
                CHECK(n > 0);
                p->queued -= (size_t)n;
                memmove(p->tx, p->tx + n, p->queued);
            }
        }
        if (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            uint8_t input[2048], frame[RNC_MTU];
            ssize_t n = recv(p->fd, input, sizeof(input), 0), i;
            if (n < 0)
                CHECK(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR);
            else
                CHECK(n > 0);
            for (i = 0; i < n; ++i)
                if (rnc_hdlc_feed(&p->framing, input[i], frame, sizeof(frame), &size) == RNC_OK)
                    receive_packet(p, frame, size);
        }
        oracle_events(p);
        if (p->fd >= 0 && !p->started && now >= announce_at) {
            if (p->server) {
                rnc_packet announce;
                time_t seconds = time(NULL);
                CHECK(seconds >= 0);
                CHECK(rnc_announce_create(&p->own, "reticulum_c.interop.channel", NULL, 0, (uint64_t)seconds,
                                          random_bytes, NULL, &announce) == RNC_OK);
                enqueue(p, &announce);
            } else {
                uint8_t hash[16];
                CHECK(rnc_destination_hash("reticulum_c.interop.channel", &p->remote, p->name, hash) ==
                      RNC_OK);
                CHECK(lev_announce(p->node, hash, NULL, 0, 1000) == LEV_OK);
            }
            announce_at = now + 1000;
        }
        if (p->server && !p->worker_started && !atomic_load_explicit(&p->connected, memory_order_acquire) &&
            lev_has_path(p->node, p->destination) == 1) {
            CHECK(!pthread_create(&p->worker, NULL, connect_peer, p));
            p->worker_started = 1;
        }
        if (p->worker_started && atomic_load_explicit(&p->connected, memory_order_acquire)) {
            CHECK(!pthread_join(p->worker, NULL));
            p->worker_started = 0;
            CHECK(p->connect_result == LEV_OK);
        }
        if (p->active && p->identified && !sent) {
            CHECK(rnc_link_send(p->link, 0, outgoing_text, sizeof(outgoing_text) - 1u, milliseconds()) ==
                  RNC_OK);
            sent = 1;
            drain(p);
        }
        if (p->oracle_messages == 1 && !p->reply_sent &&
            (!p->server || atomic_load_explicit(&p->connected, memory_order_acquire)) && p->oracle_link) {
            int result =
                lev_link_try_send(p->oracle_link, (const uint8_t *)incoming_text, sizeof(incoming_text) - 1u);
            CHECK(result == LEV_OK || result == LEV_ERR_AGAIN);
            if (result == LEV_OK)
                p->reply_sent = 1;
        }
        CHECK(rnc_link_tick(p->link, milliseconds()) == RNC_OK);
        drain(p);
        if (!p->closing && p->messages == 1 && p->delivered == 1 && p->oracle_messages == 1 &&
            p->reply_sent && !p->queued) {
            CHECK(p->server || p->oracle_identified == 1);
            p->closing = 1;
            CHECK(rnc_link_close(p->link, milliseconds()) == RNC_OK);
            drain(p);
        }
        if (p->closing && !p->queued && p->oracle_closed == 1)
            break;
    }
    CHECK(milliseconds() < deadline && p->active && p->identified && p->messages == 1 && p->delivered == 1 &&
          p->oracle_closed == 1);
    if (p->loss)
        CHECK(p->outgoing_packets >= 2 && p->incoming_packets >= 2 && p->proofs >= 2);
    printf("Leviculum live %s: identity proofs, exact bidirectional Channel payloads, signed RNC delivery, "
           "single application delivery and graceful close passed\n",
           argv[1]);
    cleanup();
    return 0;
}
