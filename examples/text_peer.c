#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#include "posix_host.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <poll.h>
#include <reticulum_c/rnc_link.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Native authenticated links carrying generic text Channel messages.
 * This host owns TCP, HDLC, persistent keys and the clock; reticulum_c owns
 * protocol state. Both peers identify before application data is admitted. */
#define TEXT_LIMIT RNC_CHANNEL_MDU
#define TX_SIZE (64u * RNC_HDLC_MAX)
typedef struct peer_host {
    rnc_identity own;
    rnc_announce peer;
    uint8_t destination[16], name[10], pin[16], tx[TX_SIZE];
    size_t queued;
    int pinned, discovered, listener, started, identified, closed;
    rnc_link *link;
    char lines[16][TEXT_LIMIT + 1u];
    size_t line_head, line_count;
    rnc_hdlc framing;
} peer_host;
static volatile sig_atomic_t stopped;
static void stop_handler(int signal_number) {
    (void)signal_number;
    stopped = 1;
}
static int queue_packet(peer_host *host, const rnc_packet *packet) {
    uint8_t raw[RNC_MTU];
    size_t size, framed;
    if (rnc_packet_encode(packet, raw, sizeof(raw), &size) != RNC_OK ||
        rnc_hdlc_encode(raw, size, host->tx + host->queued, sizeof(host->tx) - host->queued, &framed) !=
            RNC_OK) {
        fprintf(stderr, "Packet output queue exhausted or encode failed\n");
        return -1;
    }
    host->queued += framed;
    return 0;
}
static int announce(peer_host *host) {
    rnc_packet packet;
    time_t seconds = time(NULL);
    if (seconds < 0 || rnc_announce_create(&host->own, "reticulum_c.text.v1", NULL, 0, (uint64_t)seconds,
                                           random_bytes, NULL, &packet) != RNC_OK)
        return -1;
    return queue_packet(host, &packet);
}
static uint64_t milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now))
        abort();
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}
static int events(peer_host *host) {
    rnc_link_event event;
    while (rnc_link_poll(host->link, &event) == RNC_OK) {
        if (event.type == RNC_LINK_SEND) {
            if (queue_packet(host, &event.packet))
                return -1;
        } else if (event.type == RNC_LINK_ACTIVE) {
            puts("Link active");
            if (!host->listener && rnc_link_identify(host->link, &host->own, milliseconds()) != RNC_OK)
                return -1;
        } else if (event.type == RNC_LINK_IDENTIFIED) {
            /* Bind the initiator's identity proof to the selected announce. */
            if (!host->discovered || memcmp(event.identity_hash, host->peer.identity.hash, 16)) {
                fprintf(stderr, "Identity does not match the selected peer announce\n");
                return -1;
            }
            host->identified = 1;
            printf("Authenticated peer: ");
            print_address(event.identity_hash);
            putchar('\n');
        } else if (event.type == RNC_LINK_MESSAGE) {
            size_t i;
            if (!host->identified) {
                fprintf(stderr, "Unidentified peer sent application data\n");
                return -1;
            }
            if (event.message_type == 0x0101) {
                printf("Encrypted text: ");
                for (i = 0; i < event.size; ++i) {
                    unsigned char value = event.data[i];
                    putchar(value >= 32 && value != 127 ? value : '?');
                }
                putchar('\n');
            }
        } else if (event.type == RNC_LINK_DELIVERED)
            printf("Delivery confirmed: %u\n", (unsigned)event.sequence);
        else if (event.type == RNC_LINK_CLOSED) {
            host->closed = 1;
            if (event.reason != RNC_OK) {
                fprintf(stderr, "Link closed: %d\n", event.reason);
                return -1;
            }
        }
    }
    fflush(stdout);
    return 0;
}
static int flush_lines(peer_host *host) {
    while (host->identified && rnc_link_is_active(host->link) && host->line_count) {
        const char *line = host->lines[host->line_head];
        rnc_result result = rnc_link_send(host->link, 0x0101, line, strlen(line), milliseconds());
        if (result == RNC_AGAIN)
            return 0;
        if (result != RNC_OK)
            return -1;
        OPENSSL_cleanse(host->lines[host->line_head], sizeof(host->lines[0]));
        host->line_head = (host->line_head + 1u) % 16u;
        --host->line_count;
        if (events(host))
            return -1;
    }
    return 0;
}
static int handle_packet(peer_host *host, const uint8_t *data, size_t size) {
    rnc_packet packet;
    rnc_result result;
    if (rnc_packet_decode(data, size, &packet) != RNC_OK)
        return 0;
    if ((packet.flags & 0x0fu) == RNC_ANNOUNCE) {
        rnc_announce candidate;
        if (rnc_announce_verify(&packet, &candidate) != RNC_OK ||
            memcmp(candidate.name_hash, host->name, 10) ||
            !memcmp(candidate.destination, host->destination, 16) ||
            (host->pinned && memcmp(candidate.destination, host->pin, 16)) ||
            (host->discovered && memcmp(candidate.destination, host->peer.destination, 16)))
            return 0;
        host->peer = candidate;
        if (!host->discovered) {
            host->discovered = 1;
            printf("Peer destination: ");
            print_address(candidate.destination);
            putchar('\n');
        }
        if (!host->listener && !host->started) {
            if (rnc_link_open(host->link, &candidate, milliseconds()) != RNC_OK)
                return -1;
            host->started = 1;
        }
    } else if ((packet.flags & 0x0fu) == 2 && host->listener && !host->started && host->discovered) {
        result = rnc_link_accept(host->link, &host->own, host->destination, &packet, milliseconds());
        if (result == RNC_OK)
            host->started = 1;
        else if (result == RNC_CRYPTO)
            return -1;
    } else if (host->started) {
        result = rnc_link_input(host->link, &packet, milliseconds());
        if (result == RNC_CRYPTO || result == RNC_AGAIN)
            return -1;
    }
    return events(host);
}
static int send_line(peer_host *host, const char *line) {
    if (!strcmp(line, "/announce"))
        return announce(host);
    if (!*line)
        return 0;
    if (!host->discovered) {
        fprintf(stderr, "No discovered peer; wait for an announce\n");
        return 0;
    }
    if (host->line_count == 16) {
        fprintf(stderr, "Text output queue exhausted\n");
        return -1;
    }
    strcpy(host->lines[(host->line_head + host->line_count) % 16u], line);
    ++host->line_count;
    return flush_lines(host);
}

static int run_peer(peer_host *host, int fd) {
    char line[TEXT_LIMIT + 1u];
    size_t used = 0;
    int stdin_open = 1, too_long = 0, flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) || announce(host))
        return 1;
    uint64_t shutdown_deadline = 0;
    for (;;) {
        uint64_t now = milliseconds();
        if (stopped && !shutdown_deadline) {
            if (rnc_link_close(host->link, now) != RNC_OK || events(host))
                return 1;
            shutdown_deadline = now + 200;
        }
        if ((host->closed && !host->queued) || (shutdown_deadline && now >= shutdown_deadline))
            return 0;
        if (!host->closed && (rnc_link_tick(host->link, now) != RNC_OK || events(host) || flush_lines(host)))
            return 1;
        struct pollfd fds[2] = {{fd, POLLIN, 0}, {stdin_open ? STDIN_FILENO : -1, POLLIN, 0}};
        if (host->queued)
            fds[0].events |= POLLOUT;
        if (poll(fds, 2, 100) < 0) {
            if (errno == EINTR)
                continue;
            return 1;
        }
        if (fds[0].revents & POLLOUT) {
            ssize_t n = send(fd, host->tx, host->queued, 0);
            if (n < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
                return 1;
            if (!n)
                return 1;
            if (n > 0) {
                host->queued -= (size_t)n;
                memmove(host->tx, host->tx + n, host->queued);
            }
        }
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            uint8_t input[2048], frame[RNC_MTU];
            ssize_t n = recv(fd, input, sizeof(input), 0), i;
            if (!n)
                return 0;
            if (n < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
                return 1;
            for (i = 0; i < n; ++i) {
                size_t size;
                if (rnc_hdlc_feed(&host->framing, input[i], frame, sizeof(frame), &size) == RNC_OK &&
                    handle_packet(host, frame, size))
                    return 1;
            }
        }
        if (fds[1].revents & (POLLIN | POLLHUP)) {
            char input[512];
            ssize_t n = read(STDIN_FILENO, input, sizeof(input)), i;
            if (n < 0 && errno != EINTR)
                return 1;
            if (!n) {
                stdin_open = 0;
                if (too_long)
                    fprintf(stderr, "Line too long (max %u bytes)\n", (unsigned)TEXT_LIMIT);
                else if (used) {
                    line[used] = 0;
                    if (send_line(host, line))
                        return 1;
                }
            }
            for (i = 0; i < n; ++i) {
                if (input[i] == '\n') {
                    if (too_long)
                        fprintf(stderr, "Line too long (max %u bytes)\n", (unsigned)TEXT_LIMIT);
                    else {
                        line[used] = 0;
                        if (send_line(host, line))
                            return 1;
                    }
                    used = 0;
                    too_long = 0;
                } else if (input[i] != '\r') {
                    if (used == TEXT_LIMIT || !input[i])
                        too_long = 1;
                    else
                        line[used++] = input[i];
                }
            }
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    peer_host *host;
    struct sigaction action = {0};
    int listener, fd, status = 1, pin_index;
    unsigned long port;
    char *end;
    const char *number, *key_file, *p;
    if (argc < 2)
        goto usage;
    listener = !strcmp(argv[1], "listen");
    if ((!listener && strcmp(argv[1], "connect")) || (listener && argc != 4 && argc != 5) ||
        (!listener && argc != 5 && argc != 6))
        goto usage;
    number = argv[listener ? 2 : 3];
    key_file = argv[listener ? 3 : 4];
    pin_index = listener ? 4 : 5;
    if (!*number)
        goto usage;
    for (p = number; *p; ++p)
        if (*p < '0' || *p > '9')
            goto usage;
    errno = 0;
    port = strtoul(number, &end, 10);
    if (errno || *end || port > 65535 || (!listener && !port))
        goto usage;
    host = calloc(1, sizeof(*host));
    if (!host)
        return 1;
    if (argc > pin_index) {
        if (decode_address(argv[pin_index], host->pin))
            goto done;
        host->pinned = 1;
    }
    if (load_identity(key_file, &host->own)) {
        fprintf(stderr, "Identity file must be a regular, owned, private 64-byte key (or a new path)\n");
        goto done;
    }
    if (rnc_destination_hash("reticulum_c.text.v1", &host->own, host->name, host->destination) != RNC_OK)
        goto done;
    printf("Destination: ");
    print_address(host->destination);
    putchar('\n');
    fflush(stdout);
    action.sa_handler = stop_handler;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &action, NULL);
    fd = listener ? listen_connection((unsigned)port, &stopped) : connect_to(argv[2], number, &stopped);
    if (fd < 0) {
        if (stopped)
            status = 0;
        else
            perror("Reticulum TCP interface");
        goto done;
    }
    host->listener = listener;
    host->link = rnc_link_new(random_bytes, NULL);
    if (!host->link) {
        close(fd);
        goto done;
    }
    status = run_peer(host, fd);
    close(fd);
done:
    rnc_link_free(host->link);
    rnc_identity_clear(&host->own);
    OPENSSL_cleanse(host, sizeof(*host));
    free(host);
    return status;
usage:
    fprintf(stderr, "Usage: %s listen PORT KEYFILE [DEST_HEX] | connect HOST PORT KEYFILE [DEST_HEX]\n",
            argv[0]);
    return 1;
}
