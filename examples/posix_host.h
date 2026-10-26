#ifndef RNC_EXAMPLE_POSIX_HOST_H
#define RNC_EXAMPLE_POSIX_HOST_H
/* Shared host-only example utilities. Protocol state remains in reticulum_c. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <poll.h>
#include <reticulum_c/rnc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static rnc_result random_bytes(void *context, uint8_t *output, size_t size) {
    (void)context;
    return size <= 500 && RAND_priv_bytes(output, (int)size) == 1 ? RNC_OK : RNC_CRYPTO;
}
static void print_address(const uint8_t address[16]) {
    size_t i;
    for (i = 0; i < 16; ++i)
        printf("%02x", address[i]);
}
static int decode_address(const char *text, uint8_t address[16]) {
    size_t i;
    if (strlen(text) != 32)
        return -1;
    for (i = 0; i < 32; ++i) {
        unsigned value;
        char c = text[i];
        if (c >= '0' && c <= '9')
            value = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f')
            value = (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            value = (unsigned)(c - 'A' + 10);
        else
            return -1;
        if (!(i & 1u))
            address[i / 2u] = (uint8_t)(value << 4);
        else
            address[i / 2u] |= (uint8_t)value;
    }
    return 0;
}

static int load_identity(const char *path, rnc_identity *identity) {
    uint8_t key[65];
    size_t used = 0;
    int fd, created = 0, status = -1;
    struct stat info;
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0 && errno == ENOENT) {
        if (rnc_identity_generate(identity, random_bytes, NULL) != RNC_OK)
            return -1;
        fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0)
            return -1;
        created = 1;
        while (used < 64) {
            ssize_t n = write(fd, identity->private_key + used, 64u - used);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                goto done;
            used += (size_t)n;
        }
        if (fsync(fd))
            goto done;
        status = 0;
    } else {
        if (fd < 0 || fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_uid != geteuid() ||
            (info.st_mode & 077) || info.st_size != 64)
            goto done;
        while (used < sizeof(key)) {
            ssize_t n = read(fd, key + used, sizeof(key) - used);
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0)
                goto done;
            if (!n)
                break;
            used += (size_t)n;
        }
        if (used == 64 && rnc_identity_from_private(identity, key) == RNC_OK)
            status = 0;
    }
done:
    if (fd >= 0 && close(fd))
        status = -1;
    if (status && created)
        unlink(path);
    OPENSSL_cleanse(key, sizeof(key));
    return status;
}

static inline int listen_connection(unsigned port, const volatile sig_atomic_t *stop) {
    struct sockaddr_in address = {0};
    socklen_t size = sizeof(address);
    int listener = socket(AF_INET, SOCK_STREAM, 0), fd = -1, reuse = 1;
    if (listener < 0)
        return -1;
    (void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)port);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) || listen(listener, 1) ||
        getsockname(listener, (struct sockaddr *)&address, &size))
        goto done;
    printf("Listening 127.0.0.1:%u\n", (unsigned)ntohs(address.sin_port));
    fflush(stdout);
    while (!*stop) {
        struct pollfd pollfd = {listener, POLLIN, 0};
        if (poll(&pollfd, 1, 100) < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (pollfd.revents & POLLIN) {
            fd = accept(listener, NULL, NULL);
            if (fd >= 0 || errno != EINTR)
                break;
        }
    }
done:
    close(listener);
    return fd;
}
static int connect_to(const char *hostname, const char *port, const volatile sig_atomic_t *stop) {
    struct addrinfo hints = {0}, *addresses, *address;
    int fd = -1;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(hostname, port, &hints, &addresses))
        return -1;
    for (address = addresses; address && !*stop; address = address->ai_next) {
        fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fd < 0)
            continue;
        if (!connect(fd, address->ai_addr, address->ai_addrlen))
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(addresses);
    return fd;
}
#endif
