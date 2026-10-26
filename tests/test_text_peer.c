#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

typedef struct child {
    pid_t pid;
    int input, output;
    char log[16384];
    size_t used;
} child;
static child children[4];
static char directory[128], first_key[180], second_key[180];
#define CHECK(x)                                                                                             \
    do {                                                                                                     \
        if (!(x)) {                                                                                          \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                                          \
            exit(1);                                                                                         \
        }                                                                                                    \
    } while (0)
static int success;
static uint64_t milliseconds(void) {
    struct timespec now;
    CHECK(!clock_gettime(CLOCK_MONOTONIC, &now));
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}
static void cleanup(void) {
    size_t i;
    for (i = 0; i < 4; ++i) {
        child *p = &children[i];
        if (!success && p->used)
            fprintf(stderr, "child log:\n%s\n", p->log);
        if (p->pid > 0) {
            int status;
            unsigned tries;
            kill(p->pid, SIGTERM);
            for (tries = 0; tries < 100; ++tries) {
                struct timespec delay = {0, 10000000};
                if (waitpid(p->pid, &status, WNOHANG) == p->pid)
                    break;
                nanosleep(&delay, NULL);
            }
            if (tries == 100) {
                kill(p->pid, SIGKILL);
                waitpid(p->pid, &status, 0);
            }
        }
        if (p->input >= 0)
            close(p->input);
        if (p->output >= 0)
            close(p->output);
    }
    unlink(first_key);
    unlink(second_key);
    rmdir(directory);
}
static void launch(child *p, char *const args[]) {
    int input[2], output[2];
    memset(p, 0, sizeof(*p));
    CHECK(!pipe(input) && !pipe(output));
    CHECK(!fcntl(input[0], F_SETFD, FD_CLOEXEC) && !fcntl(input[1], F_SETFD, FD_CLOEXEC));
    CHECK(!fcntl(output[0], F_SETFD, FD_CLOEXEC) && !fcntl(output[1], F_SETFD, FD_CLOEXEC));
    p->pid = fork();
    CHECK(p->pid >= 0);
    if (!p->pid) {
        if (dup2(input[0], STDIN_FILENO) < 0 || dup2(output[1], STDOUT_FILENO) < 0 ||
            dup2(output[1], STDERR_FILENO) < 0)
            _exit(126);
        execv(args[0], args);
        _exit(127);
    }
    close(input[0]);
    close(output[1]);
    p->input = input[1];
    p->output = output[0];
}
static void wait_text(child *p, const char *text) {
    uint64_t deadline = milliseconds() + 5000;
    while (!strstr(p->log, text)) {
        struct pollfd fd = {p->output, POLLIN, 0};
        ssize_t n;
        CHECK(milliseconds() < deadline);
        CHECK(poll(&fd, 1, 100) >= 0);
        if (!(fd.revents & (POLLIN | POLLHUP)))
            continue;
        CHECK(p->used + 1u < sizeof(p->log));
        n = read(p->output, p->log + p->used, sizeof(p->log) - p->used - 1u);
        CHECK(n > 0);
        p->used += (size_t)n;
        p->log[p->used] = 0;
    }
}
static void send_text(child *p, const char *text) {
    size_t offset = 0, size = strlen(text);
    while (offset < size) {
        ssize_t n = write(p->input, text + offset, size - offset);
        if (n < 0 && errno == EINTR)
            continue;
        CHECK(n > 0);
        offset += (size_t)n;
    }
}
static void finish(child *p, int code, int stop) {
    uint64_t deadline = milliseconds() + 4000;
    int status;
    if (stop)
        CHECK(!kill(p->pid, SIGTERM));
    for (;;) {
        struct timespec delay = {0, 10000000};
        pid_t result = waitpid(p->pid, &status, WNOHANG);
        if (result == p->pid)
            break;
        CHECK(result == 0 && milliseconds() < deadline);
        nanosleep(&delay, NULL);
    }
    p->pid = 0;
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == code);
    if (p->input >= 0)
        close(p->input);
    close(p->output);
    p->input = p->output = -1;
}
int main(int argc, char **argv) {
    child *listener = &children[0], *connector = &children[1];
    char port[12], destination[33], initial_destination[33], oversized[512];
    char *listen_args[] = {argv[1], "listen", "0", first_key, NULL};
    char *connect_args[] = {argv[1], "connect", "127.0.0.1", port, second_key, NULL, NULL};
    struct stat info;
    unsigned number;
    size_t i;
    const char *found;
    CHECK(argc == 2 || (argc == 3 && !strcmp(argv[2], "linked")));
    for (i = 0; i < 4; ++i)
        children[i].input = children[i].output = -1;
    strcpy(directory, "/tmp/reticulum-c-peer-XXXXXX");
    CHECK(mkdtemp(directory));
    snprintf(first_key, sizeof(first_key), "%s/listener.key", directory);
    snprintf(second_key, sizeof(second_key), "%s/connector.key", directory);
    atexit(cleanup);
    launch(listener, listen_args);
    wait_text(listener, "Listening 127.0.0.1:");
    found = strstr(listener->log, "Listening 127.0.0.1:");
    CHECK(sscanf(found, "Listening 127.0.0.1:%u", &number) == 1 && number);
    snprintf(port, sizeof(port), "%u", number);
    found = strstr(listener->log, "Destination: ");
    CHECK(found);
    memcpy(destination, found + 13, 32);
    destination[32] = 0;
    memcpy(initial_destination, destination, sizeof(destination));
    connect_args[5] = destination; /* Pin the intended recipient. */
    launch(connector, connect_args);
    wait_text(listener, "Peer destination:");
    wait_text(connector, "Peer destination:");
    if (argc == 3) {
        wait_text(listener, "Link active");
        wait_text(connector, "Link active");
        wait_text(listener, "Authenticated peer:");
        wait_text(connector, "Authenticated peer:");
    }
    send_text(connector, "hello-native-reticulum\n");
    wait_text(listener, "Encrypted text: hello-native-reticulum");
    send_text(listener, "hello-from-listener\n");
    wait_text(connector, "Encrypted text: hello-from-listener");
    if (argc == 3) {
        wait_text(listener, "Delivery confirmed");
        wait_text(connector, "Delivery confirmed");
    }
    if (argc == 3) {
        /* More queued lines than the protocol's two-message TX window. */
        send_text(connector, "burst-0\nburst-1\nburst-2\nburst-3\nburst-4\nburst-5\n");
        wait_text(listener, "Encrypted text: burst-5");
        for (i = 0; i < 6; ++i) {
            char expected[48];
            snprintf(expected, sizeof(expected), "Encrypted text: burst-%u", (unsigned)i);
            CHECK(strstr(listener->log, expected));
        }
    }
    memset(oversized, 'x', sizeof(oversized));
    oversized[510] = '\n';
    oversized[511] = 0;
    send_text(connector, oversized);
    wait_text(connector, "Line too long");
    send_text(connector, "after-overflow\n");
    wait_text(listener, "Encrypted text: after-overflow");
    CHECK(!strstr(listener->log, "xxxxxxxx"));
    send_text(connector, "final-unterminated-line");
    CHECK(!close(connector->input));
    connector->input = -1;
    wait_text(listener, "Encrypted text: final-unterminated-line");
    send_text(listener, "after-stdin-eof\n");
    wait_text(connector, "Encrypted text: after-stdin-eof");
    CHECK(!stat(first_key, &info) && info.st_size == 64 && !(info.st_mode & 077));
    CHECK(!stat(second_key, &info) && info.st_size == 64 && !(info.st_mode & 077));
    finish(connector, 0, 1);
    finish(listener, 0, 0);
    /* Identity persistence and EOF do not depend on an interactive terminal. */
    launch(listener, listen_args);
    wait_text(listener, "Listening 127.0.0.1:");
    found = strstr(listener->log, "Destination: ");
    CHECK(found);
    CHECK(!memcmp(found + 13, initial_destination, 32));
    found = strstr(listener->log, "Listening 127.0.0.1:");
    CHECK(sscanf(found, "Listening 127.0.0.1:%u", &number) == 1 && number);
    snprintf(port, sizeof(port), "%u", number);
    connect_args[5] = "00000000000000000000000000000000";
    launch(connector, connect_args);
    wait_text(listener, "Peer destination:");
    send_text(connector, "wrong-pin-command\n");
    wait_text(connector, "No discovered peer");
    CHECK(!strstr(connector->log, "Peer destination:"));
    oversized[510] = 'x';
    send_text(connector, oversized);
    CHECK(!close(connector->input));
    connector->input = -1;
    wait_text(connector, "Line too long");
    finish(connector, 0, 1);
    finish(listener, 0, 0);
    CHECK(!chmod(first_key, 0644));
    launch(listener, listen_args);
    finish(listener, 1, 0);
    CHECK(!stat(first_key, &info) && info.st_size == 64);
    CHECK(!unlink(first_key) && !mkfifo(first_key, 0600));
    launch(listener, listen_args);
    finish(listener, 1, 0);
    success = 1;
    puts("native Reticulum C peer: encrypted bidirectional text, destination pin, oversized line rejection, "
         "persistent private keys and shutdown passed");
    return 0;
}
