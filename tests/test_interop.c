#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
/* C protocol peer/process driver. Only the external, unmodified oracle is Python. */
#include <reticulum_c/rnc_link.h>
#ifdef RNC_ROUTED_INTEROP
#include <reticulum_c/rnc_node.h>
#endif
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
#define TX_CAPACITY (64u*RNC_HDLC_MAX)
typedef struct host {
    rnc_link *link;
    rnc_identity own;
    rnc_hdlc hdlc;
    uint8_t destination[16], name[10], tx[TX_CAPACITY];
    size_t queued;
    int server, loss, large, started, active, messages, delivered, closed;
    unsigned sent_data, received_data, received_proofs, dropped_data, dropped_proof;
} host;
static pid_t oracle;
static int oracle_input = -1, oracle_output = -1, transport = -1, listener = -1, success;
static char directory[256], oracle_log[32768];
static size_t log_used;
static uint64_t milliseconds(void) {
    struct timespec now; CHECK(!clock_gettime(CLOCK_MONOTONIC, &now));
    return (uint64_t)now.tv_sec*1000u+(uint64_t)now.tv_nsec/1000000u;
}
static void remove_tree(const char *path) {
    struct stat info; DIR *dir; struct dirent *entry;
    if (lstat(path, &info)) return;
    if (!S_ISDIR(info.st_mode)) { (void)unlink(path); return; }
    dir = opendir(path); if (!dir) return;
    while ((entry = readdir(dir))) {
        char child[2048]; int size;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        size = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        if (size > 0 && (size_t)size < sizeof(child)) remove_tree(child);
    }
    closedir(dir); (void)rmdir(path);
}
static void cleanup(void) {
    if (!success) fprintf(stderr, "Unmodified RNS oracle log:\n%s\n", oracle_log);
    if (oracle > 0) {
        int status; unsigned i; (void)kill(oracle, SIGTERM);
        for (i = 0; i < 100; ++i) {
            struct timespec delay = {0, 10000000};
            if (waitpid(oracle, &status, WNOHANG) == oracle) break;
            nanosleep(&delay, NULL);
        }
        if (i == 100) { (void)kill(oracle, SIGKILL); (void)waitpid(oracle, &status, 0); }
    }
    if (oracle_input >= 0) close(oracle_input);
    if (oracle_output >= 0) close(oracle_output);
    if (transport >= 0) close(transport);
    if (listener >= 0) close(listener);
    if (*directory) remove_tree(directory);
}
static rnc_result random_bytes(void *context, uint8_t *output, size_t size) {
    (void)context;
    return size <= RNC_MTU && RAND_priv_bytes(output, (int)size) == 1 ? RNC_OK : RNC_CRYPTO;
}
static void nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    CHECK(flags >= 0 && !fcntl(fd, F_SETFL, flags|O_NONBLOCK));
}
static void send_stdin(const char *text) {
    size_t done = 0, size = strlen(text);
    while (done < size) {
        ssize_t n = write(oracle_input, text+done, size-done);
        if (n < 0 && errno == EINTR) continue;
        CHECK(n > 0); done += (size_t)n;
    }
}
static void launch(const char *python, const char *example, const char *destination) {
    int input[2], output[2];
    CHECK(!pipe(input) && !pipe(output));
    CHECK(!fcntl(input[0], F_SETFD, FD_CLOEXEC) && !fcntl(input[1], F_SETFD, FD_CLOEXEC));
    CHECK(!fcntl(output[0], F_SETFD, FD_CLOEXEC) && !fcntl(output[1], F_SETFD, FD_CLOEXEC));
    oracle = fork(); CHECK(oracle >= 0);
    if (!oracle) {
        if (dup2(input[0], STDIN_FILENO) < 0 || dup2(output[1], STDOUT_FILENO) < 0 ||
            dup2(output[1], STDERR_FILENO) < 0) _exit(126);
        if (destination) execl(python, python, "-u", example, "--config", directory, destination, (char *)NULL);
        else execl(python, python, "-u", example, "--config", directory, "--server", (char *)NULL);
        _exit(127);
    }
    close(input[0]); close(output[1]); oracle_input = input[1]; oracle_output = output[0];
}
static void wire_enqueue(host *h, const rnc_packet *packet) {
    uint8_t raw[RNC_MAX_MTU]; size_t size, framed;
    CHECK(rnc_packet_encode(packet, raw, sizeof(raw), &size) == RNC_OK);
    CHECK(rnc_hdlc_encode(raw, size, h->tx+h->queued, sizeof(h->tx)-h->queued, &framed) == RNC_OK);
    h->queued += framed;
}
#ifdef RNC_ROUTED_INTEROP
static rnc_node *routers[2];
static rnc_identity router_ids[2];
static void receive_endpoint(host *h,const uint8_t *raw,size_t size);
static void enqueue(host *h,const rnc_packet *packet) {
    rnc_packet p=*packet;(void)h;
    if (((p.flags>>2)&3u)==RNC_SINGLE&&(p.flags&3u)!=RNC_ANNOUNCE) {
        p.flags=(uint8_t)((p.flags&0x2fu)|0x50u);memcpy(p.transport_id,router_ids[0].hash,16);
    }
    CHECK(rnc_node_input(routers[0],1,&p,(uint64_t)time(NULL),milliseconds())==RNC_OK);
}
static void receive_packet(host *h,const uint8_t *raw,size_t size) {
    rnc_packet p;(void)h;CHECK(rnc_packet_decode(raw,size,&p)==RNC_OK);
    CHECK(rnc_node_input(routers[1],2,&p,(uint64_t)time(NULL),milliseconds())==RNC_OK);
}
static void pump_routes(host *h) {
    unsigned pass,i;int progressed;
    for(pass=0;pass<64;pass++) {
        progressed=0;
        for(i=0;i<2;i++) {
            rnc_node_event e;
            CHECK(rnc_node_tick(routers[i],(uint64_t)time(NULL),milliseconds())==RNC_OK);
            while(rnc_node_poll(routers[i],&e)==RNC_OK) if(e.type==RNC_NODE_SEND) {
                progressed=1;
                if(i==0&&e.interface_id==1) {
                    uint8_t raw[RNC_MAX_MTU];size_t size;CHECK(rnc_packet_encode(&e.packet,raw,sizeof(raw),&size)==RNC_OK);receive_endpoint(h,raw,size);
                } else if(i==1&&e.interface_id==2) wire_enqueue(h,&e.packet);
                else CHECK(rnc_node_input(routers[1-i],i?2:1,&e.packet,(uint64_t)time(NULL),milliseconds())==RNC_OK);
            }
        }
        if(!progressed)break;
    }
}
#else
#define enqueue wire_enqueue
#endif
static const char *large_message(void) {
    static char message[1025];size_t i;
    if(!message[0]){for(i=0;i<sizeof(message)-1;i++)message[i]=(char)('a'+i%26);message[sizeof(message)-1]=0;}
    return message;
}
static const char *large_reply(void) {
    static char reply[1100];CHECK(snprintf(reply,sizeof(reply),"I received \"%s\" over the link",large_message())>0);return reply;
}
/* Channel.py uses a two-element MessagePack array: (str, datetime). Nil is a
 * valid second field for its unpacker. Inspect only the echoed first field. */
static void send_message(host *h, const char *text) {
    uint8_t data[RNC_CHANNEL_MAX_MDU]; size_t size=strlen(text),start;
    CHECK(size<65536&&size+5<=rnc_link_channel_mdu(h->link));data[0]=0x92;
    if(size<256){data[1]=0xd9;data[2]=(uint8_t)size;start=3;}
    else{data[1]=0xda;data[2]=(uint8_t)(size>>8);data[3]=(uint8_t)size;start=4;}
    memcpy(data+start,text,size);data[start+size]=0xc0;
    CHECK(rnc_link_send(h->link,0x0101,data,start+size+1,milliseconds())==RNC_OK);
}
static void check_message(const rnc_link_event *event, const char *expected) {
    size_t start = 2, length;
    CHECK(event->message_type == 0x0101 && event->size >= 3 && event->data[0] == 0x92);
    if ((event->data[1] & 0xe0) == 0xa0) length = event->data[1] & 0x1f;
    else if(event->data[1]==0xda) { CHECK(event->size>=5);length=(size_t)event->data[2]*256+event->data[3];start=4; }
    else { CHECK(event->data[1] == 0xd9 && event->size >= 4); length = event->data[2]; start = 3; }
    CHECK(start+length < event->size && strlen(expected) == length && !memcmp(event->data+start, expected, length));
}
static void drain(host *h) {
    rnc_link_event event;
    while (rnc_link_poll(h->link, &event) == RNC_OK) {
        if (event.type == RNC_LINK_SEND) {
            if (event.packet.context == 14) ++h->sent_data;
            enqueue(h, &event.packet);
        } else if (event.type == RNC_LINK_ACTIVE) {
            CHECK(!h->active); h->active = 1;
            if (!h->server) {
                rnc_identity remote;
                CHECK(rnc_link_remote_identity(h->link, &remote) == RNC_OK && !remote.has_private);
                CHECK(rnc_link_identify(h->link, &h->own, milliseconds()) == RNC_OK);
                if(h->large)CHECK(rnc_link_mtu(h->link)==4096);
                send_message(h, h->large?large_message():"native-c-to-rns");
            }
        } else if (event.type == RNC_LINK_IDENTIFIED) CHECK(!h->server);
        else if (event.type == RNC_LINK_MESSAGE) {
            CHECK(h->messages++ == 0); /* The retry case must not redeliver. */
            if (h->server) {
                check_message(&event, "rns-to-native-c");
                send_message(h, "I received rns-to-native-c in C");
            } else check_message(&event, h->large?large_reply():"I received \"native-c-to-rns\" over the link");
        } else if (event.type == RNC_LINK_DELIVERED) { CHECK(event.sequence == 0); ++h->delivered; }
        else if (event.type == RNC_LINK_CLOSED) CHECK(h->closed && event.reason == RNC_OK);
    }
}
#ifdef RNC_ROUTED_INTEROP
static void receive_endpoint(host *h, const uint8_t *raw, size_t size) {
#else
static void receive_packet(host *h, const uint8_t *raw, size_t size) {
#endif
    rnc_packet packet; rnc_result result;
    CHECK(rnc_packet_decode(raw, size, &packet) == RNC_OK);
    if (!h->started && !h->server && (packet.flags & 15u) == RNC_ANNOUNCE) {
        rnc_announce announce;
        CHECK(rnc_announce_verify(&packet, &announce) == RNC_OK);
        if (memcmp(announce.name_hash, h->name, 10)) return;
        CHECK(rnc_link_open(h->link, &announce, milliseconds()) == RNC_OK); h->started = 1;
    } else if (!h->started && h->server && (packet.flags & 15u) == 2 && !memcmp(packet.destination, h->destination, 16)) {
        CHECK(rnc_link_accept(h->link, &h->own, h->destination, &packet, milliseconds()) == RNC_OK); h->started = 1;
    } else if (h->started) {
        uint8_t address[16];
        CHECK(rnc_link_address(h->link, address) == RNC_OK);
        if (memcmp(address, packet.destination, 16)) return; /* Discovery/path traffic. */
        if ((packet.flags & 15u) == 15 && packet.context == 0) {
            ++h->received_proofs;
            if (h->loss && !h->dropped_proof++) return;
        }
        if ((packet.flags & 15u) == 12 && packet.context == 14) {
            ++h->received_data;
            if (h->loss && !h->dropped_data++) return;
        }
        result = rnc_link_input(h->link, &packet, milliseconds());
        if (result != RNC_OK) fprintf(stderr, "input flags=%u context=%u bytes=%zu result=%d\n", packet.flags, packet.context, packet.data_size, result);
        CHECK(result == RNC_OK);
    }
    drain(h);
}
int main(int argc, char **argv) {
    host *h; struct sockaddr_in address = {0}; socklen_t address_size = sizeof(address);
    char path[512], destination[33]; FILE *config; uint64_t deadline, announce_at = 0;
    int announced = 0, requested = 0, typed = 0; unsigned i;
    CHECK(argc == 4);
    CHECK(!strcmp(argv[3], "client") || !strcmp(argv[3], "server") || !strcmp(argv[3], "loss") || !strcmp(argv[3], "large"));
    atexit(cleanup); signal(SIGPIPE, SIG_IGN);
    h = calloc(1, sizeof(*h)); CHECK(h);
    h->server = !strcmp(argv[3], "server"); h->loss = !strcmp(argv[3], "loss");h->large=!strcmp(argv[3],"large");
    CHECK(rnc_identity_generate(&h->own, random_bytes, NULL) == RNC_OK);
    CHECK(rnc_destination_hash("example_utilities.channelexample", &h->own, h->name, h->destination) == RNC_OK);
    for (i = 0; i < 16; ++i) snprintf(destination+i*2u, 3, "%02x", h->destination[i]);
    h->link = rnc_link_new(random_bytes, NULL); CHECK(h->link);
#ifdef RNC_ROUTED_INTEROP
    for(i=0;i<2;i++) {
        CHECK(rnc_identity_generate(&router_ids[i],random_bytes,NULL)==RNC_OK);
        routers[i]=rnc_node_new(&router_ids[i],1,random_bytes,NULL);CHECK(routers[i]);
        CHECK(rnc_node_add_interface(routers[i],1,10000000)==RNC_OK);
        CHECK(rnc_node_add_interface(routers[i],2,10000000)==RNC_OK);
        if(h->large){CHECK(rnc_node_interface_mtu(routers[i],1,4096)==RNC_OK);CHECK(rnc_node_interface_mtu(routers[i],2,4096)==RNC_OK);}
    }
#endif
    if(h->large)CHECK(rnc_link_configure_mtu(h->link,4096)==RNC_OK);
    strcpy(directory, "/tmp/reticulum-live-XXXXXX"); CHECK(mkdtemp(directory));
    listener = socket(AF_INET, SOCK_STREAM, 0); CHECK(listener >= 0);
    CHECK(!fcntl(listener, F_SETFD, FD_CLOEXEC)); nonblocking(listener);
    address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(!bind(listener, (struct sockaddr *)&address, sizeof(address)) && !listen(listener, 1));
    CHECK(!getsockname(listener, (struct sockaddr *)&address, &address_size));
    CHECK(snprintf(path, sizeof(path), "%s/config", directory) > 0);
    config = fopen(path, "w"); CHECK(config);
    CHECK(fprintf(config, "[reticulum]\n enable_transport = No\n share_instance = No\n panic_on_interface_error = Yes\n[logging]\n loglevel = 6\n[interfaces]\n [[Native C]]\n type = TCPClientInterface\n enabled = Yes\n target_host = 127.0.0.1\n target_port = %u\n", (unsigned)ntohs(address.sin_port)) > 0);
    CHECK(!fclose(config));
    launch(argv[1], argv[2], h->server ? destination : NULL);
    deadline = milliseconds()+20000;
    while (milliseconds() < deadline) {
        struct pollfd fds[3] = {{transport >= 0 ? -1 : listener, POLLIN, 0},
            {transport, POLLIN | (h->queued ? POLLOUT : 0), 0}, {oracle_output, POLLIN, 0}};
        uint64_t now = milliseconds();
        CHECK(poll(fds, 3, 20) >= 0);
        if (fds[0].revents & POLLIN) {
            transport = accept(listener, NULL, NULL); CHECK(transport >= 0); nonblocking(transport);
        }
        if (fds[2].revents & (POLLIN|POLLHUP)) {
            ssize_t n; CHECK(log_used+1u < sizeof(oracle_log));
            n = read(oracle_output, oracle_log+log_used, sizeof(oracle_log)-log_used-1u);
            CHECK(n > 0); log_used += (size_t)n; oracle_log[log_used] = 0;
        }
        if (fds[1].revents & POLLOUT) {
            ssize_t n = send(transport, h->tx, h->queued, 0);
            if (n < 0) CHECK(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK);
            else { CHECK(n > 0); h->queued -= (size_t)n; memmove(h->tx, h->tx+n, h->queued); }
        }
        if (fds[1].revents & (POLLIN|POLLHUP|POLLERR)) {
            uint8_t bytes[2048], frame[RNC_MAX_MTU]; ssize_t n = recv(transport, bytes, sizeof(bytes), 0), offset;
            if (n < 0) CHECK(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK);
            else CHECK(n > 0);
            for (offset = 0; offset < n; ++offset) {
                size_t size;
                if (rnc_hdlc_feed(&h->hdlc, bytes[offset], frame, sizeof(frame), &size) == RNC_OK) receive_packet(h, frame, size);
            }
        }
        if (transport >= 0 && !h->server && !requested && strstr(oracle_log, "running, waiting for a connection")) {
            send_stdin("\n"); requested = 1;
        }
        /* RNS starts its TCP read thread before configuring IFAC fields.
         * Socket acceptance alone is too early to send the first announce. */
        if (transport >= 0 && h->server && !h->started && now >= announce_at &&
            strstr(oracle_log, "System interfaces are ready")) {
            rnc_packet packet; time_t seconds = time(NULL); CHECK(seconds >= 0);
            CHECK(rnc_announce_create(&h->own, "example_utilities.channelexample", NULL, 0,
                (uint64_t)seconds, random_bytes, NULL, &packet) == RNC_OK);
            enqueue(h, &packet); announce_at = now+1000; announced = 1;
        }
        if (h->server && !typed && strstr(oracle_log, "Link established with server")) {
            send_stdin("rns-to-native-c\n"); typed = 1;
        }
        CHECK(rnc_link_tick(h->link, milliseconds()) == RNC_OK); drain(h);
#ifdef RNC_ROUTED_INTEROP
        pump_routes(h);
#endif
        if (!h->closed && h->messages == 1 && h->delivered == 1 && !h->queued &&
            strstr(oracle_log, h->server ? "Received data on the link: I received rns-to-native-c in C" : (h->large?large_message():"Received data on the link: native-c-to-rns"))) {
            h->closed = 1;
            CHECK(rnc_link_close(h->link, milliseconds()) == RNC_OK); drain(h);
        }
        if (h->closed && !h->queued && strstr(oracle_log, h->server ? "The link was closed by the server" : "Client disconnected")) break;
    }
    CHECK(milliseconds() < deadline && h->active && h->messages == 1 && h->delivered == 1 && h->closed);
    CHECK(!h->server || (announced && typed));
    if (h->loss) CHECK(h->sent_data >= 2 && h->received_data >= 2 && h->received_proofs >= 2);
    printf("RNS 1.5.5 live %s: authenticated destination, bidirectional typed payload, signed delivery proof, graceful close%s passed\n",
        argv[3], h->loss ? ", dropped data/proof retries and duplicate suppression" : "");
    rnc_link_free(h->link); rnc_identity_clear(&h->own); free(h); success = 1; return 0;
}
