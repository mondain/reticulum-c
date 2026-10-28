/* Portable MCU example application; see rnc_mcu_app.h. No platform headers: the
 * only libc used is string.h, stdio.h (snprintf) and stdlib.h (malloc/free). */
#include "rnc_mcu_app.h"
#include <reticulum_c/rnc.h>
#include <reticulum_c/rnc_ipc.h>
#include <reticulum_c/rnc_node.h>
#include <reticulum_c/rnc_responder.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef RNC_PROFILE_MCU
#error "mcu/app must be built with the mcu profile (define RNC_PROFILE_MCU for every file that includes reticulum_c headers)"
#endif

#define IFACE_ID 1u
#define READ_CHUNK 64u
#define MAX_REQUEST 1024u
#define FIRST_REPEAT_MS 5000u /* the second announce, after the first may have been lost */
#define STEP_MS 20u

struct rnc_mcu_app {
  rnc_mcu_platform platform;
  rnc_mcu_config config;
  rnc_identity identity;
  rnc_node *node;
  rnc_responder *responder;
  uint8_t destination[16];
  /* clock (see the policy in rnc_mcu_app.h): unix = base + now_ms / 1000 */
  uint64_t base, last_unix, last_persist_unix;
  int persist_time;
  uint64_t last_now_ms;
  /* announce schedule */
  unsigned announces;
  uint64_t next_announce_ms;
  /* receive and transmit scratch, kept off the (small) task stack */
  rnc_hdlc hdlc;
  rnc_packet packet;
  rnc_node_event event;
  uint8_t frame[RNC_MAX_FRAME];
  uint8_t wire[RNC_MAX_FRAME + 8u];
  uint8_t hdlc_out[RNC_HDLC_MAX];
  uint8_t readbuf[READ_CHUNK];
  char logline[128];
};

static void say_n(rnc_mcu_app *app, const char *message, long value) {
  if (!app->platform.log)
    return;
  (void)snprintf(app->logline, sizeof(app->logline), "%s %ld", message, value);
  app->platform.log(app->platform.context, app->logline);
}
static void say(rnc_mcu_app *app, const char *message) {
  if (!app->platform.log)
    return;
  (void)snprintf(app->logline, sizeof(app->logline), "%s", message);
  app->platform.log(app->platform.context, app->logline);
}

/* ---- clock -------------------------------------------------------------- */
uint64_t rnc_mcu_app_unix(rnc_mcu_app *app, uint64_t now_ms) {
  uint64_t u = app->base + now_ms / 1000u;
  if (app->platform.unix_seconds) {
    uint64_t real = app->platform.unix_seconds(app->platform.context);
    if (real > u) {
      app->base += real - u;
      u = real;
    }
  }
  if (u < app->last_unix) /* the monotonic source cannot go back, but be safe */
    u = app->last_unix;
  app->last_unix = u;
  return u;
}
int rnc_mcu_app_set_unix(rnc_mcu_app *app, uint64_t now_ms, uint64_t unix_seconds) {
  uint64_t u = rnc_mcu_app_unix(app, now_ms);
  if (unix_seconds <= u || unix_seconds > UINT64_C(0xffffffffff))
    return -1;
  app->base = unix_seconds - now_ms / 1000u;
  app->last_unix = unix_seconds;
  return 0;
}
static void persist_time(rnc_mcu_app *app, uint64_t unix_now) {
  uint8_t b[8];
  unsigned i;
  if (!app->persist_time || unix_now < app->last_persist_unix + RNC_MCU_TIME_PERSIST_S)
    return;
  for (i = 0; i < 8; i++)
    b[i] = (uint8_t)(unix_now >> (56u - 8u * i));
  if (app->platform.persist(app->platform.context, RNC_MCU_KEY_TIME, b, sizeof(b)) == 0)
    app->last_persist_unix = unix_now;
}
static void clock_init(rnc_mcu_app *app, uint64_t now_ms) {
  uint64_t start = RNC_MCU_BUILD_EPOCH, real = 0;
  uint8_t b[8];
  int n;
  if (app->platform.unix_seconds)
    real = app->platform.unix_seconds(app->platform.context);
  if (real) {
    start = real;
  } else {
    n = app->platform.load(app->platform.context, RNC_MCU_KEY_TIME, b, sizeof(b));
    if (n == 8) {
      uint64_t stored = 0;
      unsigned i;
      for (i = 0; i < 8; i++)
        stored = (stored << 8) | b[i];
      /* later than anything announced before the reboot */
      stored += RNC_MCU_TIME_PERSIST_S + 1u;
      if (stored > start && stored < UINT64_C(0xffffffffff))
        start = stored;
    }
    app->persist_time = 1;
  }
  app->base = start - now_ms / 1000u;
  app->last_unix = start;
  app->last_persist_unix = start;
}

/* ---- request handlers ----------------------------------------------------- */
static rnc_result handle_echo(void *context, const char *path, const uint8_t *request,
                              size_t size, const uint8_t *identity, uint8_t *response,
                              size_t capacity, size_t *written) {
  (void)context;
  (void)path;
  (void)identity;
  if (size > capacity)
    return RNC_NO_SPACE;
  memcpy(response, request, size);
  *written = size;
  return RNC_OK;
}
static rnc_result handle_info(void *context, const char *path, const uint8_t *request,
                              size_t size, const uint8_t *identity, uint8_t *response,
                              size_t capacity, size_t *written) {
  rnc_mcu_app *app = context;
  rnc_rpc_writer w;
  size_t heap = app->platform.free_heap ? app->platform.free_heap(app->platform.context) : 0;
  size_t pairs = 4u + (heap ? 1u : 0u);
  (void)path;
  (void)request;
  (void)size;
  (void)identity;
  rnc_rpc_writer_init(&w, response, capacity);
  (void)rnc_rpc_write_map(&w, pairs);
  (void)rnc_rpc_write_string(&w, "name");
  (void)rnc_rpc_write_string(&w, RNC_MCU_FIRMWARE_NAME);
  (void)rnc_rpc_write_string(&w, "version");
  (void)rnc_rpc_write_string(&w, RNC_MCU_VERSION);
  (void)rnc_rpc_write_string(&w, "board");
  (void)rnc_rpc_write_string(&w, app->platform.board ? app->platform.board : "unknown");
  (void)rnc_rpc_write_string(&w, "uptime");
  (void)rnc_rpc_write_uint(&w, app->last_now_ms / 1000u);
  if (heap) {
    (void)rnc_rpc_write_string(&w, "heap");
    (void)rnc_rpc_write_uint(&w, heap);
  }
  return rnc_rpc_writer_finish(&w, written);
}

/* ---- node plumbing ------------------------------------------------------- */
static rnc_result random_adapter(void *context, uint8_t *out, size_t size) {
  rnc_mcu_app *app = context;
  return app->platform.random(app->platform.context, out, size) == 0 ? RNC_OK : RNC_CRYPTO;
}

static void transmit(rnc_mcu_app *app, const rnc_packet *packet) {
  size_t wire_size = 0, framed = 0, done = 0;
  unsigned stalls = 0;
  if (rnc_packet_encode(packet, app->wire, sizeof(app->wire), &wire_size) != RNC_OK ||
      rnc_hdlc_encode(app->wire, wire_size, app->hdlc_out, sizeof(app->hdlc_out),
                      &framed) != RNC_OK)
    return;
  while (done < framed && stalls < 3u) {
    size_t n = app->platform.write(app->platform.context, app->hdlc_out + done, framed - done);
    if (n == 0)
      stalls++;
    done += n;
  }
  if (done < framed)
    say_n(app, "tx dropped bytes:", (long)(framed - done));
}

/* Hands out everything the node and the responder have queued. */
static void drain(rnc_mcu_app *app, uint64_t unix_now, uint64_t now_ms) {
  while (rnc_node_poll(app->node, &app->event) == RNC_OK) {
    if (app->event.type == RNC_NODE_SEND) {
      transmit(app, &app->event.packet);
    } else if (app->event.type == RNC_NODE_LOCAL) {
      rnc_result r = rnc_responder_input(app->responder, &app->event, unix_now, now_ms);
      if (r != RNC_OK && r != RNC_AGAIN)
        say_n(app, "responder refused a packet, result", (long)r);
    }
  }
}

static void receive_frame(rnc_mcu_app *app, size_t size, uint64_t unix_now, uint64_t now_ms) {
  rnc_result r;
  if (rnc_packet_decode(app->frame, size, &app->packet) != RNC_OK)
    return;
  r = rnc_node_input(app->node, IFACE_ID, &app->packet, unix_now, now_ms);
  if (r == RNC_AGAIN) { /* the node's queue is full: hand it out, then retry */
    drain(app, unix_now, now_ms);
    r = rnc_node_input(app->node, IFACE_ID, &app->packet, unix_now, now_ms);
  }
  if (r != RNC_OK && r != RNC_AGAIN && r != RNC_PROTOCOL && r != RNC_INVALID)
    say_n(app, "node rejected a packet, result", (long)r);
  drain(app, unix_now, now_ms); /* every input can queue output; never let it pile up */
}

static void read_serial(rnc_mcu_app *app, uint64_t unix_now, uint64_t now_ms) {
  unsigned rounds;
  for (rounds = 0; rounds < 16u; rounds++) {
    size_t got = app->platform.read(app->platform.context, app->readbuf, sizeof(app->readbuf)), i;
    if (!got)
      return;
    for (i = 0; i < got; i++) {
      size_t frame_size = 0;
      if (rnc_hdlc_feed(&app->hdlc, app->readbuf[i], app->frame, sizeof(app->frame),
                        &frame_size) == RNC_OK)
        receive_frame(app, frame_size, unix_now, now_ms);
    }
  }
}

/* ---- public API ----------------------------------------------------------- */
rnc_mcu_app *rnc_mcu_app_new(const rnc_mcu_platform *platform, const rnc_mcu_config *config) {
  rnc_mcu_app *app;
  uint8_t key[64];
  int n;
  if (!platform || !platform->write || !platform->read || !platform->random ||
      !platform->now_ms || !platform->persist || !platform->load)
    return NULL;
  app = calloc(1, sizeof(*app));
  if (!app)
    return NULL;
  app->platform = *platform;
  if (config)
    app->config = *config;
  if (!app->config.announce_interval_ms)
    app->config.announce_interval_ms = RNC_MCU_ANNOUNCE_MS;
  if (!app->config.bitrate)
    app->config.bitrate = 115200u;
  clock_init(app, platform->now_ms(platform->context));

  n = platform->load(platform->context, RNC_MCU_KEY_IDENTITY, key, sizeof(key));
  if (n == (int)sizeof(key) && rnc_identity_from_private(&app->identity, key) == RNC_OK) {
    say(app, "identity loaded");
  } else {
    if (rnc_identity_generate(&app->identity, random_adapter, app) != RNC_OK) {
      free(app);
      return NULL;
    }
    if (platform->persist(platform->context, RNC_MCU_KEY_IDENTITY, app->identity.private_key,
                          64) != 0)
      say(app, "identity created but NOT persisted: it changes at every boot");
    else
      say(app, "identity created and stored");
  }
  {
    volatile uint8_t *k = key;
    size_t i;
    for (i = 0; i < sizeof(key); i++)
      k[i] = 0;
  }

  app->node = rnc_node_new(&app->identity, 0, random_adapter, app);
  if (!app->node || rnc_node_add_interface(app->node, IFACE_ID, app->config.bitrate) != RNC_OK ||
      rnc_node_add_destination(app->node, &app->identity, RNC_MCU_APP_NAME, NULL, 0,
                               app->destination) != RNC_OK)
    goto fail;
  app->responder = rnc_responder_new(app->node, MAX_REQUEST, random_adapter, app);
  if (!app->responder ||
      rnc_responder_add_destination(app->responder, &app->identity, app->destination) != RNC_OK ||
      rnc_responder_register(app->responder, app->destination, "/echo", RNC_SERVICE_ALLOW_ALL, NULL,
                             0, handle_echo, app) != RNC_OK ||
      rnc_responder_register(app->responder, app->destination, "/info", RNC_SERVICE_ALLOW_ALL, NULL,
                             0, handle_info, app) != RNC_OK)
    goto fail;
  app->announces = 0;
  app->next_announce_ms = 0;
  return app;
fail:
  rnc_mcu_app_free(app);
  return NULL;
}

void rnc_mcu_app_free(rnc_mcu_app *app) {
  if (!app)
    return;
  rnc_responder_free(app->responder);
  rnc_node_free(app->node);
  rnc_identity_clear(&app->identity);
  free(app);
}

int rnc_mcu_app_destination(const rnc_mcu_app *app, uint8_t hash[16]) {
  if (!app || !hash)
    return -1;
  memcpy(hash, app->destination, 16);
  return 0;
}

unsigned rnc_mcu_app_step(rnc_mcu_app *app, uint64_t now_ms) {
  uint64_t unix_now;
  unsigned wait = STEP_MS;
  if (now_ms < app->last_now_ms) /* the node requires time that does not go back */
    now_ms = app->last_now_ms;
  app->last_now_ms = now_ms;
  unix_now = rnc_mcu_app_unix(app, now_ms);

  read_serial(app, unix_now, now_ms);
  (void)rnc_node_tick(app->node, unix_now, now_ms);
  (void)rnc_responder_tick(app->responder, unix_now, now_ms);
  drain(app, unix_now, now_ms);

  if (now_ms >= app->next_announce_ms) {
    rnc_result r = rnc_node_announce(app->node, app->destination, unix_now, now_ms);
    if (r != RNC_OK)
      say_n(app, "announce failed, result", (long)r);
    app->announces++;
    app->next_announce_ms =
        now_ms + (app->announces == 1u ? FIRST_REPEAT_MS : app->config.announce_interval_ms);
    drain(app, unix_now, now_ms);
  }
  persist_time(app, unix_now);
  if (app->next_announce_ms > now_ms && app->next_announce_ms - now_ms < wait)
    wait = (unsigned)(app->next_announce_ms - now_ms);
  return wait;
}
