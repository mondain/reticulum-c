#include "wifi_transport.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#include "sdkconfig.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#define QUEUE_BYTES 4096u
#define BACKOFF_MIN_MS 500u
#define BACKOFF_MAX_MS 30000u
#define CONNECT_TIMEOUT_MS 10000u
#define WIFI_TIMEOUT_MS 30000u /* a connection attempt that got neither an IP nor a failure */

typedef enum { TCP_DOWN, TCP_CONNECTING, TCP_UP } tcp_state_t;

static rnc_mcu_cfg s_cfg;
static char s_port[8];
static volatile int s_got_ip;      /* set by the event handler */
static volatile int s_need_connect; /* the station must (re)connect to the access point */
static volatile int s_disconnects;  /* counted by the event handler, consumed by the pump */
static int s_fd = -1;
static tcp_state_t s_tcp = TCP_DOWN;
static uint64_t s_tcp_retry_ms, s_tcp_started_ms;
static uint64_t s_wifi_retry_ms, s_wifi_started_ms;
static rnc_mcu_backoff s_wifi_backoff, s_tcp_backoff;
static rnc_mcu_txq s_txq;
static uint8_t s_txq_storage[QUEUE_BYTES];

static uint64_t now_ms(void) { return (uint64_t)(esp_timer_get_time() / 1000); }

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data) {
  (void)arg;
  (void)data;
  if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
    s_need_connect = 1;
  } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
    s_got_ip = 0;
    (void)__atomic_add_fetch(&s_disconnects, 1, __ATOMIC_ACQ_REL);
  } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
    s_got_ip = 1;
  }
}

esp_err_t wifi_transport_start(const rnc_mcu_cfg *cfg) {
  wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
  wifi_config_t wc;
  esp_err_t err;
  s_cfg = *cfg;
  (void)snprintf(s_port, sizeof(s_port), "%u", (unsigned)cfg->port);
  rnc_mcu_txq_init(&s_txq, s_txq_storage, sizeof(s_txq_storage));
  rnc_mcu_backoff_init(&s_wifi_backoff, BACKOFF_MIN_MS, BACKOFF_MAX_MS);
  rnc_mcu_backoff_init(&s_tcp_backoff, BACKOFF_MIN_MS, BACKOFF_MAX_MS);

  if ((err = esp_netif_init()) != ESP_OK)
    return err;
  err = esp_event_loop_create_default();
  if (err != ESP_OK && err != ESP_ERR_INVALID_STATE)
    return err;
  if (!esp_netif_create_default_wifi_sta())
    return ESP_FAIL;
  if ((err = esp_wifi_init(&init)) != ESP_OK)
    return err;
  /* the credentials live in the settings partition only, not in the Wi-Fi driver's NVS */
  (void)esp_wifi_set_storage(WIFI_STORAGE_RAM);
  if ((err = esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_event, NULL)) != ESP_OK ||
      (err = esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_event, NULL)) != ESP_OK)
    return err;

  memset(&wc, 0, sizeof(wc));
  memcpy(wc.sta.ssid, s_cfg.ssid, strlen(s_cfg.ssid));
  memcpy(wc.sta.password, s_cfg.password, strlen(s_cfg.password));
  wc.sta.threshold.authmode = s_cfg.password[0] ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
  wc.sta.pmf_cfg.capable = true;
  wc.sta.pmf_cfg.required = false;
  wc.sta.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;
  if ((err = esp_wifi_set_mode(WIFI_MODE_STA)) != ESP_OK ||
      (err = esp_wifi_set_config(WIFI_IF_STA, &wc)) != ESP_OK)
    return err;
  memset(&wc, 0, sizeof(wc));
  return esp_wifi_start();
}

/* ---- TCP ------------------------------------------------------------------ */
static void tcp_drop(uint64_t now) {
  if (s_fd >= 0)
    close(s_fd);
  s_fd = -1;
  s_tcp = TCP_DOWN;
  rnc_mcu_txq_clear(&s_txq);
  s_tcp_retry_ms = now + rnc_mcu_backoff_next(&s_tcp_backoff, esp_random());
}

static void tcp_start(uint64_t now) {
  struct addrinfo hints, *res = NULL, *ai;
  int fd = -1;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(s_cfg.host, s_port, &hints, &res) != 0 || !res) {
    tcp_drop(now);
    return;
  }
  for (ai = res; ai; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0)
      continue;
    (void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0 || errno == EINPROGRESS)
      break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0) {
    tcp_drop(now);
    return;
  }
  s_fd = fd;
  s_tcp = TCP_CONNECTING;
  s_tcp_started_ms = now;
}

static void tcp_flush(uint64_t now) {
  const uint8_t *data;
  size_t n;
  while (s_tcp == TCP_UP && (n = rnc_mcu_txq_peek(&s_txq, &data)) > 0) {
    int sent = send(s_fd, data, n, MSG_DONTWAIT);
    if (sent > 0) {
      rnc_mcu_txq_consume(&s_txq, (size_t)sent);
    } else if (sent < 0 && errno == EINTR) {
      continue;
    } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return;
    } else {
      tcp_drop(now);
      return;
    }
  }
}

static void tcp_finish_connect(uint64_t now) {
  fd_set wfds;
  struct timeval tv = {0, 0};
  int err = 0;
  socklen_t len = sizeof(err);
  FD_ZERO(&wfds);
  FD_SET(s_fd, &wfds);
  if (select(s_fd + 1, NULL, &wfds, NULL, &tv) > 0) {
    if (getsockopt(s_fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) {
      tcp_drop(now);
    } else {
      int one = 1, idle = 30, interval = 10, count = 3;
      (void)setsockopt(s_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
      (void)setsockopt(s_fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
      (void)setsockopt(s_fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
      (void)setsockopt(s_fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
      (void)setsockopt(s_fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
      s_tcp = TCP_UP;
      rnc_mcu_backoff_reset(&s_tcp_backoff);
    }
  } else if (now - s_tcp_started_ms > CONNECT_TIMEOUT_MS) {
    tcp_drop(now);
  }
}

/* One pass of the connection state machine. */
static void pump(void) {
  uint64_t now = now_ms();
  int disconnects = __atomic_exchange_n(&s_disconnects, 0, __ATOMIC_ACQ_REL);
  if (disconnects) { /* the access point connection dropped (or an attempt failed) */
    s_wifi_retry_ms = now + rnc_mcu_backoff_next(&s_wifi_backoff, esp_random());
    s_need_connect = 1;
    s_wifi_started_ms = 0;
    if (s_tcp != TCP_DOWN)
      tcp_drop(now);
  }
  if (s_need_connect && now >= s_wifi_retry_ms) {
    s_need_connect = 0;
    s_wifi_started_ms = now;
    if (esp_wifi_connect() != ESP_OK) { /* busy: try again after the backoff */
      s_need_connect = 1;
      s_wifi_retry_ms = now + rnc_mcu_backoff_next(&s_wifi_backoff, esp_random());
    }
  }
  if (s_got_ip) {
    rnc_mcu_backoff_reset(&s_wifi_backoff);
    s_wifi_started_ms = 0;
  } else if (s_wifi_started_ms && now - s_wifi_started_ms > WIFI_TIMEOUT_MS) {
    (void)esp_wifi_disconnect(); /* raises a disconnect event, which schedules the retry */
    s_wifi_started_ms = 0;
  }
  if (!s_got_ip) {
    if (s_tcp != TCP_DOWN)
      tcp_drop(now);
    return;
  }
  if (s_tcp == TCP_DOWN && now >= s_tcp_retry_ms)
    tcp_start(now);
  if (s_tcp == TCP_CONNECTING)
    tcp_finish_connect(now);
  tcp_flush(now);
}

int wifi_transport_link_up(void *context) {
  (void)context;
  pump();
  return s_tcp == TCP_UP;
}

size_t wifi_transport_write(void *context, const uint8_t *data, size_t size) {
  (void)context;
  if (s_tcp != TCP_UP)
    return 0;
  /* one HDLC frame: queued whole or refused (backpressure); a full queue is drained first */
  if (rnc_mcu_txq_free(&s_txq) < size)
    tcp_flush(now_ms());
  return rnc_mcu_txq_push(&s_txq, data, size) ? size : 0;
}

size_t wifi_transport_read(void *context, uint8_t *buffer, size_t capacity) {
  int n;
  (void)context;
  if (s_tcp != TCP_UP)
    return 0;
  n = recv(s_fd, buffer, capacity, MSG_DONTWAIT);
  if (n > 0)
    return (size_t)n;
  if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
    tcp_drop(now_ms());
  return 0;
}
