/* Unit test of the portable network helpers shared by the Wi-Fi ports and the host
 * harness (mcu/app/rnc_mcu_net.h): reconnect backoff, bounded output queue with
 * whole-frame backpressure, provisioning settings and the line console. No sockets.
 * Built in the mcu profile build. */
#include "rnc_mcu_net.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                  \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

/* feeds a command line (and a newline) to the console; returns the actions */
static unsigned type(rnc_mcu_console *c, rnc_mcu_cfg *cfg, const char *line, char *reply,
                     size_t reply_size) {
  unsigned actions = 0;
  size_t i;
  reply[0] = 0;
  for (i = 0; line[i]; i++)
    actions |= rnc_mcu_console_feed(c, cfg, (uint8_t)line[i], reply, reply_size);
  actions |= rnc_mcu_console_feed(c, cfg, '\n', reply, reply_size);
  return actions;
}

int main(void) {
  rnc_mcu_backoff b;
  rnc_mcu_txq q;
  uint8_t storage[16];
  const uint8_t *ptr;
  uint32_t d, last;
  int i;
  rnc_mcu_cfg cfg;
  rnc_mcu_console con;
  char reply[256];

  /* ---- backoff: grows, stays within [3/4 of the step, the step], is capped, resets */
  rnc_mcu_backoff_init(&b, 250, 4000);
  last = 0;
  for (i = 0; i < 12; i++) {
    uint32_t step = 250u << (i < 4 ? i : 4); /* 250 500 1000 2000 4000 4000 ... */
    if (step > 4000)
      step = 4000;
    d = rnc_mcu_backoff_next(&b, 0xffffffffu); /* the largest jitter */
    CHECK(d >= step - step / 4 && d <= step);
    d = 0;
    if (i)
      CHECK(last <= 4000);
    last = step;
  }
  CHECK(rnc_mcu_backoff_next(&b, 0) == 4000); /* no jitter: the cap */
  rnc_mcu_backoff_reset(&b);
  CHECK(rnc_mcu_backoff_next(&b, 0) == 250); /* a successful connection starts over */
  CHECK(rnc_mcu_backoff_next(&b, 0) == 500);
  rnc_mcu_backoff_init(&b, 0, 0); /* nonsense is repaired, never zero */
  CHECK(rnc_mcu_backoff_next(&b, 0) >= 1);

  /* ---- bounded output queue: whole frames or nothing */
  rnc_mcu_txq_init(&q, storage, sizeof(storage));
  CHECK(rnc_mcu_txq_free(&q) == 16);
  CHECK(rnc_mcu_txq_push(&q, (const uint8_t *)"0123456789", 10) == 1);
  CHECK(rnc_mcu_txq_push(&q, (const uint8_t *)"abcdefgh", 8) == 0); /* does not fit: dropped whole */
  CHECK(q.dropped == 1 && rnc_mcu_txq_free(&q) == 6);
  CHECK(rnc_mcu_txq_peek(&q, &ptr) == 10 && !memcmp(ptr, "0123456789", 10));
  rnc_mcu_txq_consume(&q, 4);
  CHECK(rnc_mcu_txq_free(&q) == 10);
  CHECK(rnc_mcu_txq_push(&q, (const uint8_t *)"abcdefgh", 8) == 1); /* wraps around the end */
  CHECK(rnc_mcu_txq_peek(&q, &ptr) == 12 && !memcmp(ptr, "456789abcdef", 12)); /* to the end */
  rnc_mcu_txq_consume(&q, 12);
  CHECK(rnc_mcu_txq_peek(&q, &ptr) == 2 && !memcmp(ptr, "gh", 2)); /* the wrapped part */
  rnc_mcu_txq_consume(&q, 2);
  CHECK(rnc_mcu_txq_peek(&q, &ptr) == 0 && rnc_mcu_txq_free(&q) == 16);
  CHECK(rnc_mcu_txq_push(&q, (const uint8_t *)"xyz", 3) == 1);
  rnc_mcu_txq_clear(&q); /* a dropped connection discards what was queued for it */
  CHECK(rnc_mcu_txq_peek(&q, &ptr) == 0 && rnc_mcu_txq_free(&q) == 16);
  CHECK(rnc_mcu_txq_push(&q, (const uint8_t *)"0123456789abcdefg", 17) == 0); /* larger than the queue */

  /* ---- settings and the console */
  rnc_mcu_cfg_init(&cfg);
  CHECK(!strcmp(cfg.mode, "serial") && cfg.port == 4242);
  CHECK(!rnc_mcu_cfg_wifi_ready(&cfg)); /* no credentials */
  rnc_mcu_console_init(&con);
  CHECK(type(&con, &cfg, "set ssid My Network", reply, sizeof(reply)) == 0);
  CHECK(!strcmp(cfg.ssid, "My Network")); /* the value is the rest of the line */
  type(&con, &cfg, "set password correct horse", reply, sizeof(reply));
  CHECK(!strcmp(cfg.password, "correct horse"));
  type(&con, &cfg, "set host 192.168.1.10", reply, sizeof(reply));
  type(&con, &cfg, "set port 4965", reply, sizeof(reply));
  CHECK(cfg.port == 4965);
  type(&con, &cfg, "set mode wifi", reply, sizeof(reply));
  CHECK(!strcmp(cfg.mode, "wifi") && rnc_mcu_cfg_wifi_ready(&cfg));
  /* get never prints the password */
  type(&con, &cfg, "get", reply, sizeof(reply));
  CHECK(strstr(reply, "ssid=My Network") && strstr(reply, "host=192.168.1.10"));
  CHECK(!strstr(reply, "correct horse") && strstr(reply, "password=(set)"));
  type(&con, &cfg, "get password", reply, sizeof(reply));
  CHECK(!strstr(reply, "correct horse"));
  /* refused values leave the settings alone */
  type(&con, &cfg, "set port 70000", reply, sizeof(reply));
  CHECK(cfg.port == 4965 && strstr(reply, "error"));
  type(&con, &cfg, "set port x", reply, sizeof(reply));
  CHECK(cfg.port == 4965 && strstr(reply, "error"));
  type(&con, &cfg, "set mode radio", reply, sizeof(reply));
  CHECK(!strcmp(cfg.mode, "wifi") && strstr(reply, "error"));
  type(&con, &cfg, "set password short", reply, sizeof(reply)); /* WPA needs 8..63 */
  CHECK(!strcmp(cfg.password, "correct horse") && strstr(reply, "error"));
  type(&con, &cfg, "set colour red", reply, sizeof(reply));
  CHECK(strstr(reply, "error"));
  type(&con, &cfg, "set ssid 0123456789012345678901234567890123", reply, sizeof(reply)); /* 34 */
  CHECK(!strcmp(cfg.ssid, "My Network") && strstr(reply, "error"));
  type(&con, &cfg, "set password", reply, sizeof(reply)); /* an open network */
  CHECK(cfg.password[0] == 0);
  /* actions */
  CHECK(type(&con, &cfg, "save", reply, sizeof(reply)) == RNC_MCU_CONSOLE_SAVE);
  CHECK(type(&con, &cfg, "reboot", reply, sizeof(reply)) == RNC_MCU_CONSOLE_REBOOT);
  CHECK(type(&con, &cfg, "help", reply, sizeof(reply)) == 0 && strstr(reply, "set"));
  CHECK(type(&con, &cfg, "", reply, sizeof(reply)) == 0 && reply[0] == 0);
  CHECK(type(&con, &cfg, "nonsense", reply, sizeof(reply)) == 0 && strstr(reply, "error"));
  /* CRLF terminals and an over-long line (refused, and the console recovers) */
  {
    unsigned a = 0;
    const char *crlf = "save\r\n";
    for (i = 0; crlf[i]; i++)
      a |= rnc_mcu_console_feed(&con, &cfg, (uint8_t)crlf[i], reply, sizeof(reply));
    CHECK(a == RNC_MCU_CONSOLE_SAVE);
  }
  {
    char longline[400];
    memset(longline, 'a', sizeof(longline) - 1);
    longline[sizeof(longline) - 1] = 0;
    type(&con, &cfg, longline, reply, sizeof(reply));
    CHECK(strstr(reply, "error"));
    CHECK(type(&con, &cfg, "save", reply, sizeof(reply)) == RNC_MCU_CONSOLE_SAVE);
  }
  type(&con, &cfg, "clear", reply, sizeof(reply));
  CHECK(!strcmp(cfg.mode, "serial") && cfg.ssid[0] == 0 && cfg.host[0] == 0);
  puts("mcu net tests passed");
  return 0;
}
