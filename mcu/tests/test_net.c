/* Unit test of the portable network helpers shared by the Wi-Fi ports and the host
 * harness (mcu/app/rnc_mcu_net.h): reconnect backoff, bounded output queue with
 * whole-frame backpressure, provisioning settings and the line console. No sockets.
 * Built in the mcu profile build. */
#include "rnc_mcu_net.h"
#include <reticulum_c/rnc_netstamp.h>
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
  /* the Bluetooth PIN: six digits, set by the operator, never printed, off until set */
  CHECK(!rnc_mcu_cfg_ble_ready(&cfg));
  type(&con, &cfg, "get ble.pin", reply, sizeof(reply));
  CHECK(strstr(reply, "ble.pin=(empty)"));
  type(&con, &cfg, "set ble.pin 123456", reply, sizeof(reply));
  CHECK(!strstr(reply, "error") && !strcmp(cfg.ble_pin, "123456") && rnc_mcu_cfg_ble_ready(&cfg));
  type(&con, &cfg, "get ble.pin", reply, sizeof(reply));
  CHECK(strstr(reply, "ble.pin=(set)") && !strstr(reply, "123456"));
  type(&con, &cfg, "get", reply, sizeof(reply));
  CHECK(strstr(reply, "ble.pin=(set)") && !strstr(reply, "123456"));
  {
    static const char *bad[] = {"set ble.pin 12345", "set ble.pin 1234567", "set ble.pin 12a456",
                                "set ble.pin 12 456", "set ble.pin -12345"};
    unsigned i;
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
      type(&con, &cfg, bad[i], reply, sizeof(reply));
      CHECK(strstr(reply, "error") && !strcmp(cfg.ble_pin, "123456"));
    }
  }
  type(&con, &cfg, "set ble.pin", reply, sizeof(reply)); /* an empty value turns Bluetooth off */
  CHECK(!rnc_mcu_cfg_ble_ready(&cfg) && cfg.ble_pin[0] == 0);
  type(&con, &cfg, "set ble.pin 654321", reply, sizeof(reply));
  CHECK(rnc_mcu_cfg_ble_ready(&cfg));
  /* the RNode modem mode */
  type(&con, &cfg, "set mode rnode", reply, sizeof(reply));
  CHECK(!strcmp(cfg.mode, "rnode") && rnc_mcu_cfg_rnode_mode(&cfg) && !rnc_mcu_cfg_wifi_mode(&cfg));
  CHECK(!strstr(reply, "error"));
  type(&con, &cfg, "get mode", reply, sizeof(reply));
  CHECK(strstr(reply, "mode=rnode"));
  type(&con, &cfg, "set mode xyz", reply, sizeof(reply));
  CHECK(!strcmp(cfg.mode, "rnode") && strstr(reply, "error"));
  type(&con, &cfg, "set mode wifi", reply, sizeof(reply));
  CHECK(!strcmp(cfg.mode, "wifi") && !rnc_mcu_cfg_rnode_mode(&cfg));
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
  CHECK(cfg.ble_pin[0] == 0 && !rnc_mcu_cfg_ble_ready(&cfg)); /* clear removes the PIN too */

  /* ---- the radio settings: nothing is set after a clear, and the radio stays off until
   * every transmit setting is given */
  CHECK(cfg.lora.mode == RNC_LORA_MODE_OFF && cfg.lora.set == 0 && !rnc_lora_cfg_ready(&cfg.lora));
  type(&con, &cfg, "get", reply, sizeof(reply));
  CHECK(strstr(reply, "lora.mode=off") && strstr(reply, "lora.freq=(not set)") &&
        strstr(reply, "lora.txp=(not set)") && strstr(reply, "lora.airtime=1.00"));
  type(&con, &cfg, "set lora.mode leaf", reply, sizeof(reply));
  type(&con, &cfg, "set lora.freq 868.1", reply, sizeof(reply));
  type(&con, &cfg, "set lora.bw 125", reply, sizeof(reply));
  type(&con, &cfg, "set lora.sf 8", reply, sizeof(reply));
  type(&con, &cfg, "set lora.cr 5", reply, sizeof(reply));
  CHECK(cfg.lora.mode == RNC_LORA_MODE_LEAF && !rnc_lora_cfg_ready(&cfg.lora)); /* no power yet */
  type(&con, &cfg, "set lora.txp 14", reply, sizeof(reply));
  CHECK(rnc_lora_cfg_ready(&cfg.lora) && cfg.lora.freq_hz == 868100000u && cfg.lora.bw_hz == 125000u);
  type(&con, &cfg, "get lora.freq", reply, sizeof(reply));
  CHECK(!strcmp(reply, "lora.freq=868100000"));
  type(&con, &cfg, "get", reply, sizeof(reply));
  CHECK(strstr(reply, "lora.mode=leaf") && strstr(reply, "lora.sf=8") && strstr(reply, "lora.txp=14"));
  type(&con, &cfg, "set lora.freq 99", reply, sizeof(reply)); /* refused: unchanged */
  CHECK(strstr(reply, "error") && cfg.lora.freq_hz == 868100000u);
  type(&con, &cfg, "set lora.txp 99", reply, sizeof(reply));
  CHECK(strstr(reply, "error") && cfg.lora.txp_dbm == 14);
  type(&con, &cfg, "set lora.nope 1", reply, sizeof(reply));
  CHECK(strstr(reply, "error"));
  type(&con, &cfg, "set lora.mode gateway", reply, sizeof(reply));
  CHECK(cfg.lora.mode == RNC_LORA_MODE_GATEWAY && rnc_lora_cfg_ready(&cfg.lora));
  type(&con, &cfg, "help", reply, sizeof(reply));
  CHECK(strstr(reply, "lora.freq") && strstr(reply, "stays off"));
  type(&con, &cfg, "clear", reply, sizeof(reply)); /* back to a radio that is off and unset */
  CHECK(cfg.lora.mode == RNC_LORA_MODE_OFF && cfg.lora.set == 0 && !rnc_lora_cfg_ready(&cfg.lora));
  /* ---- the destination stamp: material shown by the console, a stamp checked against it before it is taken ---- */
  {
    uint8_t material[90], found[14], rnd = 3;
    char hexmat[181], cmd[64], good[29];
    size_t k;
    rnc_mcu_cfg_init(&cfg);
    cfg.stamp_value = 6.0; /* a test does not search for 2^25 hashes */
    for (k = 0; k < sizeof(material); k++)
      material[k] = (uint8_t)(k * 7 + 1);
    for (k = 0; k < sizeof(material); k++)
      (void)snprintf(hexmat + 2 * k, 3, "%02x", material[k]);
    /* before the identity exists there is no material, and no stamp can be set */
    type(&con, &cfg, "get stamp.material", reply, sizeof(reply));
    CHECK(strstr(reply, "(not yet") != NULL);
    type(&con, &cfg, "get stamp.status", reply, sizeof(reply));
    CHECK(!strcmp(reply, "stamp.status=none"));
    type(&con, &cfg, "set stamp 00112233445566778899aabbccdd", reply, sizeof(reply));
    CHECK(strstr(reply, "error") && !cfg.stamp_new_set);
    /* the platform fills the material and status in (rnc_mcu_stamp_prepare) */
    memcpy(cfg.stamp_material, hexmat, sizeof(hexmat));
    memcpy(cfg.stamp_status, "none", 5);
    type(&con, &cfg, "get stamp.material", reply, sizeof(reply));
    CHECK(!strcmp(reply + strlen("stamp.material="), hexmat) && !strncmp(reply, "stamp.material=", 15));
    {
      rnc_result r;
      uint64_t i = 0;
      do {
        uint8_t seedbytes[14] = {0};
        seedbytes[0] = rnd;
        seedbytes[13] = (uint8_t)i;
        seedbytes[12] = (uint8_t)(i >> 8);
        memcpy(found, seedbytes, sizeof(found));
        r = rnc_netstamp_valid(material, sizeof(material), found, sizeof(found), cfg.stamp_value) ? RNC_OK : RNC_AGAIN;
        i++;
      } while (r != RNC_OK && i < 100000);
      CHECK(r == RNC_OK);
    }
    for (k = 0; k < 14; k++)
      (void)snprintf(good + 2 * k, 3, "%02x", found[k]);
    (void)snprintf(cmd, sizeof(cmd), "set stamp %s", good);
    type(&con, &cfg, cmd, reply, sizeof(reply));
    CHECK(!strstr(reply, "error") && cfg.stamp_new_set && !memcmp(cfg.stamp_new, found, 14));
    /* a stamp that falls short, one of the wrong length and a non hex one are refused and change nothing */
    cfg.stamp_new_set = 0;
    found[0] ^= 0xff;
    found[1] ^= 0xff;
    for (k = 0; k < 14; k++)
      (void)snprintf(good + 2 * k, 3, "%02x", found[k]);
    (void)snprintf(cmd, sizeof(cmd), "set stamp %s", good);
    {
      int refused;
      type(&con, &cfg, cmd, reply, sizeof(reply));
      refused = strstr(reply, "error") != NULL;
      /* the flipped bytes may, with probability 1/64, meet a cost of 6 again: only refusals are checked */
      CHECK(refused ? !cfg.stamp_new_set : 1);
    }
    cfg.stamp_new_set = 0;
    type(&con, &cfg, "set stamp 0011", reply, sizeof(reply));
    CHECK(strstr(reply, "error") && !cfg.stamp_new_set);
    type(&con, &cfg, "set stamp zz112233445566778899aabbccdd", reply, sizeof(reply));
    CHECK(strstr(reply, "error") && !cfg.stamp_new_set);
    /* an empty value clears the stored stamp */
    type(&con, &cfg, "set stamp", reply, sizeof(reply));
    CHECK(strstr(reply, "error") != NULL); /* needs a value; the explicit way is "set stamp clear" */
    type(&con, &cfg, "set stamp clear", reply, sizeof(reply));
    CHECK(!strstr(reply, "error") && cfg.stamp_new_set && !memcmp(cfg.stamp_new, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 14));
    /* "clear" restores the defaults but not what the platform reported about the identity */
    type(&con, &cfg, "clear", reply, sizeof(reply));
    CHECK(!strcmp(cfg.stamp_material, hexmat) && !cfg.stamp_new_set);
  }
  puts("mcu net tests passed");
  return 0;
}
