#ifndef RNC_MCU_PLATFORM_H
#define RNC_MCU_PLATFORM_H
/*
 * Platform interface of the portable MCU example application (rnc_mcu_app.h).
 *
 * The application contains no platform headers; everything it needs from the
 * board is in this table, filled by the port (ESP-IDF, the host build, and later
 * Arduino/PlatformIO or nRF52 ports). Only `write`, `read`, `random`, `now_ms`,
 * `persist` and `load` are required; the others may be NULL.
 *
 * Threading: the application calls the hooks only from rnc_mcu_app_step (and
 * rnc_mcu_app_new / _free), always from one task.
 */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Keys the application passes to persist/load. */
#define RNC_MCU_KEY_IDENTITY "identity" /* 64 bytes: the raw private key */
#define RNC_MCU_KEY_TIME "time"         /* 8 bytes: the unix-time high-water mark */

typedef struct rnc_mcu_platform {
  void *context; /* passed back as the first argument of every hook */

  /* REQUIRED. Send bytes on the serial transport. Returns how many bytes were
   * accepted; it may block briefly (a UART with a full FIFO). A short count means
   * the rest was dropped, which Reticulum tolerates (the frame is lost). */
  size_t (*write)(void *context, const uint8_t *data, size_t size);
  /* REQUIRED. Non-blocking: copy up to `capacity` bytes that are already
   * available into `buffer` and return how many (0 when none). */
  size_t (*read)(void *context, uint8_t *buffer, size_t capacity);
  /* REQUIRED. Fill `buffer` with cryptographically secure random bytes (the
   * hardware RNG with the radio or Wi-Fi enabled, or the system RNG on a host).
   * Return 0 on success. */
  int (*random)(void *context, uint8_t *buffer, size_t size);
  /* REQUIRED. Monotonic milliseconds since an arbitrary start (never goes back). */
  uint64_t (*now_ms)(void *context);
  /* OPTIONAL. Real unix seconds from an RTC, SNTP or GPS; return 0 while the
   * time is not known. When it returns non-zero it wins over the built-in
   * estimate (see the time policy in rnc_mcu_app.h). */
  uint64_t (*unix_seconds)(void *context);
  /* OPTIONAL. One log line without a trailing newline. */
  void (*log)(void *context, const char *line);
  /* REQUIRED. Store `size` bytes under `key` (flash/NVS/file); 0 on success. The
   * identity must survive power loss, or every boot becomes a new node. */
  int (*persist)(void *context, const char *key, const void *data, size_t size);
  /* REQUIRED. Read the bytes stored under `key` into `buffer`. Returns the stored
   * length, or a negative value when nothing is stored (or on error). */
  int (*load)(void *context, const char *key, void *buffer, size_t capacity);
  /* OPTIONAL. Free heap in bytes, reported by /info. */
  size_t (*free_heap)(void *context);
  /* OPTIONAL. Whether the transport is connected right now: nonzero = up, 0 =
   * down. NULL means a transport that is always up (a serial line), which is the
   * behaviour of every port before connection oriented transports existed. A TCP
   * client over Wi-Fi returns 0 while it is (re)connecting.
   *
   * The application polls it at every step and reacts to the changes:
   *  - while down it reads nothing, writes nothing (frames the node produces are
   *    counted and dropped rather than delivered late over a new connection) and
   *    does not announce;
   *  - when it goes from down to up it resets the HDLC decoder (a half frame of
   *    the old connection must not be glued to the new stream) and announces again
   *    after RNC_MCU_LINK_UP_DELAY_MS (then once more FIRST_REPEAT later, as at boot),
   *    so the peer learns the path again without waiting for the regular interval.
   * The hook must be cheap and non-blocking. */
  int (*link_up)(void *context);

  const char *board; /* shown by /info, for example "heltec_wifi_lora_32_v3"; may be NULL */
} rnc_mcu_platform;

#ifdef __cplusplus
}
#endif
#endif
