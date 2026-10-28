#ifndef RNC_RADIO_HAL_H
#define RNC_RADIO_HAL_H
/*
 * Hardware abstraction of the LoRa radio drivers. Portable C, no platform headers: a
 * port (ESP-IDF, Arduino ESP32, Arduino nRF52) or a test model fills this table.
 *
 * Polling is the base mode of operation; an interrupt line is optional and only
 * used as a hint that "something happened" (the drivers still read the chip's own
 * status before they act on it, so a missing or noisy line cannot cause a wrong
 * result, only a missed poll shortcut).
 */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum rnc_radio_pin {
  RNC_PIN_RESET = 0, /* output, active low (NRESET) */
  RNC_PIN_BUSY,      /* input, SX126x BUSY (high while the chip processes a command) */
  RNC_PIN_DIO,       /* input, SX126x DIO1 / SX127x DIO0 (the interrupt line) */
  RNC_PIN_RXEN,      /* output, external RF switch or antenna supply, when the board has one */
  RNC_PIN_TXEN,      /* output, external RF switch transmit path, when the board has one */
  RNC_PIN_COUNT
} rnc_radio_pin;

typedef struct rnc_radio_hal {
  void *context; /* first argument of every hook */

  /* REQUIRED. One SPI transaction: chip select asserted, `len` bytes clocked out
   * from `tx` (zeros when NULL) while `len` bytes are clocked in to `rx` (discarded
   * when NULL), chip select released. SPI mode 0, MSB first, up to 8 MHz. Returns 0
   * on success. */
  int (*spi_transfer)(void *context, const uint8_t *tx, uint8_t *rx, size_t len);
  /* REQUIRED. Drive an output pin. A pin the board does not have is ignored. */
  void (*gpio_write)(void *context, rnc_radio_pin pin, int level);
  /* OPTIONAL (NULL = no such input). Level of an input pin: 0 or 1; a negative value
   * means the pin does not exist on this board. */
  int (*gpio_read)(void *context, rnc_radio_pin pin);
  /* REQUIRED. Busy-wait or sleep for at least this many microseconds. */
  void (*delay_us)(void *context, uint32_t us);
  /* REQUIRED. Monotonic microseconds since an arbitrary start. */
  uint64_t (*now_us)(void *context);
} rnc_radio_hal;

#ifdef __cplusplus
}
#endif
#endif
