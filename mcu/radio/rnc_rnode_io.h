#ifndef RNC_RNODE_IO_H
#define RNC_RNODE_IO_H
/*
 * A byte transport between the RNode module and its host: the USB serial port today, a
 * Bluetooth LE Nordic UART service next. The module (rnc_rnode.h) holds no protocol logic
 * for either; the owner supplies one of these per transport.
 *
 *   read   copies up to `capacity` bytes that arrived from the host into `buffer` without
 *          blocking; returns how many (0 for none), or a negative value on error
 *   write  sends `size` bytes to the host; returns how many it took. Bytes it does not take
 *          are dropped (and counted): a transport that has to chunk (a Bluetooth packet is
 *          20 to 244 bytes) queues the rest itself.
 */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rnc_rnode_io {
  int (*read)(void *context, uint8_t *buffer, size_t capacity);
  int (*write)(void *context, const uint8_t *data, size_t size);
  void *context;
} rnc_rnode_io;

#ifdef __cplusplus
}
#endif
#endif
