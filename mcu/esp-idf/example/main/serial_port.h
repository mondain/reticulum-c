#ifndef SERIAL_PORT_H
#define SERIAL_PORT_H
/* The board's serial port (a UART behind the USB bridge, or the built-in USB
 * Serial/JTAG, chosen in menuconfig). It carries the HDLC stream in serial mode and
 * the provisioning console / status text in Wi-Fi mode. */
#include "esp_err.h"
#include <stddef.h>
#include <stdint.h>

esp_err_t serial_port_init(void);
size_t serial_port_write(void *context, const uint8_t *data, size_t size);
size_t serial_port_read(void *context, uint8_t *buffer, size_t capacity);
/* text for a person (provisioning console, Wi-Fi mode status); LF becomes CR LF */
void serial_port_print(const char *text);
#endif
