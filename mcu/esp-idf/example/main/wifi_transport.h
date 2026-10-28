#ifndef WIFI_TRANSPORT_H
#define WIFI_TRANSPORT_H
/* The Wi-Fi TCP transport: station mode, a TCP client to a Reticulum node's
 * TCPServerInterface (HDLC framed, like the serial interface). Plug the functions into
 * the rnc_mcu_platform table; all of them are called from the Reticulum task only.
 *
 * Reconnects at both levels with exponential backoff: the access point (esp_wifi) and
 * the TCP connection. link_up reports whether the TCP connection is established; it
 * is also what drives the connection, so the application must call it every step.
 * The socket is non-blocking with TCP_NODELAY and keepalive; output goes through a
 * bounded queue, and a frame that does not fit is dropped whole. */
#include "esp_err.h"
#include "rnc_mcu_net.h"
#include <stddef.h>
#include <stdint.h>

/* Starts the Wi-Fi station with the credentials in `cfg` (copied) and remembers the
 * server to connect to. The caller guarantees rnc_mcu_cfg_wifi_ready(cfg). */
esp_err_t wifi_transport_start(const rnc_mcu_cfg *cfg);

int wifi_transport_link_up(void *context);
size_t wifi_transport_write(void *context, const uint8_t *data, size_t size);
size_t wifi_transport_read(void *context, uint8_t *buffer, size_t capacity);
#endif
