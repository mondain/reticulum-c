#include "serial_port.h"
#include "sdkconfig.h"

#if defined(CONFIG_RETICULUM_MCU_TRANSPORT_USB_SERIAL_JTAG)
#include "driver/usb_serial_jtag.h"
#include "freertos/FreeRTOS.h"
esp_err_t serial_port_init(void) {
  usb_serial_jtag_driver_config_t cfg = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
  cfg.rx_buffer_size = 1024;
  cfg.tx_buffer_size = 1024;
  return usb_serial_jtag_driver_install(&cfg);
}
size_t serial_port_write(void *context, const uint8_t *data, size_t size) {
  int n = usb_serial_jtag_write_bytes(data, size, pdMS_TO_TICKS(50));
  (void)context;
  return n > 0 ? (size_t)n : 0;
}
size_t serial_port_read(void *context, uint8_t *buffer, size_t capacity) {
  int n = usb_serial_jtag_read_bytes(buffer, capacity, 0);
  (void)context;
  return n > 0 ? (size_t)n : 0;
}
#else
#include "driver/uart.h"
#define UART_PORT ((uart_port_t)CONFIG_RETICULUM_MCU_UART_NUM)
esp_err_t serial_port_init(void) {
  uart_config_t cfg = {
      .baud_rate = CONFIG_RETICULUM_MCU_UART_BAUD,
      .data_bits = UART_DATA_8_BITS,
      .parity = UART_PARITY_DISABLE,
      .stop_bits = UART_STOP_BITS_1,
      .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
      .source_clk = UART_SCLK_DEFAULT,
  };
  esp_err_t err = uart_driver_install(UART_PORT, 2048, 0, 0, NULL, 0);
  if (err != ESP_OK)
    return err;
  err = uart_param_config(UART_PORT, &cfg);
  if (err != ESP_OK)
    return err;
  return uart_set_pin(UART_PORT,
                      CONFIG_RETICULUM_MCU_UART_TX_GPIO < 0 ? UART_PIN_NO_CHANGE
                                                            : CONFIG_RETICULUM_MCU_UART_TX_GPIO,
                      CONFIG_RETICULUM_MCU_UART_RX_GPIO < 0 ? UART_PIN_NO_CHANGE
                                                            : CONFIG_RETICULUM_MCU_UART_RX_GPIO,
                      UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
}
size_t serial_port_write(void *context, const uint8_t *data, size_t size) {
  int n = uart_write_bytes(UART_PORT, data, size); /* blocks until queued to the FIFO */
  (void)context;
  return n > 0 ? (size_t)n : 0;
}
size_t serial_port_read(void *context, uint8_t *buffer, size_t capacity) {
  int n = uart_read_bytes(UART_PORT, buffer, capacity, 0);
  (void)context;
  return n > 0 ? (size_t)n : 0;
}
#endif

void serial_port_print(const char *text) {
  for (; *text; text++) {
    uint8_t c = (uint8_t)*text;
    if (c == '\n') {
      static const uint8_t crlf[2] = {'\r', '\n'};
      (void)serial_port_write(NULL, crlf, 2);
    } else {
      (void)serial_port_write(NULL, &c, 1);
    }
  }
}
