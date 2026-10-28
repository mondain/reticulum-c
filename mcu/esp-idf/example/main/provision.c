#include "provision.h"
#include "driver/gpio.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "net_settings.h"
#include "serial_port.h"
#include <string.h>

#define ENTRY_LINE "rnc-config"

int provision_requested(unsigned window_ms, int button_gpio) {
  char line[24];
  size_t length = 0;
  unsigned elapsed, low_ms = 0;
  uint8_t byte;
  if (window_ms == 0)
    return 0;
  if (button_gpio >= 0) {
    gpio_config_t io = {
        .pin_bit_mask = 1ULL << button_gpio,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
    };
    (void)gpio_config(&io);
  }
  for (elapsed = 0; elapsed < window_ms; elapsed += 10) {
    while (serial_port_read(NULL, &byte, 1) == 1) {
      if (byte == '\r' || byte == '\n') {
        line[length] = 0;
        if (length == strlen(ENTRY_LINE) && !memcmp(line, ENTRY_LINE, length))
          return 1;
        length = 0;
      } else if (length + 1 < sizeof(line)) {
        line[length++] = (char)byte;
      } else {
        length = 0; /* too long to be our line; whatever follows is judged afresh */
      }
    }
    if (button_gpio >= 0) {
      low_ms = gpio_get_level((gpio_num_t)button_gpio) == 0 ? low_ms + 10 : 0;
      if (low_ms >= 300)
        return 1;
    }
    vTaskDelay(pdMS_TO_TICKS(10) ? pdMS_TO_TICKS(10) : 1);
  }
  return 0;
}

static int hides_input(const rnc_mcu_console *con) {
  /* the password is echoed as * while it is typed */
  return con->length >= 12 && !strncmp(con->line, "set password", 12);
}

void provision_console(rnc_mcu_cfg *cfg, const char *reason) {
  rnc_mcu_console con;
  char reply[512];
  uint8_t byte;
  rnc_mcu_console_init(&con);
  serial_port_print("\n\nreticulum-c provisioning console\n");
  serial_port_print(reason);
  serial_port_print("\nThe Reticulum node is not running. Type help. Settings are stored with "
                    "save, and used after reboot.\n");
  rnc_mcu_console_get(cfg, NULL, reply, sizeof(reply));
  serial_port_print(reply);
  serial_port_print("\nrnc> ");
  for (;;) {
    if (serial_port_read(NULL, &byte, 1) != 1) {
      vTaskDelay(pdMS_TO_TICKS(10) ? pdMS_TO_TICKS(10) : 1);
      continue;
    }
    if (byte == '\r' || byte == '\n') {
      unsigned actions;
      size_t had = con.length;
      reply[0] = 0;
      actions = rnc_mcu_console_feed(&con, cfg, byte, reply, sizeof(reply));
      if (had || reply[0]) {
        serial_port_print("\n");
        if (reply[0]) {
          serial_port_print(reply);
          serial_port_print("\n");
        }
      }
      if (actions & RNC_MCU_CONSOLE_SAVE) {
        serial_port_print(net_settings_save(cfg) == ESP_OK ? "stored\n" : "error: cannot store\n");
      }
      if (actions & RNC_MCU_CONSOLE_REBOOT) {
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_restart();
      }
      if (had)
        serial_port_print("rnc> ");
    } else {
      size_t before = con.length;
      int hide = hides_input(&con);
      reply[0] = 0;
      (void)rnc_mcu_console_feed(&con, cfg, byte, reply, sizeof(reply));
      if (con.length > before) { /* accepted: echo it */
        uint8_t shown = hide ? (uint8_t)'*' : byte;
        (void)serial_port_write(NULL, &shown, 1);
      } else if (con.length < before) { /* backspace */
        serial_port_print("\b \b");
      }
    }
  }
}
