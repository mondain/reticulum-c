/* ESP-IDF radio HAL; see radio_hal_idf.h. NOT RUN ON HARDWARE: compiled only. */
#include "radio_hal_idf.h"
#include "driver/gpio.h"
#include "driver/i2c.h"
#include "driver/spi_master.h"
#include "esp_rom_sys.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

#define RADIO_SPI_HOST SPI2_HOST
#define RADIO_SPI_HZ 4000000

static struct {
  spi_device_handle_t spi;
  int8_t pin[RNC_PIN_COUNT];
  uint8_t ready;
} s_hal;

static int hal_spi(void *context, const uint8_t *tx, uint8_t *rx, size_t len) {
  spi_transaction_t t;
  (void)context;
  if (!s_hal.ready || len == 0 || len > 260)
    return -1;
  memset(&t, 0, sizeof(t));
  t.length = len * 8;
  t.tx_buffer = tx; /* NULL sends zeros */
  t.rx_buffer = rx;
  return spi_device_polling_transmit(s_hal.spi, &t) == ESP_OK ? 0 : -1;
}

static void hal_write(void *context, rnc_radio_pin pin, int level) {
  (void)context;
  if (pin < RNC_PIN_COUNT && s_hal.pin[pin] >= 0)
    gpio_set_level((gpio_num_t)s_hal.pin[pin], level ? 1 : 0);
}

static int hal_read(void *context, rnc_radio_pin pin) {
  (void)context;
  if (pin >= RNC_PIN_COUNT || s_hal.pin[pin] < 0)
    return -1;
  return gpio_get_level((gpio_num_t)s_hal.pin[pin]);
}

static void hal_delay(void *context, uint32_t us) {
  (void)context;
  if (us >= 2000u)
    vTaskDelay((pdMS_TO_TICKS(us / 1000u) ? pdMS_TO_TICKS(us / 1000u) : 1) + 1);
  else
    esp_rom_delay_us(us);
}

static uint64_t hal_now(void *context) {
  (void)context;
  return (uint64_t)esp_timer_get_time();
}

static void pin_out(int pin, int level) {
  gpio_config_t io = {.pin_bit_mask = 1ULL << pin, .mode = GPIO_MODE_OUTPUT};
  if (pin < 0)
    return;
  (void)gpio_config(&io);
  gpio_set_level((gpio_num_t)pin, level);
}
static void pin_in(int pin) {
  gpio_config_t io = {.pin_bit_mask = 1ULL << pin, .mode = GPIO_MODE_INPUT};
  if (pin < 0)
    return;
  (void)gpio_config(&io);
}

/* The T-Beam v1.0/v1.1 power the LoRa module from LDO2 of the AXP192, which must be set to
 * 3.3 V and switched on over I2C before the radio answers. Register numbers from the AXP192
 * data sheet: 0x28 LDO2/LDO3 voltage (high nibble LDO2, 1.8 V + 0.1 V per step), 0x12 output
 * enable (bit 2: LDO2). Address 0x34. UNTESTED. */
static int axp192_enable_lora(int sda, int scl) {
  i2c_config_t cfg;
  uint8_t reg28[2] = {0x28, 0}, set28[2], reg12[2] = {0x12, 0}, set12[2];
  uint8_t v;
  memset(&cfg, 0, sizeof(cfg));
  cfg.mode = I2C_MODE_MASTER;
  cfg.sda_io_num = sda;
  cfg.scl_io_num = scl;
  cfg.sda_pullup_en = GPIO_PULLUP_ENABLE;
  cfg.scl_pullup_en = GPIO_PULLUP_ENABLE;
  cfg.master.clk_speed = 100000;
  if (i2c_param_config(I2C_NUM_0, &cfg) != ESP_OK ||
      i2c_driver_install(I2C_NUM_0, I2C_MODE_MASTER, 0, 0, 0) != ESP_OK)
    return -1;
  if (i2c_master_write_read_device(I2C_NUM_0, 0x34, reg28, 1, &v, 1, pdMS_TO_TICKS(100)) != ESP_OK)
    return -1;
  set28[0] = 0x28;
  set28[1] = (uint8_t)((v & 0x0F) | 0xF0); /* LDO2 = 3.3 V, LDO3 unchanged */
  if (i2c_master_write_to_device(I2C_NUM_0, 0x34, set28, 2, pdMS_TO_TICKS(100)) != ESP_OK)
    return -1;
  if (i2c_master_write_read_device(I2C_NUM_0, 0x34, reg12, 1, &v, 1, pdMS_TO_TICKS(100)) != ESP_OK)
    return -1;
  set12[0] = 0x12;
  set12[1] = (uint8_t)(v | 0x04); /* LDO2 on */
  if (i2c_master_write_to_device(I2C_NUM_0, 0x34, set12, 2, pdMS_TO_TICKS(100)) != ESP_OK)
    return -1;
  (void)reg28;
  vTaskDelay(pdMS_TO_TICKS(20));
  i2c_driver_delete(I2C_NUM_0);
  return 0;
}

int radio_hal_idf_init(const rnc_board *board, rnc_radio_hal *hal) {
  spi_bus_config_t bus;
  spi_device_interface_config_t dev;
  if (!board || !board->supported)
    return -1;
  memset(&s_hal, 0, sizeof(s_hal));
  memset(s_hal.pin, -1, sizeof(s_hal.pin));
  s_hal.pin[RNC_PIN_RESET] = board->reset;
  s_hal.pin[RNC_PIN_BUSY] = board->busy;
  s_hal.pin[RNC_PIN_DIO] = board->dio;
  s_hal.pin[RNC_PIN_RXEN] = board->rxen;
  s_hal.pin[RNC_PIN_TXEN] = board->txen;
  if (board->power_pin >= 0)
    pin_out(board->power_pin, 1);
  if (board->pmu == RNC_BOARD_PMU_AXP192 && axp192_enable_lora(board->i2c_sda, board->i2c_scl) != 0)
    return -2;
  if (board->pmu == RNC_BOARD_PMU_AXP2101)
    return -3; /* not implemented */
  pin_out(board->reset, 1);
  pin_out(board->rxen, 0);
  pin_out(board->txen, 0);
  pin_in(board->busy);
  pin_in(board->dio);
  memset(&bus, 0, sizeof(bus));
  bus.mosi_io_num = board->mosi;
  bus.miso_io_num = board->miso;
  bus.sclk_io_num = board->sck;
  bus.quadwp_io_num = -1;
  bus.quadhd_io_num = -1;
  bus.max_transfer_sz = 300;
  if (spi_bus_initialize(RADIO_SPI_HOST, &bus, SPI_DMA_CH_AUTO) != ESP_OK)
    return -4;
  memset(&dev, 0, sizeof(dev));
  dev.clock_speed_hz = RADIO_SPI_HZ;
  dev.mode = 0;
  dev.spics_io_num = board->cs;
  dev.queue_size = 1;
  if (spi_bus_add_device(RADIO_SPI_HOST, &dev, &s_hal.spi) != ESP_OK)
    return -5;
  s_hal.ready = 1;
  memset(hal, 0, sizeof(*hal));
  hal->spi_transfer = hal_spi;
  hal->gpio_write = hal_write;
  hal->gpio_read = hal_read;
  hal->delay_us = hal_delay;
  hal->now_us = hal_now;
  return 0;
}
