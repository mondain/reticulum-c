#ifndef RNC_NRF52840_VARIANT_H
#define RNC_NRF52840_VARIANT_H
/*
 * Arduino variant for the reticulum-c firmware on nRF52840 boards (RAK4631, Heltec T114,
 * LilyGo T-Echo) with the Adafruit nRF52 core. Its one purpose is an identity pin map:
 * Arduino pin number n is the chip's GPIO n for n < 32 (port 0) and 32 + k for P1.k, so
 * the radio pin numbers of mcu/radio/rnc_boards.c (chip GPIO numbers) can be given to
 * pinMode, digitalWrite and the SPI library as they are. No board LEDs or buttons are
 * assumed and nothing is driven at boot. Written for this project.
 */
#include "WVariant.h"

#ifdef __cplusplus
extern "C" {
#endif

/* the boards have a 32.768 kHz crystal (the core insists on knowing the low frequency clock) */
#define USE_LFXO

#define PINS_COUNT (48)
#define NUM_DIGITAL_PINS (48)
#define NUM_ANALOG_INPUTS (0)
#define NUM_ANALOG_OUTPUTS (0)

/* the core wants an LED and its polarity; no pin is an LED here (an unused pin number) */
#define PIN_LED1 (0xFF)
#define LED_BUILTIN PIN_LED1
#define LED_CONN PIN_LED1
#define LED_RED PIN_LED1
#define LED_BLUE PIN_LED1
#define LED_STATE_ON 0

/* UART pins and SPI/Wire defaults: not connected to anything the firmware uses (Serial is
 * the native USB port) */
#define PIN_SERIAL1_RX (0xFF)
#define PIN_SERIAL1_TX (0xFF)
#define PIN_SERIAL2_RX (0xFF)
#define PIN_SERIAL2_TX (0xFF)

#define SPI_INTERFACES_COUNT 1
#define PIN_SPI_MISO (0xFF)
#define PIN_SPI_MOSI (0xFF)
#define PIN_SPI_SCK (0xFF)

static const uint8_t SS = 0xFF;
static const uint8_t MOSI = PIN_SPI_MOSI;
static const uint8_t MISO = PIN_SPI_MISO;
static const uint8_t SCK = PIN_SPI_SCK;

#define WIRE_INTERFACES_COUNT 1
#define PIN_WIRE_SDA (0xFF)
#define PIN_WIRE_SCL (0xFF)

#ifdef __cplusplus
}
#endif
#endif
