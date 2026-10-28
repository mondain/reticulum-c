#ifndef RNC_LORA_IF_H
#define RNC_LORA_IF_H
/*
 * The LoRa interface of a Reticulum node: a radio (rnc_modem) plus the air framing, the
 * CSMA channel access and the airtime budget. The owner calls rnc_lora_if_step() from its
 * loop and exchanges whole Reticulum packets:
 *
 *   rnc_lora_if_send()  queues a packet (up to 508 bytes; Reticulum's MTU of 500 is
 *                       split into two LoRa frames when it exceeds 254 bytes)
 *   rnc_lora_if_recv()  returns the next complete packet received, if any
 *
 * Nothing is transmitted unless the airtime budget allows the whole packet and the
 * channel has been free (see rnc_lora_mac.h). Packets that cannot be sent (queue full,
 * budget exhausted for longer than the queue life, larger than the budget) are dropped
 * and counted; Reticulum tolerates lost packets.
 */
#include "rnc_lora_air.h"
#include "rnc_lora_mac.h"
#include "rnc_lora_phy.h"
#include "rnc_modem.h"
#include "rnc_radio_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef RNC_LORA_TXQ
#define RNC_LORA_TXQ 3u /* packets waiting to be sent */
#endif
/* a queued packet older than this is dropped instead of sent late */
#ifndef RNC_LORA_TXQ_LIFE_MS
#define RNC_LORA_TXQ_LIFE_MS 60000u
#endif
#define RNC_LORA_MTU 500u /* the Reticulum MTU of the interface */

typedef struct rnc_lora_if_stats {
  uint32_t tx_packets, tx_frames, rx_packets, rx_frames;
  uint32_t rx_crc_errors;     /* frames the radio dropped for a bad CRC */
  uint32_t rx_overrun;        /* complete packets lost because the owner had not collected the last */
  uint32_t tx_dropped_queue;  /* queue full */
  uint32_t tx_dropped_stale;  /* waited longer than the queue life */
  uint32_t tx_dropped_budget; /* larger than the whole airtime budget */
  uint32_t tx_deferred_budget;/* waits for budget (counted once per packet) */
  uint32_t tx_failures;       /* the radio did not finish a transmission or refused it */
  uint32_t deferrals;         /* busy channel interrupted the backoff */
  uint32_t restarts;          /* radio initialisations after a failure */
  uint32_t rx_largest, tx_largest; /* biggest packet received and sent, bytes */
  int16_t last_rssi_dbm, last_snr_quarter_db;
} rnc_lora_if_stats;

typedef struct rnc_lora_if {
  rnc_modem *modem;
  const rnc_radio_hal *hal;
  uint32_t (*random32)(void *context);
  void *random_context;
  rnc_lora_params params;
  rnc_airtime budget;
  rnc_csma csma;
  rnc_air_rx air;
  rnc_lora_if_stats stats;
  uint8_t state; /* 0 down, 1 receiving, 2 waiting for the channel, 3 transmitting */
  uint64_t retry_us;
  /* transmit queue */
  uint8_t q[RNC_LORA_TXQ][RNC_AIR_PACKET_MAX];
  uint16_t q_size[RNC_LORA_TXQ];
  uint64_t q_time_ms[RNC_LORA_TXQ];
  uint8_t q_head, q_count;
  /* the packet being sent */
  uint8_t tx_seq, tx_frame, tx_frames, last_seq, budget_waiting;
  uint8_t frame[RNC_AIR_FRAME_MAX];
  /* the last received packet, until collected */
  uint8_t rx[RNC_AIR_PACKET_MAX];
  uint16_t rx_size;
} rnc_lora_if;

/* Prepares the interface (no hardware access). `airtime_hundredths`: the budget, 100 =
 * 1 %. `random32` is any source of 32 random bits (backoff, sequence numbers). */
void rnc_lora_if_init(rnc_lora_if *li, rnc_modem *modem, const rnc_radio_hal *hal,
                      uint32_t (*random32)(void *context), void *random_context,
                      uint32_t airtime_hundredths);
/* Initialises the radio with `params` and starts receiving. 0, or a negative driver
 * error (the interface stays down and is retried every ten seconds by _step). */
int rnc_lora_if_start(rnc_lora_if *li, const rnc_lora_params *params);
/* 1 when the radio is running. */
int rnc_lora_if_up(const rnc_lora_if *li);

/* Queues a packet: RNC_OK-style 0 when queued, -1 dropped (queue full, too large). */
int rnc_lora_if_send(rnc_lora_if *li, const uint8_t *packet, size_t size, uint64_t now_us);
/* Copies the next complete received packet to `out` (capacity at least 508) and returns
 * its size, 0 if none. */
size_t rnc_lora_if_recv(rnc_lora_if *li, uint8_t *out, size_t capacity);

/* One pass of the work: receive, expire, channel access, transmit. Returns the number of
 * milliseconds after which it wants to be called again at the latest. Call it every few
 * milliseconds while receiving or transmitting. */
unsigned rnc_lora_if_step(rnc_lora_if *li, uint64_t now_us);

/* The bit rate to give rnc_node_add_interface (RNode style, from the modem settings). */
uint32_t rnc_lora_if_bitrate(const rnc_lora_if *li);

#ifdef __cplusplus
}
#endif
#endif
