/* LoRa interface adapter; see rnc_lora_if.h. */
#include "rnc_lora_if.h"
#include <string.h>

enum { S_DOWN = 0, S_RX = 1, S_CONTEND = 2, S_TX = 3 };
#define RETRY_US 10000000u

void rnc_lora_if_init(rnc_lora_if *li, rnc_modem *modem, const rnc_radio_hal *hal,
                      uint32_t (*random32)(void *context), void *random_context,
                      uint32_t airtime_hundredths) {
  memset(li, 0, sizeof(*li));
  li->modem = modem;
  li->hal = hal;
  li->random32 = random32;
  li->random_context = random_context;
  li->last_seq = 0xFFu;
  rnc_airtime_init(&li->budget, airtime_hundredths);
}

int rnc_lora_if_start(rnc_lora_if *li, const rnc_lora_params *params) {
  int r;
  uint64_t toa255;
  li->params = *params;
  if (!li->params.preamble_symbols)
    li->params.preamble_symbols = (uint16_t)rnc_lora_default_preamble(
        params->bw_hz, params->sf, params->cr);
  li->state = S_DOWN;
  r = li->modem->ops->init(li->modem, &li->params);
  if (r != 0) {
    li->retry_us = li->hal->now_us(li->hal->context) + RETRY_US;
    return r;
  }
  toa255 = rnc_lora_toa_us(&li->params, 255u);
  rnc_air_rx_init(&li->air, 2000000u + toa255 / 2u, 10000000u);
  rnc_air_rx_set_max(&li->air, RNC_LORA_MTU); /* Reticulum never sends more than its MTU */
  rnc_csma_init(&li->csma, rnc_lora_symbol_us(params->bw_hz, params->sf),
                rnc_lora_bitrate(&li->params) > 30000u);
  if (li->modem->ops->start_rx(li->modem) != 0) {
    li->retry_us = li->hal->now_us(li->hal->context) + RETRY_US;
    return -6;
  }
  li->q_head = li->q_count = 0;
  li->state = S_RX;
  return 0;
}

int rnc_lora_if_up(const rnc_lora_if *li) { return li->state != S_DOWN; }

uint32_t rnc_lora_if_bitrate(const rnc_lora_if *li) { return rnc_lora_bitrate(&li->params); }

int rnc_lora_if_send(rnc_lora_if *li, const uint8_t *packet, size_t size, uint64_t now_us) {
  unsigned slot;
  if (li->state == S_DOWN || !packet || size == 0u || size > RNC_AIR_PACKET_MAX)
    return -1;
  if (li->q_count >= RNC_LORA_TXQ) {
    li->stats.tx_dropped_queue++;
    return -1;
  }
  slot = (li->q_head + li->q_count) % RNC_LORA_TXQ;
  memcpy(li->q[slot], packet, size);
  li->q_size[slot] = (uint16_t)size;
  li->q_time_ms[slot] = now_us / 1000u;
  li->q_count++;
  return 0;
}

size_t rnc_lora_if_recv(rnc_lora_if *li, uint8_t *out, size_t capacity) {
  size_t n = li->rx_size;
  if (!n || n > capacity)
    return 0;
  memcpy(out, li->rx, n);
  li->rx_size = 0;
  return n;
}

static void queue_pop(rnc_lora_if *li) {
  li->q_head = (uint8_t)((li->q_head + 1u) % RNC_LORA_TXQ);
  li->q_count--;
  li->budget_waiting = 0;
}

static void poll_receive(rnc_lora_if *li, uint64_t now_us) {
  uint8_t frame[RNC_AIR_FRAME_MAX], packet[RNC_AIR_PACKET_MAX];
  rnc_modem_rx_info info;
  unsigned rounds;
  for (rounds = 0; rounds < 4u; rounds++) {
    int n = li->modem->ops->poll_rx(li->modem, frame, sizeof(frame), &info);
    size_t got;
    if (n == 0)
      break;
    if (n < 0) {
      li->stats.rx_crc_errors++;
      continue;
    }
    li->stats.rx_frames++;
    li->stats.last_rssi_dbm = info.rssi_dbm;
    li->stats.last_snr_quarter_db = info.snr_quarter_db;
    got = rnc_air_rx_frame(&li->air, frame, (size_t)n, now_us, packet);
    if (got) {
      if (li->rx_size) {
        li->stats.rx_overrun++;
      } else {
        memcpy(li->rx, packet, got);
        li->rx_size = (uint16_t)got;
        li->stats.rx_packets++;
        if (got > li->stats.rx_largest)
          li->stats.rx_largest = (uint32_t)got;
      }
    }
  }
  rnc_air_rx_tick(&li->air, now_us);
}

/* builds frame `li->tx_frame` of the head packet and starts it; 0 or -1 */
static int start_frame(rnc_lora_if *li) {
  const uint8_t *packet = li->q[li->q_head];
  size_t size = li->q_size[li->q_head];
  size_t n = rnc_air_build(packet, size, li->tx_seq, li->tx_frame, li->frame);
  if (!n || li->modem->ops->start_tx(li->modem, li->frame, n) != 0)
    return -1;
  li->stats.tx_frames++;
  return 0;
}

static void resume_rx(rnc_lora_if *li, uint64_t now_us) {
  if (li->modem->ops->start_rx(li->modem) != 0) {
    li->state = S_DOWN;
    li->retry_us = now_us + RETRY_US;
  } else {
    li->state = S_RX;
  }
}

unsigned rnc_lora_if_step(rnc_lora_if *li, uint64_t now_us) {
  uint64_t now_ms = now_us / 1000u;
  if (li->state == S_DOWN) {
    if (li->retry_us && now_us >= li->retry_us) {
      li->stats.restarts++;
      (void)rnc_lora_if_start(li, &li->params);
    }
    return 1000u;
  }
  if (li->state == S_TX) {
    int r = li->modem->ops->poll_tx(li->modem);
    if (r == 0)
      return 2u;
    if (r < 0) {
      li->stats.tx_failures++;
      queue_pop(li);
      resume_rx(li, now_us);
      return 2u;
    }
    if (li->tx_frame + 1u < li->tx_frames) { /* the second half follows at once */
      li->tx_frame++;
      if (start_frame(li) != 0) {
        li->stats.tx_failures++;
        queue_pop(li);
        resume_rx(li, now_us);
      }
      return 2u;
    }
    li->stats.tx_packets++;
    if (li->q_size[li->q_head] > li->stats.tx_largest)
      li->stats.tx_largest = li->q_size[li->q_head];
    queue_pop(li);
    resume_rx(li, now_us);
    return 2u;
  }

  poll_receive(li, now_us);

  if (li->state == S_RX && li->q_count) {
    uint8_t slot = li->q_head;
    uint64_t toa_ms;
    int allowed;
    if (now_ms - li->q_time_ms[slot] > RNC_LORA_TXQ_LIFE_MS) {
      li->stats.tx_dropped_stale++;
      queue_pop(li);
    } else {
      toa_ms = (rnc_lora_packet_toa_us(&li->params, li->q_size[slot]) + 999u) / 1000u;
      allowed = toa_ms > 0xFFFFFFFFu ? 2 : rnc_airtime_allows(&li->budget, now_ms, (uint32_t)toa_ms);
      if (allowed == 2) { /* longer than the whole budget: it can never be sent */
        li->budget.denied++;
        li->stats.tx_dropped_budget++;
        queue_pop(li);
      } else if (allowed == 1) {
        rnc_csma_begin(&li->csma);
        li->state = S_CONTEND;
      } else if (!li->budget_waiting) {
        li->budget_waiting = 1;
        li->budget.denied++;
        li->stats.tx_deferred_budget++;
      }
    }
  }

  if (li->state == S_CONTEND) {
    int busy = li->modem->ops->carrier(li->modem);
    uint32_t before = li->csma.deferrals;
    int go = rnc_csma_step(&li->csma, now_ms, busy, li->random32(li->random_context));
    li->stats.deferrals += li->csma.deferrals - before;
    if (go) {
      uint64_t toa_ms = (rnc_lora_packet_toa_us(&li->params, li->q_size[li->q_head]) + 999u) / 1000u;
      /* the budget is checked again at the moment of transmission, not only when the wait
       * began (the window moves on while waiting for the channel) */
      if (rnc_airtime_allows(&li->budget, now_ms, (uint32_t)toa_ms) != 1) {
        li->state = S_RX;
      } else {
        li->tx_seq = (uint8_t)rnc_air_next_sequence(li->last_seq, li->random32(li->random_context));
        li->last_seq = li->tx_seq;
        li->tx_frame = 0;
        li->tx_frames = (uint8_t)rnc_air_frames(li->q_size[li->q_head]);
        rnc_airtime_book(&li->budget, now_ms, (uint32_t)toa_ms);
        if (start_frame(li) != 0) {
          li->stats.tx_failures++;
          queue_pop(li);
          resume_rx(li, now_us);
        } else {
          li->state = S_TX;
        }
      }
    }
  }
  return li->state == S_RX && !li->q_count ? 5u : 2u;
}
