/* Air framing of Reticulum packets on LoRa; see rnc_lora_air.h. */
#include "rnc_lora_air.h"
#include <string.h>

unsigned rnc_air_frames(size_t n) {
  if (n == 0 || n > RNC_AIR_PACKET_MAX)
    return 0;
  return n <= RNC_AIR_FRAGMENT ? 1u : 2u;
}

uint8_t rnc_air_header(unsigned sequence, int split) {
  return (uint8_t)(((sequence & 0x0Fu) << 4) | (split ? RNC_AIR_FLAG_SPLIT : 0u));
}

size_t rnc_air_build(const uint8_t *packet, size_t n, unsigned sequence, unsigned index,
                     uint8_t *out) {
  unsigned frames = rnc_air_frames(n);
  size_t offset, count;
  if (!packet || !out || !frames || index >= frames)
    return 0;
  offset = index * RNC_AIR_FRAGMENT;
  count = frames == 1u ? n : (index == 0u ? RNC_AIR_FRAGMENT : n - RNC_AIR_FRAGMENT);
  out[0] = rnc_air_header(sequence, frames == 2u);
  memcpy(out + 1, packet + offset, count);
  return count + 1u;
}

unsigned rnc_air_next_sequence(unsigned previous, uint32_t random) {
  unsigned s = (unsigned)(random & 0x0Fu);
  if (previous <= 15u && s == (previous & 0x0Fu))
    s = (s + 1u + (unsigned)((random >> 4) % 15u)) & 0x0Fu;
  return s;
}

/* ---- receive ----------------------------------------------------------------- */
static uint32_t fnv1a(const uint8_t *d, size_t n) {
  uint32_t h = 2166136261u;
  size_t i;
  for (i = 0; i < n; i++)
    h = (h ^ d[i]) * 16777619u;
  return h;
}

void rnc_air_rx_init(rnc_air_rx *rx, uint64_t timeout_us, uint64_t dup_window_us) {
  memset(rx, 0, sizeof(*rx));
  rx->pending_seq = RNC_AIR_SEQ_NONE;
  rx->last_seq = RNC_AIR_SEQ_NONE;
  rx->timeout_us = timeout_us;
  rx->dup_window_us = dup_window_us;
  rx->max_packet = RNC_AIR_PACKET_MAX;
}

void rnc_air_rx_set_max(rnc_air_rx *rx, size_t max) {
  rx->max_packet = max > RNC_AIR_PACKET_MAX ? RNC_AIR_PACKET_MAX : max;
}

static void drop_pending(rnc_air_rx *rx) {
  rx->pending_seq = RNC_AIR_SEQ_NONE;
  rx->pending_size = 0;
}

void rnc_air_rx_tick(rnc_air_rx *rx, uint64_t now_us) {
  if (rx->pending_seq != RNC_AIR_SEQ_NONE && rx->timeout_us &&
      now_us - rx->pending_since_us >= rx->timeout_us) {
    rx->dropped_expired++;
    drop_pending(rx);
  }
}

size_t rnc_air_rx_frame(rnc_air_rx *rx, const uint8_t *frame, size_t size, uint64_t now_us,
                        uint8_t *out) {
  unsigned seq;
  const uint8_t *body;
  size_t n;
  rnc_air_rx_tick(rx, now_us);
  if (!frame || size < 2u || size > RNC_AIR_FRAME_MAX) {
    /* an empty body is the header-only frame some senders add after a full-size
     * packet; it carries nothing and must not disturb a pending half either */
    rx->dropped_bad++;
    return 0;
  }
  seq = frame[0] >> 4;
  body = frame + 1;
  n = size - 1u;
  if (!(frame[0] & RNC_AIR_FLAG_SPLIT)) {
    if (rx->pending_seq != RNC_AIR_SEQ_NONE) {
      rx->dropped_orphans++;
      drop_pending(rx);
    }
    memcpy(out, body, n);
    rx->delivered++;
    return n;
  }
  if (rx->pending_seq != RNC_AIR_SEQ_NONE && rx->pending_seq == seq &&
      rx->pending_size + n <= rx->max_packet) {
    if (n == rx->pending_size && !memcmp(body, rx->pending, n)) {
      rx->dropped_dup++; /* the same frame again, not the second half */
      return 0;
    }
    {
      size_t total = rx->pending_size + n;
      uint32_t hash;
      memcpy(out, rx->pending, rx->pending_size);
      memcpy(out + rx->pending_size, body, n);
      drop_pending(rx);
      hash = fnv1a(out, total);
      if (rx->last_seq == seq && rx->last_hash == hash && rx->dup_window_us &&
          now_us - rx->last_us < rx->dup_window_us) {
        rx->dropped_dup++;
        return 0;
      }
      rx->last_seq = seq;
      rx->last_hash = hash;
      rx->last_us = now_us;
      rx->delivered++;
      return total;
    }
  }
  /* the first half of a packet (a different sequence number replaces a pending half) */
  if (n != RNC_AIR_FRAGMENT) {
    /* not a first half: a stray second half whose first half was lost. The stock receiver
     * would replace the pending half by it; a pending half of another packet is lost the
     * same way here, but the stray is not kept, so it cannot be glued to a later frame */
    rx->dropped_bad++;
    if (rx->pending_seq != RNC_AIR_SEQ_NONE) {
      rx->dropped_orphans++;
      drop_pending(rx);
    }
    return 0;
  }
  if (rx->pending_seq == seq && !memcmp(body, rx->pending, n)) {
    rx->dropped_dup++; /* the first half again: keep waiting for the second */
    return 0;
  }
  if (rx->pending_seq != RNC_AIR_SEQ_NONE)
    rx->restarts++;
  memcpy(rx->pending, body, n);
  rx->pending_size = n;
  rx->pending_seq = seq;
  rx->pending_since_us = now_us;
  return 0;
}
