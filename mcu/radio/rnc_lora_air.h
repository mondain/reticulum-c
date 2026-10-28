#ifndef RNC_LORA_AIR_H
#define RNC_LORA_AIR_H
/*
 * Over-the-air framing of a Reticulum packet on LoRa, compatible with stock RNodes.
 *
 * Every LoRa frame starts with one header byte:
 *     bits 7..4  sequence number (0..15, random per packet)
 *     bits 3..1  zero when sent (ignored when received)
 *     bit 0      split flag: set on both frames of a packet that does not fit one
 * A packet of up to 254 bytes goes in one frame: header + packet (at most 255 bytes,
 * the LoRa payload limit), split flag clear. A larger packet (up to 508 bytes, the
 * RNode MTU) goes in two frames with the same header (split flag set, same sequence
 * number): the first carries exactly 254 packet bytes, the second the rest.
 *
 * Reception follows the stock receiver: a frame without the split flag is a whole
 * packet (and drops a pending first half); a split frame is the first half when
 * nothing is pending or its sequence number differs from the pending one (the pending
 * half is dropped), and the second half when the sequence number matches. This
 * implementation adds, for robustness (none of it changes what is sent):
 *   - a first half is only kept if it carries exactly 254 bytes (no sender splits
 *     otherwise), which also makes the trailing empty frame some firmware sends after
 *     a 508 byte packet harmless;
 *   - a pending first half expires after `timeout_us` (orphan fragments);
 *   - a frame identical to the pending first half is a duplicate and is ignored, so
 *     it cannot be taken for the second half;
 *   - a completed packet is only delivered once per sequence number and content
 *     within the duplicate window (the last completed packet is remembered), so a
 *     second copy of the same two frames is not delivered twice.
 */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RNC_AIR_FRAME_MAX 255u    /* LoRa payload limit: header + 254 */
#define RNC_AIR_HEADER 1u
#define RNC_AIR_FRAGMENT 254u     /* packet bytes in one frame */
#define RNC_AIR_PACKET_MAX 508u   /* two full frames */
#define RNC_AIR_FLAG_SPLIT 0x01u
#define RNC_AIR_SEQ_NONE 0xFFu

/* ---- transmit side ---------------------------------------------------------- */
/* 1 for a packet of up to 254 bytes, 2 up to 508, 0 for 0 or more than 508. */
unsigned rnc_air_frames(size_t packet_size);
/* The header byte for a packet with this sequence number (0..15). */
uint8_t rnc_air_header(unsigned sequence, int split);
/* Builds frame `index` (0 or 1) of the packet into out[RNC_AIR_FRAME_MAX]; returns its
 * size, 0 on bad arguments. */
size_t rnc_air_build(const uint8_t *packet, size_t packet_size, unsigned sequence,
                     unsigned index, uint8_t *out);
/* A sequence number for the next packet: random nibble, never equal to `previous`
 * (so two packets in a row cannot be confused for halves of one). */
unsigned rnc_air_next_sequence(unsigned previous, uint32_t random);

/* ---- receive side ----------------------------------------------------------- */
typedef struct rnc_air_rx {
  uint8_t pending[RNC_AIR_FRAGMENT]; /* the first half */
  size_t pending_size;
  unsigned pending_seq;              /* RNC_AIR_SEQ_NONE when nothing is pending */
  uint64_t pending_since_us;
  uint64_t timeout_us;               /* 0 = never expire */
  /* duplicate window: the last completed split packet */
  unsigned last_seq;
  uint32_t last_hash;
  uint64_t last_us;
  uint64_t dup_window_us;
  size_t max_packet;                 /* largest packet accepted (508, or 500 for Reticulum) */
  /* counters */
  uint32_t delivered, dropped_orphans, dropped_expired, dropped_dup, dropped_bad,
      restarts;
} rnc_air_rx;

void rnc_air_rx_init(rnc_air_rx *rx, uint64_t timeout_us, uint64_t dup_window_us);
/* Limits the packet size (default 508). A split frame that is a full 254 bytes cannot be the
 * second half of a packet of at most `max` < 508 bytes, so with the Reticulum MTU of 500 a
 * full-size frame carrying the pending sequence number starts a new packet instead of being
 * glued to the pending half (the stock receiver cannot tell the two apart). */
void rnc_air_rx_set_max(rnc_air_rx *rx, size_t max);
/* Expires an orphan first half whose time has run out; call it from the poll loop. */
void rnc_air_rx_tick(rnc_air_rx *rx, uint64_t now_us);
/* Feeds one received LoRa frame. Returns the packet size (> 0) when a packet is
 * complete (copied to `out`, which must hold RNC_AIR_PACKET_MAX bytes), else 0. */
size_t rnc_air_rx_frame(rnc_air_rx *rx, const uint8_t *frame, size_t size, uint64_t now_us,
                        uint8_t *out);

#ifdef __cplusplus
}
#endif
#endif
