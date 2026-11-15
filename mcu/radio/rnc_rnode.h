#ifndef RNC_RNODE_H
#define RNC_RNODE_H
/*
 * The device side of the RNode KISS protocol: the board is a LoRa modem that a host
 * (Sideband, rnsd, this project's host RNode adapter) drives. The host sends KISS frames
 * with radio settings and packets; the module answers with the applied settings, received
 * packets and signal figures. No Reticulum node runs on the board in this mode.
 *
 * The module owns no hardware and no clock. The owner feeds it the bytes from the host
 * (rnc_rnode_feed), sends what it wants to say (rnc_rnode_pull) and calls rnc_rnode_step.
 * The radio is an rnc_lora_if the owner prepared with rnc_lora_if_init; the module starts,
 * reconfigures and stops it as the host commands (see docs/rnode-mode-design.txt).
 *
 * Command values follow src/host_posix.c of this project (the host side of the same
 * protocol) and RNodeInterface.py of Reticulum 1.5.5.
 */
#include "rnc_lora_if.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* the firmware version reported to the host; the project's host adapter requires 1.52 and
 * the multi-radio check 1.74 */
#define RNC_RNODE_FW_MAJOR 1
#define RNC_RNODE_FW_MINOR 74

/* the largest frame body accepted: command byte plus a packet plus slack */
#define RNC_RNODE_IN_MAX (RNC_AIR_PACKET_MAX + 8u)
/* bytes waiting for the host: a received packet escaped in the worst case, plus reports */
#define RNC_RNODE_OUT_MAX 2400u

typedef struct rnc_rnode_stats {
  uint32_t frames_ok;     /* complete frames handled */
  uint32_t frames_bad;    /* frames dropped: bad escape or longer than RNC_RNODE_IN_MAX */
  uint32_t out_dropped;   /* replies dropped because the host side was not draining */
  uint8_t last_cmd;       /* the command of the last complete frame */
  uint16_t last_len;      /* its payload size */
} rnc_rnode_stats;

typedef struct rnc_rnode {
  rnc_lora_if *li; /* the radio; may be NULL in tests of the framing only */
  uint8_t platform, mcu, board;
  /* parser */
  uint8_t in[RNC_RNODE_IN_MAX];
  uint16_t in_len;
  uint8_t in_frame, in_escaped, in_discard;
  /* bytes for the host */
  uint8_t out[RNC_RNODE_OUT_MAX];
  uint16_t out_len;
  rnc_rnode_stats stats;
} rnc_rnode;

/* `platform`, `mcu` and `board` are the identity bytes reported for commands 0x48, 0x49
 * and 0x47. */
void rnc_rnode_init(rnc_rnode *rn, rnc_lora_if *li, uint8_t platform, uint8_t mcu, uint8_t board);
/* Bytes from the host. Never blocks. */
void rnc_rnode_feed(rnc_rnode *rn, const uint8_t *bytes, size_t size, uint64_t now_us);
/* Copies up to `capacity` bytes for the host into `out`; returns how many. */
size_t rnc_rnode_pull(rnc_rnode *rn, uint8_t *out, size_t capacity);
/* One pass of the work; returns the milliseconds after which it wants to be called again. */
unsigned rnc_rnode_step(rnc_rnode *rn, uint64_t now_us);
/* The host is gone (disconnect, reset): clears the parser and the pending output. */
void rnc_rnode_reset(rnc_rnode *rn);

#ifdef __cplusplus
}
#endif
#endif
