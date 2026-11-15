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
#include "rnc_rnode_io.h"
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
  uint32_t drops_radio_off; /* host packets dropped because the radio was not on */
  uint32_t drops_queue;   /* host packets the transmit queue could not take */
  uint8_t last_cmd;       /* the command of the last complete frame */
  uint16_t last_len;      /* its payload size */
} rnc_rnode_stats;

typedef struct rnc_rnode {
  rnc_lora_if *li; /* the radio; may be NULL in tests of the framing only */
  uint8_t platform, mcu, board;
  /* what the host has set; the radio runs only when all five are set and the state is on */
  rnc_lora_params p;
  uint8_t set, on;
  uint8_t sf_min;      /* lowest spreading factor the chip takes (5, or 7 for an SX127x) */
  int8_t txp_max;      /* highest output power the board accepts, dBm */
  uint16_t lock_short, lock_long; /* airtime locks, hundredths of a percent; 0 = not set */
  uint32_t default_budget_ms;     /* the budget the owner prepared; restored by _reset */
  uint8_t ready_owed;             /* the queue was full: READY is sent when it has room again */
  uint8_t reset_requested;        /* the host sent RESET (0x55, 0xf8) */
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
/* The limits of this chip and board, from the board table; the defaults (5, 22) are those
 * of the SX126x. A setting outside them is refused, not clipped. */
void rnc_rnode_set_limits(rnc_rnode *rn, uint8_t sf_min, int8_t txp_max_dbm);
/* 1 when the radio is running: every setting made, the state on and the chip up. */
int rnc_rnode_radio_on(const rnc_rnode *rn);
/* Bytes from the host. Never blocks. */
void rnc_rnode_feed(rnc_rnode *rn, const uint8_t *bytes, size_t size, uint64_t now_us);
/* Copies up to `capacity` bytes for the host into `out`; returns how many. */
size_t rnc_rnode_pull(rnc_rnode *rn, uint8_t *out, size_t capacity);
/* Moves bytes between the module and one transport: reads what the host sent, steps the
 * module, writes what the module wants to say. Returns the number of bytes written to the
 * transport. With several transports the owner calls this for the one that is in use (the
 * one that last sent bytes), so replies and received packets go to that one. */
size_t rnc_rnode_pump(rnc_rnode *rn, const rnc_rnode_io *io, uint64_t now_us);
/* One pass of the work; returns the milliseconds after which it wants to be called again. */
unsigned rnc_rnode_step(rnc_rnode *rn, uint64_t now_us);
/* 1 once after the host asked for a restart (RESET, 0x55 0xf8): the owner reboots the board.
 * The radio is already off and the settings are cleared. */
int rnc_rnode_reset_requested(rnc_rnode *rn);
/* The host is gone (disconnect, reset): clears the parser and the pending output. */
void rnc_rnode_reset(rnc_rnode *rn);

/* ---- the boot window ------------------------------------------------------------------
 * In rnode mode the serial port carries KISS frames only, but every boot still opens the
 * short setup window in which the line "rnc-config" starts the setup console (so a board
 * can always be switched back without reflashing). A host may start talking at once after
 * a USB-triggered reset and gives up on DETECT after a fraction of a second, so during the
 * window every byte also goes to the module as usual (identity commands cannot start the
 * radio); the window only watches for the console line. */
typedef struct rnc_rnode_window {
  uint8_t line[11]; /* the current line, up to one byte more than the console line */
  uint8_t line_len;
} rnc_rnode_window;
void rnc_rnode_window_init(rnc_rnode_window *w);
/* One byte from the host during the window: passed to `rn` (may be NULL) and watched for
 * the line "rnc-config". Returns 1 when that line has just been completed (by LF or CR). */
int rnc_rnode_window_feed(rnc_rnode_window *w, rnc_rnode *rn, uint8_t byte, uint64_t now_us);

#ifdef __cplusplus
}
#endif
#endif
