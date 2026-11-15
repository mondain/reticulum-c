#include "rnc_rnode.h"
#include <string.h>

#define FEND 0xC0u
#define FESC 0xDBu
#define TFEND 0xDCu
#define TFESC 0xDDu

#define CMD_BOARD 0x47u
#define CMD_PLATFORM 0x48u
#define CMD_MCU 0x49u
#define CMD_FW_VERSION 0x50u
#define CMD_DETECT 0x08u
#define DETECT_REQ 0x73u
#define DETECT_RESP 0x46u
#define CMD_LEAVE 0x0Au
#define CMD_RESET 0x55u
#define CMD_DATA 0x00u
#define CMD_READY 0x0Fu
#define CMD_STAT_RSSI 0x23u
#define CMD_STAT_SNR 0x24u
#define CMD_FREQUENCY 0x01u
#define CMD_BANDWIDTH 0x02u
#define CMD_TXPOWER 0x03u
#define CMD_SF 0x04u
#define CMD_CR 0x05u
#define CMD_RADIO_STATE 0x06u
#define CMD_ST_ALOCK 0x0Bu
#define CMD_LT_ALOCK 0x0Cu

#define SET_FREQ 0x01u
#define SET_BW 0x02u
#define SET_TXP 0x04u
#define SET_SF 0x08u
#define SET_CR 0x10u
#define SET_ALL 0x1Fu

void rnc_rnode_init(rnc_rnode *rn, rnc_lora_if *li, uint8_t platform, uint8_t mcu, uint8_t board) {
  memset(rn, 0, sizeof(*rn));
  rn->li = li;
  rn->platform = platform;
  rn->mcu = mcu;
  rn->board = board;
  rn->sf_min = 5;
  rn->txp_max = 22;
  if (li)
    rn->default_budget_ms = li->budget.budget_ms;
}

void rnc_rnode_set_limits(rnc_rnode *rn, uint8_t sf_min, int8_t txp_max_dbm) {
  rn->sf_min = sf_min;
  rn->txp_max = txp_max_dbm;
}

int rnc_rnode_radio_on(const rnc_rnode *rn) {
  return rn->on && rn->set == SET_ALL && rn->li && rnc_lora_if_up(rn->li);
}

/* appends one KISS frame to the output; the whole frame or nothing */
static void put_frame(rnc_rnode *rn, uint8_t cmd, const uint8_t *data, size_t size) {
  size_t i, need = 3u + size * 2u;
  uint8_t *p;
  if (RNC_RNODE_OUT_MAX - rn->out_len < need) {
    rn->stats.out_dropped++;
    return;
  }
  p = rn->out + rn->out_len;
  *p++ = FEND;
  *p++ = cmd; /* the commands this module sends never need escaping */
  for (i = 0; i < size; i++) {
    if (data[i] == FEND) {
      *p++ = FESC;
      *p++ = TFEND;
    } else if (data[i] == FESC) {
      *p++ = FESC;
      *p++ = TFESC;
    } else {
      *p++ = data[i];
    }
  }
  *p++ = FEND;
  rn->out_len = (uint16_t)(p - rn->out);
}

static uint32_t get32(const uint8_t *d) {
  return ((uint32_t)d[0] << 24) | ((uint32_t)d[1] << 16) | ((uint32_t)d[2] << 8) | d[3];
}

/* Starts, reconfigures or stops the radio to match what the host has set. The radio is
 * only ever started here, and only with every setting made and the state on. */
static void apply_radio(rnc_rnode *rn) {
  if (!rn->li)
    return;
  if (rn->on && rn->set == SET_ALL)
    (void)rnc_lora_if_reconfigure(rn->li, &rn->p);
  else if (rnc_lora_if_up(rn->li))
    rnc_lora_if_stop(rn->li);
}

static void apply_airtime(rnc_rnode *rn) {
  uint32_t v = rn->lock_short, l = rn->lock_long;
  if (!rn->li)
    return;
  /* the budget is one hourly percentage: the smaller of the locks the host has set */
  if (!v || (l && l < v))
    v = l;
  if (v)
    rnc_airtime_set_limit(&rn->li->budget, v);
}

static void send_ready(rnc_rnode *rn) {
  static const uint8_t one = 1;
  put_frame(rn, CMD_READY, &one, 1);
}

static void handle(rnc_rnode *rn, uint8_t cmd, const uint8_t *data, size_t size, uint64_t now_us) {
  uint8_t v[2];
  switch (cmd) {
  case CMD_DATA:
    if (size == 0u)
      break;
    if (!rnc_rnode_radio_on(rn)) {
      rn->stats.drops_radio_off++; /* never transmit before the host has configured the radio */
      break;
    }
    if (rnc_lora_if_send(rn->li, data, size, now_us) != 0) {
      rn->stats.drops_queue++;
      break;
    }
    if (rn->li->q_count < RNC_LORA_TXQ)
      send_ready(rn); /* room for another */
    break;
  case CMD_LEAVE: /* the host exits: the radio goes off and nothing is left configured */
    if (size == 1u && data[0] == 0xFFu)
      rnc_rnode_reset(rn);
    break;
  case CMD_RESET:
    if (size == 1u && data[0] == 0xF8u) {
      rnc_rnode_reset(rn);
      rn->reset_requested = 1;
    }
    break;
  case CMD_DETECT:
    if (size == 1u && data[0] == DETECT_REQ) {
      v[0] = DETECT_RESP;
      put_frame(rn, CMD_DETECT, v, 1);
    }
    break;
  case CMD_FW_VERSION:
    v[0] = RNC_RNODE_FW_MAJOR;
    v[1] = RNC_RNODE_FW_MINOR;
    put_frame(rn, CMD_FW_VERSION, v, 2);
    break;
  case CMD_PLATFORM:
    put_frame(rn, CMD_PLATFORM, &rn->platform, 1);
    break;
  case CMD_MCU:
    put_frame(rn, CMD_MCU, &rn->mcu, 1);
    break;
  case CMD_BOARD:
    put_frame(rn, CMD_BOARD, &rn->board, 1);
    break;
  case CMD_FREQUENCY:
    if (size == 4u) {
      uint32_t f = get32(data);
      if (f < 137000000u || f > 1020000000u)
        break;
      rn->p.freq_hz = f;
      rn->set |= SET_FREQ;
      put_frame(rn, cmd, data, 4);
      if (rn->on)
        apply_radio(rn);
    }
    break;
  case CMD_BANDWIDTH:
    if (size == 4u) {
      uint32_t bw = get32(data);
      if (rnc_lora_bw_index(bw) < 0)
        break;
      rn->p.bw_hz = bw;
      rn->set |= SET_BW;
      put_frame(rn, cmd, data, 4);
      if (rn->on)
        apply_radio(rn);
    }
    break;
  case CMD_TXPOWER:
    if (size == 1u) {
      int8_t dbm = (int8_t)data[0];
      if (dbm < -9 || dbm > rn->txp_max)
        break;
      rn->p.txp_dbm = dbm;
      rn->set |= SET_TXP;
      put_frame(rn, cmd, data, 1);
      if (rn->on)
        apply_radio(rn);
    }
    break;
  case CMD_SF:
    if (size == 1u) {
      if (data[0] < rn->sf_min || data[0] > RNC_LORA_SF_MAX)
        break;
      rn->p.sf = data[0];
      rn->set |= SET_SF;
      put_frame(rn, cmd, data, 1);
      if (rn->on)
        apply_radio(rn);
    }
    break;
  case CMD_CR:
    if (size == 1u) {
      if (data[0] < 5u || data[0] > 8u)
        break;
      rn->p.cr = data[0];
      rn->set |= SET_CR;
      put_frame(rn, cmd, data, 1);
      if (rn->on)
        apply_radio(rn);
    }
    break;
  case CMD_RADIO_STATE:
    if (size != 1u || (data[0] > 1u && data[0] != 0xFFu))
      break;
    if (data[0] == 1u) {
      if (rn->set != SET_ALL)
        break; /* not every setting made: no reply, the chip stays untouched */
      rn->on = 1;
      apply_radio(rn);
      if (!rnc_rnode_radio_on(rn)) { /* the chip refused: report it, stay off */
        rn->on = 0;
        apply_radio(rn);
      }
    } else if (data[0] == 0u) {
      rn->on = 0;
      apply_radio(rn);
    }
    v[0] = (uint8_t)rnc_rnode_radio_on(rn); /* the state itself, also for the 0xFF query */
    put_frame(rn, cmd, v, 1);
    break;
  case CMD_ST_ALOCK:
  case CMD_LT_ALOCK:
    if (size == 2u) {
      uint16_t hundredths = (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
      if (hundredths < 1u || hundredths > 10000u)
        break;
      if (cmd == CMD_ST_ALOCK)
        rn->lock_short = hundredths;
      else
        rn->lock_long = hundredths;
      apply_airtime(rn);
      put_frame(rn, cmd, data, 2);
    }
    break;
  default:
    break; /* unknown commands are ignored, as stock RNodes do */
  }
}

static void feed_byte(rnc_rnode *rn, uint8_t b, uint64_t now_us) {
  if (b == FEND) {
    if (rn->in_frame && rn->in_len > 0u) {
      if (rn->in_discard || rn->in_escaped) {
        rn->stats.frames_bad++;
      } else {
        rn->stats.frames_ok++;
        rn->stats.last_cmd = rn->in[0];
        rn->stats.last_len = (uint16_t)(rn->in_len - 1u);
        handle(rn, rn->in[0], rn->in + 1, (size_t)rn->in_len - 1u, now_us);
      }
    }
    /* the delimiter that ends a frame also starts the next */
    rn->in_frame = 1;
    rn->in_len = 0;
    rn->in_escaped = 0;
    rn->in_discard = 0;
    return;
  }
  if (!rn->in_frame || rn->in_discard)
    return;
  if (rn->in_escaped) {
    rn->in_escaped = 0;
    if (b == TFEND) {
      b = (uint8_t)FEND;
    } else if (b == TFESC) {
      b = (uint8_t)FESC;
    } else {
      rn->in_discard = 1; /* a bad escape poisons the frame */
      return;
    }
  } else if (b == FESC) {
    rn->in_escaped = 1;
    return;
  }
  if (rn->in_len >= RNC_RNODE_IN_MAX) {
    rn->in_discard = 1;
    return;
  }
  rn->in[rn->in_len++] = b;
}

void rnc_rnode_feed(rnc_rnode *rn, const uint8_t *bytes, size_t size, uint64_t now_us) {
  size_t i;
  for (i = 0; i < size; i++)
    feed_byte(rn, bytes[i], now_us);
}

size_t rnc_rnode_pull(rnc_rnode *rn, uint8_t *out, size_t capacity) {
  size_t n = rn->out_len < capacity ? rn->out_len : capacity;
  if (n == 0u)
    return 0u;
  memcpy(out, rn->out, n);
  memmove(rn->out, rn->out + n, (size_t)rn->out_len - n);
  rn->out_len = (uint16_t)(rn->out_len - n);
  return n;
}

unsigned rnc_rnode_step(rnc_rnode *rn, uint64_t now_us) {
  unsigned wait = 100u;
  if (!rn->li)
    return wait;
  wait = rnc_lora_if_step(rn->li, now_us);
  if (rn->li->stats.tx_packets != rn->last_tx_packets) {
    rn->last_tx_packets = rn->li->stats.tx_packets;
    if (rn->li->q_count < RNC_LORA_TXQ)
      send_ready(rn); /* a transmission finished */
  }
  /* a received packet goes to the host with its signal figures; it waits in the interface
   * until the host side has room for the worst case (every byte escaped) */
  if (RNC_RNODE_OUT_MAX - rn->out_len >= 2u * RNC_AIR_PACKET_MAX + 16u) {
    uint8_t pkt[RNC_AIR_PACKET_MAX], v;
    int rssi, snr;
    size_t n = rnc_lora_if_recv(rn->li, pkt, sizeof(pkt));
    if (n) {
      rssi = rn->li->stats.last_rssi_dbm + 157;
      snr = rn->li->stats.last_snr_quarter_db;
      v = (uint8_t)(rssi < 0 ? 0 : rssi > 255 ? 255 : rssi);
      put_frame(rn, CMD_STAT_RSSI, &v, 1);
      v = (uint8_t)(int8_t)(snr < -128 ? -128 : snr > 127 ? 127 : snr);
      put_frame(rn, CMD_STAT_SNR, &v, 1);
      put_frame(rn, CMD_DATA, pkt, n);
    }
  }
  return wait;
}

int rnc_rnode_reset_requested(rnc_rnode *rn) {
  int r = rn->reset_requested;
  rn->reset_requested = 0;
  return r;
}

size_t rnc_rnode_pump(rnc_rnode *rn, const rnc_rnode_io *io, uint64_t now_us) {
  uint8_t buf[128];
  size_t total = 0;
  int n;
  while ((n = io->read(io->context, buf, sizeof(buf))) > 0)
    rnc_rnode_feed(rn, buf, (size_t)n, now_us);
  (void)rnc_rnode_step(rn, now_us);
  for (;;) {
    size_t got = rnc_rnode_pull(rn, buf, sizeof(buf));
    int w;
    if (got == 0u)
      break;
    w = io->write(io->context, buf, got);
    if (w < 0)
      w = 0;
    if ((size_t)w < got) /* what the transport did not take is dropped */
      rn->stats.out_dropped += (uint32_t)(got - (size_t)w);
    total += (size_t)w;
  }
  return total;
}

void rnc_rnode_reset(rnc_rnode *rn) {
  rn->in_len = 0;
  rn->in_frame = rn->in_escaped = rn->in_discard = 0;
  rn->out_len = 0;
  /* the next host starts from nothing: no settings, radio off, the default airtime budget */
  rn->set = rn->on = 0;
  memset(&rn->p, 0, sizeof(rn->p));
  rn->lock_short = rn->lock_long = 0;
  if (rn->li) {
    rnc_lora_if_stop(rn->li);
    rn->li->budget.budget_ms = rn->default_budget_ms;
  }
}

/* ---- the boot window ---------------------------------------------------------------- */
static const char CONSOLE_LINE[] = "rnc-config";

void rnc_rnode_window_init(rnc_rnode_window *w) { memset(w, 0, sizeof(*w)); }

int rnc_rnode_window_feed(rnc_rnode_window *w, uint8_t byte) {
  const size_t want = sizeof(CONSOLE_LINE) - 1u;
  if (w->keep_len == RNC_RNODE_WINDOW_KEEP) { /* full: the oldest byte goes */
    memmove(w->keep, w->keep + 1, RNC_RNODE_WINDOW_KEEP - 1u);
    w->keep_len--;
  }
  w->keep[w->keep_len++] = byte;
  if (byte == '\n' || byte == '\r') {
    int match = w->line_len == want && !memcmp(w->line, CONSOLE_LINE, want);
    w->line_len = 0;
    if (match) { /* the line and its terminator are not for the KISS parser */
      w->keep_len = (uint16_t)(w->keep_len - (want + 1u));
      return 1;
    }
    return 0;
  }
  if (w->line_len < sizeof(w->line))
    w->line[w->line_len++] = byte; /* one byte beyond the console line marks "too long" */
  return 0;
}

size_t rnc_rnode_window_take(rnc_rnode_window *w, uint8_t *out, size_t capacity) {
  size_t n = w->keep_len < capacity ? w->keep_len : capacity;
  if (n == 0u)
    return 0u;
  memcpy(out, w->keep, n);
  memmove(w->keep, w->keep + n, (size_t)w->keep_len - n);
  w->keep_len = (uint16_t)(w->keep_len - n);
  return n;
}
