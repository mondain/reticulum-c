/* What the rnsh initiator does with the keys typed on its terminal: the "~" escapes and line-interactive mode, as
 * RNS/Utilities/rnsh/initiator.py. In line mode what is typed is shown at once and held; Enter or one of a set of
 * control keys sends it and wipes the local copy, so that the remote side's echo takes its place.
 *
 * Where this differs from the reference, which handles a whole read at once: keys are taken one at a time, so text
 * typed or pasted after an Enter waits for the next one, Backspace works on text from the same read, and nothing is
 * left behind when line mode is left; Backspace removes a whole UTF-8 character; and a line that fills the buffer is
 * sent rather than growing without limit. */
#ifndef RNC_EXAMPLE_SH_LINE_H
#define RNC_EXAMPLE_SH_LINE_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SH_LINE_MAX 4096u
#define SH_READ_MAX 1023u /* the most one call to sh_keys_feed takes */
#define SH_SEND_MAX (SH_LINE_MAX + 2u * SH_READ_MAX)

typedef struct sh_keys {
  int after_newline, escape, line_mode;
  size_t held;
  uint8_t line[SH_LINE_MAX];
} sh_keys;

/* writes to the user's terminal */
typedef void (*sh_show)(void *context, const void *data, size_t size);

static void sh_keys_init(sh_keys *k) {
  memset(k, 0, sizeof(*k));
  k->after_newline = 1;
}

/* one terminal column for each character, none for control characters and UTF-8 continuation bytes */
static int sh_takes_column(uint8_t c) { return c >= 0x20 && c != 0x7f && (c & 0xc0) != 0x80; }

static void sh_wipe_character(sh_show show, void *context) { show(context, "\b \b", 3); }

static void sh_send_line(sh_keys *k, uint8_t *out, size_t *out_len, sh_show show, void *context) {
  size_t i;
  for (i = 0; i < k->held; ++i)
    if (sh_takes_column(k->line[i]))
      sh_wipe_character(show, context);
  memcpy(out + *out_len, k->line, k->held);
  *out_len += k->held;
  k->held = 0;
}

/* One byte for the remote side. `sends` says that it ends the line. */
static void sh_put(sh_keys *k, uint8_t c, int sends, uint8_t *out, size_t *out_len, sh_show show, void *context) {
  if (!k->line_mode) {
    out[(*out_len)++] = c;
    return;
  }
  if (k->held == SH_LINE_MAX)
    sh_send_line(k, out, out_len, show, context);
  if (sends) { /* the wiped text and then the key that sent it */
    sh_send_line(k, out, out_len, show, context);
    out[(*out_len)++] = c;
  } else {
    k->line[k->held++] = c;
    show(context, &c, 1);
  }
}

static void sh_say(sh_show show, void *context, const char *text) { show(context, text, strlen(text)); }

/* Takes `n` (at most SH_READ_MAX) typed bytes. What is to go to the remote side is appended to `out`, which holds
 * SH_SEND_MAX bytes. Returns 1 when the user asked to leave ("~."). */
static int sh_keys_feed(sh_keys *k, const uint8_t *typed, size_t n, uint8_t *out, size_t *out_len, sh_show show,
                        void *context) {
  /* Ctrl-A, C, D, E, L, Q, S, U, Y, Tab, Ctrl-Z and Escape */
  static const char sending[] = "\x01\x03\x04\x05\x0c\x11\x13\x15\x19\t\x1a\x1b";
  size_t i;
  for (i = 0; i < n; ++i) {
    const uint8_t c = typed[i];
    if (c == '\r') {
      k->after_newline = 1;
      sh_put(k, c, 1, out, out_len, show, context);
    } else if (k->line_mode && c && strchr(sending, c)) {
      k->after_newline = 0;
      sh_put(k, c, 1, out, out_len, show, context);
    } else if (k->line_mode && (c == '\b' || c == 0x7f)) {
      int column = 0;
      k->after_newline = 0;
      while (k->held) { /* back over the continuation bytes to the first byte of the character */
        const uint8_t last = k->line[--k->held];
        column = sh_takes_column(last);
        if ((last & 0xc0) != 0x80)
          break;
      }
      if (column)
        sh_wipe_character(show, context);
    } else if (k->after_newline && c == '~') {
      k->after_newline = 0;
      k->escape = 1;
    } else if (k->escape) {
      k->escape = 0;
      if (c == '.')
        return 1;
      if (c == 'L') {
        k->line_mode = !k->line_mode;
        sh_say(show, context,
               k->line_mode ? "\n\rLine-interactive mode enabled\n\r" : "\n\rLine-interactive mode disabled\n\r");
      } else if (c == '?') {
        sh_say(show, context,
               "\n\r\n\rSupported rnsh escape sequences:"
               "\n\r  ~~  Send the escape character by typing it twice"
               "\n\r  ~.  Terminate session and exit immediately"
               "\n\r  ~L  Toggle line-interactive mode"
               "\n\r  ~?  Display this quick reference\n\r"
               "\n\r(Escape sequences are only recognized immediately after newline)\n\r");
      } else {
        if (c != '~')
          sh_put(k, '~', 0, out, out_len, show, context);
        sh_put(k, c, 0, out, out_len, show, context);
      }
    } else {
      k->after_newline = 0;
      sh_put(k, c, 0, out, out_len, show, context);
    }
  }
  return 0;
}
#endif
