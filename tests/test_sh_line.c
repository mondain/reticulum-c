/* The initiator's keyboard handling (examples/sh_line.h): rnsh's escapes and line-interactive mode. */
#include "../examples/sh_line.h"
#include <stdio.h>
#include <stdlib.h>

#define CHECK(x)                                                                                                       \
  do {                                                                                                                 \
    if (!(x)) {                                                                                                        \
      fprintf(stderr, "%s:%d %s\n  sent=[%.*s]\n  shown=[%.*s]\n", __FILE__, __LINE__, #x, (int)sent_len,             \
              (char *)sent, (int)shown_len, shown);                                                                    \
      exit(1);                                                                                                         \
    }                                                                                                                  \
  } while (0)

static uint8_t sent[3 * SH_LINE_MAX];
static char shown[8 * SH_LINE_MAX];
static size_t sent_len, shown_len;
static sh_keys keys;
static int quit;

static void show(void *context, const void *data, size_t size) {
  (void)context;
  if (shown_len + size < sizeof(shown)) {
    memcpy(shown + shown_len, data, size);
    shown_len += size;
  }
  shown[shown_len] = 0;
}
static void type_bytes(const char *text, size_t n) {
  uint8_t out[SH_SEND_MAX];
  size_t out_len = 0;
  quit = sh_keys_feed(&keys, (const uint8_t *)text, n, out, &out_len, show, NULL);
  memcpy(sent + sent_len, out, out_len);
  sent_len += out_len;
}
static void type(const char *text) { type_bytes(text, strlen(text)); }
/* forget what was sent and shown so far, keeping the editor's state */
static void clear(void) {
  sent_len = shown_len = 0;
  shown[0] = 0;
  quit = 0;
}
static void fresh(void) {
  sh_keys_init(&keys);
  clear();
}
static int sent_is(const char *want) { return sent_len == strlen(want) && !memcmp(sent, want, sent_len); }
static int shown_is(const char *want) { return shown_len == strlen(want) && !memcmp(shown, want, shown_len); }
static void line_mode(void) {
  fresh();
  type("~L"); /* a session starts as if after a newline */
  clear();
}

static void test_character_mode(void) {
  fresh();
  type("ls -l\r");
  CHECK(sent_is("ls -l\r") && shown_is("") && !quit);
  clear();
  type("~~x"); /* the escape character, typed twice after a newline */
  CHECK(sent_is("~x"));
  fresh();
  type("~zy");
  CHECK(sent_is("~zy")); /* not an escape: both characters go */
  fresh();
  type("a~.");
  CHECK(sent_is("a~.") && !quit); /* only right after a newline */
  clear();
  type("\r~.");
  CHECK(quit);
  fresh();
  type("\x7f\t\x03");
  CHECK(sent_is("\x7f\t\x03")); /* editing keys are the remote side's business here */
}

static void test_toggle_and_help(void) {
  fresh();
  type("~L");
  CHECK(sent_is("") && shown_is("\n\rLine-interactive mode enabled\n\r"));
  clear();
  type("\r~L");
  CHECK(sent_is("\r") && strstr(shown, "Line-interactive mode disabled"));
  clear();
  type("ab");
  CHECK(sent_is("ab") && shown_is(""));
  fresh();
  type("~?");
  CHECK(sent_is("") && strstr(shown, "Supported rnsh escape sequences:") && strstr(shown, "~~") &&
        strstr(shown, "~.") && strstr(shown, "~L") && strstr(shown, "~?"));
}

static void test_line_is_held_until_enter(void) {
  line_mode();
  type("hel");
  type("lo");
  CHECK(sent_is("") && shown_is("hello"));
  clear();
  type("\r");
  /* the local copy is wiped, so that the remote side's echo takes its place */
  CHECK(sent_is("hello\r") && shown_is("\b \b\b \b\b \b\b \b\b \b"));
  clear();
  type("x");
  CHECK(sent_is("") && shown_is("x"));
}

static void test_control_keys_send_the_line(void) {
  static const char keys_that_send[] = {1, 3, 4, 5, 12, 17, 19, 21, 25, 9, 26, 27};
  size_t i;
  for (i = 0; i < sizeof(keys_that_send); ++i) {
    char want[4] = {'a', 'b', keys_that_send[i], 0};
    line_mode();
    type("ab");
    type_bytes(keys_that_send + i, 1);
    CHECK(sent_is(want));
  }
  line_mode();
  type("a\x02"); /* any other control key is part of the line, and takes no column */
  CHECK(sent_is(""));
  clear();
  type("\r");
  CHECK(sent_is("a\x02\r") && shown_is("\b \b"));
}

static void test_backspace(void) {
  line_mode();
  type("hello\x7f\x7f"); /* also when it arrives together with the text */
  type("p\r");
  CHECK(sent_is("help\r"));
  line_mode();
  type("ab\b");
  CHECK(sent_is("") && shown_is("ab\b \b"));
  clear();
  type("\x7f\x7f\x7f"); /* nothing left to remove: nothing shown, nothing sent */
  CHECK(sent_is("") && shown_is("\b \b"));
  line_mode();
  type("caf\xc3\xa9\x7f");
  type("e\r");
  CHECK(sent_is("cafe\r"));
  line_mode();
  type("\xe2\x82\xac\xf0\x9f\x98\x80\x7f\x7f\r"); /* three and four byte characters */
  CHECK(sent_is("\r"));
}

static void test_text_after_enter_waits(void) {
  line_mode();
  type("ls\rrm -r x");
  CHECK(sent_is("ls\r"));
  clear();
  type("\r");
  CHECK(sent_is("rm -r x\r"));
  /* Enter and the toggle in one read leave nothing behind */
  line_mode();
  type("abc");
  type("\r~L");
  type("d");
  CHECK(sent_is("abc\rd"));
}

static void test_long_line(void) {
  size_t i;
  line_mode();
  for (i = 0; i < SH_LINE_MAX; ++i)
    type("a");
  CHECK(sent_len == 0);
  type("b");
  CHECK(sent_len == SH_LINE_MAX); /* a full line goes out rather than losing anything */
  clear();
  type("\r");
  CHECK(sent_is("b\r"));
  /* the most one read can add to what the line already holds */
  line_mode();
  {
    char block[SH_READ_MAX];
    memset(block, 'c', sizeof(block));
    for (i = 0; i < SH_LINE_MAX - 1; ++i)
      type("a");
    block[sizeof(block) - 1] = '\r';
    type_bytes(block, sizeof(block));
    CHECK(sent_len == SH_LINE_MAX - 1 + SH_READ_MAX);
  }
}

static void test_quit_from_line_mode(void) {
  line_mode();
  type("ab\r~.cd");
  CHECK(quit && sent_is("ab\r"));
}

int main(void) {
  test_character_mode();
  test_toggle_and_help();
  test_line_is_held_until_enter();
  test_control_keys_send_the_line();
  test_backspace();
  test_text_after_enter_waits();
  test_long_line();
  test_quit_from_line_mode();
  puts("sh keyboard tests passed");
  return 0;
}
