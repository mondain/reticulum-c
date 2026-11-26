/* example_channel: the reference's Examples/Channel.py as a C program.
 *
 *   reticulum-c-example-channel --connect HOST:PORT --identity FILE server
 *   reticulum-c-example-channel --connect HOST:PORT --identity FILE client DESTINATION
 *
 * A Channel carries typed messages over a link, in order, each retried until the other end has proved it got
 * it (rnc_link_send, event RNC_LINK_MESSAGE). The message type here is the reference example's StringMessage,
 * 0x0101: the MessagePack array [text, time], the time as MessagePack's timestamp extension, which is what a
 * Python datetime becomes. Only a few messages can be unproved at once; a line waits until there is room.
 * A reference Channel.py can be either end. */
#include "example_link_chat.h"

#define STRING_MESSAGE 0x0101u

static void put_be(uint8_t *out, uint64_t value, size_t bytes) {
  size_t i;
  for (i = 0; i < bytes; ++i)
    out[i] = (uint8_t)(value >> (8u * (bytes - 1u - i)));
}
static uint64_t get_be(const uint8_t *in, size_t bytes) {
  uint64_t value = 0;
  size_t i;
  for (i = 0; i < bytes; ++i)
    value = value << 8 | in[i];
  return value;
}
/* [text, timestamp]; 0 when it does not fit. */
static size_t message_pack(const char *text, size_t size, uint8_t *out, size_t cap) {
  struct timespec now;
  size_t n = 0;
  if (size > 0xffff || size + 14u > cap)
    return 0;
  clock_gettime(CLOCK_REALTIME, &now);
  out[n++] = 0x92; /* array of two */
  if (size < 32)
    out[n++] = (uint8_t)(0xa0u | size); /* fixstr */
  else if (size < 256) {
    out[n++] = 0xd9; /* str 8 */
    out[n++] = (uint8_t)size;
  } else {
    out[n++] = 0xda; /* str 16 */
    put_be(out + n, size, 2);
    n += 2;
  }
  memcpy(out + n, text, size);
  n += size;
  out[n++] = 0xd7; /* fixext 8, type -1: nanoseconds in 30 bits, seconds in 34 */
  out[n++] = 0xff;
  put_be(out + n, (uint64_t)now.tv_nsec << 34 | ((uint64_t)now.tv_sec & UINT64_C(0x3ffffffff)), 8);
  return n + 8u;
}
/* The text and the time of a message; 0 when it is not one. */
static int message_unpack(const uint8_t *in, size_t size, const uint8_t **text, size_t *length, uint64_t *seconds,
                          unsigned *micros) {
  size_t n = 1, l;
  if (size < 2 || in[0] != 0x92)
    return 0;
  if ((in[n] & 0xe0u) == 0xa0u)
    l = in[n++] & 0x1fu;
  else if (in[n] == 0xd9 && size >= 3) {
    l = in[n + 1];
    n += 2;
  } else if (in[n] == 0xda && size >= 4) {
    l = (size_t)get_be(in + n + 1, 2);
    n += 3;
  } else
    return 0;
  if (l > size - n)
    return 0;
  *text = in + n;
  *length = l;
  n += l;
  if (size - n == 6 && in[n] == 0xd6 && in[n + 1] == 0xff) { /* whole seconds */
    *seconds = get_be(in + n + 2, 4);
    *micros = 0;
  } else if (size - n == 10 && in[n] == 0xd7 && in[n + 1] == 0xff) {
    uint64_t value = get_be(in + n + 2, 8);
    *seconds = value & UINT64_C(0x3ffffffff);
    *micros = (unsigned)((value >> 34) / 1000u);
  } else
    return 0;
  return 1;
}
static int channel_send(example_links *links, example_link *l, const char *text, size_t size, size_t *consumed) {
  uint8_t message[RNC_LINK_MAX_MDU];
  size_t n = message_pack(text, size, message, rnc_link_channel_mdu(l->link));
  (void)links;
  *consumed = 0;
  if (!n)
    return 0;
  if (rnc_link_send(l->link, STRING_MESSAGE, message, n, example_now_ms()) == RNC_OK)
    *consumed = size; /* RNC_AGAIN: the window is full, try again later */
  return 1;
}
static int channel_take(example_links *links, example_link *l, const rnc_link_event *event, char *text, size_t capacity,
                        size_t *size, char note[80]) {
  const uint8_t *found;
  size_t length;
  uint64_t seconds;
  unsigned micros;
  time_t when;
  struct tm utc;
  char date[32];
  (void)links;
  (void)l;
  if (event->type != RNC_LINK_MESSAGE || event->message_type != STRING_MESSAGE ||
      !message_unpack(event->data, event->size, &found, &length, &seconds, &micros) || length >= capacity)
    return 0;
  memcpy(text, found, length);
  *size = length;
  when = (time_t)seconds;
  if (!gmtime_r(&when, &utc) || !strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", &utc))
    (void)snprintf(date, sizeof(date), "unknown");
  (void)snprintf(note, 80, " (message created at %s.%06u UTC)", date, micros);
  return 1;
}
int main(int argc, char **argv) {
  example_chat_options options = {0};
  options.aspects = "example_utilities.channelexample";
  options.title = "Channel example";
  options.send = channel_send;
  options.take = channel_take;
  return example_link_main(argc, argv, &options);
}
