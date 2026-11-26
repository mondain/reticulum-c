/* example_buffer: the reference's Examples/Buffer.py as a C program.
 *
 *   reticulum-c-example-buffer --connect HOST:PORT --identity FILE server
 *   reticulum-c-example-buffer --connect HOST:PORT --identity FILE client DESTINATION
 *
 * A Buffer is a byte stream over a link's Channel: what one end writes the other reads, in order, with no
 * message boundaries promised. Here each link has one stream, number 0 in both directions, as the reference
 * example's create_bidirectional_buffer(0, 0, ...). A write takes what fits in one message, so a long line goes
 * out in pieces and each piece that arrives is reported. A reference Buffer.py can be either end. */
#include "example_link_chat.h"
#include <reticulum_c/rnc_buffer.h>

#define STREAM 0u
#define RECEIVE_CAPACITY (64u * 1024u)

static rnc_stream *streams[EXAMPLE_LINKS]; /* by link slot */

static void buffer_opened(example_links *links, example_link *l) {
  size_t i = (size_t)(l - links->slot);
  rnc_stream_free(streams[i]);
  streams[i] = rnc_stream_new(STREAM, RECEIVE_CAPACITY);
}
static void buffer_closed(example_links *links, example_link *l) {
  size_t i = (size_t)(l - links->slot);
  rnc_stream_free(streams[i]);
  streams[i] = NULL;
}
static int buffer_send(example_links *links, example_link *l, const char *text, size_t size, size_t *consumed) {
  rnc_stream *stream = streams[l - links->slot];
  *consumed = 0;
  if (stream && rnc_stream_write(stream, l->link, text, size, 0, 0, consumed, example_now_ms()) != RNC_OK)
    *consumed = 0; /* the window is full: try again later */
  return 1;
}
static int buffer_take(example_links *links, example_link *l, const rnc_link_event *event, char *text, size_t capacity,
                       size_t *size, char note[80]) {
  rnc_stream *stream = streams[l - links->slot];
  int eof = 0;
  if (!stream || event->type != RNC_LINK_MESSAGE || event->message_type != RNC_STREAM_MESSAGE ||
      rnc_stream_input(stream, event) != RNC_OK)
    return 0;
  note[0] = 0;
  *size = 0;
  return rnc_stream_read(stream, (uint8_t *)text, capacity, size, &eof) == RNC_OK && *size;
}
int main(int argc, char **argv) {
  example_chat_options options = {0};
  options.aspects = "example_utilities.bufferexample";
  options.title = "Link buffer example";
  options.server_received = "Received data over the buffer";
  options.client_received = "Received data over the link buffer";
  options.over = "buffer";
  options.opened = buffer_opened;
  options.closed = buffer_closed;
  options.send = buffer_send;
  options.take = buffer_take;
  return example_link_main(argc, argv, &options);
}
