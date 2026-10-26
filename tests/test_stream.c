#define main rnc_baseline_test_main
#include "test_link.c"
#undef main
#include <reticulum_c/rnc_buffer.h>
#ifdef RNC_HAVE_BZIP2
#include <bzlib.h>
#endif

static void codec_test(void) {
  uint8_t encoded[RNC_CHANNEL_MDU], decoded[RNC_STREAM_CHUNK_MAX];
  uint8_t data[RNC_STREAM_CHUNK_MAX];
  size_t n, used, m;
  uint16_t id;
  int eof;
  memset(data, 'x', sizeof(data));
  CHECK(rnc_stream_encode(7, "hello", 5, 1, 0, encoded, sizeof(encoded), &n,
                          &used) == RNC_OK);
  CHECK(n == 7 && used == 5 && encoded[0] == 0x80 && encoded[1] == 7);
  CHECK(rnc_stream_decode(encoded, n, &id, &eof, decoded, sizeof(decoded),
                          &m) == RNC_OK);
  CHECK(id == 7 && eof == 1 && m == 5 && !memcmp(decoded, "hello", 5));
  CHECK(rnc_stream_encode(0x4000, data, 1, 0, 0, encoded, sizeof(encoded), &n,
                          &used) == RNC_INVALID);
  CHECK(rnc_stream_encode(7, data, sizeof(data), 1, 0, encoded, sizeof(encoded),
                          &n, &used) == RNC_OK);
  CHECK(used == RNC_CHANNEL_MDU - 2 && !(encoded[0] & 0x80));
  CHECK(rnc_stream_decode(encoded, 1, &id, &eof, decoded, sizeof(decoded),
                          &m) == RNC_PROTOCOL);
  CHECK(rnc_stream_encode(7, data, sizeof(data), 1, 1, encoded, sizeof(encoded),
                          &n, &used) == RNC_OK);
#ifdef RNC_HAVE_BZIP2
  CHECK((encoded[0] & 0xc0) == 0xc0 && used == sizeof(data));
  CHECK(rnc_stream_decode(encoded, n, &id, &eof, decoded, sizeof(decoded),
                          &m) == RNC_OK);
  CHECK(m == sizeof(data) && !memcmp(decoded, data, sizeof(data)) && eof);
  encoded[n - 2] ^= 0x80;
  memset(decoded, 0xa5, sizeof(decoded));
  CHECK(rnc_stream_decode(encoded, n, &id, &eof, decoded, sizeof(decoded),
                          &m) == RNC_PROTOCOL);
  CHECK(decoded[0] == 0xa5 && m == 0);
  {
    char bomb[RNC_STREAM_CHUNK_MAX + 1];
    unsigned int len = sizeof(encoded) - 2;
    memset(bomb, 'z', sizeof(bomb));
    CHECK(BZ2_bzBuffToBuffCompress((char *)encoded + 2, &len, bomb,
                                   sizeof(bomb), 9, 0, 30) == BZ_OK);
    encoded[0] = 0x40;
    encoded[1] = 7;
    CHECK(rnc_stream_decode(encoded, len + 2, &id, &eof, decoded,
                            sizeof(decoded), &m) == RNC_PROTOCOL);
  }
#else
  CHECK(!(encoded[0] & 0x40));
  encoded[0] |= 0x40;
  CHECK(rnc_stream_decode(encoded, n, &id, &eof, decoded, sizeof(decoded),
                          &m) == RNC_UNSUPPORTED);
#endif
}
static void reader_test(void) {
  rnc_stream *reader = rnc_stream_new(7, 5);
  rnc_link_event event = {0};
  uint8_t output[10];
  size_t n, used;
  int eof;
  CHECK(reader && !rnc_stream_new(0x4000, 10));
  event.type = RNC_LINK_MESSAGE;
  event.message_type = 0xff00;
  CHECK(rnc_stream_encode(7, "hello", 5, 0, 0, event.data, sizeof(event.data),
                          &event.size, &used) == RNC_OK);
  CHECK(rnc_stream_input(reader, &event) == RNC_OK);
  CHECK(rnc_stream_available(reader) == 5);
  CHECK(rnc_stream_input(reader, &event) == RNC_AGAIN &&
        rnc_stream_available(reader) == 5);
  CHECK(rnc_stream_read(reader, output, 3, &n, &eof) == RNC_OK && n == 3 &&
        !eof && !memcmp(output, "hel", 3));
  CHECK(rnc_stream_encode(7, "!", 1, 1, 0, event.data, sizeof(event.data),
                          &event.size, &used) == RNC_OK);
  CHECK(rnc_stream_input(reader, &event) == RNC_OK);
  CHECK(rnc_stream_read(reader, output, sizeof(output), &n, &eof) == RNC_OK &&
        n == 3 && eof && !memcmp(output, "lo!", 3));
  CHECK(rnc_stream_at_eof(reader));
  CHECK(rnc_stream_read(reader, output, sizeof(output), &n, &eof) == RNC_OK &&
        n == 0 && eof);
  CHECK(rnc_stream_input(reader, &event) == RNC_STATE);
  rnc_stream_free(reader);
}
static void linked_test(void) {
  pair p;
  rnc_stream *writer = rnc_stream_new(9, 1), *reader = rnc_stream_new(9, 16384);
  rnc_link_event event;
  rnc_packet packet, proof;
  uint8_t data[1700], out[1700];
  size_t offset = 0, used, n;
  int eof;
  unsigned i;
  uint64_t now = 110;
  for (i = 0; i < sizeof(data); ++i)
    data[i] = (uint8_t)i;
  init(&p);
  establish(&p);
  CHECK(writer && reader);
  CHECK(rnc_link_send(p.client, 0xff00, "bad", 3, now) == RNC_INVALID);
  while (offset < sizeof(data)) {
    CHECK(rnc_stream_write(writer, p.client, data + offset,
                           sizeof(data) - offset, 1, 0, &used,
                           now++) == RNC_OK);
    offset += used;
    packet = outgoing(p.client);
    CHECK(rnc_link_input(p.server, &packet, now++) == RNC_OK);
    proof = outgoing(p.server);
    CHECK(rnc_link_poll(p.server, &event) == RNC_OK &&
          event.type == RNC_LINK_MESSAGE && event.message_type == 0xff00);
    CHECK(rnc_stream_input(reader, &event) == RNC_OK);
    CHECK(rnc_link_input(p.client, &proof, now++) == RNC_OK);
    (void)count(p.client, RNC_LINK_DELIVERED);
  }
  CHECK(rnc_stream_write(writer, p.client, "bad", 3, 0, 0, &used, now) ==
            RNC_STATE &&
        used == 0);
  CHECK(rnc_stream_read(reader, out, sizeof(out), &n, &eof) == RNC_OK &&
        n == sizeof(data) && eof && !memcmp(out, data, n));
  rnc_stream_free(writer);
  rnc_stream_free(reader);
  finish(&p);
}
int main(void) {
  codec_test();
  reader_test();
  linked_test();
  puts("stream tests passed");
  return 0;
}
