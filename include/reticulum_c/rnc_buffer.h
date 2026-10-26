#ifndef RETICULUM_C_BUFFER_H
#define RETICULUM_C_BUFFER_H
#include <reticulum_c/rnc_link.h>
#ifdef __cplusplus
extern "C" {
#endif
#define RNC_STREAM_MESSAGE 0xff00u
#define RNC_STREAM_CHUNK_MAX 16384u
#define RNC_STREAM_CAPACITY_MAX (1024u * 1024u)
typedef struct rnc_stream rnc_stream;
/* Wire codecs for standard RNS Buffer messages. A message has a two-byte
 * stream ID/EOF/compression header. Compression uses optional BZip2, with a
 * strict 16KiB decompression bound. Encoding consumes at most16KiB and marks
 * EOF only when all supplied input was consumed. Outputs commit on success. */
int rnc_stream_compression_available(void);
rnc_result rnc_stream_encode(uint16_t stream_id, const void *data, size_t size,
                             int eof, int compress, uint8_t *output,
                             size_t capacity, size_t *written,
                             size_t *consumed);
rnc_result rnc_stream_decode(const uint8_t *data, size_t size,
                             uint16_t *stream_id, int *eof, uint8_t *output,
                             size_t capacity, size_t *written);
/* One stream ID, one bounded receive ring, independent transmit/receive EOF.
 * Neither Link nor stream owns the other. Free the stream after detaching it
 * from the host pump. Functions are thread-confined like the Link API. */
rnc_stream *rnc_stream_new(uint16_t stream_id, size_t receive_capacity);
void rnc_stream_free(rnc_stream *stream);
rnc_result rnc_stream_write(rnc_stream *stream, rnc_link *link,
                            const void *data, size_t size, int eof,
                            int compress, size_t *consumed, uint64_t now_ms);
/* Accept a RNC_LINK_MESSAGE type0xff00 event. RNC_AGAIN means wrong stream or
 * insufficient ring space. The host must route/retain that event until it is
 * accepted; Channel receipt is independent of stream-buffer admission. */
rnc_result rnc_stream_input(rnc_stream *stream, const rnc_link_event *event);
rnc_result rnc_stream_read(rnc_stream *stream, uint8_t *output, size_t capacity,
                           size_t *written, int *eof);
size_t rnc_stream_available(const rnc_stream *stream);
int rnc_stream_at_eof(const rnc_stream *stream);
#ifdef __cplusplus
}
#endif
#endif
