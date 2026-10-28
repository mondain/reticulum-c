#include "crypto_backend.h"
#include <reticulum_c/rnc_buffer.h>
#include <stdlib.h>
#include <string.h>
#ifdef RNC_HAVE_BZIP2
#include <bzlib.h>
#endif
/* The decode scratch buffer: a bz2 chunk may expand up to RNC_STREAM_CHUNK_MAX, but
 * without bz2 a chunk is never larger than one channel message, so the buffer (on the
 * stack) is that much smaller for firmware builds. */
#ifdef RNC_HAVE_BZIP2
#define STREAM_DECODED_MAX RNC_STREAM_CHUNK_MAX
#else
#define STREAM_DECODED_MAX RNC_CHANNEL_MAX_MDU
#endif
struct rnc_stream {
    uint16_t id;
    int received_eof, sent_eof;
    size_t capacity, head, size;
    uint8_t data[];
};
int rnc_stream_compression_available(void) {
#ifdef RNC_HAVE_BZIP2
    return 1;
#else
    return 0;
#endif
}
rnc_result rnc_stream_encode(uint16_t id, const void *data, size_t size, int eof, int compress,
                             uint8_t *output, size_t capacity, size_t *written, size_t *consumed) {
    uint8_t message[RNC_CHANNEL_MAX_MDU];
    size_t take, packed = 0;
    int compressed = 0;
    uint16_t header;
    if (written)
        *written = 0;
    if (consumed)
        *consumed = 0;
    if (id > 0x3fff || (!data && size) || !output || !written || !consumed ||
        (eof != 0 && eof != 1) || (compress != 0 && compress != 1))
        return RNC_INVALID;
    if (capacity < 2)
        return RNC_NO_SPACE;
    size_t maximum = capacity < RNC_CHANNEL_MAX_MDU ? capacity : RNC_CHANNEL_MAX_MDU;
    take = size < RNC_STREAM_CHUNK_MAX ? size : RNC_STREAM_CHUNK_MAX;
#ifdef RNC_HAVE_BZIP2
    if (compress && take > 32) {
        unsigned int n = (unsigned int)(maximum - 2u);
        int status = BZ2_bzBuffToBuffCompress((char *)message + 2, &n, (char *)data,
                                              (unsigned int)take, 9, 0, 30);
        if (status == BZ_OK && n < take) {
            compressed = 1;
            packed = n;
        } else if (status != BZ_OK && status != BZ_OUTBUFF_FULL)
            return RNC_NO_SPACE;
    }
#else
    (void)compress;
#endif
    if (!compressed) {
        if (take > maximum - 2u)
            take = maximum - 2u;
        packed = take;
        if (take)
            memcpy(message + 2, data, take);
    }
    if (capacity < packed + 2u)
        return RNC_NO_SPACE;
    header = (uint16_t)(id | (eof && take == size ? 0x8000u : 0u) | (compressed ? 0x4000u : 0u));
    message[0] = (uint8_t)(header >> 8);
    message[1] = (uint8_t)header;
    memcpy(output, message, packed + 2u);
    *written = packed + 2u;
    *consumed = take;
    return RNC_OK;
}
rnc_result rnc_stream_decode(const uint8_t *data, size_t size, uint16_t *id, int *eof,
                             uint8_t *output, size_t capacity, size_t *written) {
    uint8_t decoded[STREAM_DECODED_MAX];
    size_t length;
    uint16_t header;
    rnc_result result = RNC_OK;
    if (written)
        *written = 0;
    if (!data || !id || !eof || !output || !written)
        return RNC_INVALID;
    if (size < 2 || size > RNC_CHANNEL_MAX_MDU)
        return RNC_PROTOCOL;
    header = (uint16_t)((uint16_t)data[0] << 8 | data[1]);
    length = size - 2u;
    if (header & 0x4000u) {
#ifdef RNC_HAVE_BZIP2
        unsigned int n = RNC_STREAM_CHUNK_MAX;
        int status = BZ2_bzBuffToBuffDecompress((char *)decoded, &n, (char *)data + 2,
                                                (unsigned int)length, 0, 0);
        if (status != BZ_OK) {
            result = RNC_PROTOCOL;
            goto done;
        }
        length = n;
#else
        result = RNC_UNSUPPORTED;
        goto done;
#endif
    } else if (length)
        memcpy(decoded, data + 2, length);
    if (capacity < length) {
        result = RNC_NO_SPACE;
        goto done;
    }
    memcpy(output, decoded, length);
    *written = length;
    *id = (uint16_t)(header & 0x3fffu);
    *eof = (header & 0x8000u) != 0;
done:
    rnc_cleanse(decoded, sizeof(decoded));
    return result;
}
rnc_stream *rnc_stream_new(uint16_t id, size_t capacity) {
    rnc_stream *stream;
    if (id > 0x3fff || !capacity || capacity > RNC_STREAM_CAPACITY_MAX)
        return NULL;
    stream = calloc(1, sizeof(*stream) + capacity);
    if (stream) {
        stream->id = id;
        stream->capacity = capacity;
    }
    return stream;
}
void rnc_stream_free(rnc_stream *stream) {
    if (stream) {
        rnc_cleanse(stream, sizeof(*stream) + stream->capacity);
        free(stream);
    }
}
rnc_result rnc_stream_write(rnc_stream *stream, rnc_link *link, const void *data, size_t size,
                            int eof, int compress, size_t *consumed, uint64_t now) {
    uint8_t message[RNC_CHANNEL_MAX_MDU];
    size_t n, used;
    rnc_result result;
    if (consumed)
        *consumed = 0;
    if (!stream || !link || !consumed)
        return RNC_INVALID;
    if (stream->sent_eof)
        return RNC_STATE;
    result = rnc_stream_encode(stream->id, data, size, eof, compress, message,
                               rnc_link_channel_mdu(link), &n, &used);
    if (result == RNC_OK)
        result = rnc_link_send_system(link, RNC_STREAM_MESSAGE, message, n, now);
    if (result == RNC_OK) {
        *consumed = used;
        if (eof && used == size)
            stream->sent_eof = 1;
    }
    rnc_cleanse(message, sizeof(message));
    return result;
}
rnc_result rnc_stream_input(rnc_stream *stream, const rnc_link_event *event) {
    uint8_t decoded[STREAM_DECODED_MAX];
    size_t length, tail, first;
    uint16_t id;
    int eof;
    rnc_result result;
    if (!stream || !event || event->type != RNC_LINK_MESSAGE ||
        event->message_type != RNC_STREAM_MESSAGE)
        return RNC_INVALID;
    if (event->size < 2 || event->size > RNC_CHANNEL_MAX_MDU)
        return RNC_PROTOCOL;
    id = (uint16_t)(((uint16_t)event->data[0] << 8 | event->data[1]) & 0x3fffu);
    if (id != stream->id)
        return RNC_AGAIN;
    if (stream->received_eof)
        return RNC_STATE;
    result =
        rnc_stream_decode(event->data, event->size, &id, &eof, decoded, sizeof(decoded), &length);
    if (result != RNC_OK)
        goto done;
    if (stream->capacity - stream->size < length) {
        result = RNC_AGAIN;
        goto done;
    }
    tail = (stream->head + stream->size) % stream->capacity;
    first = stream->capacity - tail;
    if (first > length)
        first = length;
    memcpy(stream->data + tail, decoded, first);
    memcpy(stream->data, decoded + first, length - first);
    stream->size += length;
    stream->received_eof = eof;
done:
    rnc_cleanse(decoded, sizeof(decoded));
    return result;
}
rnc_result rnc_stream_read(rnc_stream *stream, uint8_t *output, size_t capacity, size_t *written,
                           int *eof) {
    size_t n, first;
    if (written)
        *written = 0;
    if (!stream || (!output && capacity) || !written || !eof)
        return RNC_INVALID;
    *eof = stream->received_eof && !stream->size;
    if (!stream->size)
        return *eof || !capacity ? RNC_OK : RNC_AGAIN;
    n = capacity < stream->size ? capacity : stream->size;
    first = stream->capacity - stream->head;
    if (first > n)
        first = n;
    if (n) {
        memcpy(output, stream->data + stream->head, first);
        memcpy(output + first, stream->data, n - first);
        rnc_cleanse(stream->data + stream->head, first);
        rnc_cleanse(stream->data, n - first);
    }
    stream->head = (stream->head + n) % stream->capacity;
    stream->size -= n;
    *written = n;
    *eof = stream->received_eof && !stream->size;
    return RNC_OK;
}
size_t rnc_stream_available(const rnc_stream *stream) { return stream ? stream->size : 0; }
int rnc_stream_at_eof(const rnc_stream *stream) {
    return stream && stream->received_eof && !stream->size;
}
