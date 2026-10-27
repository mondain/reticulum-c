#include <reticulum_c/rnc.h>
#include <string.h>

rnc_result rnc_hdlc_encode(const uint8_t *data, size_t size, uint8_t *output, size_t capacity,
                           size_t *written) {
    size_t i, needed = 2, offset = 0;
    if (written)
        *written = 0;
    if (!data || !size || size > RNC_MAX_FRAME || !output || !written)
        return RNC_INVALID;
    for (i = 0; i < size; ++i)
        needed += data[i] == 0x7du || data[i] == 0x7eu ? 2u : 1u;
    if (needed > capacity)
        return RNC_NO_SPACE;
    output[offset++] = 0x7e;
    for (i = 0; i < size; ++i) {
        if (data[i] == 0x7du || data[i] == 0x7eu) {
            output[offset++] = 0x7d;
            output[offset++] = data[i] ^ 0x20u;
        } else
            output[offset++] = data[i];
    }
    output[offset++] = 0x7e;
    *written = offset;
    return RNC_OK;
}

rnc_result rnc_hdlc_feed(rnc_hdlc *state, uint8_t byte, uint8_t *output, size_t capacity,
                         size_t *written) {
    if (written)
        *written = 0;
    if (!state || !output || !written)
        return RNC_INVALID;
    if (byte == 0x7e) {
        rnc_result result = RNC_AGAIN;
        if (state->active && !state->discard) {
            if (state->escaped)
                result = RNC_PROTOCOL;
            else if (state->size) {
                if (capacity < state->size)
                    result = RNC_NO_SPACE;
                else {
                    memcpy(output, state->data, state->size);
                    *written = state->size;
                    result = RNC_OK;
                }
            }
        }
        state->active = 1;
        state->size = 0;
        state->escaped = state->discard = 0;
        return result;
    }
    if (!state->active || state->discard)
        return RNC_AGAIN;
    if (state->escaped) {
        state->escaped = 0;
        if (byte != 0x5du && byte != 0x5eu) {
            state->discard = 1;
            return RNC_PROTOCOL;
        }
        byte ^= 0x20u;
    } else if (byte == 0x7d) {
        state->escaped = 1;
        return RNC_AGAIN;
    }
    if (state->size == sizeof(state->data)) {
        state->discard = 1;
        return RNC_NO_SPACE;
    }
    state->data[state->size++] = byte;
    return RNC_AGAIN;
}
