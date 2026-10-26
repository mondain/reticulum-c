#include <reticulum_c/rnc.h>
#include <string.h>

rnc_result rnc_packet_encode(const rnc_packet *packet, uint8_t *output, size_t capacity,
                             size_t *written) {
    uint8_t raw[RNC_MAX_MTU];
    size_t header, limit;
    if (written)
        *written = 0;
    if (!packet || !output || !written)
        return RNC_INVALID;
    if (packet->flags & 0x80u)
        return RNC_UNSUPPORTED;
    header = packet->flags & 0x40u ? 35u : 19u;
    limit = ((packet->flags >> 2) & 3u) == RNC_LINK && (packet->flags & 3u) != RNC_ANNOUNCE
                ? RNC_MAX_MTU
                : RNC_MTU;
    if (!packet->data_size || packet->data_size > limit - header || packet->hops >= 128)
        return RNC_INVALID;
    if (capacity < header + packet->data_size)
        return RNC_NO_SPACE;
    raw[0] = packet->flags;
    raw[1] = packet->hops;
    if (header == 35)
        memcpy(raw + 2, packet->transport_id, 16);
    memcpy(raw + header - 17u, packet->destination, 16);
    raw[header - 1u] = packet->context;
    memcpy(raw + header, packet->data, packet->data_size);
    memcpy(output, raw, header + packet->data_size);
    *written = header + packet->data_size;
    return RNC_OK;
}

rnc_result rnc_packet_decode(const uint8_t *data, size_t size, rnc_packet *packet) {
    rnc_packet result = {0};
    size_t header;
    if (!data || !packet)
        return RNC_INVALID;
    if (size < 19 || size > RNC_MAX_MTU)
        return RNC_PROTOCOL;
    if (size > RNC_MTU && (((data[0] >> 2) & 3u) != RNC_LINK || (data[0] & 3u) == RNC_ANNOUNCE))
        return RNC_PROTOCOL;
    if (data[0] & 0x80u)
        return RNC_UNSUPPORTED;
    header = data[0] & 0x40u ? 35u : 19u;
    if (size <= header || data[1] >= 128)
        return RNC_PROTOCOL;
    result.flags = data[0];
    result.hops = data[1];
    if (header == 35)
        memcpy(result.transport_id, data + 2, 16);
    memcpy(result.destination, data + header - 17u, 16);
    result.context = data[header - 1u];
    result.data_size = size - header;
    memcpy(result.data, data + header, result.data_size);
    *packet = result;
    return RNC_OK;
}

rnc_result rnc_packet_hash(const rnc_packet *packet, uint8_t hash[32]) {
    uint8_t raw[RNC_MAX_MTU], hashable[RNC_MAX_MTU];
    size_t size, offset;
    rnc_result result;
    if (!hash)
        return RNC_INVALID;
    result = rnc_packet_encode(packet, raw, sizeof(raw), &size);
    if (result != RNC_OK)
        return result;
    offset = packet->flags & 0x40u ? 18u : 2u;
    hashable[0] = raw[0] & 0x0fu;
    memcpy(hashable + 1, raw + offset, size - offset);
    return rnc_hash(hashable, size - offset + 1u, hash);
}
