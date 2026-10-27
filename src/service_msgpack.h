#ifndef RNC_SERVICE_MSGPACK_H
#define RNC_SERVICE_MSGPACK_H
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
typedef struct rmp {
    const uint8_t *p;
    size_t n, i;
} rmp;
static inline int rmp_take(rmp *r, size_t n, const uint8_t **p) {
    if (n > r->n - r->i)
        return 0;
    if (p)
        *p = r->p + r->i;
    r->i += n;
    return 1;
}
static inline int rmp_num(rmp *r, size_t n, uint64_t *v) {
    const uint8_t *p;
    size_t i;
    if (!rmp_take(r, n, &p))
        return 0;
    *v = 0;
    for (i = 0; i < n; i++)
        *v = (*v << 8) | p[i];
    return 1;
}
static inline int rmp_uint(rmp *r, uint64_t *v) {
    const uint8_t *p;
    if (!rmp_take(r, 1, &p))
        return 0;
    if (*p < 128) {
        *v = *p;
        return 1;
    }
    if (*p >= 0xcc && *p <= 0xcf)
        return rmp_num(r, (size_t)1u << (*p - 0xcc), v);
    return 0;
}
static inline int rmp_len(rmp *r, int str, size_t *len) {
    const uint8_t *p;
    uint64_t n;
    uint8_t t;
    if (!rmp_take(r, 1, &p))
        return 0;
    t = *p;
    if (str && (t & 0xe0) == 0xa0) {
        *len = t & 31;
        return 1;
    }
    if ((str && t >= 0xd9 && t <= 0xdb) || (!str && t >= 0xc4 && t <= 0xc6)) {
        if (!rmp_num(r, (size_t)1u << (t - (str ? 0xd9 : 0xc4)), &n) || n > SIZE_MAX)
            return 0;
        *len = (size_t)n;
        return 1;
    }
    return 0;
}
static inline int rmp_bin(rmp *r, const uint8_t **p, size_t *n) {
    return rmp_len(r, 0, n) && rmp_take(r, *n, p);
}
static inline int rmp_skip_depth(rmp *r, unsigned depth) {
    const uint8_t *p;
    uint8_t t;
    uint64_t n = 0;
    size_t i, bytes = 0;
    int map = 0;
    if (depth > 16 || !rmp_take(r, 1, &p))
        return 0;
    t = *p;
    if (t <= 0x7f || t >= 0xe0 || t == 0xc0 || t == 0xc2 || t == 0xc3)
        return 1;
    if ((t & 0xe0) == 0xa0)
        return rmp_take(r, t & 31, NULL);
    if ((t & 0xf0) == 0x90)
        n = t & 15;
    else if ((t & 0xf0) == 0x80) {
        n = t & 15;
        map = 1;
    } else if (t == 0xdc || t == 0xdd || t == 0xde || t == 0xdf) {
        if (!rmp_num(r, (t & 1) ? 4 : 2, &n))
            return 0;
        map = t >= 0xde;
    } else if (t >= 0xc4 && t <= 0xc6) {
        if (!rmp_num(r, (size_t)1u << (t - 0xc4), &n))
            return 0;
        return n <= SIZE_MAX && rmp_take(r, (size_t)n, NULL);
    } else if (t >= 0xd9 && t <= 0xdb) {
        if (!rmp_num(r, (size_t)1u << (t - 0xd9), &n))
            return 0;
        return n <= SIZE_MAX && rmp_take(r, (size_t)n, NULL);
    } else if (t == 0xca)
        bytes = 4;
    else if (t == 0xcb)
        bytes = 8;
    else if (t >= 0xcc && t <= 0xcf)
        bytes = (size_t)1u << (t - 0xcc);
    else if (t >= 0xd0 && t <= 0xd3)
        bytes = (size_t)1u << (t - 0xd0);
    else if (t >= 0xd4 && t <= 0xd8)
        bytes = ((size_t)1u << (t - 0xd4)) + 1u;
    else if (t >= 0xc7 && t <= 0xc9) {
        if (!rmp_num(r, (size_t)1u << (t - 0xc7), &n) || n >= SIZE_MAX)
            return 0;
        return rmp_take(r, (size_t)n + 1, NULL);
    } else
        return 0;
    if (bytes)
        return rmp_take(r, bytes, NULL);
    if (n > r->n - r->i || n > SIZE_MAX / (map ? 2u : 1u))
        return 0;
    for (i = 0; i < (size_t)n * (map ? 2u : 1u); i++)
        if (!rmp_skip_depth(r, depth + 1))
            return 0;
    return 1;
}
static inline int rmp_value(const void *p, size_t n) {
    rmp r = {(const uint8_t *)p, n, 0};
    return p && rmp_skip_depth(&r, 0) && r.i == n;
}
static inline size_t rmp_put_uint(uint8_t *p, uint64_t v) {
    size_t n = 0, i;
    if (v < 128) {
        p[0] = (uint8_t)v;
        return 1;
    }
    n = v <= UINT8_MAX ? 1 : v <= UINT16_MAX ? 2 : v <= UINT32_MAX ? 4 : 8;
    p[0] = (uint8_t)(n == 1 ? 0xcc : n == 2 ? 0xcd : n == 4 ? 0xce : 0xcf);
    for (i = 0; i < n; i++)
        p[n - i] = (uint8_t)(v >> (8 * i));
    return n + 1;
}
static inline size_t rmp_put_bin(uint8_t *p, const void *v, size_t n) {
    size_t h;
    if (n <= 255) {
        p[0] = 0xc4;
        p[1] = (uint8_t)n;
        h = 2;
    } else if (n <= 65535) {
        p[0] = 0xc5;
        p[1] = (uint8_t)(n >> 8);
        p[2] = (uint8_t)n;
        h = 3;
    } else {
        p[0] = 0xc6;
        p[1] = (uint8_t)(n >> 24);
        p[2] = (uint8_t)(n >> 16);
        p[3] = (uint8_t)(n >> 8);
        p[4] = (uint8_t)n;
        h = 5;
    }
    if (n)
        memcpy(p + h, v, n);
    return h + n;
}
#endif
