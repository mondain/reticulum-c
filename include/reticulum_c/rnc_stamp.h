#ifndef RETICULUM_C_STAMP_H
#define RETICULUM_C_STAMP_H
#include <reticulum_c/rnc.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Proof-of-work stamps as LXMF's LXStamper defines them (the reference uses
 * them to rate-limit interface discovery announces). A workblock is the
 * concatenation of HKDF-SHA256 outputs (256 bytes each, salted with
 * SHA256(material || msgpack(round))), and a stamp's value is the number of
 * leading zero bits of SHA256(workblock || stamp). */
#define RNC_STAMP_SIZE 32u
#define RNC_STAMP_ROUND_SIZE 256u
#define RNC_STAMP_MAX_ROUNDS 4096u
/* Needs 256 * rounds bytes of capacity; outputs commit only on success. */
rnc_result rnc_stamp_workblock(const void *material, size_t size,
                               unsigned rounds, uint8_t *workblock,
                               size_t capacity, size_t *written);
/* Leading zero bits (0-256) of SHA256(workblock || stamp); 0 on error. */
unsigned rnc_stamp_value(const uint8_t *workblock, size_t workblock_size,
                         const uint8_t stamp[RNC_STAMP_SIZE]);
/* 1 when SHA256(workblock || stamp) <= 2^(256 - cost), as stamp_valid(). */
int rnc_stamp_valid(const uint8_t *workblock, size_t workblock_size,
                    const uint8_t stamp[RNC_STAMP_SIZE], unsigned cost);
/* Searches for a stamp of at least `cost` bits over a workblock built from
 * `material`. max_attempts bounds the work (0 = 1 << 32); RNC_TIMEOUT when it
 * is exhausted. The search starts at a random point and counts up. */
rnc_result rnc_stamp_generate(const void *material, size_t size, unsigned rounds,
                              unsigned cost, rnc_random_fn random,
                              void *random_context, uint64_t max_attempts,
                              uint8_t stamp[RNC_STAMP_SIZE]);
/* Resumable search for event loops: tries up to `attempts` stamps starting at
 * *cursor (any 32 bytes; the low 8 count up) and advances it. RNC_OK with the
 * stamp when one meets `cost`, RNC_AGAIN when this slice found none. The
 * workblock is built once by the caller with rnc_stamp_workblock. */
rnc_result rnc_stamp_find(const uint8_t *workblock, size_t workblock_size,
                          unsigned cost, uint8_t cursor[RNC_STAMP_SIZE],
                          uint64_t attempts, uint8_t stamp[RNC_STAMP_SIZE]);
#ifdef __cplusplus
}
#endif
#endif
