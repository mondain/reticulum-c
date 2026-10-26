#include <stddef.h>
#include <stdlib.h>
static unsigned fail_allocation;
static void *fault_malloc(size_t n) {
  if (fail_allocation && --fail_allocation == 0)
    return NULL;
  return malloc(n);
}
static void *fault_calloc(size_t n, size_t size) {
  if (fail_allocation && --fail_allocation == 0)
    return NULL;
  return calloc(n, size);
}
/* Inspect private transfer state and inject failures only in this module.
 * Core crypto and unrelated allocations retain their normal allocator. */
#define malloc fault_malloc
#define calloc fault_calloc
#include "../src/resource.c"
#undef malloc
#undef calloc
#define main resource_fixture_main
#include "test_resource.c"
#undef main
static void allocation_test(void) {
  pair p;
  uint8_t data[600] = {0}, out[600];
  size_t n;
  rnc_packet packet;
  init(&p, 10000);
  CHECK(rnc_resource_send(p.tx, data, sizeof(data), NULL, p.now) == RNC_OK);
  run(&p, 1000);
  CHECK(rnc_resource_read(p.rx, out, sizeof(out), &n) == RNC_OK &&
        n == sizeof(data));
  /* Preserve old completed data for every Resource-owned allocation site. */
  for (unsigned allocation = 1; allocation <= 8; allocation++) {
    fail_allocation = allocation;
    CHECK(rnc_resource_send(p.rx, data, sizeof(data), NULL, p.now) ==
          RNC_NO_SPACE);
    fail_allocation = 0;
    CHECK(rnc_resource_is_complete(p.rx));
    CHECK(p.rx->data != NULL);
    CHECK(rnc_resource_read(p.rx, out, sizeof(out), &n) == RNC_OK &&
          n == sizeof(data) && !memcmp(out, data, n));
  }
  CHECK(rnc_resource_send(p.tx, data, sizeof(data), NULL, p.now) == RNC_OK);
  CHECK(rnc_resource_pump(p.tx, p.now) == RNC_OK);
  packet = outgoing(p.a);
  CHECK(rnc_link_input(p.b, &packet, p.now) == RNC_OK);
  rnc_link_event e;
  CHECK(rnc_link_poll(p.b, &e) == RNC_OK && e.context == 2);
  for (unsigned allocation = 1; allocation <= 6; allocation++) {
    fail_allocation = allocation;
    CHECK(rnc_resource_accept(p.rx, e.data, e.size, p.now) == RNC_NO_SPACE);
    fail_allocation = 0;
    CHECK(p.rx->data != NULL);
    CHECK(rnc_resource_read(p.rx, out, sizeof(out), &n) == RNC_OK &&
          n == sizeof(data));
    CHECK(p.rx->proof_count == 1 && p.rx->state == RES_DONE);
  }
  CHECK(rnc_resource_accept(p.rx, e.data, e.size, p.now) == RNC_OK);
  finish(&p);
}
static void collision_bytes(uint32_t seed, uint8_t out[464]) {
  memset(out, 0, 464);
  out[0] = (uint8_t)seed;
  out[1] = (uint8_t)(seed >> 8);
  out[2] = (uint8_t)(seed >> 16);
  out[3] = (uint8_t)(seed >> 24);
}
static void collision_test(void) {
  rnc_resource r = {0};
  uint8_t first[464], later[464], hash[32], other[32], salt[4] = {1, 2, 3, 4};
  collision_bytes(92195, first);
  collision_bytes(125407, later);
  CHECK(digest2(first, sizeof(first), salt, 4, hash) == RNC_OK);
  CHECK(digest2(later, sizeof(later), salt, 4, other) == RNC_OK);
  CHECK(!memcmp(hash, other, 4) && memcmp(first, later, sizeof(first)));
  r.state = RES_RX_DATA;
  r.sdu = 464;
  r.adv.parts = 227;
  r.adv.transfer = 227 * 464;
  memcpy(r.adv.random, salt, 4);
  CHECK(allocate_segment(&r, r.adv.transfer, r.adv.parts) == RNC_OK);
  r.known = 227;
  r.window = 4;
  r.request_end = 227;
  r.received_count = 225;
  memset(r.received, 1, 225);
  memcpy(r.wire, first, 464);
  memcpy(r.map, hash, 4);
  memcpy(r.map + 225 * 4, hash, 4);
  CHECK(handle_part(&r, later, 464) == RNC_OK);
  CHECK(r.received[225] && r.received_count == 226 &&
        !memcmp(r.wire + 225 * 464, later, 464));
  clear_segment(&r);
  /* Sender's 224-entry collision guard advances when a later hashmap batch
   * is requested. Hashes from old batches must not shadow active parts. */
  memset(&r, 0, sizeof(r));
  r.state = RES_TX_DATA;
  r.outgoing = 1;
  r.sdu = 464;
  r.adv.parts = 300;
  r.adv.transfer = 300 * 464;
  r.receiver_min_consecutive = 150;
  CHECK(allocate_segment(&r, r.adv.transfer, r.adv.parts) == RNC_OK);
  memset(r.adv.hash, 0x44, 32);
  memcpy(r.map, hash, 4);
  memcpy(r.map + 225 * 4, hash, 4);
  uint8_t request[37] = {0};
  memcpy(request + 1, r.adv.hash, 32);
  memcpy(request + 33, hash, 4);
  CHECK(handle_request(&r, request, sizeof(request)) == RNC_OK);
  CHECK(r.wanted[225] && !r.wanted[0]);
  /* The same collision can occur at the final hashmap entry of a batch. */
  r.receiver_min_consecutive = 222;
  memset(r.map + 225 * 4, 0, 4);
  memcpy(r.map + 295 * 4, hash, 4);
  uint8_t hmu[37] = {255};
  memcpy(hmu + 1, hash, 4);
  memcpy(hmu + 5, r.adv.hash, 32);
  CHECK(handle_request(&r, hmu, sizeof(hmu)) == RNC_OK && r.hmu_segment == 4);
  clear_segment(&r);
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  if (!strcmp(argv[1], "allocation"))
    allocation_test();
  else if (!strcmp(argv[1], "collision"))
    collision_test();
  else
    CHECK(0);
  return 0;
}
