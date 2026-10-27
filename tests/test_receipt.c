#include <reticulum_c/rnc_node.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                  \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static uint32_t seed = 11;
static rnc_result rng(void *ctx, uint8_t *p, size_t n) {
  size_t i;
  (void)ctx;
  for (i = 0; i < n; i++) {
    seed = seed * 1664525u + 1013904223u;
    p[i] = (uint8_t)(seed >> 24);
  }
  return RNC_OK;
}
typedef struct pair {
  rnc_node *a, *b;
  rnc_identity ida, idb;
  uint8_t dest[16];
} pair;
static int next(rnc_node *n, rnc_node_event_type type, rnc_node_event *out) {
  rnc_node_event e;
  while (rnc_node_poll(n, &e) == RNC_OK)
    if (e.type == type) {
      *out = e;
      return 1;
    }
  return 0;
}
/* A and B each have interface 1 joined directly; A learns B's announce. */
static pair setup(void) {
  pair p;
  rnc_node_event e;
  CHECK(rnc_identity_generate(&p.ida, rng, NULL) == RNC_OK);
  CHECK(rnc_identity_generate(&p.idb, rng, NULL) == RNC_OK);
  p.a = rnc_node_new(&p.ida, 0, rng, NULL);
  p.b = rnc_node_new(&p.idb, 0, rng, NULL);
  CHECK(p.a && p.b);
  CHECK(rnc_node_add_interface(p.a, 1, 1000000) == RNC_OK);
  CHECK(rnc_node_add_interface(p.b, 1, 1000000) == RNC_OK);
  CHECK(rnc_node_add_destination(p.b, &p.idb, "receipt.test", NULL, 0,
                                 p.dest) == RNC_OK);
  CHECK(rnc_node_announce(p.b, p.dest, 1000, 0) == RNC_OK);
  CHECK(rnc_node_tick(p.b, 1000, 10) == RNC_OK);
  CHECK(next(p.b, RNC_NODE_SEND, &e));
  CHECK(rnc_node_input(p.a, 1, &e.packet, 1000, 20) == RNC_OK);
  return p;
}
static void release(pair *p) {
  rnc_node_free(p->a);
  rnc_node_free(p->b);
}
static rnc_packet data_to(const pair *p, const char *text) {
  rnc_packet d = {0};
  memcpy(d.destination, p->dest, 16);
  d.data_size = strlen(text);
  memcpy(d.data, text, d.data_size);
  return d;
}
/* PROVE_ALL: destination proves; sender's receipt reports delivery and RTT. */
static void prove_all(void) {
  pair p = setup();
  rnc_packet d = data_to(&p, "hello");
  rnc_node_event e, proof;
  uint8_t hash[32];
  CHECK(rnc_node_set_proof_strategy(p.b, p.dest, RNC_PROVE_ALL) == RNC_OK);
  CHECK(rnc_node_send_tracked(p.a, &d, 5000, 1000, 100, hash) == RNC_OK);
  CHECK(next(p.a, RNC_NODE_SEND, &e));
  CHECK(rnc_node_input(p.b, 1, &e.packet, 1000, 130) == RNC_OK);
  CHECK(next(p.b, RNC_NODE_LOCAL, &e));
  CHECK(next(p.b, RNC_NODE_SEND, &proof));
  CHECK((proof.packet.flags & 3u) == RNC_PROOF);
  CHECK(proof.packet.data_size == 64u || proof.packet.data_size == 96u);
  CHECK(rnc_node_input(p.a, 1, &proof.packet, 1000, 160) == RNC_OK);
  CHECK(next(p.a, RNC_NODE_RECEIPT, &e));
  CHECK(e.receipt_status == RNC_RECEIPT_DELIVERED);
  CHECK(!memcmp(e.receipt_hash, hash, 32));
  CHECK(e.rtt_ms == 60);
  release(&p);
}
/* PROVE_NONE (default): no proof is generated; the receipt times out. */
static void timeout(void) {
  pair p = setup();
  rnc_packet d = data_to(&p, "silent");
  rnc_node_event e;
  uint8_t hash[32];
  CHECK(rnc_node_send_tracked(p.a, &d, 5000, 1000, 100, hash) == RNC_OK);
  CHECK(next(p.a, RNC_NODE_SEND, &e));
  CHECK(rnc_node_input(p.b, 1, &e.packet, 1000, 130) == RNC_OK);
  CHECK(next(p.b, RNC_NODE_LOCAL, &e));
  CHECK(!next(p.b, RNC_NODE_SEND, &e));
  CHECK(rnc_node_tick(p.a, 1000, 4000) == RNC_OK);
  CHECK(!next(p.a, RNC_NODE_RECEIPT, &e));
  CHECK(rnc_node_tick(p.a, 1000, 5200) == RNC_OK);
  CHECK(next(p.a, RNC_NODE_RECEIPT, &e));
  CHECK(e.receipt_status == RNC_RECEIPT_FAILED);
  CHECK(!memcmp(e.receipt_hash, hash, 32));
  release(&p);
}
/* PROVE_APP: the application proves explicitly using the ingress interface. */
static void prove_app(void) {
  pair p = setup();
  rnc_packet d = data_to(&p, "ask");
  rnc_node_event e, local, proof;
  uint8_t hash[32];
  CHECK(rnc_node_set_proof_strategy(p.b, p.dest, RNC_PROVE_APP) == RNC_OK);
  CHECK(rnc_node_send_tracked(p.a, &d, 5000, 1000, 100, hash) == RNC_OK);
  CHECK(next(p.a, RNC_NODE_SEND, &e));
  CHECK(rnc_node_input(p.b, 1, &e.packet, 1000, 130) == RNC_OK);
  CHECK(next(p.b, RNC_NODE_LOCAL, &local));
  CHECK(!next(p.b, RNC_NODE_SEND, &proof));
  CHECK(rnc_node_prove(p.b, p.dest, &local.packet, local.interface_id, 1,
                       1000, 140) == RNC_OK);
  CHECK(next(p.b, RNC_NODE_SEND, &proof));
  CHECK(proof.packet.data_size == 64u);
  CHECK(rnc_node_input(p.a, 1, &proof.packet, 1000, 150) == RNC_OK);
  CHECK(next(p.a, RNC_NODE_RECEIPT, &e));
  CHECK(e.receipt_status == RNC_RECEIPT_DELIVERED);
  release(&p);
}
/* A proof signed by another identity must not satisfy the receipt. */
static void forged(void) {
  pair p = setup();
  rnc_packet d = data_to(&p, "spoof"), proof = {0};
  rnc_node_event e;
  rnc_identity evil;
  uint8_t hash[32];
  CHECK(rnc_identity_generate(&evil, rng, NULL) == RNC_OK);
  CHECK(rnc_node_send_tracked(p.a, &d, 5000, 1000, 100, hash) == RNC_OK);
  CHECK(next(p.a, RNC_NODE_SEND, &e));
  /* Valid proof layout for the real packet hash, signed by the wrong key. */
  proof.flags = RNC_PROOF;
  memcpy(proof.destination, hash, 16);
  CHECK(rnc_identity_sign(&evil, hash, 32, proof.data) == RNC_OK);
  proof.data_size = 64;
  CHECK(rnc_node_input(p.a, 1, &proof, 1000, 150) != RNC_OK);
  CHECK(!next(p.a, RNC_NODE_RECEIPT, &e));
  CHECK(rnc_node_tick(p.a, 1000, 5200) == RNC_OK);
  CHECK(next(p.a, RNC_NODE_RECEIPT, &e));
  CHECK(e.receipt_status == RNC_RECEIPT_FAILED);
  release(&p);
}
int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  if (!strcmp(argv[1], "prove_all"))
    prove_all();
  else if (!strcmp(argv[1], "timeout"))
    timeout();
  else if (!strcmp(argv[1], "prove_app"))
    prove_app();
  else if (!strcmp(argv[1], "forged"))
    forged();
  else
    return 2;
  return 0;
}
