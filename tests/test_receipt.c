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
/* Receipts can be queried after the fact: pending, then delivered or failed
 * with the RTT, and unknown hashes report as culled. */
static void status(void) {
  pair p = setup();
  rnc_packet d = data_to(&p, "query"), d2 = data_to(&p, "never");
  rnc_node_event e, proof;
  rnc_receipt_status st = RNC_RECEIPT_DELIVERED;
  uint64_t rtt = 99;
  uint8_t hash[32], hash2[32], unknown[32] = {1};
  CHECK(rnc_node_set_proof_strategy(p.b, p.dest, RNC_PROVE_ALL) == RNC_OK);
  CHECK(rnc_node_send_tracked(p.a, &d, 5000, 1000, 100, hash) == RNC_OK);
  CHECK(rnc_node_receipt_status(p.a, hash, &st, &rtt) == RNC_OK &&
        st == RNC_RECEIPT_SENT && rtt == 0);
  CHECK(rnc_node_receipt_status(p.a, unknown, &st, &rtt) == RNC_STATE);
  CHECK(next(p.a, RNC_NODE_SEND, &e));
  CHECK(rnc_node_input(p.b, 1, &e.packet, 1000, 130) == RNC_OK);
  CHECK(next(p.b, RNC_NODE_SEND, &proof));
  CHECK(rnc_node_input(p.a, 1, &proof.packet, 1000, 160) == RNC_OK);
  CHECK(next(p.a, RNC_NODE_RECEIPT, &e));
  CHECK(rnc_node_receipt_status(p.a, hash, &st, &rtt) == RNC_OK &&
        st == RNC_RECEIPT_DELIVERED && rtt == 60);
  /* a second packet nobody proves fails but stays queryable */
  CHECK(rnc_node_set_proof_strategy(p.b, p.dest, RNC_PROVE_NONE) == RNC_OK);
  CHECK(rnc_node_send_tracked(p.a, &d2, 1000, 1000, 200, hash2) == RNC_OK);
  CHECK(rnc_node_tick(p.a, 1000, 1300) == RNC_OK);
  CHECK(next(p.a, RNC_NODE_RECEIPT, &e));
  CHECK(rnc_node_receipt_status(p.a, hash2, &st, &rtt) == RNC_OK &&
        st == RNC_RECEIPT_FAILED && rtt == 1100);
  CHECK(rnc_node_receipt_status(p.a, hash, &st, &rtt) == RNC_OK &&
        st == RNC_RECEIPT_DELIVERED);
  release(&p);
}
/* Every slot holding a pending receipt blocks a new one; finished receipts
 * are recycled, oldest first, so tracking never wedges. */
static void recycle(void) {
  pair p = setup();
  rnc_node_event e;
  rnc_receipt_status st;
  uint64_t rtt;
  uint8_t first[32], hash[32];
  unsigned i;
  for (i = 0; i < RNC_NODE_RECEIPTS; ++i) {
    char text[16];
    rnc_packet d;
    snprintf(text, sizeof(text), "p%u", i);
    d = data_to(&p, text);
    CHECK(rnc_node_send_tracked(p.a, &d, 1000, 1000, 100, i ? hash : first) ==
          RNC_OK);
    while (next(p.a, RNC_NODE_SEND, &e)) {
    }
  }
  {
    rnc_packet d = data_to(&p, "overflow");
    CHECK(rnc_node_send_tracked(p.a, &d, 1000, 1000, 100, hash) == RNC_AGAIN);
    CHECK(rnc_node_tick(p.a, 1000, 1200) == RNC_OK);
    while (next(p.a, RNC_NODE_RECEIPT, &e)) {
    }
    CHECK(rnc_node_receipt_status(p.a, first, &st, &rtt) == RNC_OK &&
          st == RNC_RECEIPT_FAILED);
    CHECK(rnc_node_send_tracked(p.a, &d, 1000, 1000, 1300, hash) == RNC_OK);
    CHECK(rnc_node_receipt_status(p.a, hash, &st, &rtt) == RNC_OK &&
          st == RNC_RECEIPT_SENT);
  }
  release(&p);
}
/* Timeout 0 asks for the reference default: first hop (one MTU at the
 * interface rate plus 6 s) and 6 s per hop. */
static void default_timeout(void) {
  pair p = setup();
  rnc_packet d = data_to(&p, "default");
  rnc_route route;
  rnc_node_event e;
  uint64_t timeout = 0, want;
  uint8_t hash[32], none[16] = {9};
  CHECK(rnc_node_lookup(p.a, p.dest, 100, &route) == RNC_OK);
  want = 6000u + 4000000u / 1000000u + 6000u * route.hops;
  CHECK(rnc_node_receipt_timeout(p.a, p.dest, 100, &timeout) == RNC_OK &&
        timeout == want);
  CHECK(rnc_node_receipt_timeout(p.a, none, 100, &timeout) == RNC_STATE);
  CHECK(rnc_node_send_tracked(p.a, &d, 0, 1000, 100, hash) == RNC_OK);
  while (next(p.a, RNC_NODE_SEND, &e)) {
  }
  CHECK(rnc_node_tick(p.a, 1000, 100 + want - 1) == RNC_OK);
  CHECK(!next(p.a, RNC_NODE_RECEIPT, &e));
  CHECK(rnc_node_tick(p.a, 1000, 100 + want) == RNC_OK);
  CHECK(next(p.a, RNC_NODE_RECEIPT, &e) &&
        e.receipt_status == RNC_RECEIPT_FAILED);
  release(&p);
}
/* use_implicit_proof = No: the destination answers with the 96 byte explicit
 * proof (hash plus signature), and the sender still accepts it. */
static void explicit_proof(void) {
  pair p = setup();
  rnc_packet d = data_to(&p, "explicit");
  rnc_node_event e, proof;
  uint8_t hash[32];
  CHECK(rnc_node_implicit_proofs(p.b) == 1);
  CHECK(rnc_node_set_implicit_proofs(p.b, 0) == RNC_OK &&
        rnc_node_implicit_proofs(p.b) == 0);
  CHECK(rnc_node_set_proof_strategy(p.b, p.dest, RNC_PROVE_ALL) == RNC_OK);
  CHECK(rnc_node_send_tracked(p.a, &d, 5000, 1000, 100, hash) == RNC_OK);
  CHECK(next(p.a, RNC_NODE_SEND, &e));
  CHECK(rnc_node_input(p.b, 1, &e.packet, 1000, 130) == RNC_OK);
  CHECK(next(p.b, RNC_NODE_SEND, &proof));
  CHECK((proof.packet.flags & 3u) == RNC_PROOF && proof.packet.data_size == 96u);
  CHECK(!memcmp(proof.packet.data, hash, 32));
  CHECK(rnc_node_input(p.a, 1, &proof.packet, 1000, 160) == RNC_OK);
  CHECK(next(p.a, RNC_NODE_RECEIPT, &e) &&
        e.receipt_status == RNC_RECEIPT_DELIVERED);
  CHECK(rnc_node_set_implicit_proofs(p.b, 2) == RNC_INVALID);
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
  else if (!strcmp(argv[1], "explicit_proof"))
    explicit_proof();
  else if (!strcmp(argv[1], "status"))
    status();
  else if (!strcmp(argv[1], "recycle"))
    recycle();
  else if (!strcmp(argv[1], "default_timeout"))
    default_timeout();
  else
    return 2;
  return 0;
}
