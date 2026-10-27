#include <reticulum_c/rnc_ipc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef RNC_IPC_WITH_PYTHON
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#endif
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                  \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static rnc_result rng(void *ctx, uint8_t *out, size_t n) {
  uint8_t *v = ctx;
  while (n--)
    *out++ = (*v)++;
  return RNC_OK;
}
static void pair_ready(rnc_rpc **a, rnc_rpc **b) {
  static uint8_t ar = 1, br = 43;
  rnc_rpc_event e;
  unsigned i;
  size_t n;
  *a = rnc_rpc_new("shared secret", 13, 0, rng, &ar, 1024);
  *b = rnc_rpc_new("shared secret", 13, 1, rng, &br, 1024);
  CHECK(*a && *b && rnc_rpc_start(*a, 100) == RNC_OK &&
        rnc_rpc_start(*b, 100) == RNC_OK);
  for (i = 0; i < 16 &&
              (!rnc_rpc_is_authenticated(*a) || !rnc_rpc_is_authenticated(*b));
       i++) {
    while (rnc_rpc_poll(*b, &e) == RNC_OK)
      if (e.type == RNC_RPC_SEND)
        CHECK(rnc_rpc_input(*a, e.data, e.size, &n, 101 + i) == RNC_OK &&
              n == e.size);
    while (rnc_rpc_poll(*a, &e) == RNC_OK)
      if (e.type == RNC_RPC_SEND)
        CHECK(rnc_rpc_input(*b, e.data, e.size, &n, 101 + i) == RNC_OK &&
              n == e.size);
  }
  CHECK(rnc_rpc_is_authenticated(*a) && rnc_rpc_is_authenticated(*b));
  while (rnc_rpc_poll(*a, &e) == RNC_OK) {
  }
  while (rnc_rpc_poll(*b, &e) == RNC_OK) {
  }
}
static void handshake(void) {
  rnc_rpc *a, *b;
  rnc_rpc_event e;
  uint8_t ar = 1, br = 2;
  size_t n, i;
  const uint8_t msg[] = {0x81, 0xa3, 'g', 'e', 't', 0xaa, 'l', 'i',
                         'n',  'k',  '_', 'c', 'o', 'u',  'n', 't'};
  pair_ready(&a, &b);
  CHECK(rnc_rpc_send(a, msg, sizeof(msg), 200) == RNC_OK);
  CHECK(rnc_rpc_poll(a, &e) == RNC_OK && e.type == RNC_RPC_SEND &&
        e.size == sizeof(msg) + 4);
  for (i = 0; i < e.size; i++)
    CHECK(rnc_rpc_input(b, e.data + i, 1, &n, 201 + i) == RNC_OK && n == 1);
  CHECK(rnc_rpc_poll(b, &e) == RNC_OK && e.type == RNC_RPC_MESSAGE &&
        e.size == sizeof(msg) && !memcmp(e.data, msg, e.size));
  CHECK(rnc_rpc_close(a) == RNC_OK && !rnc_rpc_is_authenticated(a));
  rnc_rpc_free(a);
  rnc_rpc_free(b);
  a = rnc_rpc_new("a", 1, 0, rng, &ar, 1024);
  b = rnc_rpc_new("a", 1, 1, rng, &br, 1024);
  CHECK(a && b && rnc_rpc_start(a, 0) == RNC_OK &&
        rnc_rpc_start(b, 0) == RNC_OK);
  CHECK(rnc_rpc_poll(b, &e) == RNC_OK);
  CHECK(rnc_rpc_input(a, e.data, e.size, &n, 30000) == RNC_TIMEOUT);
  rnc_rpc_free(a);
  rnc_rpc_free(b);
}
static void bounds(void) {
  rnc_rpc *a, *b;
  rnc_rpc_event e;
  uint8_t ar = 1, br = 2, huge[] = {0, 1, 0, 1};
  size_t n;
  pair_ready(&a, &b);
  CHECK(rnc_rpc_input(b, huge, sizeof(huge), &n, 500) == RNC_PROTOCOL &&
        !rnc_rpc_is_authenticated(b));
  rnc_rpc_free(a);
  rnc_rpc_free(b);
  a = rnc_rpc_new("a", 1, 0, rng, &ar, 1024);
  b = rnc_rpc_new("b", 1, 1, rng, &br, 1024);
  CHECK(a && b && rnc_rpc_start(a, 0) == RNC_OK &&
        rnc_rpc_start(b, 0) == RNC_OK);
  CHECK(rnc_rpc_poll(b, &e) == RNC_OK &&
        rnc_rpc_input(a, e.data, e.size, &n, 1) == RNC_OK);
  CHECK(rnc_rpc_poll(a, &e) == RNC_OK &&
        rnc_rpc_input(b, e.data, e.size, &n, 2) == RNC_AUTH &&
        !rnc_rpc_is_authenticated(b));
  rnc_rpc_free(a);
  rnc_rpc_free(b);
  a = rnc_rpc_new("a", 1, 1, rng, &ar, 1024);
  CHECK(a && rnc_rpc_start(a, 100) == RNC_OK &&
        rnc_rpc_tick(a, 30100) == RNC_OK && !rnc_rpc_is_authenticated(a));
  CHECK(rnc_rpc_tick(a, 30000) == RNC_INVALID);
  rnc_rpc_free(a);
  pair_ready(&a, &b);
  for (n = 0; n < RNC_RPC_EVENTS; n++)
    CHECK(rnc_rpc_send(a, "x", 1, 600) == RNC_OK);
  CHECK(rnc_rpc_send(a, "x", 1, 600) == RNC_AGAIN);
  CHECK(rnc_rpc_input(a, (const uint8_t *)"x", 1, &n, 600) == RNC_AGAIN &&
        n == 0);
  rnc_rpc_free(a);
  rnc_rpc_free(b);
}
static void query(void) {
  rnc_rpc_query q, saved;
  uint8_t get[] = {0x81, 0xa3, 'g', 'e', 't', 0xaa, 'l', 'i',
                   'n',  'k',  '_', 'c', 'o', 'u',  'n', 't'};
  CHECK(rnc_rpc_decode_query(get, sizeof(get), &q) == RNC_OK &&
        q.type == RNC_RPC_LINK_COUNT);
  saved = q;
  {
    uint8_t nul[] = {0x81, 0xa3, 'g', 'e', 't', 0xab, 'l', 'i', 'n',
                     'k',  '_',  'c', 'o', 'u', 'n',  't', 0};
    CHECK(rnc_rpc_decode_query(nul, sizeof(nul), &q) != RNC_OK);
  }
  get[5] = 0xdb;
  CHECK(rnc_rpc_decode_query(get, sizeof(get), &q) == RNC_PROTOCOL &&
        !memcmp(&saved, &q, sizeof(q)));
  {
    uint8_t d[] = {0x82, 0xa3, 'g', 'e', 't', 0xaa, 'p', 'a',  't',
                   'h',  '_',  't', 'a', 'b', 'l',  'e', 0xa8, 'm',
                   'a',  'x',  '_', 'h', 'o', 'p',  's', 0xc0};
    CHECK(rnc_rpc_decode_query(d, sizeof(d), &q) == RNC_OK &&
          q.type == RNC_RPC_PATH_TABLE && !q.has_max_hops);
  }
  {
    uint8_t unsupported[] = {0x81, 0xa4, 'd', 'r', 'o', 'p',
                             0xa4, 'p',  'a', 't', 'h'};
    CHECK(rnc_rpc_decode_query(unsupported, sizeof(unsupported), &q) != RNC_OK);
  }
}
static size_t unhex(const char *hex, uint8_t *out) {
  size_t i, n = strlen(hex) / 2;
  for (i = 0; i < n; ++i) {
    unsigned v;
    CHECK(sscanf(hex + 2 * i, "%2x", &v) == 1);
    out[i] = (uint8_t)v;
  }
  return n;
}
/* Bytes below were produced by RNS.vendor.umsgpack (reference RPC clients). */
static void blackhole_rpc(void) {
  uint8_t msg[256], id[16];
  rnc_rpc_query q;
  rnc_rpc_command c;
  size_t n;
  memset(id, 0x11, 16);
  n = unhex("82a3676574ad69735f626c61636b686f6c6564ad6964656e746974795f68617368"
            "c41011111111111111111111111111111111",
            msg);
  CHECK(rnc_rpc_decode_query(msg, n, &q) == RNC_OK &&
        q.type == RNC_RPC_IS_BLACKHOLED && q.has_identity &&
        !memcmp(q.identity_hash, id, 16));
  /* is_blackholed needs the identity */
  n = unhex("81a3676574ad69735f626c61636b686f6c6564", msg);
  CHECK(rnc_rpc_decode_query(msg, n, &q) == RNC_PROTOCOL);
  /* mutating calls are not queries */
  n = unhex("81b4756e626c61636b686f6c655f6964656e74697479c410"
            "11111111111111111111111111111111",
            msg);
  CHECK(rnc_rpc_decode_query(msg, n, &q) != RNC_OK);
  CHECK(rnc_rpc_decode_command(msg, n, &c) == RNC_OK &&
        c.type == RNC_RPC_UNBLACKHOLE_IDENTITY && !memcmp(c.identity, id, 16));
  n = unhex("83b2626c61636b686f6c655f6964656e74697479c4101111111111111111111111"
            "1111111111a5756e74696cc0a6726561736f6ec0",
            msg);
  CHECK(rnc_rpc_decode_command(msg, n, &c) == RNC_OK &&
        c.type == RNC_RPC_BLACKHOLE_IDENTITY && c.until == 0 &&
        c.reason[0] == 0 && !memcmp(c.identity, id, 16));
  n = unhex("83b2626c61636b686f6c655f6964656e74697479c4101111111111111111111111"
            "1111111111a5756e74696ccb41edcd6500100000a6726561736f6ea47370616d",
            msg);
  CHECK(rnc_rpc_decode_command(msg, n, &c) == RNC_OK &&
        c.type == RNC_RPC_BLACKHOLE_IDENTITY && c.until == 4000000000u &&
        !strcmp(c.reason, "spam"));
  /* wrong identity size and queries are rejected without output */
  n = unhex("81b2626c61636b686f6c655f6964656e74697479c4021111", msg);
  memset(&c, 0, sizeof(c));
  CHECK(rnc_rpc_decode_command(msg, n, &c) == RNC_PROTOCOL && !c.type);
  n = unhex("81a3676574aa6c696e6b5f636f756e74", msg);
  CHECK(rnc_rpc_decode_command(msg, n, &c) == RNC_UNSUPPORTED);
}
static void writer(void) {
  uint8_t out[128], tiny = 42;
  rnc_rpc_writer w;
  size_t n;
  rnc_rpc_writer_init(&w, out, sizeof(out));
  CHECK(rnc_rpc_write_map(&w, 2) == RNC_OK &&
        rnc_rpc_write_string(&w, "interfaces") == RNC_OK &&
        rnc_rpc_write_array(&w, 0) == RNC_OK &&
        rnc_rpc_write_string(&w, "transport_id") == RNC_OK &&
        rnc_rpc_write_nil(&w) == RNC_OK &&
        rnc_rpc_writer_finish(&w, &n) == RNC_OK && n > 0);
  rnc_rpc_writer_init(&w, &tiny, 1);
  CHECK(rnc_rpc_write_uint(&w, 1000) == RNC_NO_SPACE && tiny == 42 &&
        rnc_rpc_writer_finish(&w, &n) == RNC_NO_SPACE && n == 0);
  rnc_rpc_writer_init(&w, out, sizeof(out));
  CHECK(rnc_rpc_write_array(&w, 1) == RNC_OK &&
        rnc_rpc_writer_finish(&w, &n) == RNC_PROTOCOL);
  rnc_rpc_writer_init(&w, out, sizeof(out));
  CHECK(rnc_rpc_write_string(&w, "\xc0\x80") == RNC_INVALID);
}
#ifdef RNC_IPC_WITH_PYTHON
static PyObject *py_must(PyObject *p) {
  if (!p) {
    PyErr_Print();
    CHECK(p);
  }
  return p;
}
static PyObject *py_bytes(const void *p, size_t n) {
  return py_must(PyBytes_FromStringAndSize(p, (Py_ssize_t)n));
}
static void py_path(const char *path) {
  PyObject *p = py_must(PyUnicode_FromString(path));
  CHECK(PyList_Insert(PySys_GetObject("path"), 0, p) == 0);
  Py_DECREF(p);
}
static void oracle(int argc, char **argv) {
  static const char *digests[] = {"sha256", "sha384", "sha3_256", "sha3_384",
                                  NULL};
  PyObject *module, *key, *expected, *verified, *body, *mac, *mp, *dict, *get,
      *dest, *packed, *decoded;
  rnc_rpc *a, *b;
  rnc_rpc_event e;
  uint8_t random = 1, frame[260], challenge_bytes[80], out[512], address[16];
  size_t i, j, n, consumed, hn;
  rnc_rpc_query q;
  rnc_rpc_writer w;
  Py_Initialize();
  if (argc >= 4)
    py_path(argv[3]);
  if (argc >= 3)
    py_path(argv[2]);
  module = py_must(PyImport_ImportModule("multiprocessing.connection"));
  key = py_bytes("shared secret", 13);
  for (i = 0; i < 5; i++) {
    if (i < 4) {
      int z = snprintf((char *)challenge_bytes, sizeof(challenge_bytes), "{%s}",
                       digests[i]);
      CHECK(z > 0);
      hn = (size_t)z;
      for (j = 0; j < 40; j++)
        challenge_bytes[hn + j] = (uint8_t)j;
      hn += 40;
    } else {
      hn = 20;
      for (j = 0; j < hn; j++)
        challenge_bytes[j] = (uint8_t)j;
    }
    n = 11 + hn;
    frame[0] = frame[1] = frame[2] = 0;
    frame[3] = (uint8_t)n;
    memcpy(frame + 4, "#CHALLENGE#", 11);
    memcpy(frame + 15, challenge_bytes, hn);
    a = rnc_rpc_new("shared secret", 13, 0, rng, &random, 1024);
    CHECK(a && rnc_rpc_start(a, 0) == RNC_OK &&
          rnc_rpc_input(a, frame, n + 4, &consumed, 1) == RNC_OK &&
          consumed == n + 4);
    CHECK(rnc_rpc_poll(a, &e) == RNC_OK && e.type == RNC_RPC_SEND &&
          e.size > 4);
    body = py_bytes(challenge_bytes, hn);
    expected = py_must(
        PyObject_CallMethod(module, "_create_response", "OO", key, body));
    CHECK(PyBytes_Size(expected) == (Py_ssize_t)e.size - 4 &&
          !memcmp(PyBytes_AsString(expected), e.data + 4, e.size - 4));
    mac = py_bytes(e.data + 4, e.size - 4);
    verified = py_must(PyObject_CallMethod(module, "_verify_challenge", "OOO",
                                           key, body, mac));
    CHECK(verified == Py_None);
    Py_DECREF(verified);
    Py_DECREF(mac);
    Py_DECREF(expected);
    Py_DECREF(body);
    rnc_rpc_free(a);
  }
  b = rnc_rpc_new("shared secret", 13, 1, rng, &random, 1024);
  CHECK(b && rnc_rpc_start(b, 0) == RNC_OK && rnc_rpc_poll(b, &e) == RNC_OK);
  body = py_bytes(e.data + 15, e.size - 15);
  expected =
      py_must(PyObject_CallMethod(module, "_create_response", "OO", key, body));
  n = (size_t)PyBytes_Size(expected);
  frame[0] = frame[1] = frame[2] = 0;
  frame[3] = (uint8_t)n;
  memcpy(frame + 4, PyBytes_AsString(expected), n);
  CHECK(rnc_rpc_input(b, frame, n + 4, &consumed, 1) == RNC_OK &&
        rnc_rpc_poll(b, &e) == RNC_OK && e.type == RNC_RPC_SEND &&
        e.size == 13 && !memcmp(e.data + 4, "#WELCOME#", 9));
  Py_DECREF(expected);
  Py_DECREF(body);
  rnc_rpc_free(b);
  Py_DECREF(key);
  Py_DECREF(module);
  puts("RPC HMAC challenge/digest compatibility: C <-> unmodified CPython "
       "passed");
  if (argc >= 3) {
    mp = py_must(PyImport_ImportModule("RNS.vendor.umsgpack"));
    dict = py_must(PyDict_New());
    get = py_must(PyUnicode_FromString("next_hop"));
    for (i = 0; i < 16; i++)
      address[i] = (uint8_t)i;
    dest = py_bytes(address, 16);
    CHECK(PyDict_SetItemString(dict, "get", get) == 0 &&
          PyDict_SetItemString(dict, "destination_hash", dest) == 0);
    packed = py_must(PyObject_CallMethod(mp, "packb", "O", dict));
    CHECK(rnc_rpc_decode_query(PyBytes_AsString(packed),
                               (size_t)PyBytes_Size(packed), &q) == RNC_OK &&
          q.type == RNC_RPC_NEXT_HOP && q.has_destination &&
          !memcmp(q.destination_hash, address, 16));
    rnc_rpc_writer_init(&w, out, sizeof(out));
    CHECK(rnc_rpc_write_map(&w, 3) == RNC_OK &&
          rnc_rpc_write_string(&w, "interfaces") == RNC_OK &&
          rnc_rpc_write_array(&w, 1) == RNC_OK &&
          rnc_rpc_write_map(&w, 2) == RNC_OK &&
          rnc_rpc_write_string(&w, "name") == RNC_OK &&
          rnc_rpc_write_string(&w, "test0") == RNC_OK &&
          rnc_rpc_write_string(&w, "online") == RNC_OK &&
          rnc_rpc_write_bool(&w, 1) == RNC_OK &&
          rnc_rpc_write_string(&w, "transport_id") == RNC_OK &&
          rnc_rpc_write_bin(&w, address, 16) == RNC_OK &&
          rnc_rpc_write_string(&w, "uptime") == RNC_OK &&
          rnc_rpc_write_real(&w, 1.5) == RNC_OK &&
          rnc_rpc_writer_finish(&w, &n) == RNC_OK);
    body = py_bytes(out, n);
    decoded = py_must(PyObject_CallMethod(mp, "unpackb", "O", body));
    CHECK(PyDict_Check(decoded) &&
          PyList_Size(PyDict_GetItemString(decoded, "interfaces")) == 1 &&
          PyFloat_AsDouble(PyDict_GetItemString(decoded, "uptime")) == 1.5);
    expected = PyDict_GetItemString(decoded, "transport_id");
    CHECK(PyBytes_Size(expected) == 16 &&
          !memcmp(PyBytes_AsString(expected), address, 16));
    Py_DECREF(decoded);
    Py_DECREF(body);
    Py_DECREF(packed);
    Py_DECREF(dest);
    Py_DECREF(get);
    Py_DECREF(dict);
    Py_DECREF(mp);
    puts("RPC MessagePack query/response compatibility: C <-> unmodified RNS "
         "passed");
  }
  CHECK(Py_FinalizeEx() == 0);
}
#endif
int main(int argc, char **argv) {
#ifdef RNC_IPC_WITH_PYTHON
  if (argc >= 2 && !strcmp(argv[1], "oracle")) {
    oracle(argc, argv);
    return 0;
  }
#endif
  CHECK(argc == 2);
  if (!strcmp(argv[1], "handshake"))
    handshake();
  else if (!strcmp(argv[1], "bounds"))
    bounds();
  else if (!strcmp(argv[1], "query"))
    query();
  else if (!strcmp(argv[1], "blackhole"))
    blackhole_rpc();
  else if (!strcmp(argv[1], "writer"))
    writer();
  else
    CHECK(0);
  return 0;
}
