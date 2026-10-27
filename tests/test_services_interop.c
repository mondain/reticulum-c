#define _POSIX_C_SOURCE 200809L
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#define main resource_unit_main
#include "test_resource.c"
#undef main
#include "../src/internal.h" /* Test-only access to an established session key. */
#include <reticulum_c/rnc_service.h>
#include <time.h>
#include <unistd.h>
/* C/CPython driver for unchanged RNS protocol methods. Only host I/O hooks
 * (outbound packet capture and packet-cache storage) are supplied by this test.
 * The oracle Link is supplied a session already established by real C links;
 * this test establishes post-handshake wire compatibility, not live routing. */
static PyObject *oracle_rns, *oracle_link, *oracle_frames, *oracle_cache, *oracle_results;
static PyObject *must(PyObject *p) {
    if (!p) {
        PyErr_Print();
        CHECK(p);
    }
    return p;
}
static PyObject *pybytes(const void *p, size_t n) {
    return must(PyBytes_FromStringAndSize(p, (Py_ssize_t)n));
}
static void set_attr(PyObject *o, const char *name, PyObject *value) {
    CHECK(PyObject_SetAttrString(o, name, value) == 0);
}
static void set_int(PyObject *o, const char *name, long n) {
    PyObject *v = must(PyLong_FromLong(n));
    set_attr(o, name, v);
    Py_DECREF(v);
}
static void set_float(PyObject *o, const char *name, double n) {
    PyObject *v = must(PyFloat_FromDouble(n));
    set_attr(o, name, v);
    Py_DECREF(v);
}
static PyObject *attr(PyObject *o, const char *name) {
    return must(PyObject_GetAttrString(o, name));
}
static void add_path(const char *s) {
    PyObject *v = must(PyUnicode_FromString(s));
    CHECK(PyList_Insert(PySys_GetObject("path"), 0, v) == 0);
    Py_DECREF(v);
}
static PyObject *capture(PyObject *self, PyObject *packet) {
    PyObject *raw;
    (void)self;
    raw = PyObject_GetAttrString(packet, "raw");
    if (!raw)
        return NULL;
    if (PyList_Append(oracle_frames, raw) < 0) {
        Py_DECREF(raw);
        return NULL;
    }
    Py_DECREF(raw);
    if (PyObject_SetAttrString(packet, "sent", Py_True) < 0)
        return NULL;
    Py_RETURN_TRUE;
}
static PyObject *cache_packet(PyObject *self, PyObject *args, PyObject *kw) {
    PyObject *packet, *raw, *hash;
    (void)self;
    (void)kw;
    if (!PyArg_ParseTuple(args, "O", &packet))
        return NULL;
    raw = PyObject_GetAttrString(packet, "raw");
    hash = PyObject_GetAttrString(packet, "packet_hash");
    if (!raw || !hash) {
        Py_XDECREF(raw);
        Py_XDECREF(hash);
        return NULL;
    }
    if (PyDict_SetItem(oracle_cache, hash, raw) < 0) {
        Py_DECREF(raw);
        Py_DECREF(hash);
        return NULL;
    }
    Py_DECREF(raw);
    Py_DECREF(hash);
    Py_RETURN_NONE;
}
static PyObject *resource_done(PyObject *self, PyObject *resource) {
    PyObject *data, *value;
    (void)self;
    data = PyObject_GetAttrString(resource, "data");
    if (!data)
        return NULL;
    value = PyObject_CallMethod(data, "read", NULL);
    Py_DECREF(data);
    if (!value)
        return NULL;
    if (PyList_Append(oracle_results, value) < 0) {
        Py_DECREF(value);
        return NULL;
    }
    Py_DECREF(value);
    Py_RETURN_NONE;
}
static PyObject *echo_request(PyObject *self, PyObject *args) {
    PyObject *value;
    (void)self;
    if (!PyTuple_Check(args) || PyTuple_Size(args) != 6) {
        PyErr_SetString(PyExc_TypeError, "echo needs six arguments");
        return NULL;
    }
    value = PyTuple_GetItem(args, 1);
    Py_INCREF(value);
    return value;
}
static PyMethodDef capture_method = {"capture", capture, METH_O, "Capture host packets."};
static PyMethodDef cache_method = {"cache_packet", (PyCFunction)(void (*)(void))cache_packet,
                                   METH_VARARGS | METH_KEYWORDS, "Store host cache."};
static PyMethodDef done_method = {"resource_done", resource_done, METH_O,
                                  "Read completed oracle data."};
static PyMethodDef echo_method = {"echo_request", echo_request, METH_VARARGS,
                                  "Echo application data."};
static PyObject *done_callback;
static void setup_oracle(pair *p, const char *reference, const char *dependencies, char temp[64]) {
    PyObject *cls, *transport, *fn, *callbacks, *nsclass, *types, *v, *crypto, *tokenclass, *key,
        *dest, *handlers, *handler, *module, *echo, *code, *inspect, *signature, *parameters;
    uint8_t hash[32];
    Py_Initialize();
    if (dependencies)
        add_path(dependencies);
    add_path(reference);
    oracle_rns = must(PyImport_ImportModule("RNS"));
    oracle_frames = must(PyList_New(0));
    oracle_cache = must(PyDict_New());
    oracle_results = must(PyList_New(0));
    strcpy(temp, "/tmp/rnc-resource-oracle-XXXXXX");
    CHECK(mkdtemp(temp));
    cls = attr(oracle_rns, "Reticulum");
    v = must(PyUnicode_FromString(temp));
    set_attr(cls, "resourcepath", v);
    Py_DECREF(v);
    Py_DECREF(cls);
    transport = attr(oracle_rns, "Transport");
    fn = must(PyCFunction_New(&capture_method, NULL));
    set_attr(transport, "outbound", fn);
    Py_DECREF(fn);
    fn = must(PyCFunction_New(&cache_method, NULL));
    set_attr(transport, "cache", fn);
    Py_DECREF(fn);
    Py_DECREF(transport);
    cls = attr(oracle_rns, "Link");
    oracle_link = must(PyObject_CallMethod(cls, "__new__", "O", cls));
    v = attr(cls, "ACTIVE");
    set_attr(oracle_link, "status", v);
    Py_DECREF(v);
    v = attr(cls, "ACCEPT_ALL");
    set_attr(oracle_link, "resource_strategy", v);
    Py_DECREF(v);
    Py_DECREF(cls);
    set_int(oracle_link, "type", RNC_LINK);
    set_int(oracle_link, "mtu", (long)rnc_link_mtu(p->a));
    set_int(oracle_link, "mdu", (long)rnc_link_mdu(p->a));
    set_int(oracle_link, "tx", 0);
    set_int(oracle_link, "rx", 0);
    set_int(oracle_link, "txbytes", 0);
    set_int(oracle_link, "rxbytes", 0);
    set_int(oracle_link, "establishment_cost", 300);
    set_int(oracle_link, "traffic_timeout_factor", 6);
    set_float(oracle_link, "rtt", 0.001);
    set_float(oracle_link, "last_outbound", 0);
    set_float(oracle_link, "last_inbound", 0);
    set_float(oracle_link, "last_data", 0);
    set_float(oracle_link, "expected_rate", 100000);
    set_attr(oracle_link, "attached_interface", Py_None);
    set_attr(oracle_link, "_Link__remote_identity", Py_None);
    set_attr(oracle_link, "_Link__track_phy_stats", Py_False);
    set_attr(oracle_link, "initiator", Py_False);
    set_attr(oracle_link, "last_resource_window", Py_None);
    set_attr(oracle_link, "last_resource_eifr", Py_None);
    v = must(PyList_New(0));
    set_attr(oracle_link, "incoming_resources", v);
    Py_DECREF(v);
    v = must(PyList_New(0));
    set_attr(oracle_link, "outgoing_resources", v);
    Py_DECREF(v);
    v = must(PyList_New(0));
    set_attr(oracle_link, "pending_requests", v);
    Py_DECREF(v);
    v = pybytes(p->a->address, 16);
    set_attr(oracle_link, "link_id", v);
    set_attr(oracle_link, "hash", v);
    Py_DECREF(v);
    crypto = attr(oracle_rns, "Cryptography");
    tokenclass = attr(crypto, "Token");
    key = pybytes(p->a->key, 64);
    v = must(PyObject_CallOneArg(tokenclass, key));
    set_attr(oracle_link, "token", v);
    set_attr(oracle_link, "derived_key", key);
    Py_DECREF(v);
    Py_DECREF(key);
    Py_DECREF(tokenclass);
    Py_DECREF(crypto);
    types = must(PyImport_ImportModule("types"));
    nsclass = attr(types, "SimpleNamespace");
    callbacks = must(PyObject_CallNoArgs(nsclass));
    set_attr(callbacks, "resource_started", Py_None);
    done_callback = must(PyCFunction_New(&done_method, NULL));
    set_attr(callbacks, "resource_concluded", done_callback);
    set_attr(callbacks, "resource", Py_None);
    set_attr(callbacks, "packet", Py_None);
    set_attr(oracle_link, "callbacks", callbacks);
    Py_DECREF(callbacks);
    dest = must(PyObject_CallNoArgs(nsclass));
    handlers = must(PyDict_New());
    CHECK(rnc_hash("/echo", 5, hash) == RNC_OK);
    v = pybytes(hash, 16);
    handler = must(PyList_New(5));
    PyList_SET_ITEM(handler, 0, must(PyUnicode_FromString("/echo")));
    echo = must(PyCFunction_New(&echo_method, NULL));
    /* inspect.signature does not infer signatures of C callbacks; assign a
     * Python Signature object describing the six application parameters. */
    inspect = must(PyImport_ImportModule("inspect"));
    signature = attr(inspect, "Signature");
    parameters = must(PyList_New(6));
    code = attr(inspect, "Parameter");
    for (int i = 0; i < 6; i++) {
        char name[8];
        snprintf(name, sizeof(name), "arg%d", i);
        PyObject *param = must(PyObject_CallFunction(code, "si", name, 1));
        PyList_SET_ITEM(parameters, i, param);
    }
    module = must(PyObject_CallFunction(signature, "O", parameters));
    PyObject *functools = must(PyImport_ImportModule("functools"));
    PyObject *partial = attr(functools, "partial");
    PyObject *wrapped = must(PyObject_CallOneArg(partial, echo));
    set_attr(wrapped, "__signature__", module);
    Py_DECREF(echo);
    echo = wrapped;
    Py_DECREF(partial);
    Py_DECREF(functools);
    Py_DECREF(module);
    Py_DECREF(parameters);
    Py_DECREF(code);
    Py_DECREF(signature);
    Py_DECREF(inspect);
    PyList_SET_ITEM(handler, 1, echo);
    PyList_SET_ITEM(handler, 2, must(PyLong_FromLong(1)));
    PyList_SET_ITEM(handler, 3, must(PyList_New(0)));
    Py_INCREF(Py_False);
    PyList_SET_ITEM(handler, 4, Py_False);
    CHECK(PyDict_SetItem(handlers, v, handler) == 0);
    Py_DECREF(handler);
    Py_DECREF(v);
    set_attr(dest, "request_handlers", handlers);
    set_attr(dest, "max_request_size", Py_None);
    Py_DECREF(handlers);
    set_attr(oracle_link, "destination", dest);
    Py_DECREF(dest);
    Py_DECREF(nsclass);
    Py_DECREF(types);
}
static void quiet_wait(void) {
    struct timespec t = {0, 1000000};
    Py_BEGIN_ALLOW_THREADS nanosleep(&t, NULL);
    Py_END_ALLOW_THREADS
}
static void send_to_oracle(const rnc_packet *packet) {
    uint8_t wire[RNC_MAX_MTU];
    size_t n;
    PyObject *cls, *b, *args, *p, *result;
    if (packet->context == 8) {
        PyObject *hash = pybytes(packet->data, packet->data_size),
                 *cached = PyDict_GetItemWithError(oracle_cache, hash);
        if (cached)
            CHECK(PyList_Append(oracle_frames, cached) == 0);
        else
            CHECK(!PyErr_Occurred());
        Py_DECREF(hash);
        return;
    }
    CHECK(rnc_packet_encode(packet, wire, sizeof(wire), &n) == RNC_OK);
    cls = attr(oracle_rns, "Packet");
    b = pybytes(wire, n);
    args = must(PyTuple_Pack(2, Py_None, b));
    p = must(PyObject_CallObject(cls, args));
    result = must(PyObject_CallMethod(p, "unpack", NULL));
    CHECK(PyObject_IsTrue(result));
    Py_DECREF(result);
    set_attr(p, "link", oracle_link);
    result = must(PyObject_CallMethod(oracle_link, "receive", "O", p));
    Py_DECREF(result);
    Py_DECREF(p);
    Py_DECREF(args);
    Py_DECREF(b);
    Py_DECREF(cls);
}
static void receive_from_oracle(pair *p) {
    while (PyList_Size(oracle_frames) > 0) {
        PyObject *b = PyList_GetItem(oracle_frames, 0);
        rnc_packet packet;
        CHECK(PyBytes_Check(b));
        CHECK(rnc_packet_decode((const uint8_t *)PyBytes_AsString(b), (size_t)PyBytes_Size(b),
                                &packet) == RNC_OK);
        CHECK(rnc_link_input(p->a, &packet, p->now) == RNC_OK);
        CHECK(PySequence_DelItem(oracle_frames, 0) == 0);
    }
}
static void drain_native(pair *p, rnc_resource *resource, rnc_service *service) {
    rnc_link_event e;
    while (rnc_link_poll(p->a, &e) == RNC_OK) {
        if (e.type == RNC_LINK_SEND)
            send_to_oracle(&e.packet);
        else if (e.type == RNC_LINK_PACKET || e.type == RNC_LINK_RESOURCE_PACKET) {
            rnc_result result;
            if (service)
                result = rnc_service_input(service, &e, p->now);
            else if (e.type == RNC_LINK_PACKET && e.context == 2)
                result = rnc_resource_accept(resource, e.data, e.size, p->now);
            else
                result = rnc_resource_input(resource, &e, p->now);
            CHECK(result == RNC_OK || result == RNC_AGAIN);
        }
    }
}
static void resource_oracle(pair *p, int sending, int compress, size_t size) {
    uint8_t *data = malloc(size), *copy = malloc(size);
    rng random = {1234567};
    size_t n;
    unsigned i;
    PyObject *reference = NULL, *klass, *args, *kw, *b, *result;
    CHECK(data && copy);
    if (compress)
        memset(data, 0, size);
    else
        random_bytes(&random, data, size);
    if (sending) {
        rnc_resource_options o = {0};
        o.compress = compress;
        CHECK(rnc_resource_send(p->tx, data, size, &o, p->now) == RNC_OK);
    } else {
        klass = attr(oracle_rns, "Resource");
        b = pybytes(data, size);
        args = must(PyTuple_Pack(2, b, oracle_link));
        kw = must(PyDict_New());
        CHECK(PyDict_SetItemString(kw, "advertise", Py_False) == 0 &&
              PyDict_SetItemString(kw, "auto_compress", compress ? Py_True : Py_False) == 0);
        reference = must(PyObject_Call(klass, args, kw));
        result = must(PyObject_CallMethod(reference, "_Resource__advertise_job", NULL));
        Py_DECREF(result);
        Py_DECREF(kw);
        Py_DECREF(args);
        Py_DECREF(b);
        Py_DECREF(klass);
    }
    for (i = 0; i < 20000; i++) {
        rnc_resource_event e;
        CHECK(rnc_resource_pump(p->tx, p->now) == RNC_OK);
        drain_native(p, p->tx, NULL);
        receive_from_oracle(p);
        drain_native(p, p->tx, NULL);
        while (rnc_resource_poll(p->tx, &e) == RNC_OK) {
            CHECK(e.type != RNC_RESOURCE_FAILED);
        }
        if (sending && rnc_resource_is_complete(p->tx) && PyList_Size(oracle_results) == 1)
            break;
        if (!sending && rnc_resource_is_complete(p->tx)) {
            result = attr(reference, "status");
            long status = PyLong_AsLong(result);
            Py_DECREF(result);
            if (status == 6)
                break;
        }
        p->now += 1;
        CHECK(rnc_resource_tick(p->tx, p->now) == RNC_OK);
        quiet_wait();
    }
    CHECK(i < 20000);
    if (sending) {
        result = PyList_GetItem(oracle_results, 0);
        CHECK(PyBytes_Check(result) && PyBytes_Size(result) == (Py_ssize_t)size &&
              !memcmp(PyBytes_AsString(result), data, size));
    } else {
        CHECK(rnc_resource_read(p->tx, copy, size, &n) == RNC_OK && n == size &&
              !memcmp(data, copy, size));
    }
    Py_XDECREF(reference);
    free(data);
    free(copy);
    puts(sending ? "Resource C->unmodified RNS passed" : "Resource unmodified RNS->C passed");
}

static PyObject *response_done(PyObject *self, PyObject *receipt) {
    PyObject *response;
    (void)self;
    response = PyObject_GetAttrString(receipt, "response");
    if (!response)
        return NULL;
    if (PyList_Append(oracle_results, response) < 0) {
        Py_DECREF(response);
        return NULL;
    }
    Py_DECREF(response);
    Py_RETURN_NONE;
}
static PyMethodDef response_method = {"response_done", response_done, METH_O, "Record response."};
static PyObject *pending_receipt(const uint8_t id[16]) {
    PyObject *module = must(PyImport_ImportModule("RNS.Link"));
    PyObject *cls = attr(module, "RequestReceipt");
    PyObject *receipt = must(PyObject_CallMethod(cls, "__new__", "O", cls));
    PyObject *v = pybytes(id, 16);
    set_attr(receipt, "request_id", v);
    Py_DECREF(v);
    set_int(receipt, "status", 1);
    set_attr(receipt, "max_response_size", Py_None);
    set_attr(receipt, "packet_receipt", Py_None);
    set_attr(receipt, "response_size", Py_None);
    set_attr(receipt, "response_transfer_size", Py_None);
    set_attr(receipt, "started_at", Py_None);
    set_attr(receipt, "link", oracle_link);
    PyObject *types = must(PyImport_ImportModule("types"));
    PyObject *ns = attr(types, "SimpleNamespace");
    PyObject *callbacks = must(PyObject_CallNoArgs(ns));
    PyObject *fn = must(PyCFunction_New(&response_method, NULL));
    set_attr(callbacks, "response", fn);
    Py_DECREF(fn);
    set_attr(callbacks, "progress", Py_None);
    set_attr(callbacks, "failed", Py_None);
    set_attr(receipt, "callbacks", callbacks);
    Py_DECREF(callbacks);
    v = attr(oracle_link, "pending_requests");
    CHECK(PyList_Append(v, receipt) == 0);
    Py_DECREF(v);
    Py_DECREF(ns);
    Py_DECREF(types);
    Py_DECREF(cls);
    Py_DECREF(module);
    return receipt;
}
static PyObject *reference_request(const uint8_t *data, size_t size, uint8_t id[16]) {
    uint8_t hash[32];
    PyObject *mp = must(PyImport_ImportModule("RNS.vendor.umsgpack"));
    PyObject *request = must(PyList_New(3));
    CHECK(rnc_hash("/echo", 5, hash) == RNC_OK);
    PyList_SET_ITEM(request, 0, must(PyFloat_FromDouble(1700000000.25)));
    PyList_SET_ITEM(request, 1, pybytes(hash, 16));
    PyList_SET_ITEM(request, 2, pybytes(data, size));
    PyObject *packed = must(PyObject_CallMethod(mp, "packb", "O", request));
    PyObject *reference = NULL, *result;
    PyObject *mdu_object = attr(oracle_link, "mdu");
    long inline_capacity = PyLong_AsLong(mdu_object);
    Py_DECREF(mdu_object);
    if (PyBytes_Size(packed) <= inline_capacity) {
        PyObject *klass = attr(oracle_rns, "Packet");
        PyObject *args = must(PyTuple_Pack(2, oracle_link, packed));
        PyObject *kw = must(PyDict_New());
        PyObject *context = must(PyLong_FromLong(9));
        CHECK(PyDict_SetItemString(kw, "context", context) == 0);
        reference = must(PyObject_Call(klass, args, kw));
        result = must(PyObject_CallMethod(reference, "send", NULL));
        Py_DECREF(result);
        result = must(PyObject_CallMethod(reference, "getTruncatedHash", NULL));
        CHECK(PyBytes_Check(result) && PyBytes_Size(result) == 16);
        memcpy(id, PyBytes_AsString(result), 16);
        Py_DECREF(result);
        Py_DECREF(context);
        Py_DECREF(kw);
        Py_DECREF(args);
        Py_DECREF(klass);
    } else {
        CHECK(rnc_hash(PyBytes_AsString(packed), (size_t)PyBytes_Size(packed), hash) == RNC_OK);
        memcpy(id, hash, 16);
        PyObject *klass = attr(oracle_rns, "Resource");
        PyObject *args = must(PyTuple_Pack(2, packed, oracle_link));
        PyObject *kw = must(PyDict_New());
        PyObject *qid = pybytes(id, 16);
        CHECK(PyDict_SetItemString(kw, "advertise", Py_False) == 0);
        CHECK(PyDict_SetItemString(kw, "auto_compress", Py_False) == 0);
        CHECK(PyDict_SetItemString(kw, "request_id", qid) == 0);
        reference = must(PyObject_Call(klass, args, kw));
        result = must(PyObject_CallMethod(reference, "_Resource__advertise_job", NULL));
        Py_DECREF(result);
        Py_DECREF(qid);
        Py_DECREF(kw);
        Py_DECREF(args);
        Py_DECREF(klass);
    }
    PyObject *receipt = pending_receipt(id);
    Py_DECREF(receipt);
    Py_DECREF(packed);
    Py_DECREF(request);
    Py_DECREF(mp);
    return reference;
}
static void service_oracle(pair *p, int client, size_t size) {
    uint8_t *data = malloc(size), *encoded = malloc(size + 5), *copy = malloc(size + 5), id[16];
    rng random = {0x12345678};
    size_t n, vn;
    unsigned i, complete = 0;
    CHECK(data && encoded && copy);
    random_bytes(&random, data, size);
    if (size < 256) {
        encoded[0] = 0xc4;
        encoded[1] = (uint8_t)size;
        vn = 2;
    } else {
        encoded[0] = 0xc5;
        encoded[1] = (uint8_t)(size >> 8);
        encoded[2] = (uint8_t)size;
        vn = 3;
    }
    memcpy(encoded + vn, data, size);
    vn += size;
    rnc_service *service = rnc_service_new(p->a, size + 100, random_bytes, &p->ar);
    CHECK(service);
    PyObject *reference = NULL;
    if (client)
        CHECK(rnc_service_request(service, "/echo", encoded, vn, 1700000000.25, p->now, 30000,
                                  id) == RNC_OK);
    else {
        CHECK(rnc_service_register(service, "/echo", RNC_SERVICE_ALLOW_ALL, NULL, 0) == RNC_OK);
        reference = reference_request(data, size, id);
    }
    for (i = 0; i < 20000 && !complete; i++) {
        rnc_service_event e;
        CHECK(rnc_service_pump(service, p->now) == RNC_OK);
        drain_native(p, NULL, service);
        receive_from_oracle(p);
        drain_native(p, NULL, service);
        while (rnc_service_poll(service, &e, copy, size + 5, &n) == RNC_OK) {
            CHECK(n == vn && !memcmp(encoded, copy, vn) && !memcmp(e.request_id, id, 16));
            if (client) {
                CHECK(e.type == RNC_SERVICE_RESPONSE);
                complete++;
            } else {
                CHECK(e.type == RNC_SERVICE_REQUEST);
                CHECK(rnc_service_respond(service, id, copy, n, p->now) == RNC_OK);
            }
        }
        if (!client && PyList_Size(oracle_results)) {
            PyObject *result = PyList_GetItem(oracle_results, 0);
            CHECK(PyBytes_Check(result) && PyBytes_Size(result) == (Py_ssize_t)size &&
                  !memcmp(PyBytes_AsString(result), data, size));
            complete++;
        }
        p->now += 1;
        CHECK(rnc_service_tick(service, p->now) == RNC_OK);
        quiet_wait();
    }
    CHECK(complete == 1);
    /* Flush the final Resource proof before releasing the response state. */
    CHECK(rnc_service_pump(service, p->now) == RNC_OK);
    drain_native(p, NULL, service);
    quiet_wait();
    Py_XDECREF(reference);
    rnc_service_free(service);
    free(data);
    free(encoded);
    free(copy);
    puts(client ? "Request/response C client <-> unmodified RNS passed"
                : "Request/response unmodified RNS client <-> C passed");
}
int main(int argc, char **argv) {
    pair p;
    char temp[64];
    int sending, compress;
    size_t size;
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "usage: %s RNS_CHECKOUT MODE [ORACLE_DEPENDENCIES]\n", argv[0]);
        return 2;
    }
    sending = !strcmp(argv[2], "large_send") || !strcmp(argv[2], "send") ||
              !strcmp(argv[2], "send_compressed") || !strcmp(argv[2], "segments");
    compress = !strcmp(argv[2], "send_compressed") || !strcmp(argv[2], "receive_compressed");
    size = !strcmp(argv[2], "segments") ? RNC_RESOURCE_SEGMENT_MAX + 5000u : 50000u;
    init_with_mtu(&p, size + 100, !strncmp(argv[2], "large_", 6) ? 4096 : RNC_MTU);
    setup_oracle(&p, argv[1], argc == 4 ? argv[3] : NULL, temp);
    if (strstr(argv[2], "service_"))
        service_oracle(&p, strstr(argv[2], "client") != NULL,
                       strstr(argv[2], "bulk")          ? 50000u
                       : !strncmp(argv[2], "large_", 6) ? 2000u
                                                        : 60u);
    else
        resource_oracle(&p, sending, compress, size);
    quiet_wait();
    Py_DECREF(done_callback);
    Py_DECREF(oracle_link);
    Py_DECREF(oracle_results);
    Py_DECREF(oracle_cache);
    Py_DECREF(oracle_frames);
    Py_DECREF(oracle_rns);
    CHECK(Py_FinalizeEx() == 0);
    finish(&p);
    CHECK(rmdir(temp) == 0);
    return 0;
}
