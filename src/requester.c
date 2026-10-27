#include "service_msgpack.h"
#include <openssl/crypto.h>
#include <reticulum_c/rnc_link.h>
#include <reticulum_c/rnc_requester.h>
#include <stdlib.h>
#include <string.h>

#define REQUESTER_PATH_MAX 64u
#define REQUESTER_CLOSE_GRACE_MS 2000u
enum job_state { JOB_OPENING = 1, JOB_REQUESTED, JOB_CLOSING };
typedef struct requester_job {
  int used, finished, released;
  enum job_state state;
  rnc_link *link;
  rnc_service *service;
  uint8_t id[16], destination[16], request_id[16];
  int has_request_id;
  double last_progress;
  rnc_identity identify;
  int has_identify;
  char path[REQUESTER_PATH_MAX];
  uint8_t *value;
  size_t value_size;
  uint32_t tag;
  uint64_t deadline, close_deadline;
  rnc_requester_status status;
  uint8_t *response;
  size_t response_size;
} requester_job;
struct rnc_requester {
  rnc_node *node;
  size_t max_value;
  rnc_random_fn random;
  void *random_context;
  uint8_t *scratch;
  requester_job jobs[RNC_REQUESTER_JOBS];
};
rnc_requester *rnc_requester_new(rnc_node *node, size_t max_value,
                                 rnc_random_fn random, void *random_context) {
  rnc_requester *r;
  if (!node || !random)
    return NULL;
  r = calloc(1, sizeof(*r));
  if (!r)
    return NULL;
  r->node = node;
  r->max_value = max_value ? max_value : 1048576u;
  r->random = random;
  r->random_context = random_context;
  r->scratch = malloc(r->max_value);
  if (!r->scratch) {
    free(r);
    return NULL;
  }
  return r;
}
static void job_release_link(rnc_requester *r, requester_job *j) {
  if (j->released)
    return;
  (void)rnc_node_unbind_link(r->node, j->id);
  rnc_service_free(j->service);
  rnc_link_free(j->link);
  j->service = NULL;
  j->link = NULL;
  j->released = 1;
}
static void job_clear(rnc_requester *r, requester_job *j) {
  job_release_link(r, j);
  if (j->value)
    OPENSSL_cleanse(j->value, j->value_size);
  free(j->value);
  free(j->response);
  OPENSSL_cleanse(j, sizeof(*j));
}
void rnc_requester_free(rnc_requester *r) {
  size_t i;
  if (!r)
    return;
  for (i = 0; i < RNC_REQUESTER_JOBS; i++)
    if (r->jobs[i].used)
      job_clear(r, &r->jobs[i]);
  OPENSSL_cleanse(r->scratch, r->max_value);
  free(r->scratch);
  OPENSSL_cleanse(r, sizeof(*r));
  free(r);
}
rnc_result rnc_requester_start(rnc_requester *r, const uint8_t destination[16],
                               const rnc_identity *identify, const char *path,
                               const void *encoded_value, size_t value_size,
                               uint32_t tag, uint64_t timeout_ms,
                               uint64_t unix_seconds, uint64_t now_ms) {
  requester_job *j = NULL;
  rnc_route route;
  size_t i, n;
  rnc_result result;
  if (!r || !destination || !path || !*path || !encoded_value || !value_size ||
      value_size > r->max_value || !rmp_value(encoded_value, value_size) ||
      !timeout_ms || timeout_ms > UINT64_MAX - now_ms ||
      (identify && !identify->has_private))
    return RNC_INVALID;
  n = strlen(path);
  if (n >= REQUESTER_PATH_MAX)
    return RNC_INVALID;
  (void)unix_seconds;
  for (i = 0; i < RNC_REQUESTER_JOBS; i++)
    if (!r->jobs[i].used) {
      j = &r->jobs[i];
      break;
    }
  if (!j)
    return RNC_AGAIN;
  result = rnc_node_lookup(r->node, destination, now_ms, &route);
  if (result != RNC_OK)
    return RNC_STATE;
  memset(j, 0, sizeof(*j));
  j->link = rnc_link_new(r->random, r->random_context);
  j->service = j->link ? rnc_service_new(j->link, r->max_value, r->random,
                                         r->random_context)
                       : NULL;
  j->value = malloc(value_size);
  if (!j->service || !j->value) {
    result = RNC_NO_SPACE;
    goto fail;
  }
  result = rnc_link_configure_mtu(j->link,
                                  rnc_node_link_mtu_to(r->node, destination, now_ms));
  if (result == RNC_OK)
    result = rnc_link_open(j->link, &route.announce, now_ms);
  if (result == RNC_OK)
    result = rnc_link_address(j->link, j->id);
  if (result == RNC_OK)
    result = rnc_node_bind_link_on(r->node, j->id, route.interface_id);
  if (result != RNC_OK)
    goto fail;
  memcpy(j->value, encoded_value, value_size);
  j->value_size = value_size;
  memcpy(j->path, path, n);
  memcpy(j->destination, destination, 16);
  if (identify) {
    j->identify = *identify;
    j->has_identify = 1;
  }
  j->tag = tag;
  j->deadline = now_ms + timeout_ms;
  j->state = JOB_OPENING;
  j->used = 1;
  return RNC_OK;
fail:
  if (j->service)
    rnc_service_free(j->service);
  if (j->link)
    rnc_link_free(j->link);
  free(j->value);
  OPENSSL_cleanse(j, sizeof(*j));
  return result;
}
rnc_result rnc_requester_input(rnc_requester *r, const rnc_node_event *event,
                               uint64_t unix_seconds, uint64_t now_ms) {
  size_t i;
  rnc_result result;
  (void)unix_seconds;
  if (!r || !event)
    return RNC_INVALID;
  if (event->type != RNC_NODE_LOCAL)
    return RNC_AGAIN;
  for (i = 0; i < RNC_REQUESTER_JOBS; i++) {
    requester_job *j = &r->jobs[i];
    if (j->used && !j->released &&
        !memcmp(j->id, event->packet.destination, 16)) {
      result = rnc_link_input(j->link, &event->packet, now_ms);
      return result == RNC_AGAIN ? RNC_NO_SPACE : RNC_OK;
    }
  }
  return RNC_AGAIN;
}
static void job_finish(requester_job *j, rnc_requester_status status,
                       uint64_t now) {
  if (j->finished)
    return;
  j->finished = 1;
  j->status = status;
  j->state = JOB_CLOSING;
  j->close_deadline = now + REQUESTER_CLOSE_GRACE_MS;
  (void)rnc_link_close(j->link, now);
}
static void job_service_events(rnc_requester *r, requester_job *j,
                               uint64_t now) {
  rnc_service_event event;
  size_t got;
  while (rnc_service_poll(j->service, &event, r->scratch, r->max_value, &got) ==
         RNC_OK) {
    if (event.type == RNC_SERVICE_RESPONSE && !j->finished) {
      j->response = got ? malloc(got) : NULL;
      if (got && !j->response)
        job_finish(j, RNC_REQUESTER_FAILED, now);
      else {
        if (got)
          memcpy(j->response, r->scratch, got);
        j->response_size = got;
        job_finish(j, RNC_REQUESTER_DONE, now);
      }
    } else if (event.type == RNC_SERVICE_TIMEOUT ||
               event.type == RNC_SERVICE_FAILED)
      job_finish(j, RNC_REQUESTER_FAILED, now);
  }
}
rnc_result rnc_requester_tick(rnc_requester *r, uint64_t unix_seconds,
                              uint64_t now_ms) {
  size_t i;
  if (!r)
    return RNC_INVALID;
  for (i = 0; i < RNC_REQUESTER_JOBS; i++) {
    requester_job *j = &r->jobs[i];
    rnc_link_event le;
    int closed = 0;
    if (!j->used || j->released)
      continue;
    if (j->state != JOB_CLOSING && now_ms >= j->deadline)
      job_finish(j, RNC_REQUESTER_FAILED, now_ms);
    (void)rnc_link_tick(j->link, now_ms);
    while (rnc_link_poll(j->link, &le) == RNC_OK) {
      if (le.type == RNC_LINK_SEND)
        (void)rnc_node_send(r->node, &le.packet, unix_seconds, now_ms);
      else if (le.type == RNC_LINK_PACKET ||
               le.type == RNC_LINK_RESOURCE_PACKET ||
               le.type == RNC_LINK_CLOSED) {
        (void)rnc_service_input(j->service, &le, now_ms);
        if (le.type == RNC_LINK_CLOSED)
          closed = 1;
      }
    }
    if (j->state == JOB_OPENING && rnc_link_is_active(j->link)) {
      uint64_t remaining = j->deadline > now_ms ? j->deadline - now_ms : 1;
      uint8_t request_id[16];
      if (j->has_identify)
        (void)rnc_link_identify(j->link, &j->identify, now_ms);
      if (rnc_service_request(j->service, j->path, j->value, j->value_size,
                              (double)unix_seconds, now_ms, remaining,
                              request_id) == RNC_OK) {
        memcpy(j->request_id, request_id, 16);
        j->has_request_id = 1;
        j->state = JOB_REQUESTED;
      }
      else
        job_finish(j, RNC_REQUESTER_FAILED, now_ms);
    }
    if (j->state != JOB_CLOSING) {
      (void)rnc_service_pump(j->service, now_ms);
      (void)rnc_service_tick(j->service, now_ms);
      if (j->has_request_id) {
        rnc_request_state state;
        double value;
        if (rnc_service_request_state(j->service, j->request_id, &state,
                                      &value) == RNC_OK)
          j->last_progress = value;
      }
      job_service_events(r, j, now_ms);
    }
    /* flush packets queued by the above (request, identify, teardown) */
    while (rnc_link_poll(j->link, &le) == RNC_OK) {
      if (le.type == RNC_LINK_SEND)
        (void)rnc_node_send(r->node, &le.packet, unix_seconds, now_ms);
      else if (le.type == RNC_LINK_CLOSED)
        closed = 1;
    }
    if (closed && !j->finished)
      job_finish(j, RNC_REQUESTER_FAILED, now_ms);
    if (j->state == JOB_CLOSING &&
        (closed || now_ms >= j->close_deadline))
      job_release_link(r, j);
  }
  return RNC_OK;
}
rnc_result rnc_requester_progress(const rnc_requester *r, uint32_t tag,
                                  rnc_request_state *state, double *progress) {
  size_t i;
  if (!r || !state)
    return RNC_INVALID;
  for (i = 0; i < RNC_REQUESTER_JOBS; i++) {
    const requester_job *j = &r->jobs[i];
    double value = 0;
    if (!j->used || j->tag != tag)
      continue;
    if (j->finished) {
      *state = j->status == RNC_REQUESTER_DONE ? RNC_REQUEST_READY
                                               : RNC_REQUEST_FAILED;
      value = *state == RNC_REQUEST_READY ? 1.0 : j->last_progress;
    } else if (j->has_request_id && j->service &&
               rnc_service_request_state(j->service, j->request_id, state,
                                         &value) == RNC_OK) {
    } else
      *state = RNC_REQUEST_SENT;
    if (progress)
      *progress = value;
    return RNC_OK;
  }
  return RNC_STATE;
}
rnc_result rnc_requester_poll(rnc_requester *r, rnc_requester_result *result,
                              void *response, size_t capacity) {
  size_t i;
  if (!r || !result)
    return RNC_INVALID;
  for (i = 0; i < RNC_REQUESTER_JOBS; i++) {
    requester_job *j = &r->jobs[i];
    if (!j->used || !j->finished || !j->released)
      continue;
    memset(result, 0, sizeof(*result));
    result->tag = j->tag;
    result->status = j->status;
    memcpy(result->destination, j->destination, 16);
    result->size = j->response_size;
    if (j->response_size > capacity || (j->response_size && !response))
      return RNC_NO_SPACE;
    if (j->response_size)
      memcpy(response, j->response, j->response_size);
    job_clear(r, j);
    return RNC_OK;
  }
  return RNC_AGAIN;
}
