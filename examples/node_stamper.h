/* Destination stamps (RNS 1.6), for the node daemon and the command line tools (tool_stamps.h). Every local
 * SINGLE destination gets a stamp over its public data (destination hash, public key, name hash). The search is
 * plain hashing and runs on worker threads in slices, so shutdown and reloads never wait on it; the caller's
 * main loop collects a finished stamp with stamper_step, which hands it to the node and saves it in
 * <state>.stamps so a restart does not search again. The node itself never waits for a stamp: until one is
 * loaded the destination's announces and path responses go out unstamped. */
#ifndef RNC_EXAMPLES_NODE_STAMPER_H
#define RNC_EXAMPLES_NODE_STAMPER_H
#include "pr_stamp.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <reticulum_c/rnc.h>
#include <reticulum_c/rnc_log.h>
#include <pthread.h>
#ifdef __linux__
#include <sys/syscall.h>
/* the strict POSIX feature level of node_daemon.c hides these; a worker lowers its own scheduling priority */
extern int setpriority(int which, unsigned int who, int prio); /* id_t is unsigned int; musl hides the type here */
extern long syscall(long number, ...);
#define STAMPER_PRIO_PROCESS 0
#endif
#define STAMPER_MAX_WORKERS 16u
#define STAMPER_MAX_DESTINATIONS 16u
#define STAMPER_SLICE 65536u
typedef struct stamper_entry {
  uint8_t destination[16], stamp[RNC_NETSTAMP_SIZE];
} stamper_entry;
typedef struct stamper_options {
  int stamp_destinations, stamp_prs;
  double destination_value, pr_value, pr_stamp_timeout;
  unsigned workers, niceness; /* workers 0: one per core */
} stamper_options;
static struct stamper {
  int enabled, searching, found, cancel;
  rnc_node *node;
  char path[1100]; /* <state>.stamps; empty without a state file */
  double value, pr_value, pr_timeout;
  unsigned workers, niceness, started, live; /* live: workers still searching */
  pthread_t threads[STAMPER_MAX_WORKERS];
  pthread_mutex_t lock;
  uint8_t job_destination[16], job_material[90], job_stamp[RNC_NETSTAMP_SIZE];
  stamper_entry done[STAMPER_MAX_DESTINATIONS]; /* loaded into the node */
  size_t done_count;
  stamper_entry kept[STAMPER_MAX_DESTINATIONS]; /* saved ones not in use: another program sharing the file, or a
                                                   destination not registered yet; written back on save */
  size_t kept_count;
  uint8_t gave_up[STAMPER_MAX_DESTINATIONS][16]; /* destinations whose search failed; not retried in this run */
  size_t gave_up_count;
} stp;
static int stamper_has(const uint8_t destination[16]) {
  size_t i;
  for (i = 0; i < stp.done_count; ++i)
    if (!memcmp(stp.done[i].destination, destination, 16))
      return 1;
  for (i = 0; i < stp.gave_up_count; ++i)
    if (!memcmp(stp.gave_up[i], destination, 16))
      return 1;
  return 0;
}
static int stamper_write(const char *path, const uint8_t *data, size_t size) {
  char temp[1200];
  size_t used = 0;
  int fd, ok = 0;
  if (snprintf(temp, sizeof(temp), "%s.tmp.XXXXXX", path) >= (int)sizeof(temp))
    return 0;
  fd = mkstemp(temp);
  if (fd < 0)
    return 0;
  if (fchmod(fd, 0600) == 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) == 0) {
    while (used < size) {
      ssize_t n = write(fd, data + used, size - used);
      if (n < 0 && errno == EINTR)
        continue;
      if (n <= 0)
        break;
      used += (size_t)n;
    }
    ok = used == size && fsync(fd) == 0;
  }
  ok = close(fd) == 0 && ok && rename(temp, path) == 0;
  if (!ok)
    (void)unlink(temp);
  return ok;
}
static void stamper_save(void) {
  uint8_t data[8 + STAMPER_MAX_DESTINATIONS * sizeof(stamper_entry) + 32];
  size_t n = 6, i, count = 0;
  if (!stp.path[0])
    return;
  memcpy(data, "RNST", 4);
  data[4] = 1;
  for (i = 0; i < stp.done_count + stp.kept_count && count < STAMPER_MAX_DESTINATIONS; ++i, ++count) {
    const stamper_entry *e = i < stp.done_count ? &stp.done[i] : &stp.kept[i - stp.done_count];
    memcpy(data + n, e->destination, 16);
    memcpy(data + n + 16, e->stamp, RNC_NETSTAMP_SIZE);
    n += sizeof(stamper_entry);
  }
  data[5] = (uint8_t)count;
  if (rnc_hash(data, n, data + n) != RNC_OK)
    return;
  if (!stamper_write(stp.path, data, n + 32))
    rnc_logf(RNC_LOG_WARNING, "stamps", "cannot save %s", stp.path);
}
/* Gives the node the saved stamp of `destination`, if there is one and it still verifies. */
static int stamper_apply_kept(const uint8_t destination[16]) {
  size_t i;
  for (i = 0; i < stp.kept_count; ++i)
    if (!memcmp(stp.kept[i].destination, destination, 16)) {
      rnc_result r = rnc_node_set_destination_stamp(stp.node, destination, stp.kept[i].stamp);
      if (r == RNC_STATE)
        return 0;
      if (r == RNC_OK && stp.done_count < STAMPER_MAX_DESTINATIONS) {
        stp.done[stp.done_count++] = stp.kept[i];
        rnc_logf(RNC_LOG_VERBOSE, "stamps", "stamp loaded from %s", stp.path);
      }
      stp.kept[i] = stp.kept[--stp.kept_count]; /* in use now, or no longer good (another value or identity) */
      return r == RNC_OK;
    }
  return 0;
}
/* Stamps found by an earlier run; each is applied once its destination is registered. */
static void stamper_load(void) {
  uint8_t data[8 + STAMPER_MAX_DESTINATIONS * sizeof(stamper_entry) + 32], digest[32];
  FILE *f;
  size_t got, count, i;
  if (!stp.path[0] || !(f = fopen(stp.path, "rb")))
    return;
  got = fread(data, 1, sizeof(data), f);
  fclose(f);
  if (got < 38 || memcmp(data, "RNST", 4) || data[4] != 1)
    return;
  count = data[5];
  if (count > STAMPER_MAX_DESTINATIONS || got != 6 + count * sizeof(stamper_entry) + 32 ||
      rnc_hash(data, got - 32, digest) != RNC_OK || memcmp(digest, data + got - 32, 32))
    return;
  for (i = 0; i < count; ++i)
    memcpy(&stp.kept[stp.kept_count++], data + 6 + i * sizeof(stamper_entry), sizeof(stamper_entry));
}
static void *stamper_worker_run(void *unused);
static void *stamper_worker(void *unused) {
  void *r = stamper_worker_run(unused);
  pthread_mutex_lock(&stp.lock);
  if (stp.live)
    --stp.live;
  pthread_mutex_unlock(&stp.lock);
  return r;
}
static void *stamper_worker_run(void *unused) {
  uint8_t stamp[RNC_NETSTAMP_SIZE];
  (void)unused;
#ifdef __linux__
  if (stp.niceness)
    (void)setpriority(STAMPER_PRIO_PROCESS, (unsigned int)syscall(SYS_gettid), (int)stp.niceness);
#endif
  for (;;) {
    rnc_result r;
    int stop;
    pthread_mutex_lock(&stp.lock);
    stop = stp.cancel || stp.found;
    pthread_mutex_unlock(&stp.lock);
    if (stop)
      return NULL;
    r = rnc_netstamp_find(stp.job_material, sizeof(stp.job_material), stp.value, stamp_random, NULL, STAMPER_SLICE,
                          stamp, NULL);
    if (r == RNC_OK) {
      pthread_mutex_lock(&stp.lock);
      if (!stp.found && !stp.cancel) {
        memcpy(stp.job_stamp, stamp, sizeof(stamp));
        stp.found = 1;
      }
      pthread_mutex_unlock(&stp.lock);
      return NULL;
    }
    if (r != RNC_TIMEOUT)
      return NULL;
  }
}
static void stamper_join(void) {
  unsigned i;
  pthread_mutex_lock(&stp.lock);
  stp.cancel = 1;
  pthread_mutex_unlock(&stp.lock);
  for (i = 0; i < stp.started; ++i)
    pthread_join(stp.threads[i], NULL);
  stp.started = 0;
  stp.searching = 0;
}
static void stamper_begin(const uint8_t destination[16]) {
  unsigned i;
  if (rnc_node_destination_stamp_material(stp.node, destination, stp.job_material) != RNC_OK)
    return;
  memcpy(stp.job_destination, destination, 16);
  stp.found = 0;
  stp.cancel = 0;
  stp.live = stp.workers; /* counted down by each worker as it leaves; a thread that cannot start leaves at once */
  for (i = 0; i < stp.workers; ++i)
    if (pthread_create(&stp.threads[stp.started], NULL, stamper_worker, NULL) == 0)
      ++stp.started;
    else {
      pthread_mutex_lock(&stp.lock);
      --stp.live;
      pthread_mutex_unlock(&stp.lock);
    }
  stp.searching = stp.started != 0;
  if (stp.searching)
    rnc_logf(RNC_LOG_VERBOSE, "stamps", "searching a destination stamp of value %.2f on %u worker(s)", stp.value,
             stp.started);
}
/* Path requests are stamped inline: at pr_value (15.8 by default) the search takes milliseconds. The slice
 * loop gives up at pr_stamp_timeout, and the request is cancelled then. */
static int stamper_pr_provider(void *context, const uint8_t material[32], uint8_t stamp[RNC_NETSTAMP_SIZE]) {
  (void)context;
  return pr_stamp_search(material, stp.pr_value, stp.pr_timeout, stamp);
}
static void stamper_start_options(const stamper_options *o, rnc_node *node, const char *state) {
  long cores;
  memset(&stp, 0, sizeof(stp));
  pthread_mutex_init(&stp.lock, NULL);
  stp.node = node;
  stp.pr_value = o->pr_value;
  stp.pr_timeout = o->pr_stamp_timeout;
  if (o->stamp_prs)
    (void)rnc_node_set_stamp_provider(node, stamper_pr_provider, NULL);

  stp.enabled = o->stamp_destinations;
  stp.value = o->destination_value;
  stp.niceness = o->niceness;
  cores = sysconf(_SC_NPROCESSORS_ONLN);
  stp.workers = o->workers ? o->workers : (cores > 0 ? (unsigned)cores : 1u);
  if (stp.workers > STAMPER_MAX_WORKERS)
    stp.workers = STAMPER_MAX_WORKERS;
  (void)rnc_node_set_stamp_emission(node, 0, o->destination_value);
  if (!stp.enabled)
    return;
  if (state && snprintf(stp.path, sizeof(stp.path), "%s.stamps", state) >= (int)sizeof(stp.path))
    stp.path[0] = 0;
  stamper_load();
}
static void stamper_stop(void) {
  if (!stp.node)
    return;
  stamper_join();
  pthread_mutex_destroy(&stp.lock);
  memset(&stp, 0, sizeof(stp));
}
/* Once per loop: collect a finished stamp, start the next search. */
static void stamper_step(void) {
  uint8_t destination[16];
  size_t i;
  int found;
  if (!stp.enabled || !stp.node)
    return;
  if (stp.searching) {
    unsigned live;
    pthread_mutex_lock(&stp.lock);
    found = stp.found;
    live = stp.live;
    pthread_mutex_unlock(&stp.lock);
    if (!found && live) /* still searching */
      return;
    if (!found) { /* every worker left on an error: give this destination up for the run instead of waiting for ever */
      stamper_join();
      if (stp.gave_up_count < STAMPER_MAX_DESTINATIONS)
        memcpy(stp.gave_up[stp.gave_up_count++], stp.job_destination, 16);
      rnc_logf(RNC_LOG_ERROR, "stamps", "the destination stamp search failed; destination left unstamped");
      return;
    }
    stamper_join();
    if (rnc_node_set_destination_stamp(stp.node, stp.job_destination, stp.job_stamp) == RNC_OK &&
        stp.done_count < STAMPER_MAX_DESTINATIONS) {
      memcpy(stp.done[stp.done_count].destination, stp.job_destination, 16);
      memcpy(stp.done[stp.done_count].stamp, stp.job_stamp, RNC_NETSTAMP_SIZE);
      ++stp.done_count;
      stamper_save();
      rnc_logf(RNC_LOG_NOTICE, "stamps", "destination stamp found and loaded");
    }
  }
  for (i = 0; rnc_node_destination_at(stp.node, i, destination) == RNC_OK; ++i)
    if (!stamper_has(destination) && !stamper_apply_kept(destination)) {
      stamper_begin(destination);
      if (stp.searching)
        return;
    }
}
#endif
