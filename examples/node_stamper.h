/* Destination stamps for the node daemon (RNS 1.6). Every local SINGLE destination gets a stamp over its
 * public data (destination hash, public key, name hash) at [stamps] destination_value. The search is plain
 * hashing and runs on worker threads (max_workers, at worker_niceness) in slices, so shutdown and reloads
 * never wait on it; the main loop collects a finished stamp, hands it to the node and saves it beside the
 * state file (<state>.stamps) so a restart does not search again. The node itself never waits for a stamp:
 * until one is loaded the destination's announces and path responses go out unstamped. Included by
 * node_daemon.c. */
#include <pthread.h>
#ifdef __linux__
#include <sys/syscall.h>
/* the strict POSIX feature level of node_daemon.c hides these; a worker lowers its own scheduling priority */
extern int setpriority(int which, id_t who, int prio);
extern long syscall(long number, ...);
#define STAMPER_PRIO_PROCESS 0
#endif
#define STAMPER_MAX_WORKERS 16u
#define STAMPER_MAX_DESTINATIONS 16u
#define STAMPER_SLICE 65536u
typedef struct stamper_entry {
  uint8_t destination[16], stamp[RNC_NETSTAMP_SIZE];
} stamper_entry;
static struct stamper {
  int enabled, searching, found, cancel;
  rnc_node *node;
  char path[1100]; /* <state>.stamps; empty without a state file */
  double value;
  unsigned workers, niceness, started;
  pthread_t threads[STAMPER_MAX_WORKERS];
  pthread_mutex_t lock;
  uint8_t job_destination[16], job_material[90], job_stamp[RNC_NETSTAMP_SIZE];
  stamper_entry done[STAMPER_MAX_DESTINATIONS];
  size_t done_count;
} stp;
static int stamper_has(const uint8_t destination[16]) {
  size_t i;
  for (i = 0; i < stp.done_count; ++i)
    if (!memcmp(stp.done[i].destination, destination, 16))
      return 1;
  return 0;
}
static void stamper_save(void) {
  uint8_t data[8 + STAMPER_MAX_DESTINATIONS * sizeof(stamper_entry) + 32];
  size_t n = 0, i;
  if (!stp.path[0])
    return;
  memcpy(data, "RNST", 4);
  data[4] = 1;
  data[5] = (uint8_t)stp.done_count;
  n = 6;
  for (i = 0; i < stp.done_count; ++i) {
    memcpy(data + n, stp.done[i].destination, 16);
    memcpy(data + n + 16, stp.done[i].stamp, RNC_NETSTAMP_SIZE);
    n += sizeof(stamper_entry);
  }
  if (rnc_hash(data, n, data + n) != RNC_OK)
    return;
  if (!write_file_atomic(stp.path, data, n + 32))
    rnc_logf(RNC_LOG_WARNING, "stamps", "cannot save %s", stp.path);
}
/* Stamps found by an earlier run; one that no longer verifies (another identity, another value) is ignored. */
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
  if (got != 6 + count * sizeof(stamper_entry) + 32 || rnc_hash(data, got - 32, digest) != RNC_OK ||
      memcmp(digest, data + got - 32, 32))
    return;
  for (i = 0; i < count && stp.done_count < STAMPER_MAX_DESTINATIONS; ++i) {
    const uint8_t *e = data + 6 + i * sizeof(stamper_entry);
    if (rnc_node_set_destination_stamp(stp.node, e, e + 16) == RNC_OK) {
      memcpy(&stp.done[stp.done_count++], e, sizeof(stamper_entry));
      rnc_logf(RNC_LOG_VERBOSE, "stamps", "stamp loaded from %s", stp.path);
    }
  }
}
static void *stamper_worker(void *unused) {
  uint8_t stamp[RNC_NETSTAMP_SIZE];
  (void)unused;
#ifdef __linux__
  (void)setpriority(STAMPER_PRIO_PROCESS, (id_t)syscall(SYS_gettid), (int)stp.niceness);
#endif
  for (;;) {
    rnc_result r;
    int stop;
    pthread_mutex_lock(&stp.lock);
    stop = stp.cancel || stp.found;
    pthread_mutex_unlock(&stp.lock);
    if (stop)
      return NULL;
    r = rnc_netstamp_find(stp.job_material, sizeof(stp.job_material), stp.value, secure_random, NULL, STAMPER_SLICE,
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
  for (i = 0; i < stp.workers; ++i)
    if (pthread_create(&stp.threads[stp.started], NULL, stamper_worker, NULL) == 0)
      ++stp.started;
  stp.searching = stp.started != 0;
  if (stp.searching)
    rnc_logf(RNC_LOG_VERBOSE, "stamps", "searching a destination stamp of value %.2f on %u worker(s)", stp.value,
             stp.started);
}
static void stamper_start(const config *c, rnc_node *node, const char *state) {
  long cores;
  memset(&stp, 0, sizeof(stp));
  pthread_mutex_init(&stp.lock, NULL);
  stp.node = node;
  stp.enabled = c->stamp_destinations;
  stp.value = c->destination_value;
  stp.niceness = c->worker_niceness;
  cores = sysconf(_SC_NPROCESSORS_ONLN);
  stp.workers = c->max_workers ? c->max_workers : (cores > 0 ? (unsigned)cores : 1u);
  if (stp.workers > STAMPER_MAX_WORKERS)
    stp.workers = STAMPER_MAX_WORKERS;
  (void)rnc_node_set_stamp_emission(node, 0, c->destination_value);
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
    pthread_mutex_lock(&stp.lock);
    found = stp.found;
    pthread_mutex_unlock(&stp.lock);
    if (!found)
      return;
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
    if (!stamper_has(destination)) {
      stamper_begin(destination);
      if (stp.searching)
        return;
    }
}
