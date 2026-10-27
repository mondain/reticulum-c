/* Interface discovery: announcing this node's discoverable interfaces on
 * rnstransport.discovery.interface (RNS.Discovery.InterfaceAnnouncer), and
 * listening for other nodes' announces. Included by node_daemon.c after
 * node_mgmt.h. */
#include <reticulum_c/rnc_discovery.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <poll.h>
#include <sys/wait.h>
#define DISCOVERY_IMPL_NAME "reticulum-c"
#define DISCOVERY_VERSION "0.2"
#define DISCOVERY_JOB_DEFAULT_MS 60000u
#define DISCOVERY_DEFAULT_INTERVAL_S (6u * 60u * 60u)
#define DISCOVERY_SLICE 4000u
typedef struct discovery_job {
  int active;
  size_t iface;
  uint8_t packed[RNC_DISCOVERY_PAYLOAD_MAX];
  size_t packed_size;
  uint8_t *workblock;
  size_t work_size;
  uint8_t cursor[RNC_STAMP_SIZE];
  unsigned cost;
  int encrypt;
} discovery_job;
#define DISCOVERED_MAX 256u
#define DISCOVERED_INVALID_CACHE 64u
typedef struct discovered_entry {
  int used;
  rnc_discovery_record record;
} discovered_entry;
typedef struct discovery_state {
  int announcing, listening;
  unsigned required_value;
  const config *settings_ref;
  char storage[1100];
  discovered_entry table[DISCOVERED_MAX];
  uint8_t invalid[DISCOVERED_INVALID_CACHE][32];
  size_t invalid_next;
  /* auto-connect */
  struct {
    int used;
    uint32_t id;
    uint8_t endpoint[32];
    uint64_t down_since;
  } ac[16];
  uint32_t ac_next_id;
  uint64_t ac_monitor_next;
  int ac_initial_ran, bootstrap_off[CONFIG_INTERFACES];
  rnc_identity identity; /* network identity if configured, else transport's */
  rnc_identity network;  /* the network identity (for encryption) */
  int has_network;
  uint8_t destination[16];
  uint64_t last[CONFIG_INTERFACES], next_job;
  discovery_job job;
} discovery_state;
static discovery_state disc;
/* where discovered interfaces persist; set from --state, overridable in config */
static char discovery_dir[1100];
static void discovery_stop(void) {
  if (disc.job.workblock) {
    OPENSSL_cleanse(disc.job.workblock, disc.job.work_size);
    free(disc.job.workblock);
  }
  rnc_identity_clear(&disc.identity);
  rnc_identity_clear(&disc.network);
  memset(&disc, 0, sizeof(disc));
}
/* Runs an executable without arguments and returns its trimmed stdout; used
 * for reachable_on and location_cmd, as the reference does. */
static int capture_command(const char *path, char *out, size_t capacity) {
  int fds[2], status;
  pid_t child;
  size_t used = 0;
  uint64_t deadline = monotonic_ms() + 5000u;
  if (pipe(fds) < 0)
    return 0;
  child = fork();
  if (child < 0) {
    close(fds[0]);
    close(fds[1]);
    return 0;
  }
  if (!child) {
    close(fds[0]);
    if (dup2(fds[1], STDOUT_FILENO) < 0)
      _exit(126);
    close(fds[1]);
    execl(path, path, (char *)NULL);
    _exit(127);
  }
  close(fds[1]);
  for (;;) {
    struct pollfd p = {fds[0], POLLIN, 0};
    int remaining = (int)(deadline > monotonic_ms() ? deadline - monotonic_ms() : 0);
    ssize_t n;
    if (!remaining || poll(&p, 1, remaining) <= 0) {
      (void)kill(child, SIGKILL);
      break;
    }
    n = read(fds[0], out + used, capacity - 1 - used);
    if (n <= 0)
      break;
    used += (size_t)n;
    if (used >= capacity - 1)
      break;
  }
  close(fds[0]);
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
      WEXITSTATUS(status))
    return 0;
  out[used] = 0;
  while (used && (out[used - 1] == '\n' || out[used - 1] == '\r' ||
                  out[used - 1] == ' ')) {
    out[--used] = 0;
  }
  return used > 0;
}
static int is_executable_file(const char *path) {
  struct stat st;
  return stat(path, &st) == 0 && S_ISREG(st.st_mode) && access(path, X_OK) == 0;
}
/* Fills the announce description for an interface, or returns 0 (and says why
 * on stderr) when it cannot be announced. */
static int discovery_describe(const interface_config *f, rnc_discovery_info *info) {
  const config *c = &mgmt.settings;
  rnc_host_status status;
  const char *type = f->type_name;
  char reachable[128];
  memset(info, 0, sizeof(*info));
  info->transport = c->transport;
  memcpy(info->transport_id, mgmt.identity->hash, 16);
  (void)snprintf(info->impl_name, sizeof(info->impl_name), "%s",
                 DISCOVERY_IMPL_NAME);
  (void)snprintf(info->version, sizeof(info->version), "%s", DISCOVERY_VERSION);
  (void)snprintf(info->name, sizeof(info->name), "%s",
                 f->disc_name[0] ? f->disc_name : f->name);
  if (f->has_lxmf) {
    info->has_operator = 1;
    memcpy(info->operator_address, f->lxmf, 16);
  }
  info->has_latitude = f->has_lat;
  info->has_longitude = f->has_lon;
  info->has_height = f->has_height;
  info->latitude = f->lat;
  info->longitude = f->lon;
  info->height = f->height;
  if (f->location_cmd[0] && is_executable_file(f->location_cmd)) {
    char out[128];
    double lat, lon, height;
    if (!capture_command(f->location_cmd, out, sizeof(out)) ||
        sscanf(out, "%lf , %lf , %lf", &lat, &lon, &height) != 3 ||
        lat < -90 || lat > 90 || lon < -180 || lon > 180 || height < -4000 ||
        height > 1e6) {
      rnc_logf(RNC_LOG_ERROR, "discovery", "location command for %s failed", f->name);
      return 0;
    }
    info->has_latitude = info->has_longitude = info->has_height = 1;
    info->latitude = lat;
    info->longitude = lon;
    info->height = height;
  }
  if (f->publish_ifac) {
    if (strlen(f->netname) >= sizeof(info->ifac_netname) ||
        strlen(f->passphrase) >= sizeof(info->ifac_netkey)) {
      rnc_logf(RNC_LOG_ERROR, "discovery", "IFAC name or passphrase of %s is too long to "
                      "publish", f->name);
      return 0;
    }
    memcpy(info->ifac_netname, f->netname, strlen(f->netname) + 1u);
    memcpy(info->ifac_netkey, f->passphrase, strlen(f->passphrase) + 1u);
  }
  if (f->host.kind == RNC_HOST_TCP_LISTEN) {
    (void)snprintf(info->type, sizeof(info->type), "%s",
                   !strcmp(type, "BackboneInterface") ? "BackboneInterface"
                                                       : "TCPServerInterface");
    if (!f->reachable_on[0])
      return 0;
    (void)snprintf(reachable, sizeof(reachable), "%s", f->reachable_on);
    if (is_executable_file(reachable) &&
        !capture_command(f->reachable_on, reachable, sizeof(reachable))) {
      rnc_logf(RNC_LOG_ERROR, "discovery", "reachable_on command for %s failed", f->name);
      return 0;
    }
    if (!rnc_discovery_is_ip_address(reachable) &&
        !rnc_discovery_is_hostname(reachable)) {
      rnc_logf(RNC_LOG_ERROR, "discovery", "reachable_on \"%s\" for %s is not an address",
              reachable, f->name);
      return 0;
    }
    (void)snprintf(info->reachable_on, sizeof(info->reachable_on), "%s", reachable);
    if (rnc_host_get_status(mgmt.host, f->interface_id, &status) != RNC_OK ||
        !status.bound_port)
      return 0;
    info->has_port = 1;
    info->port = status.bound_port;
  } else if (f->host.kind == RNC_HOST_RNODE) {
    (void)snprintf(info->type, sizeof(info->type), "RNodeInterface");
    info->has_frequency = info->has_bandwidth = 1;
    info->frequency = f->host.frequency;
    info->bandwidth = f->host.bandwidth;
    info->spreading_factor = f->host.spreading_factor;
    info->coding_rate = f->host.coding_rate;
  } else if (f->host.kind == RNC_HOST_KISS ||
             (f->host.kind == RNC_HOST_TCP_CONNECT && f->host.kiss_framing)) {
    (void)snprintf(info->type, sizeof(info->type), "KISSInterface");
    info->has_frequency = f->disc_frequency != 0;
    info->has_bandwidth = f->disc_bandwidth != 0;
    info->frequency = f->disc_frequency;
    info->bandwidth = f->disc_bandwidth;
    info->has_modulation = f->disc_modulation[0] != 0;
    (void)snprintf(info->modulation, sizeof(info->modulation), "%s",
                   f->disc_modulation);
  } else {
    rnc_logf(RNC_LOG_ERROR, "discovery", "%s cannot be announced (unsupported type)",
            f->name);
    return 0;
  }
  (void)c;
  return 1;
}
static int discovered_load(void);
static void autoconnect_initial(void);
static int discovery_start(const config *c, const rnc_identity *transport,
                           const rnc_identity *network, rnc_node *node) {
  size_t i;
  int any = 0;
  discovery_stop();
  for (i = 0; i < c->count; ++i)
    any |= c->interfaces[i].enabled && c->interfaces[i].discoverable;
  if (network) {
    disc.network = *network;
    disc.has_network = 1;
  }
  disc.listening = c->discover_interfaces;
  disc.required_value = c->required_discovery_value
                            ? c->required_discovery_value
                            : RNC_DISCOVERY_DEFAULT_STAMP_VALUE;
  (void)snprintf(disc.storage, sizeof(disc.storage), "%s",
                 c->discovery_storage[0] ? c->discovery_storage : discovery_dir);
  if (disc.listening && !discovered_load()) {
    discovery_stop();
    return 0;
  }
  if (disc.listening)
    autoconnect_initial();
  if (!any)
    return 1;
  disc.identity = network ? *network : *transport;
  if (rnc_node_add_destination(node, &disc.identity,
                               "rnstransport.discovery.interface", NULL, 0,
                               disc.destination) != RNC_OK) {
    discovery_stop();
    return 0;
  }
  disc.announcing = 1;
  disc.next_job = monotonic_ms() +
                  (c->discovery_job_interval ? c->discovery_job_interval * 1000u
                                             : DISCOVERY_JOB_DEFAULT_MS);
  return 1;
}
static void discovery_begin(size_t i, uint64_t now) {
  const interface_config *f = &mgmt.settings.interfaces[i];
  rnc_discovery_info info;
  uint8_t material[32];
  discovery_job *j = &disc.job;
  size_t work;
  disc.last[i] = now;
  if (!discovery_describe(f, &info))
    return;
  if (f->disc_encrypt && !disc.has_network) {
    rnc_logf(RNC_LOG_ERROR, "discovery", "encryption requested for %s but no network "
                    "identity is configured", f->name);
    return;
  }
  if (rnc_discovery_pack(&info, j->packed, sizeof(j->packed) - RNC_STAMP_SIZE,
                         &j->packed_size) != RNC_OK ||
      rnc_discovery_stamp_material(j->packed, j->packed_size, material) !=
          RNC_OK) {
    rnc_logf(RNC_LOG_ERROR, "discovery", "cannot describe %s", f->name);
    return;
  }
  work = (size_t)RNC_DISCOVERY_STAMP_ROUNDS * RNC_STAMP_ROUND_SIZE;
  j->workblock = malloc(work);
  if (!j->workblock ||
      rnc_stamp_workblock(material, 32, RNC_DISCOVERY_STAMP_ROUNDS, j->workblock,
                          work, &j->work_size) != RNC_OK ||
      secure_random(NULL, j->cursor, sizeof(j->cursor)) != RNC_OK) {
    free(j->workblock);
    j->workblock = NULL;
    return;
  }
  j->cost = f->stamp_value ? f->stamp_value : RNC_DISCOVERY_DEFAULT_STAMP_VALUE;
  j->encrypt = f->disc_encrypt;
  j->iface = i;
  j->active = 1;
}
static void discovery_finish(const uint8_t stamp[RNC_STAMP_SIZE],
                             uint64_t unix_seconds, uint64_t now) {
  discovery_job *j = &disc.job;
  uint8_t data[RNC_DISCOVERY_PAYLOAD_MAX];
  size_t n;
  if (rnc_discovery_seal(j->packed, j->packed_size, stamp,
                         j->encrypt ? &disc.network : NULL, secure_random, NULL,
                         data, sizeof(data), &n) != RNC_OK ||
      rnc_node_set_destination_data(mgmt.node, disc.destination, data, n) !=
          RNC_OK) {
    rnc_logf(RNC_LOG_ERROR, "discovery", "announce for %s does not fit (%zu bytes)",
            mgmt.settings.interfaces[j->iface].name, j->packed_size);
    return;
  }
  (void)rnc_node_announce(mgmt.node, disc.destination, unix_seconds, now);
  printf("discovery announce interface=%s bytes=%zu\n",
         mgmt.settings.interfaces[j->iface].name, n);
  rnc_logf(RNC_LOG_VERBOSE, "discovery", "announced %s (%zu bytes)",
           mgmt.settings.interfaces[j->iface].name, n);
}
static void autoconnect_monitor(uint64_t unix_seconds, uint64_t now);
static void discovery_step(uint64_t unix_seconds, uint64_t now) {
  const config *c = &mgmt.settings;
  discovery_job *j = &disc.job;
  size_t i, best = c->count;
  uint64_t oldest = 0;
  if (disc.listening)
    autoconnect_monitor(unix_seconds, now);
  if (!disc.announcing)
    return;
  if (j->active) {
    uint8_t stamp[RNC_STAMP_SIZE];
    rnc_result r = rnc_stamp_find(j->workblock, j->work_size, j->cost, j->cursor,
                                  DISCOVERY_SLICE, stamp);
    if (r == RNC_AGAIN)
      return;
    if (r == RNC_OK)
      discovery_finish(stamp, unix_seconds, now);
    OPENSSL_cleanse(j->workblock, j->work_size);
    free(j->workblock);
    j->workblock = NULL;
    j->active = 0;
    return;
  }
  if (now < disc.next_job)
    return;
  disc.next_job = now + (c->discovery_job_interval ? c->discovery_job_interval * 1000u
                                                   : DISCOVERY_JOB_DEFAULT_MS);
  for (i = 0; i < c->count; ++i) {
    const interface_config *f = &c->interfaces[i];
    uint64_t interval = (f->announce_interval_s ? f->announce_interval_s
                                                : DISCOVERY_DEFAULT_INTERVAL_S) * 1000u;
    uint64_t age = disc.last[i] ? now - disc.last[i] : UINT64_MAX;
    if (!f->enabled || !f->discoverable || age <= interval)
      continue;
    if (best == c->count || age > oldest) {
      best = i;
      oldest = age;
    }
  }
  if (best < c->count)
    discovery_begin(best, now);
}

/* ---- listening ---- */
static void discovered_path(char *out, size_t size,
                            const rnc_discovery_info *info) {
  uint8_t hash[32];
  size_t i, n;
  (void)rnc_discovery_hash(info, hash);
  n = (size_t)snprintf(out, size, "%s/", disc.storage);
  for (i = 0; i < 32 && n + 3 <= size; ++i)
    n += (size_t)snprintf(out + n, size - n, "%02x", hash[i]);
}
static int discovered_same(const rnc_discovery_info *a, const rnc_discovery_info *b) {
  return !memcmp(a->transport_id, b->transport_id, 16) && !strcmp(a->name, b->name);
}
static int discovered_supported(const char *type) {
  return !strcmp(type, "BackboneInterface") || !strcmp(type, "TCPServerInterface") ||
         !strcmp(type, "I2PInterface") || !strcmp(type, "RNodeInterface") ||
         !strcmp(type, "WeaveInterface") || !strcmp(type, "KISSInterface");
}
static int discovered_load(void) {
  DIR *dir;
  struct dirent *e;
  if (!disc.storage[0])
    return 1;
  dir = opendir(disc.storage);
  if (!dir)
    return errno == ENOENT; /* nothing heard yet */
  while ((e = readdir(dir)) != NULL) {
    char path[1300];
    uint8_t data[RNC_DISCOVERY_RECORD_MAX];
    struct stat st;
    int fd;
    ssize_t n;
    size_t slot;
    rnc_discovery_record rec;
    if (e->d_name[0] == '.' ||
        snprintf(path, sizeof(path), "%s/%s", disc.storage, e->d_name) >=
            (int)sizeof(path))
      continue;
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
      continue;
    n = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
                st.st_size <= (off_t)sizeof(data)
            ? read(fd, data, sizeof(data))
            : -1;
    close(fd);
    if (n <= 0 || rnc_discovery_record_unpack(data, (size_t)n, &rec) != RNC_OK)
      continue; /* a corrupt file is left for the user to look at */
    for (slot = 0; slot < DISCOVERED_MAX && disc.table[slot].used; ++slot) {
    }
    if (slot < DISCOVERED_MAX) {
      disc.table[slot].used = 1;
      disc.table[slot].record = rec;
    }
  }
  closedir(dir);
  return 1;
}
static void discovered_save(const rnc_discovery_record *rec) {
  uint8_t data[RNC_DISCOVERY_RECORD_MAX];
  size_t n;
  char path[1300];
  if (!disc.storage[0])
    return;
  (void)mkdir(disc.storage, 0700);
  discovered_path(path, sizeof(path), &rec->info);
  if (rnc_discovery_record_pack(rec, data, sizeof(data), &n) == RNC_OK)
    (void)write_file_atomic(path, data, n);
}
static int discovered_remove_reason(const discovered_entry *e, double now,
                                    const config *c, rnc_node *node,
                                    uint64_t unix_seconds) {
  const rnc_discovery_record *r = &e->record;
  size_t i;
  int listed = 0;
  if (rnc_discovery_status(now - r->last_heard) < 0)
    return 1;
  if (c->disc_source_count) {
    for (i = 0; i < c->disc_source_count; ++i)
      listed |= !memcmp(c->disc_sources[i], r->network_id, 16);
    if (!listed)
      return 1;
  }
  if (!discovered_supported(r->info.type))
    return 1;
  if (rnc_node_is_blackholed(node, r->network_id, unix_seconds) ||
      rnc_node_is_blackholed(node, r->info.transport_id, unix_seconds))
    return 1;
  if (r->info.reachable_on[0] &&
      !rnc_discovery_is_ip_address(r->info.reachable_on) &&
      !rnc_discovery_is_hostname(r->info.reachable_on))
    return 1;
  return 0;
}
/* Drops entries the reference would drop when listing. */
static void discovered_prune(uint64_t unix_seconds) {
  size_t i;
  for (i = 0; i < DISCOVERED_MAX; ++i) {
    char path[1300];
    if (!disc.table[i].used ||
        !discovered_remove_reason(&disc.table[i], (double)unix_seconds,
                                  &mgmt.settings, mgmt.node, unix_seconds))
      continue;
    if (disc.storage[0]) {
      discovered_path(path, sizeof(path), &disc.table[i].record.info);
      (void)unlink(path);
    }
    disc.table[i].used = 0;
  }
}
/* Handles an announce event from the node: stores it if it is a valid, stamped
 * discovery announce from an authorised network. */
static void autoconnect(const rnc_discovery_record *rec);
static void discovery_heard(const rnc_node_event *event, uint64_t unix_seconds) {
  const rnc_announce *a = &event->route.announce;
  const config *c = &mgmt.settings;
  rnc_discovery_record rec;
  uint8_t stamp[RNC_STAMP_SIZE], digest[32];
  unsigned value = 0;
  size_t i, slot = DISCOVERED_MAX, empty = DISCOVERED_MAX;
  rnc_result r;
  if (!disc.listening || !rnc_announce_matches_aspect(a, "rnstransport.discovery.interface"))
    return;
  if (c->disc_source_count) {
    int listed = 0;
    for (i = 0; i < c->disc_source_count; ++i)
      listed |= !memcmp(c->disc_sources[i], a->identity.hash, 16);
    if (!listed)
      return;
  }
  if (rnc_hash(a->app_data, a->app_size, digest) != RNC_OK)
    return;
  for (i = 0; i < DISCOVERED_INVALID_CACHE; ++i)
    if (!memcmp(disc.invalid[i], digest, 32))
      return; /* already rejected for its stamp */
  r = rnc_discovery_parse(a->app_data, a->app_size, disc.required_value,
                          disc.has_network ? &disc.network : NULL, &rec.info,
                          stamp, &value);
  if (r == RNC_AUTH) {
    memcpy(disc.invalid[disc.invalid_next++ % DISCOVERED_INVALID_CACHE], digest, 32);
    return;
  }
  if (r != RNC_OK || !discovered_supported(rec.info.type))
    return;
  memcpy(rec.stamp, stamp, RNC_STAMP_SIZE);
  rec.value = value;
  memcpy(rec.network_id, a->identity.hash, 16);
  rec.hops = event->route.hops;
  rec.received = rec.last_heard = rec.discovered = (double)unix_seconds;
  rec.heard_count = 0;
#ifdef __APPLE__
  i = 0; /* no Backbone on macOS: connect as a plain TCP client */
#else
  i = 1;
#endif
  if (rnc_discovery_config_entry(&rec.info, (int)i, rec.config_entry,
                                 sizeof(rec.config_entry)) != RNC_OK)
    rec.config_entry[0] = 0;
  for (i = 0; i < DISCOVERED_MAX; ++i) {
    if (disc.table[i].used && discovered_same(&disc.table[i].record.info, &rec.info))
      slot = i;
    else if (!disc.table[i].used && empty == DISCOVERED_MAX)
      empty = i;
  }
  if (slot < DISCOVERED_MAX) {
    rec.discovered = disc.table[slot].record.discovered;
    rec.heard_count = disc.table[slot].record.heard_count + 1u;
  } else if (empty < DISCOVERED_MAX)
    slot = empty;
  else
    return; /* table full; pruning frees slots on the next listing */
  disc.table[slot].used = 1;
  disc.table[slot].record = rec;
  discovered_save(&rec);
  printf("discovered %s \"%s\" value=%u hops=%u\n", rec.info.type,
         rec.info.name, value, rec.hops);
  rnc_logf(RNC_LOG_DEBUG, "discovery", "discovered %s \"%s\" (stamp value %u, %u hop(s))",
           rec.info.type, rec.info.name, value, rec.hops);
  autoconnect(&rec);
}
/* Admin listing, most available and best-stamped first. */
static void discovery_list(admin_client *c, uint64_t unix_seconds) {
  size_t order[DISCOVERED_MAX], count = 0, i, j;
  discovered_prune(unix_seconds);
  for (i = 0; i < DISCOVERED_MAX; ++i)
    if (disc.table[i].used)
      order[count++] = i;
  for (i = 1; i < count; ++i) /* insertion sort, descending */
    for (j = i; j > 0; --j) {
      const rnc_discovery_record *x = &disc.table[order[j]].record,
                                 *y = &disc.table[order[j - 1]].record;
      int sx = rnc_discovery_status((double)unix_seconds - x->last_heard),
          sy = rnc_discovery_status((double)unix_seconds - y->last_heard);
      if (sx > sy || (sx == sy && (x->value > y->value ||
                                   (x->value == y->value && x->last_heard > y->last_heard)))) {
        size_t t = order[j];
        order[j] = order[j - 1];
        order[j - 1] = t;
      } else
        break;
    }
  for (i = 0; i < count; ++i) {
    const rnc_discovery_record *r = &disc.table[order[i]].record;
    int status = rnc_discovery_status((double)unix_seconds - r->last_heard);
    append(c, "discovered name=%s type=%s status=%s hops=%u value=%u heard=%u",
           r->info.name, r->info.type,
           status == RNC_DISCOVERY_STATUS_AVAILABLE ? "available"
           : status == RNC_DISCOVERY_STATUS_UNKNOWN ? "unknown" : "stale",
           r->hops, r->value, (unsigned)r->heard_count);
    append(c, " transport_id=");
    for (j = 0; j < 16; ++j)
      append(c, "%02x", r->info.transport_id[j]);
    append(c, " network_id=");
    for (j = 0; j < 16; ++j)
      append(c, "%02x", r->network_id[j]);
    if (r->info.reachable_on[0])
      append(c, " reachable_on=%s", r->info.reachable_on);
    if (r->info.has_port)
      append(c, " port=%u", (unsigned)r->info.port);
    append(c, "\n");
  }
}

/* ---- auto-connect (BackboneInterface announcements only) ---- */
#define AUTOCONNECT_ID_BASE 0x7ffd0000u
#define AUTOCONNECT_MIN_VERSION "1.5.2"
static size_t autoconnect_count(void) {
  size_t i, n = 0;
  for (i = 0; i < 16; ++i)
    n += disc.ac[i].used;
  return n;
}
/* components of a dotted version, as RNS.Discovery.version_tuple */
static int version_parts(const char *text, unsigned out[4]) {
  size_t n = 0;
  while (*text && n < 4) {
    char *end;
    unsigned long v;
    if (!isdigit((unsigned char)*text))
      break;
    v = strtoul(text, &end, 10);
    out[n++] = (unsigned)v;
    text = *end == '.' ? end + 1 : end;
    if (*end != '.')
      break;
  }
  return (int)n;
}
static int autoconnect_qualified(const rnc_discovery_info *info) {
  unsigned have[4] = {0}, need[4] = {0};
  int hn, nn, i;
  if (mgmt.settings.autoconnect_unverified)
    return 1;
  if (strcmp(info->impl_name, "RNS") || !info->version[0])
    return 0;
  hn = version_parts(info->version, have);
  nn = version_parts(AUTOCONNECT_MIN_VERSION, need);
  if (!hn)
    return 0;
  for (i = 0; i < 4 && (i < hn || i < nn); ++i) {
    unsigned h = i < hn ? have[i] : 0, n = i < nn ? need[i] : 0;
    if (h != n)
      return h > n;
  }
  return 1;
}
static int autoconnect_exists(const rnc_discovery_info *info) {
  uint8_t endpoint[32];
  size_t i;
  (void)rnc_discovery_endpoint_hash(info, endpoint);
  for (i = 0; i < 16; ++i)
    if (disc.ac[i].used && !memcmp(disc.ac[i].endpoint, endpoint, 32))
      return 1;
  for (i = 0; i < mgmt.settings.count; ++i) {
    const interface_config *f = &mgmt.settings.interfaces[i];
    if (f->enabled && !disc.bootstrap_off[i] &&
        f->host.kind == RNC_HOST_TCP_CONNECT && f->host.address &&
        !strcmp(f->host.address, info->reachable_on) &&
        (!info->has_port || f->host.port == info->port))
      return 1;
  }
  return 0;
}
/* Yggdrasil addresses (200::/7) need that network; the reference leaves them. */
static int is_yggdrasil(const char *address) {
  struct in6_addr a;
  return inet_pton(AF_INET6, address, &a) == 1 && (a.s6_addr[0] & 0xfe) == 0x02;
}
static int autoconnect_name_taken(const char *name) {
  size_t i;
  rnc_host_status st;
  for (i = 0; rnc_host_status_at(mgmt.host, i, &st) == RNC_OK; ++i)
    if (!strcmp(st.name, name))
      return 1;
  return 0;
}
static void autoconnect(const rnc_discovery_record *rec) {
  const config *c = &mgmt.settings;
  const rnc_discovery_info *info = &rec->info;
  rnc_host_config cfg;
  rnc_ifac ifac;
  char name[96];
  size_t slot;
  unsigned seq = 2;
  if (!c->autoconnect_max || autoconnect_count() >= c->autoconnect_max)
    return;
  if (strcmp(info->type, "BackboneInterface") || !info->has_port ||
      !info->reachable_on[0] || !autoconnect_qualified(info))
    return;
  if (autoconnect_exists(info))
    return;
  if (is_yggdrasil(info->reachable_on))
    return;
  if (info->reachable_on[strlen(info->reachable_on) - 1] != '.' &&
      strlen(info->reachable_on) > 6 &&
      !strcmp(info->reachable_on + strlen(info->reachable_on) - 6, ".onion"))
    return; /* would need Tor */
  if (!c->autoconnect_allow_local &&
      (!strcmp(info->reachable_on, "127.0.0.1") ||
       !strcmp(info->reachable_on, "0.0.0.0")))
    return; /* the reference refuses these as invalid targets */
  for (slot = 0; slot < 16 && disc.ac[slot].used; ++slot) {
  }
  if (slot == 16)
    return;
  (void)snprintf(name, sizeof(name), "%s", info->name);
  while (autoconnect_name_taken(name))
    (void)snprintf(name, sizeof(name), "%.80s (%u)", info->name, seq++);
  memset(&cfg, 0, sizeof(cfg));
  cfg.kind = RNC_HOST_TCP_CONNECT;
  cfg.name = name;
  cfg.address = info->reachable_on;
  cfg.port = (uint16_t)info->port;
  cfg.bitrate = 5000000u; /* the reference configures 5 Mbit/s */
  cfg.mode = c->has_autoconnect_mode ? c->autoconnect_mode
             : c->transport          ? RNC_MODE_GATEWAY
                                     : RNC_MODE_FULL;
  if (info->ifac_netname[0] || info->ifac_netkey[0]) {
    if (rnc_ifac_init(&ifac, info->ifac_netname, strlen(info->ifac_netname),
                      info->ifac_netkey, strlen(info->ifac_netkey), 16) != RNC_OK)
      return;
    cfg.ifac = &ifac;
  }
  if (rnc_host_add(mgmt.host, AUTOCONNECT_ID_BASE + disc.ac_next_id, &cfg) !=
      RNC_OK) {
    rnc_logf(RNC_LOG_ERROR, "discovery", "cannot auto-connect %s", name);
    return;
  }
  disc.ac[slot].used = 1;
  disc.ac[slot].id = AUTOCONNECT_ID_BASE + disc.ac_next_id++;
  disc.ac[slot].down_since = 0;
  (void)rnc_discovery_endpoint_hash(info, disc.ac[slot].endpoint);
  printf("auto-connecting %s to %s:%u\n", name, info->reachable_on,
         (unsigned)info->port);
}
/* Connects to what is already known, best first, up to the configured count. */
static void autoconnect_initial(void) {
  size_t i;
  if (!mgmt.settings.autoconnect_max)
    return;
  for (i = 0; i < DISCOVERED_MAX; ++i)
    if (disc.table[i].used && disc.table[i].record.info.transport &&
        !discovered_remove_reason(&disc.table[i], (double)time(NULL), &mgmt.settings,
                                  mgmt.node, (uint64_t)time(NULL)))
      autoconnect(&disc.table[i].record);
  disc.ac_initial_ran = 1;
}
static void autoconnect_monitor(uint64_t unix_seconds, uint64_t now) {
  const config *c = &mgmt.settings;
  uint64_t every = (c->autoconnect_monitor_seconds ? c->autoconnect_monitor_seconds : 5u) * 1000u;
  uint64_t detach = (c->autoconnect_detach_seconds ? c->autoconnect_detach_seconds : 12u) * 1000u;
  size_t i, online = 0, bootstraps_active = 0, free_slots, reserved;
  if (!c->autoconnect_max || now < disc.ac_monitor_next)
    return;
  disc.ac_monitor_next = now + every;
  for (i = 0; i < 16; ++i) {
    rnc_host_status st;
    if (!disc.ac[i].used)
      continue;
    if (rnc_host_get_status(mgmt.host, disc.ac[i].id, &st) != RNC_OK) {
      disc.ac[i].used = 0; /* removed from under us */
      continue;
    }
    if (st.online) {
      online++;
      disc.ac[i].down_since = 0;
    } else if (!disc.ac[i].down_since)
      disc.ac[i].down_since = now;
    else if (now - disc.ac[i].down_since >= detach) {
      printf("auto-discovered interface %s down, detaching\n", st.name);
      (void)rnc_host_remove(mgmt.host, disc.ac[i].id);
      disc.ac[i].used = 0;
    }
  }
  for (i = 0; i < c->count; ++i)
    bootstraps_active += c->interfaces[i].enabled &&
                         c->interfaces[i].bootstrap_only && !disc.bootstrap_off[i];
  if (online >= c->autoconnect_max) {
    for (i = 0; i < c->count; ++i)
      if (c->interfaces[i].enabled && c->interfaces[i].bootstrap_only &&
          !disc.bootstrap_off[i]) {
        printf("tearing down bootstrap interface %s\n", c->interfaces[i].name);
        (void)rnc_host_remove(mgmt.host, c->interfaces[i].interface_id);
        disc.bootstrap_off[i] = 1;
      }
  }
  if (!online && !bootstraps_active) {
    for (i = 0; i < c->count; ++i)
      if (c->interfaces[i].enabled && c->interfaces[i].bootstrap_only &&
          disc.bootstrap_off[i] &&
          rnc_host_add(mgmt.host, c->interfaces[i].interface_id,
                       &c->interfaces[i].host) == RNC_OK) {
        printf("no auto-discovered interfaces connected, re-enabling bootstrap "
               "interface %s\n", c->interfaces[i].name);
        disc.bootstrap_off[i] = 0;
      }
  }
  free_slots = c->autoconnect_max > autoconnect_count()
                   ? c->autoconnect_max - autoconnect_count() : 0;
  reserved = c->autoconnect_max / 4u;
  if (disc.ac_initial_ran && free_slots > reserved) {
    /* try a random available transport node we are not connected to */
    size_t candidates[DISCOVERED_MAX], count = 0;
    uint8_t pick[2];
    for (i = 0; i < DISCOVERED_MAX; ++i)
      if (disc.table[i].used && disc.table[i].record.info.transport &&
          rnc_discovery_status((double)unix_seconds - disc.table[i].record.last_heard) ==
              RNC_DISCOVERY_STATUS_AVAILABLE &&
          !autoconnect_exists(&disc.table[i].record.info))
        candidates[count++] = i;
    if (count && secure_random(NULL, pick, sizeof(pick)) == RNC_OK)
      autoconnect(&disc.table[candidates[(pick[0] | (pick[1] << 8)) % count]].record);
  }
}
