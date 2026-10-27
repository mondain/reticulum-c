/* Interface discovery: announcing this node's discoverable interfaces on
 * rnstransport.discovery.interface (RNS.Discovery.InterfaceAnnouncer), and
 * listening for other nodes' announces. Included by node_daemon.c after
 * node_mgmt.h. */
#include <reticulum_c/rnc_discovery.h>
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
typedef struct discovery_state {
  int announcing;
  rnc_identity identity; /* network identity if configured, else transport's */
  rnc_identity network;  /* the network identity (for encryption) */
  int has_network;
  uint8_t destination[16];
  uint64_t last[CONFIG_INTERFACES], next_job;
  discovery_job job;
} discovery_state;
static discovery_state disc;
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
      fprintf(stderr, "discovery: location command for %s failed\n", f->name);
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
      fprintf(stderr, "discovery: IFAC name or passphrase of %s is too long to "
                      "publish\n", f->name);
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
      fprintf(stderr, "discovery: reachable_on command for %s failed\n", f->name);
      return 0;
    }
    if (!rnc_discovery_is_ip_address(reachable) &&
        !rnc_discovery_is_hostname(reachable)) {
      fprintf(stderr, "discovery: reachable_on \"%s\" for %s is not an address\n",
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
    fprintf(stderr, "discovery: %s cannot be announced (unsupported type)\n",
            f->name);
    return 0;
  }
  (void)c;
  return 1;
}
static int discovery_start(const config *c, const rnc_identity *transport,
                           const rnc_identity *network, rnc_node *node) {
  size_t i;
  int any = 0;
  discovery_stop();
  for (i = 0; i < c->count; ++i)
    any |= c->interfaces[i].enabled && c->interfaces[i].discoverable;
  if (!any)
    return 1;
  disc.identity = network ? *network : *transport;
  if (network) {
    disc.network = *network;
    disc.has_network = 1;
  }
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
    fprintf(stderr, "discovery: encryption requested for %s but no network "
                    "identity is configured\n", f->name);
    return;
  }
  if (rnc_discovery_pack(&info, j->packed, sizeof(j->packed) - RNC_STAMP_SIZE,
                         &j->packed_size) != RNC_OK ||
      rnc_discovery_stamp_material(j->packed, j->packed_size, material) !=
          RNC_OK) {
    fprintf(stderr, "discovery: cannot describe %s\n", f->name);
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
    fprintf(stderr, "discovery: announce for %s does not fit (%zu bytes)\n",
            mgmt.settings.interfaces[j->iface].name, j->packed_size);
    return;
  }
  (void)rnc_node_announce(mgmt.node, disc.destination, unix_seconds, now);
  printf("discovery announce interface=%s bytes=%zu\n",
         mgmt.settings.interfaces[j->iface].name, n);
}
static void discovery_step(uint64_t unix_seconds, uint64_t now) {
  const config *c = &mgmt.settings;
  discovery_job *j = &disc.job;
  size_t i, best = c->count;
  uint64_t oldest = 0;
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
