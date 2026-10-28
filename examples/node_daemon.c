#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <reticulum_c/rnc_host.h>
#include <reticulum_c/rnc_ipc.h>
#include <reticulum_c/rnc_log.h>
#include <reticulum_c/rnc_service.h>
#include <signal.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#define CONFIG_INTERFACES 8u
#define BLACKHOLE_MAX 65536u
static int decode_hex(const char *s, uint8_t *out);
static int tunnels_save(const char *state, rnc_node *node,
                        const rnc_identity *owner, uint64_t unix_seconds,
                        uint64_t now);
/* the management module (node_mgmt.h) owns the network identity */
static const uint8_t *network_identity_hash(void);
/* Identity hashes separated by commas and/or blanks (at most the allow-list
 * size); replaces any previous content. */
static int parse_hash_list(const char *value, uint8_t (*out)[16],
                           size_t *count) {
  const char *token = value, *end;
  *count = 0;
  while (*token) {
    char hex[33];
    while (*token == ',' || *token == ' ' || *token == '\t')
      ++token;
    if (!*token)
      break;
    end = token;
    while (*end && *end != ',' && *end != ' ' && *end != '\t')
      ++end;
    if (end - token != 32 || *count == RNC_SERVICE_ALLOWLIST)
      return 0;
    memcpy(hex, token, 32);
    hex[32] = 0;
    if (!decode_hex(hex, out[*count]))
      return 0;
    ++*count;
    token = end;
  }
  return 1;
}
#define STATE_MAX (96u + RNC_NODE_ROUTES * (14u + RNC_MTU))
typedef struct interface_config {
  rnc_host_config host;
  char name[64], address[256], target[256], device[64], group[64], netname[128],
      passphrase[128], callsign[RNC_HOST_CALLSIGN_MAX + 2u], ax_call[8];
  size_t ifac_size;
  uint32_t interface_id;
  /* I2PInterface peers and the key file the host is pointed at */
  /* RNodeMultiInterface: the [[[radio]]] sections, and those in use */
  struct sub_config {
    char name[48];
    rnc_host_subradio radio;
    int has_vport, enabled;
  } subs[RNC_HOST_SUBRADIOS];
  rnc_host_subradio active[RNC_HOST_SUBRADIOS];
  size_t sub_count;
  int enabled_set;
  char peer_text[8][712], i2p_key[600];
  const char *peer_ptrs[8];
  int enabled, has_type, backbone;
  rnc_ifac ifac;
  /* interface discovery (announcing); see node_discovery.h */
  char type_name[32], disc_name[64], reachable_on[128], location_cmd[256],
      disc_modulation[32];
  int discoverable, disc_encrypt, publish_ifac, has_lat, has_lon, has_height,
      has_lxmf, bootstrap_only;
  unsigned announce_interval_s, stamp_value, disc_frequency, disc_bandwidth;
  double lat, lon, height;
  uint8_t lxmf[16];
} interface_config;
typedef struct config {
  int transport, share, share_tcp, remote_management, publish_blackhole,
      respond_to_probes, explicit_proofs, panic_on_interface_error,
      no_link_mtu_discovery;
  uint8_t mgmt_allowed[RNC_SERVICE_ALLOWLIST][16];
  size_t mgmt_allowed_count;
  char network_identity[512]; /* identity file path, empty = none */
  char instance_name[64];     /* accepted; the shared instance is TCP only */
  int loglevel;               /* [logging]; RNC_LOG_NOTICE when absent */
  char logdestination[16], logfile[512];
  /* interface discovery: listening, authorised sources, auto-connect */
  int discover_interfaces, autoconnect_unverified, has_autoconnect_mode;
  unsigned required_discovery_value, autoconnect_max, discovery_job_interval,
      autoconnect_monitor_seconds, autoconnect_detach_seconds;
  int autoconnect_allow_local;
  rnc_interface_mode autoconnect_mode;
  uint8_t disc_sources[RNC_SERVICE_ALLOWLIST][16];
  size_t disc_source_count;
  char discovery_storage[512];
  /* blackhole subscriptions: sources, update interval and first-run delay */
  uint8_t bh_sources[RNC_SERVICE_ALLOWLIST][16];
  size_t bh_source_count;
  unsigned bh_interval_minutes, bh_initial_wait;
  uint16_t shared_port, control_port;
  uint8_t rpc_key[RNC_RPC_KEY_MAX];
  size_t rpc_key_size;
  size_t count;
  interface_config interfaces[CONFIG_INTERFACES];
} config;
static volatile sig_atomic_t stopping, reloading;
static void signal_handler(int n) {
  if (n == SIGHUP)
    reloading = 1;
  else
    stopping = 1;
}
static uint64_t monotonic_ms(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t) < 0)
    exit(1);
  return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
static rnc_result secure_random(void *context, uint8_t *out, size_t size) {
  (void)context;
  return size <= INT_MAX && RAND_priv_bytes(out, (int)size) == 1 ? RNC_OK
                                                                 : RNC_CRYPTO;
}
static int text_copy(char *out, size_t cap, const char *in) {
  size_t n = strlen(in);
  if (n >= cap)
    return 0;
  memcpy(out, in, n + 1);
  return 1;
}
static char *trim(char *s) {
  char *end;
  while (isspace((unsigned char)*s))
    ++s;
  end = s + strlen(s);
  while (end > s && isspace((unsigned char)end[-1]))
    --end;
  *end = 0;
  return s;
}
static int number(const char *s, unsigned long max, unsigned long *out) {
  char *end;
  unsigned long value;
  if (!*s || *s == '-' || *s == '+')
    return 0;
  errno = 0;
  value = strtoul(s, &end, 10);
  if (errno || *end || value > max)
    return 0;
  *out = value;
  return 1;
}
static int boolean(const char *s, int *out) {
  if (!strcasecmp(s, "yes") || !strcasecmp(s, "true") || !strcasecmp(s, "on") ||
      !strcmp(s, "1")) {
    *out = 1;
    return 1;
  }
  if (!strcasecmp(s, "no") || !strcasecmp(s, "false") ||
      !strcasecmp(s, "off") || !strcmp(s, "0")) {
    *out = 0;
    return 1;
  }
  return 0;
}
static int set_type(interface_config *f, const char *value) {
  struct entry {
    const char *name;
    rnc_host_kind kind;
  } types[] = {{"TCPServerInterface", RNC_HOST_TCP_LISTEN},
               {"TCPClientInterface", RNC_HOST_TCP_CONNECT},
               {"UDPInterface", RNC_HOST_UDP},
               {"AutoInterface", RNC_HOST_AUTO},
               {"SerialInterface", RNC_HOST_SERIAL},
               {"KISSInterface", RNC_HOST_KISS},
               {"RNodeInterface", RNC_HOST_RNODE},
               {"PipeInterface", RNC_HOST_PIPE},
               {"AX25KISSInterface", RNC_HOST_AX25},
               {"I2PInterface", RNC_HOST_I2P},
               {"RNodeMultiInterface", RNC_HOST_RNODE_MULTI},
               {"WeaveInterface", RNC_HOST_WEAVE},
               {"BackboneInterface", RNC_HOST_TCP_LISTEN},
               {"BackboneClientInterface", RNC_HOST_TCP_CONNECT}};
  size_t i;
  for (i = 0; i < sizeof(types) / sizeof(*types); ++i)
    if (!strcmp(value, types[i].name)) {
      f->host.kind = types[i].kind;
      f->has_type = 1;
      (void)snprintf(f->type_name, sizeof(f->type_name), "%s", value);
      f->backbone = !strncmp(value, "Backbone", 8);
      /* wire-compatible with TCP (HDLC); reference defaults differ */
      if (f->backbone && types[i].kind == RNC_HOST_TCP_LISTEN)
        f->host.fast_flap.enabled = 1;
      return 1;
    }
  return 0;
}
/* Discovery announce options of an interface; -1 when `key` is not one. */
static int discovery_key(interface_config *f, const char *key,
                         const char *value) {
  char *end;
  double d;
  unsigned long n;
  int b;
  if (!strcmp(key, "discoverable")) {
    if (!boolean(value, &b))
      return 0;
    f->discoverable = b;
    return 1;
  }
  if (!strcmp(key, "discovery_encrypt") || !strcmp(key, "publish_ifac") ||
      !strcmp(key, "bootstrap_only")) {
    if (!boolean(value, &b))
      return 0;
    if (key[0] == 'd')
      f->disc_encrypt = b;
    else if (key[0] == 'p')
      f->publish_ifac = b;
    else
      f->bootstrap_only = b;
    return 1;
  }
  if (!strcmp(key, "discovery_name"))
    return text_copy(f->disc_name, sizeof(f->disc_name), value);
  if (!strcmp(key, "reachable_on"))
    return text_copy(f->reachable_on, sizeof(f->reachable_on), value);
  if (!strcmp(key, "location_cmd"))
    return text_copy(f->location_cmd, sizeof(f->location_cmd), value);
  if (!strcmp(key, "discovery_modulation"))
    return text_copy(f->disc_modulation, sizeof(f->disc_modulation), value);
  if (!strcmp(key, "announce_interval") ||
      !strcmp(key, "announce_interval_seconds")) {
    if (!number(value, 100000000ul, &n) || !n)
      return 0;
    /* minutes in the reference, never below five; the seconds form exists so
     * tests need not wait */
    f->announce_interval_s =
        key[17] == '_' ? (unsigned)n : (unsigned)(n < 5 ? 5 : n) * 60u;
    return 1;
  }
  if (!strcmp(key, "discovery_stamp_value") ||
      !strcmp(key, "discovery_frequency") ||
      !strcmp(key, "discovery_bandwidth")) {
    if (!number(value, UINT32_MAX, &n))
      return 0;
    if (key[10] == 's') {
      if (n > 64)
        return 0;
      f->stamp_value = (unsigned)n;
    } else if (key[10] == 'f')
      f->disc_frequency = (unsigned)n;
    else
      f->disc_bandwidth = (unsigned)n;
    return 1;
  }
  if (!strcmp(key, "latitude") || !strcmp(key, "longitude") ||
      !strcmp(key, "height")) {
    d = strtod(value, &end);
    if (end == value || *end || d != d)
      return 0;
    if (key[1] == 'a' && (d < -90 || d > 90))
      return 0;
    if (key[1] == 'o' && (d < -180 || d > 180))
      return 0;
    if (key[0] == 'l' && key[1] == 'a')
      f->lat = d, f->has_lat = 1;
    else if (key[0] == 'l')
      f->lon = d, f->has_lon = 1;
    else
      f->height = d, f->has_height = 1;
    return 1;
  }
  if (!strcmp(key, "discovery_lxmf_address")) {
    if (strlen(value) != 32 || !decode_hex(value, f->lxmf))
      return 0;
    f->has_lxmf = 1;
    return 1;
  }
  return -1;
}
/* Keys of a [[[radio]]] section of an RNodeMultiInterface. */
static int sub_key(struct sub_config *sub, const char *key, const char *value) {
  char *end;
  long long n;
  int b;
  if (!strcmp(key, "interface_enabled") || !strcmp(key, "outgoing") ||
      !strcmp(key, "flow_control")) {
    if (!boolean(value, &b))
      return 0;
    if (key[0] == 'i')
      sub->enabled = b;
    else if (key[0] == 'o')
      sub->radio.no_output = !b;
    else
      sub->radio.flow_control = b;
    return 1;
  }
  if (!strcmp(key, "airtime_limit_short") || !strcmp(key, "airtime_limit_long")) {
    double percent = strtod(value, &end);
    if (end == value || *end || !(percent >= 0.0) || percent > 100.0)
      return 0;
    if (key[16] == 's')
      sub->radio.airtime_limit_short = percent;
    else
      sub->radio.airtime_limit_long = percent;
    return 1;
  }
  n = strtoll(value, &end, 10);
  if (end == value || *end)
    return 0;
  if (!strcmp(key, "vport")) {
    if (n < 0 || n >= (long long)RNC_HOST_SUBRADIOS)
      return 0;
    sub->radio.vport = (unsigned)n;
    sub->has_vport = 1;
  } else if (!strcmp(key, "frequency")) {
    if (n <= 0 || n > 4294967295ll)
      return 0;
    sub->radio.frequency = (uint32_t)n;
  } else if (!strcmp(key, "bandwidth")) {
    if (n < 7800 || n > 1625000)
      return 0;
    sub->radio.bandwidth = (uint32_t)n;
  } else if (!strcmp(key, "txpower")) {
    if (n < -9 || n > 37)
      return 0;
    sub->radio.tx_power = (int)n;
  } else if (!strcmp(key, "spreadingfactor")) {
    if (n < 5 || n > 12)
      return 0;
    sub->radio.spreading_factor = (unsigned)n;
  } else if (!strcmp(key, "codingrate")) {
    if (n < 5 || n > 8)
      return 0;
    sub->radio.coding_rate = (unsigned)n;
  } else
    return 0;
  return 1;
}
static int interface_key(interface_config *f, const char *key,
                         const char *value) {
  unsigned long n;
  int b;
  if (!strcmp(key, "type"))
    return set_type(f, value);
  {
    int d = discovery_key(f, key, value);
    if (d >= 0)
      return d;
  }
  if (!strcmp(key, "enabled")) {
    if (!boolean(value, &b))
      return 0;
    f->enabled = b;
    f->enabled_set = 1;
    return 1;
  }
  if (!strcmp(key, "listen_ip") || !strcmp(key, "listen_address") ||
      !strcmp(key, "target_host") ||
      (!strcmp(key, "port") && !f->backbone) || !strcmp(key, "command"))
    return text_copy(f->address, sizeof(f->address), value);
  if (!strcmp(key, "forward_ip") || !strcmp(key, "target"))
    return text_copy(f->target, sizeof(f->target), value);
  if (!strcmp(key, "device") || !strcmp(key, "interface"))
    return text_copy(f->device, sizeof(f->device), value);
  if (!strcmp(key, "group_id"))
    return text_copy(f->group, sizeof(f->group), value);
  if (!strcmp(key, "networkname") || !strcmp(key, "network_name"))
    return text_copy(f->netname, sizeof(f->netname), value);
  if (!strcmp(key, "passphrase") || !strcmp(key, "pass_phrase"))
    return text_copy(f->passphrase, sizeof(f->passphrase), value);
  if (!strcmp(key, "flow_control")) {
    if (!boolean(value, &b))
      return 0;
    f->host.flow_control = b;
    return 1;
  }
  if (!strcmp(key, "mode") || !strcmp(key, "interface_mode")) {
    static const struct {
      const char *name;
      rnc_interface_mode mode;
    } modes[] = {{"full", RNC_MODE_FULL},
                 {"gateway", RNC_MODE_GATEWAY},
                 {"gw", RNC_MODE_GATEWAY},
                 {"access_point", RNC_MODE_ACCESS_POINT},
                 {"accesspoint", RNC_MODE_ACCESS_POINT},
                 {"ap", RNC_MODE_ACCESS_POINT},
                 {"roaming", RNC_MODE_ROAMING},
                 {"boundary", RNC_MODE_BOUNDARY}};
    size_t k;
    for (k = 0; k < sizeof(modes) / sizeof(*modes); k++)
      if (!strcasecmp(value, modes[k].name)) {
        f->host.mode = modes[k].mode;
        return 1;
      }
    return 0;
  }
  if (!strcmp(key, "announce_cap")) {
    char *end;
    double percent = strtod(value, &end);
    if (end == value || *end || !(percent > 0.0) || percent > 100.0)
      return 0;
    f->host.announce_cap_permille = (uint32_t)(percent * 10.0 + 0.5);
    return f->host.announce_cap_permille != 0;
  }
  if (!strcmp(key, "airtime_limit_short") ||
      !strcmp(key, "airtime_limit_long")) {
    char *end;
    double percent = strtod(value, &end);
    if (end == value || *end || !(percent > 0.0) || percent > 100.0)
      return 0;
    if (!strcmp(key, "airtime_limit_short"))
      f->host.airtime_limit_short = percent;
    else
      f->host.airtime_limit_long = percent;
    return 1;
  }
  if (!strcmp(key, "parity")) {
    if (!strcasecmp(value, "n") || !strcasecmp(value, "none"))
      f->host.serial_parity = 'N';
    else if (!strcasecmp(value, "e") || !strcasecmp(value, "even"))
      f->host.serial_parity = 'E';
    else if (!strcasecmp(value, "o") || !strcasecmp(value, "odd"))
      f->host.serial_parity = 'O';
    else
      return 0;
    return 1;
  }
  if (!strcmp(key, "kiss_framing") || !strcmp(key, "prefer_ipv6")) {
    if (!boolean(value, &b))
      return 0;
    if (key[0] == 'k')
      f->host.kiss_framing = b;
    else
      f->host.prefer_ipv6 = b;
    return 1;
  }
  if (!strcmp(key, "connectable")) {
    if (!boolean(value, &b))
      return 0;
    f->host.i2p_connectable = b;
    return 1;
  }
  if (!strcmp(key, "peers")) {
    /* comma separated, as the reference's list values are */
    char *copy = strdup(value), *at, *save = NULL;
    size_t count = 0;
    if (!copy)
      return 0;
    for (at = strtok_r(copy, ",", &save); at; at = strtok_r(NULL, ",", &save)) {
      char *item = trim(at);
      if (!*item)
        continue;
      if (count == 8 || strlen(item) >= sizeof(f->peer_text[0])) {
        free(copy);
        return 0;
      }
      memcpy(f->peer_text[count++], item, strlen(item) + 1u);
    }
    free(copy);
    f->host.i2p_peer_count = count;
    return 1;
  }
  if (!strcmp(key, "outgoing")) {
    if (!boolean(value, &b))
      return 0;
    f->host.no_output = !b;
    return 1;
  }
  if (!strcmp(key, "block_fast_flapping")) {
    if (!boolean(value, &b))
      return 0;
    f->host.fast_flap.enabled = b;
    return 1;
  }
  if (!strcmp(key, "fast_flapping_threshold") ||
      !strcmp(key, "fast_flapping_block_time")) {
    char *end;
    double v = strtod(value, &end);
    int minutes = !strcmp(key, "fast_flapping_block_time");
    if (end == value || *end || !(v > 0.0) || v > 31536000.0)
      return 0;
    if (minutes)
      f->host.fast_flap.expiry_seconds = (unsigned)(v * 60.0 + 0.5);
    else
      f->host.fast_flap.threshold_seconds = (unsigned)(v + 0.5);
    return 1;
  }
  if (!strcmp(key, "respawn_delay")) {
    char *end;
    double seconds = strtod(value, &end);
    if (end == value || *end || !(seconds >= 0.0) || seconds > 3600.0)
      return 0;
    f->host.respawn_delay_ms = (unsigned)(seconds * 1000.0 + 0.5);
    return 1;
  }
  if (!strcmp(key, "callsign"))
    return text_copy(f->ax_call, sizeof(f->ax_call), value);
  if (!strcmp(key, "id_callsign")) {
    if (strlen(value) > RNC_HOST_CALLSIGN_MAX)
      return 0;
    return text_copy(f->callsign, sizeof(f->callsign), value);
  }
  if (!strcmp(key, "ingress_control")) {
    if (!boolean(value, &b))
      return 0;
    f->host.ingress.disabled = !b;
    return 1;
  }
  if (!strcmp(key, "recursive_prs")) {
    if (!boolean(value, &b))
      return 0;
    f->host.recursive_path_requests = b;
    return 1;
  }
  {
    static const struct {
      const char *name;
      size_t offset;
      int hertz;
    } ic[] = {
        {"ic_new_time", offsetof(rnc_ingress_policy, new_time_s), 0},
        {"ic_burst_hold", offsetof(rnc_ingress_policy, burst_hold_s), 0},
        {"ic_burst_penalty", offsetof(rnc_ingress_policy, burst_penalty_s), 0},
        {"ic_held_release_interval",
         offsetof(rnc_ingress_policy, held_release_interval_s), 0},
        {"ic_max_held_announces", offsetof(rnc_ingress_policy, max_held), 0},
        {"ic_burst_freq_new", offsetof(rnc_ingress_policy, burst_freq_new_mhz),
         1},
        {"ic_burst_freq", offsetof(rnc_ingress_policy, burst_freq_mhz), 1},
        {"ic_pr_burst_freq_new",
         offsetof(rnc_ingress_policy, pr_burst_freq_new_mhz), 1},
        {"ic_pr_burst_freq", offsetof(rnc_ingress_policy, pr_burst_freq_mhz), 1},
        {"ec_pr_freq", offsetof(rnc_ingress_policy, ec_pr_freq_mhz), 1}};
    size_t k;
    for (k = 0; k < sizeof(ic) / sizeof(*ic); k++)
      if (!strcmp(key, ic[k].name)) {
        char *end;
        double v = strtod(value, &end);
        uint32_t out;
        if (end == value || *end || !(v > 0.0) || v > 4000000.0)
          return 0;
        out = (uint32_t)(ic[k].hertz ? v * 1000.0 + 0.5 : v + 0.5);
        if (!out)
          return 0;
        memcpy((char *)&f->host.ingress + ic[k].offset, &out, sizeof(out));
        return 1;
      }
  }
  if (!number(value, UINT32_MAX, &n))
    return 0;
  if (!strcmp(key, "databits") || !strcmp(key, "stopbits")) {
    if (key[0] == 'd') {
      if (n < 5 || n > 8)
        return 0;
      f->host.serial_databits = (unsigned)n;
    } else {
      if (n < 1 || n > 2)
        return 0;
      f->host.serial_stopbits = (unsigned)n;
    }
    return 1;
  }
  if (!strcmp(key, "max_reconnect_tries")) {
    if (n > 1000000)
      return 0;
    f->host.max_reconnect_tries = (unsigned)n;
    return 1;
  }
  if (!strcmp(key, "connect_timeout") || !strcmp(key, "reconnect_wait")) {
    if (n == 0 || n > 3600)
      return 0;
    if (key[0] == 'c')
      f->host.connect_timeout_ms = (unsigned)n * 1000u;
    else
      f->host.reconnect_wait_ms = (unsigned)n * 1000u;
    return 1;
  }
  if (!strcmp(key, "fast_flapping_grace")) {
    if (n == 0 || n > 1000)
      return 0;
    f->host.fast_flap.grace = (unsigned)n;
    return 1;
  }
  if (!strcmp(key, "listen_port") || !strcmp(key, "target_port") ||
      (!strcmp(key, "port") && f->backbone)) {
    if (n > 65535)
      return 0;
    f->host.port = (uint16_t)n;
    return 1;
  }
  if (!strcmp(key, "forward_port")) {
    if (n > 65535)
      return 0;
    f->host.target_port = (uint16_t)n;
    return 1;
  }
  if (!strcmp(key, "discovery_port")) {
    if (n >= 65535)
      return 0;
    f->host.discovery_port = (uint16_t)n;
    return 1;
  }
  if (!strcmp(key, "data_port")) {
    if (n > 65535)
      return 0;
    f->host.data_port = (uint16_t)n;
    return 1;
  }
  if (!strcmp(key, "mtu")) {
    if (n < RNC_MTU || n > RNC_MAX_MTU)
      return 0;
    f->host.mtu = (uint16_t)n;
    return 1;
  }
  if (!strcmp(key, "announce_rate_target")) {
    f->host.announce_rate_target = (uint32_t)n;
    return 1;
  }
  if (!strcmp(key, "announce_rate_grace")) {
    f->host.announce_rate_grace = (uint32_t)n;
    return 1;
  }
  if (!strcmp(key, "announce_rate_penalty")) {
    f->host.announce_rate_penalty = (uint32_t)n;
    return 1;
  }
  if (!strcmp(key, "bitrate") || !strcmp(key, "configured_bitrate")) {
    if (!n)
      return 0;
    f->host.bitrate = (uint32_t)n;
    return 1;
  }
  if (!strcmp(key, "speed") || !strcmp(key, "baudrate")) {
    f->host.serial_baud = (unsigned)n;
    return 1;
  }
  if (!strcmp(key, "kiss_port")) {
    if (n > 15)
      return 0;
    f->host.kiss_port = (unsigned)n;
    return 1;
  }
  if (!strcmp(key, "ifac_size")) {
    if (n < 8 || n > 512 || n % 8)
      return 0;
    f->ifac_size = n / 8;
    return 1;
  }
  if (!strcmp(key, "frequency")) {
    f->host.frequency = (uint32_t)n;
    return 1;
  }
  if (!strcmp(key, "bandwidth")) {
    f->host.bandwidth = (uint32_t)n;
    return 1;
  }
  if (!strcmp(key, "spreadingfactor")) {
    f->host.spreading_factor = (unsigned)n;
    return 1;
  }
  if (!strcmp(key, "codingrate")) {
    f->host.coding_rate = (unsigned)n;
    return 1;
  }
  if (!strcmp(key, "ssid") || !strcmp(key, "preamble") ||
      !strcmp(key, "txtail") || !strcmp(key, "persistence") ||
      !strcmp(key, "slottime")) {
    unsigned *field = !strcmp(key, "ssid")          ? &f->host.ssid
                      : !strcmp(key, "preamble")    ? &f->host.preamble_ms
                      : !strcmp(key, "txtail")      ? &f->host.txtail_ms
                      : !strcmp(key, "persistence") ? &f->host.persistence
                                                    : &f->host.slottime_ms;
    if (n > 65535)
      return 0;
    *field = (unsigned)n;
    return 1;
  }
  if (!strcmp(key, "id_interval")) {
    if (n == 0 || n > 86400)
      return 0;
    f->host.id_interval = (unsigned)n;
    return 1;
  }
  if (!strcmp(key, "txpower")) {
    if (n > 27)
      return 0;
    f->host.tx_power = (int)n;
    return 1;
  }
  return 0;
}
/* Stable interface IDs bind signed route checkpoints to the effective host
 * configuration. Order changes preserve IDs; changed endpoints/secrets/MTUs
 * receive different IDs and stale cached routes are skipped by core import. */
static int interface_id(interface_config *f) {
  uint8_t material[4096], digest[32];
  size_t size;
  rnc_rpc_writer w;
  const rnc_host_config *h = &f->host;
  rnc_rpc_writer_init(&w, material, sizeof(material));
  (void)rnc_rpc_write_array(&w, 24);
  (void)rnc_rpc_write_string(&w, "reticulum-c-host-interface-v1");
  (void)rnc_rpc_write_uint(&w, h->kind);
  (void)rnc_rpc_write_string(&w, f->name);
  (void)rnc_rpc_write_string(&w, h->address ? h->address : "");
  (void)rnc_rpc_write_string(&w, h->target ? h->target : "");
  (void)rnc_rpc_write_uint(&w, h->port);
  (void)rnc_rpc_write_uint(&w, h->target_port);
  (void)rnc_rpc_write_uint(&w, h->bitrate                  ? h->bitrate
                               : h->kind == RNC_HOST_RNODE ? 1200u
                                                           : 10000000u);
  (void)rnc_rpc_write_uint(&w, h->mtu                     ? h->mtu
                               : h->kind == RNC_HOST_AUTO ? 1196u
                                                          : RNC_MTU);
  (void)rnc_rpc_write_uint(&w, h->serial_baud ? h->serial_baud : 115200u);
  (void)rnc_rpc_write_uint(&w, h->kiss_port);
  (void)rnc_rpc_write_string(&w, h->device ? h->device : "");
  (void)rnc_rpc_write_string(&w, h->group ? h->group : "reticulum");
  (void)rnc_rpc_write_uint(&w, h->discovery_port ? h->discovery_port : 29716u);
  (void)rnc_rpc_write_uint(&w, h->data_port ? h->data_port : 42671u);
  (void)rnc_rpc_write_uint(&w, h->frequency);
  (void)rnc_rpc_write_uint(&w, h->bandwidth);
  (void)rnc_rpc_write_uint(&w, h->spreading_factor);
  (void)rnc_rpc_write_uint(&w, h->coding_rate);
  (void)rnc_rpc_write_int(&w, h->tx_power);
  (void)rnc_rpc_write_bool(&w, h->flow_control);
  (void)rnc_rpc_write_bool(&w, h->local);
  (void)rnc_rpc_write_uint(&w, h->ifac ? h->ifac->size : 0);
  if (h->ifac)
    (void)rnc_rpc_write_bin(&w, h->ifac->key, 64);
  else
    (void)rnc_rpc_write_nil(&w);
  if (rnc_rpc_writer_finish(&w, &size) != RNC_OK ||
      rnc_hash(material, size, digest) != RNC_OK) {
    OPENSSL_cleanse(material, sizeof(material));
    return 0;
  }
  f->interface_id = (((uint32_t)digest[0] << 24) | ((uint32_t)digest[1] << 16) |
                     ((uint32_t)digest[2] << 8) | digest[3]) &
                    0x7fffffffu;
  if (!f->interface_id)
    f->interface_id = 1;
  OPENSSL_cleanse(material, sizeof(material));
  OPENSSL_cleanse(digest, sizeof(digest));
  return f->interface_id != 0x7fff0001u;
}
/* Points the host config's strings at the interface's own buffers (also needed
 * for copies of the config, whose pointers still reference the original). */
static void interface_bind(interface_config *f) {
  f->host.name = f->name;
  f->host.address = f->address[0] ? f->address
                                  : (f->host.kind == RNC_HOST_TCP_LISTEN ||
                                             f->host.kind == RNC_HOST_UDP
                                         ? "127.0.0.1"
                                         : NULL);
  f->host.target = f->target[0] ? f->target : NULL;
  f->host.device = f->device[0] ? f->device : NULL;
  f->host.group = f->group[0] ? f->group : NULL;
  f->host.id_callsign = f->callsign[0] ? f->callsign : NULL;
  f->host.callsign = f->ax_call[0] ? f->ax_call : NULL;
  if (f->host.ifac)
    f->host.ifac = &f->ifac;
  if (f->host.kind == RNC_HOST_RNODE_MULTI) {
    /* a radio is in use when it says so itself or the whole interface was
     * enabled in so many words, as the reference decides it */
    size_t k, used = 0;
    for (k = 0; k < f->sub_count; ++k)
      if (f->subs[k].enabled || (f->enabled_set && f->enabled)) {
        f->active[used] = f->subs[k].radio;
        f->active[used++].name = f->subs[k].name;
      }
    f->host.subradios = f->active;
    f->host.subradio_count = used;
  }
  if (f->host.kind == RNC_HOST_I2P) {
    size_t k;
    for (k = 0; k < f->host.i2p_peer_count; ++k)
      f->peer_ptrs[k] = f->peer_text[k];
    f->host.i2p_peers = f->peer_ptrs;
    f->host.i2p_key_path = f->i2p_key[0] ? f->i2p_key : NULL;
  }
}
static int finish_config(config *c) {
  size_t i, enabled = 0;
  for (i = 0; i < c->count; ++i) {
    interface_config *f = &c->interfaces[i];
    if (!f->has_type)
      return 0;
    interface_bind(f);
    if (f->backbone && !f->host.bitrate)
      f->host.bitrate = 100000000u; /* reference BITRATE_GUESS */
    if (!f->enabled)
      continue;
    ++enabled;
    if ((f->host.kind == RNC_HOST_TCP_CONNECT &&
         (!f->host.address || !f->host.port)) ||
        (((f->host.kind >= RNC_HOST_SERIAL && f->host.kind <= RNC_HOST_AX25) ||
          f->host.kind == RNC_HOST_RNODE_MULTI ||
          f->host.kind == RNC_HOST_WEAVE) &&
         !f->host.address))
      return 0;
    if (f->host.kind == RNC_HOST_RNODE_MULTI) {
      size_t k;
      if (!f->host.subradio_count)
        return 0;
      for (k = 0; k < f->sub_count; ++k)
        if (!f->subs[k].has_vport || !f->subs[k].radio.frequency ||
            !f->subs[k].radio.bandwidth || !f->subs[k].radio.spreading_factor ||
            !f->subs[k].radio.coding_rate)
          return 0;
    }
    /* The reference sizes TCP interfaces from their bitrate, far above 500, so
     * links across them can negotiate large packets. */
    if (!f->host.mtu && (f->host.kind == RNC_HOST_TCP_LISTEN ||
                         f->host.kind == RNC_HOST_TCP_CONNECT))
      f->host.mtu = RNC_MAX_MTU;
    if (f->host.mtu &&
        (f->host.mtu < RNC_MTU || f->host.mtu > RNC_MAX_MTU ||
         (f->host.kind >= RNC_HOST_SERIAL && f->host.kind <= RNC_HOST_AX25 &&
          f->host.mtu > RNC_MTU) ||
         (f->host.kind == RNC_HOST_AUTO && f->host.mtu > 1196) ||
         (f->host.kind == RNC_HOST_WEAVE && f->host.mtu != 1024)))
      return 0;
    if (f->host.kind == RNC_HOST_RNODE &&
        (!f->host.frequency || !f->host.bandwidth ||
         f->host.spreading_factor < 5 || f->host.spreading_factor > 12 ||
         f->host.coding_rate < 5 || f->host.coding_rate > 8))
      return 0;
    if (f->netname[0] || f->passphrase[0]) {
      if (rnc_ifac_init(&f->ifac, f->netname, strlen(f->netname), f->passphrase,
                        strlen(f->passphrase),
                        f->ifac_size ? f->ifac_size : 16) != RNC_OK)
        return 0;
      f->host.ifac = &f->ifac;
    }
    if (!interface_id(f))
      return 0;
    {
      size_t j;
      for (j = 0; j < i; ++j)
        if (c->interfaces[j].enabled &&
            c->interfaces[j].interface_id == f->interface_id)
          return 0;
    }
  }
  return (enabled > 0 || c->share) &&
         (!c->share || (c->share_tcp && c->shared_port && c->control_port &&
                        c->shared_port != c->control_port));
}
static int read_config(const char *path, config *c) {
  FILE *file;
  char line[512];
  unsigned line_number = 0;
  int section = 0, valid = 1;
  interface_config *current = NULL;
  memset(c, 0, sizeof(*c));
  c->shared_port = 37428;
  c->control_port = 37429;
  c->loglevel = RNC_LOG_NOTICE;
  file = fopen(path, "r");
  if (!file)
    return 0;
  while (fgets(line, sizeof(line), file)) {
    char *s, *eq, *value, *scan;
    int quote = 0;
    ++line_number;
    if (!strchr(line, '\n') && !feof(file)) {
      valid = 0;
      break;
    }
    s = trim(line);
    if (!*s || *s == '#' || *s == ';')
      continue;
    for (scan = s; *scan; ++scan) {
      if ((*scan == '\'' || *scan == '"') && (!quote || quote == *scan))
        quote = quote ? 0 : *scan;
      else if (!quote && (*scan == '#' || *scan == ';') &&
               (scan == s || isspace((unsigned char)scan[-1]))) {
        *scan = 0;
        break;
      }
    }
    s = trim(s);
    if (!strncmp(s, "[[[", 3)) {
      size_t n = strlen(s);
      struct sub_config *sub;
      if (section < 3 || !current || current->host.kind != RNC_HOST_RNODE_MULTI ||
          n < 7 || strcmp(s + n - 3, "]]]") ||
          current->sub_count == RNC_HOST_SUBRADIOS) {
        valid = 0;
        break;
      }
      sub = &current->subs[current->sub_count++];
      memset(sub, 0, sizeof(*sub));
      s[n - 3] = 0;
      if (!text_copy(sub->name, sizeof(sub->name), s + 3)) {
        valid = 0;
        break;
      }
      sub->radio.name = sub->name;
      section = 5;
      continue;
    }
    if (!strncmp(s, "[[", 2)) {
      size_t n = strlen(s);
      if (section < 2 || n < 5 || strcmp(s + n - 2, "]]") ||
          c->count == CONFIG_INTERFACES) {
        valid = 0;
        break;
      }
      current = &c->interfaces[c->count++];
      memset(current, 0, sizeof(*current));
      current->enabled = 1;
      s[n - 2] = 0;
      if (!text_copy(current->name, sizeof(current->name), s + 2)) {
        valid = 0;
        break;
      }
      section = 3;
      continue;
    }
    if (*s == '[') {
      if (!strcmp(s, "[reticulum]")) {
        section = 1;
        current = NULL;
      } else if (!strcmp(s, "[logging]")) {
        section = 4;
        current = NULL;
      } else if (!strcmp(s, "[interfaces]")) {
        section = 2;
        current = NULL;
      } else {
        valid = 0;
        break;
      }
      continue;
    }
    eq = strchr(s, '=');
    if (!eq) {
      valid = 0;
      break;
    }
    *eq = 0;
    value = trim(eq + 1);
    s = trim(s);
    {
      size_t n = strlen(value);
      if (n >= 2 && ((value[0] == '"' && value[n - 1] == '"') ||
                     (value[0] == '\'' && value[n - 1] == '\''))) {
        value[n - 1] = 0;
        ++value;
      }
    }
    if (section == 1) {
      int b;
      unsigned long n;
      if (!strcmp(s, "shared_instance_type")) {
        if (strcasecmp(value, "tcp")) {
          valid = 0;
          break;
        }
        c->share_tcp = 1;
      } else if (!strcmp(s, "shared_instance_port") ||
                 !strcmp(s, "instance_control_port")) {
        if (!number(value, 65535, &n) || !n) {
          valid = 0;
          break;
        }
        if (!strcmp(s, "shared_instance_port"))
          c->shared_port = (uint16_t)n;
        else
          c->control_port = (uint16_t)n;
      } else if (!strcmp(s, "remote_management_allowed") ||
                 !strcmp(s, "blackhole_sources")) {
        int sources = s[0] == 'b';
        if (!parse_hash_list(value,
                             sources ? c->bh_sources : c->mgmt_allowed,
                             sources ? &c->bh_source_count
                                     : &c->mgmt_allowed_count)) {
          valid = 0;
          break;
        }
      } else if (!strcmp(s, "interface_discovery_sources")) {
        if (!parse_hash_list(value, c->disc_sources, &c->disc_source_count)) {
          valid = 0;
          break;
        }
      } else if (!strcmp(s, "discovery_storage")) {
        if (!text_copy(c->discovery_storage, sizeof(c->discovery_storage),
                       value)) {
          valid = 0;
          break;
        }
      } else if (!strcmp(s, "autoconnect_monitor_seconds") ||
                 !strcmp(s, "autoconnect_detach_seconds")) {
        if (!number(value, 3600, &n) || !n) {
          valid = 0;
          break;
        }
        if (s[12] == 'm')
          c->autoconnect_monitor_seconds = (unsigned)n;
        else
          c->autoconnect_detach_seconds = (unsigned)n;
      } else if (!strcmp(s, "autoconnect_interface_gravity") ||
                 !strcmp(s, "autoconnect_announces_to_internal")) {
        /* accepted for compatibility; path gravity is not implemented */
        char *end;
        (void)strtod(value, &end);
        if (end == value || *end) {
          valid = 0;
          break;
        }
      } else if (!strcmp(s, "required_discovery_value") ||
                 !strcmp(s, "autoconnect_discovered_interfaces") ||
                 !strcmp(s, "discovery_job_interval")) {
        if (!number(value, 100000, &n)) {
          valid = 0;
          break;
        }
        if (s[0] == 'r')
          c->required_discovery_value = (unsigned)n;
        else if (s[0] == 'a')
          c->autoconnect_max = (unsigned)n;
        else
          c->discovery_job_interval = (unsigned)n;
      } else if (!strcmp(s, "autoconnect_interface_mode")) {
        static const struct {
          const char *name;
          rnc_interface_mode mode;
        } modes[] = {{"full", RNC_MODE_FULL},
                     {"gateway", RNC_MODE_GATEWAY},
                     {"gw", RNC_MODE_GATEWAY},
                     {"access_point", RNC_MODE_ACCESS_POINT},
                     {"ap", RNC_MODE_ACCESS_POINT},
                     {"roaming", RNC_MODE_ROAMING},
                     {"boundary", RNC_MODE_BOUNDARY}};
        size_t k;
        int found = 0;
        for (k = 0; k < sizeof(modes) / sizeof(*modes); k++)
          if (!strcasecmp(value, modes[k].name)) {
            c->autoconnect_mode = modes[k].mode;
            c->has_autoconnect_mode = found = 1;
          }
        if (!found) {
          valid = 0;
          break;
        }
      } else if (!strcmp(s, "instance_name")) {
        if (!text_copy(c->instance_name, sizeof(c->instance_name), value)) {
          valid = 0;
          break;
        }
      } else if (!strcmp(s, "network_identity")) {
        const char *home = getenv("HOME");
        int n;
        if (value[0] == '~' && (value[1] == '/' || !value[1]) && home)
          n = snprintf(c->network_identity, sizeof(c->network_identity),
                       "%s%s", home, value + 1);
        else
          n = snprintf(c->network_identity, sizeof(c->network_identity), "%s",
                       value);
        if (n <= 0 || (size_t)n >= sizeof(c->network_identity)) {
          valid = 0;
          break;
        }
      } else if (!strcmp(s, "blackhole_update_interval") ||
                 !strcmp(s, "blackhole_initial_wait")) {
        if (!number(value, 100000, &n) || !n) {
          valid = 0;
          break;
        }
        if (s[10] == 'u')
          c->bh_interval_minutes = (unsigned)n;
        else
          c->bh_initial_wait = (unsigned)n;
      } else if (!strcmp(s, "rpc_key")) {
        size_t length = strlen(value), j;
        if (!length || length % 2 || length / 2 > RNC_RPC_KEY_MAX) {
          valid = 0;
          break;
        }
        c->rpc_key_size = length / 2;
        for (j = 0; j < c->rpc_key_size; ++j) {
          unsigned x, y;
          char a = value[j * 2], z = value[j * 2 + 1];
          if (!isxdigit((unsigned char)a) || !isxdigit((unsigned char)z)) {
            valid = 0;
            break;
          }
          x = (unsigned)(isdigit((unsigned char)a)
                             ? a - '0'
                             : tolower((unsigned char)a) - 'a' + 10);
          y = (unsigned)(isdigit((unsigned char)z)
                             ? z - '0'
                             : tolower((unsigned char)z) - 'a' + 10);
          c->rpc_key[j] = (uint8_t)(16 * x + y);
        }
        if (!valid)
          break;
      } else {
        if (!boolean(value, &b)) {
          valid = 0;
          break;
        }
        if (!strcmp(s, "enable_transport"))
          c->transport = b;
        else if (!strcmp(s, "share_instance"))
          c->share = b;
        else if (!strcmp(s, "enable_remote_management"))
          c->remote_management = b;
        else if (!strcmp(s, "publish_blackhole"))
          c->publish_blackhole = b;
        else if (!strcmp(s, "respond_to_probes"))
          c->respond_to_probes = b;
        else if (!strcmp(s, "use_implicit_proof"))
          c->explicit_proofs = !b;
        else if (!strcmp(s, "link_mtu_discovery"))
          c->no_link_mtu_discovery = !b;
        else if (!strcmp(s, "panic_on_interface_error"))
          c->panic_on_interface_error = b;
        else if (!strcmp(s, "discover_interfaces"))
          c->discover_interfaces = b;
        else if (!strcmp(s, "autoconnect_unverified_implementations"))
          c->autoconnect_unverified = b;
        else if (!strcmp(s, "autoconnect_allow_local"))
          c->autoconnect_allow_local = b;
        else {
          valid = 0;
          break;
        }
      }
    } else if (section == 4) {
      unsigned long n;
      if (!strcmp(s, "loglevel")) {
        if (!number(value, RNC_LOG_EXTREME, &n)) {
          valid = 0;
          break;
        }
        c->loglevel = (int)n;
      } else if (!strcmp(s, "logdestination")) {
        if (strcmp(value, "stdout") && strcmp(value, "stderr") &&
            strcmp(value, "file")) {
          valid = 0;
          break;
        }
        (void)snprintf(c->logdestination, sizeof(c->logdestination), "%s", value);
      } else if (!strcmp(s, "logfile")) {
        if (!text_copy(c->logfile, sizeof(c->logfile), value)) {
          valid = 0;
          break;
        }
      } else {
        valid = 0;
        break;
      }
    } else if (section == 5 && current && current->sub_count) {
      if (!sub_key(&current->subs[current->sub_count - 1u], s, value)) {
        valid = 0;
        break;
      }
    } else if (section == 3 && current) {
      if (!interface_key(current, s, value)) {
        valid = 0;
        break;
      }
    } else {
      valid = 0;
      break;
    }
  }
  if (ferror(file))
    valid = 0;
  fclose(file);
  if (valid)
    valid = finish_config(c);
  if (!valid)
    fprintf(stderr,
            "Unsupported or invalid configuration at %s:%u; shared-instance "
            "mode requires shared_instance_type=tcp.\n",
            path, line_number);
  return valid;
}
static int load_state(const char *path, rnc_node *node,
                      const rnc_identity *owner, uint64_t unix_seconds,
                      uint64_t now) {
  uint8_t *record;
  struct stat st;
  int fd;
  size_t used = 0;
  int ok = 0;
  if (!path)
    return 1;
  fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0)
    return errno == ENOENT;
  if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
      (st.st_mode & 077) || st.st_size < 96 || st.st_size > STATE_MAX) {
    close(fd);
    return 0;
  }
  record = malloc(STATE_MAX);
  if (!record) {
    close(fd);
    return 0;
  }
  while (used < (size_t)st.st_size) {
    ssize_t n = read(fd, record + used, (size_t)st.st_size - used);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      break;
    used += (size_t)n;
  }
  close(fd);
  if (used == (size_t)st.st_size)
    ok = rnc_node_state_import(node, owner, unix_seconds, now, record, used) ==
         RNC_OK;
  OPENSSL_cleanse(record, STATE_MAX);
  free(record);
  return ok;
}
static int save_state(const char *path, rnc_node *node,
                      const rnc_identity *owner, uint64_t unix_seconds,
                      uint64_t now) {
  uint8_t *record;
  char temp[1024] = {0}, directory[1024];
  size_t size, used = 0;
  int fd = -1, ok = 0, created = 0;
  struct stat st, owned;
  if (!path)
    return 1;
  if (lstat(path, &st) == 0 &&
      (!S_ISREG(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 077)))
    return 0;
  if (snprintf(temp, sizeof(temp), "%s.tmp.XXXXXX", path) >= (int)sizeof(temp))
    return 0;
  record = malloc(STATE_MAX);
  if (!record)
    return 0;
  if (rnc_node_state_export(node, owner, unix_seconds, now, record, STATE_MAX,
                            &size) != RNC_OK)
    goto done;
  fd = mkstemp(temp);
  if (fd < 0)
    goto done;
  if (fstat(fd, &owned) < 0)
    goto done;
  created = 1;
  if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
    goto done;
  while (used < size) {
    ssize_t n = write(fd, record + used, size - used);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      goto done;
    used += (size_t)n;
  }
  if (fsync(fd) < 0)
    goto done;
  if (close(fd) < 0) {
    fd = -1;
    goto done;
  }
  fd = -1;
  if (rename(temp, path) < 0)
    goto done;
  created = 0;
  if (!text_copy(directory, sizeof(directory), path))
    goto done;
  {
    char *slash = strrchr(directory, '/');
    if (slash) {
      if (slash == directory)
        slash[1] = 0;
      else
        *slash = 0;
    } else
      strcpy(directory, ".");
  }
  fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0 || fsync(fd) < 0)
    goto done;
  if (!tunnels_save(path, node, owner, unix_seconds, now))
    goto done;
  ok = 1;
done:
  if (fd >= 0)
    close(fd);
  if (created && lstat(temp, &st) == 0 && S_ISREG(st.st_mode) &&
      st.st_dev == owned.st_dev && st.st_ino == owned.st_ino)
    (void)unlink(temp);
  OPENSSL_cleanse(record, STATE_MAX);
  free(record);
  return ok;
}
/* Blackhole list: the reference's MessagePack file format, kept beside the
 * state file as <state>.blackhole (absent when no --state is given). */
static char blackhole_path[1100];
/* Reads a blackhole file (the reference's MessagePack layout) into the node,
 * attributing entries to `source` (NULL = this node). A missing file is fine. */
static int blackhole_load_file(rnc_node *node, const char *path,
                               const uint8_t *source) {
  uint8_t *data;
  struct stat st;
  int fd, ok = 0;
  size_t used = 0;
  fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0)
    return errno == ENOENT;
  if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
      (st.st_mode & 077) || st.st_size < 1 || st.st_size > BLACKHOLE_MAX) {
    close(fd);
    return 0;
  }
  data = malloc(BLACKHOLE_MAX);
  if (!data) {
    close(fd);
    return 0;
  }
  while (used < (size_t)st.st_size) {
    ssize_t n = read(fd, data + used, (size_t)st.st_size - used);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      break;
    used += (size_t)n;
  }
  close(fd);
  if (used == (size_t)st.st_size)
    ok = rnc_node_blackhole_import(node, data, used, source,
                                   (uint64_t)time(NULL)) == RNC_OK;
  free(data);
  return ok;
}
static int write_file_atomic(const char *path, const uint8_t *data,
                             size_t size) {
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
/* The tunnel table lives beside the state file as <state>.tunnels. */
#define TUNNEL_STATE_MAX RNC_NODE_TUNNEL_STATE_MAX
static int tunnels_save(const char *state, rnc_node *node,
                        const rnc_identity *owner, uint64_t unix_seconds,
                        uint64_t now) {
  uint8_t *data;
  char path[1200];
  size_t size;
  int ok;
  if (!state || snprintf(path, sizeof(path), "%s.tunnels", state) >= (int)sizeof(path))
    return 1;
  if (!rnc_node_tunnel_count(node)) { /* nothing to keep: drop any old table */
    (void)unlink(path);
    return 1;
  }
  data = malloc(TUNNEL_STATE_MAX);
  if (!data)
    return 0;
  ok = rnc_node_tunnels_export(node, owner, unix_seconds, now, data,
                               TUNNEL_STATE_MAX, &size) == RNC_OK &&
       write_file_atomic(path, data, size);
  free(data);
  return ok;
}
static int tunnels_load(const char *state, rnc_node *node,
                        const rnc_identity *owner, uint64_t unix_seconds,
                        uint64_t now) {
  uint8_t *data;
  char path[1200];
  struct stat st;
  int fd, ok = 0;
  ssize_t n;
  if (!state || snprintf(path, sizeof(path), "%s.tunnels", state) >= (int)sizeof(path))
    return 1;
  fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0)
    return errno == ENOENT;
  if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
      (st.st_mode & 077) || st.st_size < 96 || st.st_size > (off_t)TUNNEL_STATE_MAX) {
    close(fd);
    return 0;
  }
  data = malloc(TUNNEL_STATE_MAX);
  if (!data) {
    close(fd);
    return 0;
  }
  n = read(fd, data, TUNNEL_STATE_MAX);
  close(fd);
  ok = n == st.st_size &&
       rnc_node_tunnels_import(node, owner, unix_seconds, now, data, (size_t)n) ==
           RNC_OK;
  free(data);
  return ok;
}
static int blackhole_load(rnc_node *node) {
  return !blackhole_path[0] || blackhole_load_file(node, blackhole_path, NULL);
}
static int blackhole_save(rnc_node *node) {
  uint8_t *data;
  size_t size;
  int ok;
  if (!blackhole_path[0])
    return 1;
  data = malloc(BLACKHOLE_MAX);
  if (!data)
    return 0;
  ok = rnc_node_blackhole_export(node, data, BLACKHOLE_MAX, &size) == RNC_OK &&
       write_file_atomic(blackhole_path, data, size);
  free(data);
  return ok;
}
/* A subscribed source's last list lives in <list>.<source identity hash>. */
static int blackhole_source_path(char *out, size_t size,
                                 const uint8_t source[16]) {
  size_t i, n;
  if (!blackhole_path[0])
    return 0;
  n = (size_t)snprintf(out, size, "%s.", blackhole_path);
  if (n + 33 > size)
    return 0;
  for (i = 0; i < 16; ++i)
    (void)snprintf(out + n + 2 * i, 3, "%02x", source[i]);
  return 1;
}
static int mgmt_start(const config *c, const rnc_identity *id, rnc_node *node,
                      rnc_host *host);
static void mgmt_stop(void);
static void mgmt_local_event(const rnc_node_event *event, uint64_t unix_seconds,
                             uint64_t now);
static void mgmt_step(uint64_t unix_seconds, uint64_t now);
/* Directory for I2P destination keys: beside the state file, else beside the
 * identity file. */
static char i2p_dir[512];
static void hex_name(const uint8_t *d, size_t n, char *out) {
  size_t i;
  for (i = 0; i < n; ++i)
    (void)snprintf(out + 2 * i, 3, "%02x", d[i]);
}
/* The reference names the key file after SHA256(SHA256(name)) and, since it
 * began tying keys to the transport identity, after SHA256(SHA256(name) +
 * SHA256(identity hash)). A key already stored under the old name is kept. */
static int i2p_key_file(const interface_config *f, const rnc_identity *id,
                        char *out, size_t cap) {
  uint8_t name_hash[32], once[32], tail[32], both[64], digest[32];
  char old_name[65], new_name[65], old_path[600];
  if (!i2p_dir[0] ||
      rnc_hash(f->name, strlen(f->name), name_hash) != RNC_OK ||
      rnc_hash(name_hash, 32, once) != RNC_OK ||
      rnc_hash(id->hash, 16, tail) != RNC_OK)
    return 0;
  memcpy(both, name_hash, 32);
  memcpy(both + 32, tail, 32);
  if (rnc_hash(both, 64, digest) != RNC_OK)
    return 0;
  hex_name(once, 32, old_name);
  hex_name(digest, 32, new_name);
  if (snprintf(old_path, sizeof(old_path), "%s/%s.i2p", i2p_dir, old_name) >=
      (int)sizeof(old_path))
    return 0;
  if (access(old_path, F_OK) == 0)
    return snprintf(out, cap, "%s", old_path) < (int)cap;
  return snprintf(out, cap, "%s/%s.i2p", i2p_dir, new_name) < (int)cap;
}
static int start_node(config *c, const rnc_identity *id, const char *state,
                      rnc_node **node, rnc_host **host) {
  size_t i;
  uint64_t now = monotonic_ms();
  *node = rnc_node_new(id, c->transport, secure_random, NULL);
  *host = *node ? rnc_host_new(*node) : NULL;
  if (!*host)
    goto fail;
  if (c->explicit_proofs)
    (void)rnc_node_set_implicit_proofs(*node, 0);
  if (c->no_link_mtu_discovery)
    (void)rnc_node_set_link_mtu_discovery(*node, 0);
  for (i = 0; i < c->count; ++i)
    if (c->interfaces[i].enabled) {
      rnc_host_status status;
      if (c->interfaces[i].host.kind == RNC_HOST_I2P) {
        interface_config *f = &c->interfaces[i];
        if (i2p_dir[0])
          (void)mkdir(i2p_dir, 0700);
        if (!i2p_key_file(f, id, f->i2p_key, sizeof(f->i2p_key))) {
          fprintf(stderr, "Cannot place the key file of interface %s\n",
                  f->name);
          if (c->panic_on_interface_error)
            goto fail;
          continue;
        }
        f->host.i2p_key_path = f->i2p_key;
      }
      if (rnc_host_add(*host, c->interfaces[i].interface_id,
                       &c->interfaces[i].host) != RNC_OK) {
        fprintf(stderr, "Cannot open interface %s: %s\n", c->interfaces[i].name,
                strerror(errno));
        /* the reference logs the error and carries on without the interface
         * unless panic_on_interface_error is set */
        if (c->panic_on_interface_error)
          goto fail;
        continue;
      }
      if (rnc_host_get_status(*host, c->interfaces[i].interface_id, &status) ==
          RNC_OK)
        printf("interface id=%u kind=%u port=%u online=%d\n",
               status.interface_id, (unsigned)status.kind, status.bound_port,
               status.online);
    }
  if (c->share) {
    rnc_host_config shared = {0};
    shared.kind = RNC_HOST_TCP_LISTEN;
    shared.name = "LocalInterface[Shared Instance]";
    shared.local = 1;
    shared.address = "127.0.0.1";
    shared.port = c->shared_port;
    shared.bitrate = 1000000000u;
    shared.mtu = RNC_MAX_MTU;
    if (rnc_host_add(*host, 0x7fff0001u, &shared) != RNC_OK)
      goto fail;
  }
  if (!load_state(state, *node, id, (uint64_t)time(NULL), now)) {
    fprintf(stderr, "Invalid or unreadable signed network state\n");
    goto fail;
  }
  if (!tunnels_load(state, *node, id, (uint64_t)time(NULL), now)) {
    fprintf(stderr, "Invalid or unreadable tunnel table\n");
    goto fail;
  }
  if (!blackhole_load(*node)) {
    fprintf(stderr, "Invalid or unreadable blackhole list\n");
    goto fail;
  }
  for (i = 0; i < c->bh_source_count; ++i) {
    char path[1200];
    if (blackhole_source_path(path, sizeof(path), c->bh_sources[i]) &&
        !blackhole_load_file(*node, path, c->bh_sources[i])) {
      fprintf(stderr, "Invalid or unreadable blackhole source list\n");
      goto fail;
    }
  }
  if (!mgmt_start(c, id, *node, *host)) {
    fprintf(stderr, "Cannot start management destinations\n");
    goto fail;
  }
  return 1;
fail:
  mgmt_stop();
  rnc_host_free(*host);
  rnc_node_free(*node);
  *host = NULL;
  *node = NULL;
  return 0;
}
static void print_hex(const uint8_t *p, size_t n) {
  size_t i;
  for (i = 0; i < n; ++i)
    printf("%02x", p[i]);
}
static int decode_hex(const char *s, uint8_t *out) {
  size_t i;
  if (strlen(s) != 32)
    return 0;
  for (i = 0; i < 16; ++i) {
    unsigned a, b;
    char x = s[2 * i], y = s[2 * i + 1];
    if (!isxdigit((unsigned char)x) || !isxdigit((unsigned char)y))
      return 0;
    a = (unsigned)(isdigit((unsigned char)x)
                       ? x - '0'
                       : tolower((unsigned char)x) - 'a' + 10);
    b = (unsigned)(isdigit((unsigned char)y)
                       ? y - '0'
                       : tolower((unsigned char)y) - 'a' + 10);
    out[i] = (uint8_t)(a * 16 + b);
  }
  return 1;
}
typedef struct admin_client {
  int fd;
  uint64_t deadline;
  size_t input_size, output_size, offset;
  char input[128], output[16384];
} admin_client;
static void append(admin_client *c, const char *fmt, ...) {
  va_list args;
  int n;
  if (c->output_size >= sizeof(c->output) - 1)
    return;
  va_start(args, fmt);
  n = vsnprintf(c->output + c->output_size, sizeof(c->output) - c->output_size,
                fmt, args);
  va_end(args);
  if (n < 0)
    return;
  if ((size_t)n >= sizeof(c->output) - c->output_size)
    c->output_size = sizeof(c->output) - 1;
  else
    c->output_size += (size_t)n;
}
static void route_reply(admin_client *c, const rnc_route *r) {
  size_t i;
  append(c, "path destination=");
  for (i = 0; i < 16; ++i)
    append(c, "%02x", r->destination[i]);
  append(c, " interface=%u hops=%u expires=%llu\n", r->interface_id,
         (unsigned)r->hops, (unsigned long long)r->expires_ms);
}
static void discovery_list(admin_client *c, uint64_t unix_seconds);
static void admin_reply(admin_client *c, rnc_host *host, rnc_node *node,
                        const rnc_identity *id, const char *state,
                        uint64_t now) {
  size_t i;
  rnc_host_status status;
  rnc_route route;
  char *request = trim(c->input);
  if (!strcmp(request, "STATUS")) {
    for (i = 0; i < RNC_HOST_SLOTS; ++i)
      if (rnc_host_status_at(host, i, &status) == RNC_OK)
        append(c,
               "interface id=%u parent=%u kind=%u online=%d port=%u mtu=%u "
               "rx=%llu tx=%llu dropped=%llu queued=%zu%s%s\n",
               status.interface_id, status.parent_id, (unsigned)status.kind,
               status.online, status.bound_port, (unsigned)status.mtu,
               (unsigned long long)status.rx_packets,
               (unsigned long long)status.tx_packets,
               (unsigned long long)status.dropped_packets, status.queued_frames,
               status.i2p_b32[0] ? " i2p=" : "", status.i2p_b32);
  } else if (!strcmp(request, "ROUTES")) {
    for (i = 0; rnc_node_route_at(node, i, now, &route) == RNC_OK; ++i)
      route_reply(c, &route);
  } else if (!strncmp(request, "PATH ", 5)) {
    uint8_t dest[16];
    if (!decode_hex(request + 5, dest))
      append(c, "ERROR invalid destination\n");
    else if (rnc_node_lookup(node, dest, now, &route) != RNC_OK)
      append(c, "NOT_FOUND\n");
    else
      route_reply(c, &route);
  } else if (!strncmp(request, "BLACKHOLE ", 10)) {
    uint8_t hash[16];
    char *arg = request + 10, *end, hex[33];
    unsigned long long until = 0;
    char *reason = NULL;
    rnc_result r;
    if (strlen(arg) < 32)
      arg = NULL;
    else {
      memcpy(hex, arg, 32);
      hex[32] = 0;
    }
    if (!arg || !decode_hex(hex, hash) || (arg[32] && arg[32] != ' ')) {
      append(c, "ERROR usage: BLACKHOLE <32hex> [until-unix [reason]]\n");
    } else {
      if (arg[32]) {
        until = strtoull(arg + 33, &end, 10);
        if (end == arg + 33)
          until = 0;
        else if (*end == ' ' && end[1])
          reason = end + 1;
      }
      r = rnc_node_blackhole(node, hash, until, reason, (uint64_t)time(NULL));
      if (r == RNC_OK)
        append(c, blackhole_save(node) ? "OK\n" : "OK (not persisted)\n");
      else if (r == RNC_STATE)
        append(c, "EXISTS\n");
      else
        append(c, "ERROR blackhole table full\n");
    }
  } else if (!strncmp(request, "UNBLACKHOLE ", 12)) {
    uint8_t hash[16];
    if (!decode_hex(request + 12, hash))
      append(c, "ERROR invalid identity\n");
    else if (rnc_node_unblackhole(node, hash) != RNC_OK)
      append(c, "NOT_FOUND\n");
    else
      append(c, blackhole_save(node) ? "OK\n" : "OK (not persisted)\n");
  } else if (!strcmp(request, "BLACKHOLES")) {
    rnc_blackhole_entry e;
    size_t k;
    for (k = 0;
         rnc_node_blackhole_at(node, k, (uint64_t)time(NULL), &e) == RNC_OK;
         ++k) {
      size_t j;
      append(c, "blackhole identity=");
      for (j = 0; j < 16; ++j)
        append(c, "%02x", e.identity[j]);
      append(c, " source=");
      for (j = 0; j < 16; ++j)
        append(c, "%02x", e.source[j]);
      append(c, " until=%llu reason=%s\n", (unsigned long long)e.until,
             e.reason);
    }
  } else if (!strcmp(request, "TUNNELS")) {
    rnc_tunnel_info t;
    size_t k, j;
    for (k = 0; rnc_node_tunnel_at(node, k, &t) == RNC_OK; ++k) {
      append(c, "tunnel id=");
      for (j = 0; j < 32; ++j)
        append(c, "%02x", t.id[j]);
      append(c, " interface=%u paths=%zu\n", t.interface_id, t.paths);
    }
  } else if (!strcmp(request, "DISCOVERED")) {
    discovery_list(c, (uint64_t)time(NULL));
  } else if (!strcmp(request, "NETWORK")) {
    if (network_identity_hash()) {
      append(c, "network identity=");
      for (i = 0; i < 16; ++i)
        append(c, "%02x", network_identity_hash()[i]);
      append(c, "\n");
    } else
      append(c, "NONE\n");
  } else if (!strcmp(request, "SAVE")) {
    append(c, "%s\n",
           state && save_state(state, node, id, (uint64_t)time(NULL), now)
               ? "OK"
               : "ERROR no state path or write failed");
  } else
    append(c, "ERROR commands: STATUS ROUTES PATH <32hex> BLACKHOLE UNBLACKHOLE BLACKHOLES NETWORK DISCOVERED TUNNELS SAVE\n");
  if (!c->output_size)
    append(c, "EMPTY\n");
}
static int admin_open(const char *path, struct stat *owned) {
  struct sockaddr_un addr;
  struct stat current;
  int fd, created = 0;
  if (!path)
    return -1;
  if (strlen(path) >= sizeof(addr.sun_path)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, path);
  if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0 ||
      fcntl(fd, F_SETFL, O_NONBLOCK) < 0 ||
      bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    goto fail;
  if (lstat(path, owned) < 0)
    goto fail;
  created = 1;
  if (chmod(path, 0600) < 0 || listen(fd, 4) < 0)
    goto fail;
  return fd;
fail: {
  int error = errno;
  close(fd);
  if (created && lstat(path, &current) == 0 && S_ISSOCK(current.st_mode) &&
      current.st_dev == owned->st_dev && current.st_ino == owned->st_ino)
    (void)unlink(path);
  errno = error;
  return -1;
}
}
static void admin_step(int listener, admin_client clients[4], rnc_host *host,
                       rnc_node *node, const rnc_identity *id,
                       const char *state, uint64_t now) {
  size_t i;
  if (listener < 0)
    return;
  for (i = 0; i < 4; ++i)
    if (clients[i].fd < 0) {
      int fd = accept(listener, NULL, NULL);
      if (fd >= 0) {
        if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0 ||
            fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
          close(fd);
          break;
        }
        memset(&clients[i], 0, sizeof(clients[i]));
        clients[i].fd = fd;
        clients[i].deadline = now + 2000u;
      }
      break;
    }
  for (i = 0; i < 4; ++i) {
    admin_client *c = &clients[i];
    if (c->fd < 0)
      continue;
    if (now >= c->deadline) {
      close(c->fd);
      c->fd = -1;
      continue;
    }
    if (!c->output_size) {
      ssize_t n = read(c->fd, c->input + c->input_size,
                       sizeof(c->input) - 1 - c->input_size);
      if (n > 0) {
        char *newline;
        c->input_size += (size_t)n;
        c->input[c->input_size] = 0;
        newline = strchr(c->input, '\n');
        if (newline) {
          *newline = 0;
          admin_reply(c, host, node, id, state, now);
        } else if (c->input_size == sizeof(c->input) - 1)
          append(c, "ERROR command too long\n");
      } else if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
                            errno != EINTR)) {
        close(c->fd);
        c->fd = -1;
        continue;
      }
    }
    if (c->output_size) {
      ssize_t n =
          write(c->fd, c->output + c->offset, c->output_size - c->offset);
      if (n > 0)
        c->offset += (size_t)n;
      else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
               errno != EINTR) {
        close(c->fd);
        c->fd = -1;
        continue;
      }
      if (c->offset == c->output_size) {
        close(c->fd);
        c->fd = -1;
      }
    }
  }
}
/* Log output: "[time] [Level]   module: message" like RNS, to stderr (default),
 * stdout or a file that rolls over at 5 MiB. The daemon's own machine-readable
 * lines stay on stdout. */
#define LOG_MAXSIZE (5u * 1024u * 1024u)
static struct {
  int to_stdout, to_file;
  char path[512];
} logsink;
static void daemon_log_handler(void *context, int level, const char *module,
                               const char *message) {
  char stamp[32], line[RNC_LOG_MESSAGE_MAX + 96];
  time_t now = time(NULL);
  struct tm tm;
  (void)context;
  if (!localtime_r(&now, &tm) ||
      strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tm) == 0)
    stamp[0] = 0;
  (void)snprintf(line, sizeof(line), "[%s] %s %s%s%s\n", stamp,
                 rnc_log_level_name(level), module, module[0] ? ": " : "",
                 message);
  if (logsink.to_file) {
    FILE *f = fopen(logsink.path, "a");
    if (f) {
      long size;
      (void)fputs(line, f);
      size = ftell(f);
      (void)fclose(f);
      if (size > (long)LOG_MAXSIZE) {
        char previous[sizeof(logsink.path) + 3];
        (void)snprintf(previous, sizeof(previous), "%s.1", logsink.path);
        (void)unlink(previous);
        (void)rename(logsink.path, previous);
      }
      return;
    }
    logsink.to_file = 0; /* cannot write the file: fall back to the console */
  }
  (void)fputs(line, logsink.to_stdout ? stdout : stderr);
  if (logsink.to_stdout)
    (void)fflush(stdout);
}
static void log_apply(const config *c) {
  memset(&logsink, 0, sizeof(logsink));
  logsink.to_stdout = !strcmp(c->logdestination, "stdout");
  if (!strcmp(c->logdestination, "file") && c->logfile[0]) {
    logsink.to_file = 1;
    (void)snprintf(logsink.path, sizeof(logsink.path), "%s", c->logfile);
  }
  rnc_log_set_handler(daemon_log_handler, NULL);
  rnc_log_set_level(c->loglevel);
}
#include "node_rpc.h"
#include "node_mgmt.h"
#include "node_discovery.h"

int main(int argc, char **argv) {
  const char *config_path = NULL, *key_path = NULL, *admin_path = NULL,
             *state_path = NULL;
  int check = 0, admin = -1, result = 1;
  size_t i;
  config current;
  rnc_identity id = {0};
  rnc_node *node = NULL;
  rnc_host *host = NULL;
  struct stat admin_inode;
  admin_client clients[4];
  rpc_server rpc;
  memset(&current, 0, sizeof(current));
  memset(&rpc, 0, sizeof(rpc));
  rpc.fd = -1;
  for (i = 0; i < 4; ++i)
    rpc.clients[i].fd = -1;
  for (i = 0; i < 4; ++i)
    clients[i].fd = -1;
  for (i = 1; i < (size_t)argc; ++i) {
    if (!strcmp(argv[i], "--check"))
      check = 1;
    else if (!strcmp(argv[i], "--config") && i + 1 < (size_t)argc)
      config_path = argv[++i];
    else if (!strcmp(argv[i], "--identity") && i + 1 < (size_t)argc)
      key_path = argv[++i];
    else if (!strcmp(argv[i], "--admin") && i + 1 < (size_t)argc)
      admin_path = argv[++i];
    else if (!strcmp(argv[i], "--state") && i + 1 < (size_t)argc) {
      state_path = argv[++i];
      if (snprintf(i2p_dir, sizeof(i2p_dir), "%s.i2p", state_path) >=
          (int)sizeof(i2p_dir))
        i2p_dir[0] = 0;
      if (snprintf(blackhole_path, sizeof(blackhole_path), "%s.blackhole",
                   state_path) >= (int)sizeof(blackhole_path))
        blackhole_path[0] = 0;
      if (snprintf(discovery_dir, sizeof(discovery_dir), "%s.discovery",
                   state_path) >= (int)sizeof(discovery_dir))
        discovery_dir[0] = 0;
    }
    else if (!strcmp(argv[i], "--version")) {
      puts("reticulum-c-node 0.2 (experimental C router; own admin protocol)");
      return 0;
    } else {
      fprintf(stderr,
              "Usage: %s --config FILE [--check | --identity FILE [--admin "
              "SOCKET] [--state FILE]]\n",
              argv[0]);
      return 2;
    }
  }
  if (!config_path || (!check && !key_path) ||
      !read_config(config_path, &current)) {
    result = 2;
    goto done;
  }
  if (!i2p_dir[0] && key_path &&
      snprintf(i2p_dir, sizeof(i2p_dir), "%s.i2p", key_path) >=
          (int)sizeof(i2p_dir))
    i2p_dir[0] = 0;
  if (check) {
    puts("Configuration valid; optional shared-instance mode uses TCP and "
         "authenticated MessagePack RPC.");
    result = 0;
    goto done;
  }
  umask(077);
  setvbuf(stdout, NULL, _IOLBF, 0);
  log_apply(&current);
  rnc_logf(RNC_LOG_NOTICE, "daemon", "starting, log level %d", current.loglevel);
  if (rnc_host_identity_load(key_path, secure_random, NULL, &id) != RNC_OK) {
    fprintf(stderr, "Cannot load private identity: %s\n", strerror(errno));
    goto done;
  }
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);
  signal(SIGHUP, signal_handler);
  signal(SIGPIPE, SIG_IGN);
  if (!start_node(&current, &id, state_path, &node, &host) ||
      !rpc_open(&rpc, &current, &id))
    goto done;
  if (admin_path) {
    admin = admin_open(admin_path, &admin_inode);
    if (admin < 0) {
      fprintf(stderr, "Cannot create private admin socket: %s\n",
              strerror(errno));
      goto done;
    }
  }
  printf("Ready identity=");
  print_hex(id.hash, 16);
  printf(" admin=%s\n", admin_path ? admin_path : "disabled");
  while (!stopping) {
    rnc_host_event event;
    uint64_t now = monotonic_ms();
    if (rnc_host_step(host, 10, (uint64_t)time(NULL), now) != RNC_OK) {
      fprintf(stderr, "Host pump failed\n");
      goto done;
    }
    while (rnc_host_poll(host, &event) == RNC_OK) {
      if (event.type == RNC_HOST_UP || event.type == RNC_HOST_DOWN)
        printf("interface id=%u %s error=%d\n", event.interface_id,
               event.type == RNC_HOST_UP ? "up" : "down", event.error_number);
      else if (event.node.type == RNC_NODE_LOCAL &&
               (mgmt.responder || mgmt.requester)) {
        mgmt_local_event(&event.node, (uint64_t)time(NULL), monotonic_ms());
      } else if (event.node.type == RNC_NODE_ANNOUNCE) {
        discovery_heard(&event.node, (uint64_t)time(NULL));
        printf("announce destination=");
        print_hex(event.node.route.destination, 16);
        printf(" interface=%u hops=%u\n", event.interface_id,
               (unsigned)event.node.route.hops);
      }
    }
    mgmt_step((uint64_t)time(NULL), monotonic_ms());
    admin_step(admin, clients, host, node, &id, state_path, monotonic_ms());
    rpc_step(&rpc, host, node, &current, &id, monotonic_ms());
    if (reloading) {
      config replacement;
      reloading = 0;
      if (read_config(config_path, &replacement)) {
        log_apply(&replacement);
        if (!save_state(state_path, node, &id, (uint64_t)time(NULL),
                        monotonic_ms()))
          fprintf(stderr, "Reload postponed: cannot save network state\n");
        else {
          rpc_stop(&rpc);
          mgmt_stop();
          rnc_host_free(host);
          rnc_node_free(node);
          host = NULL;
          node = NULL;
          if (start_node(&replacement, &id, state_path, &node, &host) &&
              rpc_open(&rpc, &replacement, &id)) {
            OPENSSL_cleanse(&current, sizeof(current));
            current = replacement;
            (void)finish_config(&current);
            puts("Configuration reloaded; transport connections restart.");
          } else {
            fprintf(stderr,
                    "Reload failed; restoring previous configuration\n");
            rpc_stop(&rpc);
            mgmt_stop();
            rnc_host_free(host);
            rnc_node_free(node);
            host = NULL;
            node = NULL;
            if (!start_node(&current, &id, state_path, &node, &host) ||
                !rpc_open(&rpc, &current, &id))
              goto done;
          }
        }
      }
      OPENSSL_cleanse(&replacement, sizeof(replacement));
    }
  }
  if (!save_state(state_path, node, &id, (uint64_t)time(NULL),
                  monotonic_ms())) {
    fprintf(stderr, "Cannot save signed network state\n");
    goto done;
  }
  result = 0;
done:
  rpc_stop(&rpc);
  for (i = 0; i < 4; ++i)
    if (clients[i].fd >= 0)
      close(clients[i].fd);
  if (admin >= 0) {
    struct stat st;
    close(admin);
    if (lstat(admin_path, &st) == 0 && S_ISSOCK(st.st_mode) &&
        st.st_dev == admin_inode.st_dev && st.st_ino == admin_inode.st_ino)
      (void)unlink(admin_path);
  }
  mgmt_stop();
  rnc_host_free(host);
  rnc_node_free(node);
  rnc_identity_clear(&id);
  OPENSSL_cleanse(&current, sizeof(current));
  return result;
}
