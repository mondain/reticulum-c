#ifndef RETICULUM_C_DISCOVERY_H
#define RETICULUM_C_DISCOVERY_H
#include <reticulum_c/rnc.h>
#include <reticulum_c/rnc_stamp.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Interface discovery announce payloads (RNS.Discovery). An announce on
 * rnstransport.discovery.interface carries one flags byte, then a MessagePack
 * map with integer keys describing an interface plus a proof-of-work stamp over
 * the map, optionally encrypted to a network identity. */
#define RNC_DISCOVERY_STAMP_ROUNDS 20u
#define RNC_DISCOVERY_DEFAULT_STAMP_VALUE 16u
#define RNC_DISCOVERY_FLAG_SIGNED 0x01u
#define RNC_DISCOVERY_FLAG_ENCRYPTED 0x02u
#define RNC_DISCOVERY_PAYLOAD_MAX 1024u

typedef struct rnc_discovery_info {
  char type[32]; /* BackboneInterface, TCPServerInterface, I2PInterface,
                    RNodeInterface, WeaveInterface or KISSInterface */
  int transport;
  uint8_t transport_id[16];
  char impl_name[16], version[16]; /* empty = not announced */
  char name[96];
  int has_latitude, has_longitude, has_height;
  double latitude, longitude, height;
  int has_operator;
  uint8_t operator_address[16];
  char reachable_on[128]; /* IP, hostname or I2P b32; empty = none */
  int has_port;
  uint32_t port;
  char ifac_netname[64], ifac_netkey[64]; /* empty = not published */
  int has_frequency, has_bandwidth, has_channel, has_modulation;
  uint32_t frequency, bandwidth, channel;
  unsigned spreading_factor, coding_rate; /* RNode only; 0 = none */
  char modulation[32]; /* KISS: text; Weave: decimal digits */
} rnc_discovery_info;

/* The MessagePack map alone, laid out as the reference writes it. */
rnc_result rnc_discovery_pack(const rnc_discovery_info *info, uint8_t *output,
                              size_t capacity, size_t *written);
/* Full announce app data: flags, packed map and stamp (or the encrypted form
 * when `encrypt_to` is given). The stamp costs about 2^stamp_cost hashes. */
rnc_result rnc_discovery_announce_data(const rnc_discovery_info *info,
                                       unsigned stamp_cost,
                                       const rnc_identity *encrypt_to,
                                       rnc_random_fn random, void *random_context,
                                       uint8_t *output, size_t capacity,
                                       size_t *written);
/* Validates and decodes announce app data. RNC_OK: well formed with a stamp of
 * at least required_value (*value and stamp are filled). RNC_AUTH: stamp below
 * the requirement. RNC_STATE: encrypted but no network identity with a private
 * key was supplied, or decryption failed. RNC_PROTOCOL: malformed or invalid
 * fields. Output is only written on RNC_OK. */
rnc_result rnc_discovery_parse(const uint8_t *app_data, size_t size,
                               unsigned required_value,
                               const rnc_identity *network_identity,
                               rnc_discovery_info *info,
                               uint8_t stamp[RNC_STAMP_SIZE], unsigned *value);

/* Reference validation helpers. */
int rnc_discovery_is_ip_address(const char *text);
int rnc_discovery_is_hostname(const char *text);
/* ASCII only, runs of spaces folded, leading characters up to the first
 * letter/digit and trailing ones after the last letter/digit or ')' removed. */
void rnc_discovery_sanitize_name(const char *name, char *out, size_t capacity);
/* SHA256 of "<transport id hex><name>": identifies a discovered interface. */
rnc_result rnc_discovery_hash(const rnc_discovery_info *info, uint8_t hash[32]);
/* SHA256 of "<reachable_on>:<port>": identifies the endpoint to connect to. */
rnc_result rnc_discovery_endpoint_hash(const rnc_discovery_info *info,
                                       uint8_t hash[32]);
/* ---- discovered interface records ---- */
#define RNC_DISCOVERY_THRESHOLD_UNKNOWN (24u * 60u * 60u)
#define RNC_DISCOVERY_THRESHOLD_STALE (3u * 24u * 60u * 60u)
#define RNC_DISCOVERY_THRESHOLD_REMOVE (7u * 24u * 60u * 60u)
#define RNC_DISCOVERY_STATUS_AVAILABLE 1000
#define RNC_DISCOVERY_STATUS_UNKNOWN 100
#define RNC_DISCOVERY_STATUS_STALE 0
#define RNC_DISCOVERY_RECORD_MAX 4096u
typedef struct rnc_discovery_record {
  rnc_discovery_info info;
  uint8_t stamp[RNC_STAMP_SIZE];
  unsigned value;
  uint8_t network_id[16]; /* hash of the announcing (network) identity */
  unsigned hops;
  double received, discovered, last_heard; /* unix seconds */
  uint32_t heard_count;
  char config_entry[768];
} rnc_discovery_record;
/* Configuration entry a user can paste to connect to the interface, worded as
 * the reference writes it. use_backbone selects BackboneInterface over
 * TCPClientInterface for TCP announcements. */
rnc_result rnc_discovery_config_entry(const rnc_discovery_info *info,
                                      int use_backbone, char *output,
                                      size_t capacity);
/* The reference's on-disk record (one MessagePack map per interface). */
rnc_result rnc_discovery_record_pack(const rnc_discovery_record *record,
                                     uint8_t *output, size_t capacity,
                                     size_t *written);
rnc_result rnc_discovery_record_unpack(const uint8_t *data, size_t size,
                                       rnc_discovery_record *record);
/* AVAILABLE, UNKNOWN or STALE from the seconds since the interface was last
 * heard; returns -1 when it is old enough to be removed. */
int rnc_discovery_status(double heard_delta_seconds);
#ifdef __cplusplus
}
#endif
#endif
