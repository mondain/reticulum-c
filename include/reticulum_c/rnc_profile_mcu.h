#ifndef RETICULUM_C_PROFILE_MCU_H
#define RETICULUM_C_PROFILE_MCU_H
/*
 * Capacity profile for microcontrollers (ESP32/ESP32-S3, nRF52840 and similar,
 * roughly 256-320 KB of RAM).
 *
 * Select it with  -DRNC_PROFILE=mcu  in CMake (which defines RNC_PROFILE_MCU=1 for
 * the library and every consumer), or by defining RNC_PROFILE_MCU yourself before
 * including any reticulum_c header. Every value below is guarded, so any single one
 * can still be overridden with -D on the compiler command line, and a completely
 * custom profile can be supplied with -DRNC_PROFILE_HEADER='"my_profile.h"'.
 *
 * IMPORTANT: these constants size public structs (rnc_packet, rnc_link_event,
 * rnc_node_event, rnc_hdlc, ...) and the private tables inside rnc_node, rnc_link,
 * rnc_service and rnc_responder. The library and everything that includes its
 * headers MUST be compiled with the same profile.
 *
 * Wire compatibility: RNC_MTU stays 500, the Reticulum default, so links, resources
 * and announces interoperate with unmodified Reticulum. RNC_MAX_MTU only bounds
 * buffers: peers that would negotiate a larger link MTU (for example over a TCP
 * interface) are clamped to it, exactly as for any hop with a smaller MTU. Packets
 * or frames larger than RNC_MAX_MTU are rejected, which is correct for a device that
 * only has interfaces with 500 byte MTU (LoRa, serial, BLE).
 *
 * What shrinks (default host value -> this profile):
 *   RNC_MAX_MTU              4096 -> 500    dominant: sizes every packet buffer
 *   RNC_NODE_ROUTES           128 -> 12
 *   RNC_NODE_KNOWN            256 -> 8      remembered announces (path recall)
 *   RNC_NODE_LINKS             64 -> 8      link-table entries relayed for others
 *   RNC_NODE_EVENTS            64 -> 8      node output queue (>= INTERFACES + REQUESTS + 2)
 *   RNC_NODE_DESTINATIONS      16 -> 4
 *   RNC_NODE_INTERFACES         8 -> 2
 *   RNC_NODE_TUNNELS            8 -> 1, RNC_NODE_TUNNEL_PATHS 16 -> 2
 *   RNC_NODE_BLACKHOLE        256 -> 8
 *   RNC_LINK_EVENTS            64 -> 6      per-link output queue
 *   RNC_CHANNEL_TX_MAX / RX_WINDOW 48 -> 4  channel window, per link
 *   RNC_RESPONDER_LINKS         8 -> 2, _DESTINATIONS 4 -> 1, _HANDLERS 24 -> 4
 *   RNC_SERVICE_HANDLERS       24 -> 4, RNC_SERVICE_EVENTS 8 -> 4
 *   RNC_TRANSFER_*, RNC_REQUESTER_JOBS: smaller
 *   RNC_RATCHET_MAX_KEYS      512 -> 32     also bounds a stack array
 * and node.c's private RNC_NODE_QUEUE, _HASHES, _REVERSE, _REQUESTS, _ANNOUNCES,
 * _RATES, _HELD.
 *
 * Trade-offs of the smaller tables: fewer remembered paths and announces, a
 * shallower packet de-duplication window, a small number of simultaneous links, and
 * a channel window of 4 messages (slower bulk throughput on fast links). Bulk
 * Resource transfers still work but the per-link event queue holds fewer packets.
 * Large Resource and service payloads are bounded by the max_value you pass to
 * rnc_service_new / rnc_responder_new (heap), not by this profile.
 */

#ifndef RNC_MAX_MTU
#define RNC_MAX_MTU 500u
#endif

#ifndef RNC_NODE_INTERFACES
#define RNC_NODE_INTERFACES 2u
#endif
#ifndef RNC_NODE_ROUTES
#define RNC_NODE_ROUTES 12u
#endif
#ifndef RNC_NODE_DESTINATIONS
#define RNC_NODE_DESTINATIONS 4u
#endif
#ifndef RNC_NODE_LINKS
#define RNC_NODE_LINKS 8u
#endif
#ifndef RNC_NODE_EVENTS
#define RNC_NODE_EVENTS 8u
#endif
#ifndef RNC_NODE_RECEIPTS
#define RNC_NODE_RECEIPTS 8u
#endif
#ifndef RNC_NODE_KNOWN
#define RNC_NODE_KNOWN 8u
#endif
#ifndef RNC_NODE_TUNNELS
#define RNC_NODE_TUNNELS 1u
#endif
#ifndef RNC_NODE_TUNNEL_PATHS
#define RNC_NODE_TUNNEL_PATHS 2u
#endif
#ifndef RNC_NODE_BLACKHOLE
#define RNC_NODE_BLACKHOLE 8
#endif

#ifndef RNC_NODE_QUEUE
#define RNC_NODE_QUEUE 4u
#endif
#ifndef RNC_NODE_HASHES
#define RNC_NODE_HASHES 64u
#endif
#ifndef RNC_NODE_REVERSE
#define RNC_NODE_REVERSE 8u
#endif
#ifndef RNC_NODE_REQUESTS
#define RNC_NODE_REQUESTS 2u
#endif
#ifndef RNC_NODE_ANNOUNCES
#define RNC_NODE_ANNOUNCES 4u
#endif
#ifndef RNC_NODE_RATES
#define RNC_NODE_RATES 16u
#endif
#ifndef RNC_NODE_HELD
#define RNC_NODE_HELD 2u
#endif

#ifndef RNC_LINK_EVENTS
#define RNC_LINK_EVENTS 6u
#endif
#ifndef RNC_CHANNEL_RX_WINDOW
#define RNC_CHANNEL_RX_WINDOW 4u
#endif
#ifndef RNC_CHANNEL_TX_MAX
#define RNC_CHANNEL_TX_MAX 4u
#endif

#ifndef RNC_RESPONDER_LINKS
#define RNC_RESPONDER_LINKS 2u
#endif
#ifndef RNC_RESPONDER_DESTINATIONS
#define RNC_RESPONDER_DESTINATIONS 1u
#endif
#ifndef RNC_RESPONDER_HANDLERS
#define RNC_RESPONDER_HANDLERS 4u
#endif
#ifndef RNC_SERVICE_PENDING
#define RNC_SERVICE_PENDING 4u
#endif
#ifndef RNC_SERVICE_HANDLERS
#define RNC_SERVICE_HANDLERS 4u
#endif
#ifndef RNC_SERVICE_EVENTS
#define RNC_SERVICE_EVENTS 4u
#endif
#ifndef RNC_SERVICE_ALLOWLIST
#define RNC_SERVICE_ALLOWLIST 4u
#endif
#ifndef RNC_TRANSFER_LINKS
#define RNC_TRANSFER_LINKS 2u
#endif
#ifndef RNC_TRANSFER_JOBS
#define RNC_TRANSFER_JOBS 2u
#endif
#ifndef RNC_TRANSFER_ALLOWED
#define RNC_TRANSFER_ALLOWED 8u
#endif
#ifndef RNC_REQUESTER_JOBS
#define RNC_REQUESTER_JOBS 2u
#endif
#ifndef RNC_RATCHET_MAX_KEYS
#define RNC_RATCHET_MAX_KEYS 32u
#endif

#endif
