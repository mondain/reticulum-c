# Reticulum manual vs reticulum-c: spec gap list

- **Date:** 2026-10-26
- **Baseline:** Reticulum Manual (`Downloads/Reticulum.Manual.pdf`, text extracted with `pdftotext`). It is newer than the RNS 1.5.5 baseline used by the SDK, so some items (rngit, interface discovery, blackhole management) postdate it.
- **Method:** three read-only audits by manual section, based on headers and source rather than README claims. No builds or tests were run. Items marked *(unverified)* rest on header/grep evidence only. The audit did not read all of `host_posix.c`, `ipc.c`, `service.c`, `channel.c`, `ratchet.c` or `ifac.c` in full.

**Legend:** IMPL = implemented, PART = partial, MISS = missing, N/A = not applicable to an SDK or by design.

> **Note on config parsing:** a Reticulum-style config parser exists in `examples/node_daemon.c` (not in the library). It accepts `[reticulum]` and `[interfaces]` sections and the keys listed in [section 5](#5-config-and-utilities-manual-ch5). An early interface-audit report claiming there was no config layer was wrong.

## 1. Summary

The core protocol is solid: identities, SINGLE/GROUP/PLAIN destinations, announces (including ratcheted), path request/response, HEADER_1/2, IFAC, links, MTU negotiation, Channel, Buffer, Resources (bz2, metadata, segments), request/response, transport forwarding and link tables.

Largest gaps, in priority order:

1. Endpoint packet delivery proofs and `PacketReceipt` (PROVE_NONE/APP/ALL, implicit/explicit proofs, timeouts). Blocks the Echo and rnprobe patterns.
2. Interface policy: interface modes, configurable `announce_cap`, per-destination announce rate limiting, new-destination rate limiting, path request burst control, ingress control.
3. Announce propagation details (manual 6.7.4): retransmit retries, local rebroadcast accounting, hold-down timers, mode-dependent path expiry.
4. Missing interface types: I2P, RNode Multi, Weave. Missing options on existing types ([section 4](#4-interfaces-manual-ch7-ch8)).
5. RNode correctness (bitrate from SF/BW/CR, airtime limits and callsign beacon done; remaining): detection/firmware check.
6. Management plane: blackhole management, remote management destination, probe responder, network identities and interface discovery are done (see sections 3 and 4).
7. Persistent known-destination store (`Identity.recall`) and tunnels are done. The transport packet cache is deliberately not built: see section 3.
8. Link lifecycle polish: RTT-scaled keepalive, STALE state, statistics getters, teardown reason enum, public RTT accessor.
9. Resource window growth and rate-based timeouts: done (see section 5).
10. CLI tools and examples. (Logging hook and the `loglevel` / `instance_name` options are done.)

## 2. Protocol (manual ch6, ch9)

| Status | Feature | Notes |
| --- | --- | --- |
| IMPL | Destination hash (10B name hash + identity hash, truncated SHA-256) | `src/crypto.c` |
| IMPL | Destination types SINGLE/GROUP/PLAIN/LINK | GROUP/PLAIN are local delivery only |
| IMPL | Identity X25519 + Ed25519, 16B hash, sign/verify | |
| IMPL | SINGLE encryption (ephemeral ECDH, HKDF, AES-256-CBC, HMAC token), MDU 383 | |
| IMPL | Announce create/verify | Verify recomputes the destination hash from name hash + identity hash (`src/announce.c:51`); read, not exercised |
| IMPL | Packet header flags, hops, transport_id, contexts 0-14 and 250-255 | `src/packet.c` |
| IMPL | Packet hash | |
| IMPL | Transport vs endpoint mode | |
| IMPL | Announce validation, path learning, freshness, 300s future-timestamp reject | `node.c` |
| IMPL | Announce rebroadcast with jitter, HEADER_2 rewrite | |
| IMPL | 2% announce bandwidth cap, lowest-hops-first | Hard-coded in `node.c` |
| IMPL | Path request/response (context 11), tag dedup, 15s pending table | |
| IMPL | Link request forwarding, link table, reverse-path validation, MTU clamp | |
| IMPL | IFAC (derive, apply, verify, tag size 1-64) | `src/ifac.c` |
| IMPL | Wire format, MTU 500..4096 with 3B signalling | |
| IMPL | Crypto primitives (OpenSSL) | |
| IMPL | Ratchets: generate, rotate, export/import, encrypt/decrypt, 30-day peer expiry | `src/ratchet.c` |
| IMPL | Announce propagation (6.7.4) | One retry after 5.5s (PATHFINDER_R/G/RW), cancelled after 2 heard neighbour rebroadcasts or when passed on a further hop; single transmission for shared-instance clients; locally originated announces blocked on AP interfaces. Verified against reference `Transport.py` at the pinned commit. Hold-down of announces during path-request answers is not implemented; hop drop remains at wire hops >= 127 (reference allows 128 after increment); `MODE_INTERNAL` not implemented |
| IMPL | Path expiry | 7 days; AP 1 day, Roaming 6 hours by ingress interface mode |
| IMPL | Delivery proofs | Endpoint proof creation (implicit 64B / explicit 96B) via `rnc_node_prove` and PROVE_ALL; validation by signer in `rnc_node_send_tracked` receipts (closed in `feature/spec-gap-closure`) |
| PART | Packet prioritisation | Only the announce queue is ordered |
| IMPL | `PacketReceipt` equivalent: `rnc_node_send_tracked` + `RNC_NODE_RECEIPT` event (delivered/failed, RTT, timeout); `rnc_node_set_proof_strategy` (NONE/APP/ALL) | PROVE_APP is signalled by the LOCAL event; no callback API by design |
| IMPL | Tunnels and tunnel table | Synthesis packet on TCP client connect (not kiss-framed), validation, tunnel table with 8 h expiry, path association and restoration when a tunnel reappears, signed persistence beside the state file (`<state>.tunnels`); verified against the reference's TCP client |
| N/A | Transport packet cache and cache-request serving | In the reference `Transport.should_cache()` returns False unconditionally ("disabling it for now, until redesigned"), so nothing is ever put in the general cache and a cache request is never served. The announce cache it also keeps is what this node's route table and state checkpoint already do. Context 8 is still sent by Resource, as the reference does |
| IMPL | Persistent known-destinations table | See `rnc_node_known_export/import` |
| PART | Network identities (6.5) | `network_identity` file (created 0600 if absent, reference file format), reported as `network_id` and over the admin `NETWORK` command, with the `rnstransport.network` and `rnstransport.network.instance.<hash>` destinations registered; used for encrypted discovery announces |
| N/A | AES-128 link modes, Python pickle | By design; MessagePack RPC only |

## 3. API reference (manual ch16)

### Reticulum class

| Status | Feature | Notes |
| --- | --- | --- |
| PART | Shared instance and RPC server (HMAC, MessagePack GET queries) | Several query names (`blackholed_identities`, `rate_table`, `path_table` fields) are decoded but the host supplies the data; the first two return empty |
| PART | `get_instance`, `transport_enabled`, `link_mtu_discovery`, `should_use_implicit_proof` accessors | `rnc_node_implicit_proofs` / `rnc_node_set_implicit_proofs` cover `should_use_implicit_proof`; the rest are Python-instance accessors or concern link MTU discovery (not implemented, links stay at the 500 byte MTU) |

### Identity

| Status | Feature | Notes |
| --- | --- | --- |
| IMPL | create, from_bytes, load/get keys, sign, validate, encrypt, decrypt | |
| IMPL | `from_file` (64B raw, mode 0600, strict checks) | |
| PART | `to_file` / `pub_to_file`; `truncated_hash` / `get_random_hash` helpers | |
| IMPL | `recall`, `recall_app_data` | `rnc_node_recall`: bounded 256-entry store independent of path lifetime, with sealed export/import for host persistence. Ratchet is returned in the recalled announce |

### Destination

| Status | Feature | Notes |
| --- | --- | --- |
| IMPL | `expand_name`, `hash_from_name_and_identity`, announce, path response, request handlers (ALLOW_NONE/ALL/LIST/identified), GROUP keys | |
| PART | `accepts_links` toggle, `set_max_request_size`, `set/clear_default_app_data`, `enable_ratchets` persistence | App admits link requests; ratchet persistence is caller-owned |
| MISS | `proof_strategy`, `set_proof_requested_callback` | |

### Packet / PacketReceipt

| Status | Feature | Notes |
| --- | --- | --- |
| PART | Send via `rnc_node_send`, `rnc_link_send_packet(_hashed)` | |
| IMPL | `PacketReceipt` status, rtt, timeout | `rnc_node_send_tracked` (DELIVERED/FAILED event with rtt), `rnc_node_receipt_status` (SENT/DELIVERED/FAILED, culled = RNC_STATE), `rnc_node_receipt_timeout` and timeout 0 for the reference default (6 s per hop plus first-hop 6 s + MTU at the interface rate). Callbacks are events |
| MISS | `resend`, `get_rssi/get_snr/get_q` | Resend by building and tracking a new packet |

### Link

| Status | Feature | Notes |
| --- | --- | --- |
| IMPL | Request/proof, LRRTT, LINKIDENTIFY, LINKCLOSE, keepalive, MTU, remote identity, request/response (contexts 9/10), teardown | `src/link.c` |
| IMPL | Keepalive and timeouts | RTT-scaled keepalive (5..360 s), STALE after 2x keepalive, teardown after RTT*4+5 s, configurable establishment timeout (first hop + 6 s per hop); previously fixed 30 s / 180 s. The default establishment timeout without configuration remains 30 s |
| IMPL | Teardown reason | `rnc_link_teardown_reason`: timeout, initiator closed, destination closed |
| IMPL | RTT | `rnc_link_rtt` |
| PART | ResourceStrategy | Explicit `rnc_resource_accept` only, no strategy enum |
| PART | `get_age`, `no_inbound_for`, `no_outbound_for` | Implemented. Missing: `inactive_for` (data-only idle), establishment/expected rate, `track_phy_stats`, rssi/snr/q, `get_mode` |
| IMPL | RequestReceipt status and progress | `rnc_requester_progress` / `rnc_service_request_state`: FAILED, SENT, DELIVERED (request Resource arrived), RECEIVING (0..1 response Resource progress), READY. Callbacks are events/polling |

### Resource

| Status | Feature | Notes |
| --- | --- | --- |
| IMPL | Advertisement, hashmap/HMU, part requests, proof, cancel, cache request parsing, bz2, metadata, request-id/response flags, multi-segment | `src/resource.c` |
| IMPL | Window sizing | Receiver window 4 (or the link's previous window), +1 per completed round up to 10, 75 after 4 fast rounds (>6.25 kB/s), 4 after 2 very slow rounds (<250 B/s), shrinks on a timed-out round; remembered per link |
| IMPL | Retry/timeout logic | Receiver part timeout from the expected inflight rate (`update_eifr`, factor 4 then 2, HMU wait 3.5, grace 0.25 s, +0.5 s per retry); sender advertisement (RTT x 6 + 1 s), part-request (RTT x 96 + 78 s, then cancel) and proof (RTT x 3 + 10 s) timeouts |

### Channel / MessageBase / Buffer

| Status | Feature | Notes |
| --- | --- | --- |
| IMPL | Channel envelopes, sequencing, receive window 48, adaptive send window, retries, proofs | `src/channel.c` |
| IMPL | Buffer streams (0xff00), EOF, bz2, bidirectional | `src/stream.c` |
| PART | `register_message_type` | Application owns the uint16 type registry |
| PART | Buffer API | Explicit read/write calls; no file-like wrapper or callbacks |

### Transport class

| Status | Feature | Notes |
| --- | --- | --- |
| PART | `has_path` / `hops_to` / `next_hop` | Via `rnc_node_lookup`; `request_path` exists |
| PART | `register_announce_handler` with aspect filter | Event-based; `rnc_announce_matches_aspect` provides the filter |
| MISS | `await_path`; `request_path` on_interface/recursive options | |
| IMPL | `blackhole_identity` / `unblackhole_identity` / `is_blackholed`, expiry, reference file format | Node API, daemon admin (`BLACKHOLE` / `UNBLACKHOLE` / `BLACKHOLES`), RPC get/set, persisted beside `--state`; verified with the reference `rnpath -B/-b/-U` |
| IMPL | Blackhole publishing (`rnstransport.info.blackhole`, `/list`, open to all) | Daemon `publish_blackhole`; verified with the reference `rnpath -p` |
| IMPL | Blackhole sources: `blackhole_sources`, `blackhole_update_interval` (minutes, default 60), first-run wait 20 s | Daemon `BlackholeUpdater` equivalent on `rnc_requester`; lists persist as `<state>.blackhole.<source hash>`; verified against a reference publisher |
| IMPL | `remote_management_enabled` | `rnstransport.remote.management` with `/status` and `/path` (table; rates is empty), identity allow list |
| IMPL | `discovered_interfaces`, `interface_discovery_sources` | Daemon keeps the reference's record files (`<state>.discovery`, or `discovery_storage`) and lists them with the admin `DISCOVERED` command; the reference's own `rnstatus -d` reads files written either way |

## 4. Interfaces (manual ch7, ch8)

Existing kinds: TCP listen, TCP connect, UDP, Auto, Serial, KISS, RNode. The host adapter is closed to new kinds (`host_add` rejects kind > `RNODE`).

| Interface | Status | Detail |
| --- | --- | --- |
| Auto | IMPL | IPv6 link-local multicast, `group_id`, discovery/data ports, 1.6s announce, 22s peer timeout, per-peer sub-interfaces |
| Auto | PART | `multicast_address_type` / scope (only temporary link scope) |
| Auto | MISS | `allowed_devices`, `ignored_devices`, multiple devices; multi-NIC; Android/Windows specifics; address-change handling |
| Backbone / BackboneClient | PART | Verified against the reference in both directions; daemon types map to TCP listen/connect (same HDLC wire format) with 100 Mb/s pacing and fast-flap IP blocking; no epoll data-plane egress/ingress watermarks, `device` binding or `prefer_ipv6` |
| TCP server | IMPL | Listen, accept, IPv4/IPv6, DNS |
| TCP server | IMPL | `prefer_ipv6`, TCP keepalive and user timeout on accepted sockets |
| TCP server | MISS | `i2p_tunneled`, device binding |
| TCP client | IMPL | Connect, auto-reconnect (1s fixed) |
| TCP client | IMPL | `reconnect_wait`, `max_reconnect_tries`, `connect_timeout`, `prefer_ipv6`, keepalive and user timeout |
| TCP client | PART | Address resolved once on add; reconnects reuse it |
| TCP client | IMPL | `kiss_framing` (`fixed_mtu` is the existing `mtu`) |
| TCP client | MISS | `i2p_tunneled` |
| UDP | PART | Single unicast target; receive-only mode |
| UDP | MISS | Broadcast, multiple targets |
| I2P | MISS | Entire type |
| RNode LoRa | IMPL | Radio setup over KISS, `radio_ready` ack, flow control, serial reopen |
| RNode LoRa | MISS | Detection and firmware check, BLE/TCP RNode, RSSI/SNR/battery stats |
| RNode Multi | MISS | Sub-interfaces (only `kiss_port` in the command byte) |
| Serial | IMPL | HDLC over termios, speed |
| Serial | IMPL | databits, parity, stopbits (daemon `databits` / `parity` / `stopbits`) |
| Serial | MISS | hardware flow control, port locking |
| Pipe | IMPL | `PipeInterface`: command on a socketpair, HDLC, respawn delay, 1 Mb/s pacing |
| KISS | IMPL | Framing, port nibble, `flow_control` |
| KISS | IMPL | preamble, txtail, persistence, slottime, ready flow control, `id_callsign` / `id_interval` beacon |
| AX.25 KISS | IMPL | `AX25KISSInterface`: UI frames (APZRNS to callsign-SSID), TNC preamble/txtail/persistence/slottime, flow control with 5s unlock |
| Discoverable interfaces (8.14) | IMPL | `discoverable`, `discovery_name`, `announce_interval`, `discovery_stamp_value`, `discovery_encrypt`, `reachable_on` (or an executable), `publish_ifac`, `latitude` / `longitude` / `height` or `location_cmd`, `discovery_lxmf_address`, `discovery_frequency` / `bandwidth` / `modulation`; announced for Backbone, TCP server, RNode, KISS and kiss-framed TCP client interfaces |
| Discoverable interfaces (8.14) | IMPL | Listening (`discover_interfaces`, `required_discovery_value`, `interface_discovery_sources`) and auto-connect of Backbone announcements (`autoconnect_discovered_interfaces`, `autoconnect_unverified_implementations`, `autoconnect_interface_mode`, `bootstrap_only`) |
| Discoverable interfaces (8.14) | MISS | I2P and Weave announcements (those interface types do not exist here); `autoconnect_interface_gravity` and `autoconnect_announces_to_internal` are accepted but have no effect |
| Custom interfaces (8.1) | PART | No plugin API, but hosts can call `rnc_node_add_interface` directly |

### Common options and policy (8.15-8.20)

| Status | Feature | Notes |
| --- | --- | --- |
| IMPL | `type`, `enabled` (daemon), `name`, `bitrate`, `mtu`, IFAC (`networkname`, `passphrase`, `ifac_size`) | |
| PART | `outgoing`, `bootstrap_only`, `ifac_netname` / `ifac_netkey` aliases | `outgoing = No` (receive only, inherited by accepted connections) and `bootstrap_only` are implemented; the `ifac_netname` / `ifac_netkey` aliases are not (the reference reads `network_name`/`networkname` and `passphrase`/`pass_phrase`, which the daemon accepts) |
| IMPL | Interface modes: full, gateway, access_point, roaming, boundary | `rnc_node_interface_policy`; announce propagation rules follow the reference behavior as recalled, (the manual's table is an image, so the reference source was used). Rules verified against the pinned reference `Transport.py`. Gateway/AP/roaming interfaces now search for unknown paths on behalf of clients. Config keys `mode`/`interface_mode` in the daemon |
| IMPL | Announce rate control: `announce_cap` | Per-interface via policy and daemon `announce_cap` (percent); default 2% |
| IMPL | `announce_rate_target` / `grace` / `penalty` | Per-interface policy and daemon keys; blocks rebroadcast only, paths still learned; bounded 128-entry table |
| IMPL | New destination rate limiting (8.18) and ingress control (8.20) | Frequency-tracked burst detection, held announces released one per interval, pending-request and known-destination exemptions. Held announces share a 32-entry node table (reference default is 256 per interface). Released announces bypass the burst gate instead of re-entering it. Config keys `ingress_control`, `ic_*` in the daemon |
| IMPL | Path request burst control (8.19) and egress control | Per-interface request frequency; recursive requests suppressed during bursts and on interfaces over `ec_pr_freq` |
| IMPL | Recursive path-request search by mode | Only gateway, access point, roaming and local interfaces (or `recursive_prs`) search; boundary searches boundary and gateway peers; plain FULL no longer recurses, matching the reference. This changed the default for transport nodes |
| PART | Ingress control (8.20) | Bounded queues (node queue, 32 frames per host interface, 8 node / 24 host interface slots) are capacity limits only |


## 5. Config and utilities (manual ch5)

### `[reticulum]` section (parsed in `examples/node_daemon.c`)

| Status | Option | Notes |
| --- | --- | --- |
| IMPL | `enable_transport`, `share_instance`, `shared_instance_type` / `shared_instance_port`, `instance_control_port`, `rpc_key` | |
| IMPL | `loglevel` (`[logging]`), `logdestination` (stdout, stderr or a file that rolls over at 5 MiB), `logfile` | Library hook `rnc_log.h`; the daemon formats `[time] [Level] module: message` |
| PART | `instance_name` | Accepted; the shared instance is TCP only, so it names nothing |
| IMPL | `respond_to_probes` | Daemon registers `rnstransport.probe` with PROVE_ALL, takes no links; reported as `probe_responder` in interface stats |
| PART | `panic_on_interface_error`, `use_implicit_proof`, `link_mtu_discovery` | `panic_on_interface_error` and `use_implicit_proof` implemented; `link_mtu_discovery` is not (links stay at 500 bytes) |
| IMPL | `enable_remote_management`, `remote_management_allowed` | Daemon config, up to 8 identity hashes |
| IMPL | `publish_blackhole`, `blackhole_sources`, `blackhole_update_interval` | |
| IMPL | `network_identity` | |
| IMPL | `discover_interfaces` and related | |
| MISS | `~/.reticulum` config/storage layout | Daemon uses `--identity` and `--state` |

### Utilities (lower priority for an SDK)

| Status | Tool | Notes |
| --- | --- | --- |
| PART | `rnsd` | `examples/node_daemon.c`: config, `--check`, SIGHUP reload, checkpoints, shared instance, RPC |
| PART | `rnstatus`, `rnpath` | `reticulum-c-ctl status` and `path` (examples/reticulum_ctl.c): interface statistics, path table, hop filter, blackhole list/add/remove, JSON output, over the authenticated RPC port. Not implemented: remote (`-R`) queries, path request / drop (`-d`, `-D`, `-x`), rate and link tables, sorting, filtering by name |
| IMPL | `rnprobe` target | Reference `rnprobe` gets valid replies from the daemon; the SDK has no `rnprobe` client tool of its own |
| PART | `rnid` | `reticulum-c-ctl id`: generate, print, export hex, aspect hashes, raw sign/validate (`--raw`), chunked file encrypt/decrypt; interoperates with the reference. Not implemented: the signed-envelope `.rsg` format, embedded messages and metadata, base32/64/256 formats, import, announce, network identity requests |
| PART | `rncp` | `reticulum-c-cp` (examples/reticulum_cp.c) over the new `rnc_transfer` library: listen (`-l`, `-a`, `-n`, `-s`, `-O`, `-F`, `-j`, `-b`), push and fetch (`-f`), compatible with the reference in all four directions. Not implemented: identity allow-list files, `-p`, `-P`, `-C`, `-S`, files over 16 MiB (held in memory), the reference's `--config` (it attaches over `--connect HOST:PORT`) |
| PART | `rnx` | `reticulum-c-x` (examples/reticulum_x.c): listener with an allow list and client (`-w`, `-m`, `-d`, `-N`, `--stdin`, `--stdout`, `--stderr`), compatible with the reference in both directions. Not implemented: accept-anyone (`-n`, deliberately), interactive mode (`-x`), `-W`, `-p`, allowed-identity files, `--config`; a command is stopped after 25 s and requests/responses are limited to about 64 kB |
| PART | `rnsh` | `reticulum-c-sh` (examples/reticulum_sh.c): listener (allow list, `-C`, `-A`, default program) and initiator (`-m`, `-N`, `-w`, terminal raw mode, window size, `~.`) speaking protocol 1, compatible with the reference rnsh in both directions. Not implemented: accept-anyone (`-n`, deliberately), line-interactive mode, allowed-identities file, `-p`, `-s`, compression of sent stream data, terminal attribute application on the pty |
| MISS | `rnodeconf` | |
| IMPL | Remote management, blackhole publishing and subscribing, interface discovery | |

## 6. Examples (manual ch13)

| Status | Example | Notes |
| --- | --- | --- |
| IMPL | Announce (incl. ratcheted, path request), Broadcast/PLAIN, GROUP, Link, Identification (allow-list), Requests/Responses, Channel, Buffer, Filetransfer | |
| PART | Echo | Encrypt/decrypt, proofs and receipts with RTT done; no hops helper beyond `rnc_node_lookup` |
| PART | Callback-style APIs | Provided as events instead (service, resource, link) |

The repository contains only `examples/text_peer.c` and `examples/node_daemon.c`. No example exists for announce, broadcast, echo, link, identification, request, channel, buffer or filetransfer (tests cover them).

## 7. Suggested ordering

**Phase A: library protocol parity**

1. Endpoint DATA proofs and `PacketReceipt`, proof strategy, probe responder.
2. Announce propagation per 6.7.4 and per-destination rate limiting.
3. Interface modes with mode-dependent path expiry and announce filtering.
4. Configurable `announce_cap`, new-destination limit, path-request burst control, ingress control.
5. Known-destination store (recall), announce aspect filter, link statistics and lifecycle (RTT keepalive, STALE, reason enum, RTT accessor).

**Phase B: host interfaces**

1. RNode detection and firmware check (bitrate, airtime limits, beacon done).
2. Backbone, TCP hardening, KISS TNC parameters, serial parameters, UDP broadcast.
3. Pipe, AX.25 KISS, RNode Multi, I2P; Auto allow/ignore lists.

**Phase C: management plane**

1. Blackhole table with filtering, then publish/subscribe.
2. Remote management destination and ACL; mutating admin calls.
3. (done)

**Phase D:** examples, CLI tools.
