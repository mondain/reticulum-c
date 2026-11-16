# Reticulum manual vs reticulum-c: spec gap list

- **Date:** original audit 2026-10-26; implementation status reconciled with current headers and source on 2026-11-14.
- **Baseline:** the supplied Reticulum Manual, reviewed as text extracted with `pdftotext`. The manual and external reference snapshots are identified in [PROVENANCE.md](../PROVENANCE.md); the manual is not bundled in this repository. This is a historical manual comparison, not a fresh review against a newer protocol specification.
- **Method:** the original three read-only audits followed manual sections and inspected headers and source. They ran no builds or tests and did not read all of `host_posix.c`, `ipc.c`, `service.c`, `channel.c`, `ratchet.c` or `ifac.c` in full. The 2026-11-14 reconciliation also ran no tests; it corrects stale summaries, API mappings and defaults using current source. Later verification observations retained below apply only to the named scenarios. Items marked *(unverified)* rest on header/grep evidence only.

**Legend:** IMPL = implemented, PART = partial, MISS = missing, N/A = not applicable to an SDK or by design. IMPL records implementation coverage, not full protocol conformance or hardware certification. See [COMPATIBILITY.md](../COMPATIBILITY.md) for validation scope.

> **Note on config parsing:** a Reticulum-style config parser exists in `examples/node_daemon.c` (not in the library). It accepts `[reticulum]` and `[interfaces]` sections and the keys listed in [section 5](#5-config-and-utilities-manual-ch5). An early interface-audit report claiming there was no config layer was wrong.

## 1. Summary

The implementation covers identities, SINGLE/GROUP/PLAIN destinations, announces (including ratcheted), path request/response, HEADER_1/2, IFAC, links, MTU negotiation, Channel, Buffer, Resources (bz2, metadata, segments), request/response, transport forwarding and link tables. Endpoint proofs/receipts, interface policy, announce retries, known-destination persistence and link lifecycle APIs are implemented; they are no longer open work items.

Concrete remaining gaps include:

1. Announce propagation: done (2026-11-15). A pending path response is cancelled by neighbour rebroadcasts as the reference does; no known open item remains here.
2. Host interface options: Auto on several network devices at once (it uses one), address-change handling, and the I2P/RNode Multi/Weave options listed in section 4. Done on 2026-11-15: Auto device lists, scope and address type, `device` on TCP servers and UDP, `i2p_tunneled`. UDP multiple targets, serial hardware flow control and serial port locking are not in the pinned reference (it has one forward address and opens serial ports with `rtscts` off and no locking), so they are not gaps.
3. Management and discovery details: done (2026-11-15): gravity, `autoconnect_announces_to_internal`, I2P/Weave discovery announcements and the remote-management `rates` query.
4. API differences: no resend convenience method or per-link physical-signal tracking; event APIs replace Python callbacks. Bounded tables and queues differ from the reference's capacities.
5. CLI feature subsets and stand-alone protocol examples (sections 5 and 6). The C `rnodeconf` tool does not flash firmware; `reticulum-c-flash` writes this project's ESP32-family firmware through the ROM loader (see the `rnodeconf` row), and the browser flasher under `web/` also targets this project's MCU firmware.

Host RNode/RNode Multi adapters remain unverified against real stock RNode hardware. Separately, this project's native MCU LoRa firmware has a short 2026-11-14 bench exchange on a T-Echo leaf and T-Beam Supreme SX1262 gateway at 915 MHz: three-hop host access, a 10-byte `/echo` reply and a 116-byte `/info` response, with one request retry. This does not establish stock-RNode interoperability, range or sustained-load reliability; see [mcu/radio/README.txt](../mcu/radio/README.txt).

The native MCU firmware (PlatformIO boards, see [mcu/README.txt](../mcu/README.txt)) also has three features that are not reference-Reticulum features and so have no row in the tables below:

- **RNode mode** (`set mode rnode`): the board speaks the stock RNode KISS protocol over USB, so this project's host RNode adapter, and in principle other RNode clients, can drive its radio. Nothing is transmitted until the host has set all five radio settings; a LEAVE, RESET or board reset turns the radio off; a 1 percent per hour airtime budget stays active. Verified on 2026-11-14 with a T-Echo driven by this project's host adapter against a T-Beam Supreme (announce delivered, `radio_ready`). Not included: stock RNode EEPROM provisioning, signing and firmware-update flows (so `rnodeconf` cannot flash or provision this firmware), battery and temperature reports. The generic ESP-IDF image ignores the mode.
- **Bluetooth LE** (all PlatformIO boards): the same KISS stream over the Nordic UART service, off until a six digit PIN is set (`set ble.pin`), no access without pairing. Verified on 2026-11-15 with Sideband on an Android phone and a T-Echo (connected, frequency shown, packet counts rising, RSSI -46 dBm and SNR 12.5 dB on the far board). Not tested on hardware: the ESP32 and ESP32-S3 NimBLE builds, other phones and computers.
- **Status screens** (LilyGo T-Echo e-paper, T-Beam Supreme OLED): a read-only status page with a PIN row only while pairing is needed. Layout, PIN rule and refresh policy are unit tested; both screens were seen on hardware on 2026-11-15. Not checked on hardware: the no-PIN case, the 5 minute full refresh and the Supreme PIN rows.

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
| IMPL | Announce bandwidth cap, lowest-hops-first | Configurable per interface through `rnc_interface_policy` and daemon `announce_cap`; default 2% |
| IMPL | Path request/response (context 11), tag dedup, 15s pending table | |
| IMPL | Link request forwarding, link table, reverse-path validation, MTU clamp | |
| IMPL | IFAC (derive, apply, verify, tag size 1-64) | `src/ifac.c` |
| IMPL | Wire format, MTU 500..4096 with 3B signalling | |
| IMPL | Crypto primitives | OpenSSL backend (`src/crypto.c`); optional portable backend (`src/crypto_portable.c`, vendored Monocypher), documented in [PROVENANCE.md](../PROVENANCE.md) |
| IMPL | Ratchets: generate, rotate, export/import, encrypt/decrypt, 30-day peer expiry | `src/ratchet.c` |
| PART | Announce propagation (6.7.4) | One retry after 5.5s (PATHFINDER_R/G/RW), cancelled after 2 heard neighbour rebroadcasts or when passed on a further hop; single transmission for shared-instance clients; locally originated announces blocked on AP interfaces. Verified against reference `Transport.py` at the pinned commit. An announce is accepted up to 128 hops (127 on the wire) and a 128 hop path is learned but never passed on, as the reference's `_outbound` refuses above 127. `MODE_INTERNAL` with `announces_from_internal` and `announces_to_internal` follows the reference's broadcast rules; an INTERNAL interface sends outside the announce cap. A path response from a known path waits `PATH_REQUEST_GRACE` (0.4 s), 1.5 s more on a roaming interface, and goes at once to a local client; a roaming interface is not answered when the path lies behind it. The reference's announce-table hold-down has no counterpart because path responses and rebroadcasts are separate queue entries here, so neither replaces the other. A pending path response is dropped when two neighbours are heard passing the announce on, or one passes it on a further hop, while it waits (the reference's announce-table rules). The checks above ran against unit tests and a reading of `Transport.py`, not a live reference node |
| IMPL | Path expiry | 7 days; AP 1 day, Roaming 6 hours by ingress interface mode |
| IMPL | Delivery proofs | Endpoint proof creation (implicit 64B / explicit 96B) via `rnc_node_prove` and PROVE_ALL; validation by signer in `rnc_node_send_tracked` receipts |
| IMPL | Packet prioritisation | The reference prioritises announces with fewer hops (the announce queue here does the same) and scans interfaces fastest first; nothing else is prioritised there either |
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
| PART | Shared instance and RPC server (HMAC, MessagePack queries and blackhole mutations) | Daemon responses include interface/path statistics, link counts and blackhole entries (`examples/node_rpc.h`); `rate_table` returns the node's announce rate entries (hash, last, rate_violations, blocked_until, timestamps; filled when the node has another interface to pass announces on). Shared-instance data transport is TCP only |
| PART | `get_instance`, `transport_enabled`, `link_mtu_discovery`, `should_use_implicit_proof` accessors | `rnc_node_implicit_proofs` / `rnc_node_set_implicit_proofs` cover `should_use_implicit_proof`; `rnc_node_link_mtu_discovery` covers `link_mtu_discovery`; `get_instance` and `transport_enabled` are Python-instance accessors |

### Identity

| Status | Feature | Notes |
| --- | --- | --- |
| IMPL | create, from_bytes, load/get keys, sign, validate, encrypt, decrypt | |
| IMPL | `from_file` (64B raw, mode 0600, strict checks) | |
| IMPL | `to_file` / `pub_to_file`; `truncated_hash` / `get_random_hash` helpers | `rnc_host_identity_save` (private 0600 or public, atomic, no overwrite unless asked), `rnc_truncated_hash`, `rnc_random_hash` |
| IMPL | `recall`, `recall_app_data` | `rnc_node_recall`: bounded 256-entry store independent of path lifetime, with sealed export/import for host persistence. Ratchet is returned in the recalled announce |

### Destination

| Status | Feature | Notes |
| --- | --- | --- |
| IMPL | `expand_name`, `hash_from_name_and_identity`, announce, path response, request handlers (ALLOW_NONE/ALL/LIST/identified), GROUP keys | |
| IMPL | `accepts_links` toggle, `set_max_request_size`, `set/clear_default_app_data` | `rnc_node_set_accepts_links`, `rnc_responder_set_max_request_size` / `rnc_service_set_max_request_size` (inline requests and Resource-delivered ones), `rnc_node_set_destination_data` (NULL, 0 clears) |
| IMPL | `enable_ratchets` persistence | `rnc_ratchets_export_reference` / `rnc_ratchets_import_reference` read and write the reference's ratchet file (signed MessagePack list of private keys); the host owns the file itself. Verified against the reference in both directions |
| IMPL | `proof_strategy`, `set_proof_requested_callback` | `rnc_node_set_proof_strategy` (NONE, APP, ALL); with APP the packet arrives as a LOCAL event and the application answers with `rnc_node_prove`, which is the callback's decision |

### Packet / PacketReceipt

| Status | Feature | Notes |
| --- | --- | --- |
| IMPL | Send via `rnc_node_send`, `rnc_link_send_packet(_hashed)` | Explicit C send functions in `rnc_node.h` and `rnc_link.h` |
| IMPL | `PacketReceipt` status, rtt, timeout | `rnc_node_send_tracked` (DELIVERED/FAILED event with rtt), `rnc_node_receipt_status` (SENT/DELIVERED/FAILED, culled = RNC_STATE), `rnc_node_receipt_timeout` and timeout 0 for the reference default (6 s per hop plus first-hop 6 s + MTU at the interface rate). Callbacks are events |
| MISS | `resend` convenience method | Resend by building and tracking a new packet |
| PART | Packet `get_rssi/get_snr/get_q` | RNode signal figures are carried by `rnc_host_event` (`has_signal`, `rssi`, `snr`, `quality`), rather than stored on `rnc_packet`; other host kinds do not supply these figures |

### Link

| Status | Feature | Notes |
| --- | --- | --- |
| IMPL | Request/proof, LRRTT, LINKIDENTIFY, LINKCLOSE, keepalive, MTU, remote identity, request/response (contexts 9/10), teardown | `src/link.c` |
| IMPL | Keepalive and timeouts | RTT-scaled keepalive (5..360 s), STALE after 2x keepalive, teardown after RTT*4+5 s, configurable establishment timeout (first hop + 6 s per hop); previously fixed 30 s / 180 s. The default establishment timeout without configuration remains 30 s |
| IMPL | Teardown reason | `rnc_link_teardown_reason`: timeout, initiator closed, destination closed |
| IMPL | RTT | `rnc_link_rtt` |
| N/A | ResourceStrategy | By design the application admits each Resource with `rnc_resource_accept` (the ACCEPT_NONE / APP / ALL choice is the application's own policy before it calls it) |
| IMPL | `get_age`, `no_inbound_for`, `no_outbound_for`, `no_data_for`, `get_mode`, `get_establishment_rate`, `get_expected_rate` | `rnc_link_age_ms`, `rnc_link_no_inbound_ms`, `rnc_link_no_outbound_ms`, `rnc_link_no_data_ms`, `rnc_link_mode`, `rnc_link_establishment_rate`, `rnc_link_last_resource_eifr` |
| PART | `track_phy_stats`, rssi/snr/q | The host now collects RSSI, SNR and quality from RNodes and attaches them to each received packet's host event; per-link tracking (`link.get_rssi()`) is not provided |
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
| N/A | `register_message_type` | The application owns the uint16 type registry and dispatches on `message_type` itself |
| N/A | Buffer API wrappers | Explicit read/write calls instead of Python's file-like objects and callbacks |

### Transport class

| Status | Feature | Notes |
| --- | --- | --- |
| IMPL | `has_path` / `hops_to` / `next_hop` | `rnc_node_lookup`, `rnc_node_hops_to` (128 when unknown) |
| IMPL | Announce events with aspect filter | `RNC_NODE_ANNOUNCE` events and `rnc_announce_matches_aspect`; Python callback registration is replaced by event dispatch |
| IMPL | `await_path`; `request_path` on_interface/tag/recursive options | `rnc_host_await_path` (runs the host, asks again every 5 s, optional event callback and interrupt), `rnc_node_request_path_ex` |
| IMPL | `blackhole_identity` / `unblackhole_identity` / `is_blackholed`, expiry, reference file format | Node API, daemon admin (`BLACKHOLE` / `UNBLACKHOLE` / `BLACKHOLES`), RPC get/set, persisted beside `--state`; verified with the reference `rnpath -B/-b/-U` |
| IMPL | Blackhole publishing (`rnstransport.info.blackhole`, `/list`, open to all) | Daemon `publish_blackhole`; verified with the reference `rnpath -p` |
| IMPL | Blackhole sources: `blackhole_sources`, `blackhole_update_interval` (minutes, default 60), first-run wait 20 s | Daemon `BlackholeUpdater` equivalent on `rnc_requester`; lists persist as `<state>.blackhole.<source hash>`; verified against a reference publisher |
| IMPL | `remote_management_enabled` | `rnstransport.remote.management` with `/status` and `/path` (table and rates, each optionally for one destination), identity allow list |
| IMPL | `discovered_interfaces`, `interface_discovery_sources` | Daemon keeps the reference's record files (`<state>.discovery`, or `discovery_storage`) and lists them with the admin `DISCOVERED` command; the reference's own `rnstatus -d` reads files written either way |

## 4. Interfaces (manual ch7, ch8)

Host kinds in `rnc_host_kind`: TCP listen/connect, UDP, Auto, Serial, KISS, RNode, Pipe, AX.25 KISS, I2P, RNode Multi and Weave. Backbone/BackboneClient map to TCP listen/connect in the daemon. `rnc_host_add` accepts the enum through `RNC_HOST_WEAVE`; there is no dynamic plugin API.

| Interface | Status | Detail |
| --- | --- | --- |
| Auto | IMPL | IPv6 link-local multicast, `group_id`, discovery/data ports, 1.6s announce, 22s peer timeout, per-peer sub-interfaces |
| Auto | IMPL | `devices` and `ignored_devices` (comma lists; `lo0` always skipped), `discovery_scope` (link, admin, site, organisation, global; an unknown value is refused, where the reference would fail later) and `multicast_address_type` (permanent or temporary) |
| Auto | MISS | Using several devices at once (the first suitable device is used); Android/Windows specifics; address-change handling |
| Backbone / BackboneClient | PART | Verified against the reference in both directions; daemon types map to TCP listen/connect (same HDLC wire format) with 100 Mb/s pacing and fast-flap IP blocking; no epoll data-plane egress/ingress watermarks or `device` binding; the common TCP `prefer_ipv6` option is accepted |
| TCP server | IMPL | Listen, accept, IPv4/IPv6, DNS |
| TCP server | IMPL | `prefer_ipv6`, TCP keepalive and user timeout on accepted sockets |
| TCP server | IMPL | `device` (the device's IPv4 address, or IPv6 with `prefer_ipv6`, wins over a given address, as in the reference) and `i2p_tunneled` (I2P dead-peer timings; accepted connections inherit it) |
| TCP client | IMPL | Connect, auto-reconnect (default 5 s wait, configurable) |
| TCP client | IMPL | `reconnect_wait`, `max_reconnect_tries`, `connect_timeout`, `prefer_ipv6`, keepalive and user timeout |
| TCP client | PART | Address resolved once on add; reconnects reuse it |
| TCP client | IMPL | `kiss_framing` (`fixed_mtu` is the existing `mtu`) |
| TCP client | IMPL | `i2p_tunneled` |
| UDP | IMPL | Single target (unicast or IPv4 broadcast); receive-only mode. Datagram sockets enable `SO_BROADCAST` in `src/host_posix.c`; this source reconciliation did not exercise broadcast delivery |
| UDP | IMPL | `device`: the device's broadcast address stands in for whichever of listen and forward is not given. Multiple targets are not a reference feature (it has one `forward_ip`) |
| I2P | IMPL | `I2PInterface` through a router's SAM v3 bridge: session and key file (named as the reference names them), `peers` (b32 names, bare b32, full destinations), `connectable`, 15 s reconnect, keepalive and read watchdog, 1064 byte MTU. Verified against the unmodified reference in both directions through a fake SAM router; not tested against a real I2P router |
| I2P | MISS | SAM address from the environment (`target_host`/`target_port` set it instead), stale-tunnel state |
| RNode LoRa | IMPL | Radio setup over KISS, `radio_ready` ack, flow control, serial reopen |
| RNode LoRa | IMPL | Detection (DETECT, firmware version, platform and MCU asked first; the radio is configured when the device answers, and the interface drops after 5 s of silence) and the firmware check (at least 1.52, otherwise the interface is refused and not retried) |
| RNode LoRa | IMPL | RSSI (dBm), SNR (dB) and link quality (percent from SNR and spreading factor) of the last frame: `rnc_host_status`, on each host event for a received packet, and the RPC interface stats (`rssi`, `snr`, `q`, shown by `reticulum-c-ctl status`) |
| RNode LoRa | MISS | The host adapter reaching an RNode over BLE (the firmware serves BLE, see above), battery, temperature and channel statistics |
| RNode LoRa | IMPL | WiFi RNode over TCP: `port = tcp://host` (port 7633, or `rnc_host_config.port`); the same KISS protocol, detection and radio setup once the socket opens, a detection ping after 3.5 s of silence, reconnect after a drop |
| RNode Multi | IMPL | `RNodeMultiInterface`: one serial device, radios found by the device itself (`CMD_INTERFACES`) and selected with `CMD_SEL_INT` before each command and frame, `[[[radio]]]` sections (`vport`, frequency, bandwidth, txpower, spreadingfactor, codingrate, flow_control, airtime limits, outgoing, interface_enabled), per radio RSSI/SNR/quality, firmware 1.74 or newer, 5 s reconnect. Command streams match the unmodified reference against the same emulated device; not tested on real hardware |
| RNode Multi | MISS | The shared station-ID timer (each radio keeps its own), display/framebuffer, TCP/BLE transport |
| RNode Multi | N/A | IFAC on individual radios is not supported; the pinned reference also gives these radios no IFAC |
| Weave | IMPL | `WeaveInterface`: a Weave switch on a serial line (3 Mbaud, HDLC, WDCL framing): discovery broadcast, Ed25519 signed handshake with a per-run switch identity, every endpoint the switch reports (alive events and packets) is a peer interface (MTU 1024, 250 kb/s or `configured_bitrate`), 20 s peer timeout, packets seen from two endpoints within 0.75 s delivered once, 2 s handshake deadline and 5 s reconnect. The unmodified reference's `WeaveInterface` and this host complete the handshake with, and exchange packets through, the same emulated switch; not tested on real hardware |
| Weave | MISS | Remote display, device log/statistics rendering, `ET_PROTO_WEAVE_EP_VIA` routing hints (parsed and ignored), USB switch discovery (`weaveconf`), Weave announcements |
| Serial | IMPL | HDLC over termios, speed |
| Serial | IMPL | databits, parity, stopbits (daemon `databits` / `parity` / `stopbits`) |
| Serial | N/A | Hardware flow control and port locking: the pinned reference opens serial ports with `rtscts`, `xonxoff` and `dsrdtr` off and takes no lock |
| Pipe | IMPL | `PipeInterface`: command on a socketpair, HDLC, respawn delay, 1 Mb/s pacing |
| KISS | IMPL | Framing, port nibble, `flow_control` |
| KISS | IMPL | preamble, txtail, persistence, slottime, ready flow control, `id_callsign` / `id_interval` beacon |
| AX.25 KISS | IMPL | `AX25KISSInterface`: UI frames (APZRNS to callsign-SSID), TNC preamble/txtail/persistence/slottime, flow control with 5s unlock |
| Discoverable interfaces (8.14) | IMPL | `discoverable`, `discovery_name`, `announce_interval`, `discovery_stamp_value`, `discovery_encrypt`, `reachable_on` (or an executable), `publish_ifac`, `latitude` / `longitude` / `height` or `location_cmd`, `discovery_lxmf_address`, `discovery_frequency` / `bandwidth` / `modulation`; announced for Backbone, TCP server, RNode, KISS and kiss-framed TCP client interfaces |
| Discoverable interfaces (8.14) | IMPL | Listening (`discover_interfaces`, `required_discovery_value`, `interface_discovery_sources`) and auto-connect of Backbone announcements (`autoconnect_discovered_interfaces`, `autoconnect_unverified_implementations`, `autoconnect_interface_mode`, `bootstrap_only`) |
| Discoverable interfaces (8.14) | IMPL | I2P announcements (type `I2PInterface`, `reachable_on` the b32 address when `connectable` and the router has given one) and Weave announcements (frequency, bandwidth and integer modulation from `discovery_*`; the channel is nil, as the reference never sets it). `gravity` and `default_gravity` per interface: the same announce heard later on an interface of higher gravity, with no more hops, takes the path over, and the management stats report it. `autoconnect_interface_gravity` and `autoconnect_announces_to_internal` apply to auto-connected interfaces. Not covered: the takeover does not pass the announce on again, and no check ran against a live reference node |
| Custom interfaces (8.1) | PART | No plugin API, but hosts can call `rnc_node_add_interface` directly |

### Common options and policy (8.15-8.20)

| Status | Feature | Notes |
| --- | --- | --- |
| IMPL | `type`, `enabled` (daemon), `name`, `bitrate`, `mtu`, IFAC (`networkname`, `passphrase`, `ifac_size`) | |
| IMPL | `outgoing`, `bootstrap_only`, reference IFAC key aliases | `outgoing = No` is receive only and inherited by accepted connections; `bootstrap_only` is implemented. The daemon accepts `network_name`/`networkname` and `passphrase`/`pass_phrase`. The earlier audit listed `ifac_netname` / `ifac_netkey`, but those are not the pinned reference's config key spellings |
| IMPL | Interface modes: full, gateway, access_point, roaming, boundary | `rnc_node_interface_policy`; the original audit used the pinned reference `Transport.py` because the manual's table is an image. The listed mode rules were compared with that source. Gateway/AP/roaming interfaces now search for unknown paths on behalf of clients. Config keys `mode`/`interface_mode` in the daemon |
| IMPL | Announce rate control: `announce_cap` | Per-interface via policy and daemon `announce_cap` (percent); default 2% |
| IMPL | `announce_rate_target` / `grace` / `penalty` | Per-interface policy and daemon keys; blocks rebroadcast only, paths still learned; bounded 128-entry table |
| IMPL | New destination rate limiting (8.18) and ingress control (8.20) | Frequency-tracked burst detection, held announces released one per interval, pending-request and known-destination exemptions. Held announces share a 32-entry node table (reference default is 256 per interface). Released announces bypass the burst gate instead of re-entering it. Config keys `ingress_control`, `ic_*` in the daemon |
| IMPL | Path request burst control (8.19) and egress control | Per-interface request frequency; recursive requests suppressed during bursts and on interfaces over `ec_pr_freq` |
| IMPL | Recursive path-request search by mode | Only gateway, access point, roaming and local interfaces (or `recursive_prs`) search; boundary searches boundary and gateway peers; plain FULL no longer recurses, matching the reference. This changed the default for transport nodes |
| PART | Queue backpressure and watermarks | The rate-based ingress controls are implemented above. Bounded queues (node queue, 32 frames per host interface, default 8 node / 24 host interface slots) impose capacity limits; they do not provide Backbone epoll watermarks |


## 5. Config and utilities (manual ch5)

### `[reticulum]` section (parsed in `examples/node_daemon.c`)

| Status | Option | Notes |
| --- | --- | --- |
| IMPL | `enable_transport`, `share_instance`, `shared_instance_type` / `shared_instance_port`, `instance_control_port`, `rpc_key` | |
| IMPL | `loglevel` (`[logging]`), `logdestination` (stdout, stderr or a file that rolls over at 5 MiB), `logfile` | Library hook `rnc_log.h`; the daemon formats `[time] [Level] module: message` |
| PART | `instance_name` | Accepted; the shared instance is TCP only, so it names nothing |
| IMPL | `respond_to_probes` | Daemon registers `rnstransport.probe` with PROVE_ALL, takes no links; reported as `probe_responder` in interface stats |
| IMPL | `panic_on_interface_error`, `use_implicit_proof`, `link_mtu_discovery` | all three implemented |
| IMPL | `enable_remote_management`, `remote_management_allowed` | Daemon config, up to 8 identity hashes |
| IMPL | `publish_blackhole`, `blackhole_sources`, `blackhole_update_interval` | |
| IMPL | `network_identity` | |
| IMPL | `discover_interfaces` and related | |
| MISS | `~/.reticulum` config/storage layout | Daemon uses `--identity` and `--state` |

### Utilities (lower priority for an SDK)

| Status | Tool | Notes |
| --- | --- | --- |
| PART | `rnsd` | `examples/node_daemon.c`: config, `--check`, SIGHUP reload, checkpoints, shared instance, RPC |
| PART | `rnstatus`, `rnpath` | `reticulum-c-ctl status` and `path` (examples/reticulum_ctl.c): interface statistics with a name filter and `-s`/`-r` sorting (rate, bitrate, traffic, rx, tx, arxc, atxc, gravity; largest first as the reference sorts), path table, hop filter, `-r` announce rates, `-d` drop a path, `-x` drop everything via a next hop, `-D` drop the queued announces (the reference's `drop` RPC calls, served by the daemon), blackhole list/add/remove, JSON output, over the authenticated RPC port. Remote queries: `-R IDENTITY_HASH --attach HOST:PORT --mgmt-identity FILE [-w SECONDS]` asks another instance's `rnstransport.remote.management` for `status`, `path -t` and `path -r` (the tool brings up its own node through the given TCP interface; the reference's `-i` is `--mgmt-identity` here because `--identity` is the local daemon's). Checked against this project's daemon; the daemon's side was already checked against the reference's own `rnstatus -R` and `rnpath -R`. Not implemented: path requests, the link table, the other sort keys, discovery listing, monitor mode. `-D` also discards announces waiting out their rebroadcast delay, where the reference empties only the interface queues |
| IMPL | `rnprobe` target | Reference `rnprobe` gets valid replies from the daemon; the SDK has no `rnprobe` client tool of its own |
| PART | `rnid` | `reticulum-c-ctl id`: generate, print, export (hex, base32 `-B` or URL-safe base64 `-b`), import a private or public identity from a file, hex, base32 or base64 (`-M`, `-m`), aspect hashes, sign/validate in the reference's signed-envelope `.rsg` form (the default: the file's SHA-256 and the signer's public key under an Ed25519 signature, so `-V` works without `-i`, and `-i` then names who must have signed) and the bare `--raw` form, chunked file encrypt/decrypt; interoperates with the reference. Envelopes made here validate under the reference's `rnid -V` and the reference's validate here, checked by the interop test against the pinned checkout. The encodings are checked against Python's `base64` for a fixed key. Not implemented: embedded signed messages (`-S`) and metadata, armored text output of signatures, base256, announce, network identity requests
| PART | `rncp` | `reticulum-c-cp` (examples/reticulum_cp.c) over the new `rnc_transfer` library: listen (`-l`, `-a`, `-n`, `-s`, `-O`, `-F`, `-j`, `-b`), push and fetch (`-f`), compatible with the reference in all four directions. Also `-p` (identity and destination, without connecting), the allowed-identities file (`/etc/rncp`, `~/.config/rncp` or `~/.rncp`, first found; lines of other lengths ignored), `-S` (no progress output) and `-C` (send uncompressed, for pushes and fetch answers). Not implemented: `-P` (physical layer rates), files over 16 MiB (held in memory), the reference's `--config` (it attaches over `--connect HOST:PORT`) |
| PART | `rnx` | `reticulum-c-x` (examples/reticulum_x.c): listener with an allow list and client (`-w`, `-W`, `-m`, `-d`, `-N`, `--stdin`, `--stdout`, `--stderr`), compatible with the reference in both directions. Also `-p` and the allowed-identities file (`/etc/rnx`, `~/.config/rnx` or `~/.rnx`). Also `-x` interactive mode: a prompt that shows the last non-zero remote exit code, one command per line, `exit`, `quit`, `clear` and end of input as in the reference. Not implemented: accept-anyone (`-n`, deliberately), the reference's `--config`; a command is stopped after 25 s and requests/responses are limited to about 64 kB |
| PART | `rnodeconf` | `reticulum-c-rnodeconf` (examples/reticulum_rnodeconf.c): `-i` device information (product, signature against the vendor keys and `--trust-key`, firmware, modem, TNC settings), `-c` stored configuration, TNC and normal mode with radio parameters, Bluetooth, display, NeoPixel, interference avoidance and WiFi settings, read back by and compared with the reference against an emulated RNode. Not implemented: firmware download, update and extraction, autoinstall, EEPROM provisioning, backup, dump and wipe, signing keys, hash commands, the trusted-keys directory. Flashing is a separate tool, `reticulum-c-flash` (examples/reticulum_flash.c): it writes images to an ESP32-family board through the chip's ROM serial loader (reset into download mode, SLIP framed commands, SPI attach, 1 KiB blocks, MD5 check by the loader, reset), with `--verify-only` and `--reset-only`. It is tested against an emulated loader on a pty and was run on a LilyGo T-Beam Supreme (ESP32-S3, native USB) on 2026-11-15: this project's firmware was written (bootloader, partition table, boot_app0 and application, leaving NVS alone) and the chip's own MD5 matched for every region, again on a second pass with `--verify-only`; the chip then left the loader and booted the new image: the board's OLED showed the status page with the new version. From the serial side the board stayed silent (no console, HDLC or RNode answer), so the reset-then-console path was not exercised. It does not flash stock RNode firmware, nRF52 boards or the other RNode hardware. The separate browser flasher (`web/src/flash.js`, `web/src/nrf-dfu.js`) also installs this project's MCU firmware |
| PART | `rnsh` | `reticulum-c-sh` (examples/reticulum_sh.c): listener (allow list, `-C`, `-A`, default program) and initiator (`-m`, `-N`, `-w`, terminal raw mode, window size, `~.`) speaking protocol 1, compatible with the reference rnsh in both directions. Also `-p` (identity, and with `-l` the listening destination, without connecting), the allowed-identities file (`~/.config/rnsh/allowed_identities`, else `~/.rnsh/allowed_identities`, read at start; lines of other lengths ignored) and `-T` (pipe mode on the initiator), read against the rnsh 0.1.8 source. Not implemented: accept-anyone (`-n`, deliberately), line-interactive mode, `-s` (it only names the default identity file; this tool takes `--identity`), reloading the allowed file while running, compression of sent stream data, terminal attribute application on the pty |
| N/A | `rnir`, `rnpkg`, `RNS.Resolver` | Stubs in the pinned reference: they only start Reticulum or `pass`, so there is nothing to implement |
| IMPL | `rngit` | Git over Reticulum, in four tools: `reticulum-c-git` (repository node: list, fetch, push, delete, create, fork, mirror, sync, permissions, releases, work documents, statistics, and the nomadnet page server with markdown conversion, a built-in syntax highlighter, charts, thanks counters, signature display and media conversion), `reticulum-c-git-remote` (`git-remote-rns` helper), `reticulum-c-git-admin` (create, fork, mirror, sync, gperms, rperms, release, work) and `reticulum-c-git-cs` (the `rngcs` commit signing tool). Verified against the unmodified reference in both directions: real git clone, push, pull and branch operations, management commands (the reference CLI against the C node and the C tool against the reference node), signatures byte-identical to the reference's, and 119 page answers compared with the reference's pages with no difference. Differences: bundles and artifacts are held in memory (at most 15 MiB), syntax highlighting is a compact built-in tokeniser rather than pygments, and the reference's `rngit` single command is split in these tools (see COMPATIBILITY.md) |
| IMPL | Remote management, blackhole publishing and subscribing, interface discovery | |

## 6. Examples (manual ch13)

| Status | Example | Notes |
| --- | --- | --- |
| PART | Announce (incl. ratcheted, path request), Broadcast/PLAIN, GROUP, Link, Identification (allow-list), Requests/Responses, Channel, Buffer, Filetransfer | Library behavior and tests exist. Stand-alone examples now cover announce and listen (`examples/example_announce.c`) and a request/response service with its client (`examples/example_request.c`, the answer is the text reversed), both run against the daemon by a process test. Still absent as examples: ratchets, broadcast/PLAIN, GROUP, Link, identification, Channel, Buffer; Filetransfer is `reticulum-c-cp` |
| PART | Echo | Library encrypt/decrypt, proofs and receipts with RTT, `rnc_node_hops_to`; MCU test client in `mcu/tests/echo_client.c`, but no general host echo example |
| N/A | Callback-style APIs | Service, Resource and Link use event dispatch instead of Python callbacks by design |

The repository's executables are `examples/text_peer.c`, the node daemon (`node_daemon.c`) and the tools of section 5 (`reticulum-c-ctl`, `-cp`, `-x`, `-sh`, `-rnodeconf`, `-git`, `-git-remote`, `-git-admin`, `-git-cs`). Two stand-alone protocol examples exist (`reticulum-c-example-announce`, `reticulum-c-example-request`); the rest are covered by library tests only. MCU applications under `mcu/` and the browser tools under `web/` are separate from this manual-example checklist.

## 7. Remaining work ordering

The original Phase A library list (proofs/receipts, policy/rate controls, recall and link lifecycle) and Phase C management list (blackholes and remote management) have implementations above. Phase B host kinds and Phase D CLI tools also exist, with the explicit omissions in their tables. Their existence does not close the remaining options or validation gaps.

1. Done on 2026-11-15: hop limit, `MODE_INTERNAL`, path-response grace and the RPC rate table (section 2). Also done: cancelling a pending path response when a neighbour rebroadcasts. Open: the remote-management `rates` query.
2. Done on 2026-11-15: the host options above. Open: Auto on several devices at once, and the stale-tunnel state of I2P; retain separate validation for emulator-backed host adapters and real hardware.
3. Done on 2026-11-15: the two discovery options and I2P/Weave discovery announcements (section 6).
4. Done on 2026-11-15: path drops, rates, status sorting and filtering, `rnid` formats and import. Open: the rest of the CLI subsets (remote queries, `.rsg`, `rncp`/`rnx`/`rnsh` modes), `rnodeconf` firmware flashing, and runnable stand-alone protocol examples. Keep browser MCU firmware installation distinct from reference `rnodeconf` parity.
