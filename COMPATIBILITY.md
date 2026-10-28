# Compatibility evidence

This is an experimental subset. No complete-stack or broad certification claim
is made. Record a peer's exact revision and features exercised; unsupported
features are distinct from protocol failures.

## Before repository extraction

The independently buildable module passed 9/9 Linux unit groups with GCC 13.3
and OpenSSL 3.0.13. Clang address/undefined checks covered the same foundation.
Frozen vectors cover identities, signatures, encrypted token bytes, destination
hashes, HEADER_1, HDLC and ordinary/ratcheted announces.

The previous integration milestone exchanged exact typed Channel payloads with
unmodified RNS 1.5.5 at e40191b3d193b46b7f2d8a44424a594cd758839b in both roles,
including signed receipts, dropped data/proof recovery, single delivery and
graceful close. Native C process tests covered mutual identity proofs, pins,
key persistence/permissions, oversized/EOF input and shutdown.

## Verified standalone SDK

Snapshot `69d64d5d936fc6565791ee3f487c7d0604c352a5` passed the complete
[hosted SDK matrix](https://github.com/mondain/reticulum-c/actions/runs/40401903210).

| Job | Result | Scope |
| --- | --- | --- |
| Linux static | 11/11 | Protocol units, actual C TCP peers, relocated installed consumer. |
| Linux shared | 11/11 | Same tests using the shared library. |
| Linux address/undefined/leak sanitizers | 11/11 | ASAN detect_leaks=1 and UBSAN halt_on_error=1, including process and installed consumer. |
| macOS Release | 11/11 | Protocol units, actual C TCP peers and relocated installed consumer. |
| RNS 1.5.5 | 14/14 | Baseline plus C initiator/responder and dropped data/proof cases. |
| Leviculum C API | 14/14 | Baseline plus C initiator/responder and dropped data/proof cases. |

The pinned RNS oracle is `e40191b3d193b46b7f2d8a44424a594cd758839b`;
Leviculum is `395edd42fbbffcdfb438fcd80afa17668459d331`. Both live harnesses
require exact bidirectional application payloads, signed RNC delivery, single
application delivery and graceful close. The Leviculum cases additionally verify
initiator identity proofs; its handle-returning connect call is asynchronous,
so identification waits for LINK_ESTABLISHED. Its external FFI library is built
from unmodified source, separately from this C library and SDK.

At that extraction snapshot, Windows, multi-hop routing, IFAC, radio hardware
and other implementations remained unexecuted. The passing matrix covers only
the tested subset at these exact revisions. It does not establish complete
Reticulum stack or radio compatibility.

## SDK 0.2 development branch

The `feature/network-stack-parity` expansion has the following refreshed local
Linux evidence (GCC 13.3, Clang 18.1.3, OpenSSL 3.0.13):

| Configuration | Result | Scope |
| --- | --- | --- |
| Static SDK with pinned RNS oracle | 88/88 | Includes 14 actual network cases and 16 differential fixtures. |
| Shared SDK | 62/62 | Includes POSIX host, daemon, TCP shared-instance and relocated package consumer. |
| Compression disabled | 61/61 | Same native suite without BZip2/compression case. |
| Clang ASAN/UBSAN/LSAN | 62/62 | Leak detection enabled, including native process/PTY/package cases. |
| Pinned Leviculum C API | 65/65 | Native suite plus live initiator, responder and loss recovery. |

RNS source remains pinned to `e40191b3d193b46b7f2d8a44424a594cd758839b`;
Leviculum to `395edd42fbbffcdfb438fcd80afa17668459d331` (local oracle built
with Rust 1.98.1). Both reference trees were verified unmodified by CMake.
Direct and two-router RNS cases include exact bidirectional Channel payloads,
signed receipts, loss recovery, close and a 1024-byte large-MTU exchange.
A process case exercises unmodified RNS shared-instance status RPC.
Resource/service/security/RPC fixtures embed CPython solely as a test oracle;
they establish differential behavior after handshake, not live Resource/service
sessions against the external node. The native routing suite additionally
exercises encrypted in-memory multi-hop links and bounded routing state.

The C harness now waits for RNS's interface-ready log before announcing: an
earlier parallel run exposed RNS's TCP-read/IFAC-initialization startup race.
Both direct/routed server cases subsequently passed ten consecutive executions.
The suite also covers malformed bulk-envelope recovery, completed-advertisement
proof replay followed by another bulk request, receive-queue backpressure,
Resource allocation failure/reuse and distant map-hash collisions.

Documentation snapshot `8a22d1f3781defb57acc1bdab25b7d0c234a95aa`, with the
same implementation, passed all seven [hosted expansion jobs](https://github.com/mondain/reticulum-c/actions/runs/40426146410):
Linux static/shared/compression-disabled/sanitizers, macOS, RNS and Leviculum.
The complete RNS suite was also rerun locally at that snapshot: 88/88 passed.

Socket and leak tests require execution outside the restricted local sandbox.
Actual radio, AutoInterface multicast deployment, Windows, live external
Resource/service sessions and additional implementations still need separate
verification.

## Spec gap closure branch (`feature/spec-gap-closure`)

Local Linux evidence (GCC 13.3, OpenSSL 3.0.13), not yet run in hosted CI:

| Configuration | Result | Scope |
| --- | --- | --- |
| Static SDK with pinned RNS oracle | 120/120 | Previous 88 plus 32 new cases; includes the live direct and two-router RNS sessions. |
| Sanitizers (ASAN/UBSAN/LSAN), no oracle | 103/103 | Embedded-CPython differential cases are excluded: CPython's own allocations trip LeakSanitizer. |

Oracle: RNS at `e40191b3d193b46b7f2d8a44424a594cd758839b` in a separate checkout,
with a virtual environment containing `cryptography` 50.0.2 and `pyserial`.
New behavior is verified by native tests against the reference source's logic
(endpoint delivery proofs and receipts, interface modes, announce retransmission,
rate limiting and ingress control, known-destination recall, link keepalive/stale
state). The new native tests are not differential: they do not exchange these
features with a live RNS node. Live checks remain limited to the existing
direct and two-router Channel sessions, which still pass.

Behavior changes relative to the previous branch state: transport nodes no
longer search for unknown paths on behalf of plain `full`-mode interfaces
(gateway, access-point, roaming, boundary and local interfaces do); link
keepalive and timeout now scale with RTT instead of fixed 30 s / 180 s; ingress
control is enabled by default. See `docs/spec-gap-list.md` for what remains.

## Interface additions (`feature/rnode-correctness`)

Local Linux evidence, same toolchain and oracle as above, not yet run in hosted CI:
129/129 with the pinned RNS oracle (static SDK), host tests clean under
ASAN/UBSAN/LSAN.

Differential: `reticulum_node_process_backbone` runs the unmodified reference
`BackboneInterface` / `BackboneClientInterface` against the daemon's Backbone
types in both directions; the reference announces and the daemon must learn the
destination. This confirms the HDLC wire format and connection handling only.

Native only (no live RNS peer): RNode bitrate, airtime limits and beacon, Pipe,
AX.25 KISS, KISS TNC setup, serial frame parameters, TCP keepalive/reconnect
options, `kiss_framing`, Backbone fast-flap blocking. The `prefer_ipv6` check
is skipped on hosts whose `localhost` is not dual-stack.

Behavior changes: TCP client reconnect now waits 5 s by default (was 1 s), as
the reference does; KISS interfaces now send the TNC setup commands on open.

## Management plane: blackholing (`feature/management-plane`)

Local Linux evidence: 137/137 with the pinned RNS oracle, 113/113 under
sanitizers (differential cases excluded as before).

Differential: the unmodified reference `rnpath` adds (`-B` with `--duration` and
`--reason`), lists (`-b`) and lifts (`-U`) blackholed identities on the daemon's
shared instance over RPC. RPC decoding of `is_blackholed`, `blackhole_identity`
and `unblackhole_identity` uses bytes produced by the reference `umsgpack`, and
the persisted list round-trips the reference file layout (including a float
`until`).

Native only: announce dropping, path removal, expiry and table bounds. Blackhole
sources and publishing the list over a link are not implemented.

## Management plane: link-terminating destinations (`feature/management-plane`)

New library component `rnc_responder` (sans-I/O): accepts link requests for
registered destinations, runs one request/response service per link and calls
registered handlers, with ALLOW_ALL / ALLOW_LIST policies. The daemon uses it
for `rnstransport.remote.management` and `rnstransport.info.blackhole`.

Local Linux evidence: 144/144 with the pinned RNS oracle, 116/116 without it,
113/113 under sanitizers (differential cases excluded).

Differential: the unmodified reference `rnstatus -R` and `rnpath -R -t` query the
daemon over a TCP link with an allow-listed identity, and `rnpath -p` reads the
published blackhole list. Native: an end-to-end C client over TCP (allowed
identity answered, unlisted identity gets no answer), and in-process responder
tests (echo, silent handler, allow-list with identification, link teardown).

Limits: `/path` `rates` returns an empty list (the node keeps no rate table for
reporting); eight concurrent responder links; requests and responses are capped
at 64 KiB in the daemon. A request on a stale or closed link is not answered.
The reference reports an empty path table as a failed request; this applies to
the reference client regardless of server.

## Management plane: blackhole sources (`feature/management-plane`)

New library component `rnc_requester` (sans-I/O): opens a link to a destination
the node has a route to, optionally identifies, sends one request, returns the
response and closes the link. Four concurrent jobs. The daemon's blackhole
updater uses it: after an initial wait it asks for a path, requests `/list`
from each subscribed source once per interval, merges identities nobody has
listed yet (a local entry is never overridden) and stores the list.

Local Linux evidence: 153/153 with the pinned RNS oracle, 124/124 without it,
121/121 under sanitizers (differential cases excluded).

Differential: the daemon, subscribed to the transport identity of an unmodified
reference instance with `publish_blackhole`, picks up an identity the reference
blackholed. Native: requester tests (echo, no route, silent handler, identify
with an allow list, job limit, argument checks), merge semantics, and two
daemons (publisher and subscriber) including persistence across a restart.

Differences from the reference updater: the daemon re-asks for a missing path
every 5 s for up to 25 s instead of one blocking wait; the first-run delay can
be set with `blackhole_initial_wait` (seconds, reference fixed at 20); lists are
stored as `<state>.blackhole.<hex>` beside `--state`.

## Management plane: probe responder (`feature/management-plane`)

`respond_to_probes = Yes` registers `rnstransport.probe` on the transport
identity with PROVE_ALL and no link acceptance, and reports its hash as
`probe_responder` in RPC interface stats.

Local Linux evidence: 155/155 with the pinned RNS oracle, 125/125 without it,
122/122 under sanitizers (differential cases excluded). Differential: the
unmodified reference `rnprobe` (two probes) receives valid replies. Native: a C
client's tracked packet is proved when enabled and gets no proof when disabled.

## Network identity (`feature/network-identity`)

`network_identity = <path>` loads, or creates with mode 0600, a 64-byte identity
file in the reference's format. The daemon registers `rnstransport.network` and
`rnstransport.network.instance.<identity hash>` on it, as Transport does, reports
the hash as `network_id` in RPC interface stats and via the admin `NETWORK`
command.

Local Linux evidence: 157/157 with the pinned RNS oracle, 126/126 without,
123/123 under sanitizers (differential cases excluded). Differential: a file
written by the reference (`rnid -g`) loads in the daemon with the same hash, and
a file created by the daemon loads in the reference (`rnid -i -p`) with the same
hash. The daemon, like for its own key file, refuses an identity file readable
by group or others; the reference writes them with the default umask, so such a
file needs `chmod 600` first.

The network identity's use for interface discovery (encrypted discovery
announces) is not implemented; only the identity and its destinations are.

## Resource window growth (`feature/resource-window`)

The receiving side now follows the reference's window model (Resource.py):
start at 4 or at the link's previous incoming window, grow by one part per
completed request round up to a ceiling of 10, raise the ceiling to 75 after 4
rounds above 6.25 kB/s, lower it to 4 after 2 rounds below 250 B/s, and back off
the window and ceiling when a round times out. `rnc_resource_window()` and
`rnc_resource_window_max()` expose the state; `rnc_link_last_resource_window()`
carries it between resources on a link.

Local Linux evidence: 159/159 with the pinned RNS oracle (includes the embedded
reference Resource sender against this receiver), 129/129 without it, sanitizers
clean (differential cases excluded). Native tests drive the fast, slow, very
slow and timeout classes with a controlled clock.

Not changed: the retry timer is still a fixed 2 s (the reference derives part
timeouts from its expected inflight rate, so very slow links retry more often
here than there), and the sender side was already able to serve windows up to 75.
The in-process test harness now drains link events in batches because a link
holds RNC_LINK_EVENTS (64) undelivered events and a 75-part window can exceed
that if a host feeds a whole round before polling.

### Resource timeouts

The fixed 2 s / 60 s timers are replaced by the reference's rate-based ones:
the receiver waits `factor x outstanding x SDU x 8 / EIFR` (factor 4 until the
first part, then 2) plus a hashmap-update allowance, 0.25 s grace and 0.5 s per
retry used, where EIFR is the measured data rate, else the previous resource's
on the link, else link set-up cost over RTT. The sender's limits follow the
link RTT (advertisement RTT x 6 + 1 s, part requests RTT x 96 + 78 s then
cancel, proof RTT x 3 + 10 s). Link set-up cost is a constant 287 bytes rather
than the exact byte count; it only seeds the first estimate.

Verified by white-box tests against values computed with the reference's own
formulas, a wiring test (a measured fast rate shortens the wait from the old
2 s), the existing drop/retry transfer tests, and the embedded reference
Resource sender/receiver oracle cases (161/161 with the oracle, 131/131
without, 128/128 under sanitizers with differential cases excluded).

As in the reference, the first request of a transfer waits only about 0.4 s
because its formula mixes SDU bytes with a bits-per-second rate, so links with
a round trip above that see a duplicate first request; rates settle after the
first round.

## Interface discovery (`feature/interface-discovery`)

New library pieces: `rnc_stamp` (LXMF-compatible proof-of-work stamps, with a
resumable search for event loops), `rnc_discovery` (announce payloads: pack,
stamp, encrypt, parse and validate; the reference's on-disk record layout;
configuration entries; status classification) and
`rnc_node_set_destination_data`. The daemon uses them to announce its
discoverable interfaces, to listen for others', and to auto-connect to Backbone
announcements.

Daemon behaviour that differs from the reference:
- Stamp generation runs in slices between event-loop iterations rather than
  blocking a thread, and the announce job interval can be changed with
  `discovery_job_interval` (reference: fixed 60 s); `announce_interval_seconds`
  and `autoconnect_monitor_seconds` / `autoconnect_detach_seconds` exist so tests
  need not wait (reference: minutes, 5 s, 12 s).
- Announces carry the implementation name `reticulum-c`, so reference nodes
  auto-connect to them only with `autoconnect_unverified_implementations`.
- The reference refuses to auto-connect to 127.0.0.1 and 0.0.0.0; the daemon does
  too unless `autoconnect_allow_local` is set.
- Auto-connected interface IDs start at 0x7ffd0000.

Verification: stamp workblocks of 1, 3, 20 and 200 rounds, stamp values, packed
announce maps (three interface types) and the three record layouts match bytes
produced by the reference (`umsgpack`, `LXStamper`); an encrypted announce made
by the reference decrypts here, and ours validates in the reference. End to end
with the unmodified reference (which needs LXMF; CI installs `lxmf==1.2.1` with
`--no-deps`): the reference discovers and lists this daemon's interface
(`rnstatus -d -D`), and this daemon discovers the reference's interface
announce. Native: two-daemon listening (stored, restart, stamp requirement,
authorised sources, encryption with and without the key) and auto-connect with
bootstrap teardown and fallback.

Not implemented: Weave announcements, path gravity, and announcements for I2P interfaces.

## Logging hook (`feature/logging-hook`)

`rnc_log.h` adds a process-wide hook: `rnc_log_set_handler`, `rnc_log_set_level`
and `rnc_logf`, with RNS's levels (NONE to EXTREME, default NOTICE) and its
`[Notice]  `-style labels. The library is silent until a handler is set. It now
reports learned paths and announces dropped for blackholed identities (node,
debug), link establishment, closure and staleness (link), failed transfers
(resource) and interface up/down and refused fast-flapping peers (host).

The daemon reads `[logging]` (`loglevel` 0-8, `logdestination` stdout / stderr /
file, `logfile`) and writes `[time] [Level]   module: message`; stderr is the
default so the machine-readable lines on stdout are unaffected. The reference's
per-call `RNS.log` messages are far more numerous; this covers the main events,
not every message.


## Operator tools (`feature/cli-tools`)

`reticulum-c-ctl` (examples/reticulum_ctl.c, installed with the examples) is one
binary with three subcommands:

- `status [-j]` and `path [-t] [-m hops] [-j] [hash] [-b] [-B hash --duration
  hours --reason text] [-U hash]` talk to the daemon's RPC port
  (`instance_control_port`, default 37429) with the same HMAC-authenticated
  MessagePack calls the reference uses. The key is derived from the daemon's
  identity file (`--identity`), given as hex (`--rpc-key`) or read from a
  config file (`--config`: `rpc_key`, `instance_control_port`). Interface mode
  numbers in the RPC now follow the reference (FULL 1, ACCESS_POINT 3, ROAMING
  4, BOUNDARY 5, GATEWAY 6, internal 7), so `status` shows real modes.
- `id` handles reference-format identity files (raw 64-byte private key, mode
  0600): `-g`, `-i -p [-P]`, `-x/-X`, `-H aspects`, `-s FILE --raw` and
  `-V SIG -r FILE --raw` (raw 64-byte signature, `.rsg`), `-e` and `-d`
  (16 MiB chunks, `.rfe`) with `-w` and `-f`. Exit codes follow rnid (10 for an
  invalid signature, 12 for a failed decryption, 11 for an existing file).

Differences: an empty path table is a successful empty result here (the
reference reports a failed remote request); `path <hash>` filters the table
client-side and exits 1 when nothing matches; the RPC is still the shared
instance's TCP control port only. The envelope signature format of `rnid`
(without `--raw`), embedded messages and metadata, and the other text encodings
are not implemented, and the tool says so instead of writing a different format.

Evidence: a daemon process test drives all three subcommands (text and JSON
status, a wrong RPC key failing, an announce fed in then listed by `path -t` and
`path <hash>`, blackhole add/list/remove checked against the admin socket,
identity generation, signing, tampering, encryption and corruption). Differential
against the unmodified reference `rnid`: hashes and aspect hashes agree, the
reference validates our raw signature and ours validates the reference's, and
encrypted files decrypt in both directions.

## Tunnels (`feature/packet-cache`)

Tunnels follow `Transport.synthesize_tunnel` / `handle_tunnel`: a TCP client
(not kiss-framed) sends one broadcast PLAIN packet to `rnstransport.tunnel.
synthesize` on connect, carrying its transport public key, a stable interface
hash, a random hash and a signature; the receiver validates it, creates or
refreshes the tunnel (id = SHA256(public key || interface hash), 8 h timeout),
associates paths learned on that interface with it, and when the same tunnel
reappears on a new interface restores those paths unless a newer one exists.
`rnc_node_synthesize_tunnel`, `rnc_node_tunnel_count` / `_at` and a signed
`rnc_node_tunnels_export` / `_import` checkpoint (kept as a separate record so
the route checkpoint format is unchanged) are the API; the daemon saves the
table with `SAVE` and at exit and shows it with the admin `TUNNELS` command.

Local Linux evidence: native tests (establish, reject, restore, newer path,
expiry, persistence, host synthesis, two-daemon persistence across a restart)
and a differential test in which the unmodified reference's TCP client connects,
announces, leaves, and reconnects: the daemon keeps the path through the
absence and restores it on the reconnect without an announce. With restoration
disabled that test fails.

Notes:
- The reference's interface hash is the hash of its interface description; this
  host uses the hash of the interface name. It is only compared for equality.
- A reference instance that is not a transport node uses a fresh transport
  identity on every start unless `static_transport_identity` is set, so it only
  produces the same tunnel again with transport enabled (or that option).
- The transport packet cache is not implemented because the reference never
  populates it (`Transport.should_cache` always returns False).

Bug found on the way and fixed: an announce retry still pending for an interface
that had been removed dereferenced a null interface (a TCP client leaving while
its announce was queued for retransmission crashed the daemon). Regression test
`reticulum_announce_ingress_removed`.


## Packet receipts (`feature/packet-receipts`)

Tracked sends already reported DELIVERED or FAILED with an RTT. Receipts can now
be queried (`rnc_node_receipt_status`: SENT while pending, DELIVERED/FAILED with
the RTT afterwards, `RNC_STATE` for an unknown or recycled hash, the reference's
CULLED), and `rnc_node_send_tracked` with a timeout of 0 uses the reference's
default, `Transport.first_hop_timeout + Packet.TIMEOUT_PER_HOP * hops`: 6 s per
hop, plus 6 s and one 500-byte MTU at the first hop interface's bitrate
(`rnc_node_receipt_timeout` exposes it). Finished receipts stay queryable until
their slot is recycled, oldest first; the 32 slots are never taken from pending
receipts (`RNC_AGAIN` when all are pending). Link-proof receipts, `resend` and
signal-quality accessors are not provided.

Evidence: unit tests for pending/delivered/failed queries, slot recycling and
the default timeout boundary (expires exactly at the computed value).

## Request progress (`feature/request-progress`)

`rnc_requester_progress(requester, tag, &state, &progress)` gives the
reference's `RequestReceipt` view of a job: SENT while the link opens and the
request travels, DELIVERED when a Resource-sized request has been delivered,
RECEIVING with a 0..1 progress (transferred over total parts) while a
Resource-sized response arrives, READY (1.0) or FAILED when finished, until the
result is polled; an unknown tag returns `RNC_STATE`. An inline request goes
SENT to READY as in the reference. `rnc_service_request_state` is the same
for a request made directly on a service. The reference's progress for
multi-segment resources counts segments; responses here are single segment.

Evidence: unit tests drive an inline echo (SENT, READY only), a 3 kB echo whose
request and response both travel as Resources (SENT, DELIVERED, RECEIVING with
a fractional, non-decreasing progress, READY at 1.0), and a silent handler
(FAILED).

## File transfer: rnc_transfer and reticulum-c-cp (`feature/rncp`)

`rnc_transfer.h` is the library side of rncp. A listener owns a `rncp.receive`
destination, accepts links, and receives a file pushed as a Resource whose
metadata is `{"name": <bytes>}`; with a fetch callback it also serves the
`fetch_file` request (response True, False for not found, or 240 for not
allowed, the file following as a Resource). A client pushes or fetches. Access
follows rncp: with an allow list a sender must identify and be listed, otherwise
the link is closed; `allow_all` accepts anyone; an unauthorised fetch gets no
answer. Files are held in memory, at most `RNC_TRANSFER_MAX_SIZE` (16 MiB less
4 KiB, the Resource limit).

`reticulum-c-cp` is the command line: `-l` listen (`-a` allowed identity hash,
`-n` no authentication, `-s` save directory, `-O` overwrite instead of adding
`.1`, `.2`, `-F` allow fetch, `-j` jail, `-b` announce interval), `FILE
DESTINATION` to push, `-f REMOTE DESTINATION` to fetch. It attaches to a node
over TCP (`--connect HOST:PORT`, for instance a daemon's server interface or
shared-instance port) with its own identity file (`--identity`). Received names
are reduced to their last path component, and a fetch jail is enforced on the
normalised path and again on the resolved path so a symlink cannot leave it.

Not implemented: allowed-identity files, announce-time identity printing
(`-p`), compression control (`-C`), silent mode, the reference's `--config`.

Also fixed: a TCP client interface added before the host's first step took its
connect deadline from an unset clock, so on a real monotonic clock the first
attempt timed out immediately and the connection waited a full reconnect
interval (5 s). The deadline is now taken at the first step.

Evidence: library tests for send, a 150 kB send with non-decreasing progress,
allow-list denial (verified by disabling the checks, which fails the tests),
fetch found, not found, not allowed, fetch disabled and unlisted fetchers;
process tests with the real binaries (push with duplicate naming, allow list,
jailed fetch with an escape attempt and a missing file); a host test for the
connect deadline; and differential tests against the unmodified reference
`rncp` in all four directions (ours pushes to and fetches from the reference
listener; the reference pushes to and fetches from ours).

## Remote execution: reticulum-c-x (`feature/rnx`)

`reticulum-c-x` speaks the rnx protocol: destination `rnx.execute`, request path
`command` with `[command, timeout, stdout limit, stderr limit, stdin]`, and the
eight-element result `[executed, return code, stdout, stderr, stdout length,
stderr length, started, concluded]`. The listener splits the command with
POSIX shell quoting rules and runs it directly (no shell), kills it after the
requested timeout, returns the exit code (negative for a signal) and the
captured output, applying the requested limits. Client exit codes follow rnx:
242 no path, 243 no link, 244 request failed, 245 no result, 247 bad result,
248 not executed, 249 no response, and with `-m` the remote exit code.

Differences, on purpose: there is no accept-anyone mode, so a listener only runs
commands for the allow list (at most 8 identity hashes), and a request from an
identity that is not listed is dropped without an answer (as ALLOW_LIST does in
the reference). A command is stopped after 25 s because the request service
keeps an incoming request for 30 s, and the handler runs inside the listener's
loop, so one command runs at a time. Requests and results are limited to about
64 kB (output beyond that is counted but not returned). Interactive mode is not
implemented.

Both command line tools now keep the node running for 300 ms after finishing so
the link close actually leaves the socket; before, a listener kept a link slot
until its timeout, so after four pushes (`reticulum-c-cp`) or eight commands the
next one failed. A regression test runs 6 and 12 sequential clients.

Evidence: a process test with the real binaries (output, mirrored exit code,
stdin, output limits, stderr, a missing executable, a timeout that stops
`sleep 30`, an unlisted identity that cannot create a marker file, 12 runs in a
row) and differential tests against the unmodified reference `rnx` in both
directions (the reference runs a command on ours and mirrors its exit code; ours
runs one on the reference listener).

## Remote shell: reticulum-c-sh (`feature/rnsh`)

`reticulum-c-sh` speaks rnsh protocol 1 over a Link Channel: destination
`rnsh`, message types `0xac00` plus 0 (noop), 2 (window size), 3 (execute
command), 4 (stream data, the Buffer stream format with stream ids 0 to 2),
5 (version, `[software, 1]`), 6 (error) and 7 (command exited). The listener
requires the initiator to identify, checks its allow list, exchanges versions,
then runs the requested program (or its own default, `-C` refuses remote command
lines, `-A` appends them to the default) on a pty when the initiator is a
terminal and on pipes otherwise, as the reference does. It sets `TERM` and
`RNS_REMOTE_IDENTITY`, applies the initial and later window sizes, relays
stdin, stdout and stderr with EOF, and reports the exit code (the signal number
for a signal). A command that ignores HUP and TERM is killed when the session
ends. The initiator puts a terminal in raw mode, forwards `SIGWINCH`, and
recognises `~.` after a newline (`~~` sends a tilde).

Differences: there is no accept-anyone mode; line-interactive mode (`~L`) and
the allowed-identities file are not implemented; stream data is sent
uncompressed (compressed data from the reference is understood); the terminal
attributes the initiator sends are not applied on the pty (the reference does
not apply them either); the listener runs at most 4 sessions, announces only
with `-b`, as the reference does. The reference's listener reports
`waitpid() & 0xff`, which is 0 for any normal exit, so `-m` against a reference
listener only mirrors signals.

Evidence: process tests with the real binaries (a command, its exit code, stdin,
stderr, the default program with the remote identity in the environment, 30000
lines of output through the channel flow control, a pty for terminal clients,
typing into the shell, the `~.` escape, a program that ignores HUP and TERM,
an unlisted identity, `-C`), and differential tests against the unmodified
reference rnsh in both directions. The reference listener's pipe mode fails in
this test environment (its transmit path reports a bad file descriptor after it
starts the child), so that direction runs the client on a terminal, which uses
the reference's pty mode.

## Configuration knobs (`feature/config-knobs`)

- `outgoing = No` on an interface: it still receives, but nothing is sent on it
  (`rnc_host_config.no_output`). Connections a listener accepts inherit it.
- `use_implicit_proof = No` in `[reticulum]`: a destination set to prove every
  packet answers with the 96 byte explicit proof (packet hash and signature)
  instead of the 64 byte implicit one (`rnc_node_set_implicit_proofs`). The
  sender accepts both either way.
- `panic_on_interface_error`: an interface that cannot be opened (a port already
  in use, a missing serial device) is now logged and skipped, as the reference
  does by default, and the daemon carries on with the others; with the option
  set the daemon exits. Before, any such interface stopped the daemon. A TCP
  client that cannot reach its peer was never affected: it keeps retrying.

Not done: `link_mtu_discovery`. The reference signals the next hop's hardware MTU
when it opens a link and so can use packets larger than 500 bytes on TCP; links
here stay at 500 bytes (and peers that signal more are clamped to that), which
interoperates but moves bulk data in smaller packets.

Evidence: a host test (receive-only client, the same client with output on as a
control, and a listener's accepted connection), a receipt test for the explicit
proof format, and daemon tests for the config keys and for skip versus panic.

## Link MTU discovery (`feature/link-mtu-discovery`)

The link protocol already negotiated an MTU (3 signalling bytes in the link
request and proof, the smaller of both ends, transport nodes clamping a request
to their own interfaces), but nothing asked for more than 500 bytes. Now
applications configure their links from the interfaces: `rnc_node_link_mtu_to`
(initiator, the interface the route leaves by) and `rnc_node_link_mtu_on`
(responder, the interface the request arrived on), used by the responder,
requester, transfer listener and client, and the remote shell. `link_mtu_discovery`
(default on, `rnc_node_set_link_mtu_discovery`, daemon key `link_mtu_discovery`)
switches it off, which keeps every link at 500 bytes.

The daemon now gives TCP interfaces (server, client, Backbone) a 4096 byte MTU
unless `mtu` is set; the reference sizes them from their bitrate, far higher.
Other interface kinds keep 500. The library caps packets at 4096, below the
reference's 16 KiB and more. The admin `STATUS` line shows `mtu=`.

Measured: one megabyte pushed by `reticulum-c-cp` to the unmodified reference
`rncp` through the daemon takes 1.9 s with discovery and 8.1 s with the
daemon's interface held at 500 bytes, and the files are identical.

Evidence: requester tests (4096 byte interfaces carry packets over 2000 bytes,
discovery off stays at 500, a 500 byte far side clamps the link, intermediate
sizes), a transfer test with incompressible 60 kB over both settings, a test of
the node helpers, daemon tests for the key and the per-interface defaults, and
the reference differential tests, which now negotiate larger links.

## RNode detection and reticulum-c-rnodeconf (`feature/rnodeconf`)

Detection: like the reference RNodeInterface, the host now asks an RNode to
identify itself (DETECT, then firmware version, platform and MCU) and only
configures the radio once the device answers the detection. Silence for five
seconds drops the interface (and it is retried like any serial device). A
firmware older than 1.52 is refused: the reference calls `RNS.panic()`, which
would exit a daemon, so here the interface is logged as an error and not
retried, and the other interfaces keep running.

`reticulum-c-rnodeconf PORT` is the part of rnodeconf that talks to a running
device, built on the same KISS protocol: `-i` reads the device and its EEPROM
(checksum, product, model, signature checked against the vendor's two public
keys, or a key given with `--trust-key`, with the information the reference
prints), `-c` prints the stored configuration, `-T` with `--freq --bw --txp
--sf --cr` stores TNC mode and `-N` returns to normal mode, and `-b -B -p -D -t
-R --display-addr --recondition-display --np -x -X -w --channel --ssid --psk
--ip --nm` set Bluetooth, display, NeoPixel, interference avoidance and WiFi.
Values are range-checked before anything is sent. What it does not do needs the
vendor toolchain or the hardware and cannot be tested here: firmware download,
flashing, update and extraction, autoinstall, EEPROM provisioning, backup, dump
and wipe, signing keys and hash commands.

Evidence: an emulated RNode on a pty (device side of the KISS protocol: detect,
firmware, platform, MCU, ROM and configuration reads, all the setters, TNC save
and delete) logs every frame, so the tests check the bytes each option sends;
signature validation against a locally generated RSA key; an unprovisioned and a
damaged EEPROM; refused values. The unmodified reference rnodeconf runs against
the same emulator: it prints the same device information and configuration
lines as this tool, reads back what this tool wrote (Bluetooth, WiFi, display,
interference avoidance, NeoPixel, TNC mode) and this tool reads back what the
reference wrote, in both directions. Host tests cover detection, silence, the
1.52 boundary, a newer major version and the refusal of old firmware.

## Smaller gaps (`feature/small-gaps`)

Identity: `rnc_truncated_hash` and `rnc_random_hash` (`truncated_hash`,
`get_random_hash`); `rnc_host_identity_save` (`to_file`, `pub_to_file`: the raw
64 byte private key at mode 0600, or the public key at 0644; atomic, and an
existing file is only replaced on request).

Destination: `rnc_node_set_accepts_links` drops link requests to a destination
before the application sees them; `rnc_responder_set_max_request_size` limits
requests per destination, for present and future links (an inline request over
the limit is dropped, a Resource advertising one is not accepted, and one that
arrives anyway is dropped before the handler runs); clearing default app data
is `rnc_node_set_destination_data(node, dest, NULL, 0)`, now covered by a test
that the next announce carries none.

Transport: `rnc_node_request_path_ex` (`on_interface`, caller tag, `recursive`:
nothing is sent while announces are queued for the interface or its announce
bandwidth allowance has not recovered), `rnc_node_hops_to` (128 when unknown)
and `rnc_host_await_path`, which reticulum-c-cp, -x and -sh now share instead of
three copies of the same loop. Its callback receives every host event and a
tick per pass, and can interrupt the wait.

Link: `rnc_link_no_data_ms` (time since application data, excluding keepalive,
identification and close traffic), `rnc_link_mode` (1, AES-256-CBC) and
`rnc_link_establishment_rate` (request and proof bytes over the round trip time,
bits per second). Packets sent through `rnc_link_send_packet` and
`rnc_link_send_resource_packet` now count as outbound at the time of the call,
not the previous call.

Reclassified rather than built: packet prioritisation (the reference only
prioritises announces by hop count, as here), `proof_strategy` and its callback
(the application answers `PROVE_APP` packets with `rnc_node_prove`),
ResourceStrategy, `register_message_type` and the Buffer wrappers (the
application's own policy and registry).

Evidence: unit tests for each (link getters and rates, hash helpers, identity
files with modes and overwrite rules, request path options and the recursive
wait, hops, accepts_links, the request size limit, destination data clearing)
and a host test of `rnc_host_await_path` with a peer that creates its
destination mid-wait, a timeout, an immediate return and an interrupt.

## Ratchet file (`feature/ratchet-file`)

`rnc_ratchets_export_reference` and `rnc_ratchets_import_reference` encode and
decode the file `Destination.enable_ratchets` keeps: a MessagePack map with the
owner's Ed25519 signature over the packed key list and that list, the 32 byte
private ratchet keys newest first (a fixarray, or array16 above 15 keys). The
library does no file I/O; the host writes the bytes where it likes (atomically
and at mode 0600, like `rnc_host_identity_save`). The file carries no
timestamps, so an imported store has every key at time 0 and its next rotation
is due at once, as after a restart of the reference. Import checks the owner,
the signature and every byte of framing before it replaces anything, and a
store too small for the keys is refused. The library's own checkpoint format
(`rnc_ratchets_export`, with timestamps and an interval) is unchanged.

Evidence: unit tests (exact byte layout, round trip, empty list, array16, every
single byte flipped, wrong owner, too little room, store too small) and a
differential test: a file the unmodified reference wrote after three rotations
loads with the same public keys in the same order, and a file written here (four
rotations) loads in the reference with the same keys.

## RNode signal statistics (`feature/rnode-signal`)

An RNode reports the RSSI and SNR of a frame just before it hands the frame over.
The host keeps the latest figures as the reference's `r_stat_rssi`, `r_stat_snr`
and `r_stat_q`: RSSI is the byte less 157 dBm, SNR a signed byte in quarter dB,
and the quality is `(snr - min) / (6 - min) * 100` with `min = -9 - 2 * (sf - 7)`,
rounded to a tenth and clamped to 0 to 100. They appear in `rnc_host_status`
(`has_signal`, `rssi`, `snr`, `quality`), on every `RNC_HOST_NODE` event from that
interface (like `packet.rssi`, `packet.snr`, `packet.q`), and in the RPC interface
stats as `rssi`, `snr` and `q` (nil on other interfaces), which
`reticulum-c-ctl status` prints. Per-link tracking is not provided.

Evidence: a host test with an emulated RNode that sends the statistics frames
before an announce, at SF7, SF9, and both clamp ends; the RPC test checks the
new keys.
## WiFi RNode and TCP_NODELAY (`feature/rnode-tcp`)

An RNodeInterface whose `port` is `tcp://host` talks to the device over TCP
(port 7633; `rnc_host_config.port` overrides it). The connection is started
without blocking, the radio is detected and configured when it opens, a
detection request goes out after 3.5 s without anything written (as the
reference's keepalive does) so a dead connection shows up, and a dropped
connection is retried like any serial device. Bluetooth LE RNodes are not
supported.

Also fixed for every TCP interface (clients, servers and their accepted
connections): `TCP_NODELAY` was never set, so a small frame sent right after
another waited for the peer's delayed ACK (tens of milliseconds on a LAN). The
reference sets it on all of them.

Evidence: a host test with a TCP listener acting as the device (detection,
configuration and acknowledgement, the ping after silence, reconnect and a second
detection) and the `TCP_NODELAY` option checked on the host's connected socket.
Not tested against a real WiFi RNode.

## I2P interface (`feature/i2p`)

`I2PInterface` (host kind `RNC_HOST_I2P`) talks to a local I2P router through its
SAM v3 bridge (127.0.0.1:7656 unless `target_host` and `target_port` say
otherwise; the reference takes that from an environment variable, which is not
read here). It keeps one session open, creates it from a stored destination key
(or has the router generate one and writes it with owner-only access), and then:

- `peers`: a comma separated list of `<52 chars>.b32.i2p` names, bare 52
  character b32 addresses or full base64 destinations. A name is looked up on a
  socket of its own and the stream is made on a fresh one, as the reference's
  i2plib does. Each peer is retried every 15 s.
- `connectable = yes`: keeps one `STREAM ACCEPT` waiting at the router and
  replaces it each time someone connects.
- Streams carry HDLC frames like a TCP connection, with the reference's TCP
  keepalive options (10 s, 9 s, 5 probes, 45 s), an empty HDLC frame after 10 s
  without writing, a drop after 110 s without reading, an MTU of 1064 and a
  nominal 256 kb/s bitrate. The initiating side synthesizes a tunnel on connect.
- The key file lives in `<state>.i2p/` (or `<identity file>.i2p/`) and is named
  `hex(SHA256(SHA256(name) + SHA256(transport identity hash)))`; a file named
  `hex(SHA256(SHA256(name)))`, which older reference versions used, is used when
  it exists. A file that is not an I2P key is reported and never overwritten.
- If the router goes away, every stream goes with the session; the session is
  rebuilt on the same key when the router is back and the peers are redialled.

Evidence: unit tests for the I2P base64 alphabet, destination and b32 handling
against values the reference's i2plib produced, and SAM reply parsing; a fake
SAM router (`tests/fake_sam.c`) with host tests for session and key
persistence, dialling by name, bare b32 and destination, the retry interval,
router restart, a bad key file and the keepalive and read watchdog (the
read-timeout and retry tests fail when their constants are changed); daemon tests for key file naming and
STATUS; and, with the oracle, the unmodified reference's `I2PInterface` and this
daemon connecting through the fake router in both directions, each learning an
announce across the I2P stream.

Not tested against a real I2P router (i2pd or Java I2P): the fake implements the
subset of SAM used here, so behaviours of a real router (tunnel build times,
`PING`/`PONG` on the session socket, error results) are covered only by what the
SAM specification and the reference's client imply.

## RNode Multi (`feature/rnode-multi`)

`RNodeMultiInterface` (host kind `RNC_HOST_RNODE_MULTI`) drives one serial device
that carries several radios. The device is asked what it is and which radios it
has in one go (DETECT, firmware, platform, MCU and `CMD_INTERFACES`); 0.3 s after
it answers, each configured `[[[radio]]]` becomes an interface of its own
(a child of the device, named `<interface>[<radio>]`), after its `vport` has been
checked against the radios the device reported and its frequency against the
radio type (SX127X/SX126X 137 MHz to 1 GHz, SX128X 2.2 to 2.6 GHz). Every
command and frame for one radio is preceded by a `CMD_SEL_INT` frame naming it,
and what the device sends is applied to the radio it last selected: parameter
acknowledgements, RSSI and SNR (with that radio's own spreading factor for the
quality figure), ready, and the received frames. Radios share the line, so one
radio's frame is written out whole before another's begins. A radio that does
not confirm its parameters in 5 s, a hardware error, a reset or a vport the
device does not have takes the device down; it is reopened every 5 s. Firmware
below 1.74 is refused and not retried (the reference's check also refuses 2.0,
which is almost certainly a slip; here 2.0 is accepted).

A radio is in use when its section sets `interface_enabled = yes` or when the
interface itself says `enabled = yes`, as in the reference. `outgoing = no` on a
radio stops it transmitting; `id_callsign`/`id_interval` apply to every radio but
each keeps its own timer (the reference shares one).

Evidence: host tests with a pty device emulator (configuration of two radios of
different types with the select frame before each command, transmit only on
outgoing radios, receive routed by selection with per radio signal figures, and
the refusals above, each mutation-checked), daemon tests (the nested sections
parse, a radio without a vport and a section under another type are refused, a
disabled radio is not configured) and a differential test in which the
unmodified reference's `RNodeMultiInterface` and this host drive the same
emulator and must send every radio the same commands with the same values.
Not tested on real hardware.

## Weave (`feature/weave`)

`WeaveInterface` (host kind `RNC_HOST_WEAVE`, daemon `type = WeaveInterface`,
`port = <serial device>`, optional `configured_bitrate`) speaks WDCL to a Weave
switch: HDLC frames at 3 Mbaud, each starting with the four byte id of the switch
it is for. The host makes up a signing identity for the run (its id is the last
four bytes of the public key), broadcasts a discovery frame carrying that id,
checks the switch's reply (key and signature of the id) and answers with its own
key and a signature of the switch's id. The switch confirms with a connection
event; the host has two seconds for all of this, otherwise the line is closed and
tried again after five (the reference does the same).

Every endpoint the switch reports, by an alive event or by sending a packet, is a
peer: an interface of its own, a child of the switch interface named
`<interface>[<endpoint>]`, with MTU 1024 and the configured bitrate (250 kb/s
by default). A packet for a peer goes out as a command naming that endpoint. A
peer not heard from for 20 seconds is removed (the reference checks every 22
seconds, so its peers live up to 42). The same packet delivered by two
endpoints within 0.75 seconds is passed on once. Frames that are too short, are
for another switch, or carry an event of the wrong size are ignored. The node's
interface limit (eight) bounds the number of peers.

Differences from the reference: peers are only created once the connection
event has arrived, a log or packet frame shorter than its header is ignored
(the reference raises and closes the port), and the interface does not render
the switch's log, display or CPU/memory statistics.

Evidence: host tests with a pty switch emulator that checks the signatures
(handshake, silent and mis-signed switches, endpoints appearing and timing out,
receive with the duplicate window, transmit to each peer, malformed frames),
daemon tests, and a differential test in which the unmodified reference's
`WeaveInterface` completes the same handshake with the emulator, takes a packet
from an endpoint and sends its own announce to it. The tests fail when the
duplicate window, the signature check, the peer timeout or the endpoint in the
command is removed. Not tested on real hardware.

## rngit: git over Reticulum

Four executables port the reference's `rngit` (the single `rngit` and
`git-remote-rns` commands of RNS e40191b3): `reticulum-c-git` (the repository
node), `reticulum-c-git-remote` (install as `git-remote-rns`),
`reticulum-c-git-admin` (create, fork, mirror, sync, permissions, releases, work
documents) and `reticulum-c-git-cs` (the `rngcs` commit signing tool). All attach
to a node over TCP like the other tools. The subsections below record what each
step added, its differences from the reference and its evidence; the order is
transport, creation and permissions, then the rest.

`reticulum-c-git` is a repository node for the reference `rngit` protocol and
`reticulum-c-git-remote` is a remote helper for `rns://DESTINATION/GROUP/REPO`
URLs (install it as `git-remote-rns`). Both attach to a node over TCP, like the
other tools; the helper takes the node from `RNGIT_CONNECT=HOST:PORT` or the
`connect` key of `client_config`.

The SDK gained what the protocol needs: a service, responder and requester can
answer and receive a *file*, raw data plus one MessagePack metadata value sent
as one Resource bound to the request (the reference's file-object response, used
for fetch bundles), through `rnc_service_respond_file`,
`rnc_responder_register_file` and `rnc_requester_poll_file`.

The node serves four paths under the destination `git.repositories`:
`/git/list` (refs and the HEAD symref, `for_push` checks write access),
`/git/fetch` (a bundle of the requested refs minus what the client has, or
a bare success when the bundle would be empty), `/git/push` (a bundle that is
verified and fetched into the ref, or `update_ref` operations when the objects
are already there) and `/git/delete`. Permissions resolve as in the reference:
a repository's own list for a permission replaces the group's for that
permission, `none` wins, an administrator passes, blocked identities never do.
The configuration directory has the reference's `config`, `group.allowed` and
`NAME.allowed` files (an executable one is run and its output used). Refs and
SHAs are checked with the reference's rules (a corpus run through the reference's
own `san_ref` is a test), and every git invocation is an argument vector, never a
shell.

Differences from the reference: the whole of a bundle is held in memory, so a
request or response is limited (`max_bundle`, 8 MiB by default, 15 MiB at most;
the reference has no limit); a request is answered synchronously, so a git
operation that outlives the 30 second request window is lost; the helper opens a
link per request where the reference keeps one; a SHA with whitespace in it is
refused (the reference accepts it); a missing field in a request is answered
with an invalid-request status rather than a remote error. Everything the
reference's `rngit` does beyond this transport (creation, permissions, forks,
mirrors, releases, work documents, signing, statistics, pages) is covered by
the sections that follow.

Evidence: a real `git clone`, `push`, `pull`, branch push and delete, push of
history the node already has, and permission checks (read, write, none, unknown
repository) in three pairings against an unmodified reference: the reference
helper with the C node, the C helper with the C node, and the C helper with the
reference server. Handler tests send the requests a git client never would
(writes without permission, hostile ref names, an unidentified peer). The tests
fail when the write check of the push handler, the `refs/` restriction of
delete or the ref rules are removed. Not tested on real radio links.

### rngit management: create and permissions (`feature/rngit-manage`)

`/git/create` makes a bare repository in a group for an identity that holds the
group's create permission (an administrator of the group passes every
permission), writes `NAME.allowed` with `adm:<creator>` and loads it at once.
`/mgmt/perms` reads and replaces the group's (`gperms`) or a repository's
(`rperms`) permission file. Every statement is checked before the file is
replaced atomically, an executable file can only be changed node-side, and the
permissions are reloaded from the file plus the config's `[access]` line. The
reference's quirks are kept on purpose: setting a repository's permissions needs
administration of the group as well as of the repository, and an administrator
whose own read is set to `none` is locked out of editing. A name that starts
with a dot is refused (the reference only refuses names that exist already).

`reticulum-c-git-admin --connect HOST:PORT create URL`, `gperms URL get|set
FILE|-` and `rperms URL get|set FILE|-` take the place of `rngit create` and
`rngit perms`; where the reference opens `$EDITOR`, `set` reads a file.

Evidence: handler tests (create with and without the right, existing, dotted and
unknown names, the group and repository permission paths with their refusals,
invalid statements, executable files) fail when the create check or the
executable guard is removed; and the round trip creates a repository, pushes into
it, sets its write permission to `none` and back, and edits the group file, with
the reference `rngit create` and `rngit perms` against the C node and the C tool
against the reference node.

### rngit: forks, mirrors, releases, work documents, signing (`feature/rngit-complete`)

SDK additions the protocol needed, each with tests that fail without it:
a handler can read the caller's public key (`rnc_responder_request_identity`),
can keep the node serviced while it works (the responder can be ticked from
inside a handler; no second handler starts and a link that closes meanwhile is
released afterwards), and can answer later (`rnc_responder_defer` and
`rnc_responder_reply`, with `rnc_service_extend_request` lengthening the 30 second
request window). Up to sixteen request paths can be registered per destination.

`/git/fork`, `/git/mirror` and `/git/sync` fetch from another repository with
git itself (`rns`, `http`, `https` and `ssh` sources), so an `rns://` source goes
through `git-remote-rns`: the node puts a link to the helper beside it on the
`PATH` and points it at its own node and client identity. The work runs in a
child process and the reply is deferred, so the node stays responsive, and a
repository can fork from another repository on the same node (answered by the
node while the child waits). A fork keeps its own HEAD, a mirror follows the
source's; `[rngit] mirror_interval` (hours, 24 by default, 0 to disable) syncs
mirrors from the main loop. Eight such jobs may run at once.

`/mgmt/release` serves the reference's release store (`NAME.releases/TAG` with
`META`, notes, `THANKS`, `artifacts/`): list, view (`latest` is a tag), fetch (a
file response with the artifact name as metadata), and create in three steps
(init, artifacts, finalize) plus delete and set-latest, with the same
permissions. Differences: a tag or artifact name must be one plain path
component (the reference would remove the parent of the releases directory for
the tag `..` and read outside the artifact directory), and an artifact is held
in memory (at most 15 MiB, and not empty).

`/mgmt/work` serves work documents (issues and proposals) in the reference's
on-disk format (`NAME.work/{active,completed,proposed}/ID/root`, numbered
comments, `ID.allowed`): list, view, create, propose, edit, comment, delete,
complete, activate and per-document permissions, with the same permission rules
(a document's own list, then the repository's, then the group's), author
signatures checked against the caller's identity (create and propose over the
stripped text, edit over the text as sent) and the 256 KiB limit. Difference:
deleting a document without a permission file works (the reference fails there,
which in practice means only proposals can be deleted).

`reticulum-c-git-admin` gained `fork`, `mirror`, `sync`, `release`
(`list`, `view`, `create`, `fetch`, `verify`, `delete`, `latest`) and `work`
(`list`, `view`, `create`, `propose`, `edit`, `update`, `complete`, `activate`,
`delete`, `perms`) commands; text that the reference takes from `$EDITOR` comes
from `-m`, `-F` or standard input. Release manifests are RSG envelopes
(signature plus MessagePack: hash, signer and public key, embedded notes and a
signed envelope per artifact) written and verified like the reference's; a local
`.rsm` file can be verified offline.

`reticulum-c-git-cs` is the counterpart of `rngcs`: a git `gpg.ssh.program`
that signs and verifies commits and tags with a Reticulum identity (SSHSIG
carrying an RSG envelope). Use it with `gpg.format=ssh`,
`gpg.ssh.program=reticulum-c-git-cs` and `user.signingkey=<identity file>`; the
author or tagger email must be the 32 character identity hash, and the allowed
signers file is not consulted. Its signatures are byte-identical to the
reference tool's for the same identity and payload, and each tool verifies the
other's.

Evidence: handler tests for releases and work documents (permissions, signatures,
traversal attempts, state changes) that fail when the guards are removed;
`git_manage.sh` runs fork, mirror, sync, a release (create, list, fetch,
verify offline, tamper detection, wrong signer, delete) and a work document
(create, list, view with signature check, edit, comment, complete, activate,
delete) three ways: the C admin tool against the C node, the unmodified reference
`rngit` subcommands against the C node, and the C admin tool against the
unmodified reference node (releases and work documents there). Not tested with
real radio links.

### rngit: statistics and the page server

`[rngit] record_stats = yes` records per-day view, fetch, push, download and
release-download counters in the reference's stats file (loaded at start,
persisted every 180 seconds and at exit; a corrupt file is moved to
`stats.unreadable`). `stats_ignore_identities` skips identities; the
reference reads `stats_push_ignore_identities` but never uses it, and so does
this node. The stats page honours the `s` permission, the 90 day window and the
activity score. The reference shares one set of zeroed counters between all
repositories until the file is reloaded; this node keeps them per repository.

`[pages] serve_nomadnet = yes` adds a second destination, `nomadnetwork.node`,
announced with `node_name` as application data, serving the reference's pages
with the same paths, fields and permission checks: front, group, repository,
tree, blob, commits, commit, refs, stats, releases, release, work and work
document pages, plus artifact, download, media and work-document downloads. Files
`CONFIG/templates/NAME.mu` replace the built-in templates (`{PAGE_CONTENT}`,
`{NODE_NAME}`, `{VERSION}`, `{NAVIGATION}`, `{GEN_TIME}`); `unicode_icons` and
`media_conversion` work as in the reference, and images and video are converted
to WebP with magick, convert, gm, ffmpeg or avconv (or `RNGIT_MEDIA_BACKEND`),
the original being served when no backend exists. Markdown in READMEs, release
notes and work documents is converted to micron, and commit signatures made
with `reticulum-c-git-cs` are shown as the reference shows them.

Differences from the reference: syntax highlighting is a compact built-in
tokeniser (C and C++, Python, JavaScript and TypeScript, shell, JSON, YAML,
TOML and INI, Markdown, Rust, Go, Java, HTML and XML, CSS), not pygments, so
token classes are simpler and unknown languages are shown plain;
`[pages] highlight_syntax = no` (or `RNGIT_HIGHLIGHT=plain`) turns it off.
Display width uses a built-in wide and combining character table
(`RNGIT_NO_WCWIDTH=1` counts code points like the reference without wcwidth).
Files and blobs larger than `max_bundle` are not served, where the reference
streams any size; diffs are capped at 512 KiB, a commit's file list at 400
files, trees at 20000 entries and a page at 3 MiB; refs with a leading dash or
newline and paths with `.` or `..` components are refused. A release without
notes is shown without a preview (the reference raises and sends nothing), and
a bad work-document download is left unanswered like the reference's. Quirks
kept on purpose: the thanks counter shows 0 on the call that creates its file,
work-comment format is always markdown, and the work-document download treats
the scope `proposed` as `active`.

Evidence: handler tests for the page server and statistics (permissions,
traversal, each page type, stats recording and persistence, the highlighter),
whose mutants fail them, and a differential test that starts the unmodified
reference node and the C node over the same repositories (a signed and a
foreign-signed commit, a 130 commit history, releases, signed and tampered work
documents, binary, CRLF and UTF-8 files, a PNG converted to WebP) and compares
119 identified and 7 unidentified answers after masking generation time,
relative times, version, destination hash and the stats numbers: no
differences. The SDK gained `rnc_responder_request_link_id` and room for 24
request paths per destination.

## Microcontroller port: portable crypto, capacity profile, ESP32 and nRF52 firmware

The core library has an internal crypto backend interface
(`src/crypto_backend.h`): SHA-256, HMAC, HKDF, AES-256-CBC, X25519, Ed25519,
constant-time compare and cleanse. `-DRNC_CRYPTO=openssl` (the default) keeps the
behaviour the library always had; `-DRNC_CRYPTO=portable` links no OpenSSL at all:
Monocypher 4.0.2 (vendored, unmodified, see PROVENANCE.md) supplies X25519 and
Ed25519, and SHA-256, HMAC, HKDF and AES-256-CBC are written in portable C (AES
uses table lookups, a cache-timing tradeoff on chips without a hardware AES
engine). The reference's RPC handshake needs MD5, SHA-384 and SHA3, which the
portable backend carries too (about 3 KB; `RNC_PORTABLE_NO_RPC_DIGESTS` drops
them for firmware without RPC). Token and identity encryption now works in the
caller's buffer, which removed a per-call allocation of up to 16 MB.

Every capacity constant (MTU, node tables, queues, windows, responder and service
slots) can be overridden at compile time, and `-DRNC_PROFILE=mcu` selects a small
profile (`rnc_profile_mcu.h`; a custom header via `RNC_PROFILE_HEADER`). The MTU
stays at the Reticulum default of 500. The host profile is unchanged: a link is
920 KB there and 11 KB in the mcu profile. A node with two destinations, a
responder and two active links with services peaks at 86 KB of heap (about 7.7 KB
of stack measured; use at least 12 KB). The constants size public structures, so
every consumer of the headers must be built with the same profile.

Evidence: known-answer tests (NIST, RFC 4231, 5869, 7748, 8032) pass on both
backends, a differential test runs 57,000 random comparisons between them
(mutations of the AES polynomial, the HKDF counter and a SHA-256 rotation each
fail both), the existing suite passes with the portable backend (also with no
OpenSSL installed, and under sanitizers), and the interop tests against the
unmodified reference pass with the portable backend. In the mcu profile 131 of
164 core tests pass; the rest assume an MTU above 500 or feed many packets
without draining events and are not applicable there. The reference
Python RNS reaches the example firmware logic through a node and gets correct
`/echo` and `/info` answers.

Firmware: an ESP-IDF component and example (esp32 and esp32s3; the images are
317 KB and 341 KB with 12 and 14 KB of static RAM) and a PlatformIO/Arduino
project covering Heltec V3 and V2, a T-Beam, a LilyGo T3-S3 and the nRF52840
boards RAK4631, Heltec T114 and LilyGo T-Echo (203 KB of flash and 13 KB of static
RAM on nRF52, leaving about 115 KB of heap after the node and a 16 KB task). The
firmware clock is a build-time epoch plus uptime with a persisted high-water mark
so announces stay fresh across reboots (policy in `rnc_mcu_app.h`). All builds run
in CI and in the release. Not verified: any run on hardware (flashing, USB CDC,
the nRF52 bootloader flow, real heap use), a LoRa radio on air (see the next section), the T-Deck (no PlatformIO board), and whether
the T114, T-Echo and RAK4631 use the Adafruit bootloader and S140 memory map their
derived board definitions assume.

### Wi-Fi transport and LoRa radio (mcu)

Wi-Fi: the ESP32 firmware connects to a node's TCP interface (HDLC framing) and
reconnects and re-announces when the node restarts. Host tests drive the same app
logic against a real `reticulum-c-node`, including a node kill and restart, and
the reference Python RNS reaches it afterwards. The lwIP/Wi-Fi calls and NVS
handling are compiled but have not run on a board. Credentials are provisioned at
run time; the release packaging refuses images with compiled-in credentials.
Flash and RAM grow substantially (ESP32 app 251 KB to 775 KB with Wi-Fi).

LoRa (`mcu/radio/`, portable C behind a small HAL): SX126x and SX127x drivers, the
RNode air format (one header byte with a random sequence nibble and a split flag,
packets over 254 bytes in two frames, explicit header, CRC, private sync word),
time on air, listen-before-talk and an hourly airtime budget. The facts come from
reading the GPL RNode firmware; no code was copied (PROVENANCE.md). Bit rate
matches the unmodified reference RNodeInterface for all 320 settings and time on
air matches published Semtech values. The low-data-rate rule follows the RNode
firmware's integer rule, which differs from the datasheet at SF12/250k, SF11/125k,
SF10/62.5k and SF9/31.25k, because a mismatch makes the ends undecodable. Known
difference: a 508-byte packet is sent as two frames (the RNode adds a third,
header-only frame); Reticulum never sends more than 500. On receive, stale orphan
halves expire and duplicates are dropped, which changes nothing that is sent.
Modes: off (default), leaf, gateway (transport only there); the mcu profile limits
a gateway to two interfaces.

Evidence: driver tests against strict command-level SX126x and register-level
SX127x models, frames between the two families, a shared-medium simulator with
loss, collision and hidden-node cases, two app instances speaking Reticulum over
simulated LoRa (announce, path request, link, `/echo`, `/info`, a 900-byte
Resource), a default-build `reticulum-c-node` reaching a simulated board through a
simulated gateway, and 30 of 30 mutations caught. Not verified: anything on real
chips or on air, interop with a real RNode (the models were written from the same
datasheets as the drivers, so a shared misreading would pass), TCXO voltages, board
pins, the AXP192 sequence, CAD parameters (implemented, unused by the interface).
