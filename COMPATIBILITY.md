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
