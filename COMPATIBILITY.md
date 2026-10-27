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
