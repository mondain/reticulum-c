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
key persistence/permissions, oversized/EOF input and shutdown. The historical
combined consumer/codec build passed 33/33 and sanitizer build 29/29.

Later room integration passed encrypted in-memory tests, but the subsequent
sandbox denied socket creation (EPERM) and LeakSanitizer process tracing. Those
runs do not refresh live network or leak evidence. The room/bot adapters and
application protocol remain in the separate consumer project.

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

The separate Chitchatr consumer snapshot
`7c03cb0d7e9ac0c978602e75b7c9663cb7e07ff4` passed
[26/26 tests in normal and sanitizer/leak builds](https://github.com/mondain/chitchatr/actions/runs/40402377485).
Those runners install a pinned SDK and remove the bundled protocol directory
before configuring. Actual TCP room/client/bot cases include synchronization,
full text, private replies, room isolation/moves, disconnect/reconnect, wrong
pins and admission denial. Its application adapters remain outside this repo.

Locally, the original sandbox still denies sockets/LeakSanitizer tracing. Static
and shared SDK socket-free tests each pass 10/10, installed-package consumer
21/21 and source-provider consumer 30/30. Those local selections supplement,
and do not replace, the hosted network/leak results above.

Windows, multi-hop routing, IFAC, radio hardware and other implementations remain
unexecuted. The passing matrix certifies only the tested subset at these exact
revisions. It does not establish complete Reticulum stack or radio compatibility.
