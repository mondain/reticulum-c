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

## Standalone preparation status

The relocated installed-package consumer and all ten socket-free tests pass
locally. The generic C text peer compiles, but its TCP process test is blocked
by the same sandbox. The optional Leviculum C driver is prepared against the
pinned API; its external library could not be built locally because an offline
Rust dependency was missing. Neither preparation alone counts as a live pass.

CI is configured to execute:

- Linux static/shared unit, text-process and installed-consumer builds.
- Linux address/undefined sanitizers with leak detection enabled.
- Pinned RNS 1.5.5 C initiator/responder/loss cases.
- Pinned Leviculum C-API initiator/responder/loss cases.
- macOS Release build and applicable process/SDK tests.

Record actual run links and conclusions here after they finish. macOS and the
new standalone live oracle remain pending until CI proves them. Windows,
multi-hop networks, IFAC, radio hardware and other implementations remain
unexecuted. Room/client/bot TCP validation belongs to the consumer's CI.
