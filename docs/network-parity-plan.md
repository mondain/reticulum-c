# Reticulum network functionality implementation plan (historical)

This is the completed SDK 0.2 expansion plan for PR #2, retained as a design
record. It is not an outstanding implementation queue. For current features and
remaining gaps, use [compatibility](../COMPATIBILITY.md) and the
[gap inventory](spec-gap-list.md); dated verification is in the
[readiness record](resume-status.md).

Original authorization: implement the audited SDK expansion.
C11, MIT, Linux first, macOS second, Windows last. RNS 1.5.5 at
`e40191b3d193b46b7f2d8a44424a594cd758839b` is the protocol baseline. The original
review used the Reticulum Manual in text form before the reference source. External protocol
implementations served as test oracles, not runtime dependencies; this statement
is scoped to the protocol core, not the browser dependencies listed in
[provenance](../PROVENANCE.md).

## Design and boundaries

Keep protocol state machines sans I/O. Input, monotonic time, Unix time,
randomness, packet delivery and persistence are supplied by the caller. New
protocol modules are independently usable; hosts compose them with links.
Bound all queues, tables and transfers; invalid/authentication-failing input
must not commit output/state. RNC_AGAIN is retryable without partial consumption.
Preserve existing default link behavior and public API compatibility.

The node engine owns interface IDs, destinations, announcement/path management,
packet duplicate/reverse/link routing and caller-drained events. Host adapters
own actual descriptors, configuration, persistence and administrative sockets.
Transfer/service engines own application protocol state and pass context-tagged
plaintext through the link's authenticated raw-packet API. Stream readers/writers
use the standard Channel system message 0xff00 and preserve EOF/backpressure.

## Implementation and verification status

- [x] Isolated feature worktree and C-only library/test implementations.
- [x] IFAC, ratchet generation/rotation/persistence/encryption, signed ratcheted
  announces, GROUP keys and PLAIN destination hashing. Unit and pinned RNS
  differential checks cover byte compatibility, tampering, expiry and bounds.
- [x] Authenticated context-tagged Link packets, Buffer streams, bounded adaptive
  Channel windows and MTU negotiation. Defaults preserve earlier Link behavior.
- [x] Segmented Resources, optional bounded BZip2 compression, flow control,
  cancellation, integrity proofs and request/response services. C pairs and
  pinned RNS differential fixtures cover both roles and recovery/bounds.
- [x] Bounded mesh routing, path requests, signed announce freshness, forwarding,
  reverse proofs and transit links. In-memory multi-hop and actual direct/
  two-router RNS Channel sessions, including loss and large MTU, pass.
- [x] Optional POSIX host and node daemon, identity/checkpoint persistence,
  configuration reload, native administration and authenticated MessagePack
  shared-instance RPC. Real TCP/UDP/process/serial-PTY checks pass.
- [x] Standalone node/text examples and relocated installed SDK consumption,
  static/shared builds and compression-disabled configuration.
- [x] Linux static/shared/sanitizer/leak/compression-disabled, macOS and pinned
  RNS/Leviculum hosted jobs. Exact evidence is linked in
  [the readiness record](resume-status.md) and [compatibility](../COMPATIBILITY.md).

## Explicit verification boundaries

The original audit included wider interoperability and hardware goals. This
record describes what PR #2 implemented and verified at its own snapshot.
Physical radio was outside that original evidence. Subsequent T-Echo/Supreme
SX1262 bench flashing and LoRa exchanges are recorded in the current
[readiness record](resume-status.md). They do not establish range, sustained-load
or stock RNode radio interoperability. AutoInterface multicast deployment,
Windows and a third reference stack remain separate validation work.
Differential fixtures, PTYs and successful compilation do not replace those
checks or establish complete-stack compatibility.

Independent final source review covers protocol and node/host changes. Confirmed
Important findings must be reproduced, fixed with regression coverage and
validated before the PR is marked ready. No publication or compatibility claim
may include private downstream project details.
