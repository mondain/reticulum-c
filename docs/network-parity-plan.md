# Reticulum network functionality implementation plan

User authorization: proceed with implementations to eliminate the audited gaps.
C11, MIT, Linux first, macOS second, Windows last. RNS 1.5.5 at
`e40191b3d193b46b7f2d8a44424a594cd758839b` is the protocol baseline. Read the
Reticulum Manual 1.5.5 in text form before the reference source. External
implementations are test oracles only. No implementation is copied from them.

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
PR implements the SDK APIs and records the coverage actually executed. Live
external Resource/service sessions, AutoInterface multicast deployment, physical
radio, Windows and a third reference stack remain future validation work.
Differential fixtures, PTYs and successful compilation do not replace those
checks or establish complete-stack compatibility.

Independent final source review covers protocol and node/host changes. Confirmed
Important findings must be reproduced, fixed with regression coverage and
validated before the PR is marked ready. No publication or compatibility claim
may include private downstream project details.
