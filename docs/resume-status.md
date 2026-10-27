# Network expansion resume checkpoint

Recorded 2026-10-26 23:50 UTC. This is a development checkpoint, not a release
or a claim of complete reference compatibility.

## Location and constraints

Repository: mondain/reticulum-c, branch `feature/network-stack-parity`.
Base: `6536fb6f0a1889c428cf4cfd3f104541cc0a3e70`.
Use a dedicated worktree for this branch and preserve the main checkout.

User approved implementing the audited gaps, in C. MIT; Linux primary, macOS
second, Windows last. Protocol core remains sans I/O. External RNS, Leviculum,
and Rust implementations are optional test oracles, never runtime dependencies.
SDK version is now 0.2.0, shared ABI1 because public packet/events grew for
4096-byte MTUs; defaults remain MTU500 and a two-message Channel TX window.
BZip2 is an optional compression dependency, enabled by default.

## Implemented

- Path request codecs, signed announce caching/freshness, bounded routes,
  forwarding, return proofs, verified transit links, announce bandwidth queues,
  transparent shared-client interfaces, explicit local link binding.
- SINGLE/GROUP/PLAIN local destination registration, ratcheted announces,
  IFAC, ratchet lifecycle/persistence and GROUP encryption primitives.
- Adaptive Channels, standard Buffer streams, Resources including compression,
  metadata and segmentation, Link request/response with admission/deadlines.
- MTU negotiation up to4096, including dynamic Resource SDUs and Buffer capacity.
- Separate optional POSIX host: TCP/UDP/AutoInterface/serial/KISS/RNode, IFAC,
  bounded queues, reconnects and RNode configuration/flow-control ACKs.
- Node daemon, private identities, signed checkpoints, stable configuration-bound
  interface IDs, atomic persistence/reload, native admin and TCP shared-instance
  data/RPC. RNS1.5.5 RPC is authenticated MessagePack, not legacy pickle.

## Prior checkpoint verification

`out/parity-rns`: **63/63 socket-free CTests passed**. Includes 15 C/CPython
post-handshake differential Resource/service cases and a security oracle against
unmodified RNS1.5.5, installed SDK consumer, real serial/RNode PTY coverage and
multi-hop in-memory encrypted links. Some newly written tests are not registered
in CMake yet. Independent agents additionally ran focused ASAN/UBSAN with leak
checks disabled locally because process tracing is restricted.

Reproduce from the SDK repository root with an external reference checkout:

```sh
cmake -S . -B build-rns \
  -DRNC_INTEROP_TESTS=ON -DRNC_REFERENCE_DIR=/absolute/path/to/Reticulum \
  -DPython3_EXECUTABLE=/absolute/path/to/oracle-venv/bin/python
cmake --build build-rns -j4
ctest --test-dir build-rns -LE network --output-on-failure
```

Local sockets still fail EPERM. Actual TCP/UDP/daemon/RNS process tests must run
in hosted CI. Do not count differential method fixtures as live network results.

## Original resume queue (see resumption record below)

1. Finish the remaining confirmed review fix: `src/service.c` completed malformed
   bulk envelope errors leave `rx_ready`/`rx_binding` occupied. Release terminal
   rejected input; retain only actual event-queue backpressure. Add a regression
   that rejects malformed bulk input then completes a fresh valid bulk request.
2. Resource allocation reuse and distant-map-collision fixes just landed in
   `src/resource.c`. `tests/test_resource_failures.c` passes allocation/collision
   modes via direct C compilation, but is not registered in CMake. Re-run the
   complete differential matrix and independently review the transaction swap
   and scoped map searches. Scratch prior-review repros are under `/tmp` and
   are supporting evidence only; checked-in tests must remain sufficient.
3. Register new host tests `keys`, `rnode`, `pressure`, `udp`; register daemon
   `examples/node_daemon.c` (includes `node_rpc.h`), `test_node_rpc` and
   `test_node_process` modes `cli/network/shared/rns`. Network modes need labels.
   Add optional IPC oracle by compiling `test_ipc.c` with RNC_IPC_WITH_PYTHON=1.
4. `test_interop.c` now accepts `large` and sends a1024-byte Channel message to
   unmodified RNS. Register both direct and two-router large modes, verify actual
   network negotiation in CI. Existing local direct cases cannot run here.
5. Run normal/shared/compression-disabled/sanitizer suites, publish a draft
   preparation branch/PR, and inspect Linux/macOS/RNS/Leviculum hosted results.
   Update README/API/compatibility/provenance to match the final scope.
6. Finish independent review and publish exact verified refs. Actual radio and
   Windows execution remain unverified; no hardware or full-stack claim.

## Review evidence already addressed

Path destination hash off-by-one (frozen RNS vector), active transit-link expiry,
unauthenticated interface pinning, same-interface routing, removed-interface
queued events, oversized HEADER2, duplicate path request amplification, service
late/replayed responses and stale bulk completion, Resource quotas/duplicate HMU,
serial idle reads under backpressure, UDP errors, checkpoint configuration
binding and retry after partial state-write failure.

## Resumption verification, 2026-10-27 UTC

Resume items 1-4 are implemented and verified. The terminal malformed bulk
envelope regression failed before the fix (same input rejected repeatedly),
then completed a fresh valid bulk request/response after the fix. Independent
review found a second receive-binding leak on completed advertisement replay;
its checked-in regression also failed before the fix and now passes. Queued
backpressure retains the completed input until the application drains events.
Resource allocation/collision fixtures, host key/RNode/pressure/UDP modes,
daemon/RPC/process modes, IPC differential oracle, and direct/routed large-MTU
network cases are now registered in CMake. Shared test_stream explicitly links
its direct BZip2 dependency. CI adds a compression-disabled Linux variant.

Final Linux matrix: static+RNS 88/88; shared 62/62; compression disabled 61/61;
Clang18 ASAN/UBSAN/LSAN with detect_leaks=1 62/62; Leviculum 65/65. These include
actual loopback/process/PTY execution outside the sandbox. A parallel RNS run
exposed the oracle's early TCP-read/IFAC configuration race. The C harness now
waits for the interface-ready log; direct/routed server cases passed ten runs
each and the complete RNS suite subsequently passed. Initial sandbox leak and
socket failures are environmental and are not counted as passing runs. A Swift
Clang17 compilation crashed under the sandbox; final sanitizer evidence uses
system Clang18 and freshly rebuilt binaries.

README/API/provenance/compatibility were updated in place. No new Markdown
files were created.

Next: publish the tested preparation branch as a draft PR and inspect hosted
Linux/macOS/RNS/Leviculum results. Continue standalone SDK example and package
validation. This checkpoint is not a release or a full-stack/hardware
certification claim.
