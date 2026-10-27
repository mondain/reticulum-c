# SDK 0.2 PR readiness record

## Scope

[PR #2](https://github.com/mondain/reticulum-c/pull/2) adds a bounded C11 SDK
with a sans-I/O protocol core and a separate optional POSIX host. Version 0.2.0
uses shared ABI 1 because public packet/events support MTUs up to 4096.
Default MTU remains 500 and the default Channel TX window remains two messages.
OpenSSL 3 is required; BZip2 compression is enabled by default and can be disabled.
External implementations are optional test oracles, never runtime dependencies.

The implementation includes routing/path discovery, IFAC and ratchet security,
GROUP/PLAIN primitives, Buffer streams, segmented Resources, request/response
services, MTU negotiation, TCP/UDP/AutoInterface/serial/KISS/RNode adapters,
a node daemon, signed checkpoints and authenticated shared-instance RPC.

## Completed preparation

- Registered protocol, allocation-failure/collision, host, daemon/RPC/process,
  security/IPC oracle and direct/two-router large-MTU tests in CMake.
- Fixed terminal malformed bulk receive-slot recovery and completed Resource
  advertisement proof replay blocking subsequent bulk requests. Both regression
  tests failed before their fixes and now pass. Application queue backpressure
  retains completed input until the queue is drained.
- Fixed the shared test executable's direct BZip2 link dependency.
- Made the C network harness wait for RNS interface readiness before its first
  announce. Both direct/routed server cases passed ten consecutive runs after
  reproducing the oracle's TCP-read/IFAC initialization race.
- Verified static, shared, compression-disabled and sanitizer/leak builds,
  relocated installation, real loopback/PTY processes and pinned oracles.
- Updated standalone README, API, compatibility and provenance documentation.
- Completed independent final source reviews of protocol and node/host/IPC/
  daemon changes with no blocking findings. The node/host reviewer additionally
  passed 16 focused native tests in the Clang18 sanitizer build.

## Verified snapshots

Protocol/test implementation `f6e59211fb6432eaf664209fff3ddf2a6d4c4014`
passed the local Linux matrix: RNS 88/88, shared 62/62, compression disabled
61/61, Clang18 ASAN/UBSAN/LSAN 62/62 with leak detection, and Leviculum 65/65.

Documentation correction `8a22d1f3781defb57acc1bdab25b7d0c234a95aa` passed
all seven [hosted CI jobs](https://github.com/mondain/reticulum-c/actions/runs/40426146410):
Linux static/shared/compression-disabled/sanitizers, macOS, RNS and Leviculum.
The complete RNS suite was also rerun locally at this snapshot: 88/88 passed.
See [compatibility evidence](../COMPATIBILITY.md) for the exact scope.

## Reproduce

From the SDK root with the pinned RNS checkout and an oracle virtual environment
containing cryptography and pyserial:

```sh
cmake -S . -B build-rns \
  -DRNC_INTEROP_TESTS=ON -DRNC_REFERENCE_DIR=/absolute/path/to/Reticulum \
  -DPython3_EXECUTABLE=/absolute/path/to/oracle-venv/bin/python
cmake --build build-rns -j4
ctest --test-dir build-rns --output-on-failure
```

Socket/process and LeakSanitizer tests require an environment that permits
loopback sockets and process tracing. `-LE network` runs a narrower selection;
it does not establish live interoperability. Local sandbox failures were not
counted as passing checks.

## Verification limits

External Resource/service/security/RPC method fixtures establish differential
behavior; they are distinct from live external Resource/service sessions.
Physical radio, AutoInterface multicast deployment, Windows and additional
reference implementations remain unverified. Those require separate execution
and are outside the verified scope of this PR. This is an
experimental SDK expansion, not a release or a complete-stack certification.
