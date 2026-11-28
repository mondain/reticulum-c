# SDK 0.2 readiness and validation record

## Current status

Latest release: 0.8.0 (2026-11-28). The entries below are the 2026-11-14 snapshot. Hardware checked since then is
recorded with dates in "Bench record" in [mcu/README.md](../mcu/README.md) (T-Echo, T-Beam Supreme, XIAO nRF52840,
a Raspberry Pi gateway over Wi-Fi HaLow and LoRa) and in [COMPATIBILITY.md](../COMPATIBILITY.md); the reference
Python RNS and Leviculum interoperability jobs run on tags and on demand, not on every push.

### Snapshot of 2026-11-14

The [browser firmware installer](https://mondain.github.io/reticulum-c/) is live.
Its first published build is `main-8b46e4b63da4`, sourced from merge commit
`8b46e4b63da4aee4260307d49dcc30be5d87dba1` ([PR #41](https://github.com/mondain/reticulum-c/pull/41)).
The catalogue identifies the source revision of every offered build; this is
separate from tagged release archives such as the earlier `v0.2.0-rc4`.

Validation recorded at that implementation snapshot:

- Local Linux default static Debug/OpenSSL build: 251/251 tests, with BZip2,
  POSIX host and examples enabled. External RNS/Leviculum oracles and sanitizers
  were not enabled in this run.
- Firmware publication validation: 27 Python cases; browser transport and
  configuration checks: 31 JavaScript cases; seven Chromium UI regressions.
- All eight PlatformIO board builds and the selected Supreme ESP-IDF build pass.
  The [Pages build and deployment](https://github.com/mondain/reticulum-c/actions/runs/43635333668)
  completed successfully. The separate hosted SDK CI run for that commit was
  cancelled; it is not additional passing cross-platform or oracle evidence.
- Real T-Echo application-only JavaScript DFU completed with acknowledgements.
  Real Supreme flashing verified all four ESP32 parts by MD5, retained settings,
  and acknowledged provisioning-console `get` and `reboot`.
- A T-Echo leaf and Supreme SX1262 gateway exchanged LoRa packets at 915 MHz,
  BW 125 kHz, SF8, CR 4/5, 0 dBm and a 1% hourly airtime limit. A host reached
  the T-Echo through USB, Supreme and LoRa at three hops, verifying a 10-byte
  `/echo` reply and receiving `/info`; one request required a retry.

Only those two board profiles have hardware bench evidence. Range, sustained
load, other boards, actual Wi-Fi deployment and on-air stock RNode
interoperability remain unverified. See the current [README](../README.md),
[compatibility record](../COMPATIBILITY.md) and [release instructions](releasing.md).

The sections below retain the original PR #2 preparation and evidence. Their
snapshot counts and verification limits describe that historical milestone,
not the current feature inventory or a new certification claim.

## Original SDK expansion scope

[PR #2](https://github.com/mondain/reticulum-c/pull/2) adds a bounded C11 SDK
with a sans-I/O protocol core and a separate optional POSIX host. Version 0.2.1
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
At that original PR snapshot, physical radio, AutoInterface multicast deployment,
Windows and additional reference implementations had no execution evidence.
Those require separate execution and are outside the verified scope of this PR. This is an
experimental SDK expansion, not a release or a complete-stack certification.
