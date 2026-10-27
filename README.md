# reticulum-c

An independent, experimental C11 Reticulum SDK with packet/identity security,
authenticated links, Channels, Buffer streams, Resources, request/response
services and a bounded routing engine. The protocol core uses OpenSSL 3 and a
sans-I/O API. A separate optional POSIX host supplies interfaces and a node daemon.

Linux is the primary target, macOS second, Windows last. This project implements
a bounded subset. See [compatibility and current
evidence](COMPATIBILITY.md) before choosing a deployment.

## Build and test

Requirements: C11 compiler, CMake 3.16+, OpenSSL 3 development files, and BZip2
development files for the default compression-enabled build.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

The default library and tests have no Python/Rust/Go dependency. The optional
POSIX text peer has a process test using loopback TCP. Where sockets are
restricted, `ctest --test-dir build -LE network --output-on-failure` runs unit
and installed-consumer tests; that selection is not live network certification.

`-DRNC_SANITIZERS=ON` enables address/undefined sanitizers with GCC or Clang.
`-DBUILD_SHARED_LIBS=ON` selects a shared library. `-DBUILD_TESTING=OFF` disables
tests; `-DRNC_BUILD_EXAMPLES=OFF` disables the POSIX examples.
`-DRNC_BUILD_HOST=OFF` disables the POSIX host and daemon.
`-DRNC_COMPRESSION=OFF` removes BZip2 and rejects compressed transfers/streams.

## Install and consume

```sh
cmake --install build --prefix "$PWD/out/sdk"
cmake -S tests/consumer -B out/consumer -DCMAKE_PREFIX_PATH="$PWD/out/sdk"
cmake --build out/consumer
ctest --test-dir out/consumer --output-on-failure
```

A consumer uses:

```cmake
find_package(reticulum_c 0.2 CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE reticulum_c::reticulum_c)
```

Source integration also works with `add_subdirectory(PATH_TO_RETICULUM_C)` and
the same target. The install test moves the SDK before configuring a separate
consumer so source-tree paths cannot accidentally satisfy its dependencies.
OpenSSL Crypto and enabled BZip2 dependencies are resolved by the installed
package configuration. Link `reticulum_c::host` when using the POSIX host API.
Version 0.2 uses shared ABI 1: public packet/events grew for configurable MTUs.
Rebuild consumers; the installed package requires a matching minor version.

## POSIX node daemon

`reticulum-c-node` reads a Reticulum-style configuration. For a loopback TCP
router, create a configuration file containing:

```ini
[reticulum]
enable_transport = Yes
share_instance = No
[interfaces]
[[Local TCP]]
type = TCPServerInterface
enabled = Yes
listen_ip = 127.0.0.1
listen_port = 7778
```

```sh
./build/reticulum-c-node --config /path/to/config --check
./build/reticulum-c-node --config /path/to/config \
  --identity /path/to/private/identity --admin /path/to/private/admin.sock
```

The optional `--state FILE` selects the checkpoint path. The daemon provides
TCP/UDP/AutoInterface and serial/KISS/RNode adapters, signed route checkpoints
and authenticated shared-instance RPC. RNS 1.5.5 RPC uses MessagePack.
SIGHUP reloads configuration; SIGINT/SIGTERM
stop the daemon. Keep identity, checkpoint and admin paths in a private directory.
Actual radio and multicast deployment require separate hardware/network checks.

## Generic C text example

This example is independent of any chat application protocol. It carries text
as Channel type `0x0101` in destination namespace `reticulum_c.text.v1`.

```sh
mkdir -p out/state
./build/reticulum-c-text listen 7778 out/state/alice.key
# In another terminal; append Alice's printed destination to pin her:
./build/reticulum-c-text connect 127.0.0.1 7778 out/state/bob.key ALICE_DEST_HEX
```

Wait for `Link active` and `Authenticated peer:` on both sides. Type a line and
observe received text and separate signed delivery confirmations. Both modes
accept an optional destination pin; without one the first valid announce
selects the peer. Signed discovery alone is not an external trust decision.
The initiator proves its identity, and the host binds it to the selected peer
announce before allowing application data.

The listener binds loopback; `listen 0 KEYFILE` reports an ephemeral port.
`/announce` reannounces. Lines are limited to 425 bytes; oversize lines are
rejected in full. A bounded 16-line outbox retains data while the two-message
Channel send window is busy. Queue exhaustion fails the connection. Stdin EOF
continues receiving; Ctrl+C/SIGTERM attempt a close with a 200 ms flush budget.
Pending application text is not guaranteed to drain during shutdown.

Keys are raw 64-byte private identities, created exclusively with mode 0600.
Existing files must be regular, owned by the effective user, exactly 64 bytes,
and inaccessible to group/others. Symlinks/FIFOs are rejected. Keep keys outside
source control. See [the API contract](API.md) for host integration and identity
versus application authorization.

## Independent interoperability oracles

Tests are authored in C. Optional oracles are unmodified external projects;
they are not dependencies of the library or installed SDK. Builds never download
an oracle automatically. Exact revisions and limitations are in
[PROVENANCE.md](PROVENANCE.md).

For upstream RNS 1.5.5, prepare its checkout and a Python environment containing
cryptography and pyserial 3.5, then:

```sh
cmake -S . -B build-rns -DRNC_INTEROP_TESTS=ON \
  -DRNC_REFERENCE_DIR=/absolute/path/to/Reticulum \
  -DPython3_EXECUTABLE=/absolute/path/to/oracle-venv/bin/python
cmake --build build-rns
ctest --test-dir build-rns -L reticulum_interop --output-on-failure
```

`RNC_INTEROP_PYTHONPATH` optionally adds dependency directories. The C harness
runs unmodified `Examples/Channel.py` as each protocol role, directly and through
two C routers. A large-MTU case exchanges a 1024-byte Channel message. A loss case drops
one data packet and one proof, requiring retransmission and single delivery.
The oracle uses type `0x0101` and a MessagePack payload; it is distinct from the
text peer's raw application payload despite using the same Channel type value.
Additional C/CPython fixtures compare Resource/service wire behavior and
security/RPC primitives. These differential fixtures are distinct from live
process interoperability; use the test labels and compatibility record.

For the pinned Leviculum oracle, build its external FFI library and generated
header for a glibc Linux target. Its shared-library SONAME must resolve in its
library directory. Configure `RNC_LEVICULUM_TESTS=ON`,
`RNC_LEVICULUM_REFERENCE_DIR` and `RNC_LEVICULUM_LIBRARY`. The optional C harness
uses its C API and raw-bytes Channel type 0. The CI workflow records the exact
build and runs both roles plus a loss case. Tests require loopback sockets.

## Scope

Implemented: X25519/Ed25519 identities, HKDF-SHA256/AES-256-CBC/HMAC-SHA256,
SINGLE encryption, destination hashes, HEADER_1/HEADER_2 packet codecs, HDLC,
ordinary announce creation and ordinary/ratcheted verification, authenticated
links with initiator identity proofs, keepalives/close/timeouts, typed reliable
Channels with bounded queues, ordering, duplicates and fresh-IV retries; IFAC,
ratchet lifecycle/encryption, GROUP/PLAIN primitives, path discovery/forwarding,
Buffer streams, segmented Resources, request/response services, configurable
MTUs up to 4096, optional POSIX interfaces and persistent node state.

Defaults remain MTU 500 and a two-message Channel TX window. The implementation
does not claim complete RNS API/configuration compatibility. Radio hardware,
Windows, codecs and media devices have no execution evidence here.
Keepalives provide unauthenticated liveness, not identity.
SINGLE datagrams alone do not authenticate a sender or prevent replay.

MIT licensed; see [LICENSE](LICENSE) and [provenance](PROVENANCE.md).
