# reticulum-c compared with the reference Python Reticulum: pros and cons

This page summarises what using reticulum-c gives you, and what it costs, relative to the
reference implementation (RNS, the Python version). It is a reading aid. The sources of truth
are [spec-gap-list.md](spec-gap-list.md) (feature by feature), [../COMPATIBILITY.md](../COMPATIBILITY.md)
(what was tested and when) and [../mcu/README.md](../mcu/README.md) (firmware, limits, bench results).
Where this page and those disagree, they win.

## Summary

reticulum-c is a C implementation of the Reticulum protocol: a library (`src/`), a node daemon
and command-line tools (`examples/`), and firmware for microcontroller boards (`mcu/`).
It interoperates with the reference on the wire; the project's CI runs both against each other.
It is not a drop-in replacement for the reference. Choose it when you need to run Reticulum where
Python cannot, or when you want a small native binary. Choose the reference when you need the
broadest feature set and the application ecosystem.

## Pros

- **Runs on microcontrollers.** The firmware runs the Reticulum stack on nRF52840 and ESP32
  boards with no operating system: announces, `/echo` and `/info` requests, LoRa leaf and
  gateway modes, and an RNode mode that lets a host drive the radio over USB. Nine board
  targets are built and released. The reference needs a full Python runtime and has no
  equivalent firmware of this kind.
- **Small footprint.** The node, a responder and two links use about 86 KB of heap in the
  microcontroller profile (about 92 KB with the application's buffers), measured by
  `tests/footprint.c`. The daemon is one native binary with no interpreter, virtualenv or
  pip dependencies, which suits routers, containers and small single-board computers.
- **Embeddable.** It is a C library with an event-based API. Other programs and other languages
  can link it. The reference can only be embedded in a Python process.
- **Predictable resource use.** Tables and queues are bounded, there is no garbage collector,
  and startup is fast. On a device with a few hundred KB of RAM this matters more than speed.
- **Interoperates with the reference.** Interop workflows exercise it against the reference
  RNS and against leviculum. `rncp`, `rnx` and `rnsh` are recorded as compatible with the reference in
  both directions, and the over-the-air echo and info exchange worked with the reference RNS. A mixed network works.
- **A familiar configuration.** `reticulum-c-node` reads a Reticulum-style config file, including
  `RNodeInterface`, `TCPServerInterface`, `TCPClientInterface`, and the shared-instance and RPC
  options, so an existing setup moves over with little change.
- **Tested.** The suite includes host unit and process tests, sanitizer builds, macOS and Linux
  matrix builds, firmware builds for every board in CI, and web flasher unit and UI tests.
- **Easy to put on a board.** A browser flasher and release archives cover the supported boards,
  and the firmware has a serial setup console (`rnc-config`).

## Cons

- **Not the reference.** New protocol features and fixes appear in the reference first. This
  project follows a pinned reference commit, so it can trail it. A gap listed as closed in
  `spec-gap-list.md` records implementation coverage, not full protocol conformance.
- **Smaller ecosystem.** The Python applications (Sideband, NomadNet, MeshChat and others) are
  written against the reference. They work with this stack as peers on the network, but they do
  not run on it.
- **Feature gaps in the tools.** The command-line tools are subsets of the reference tools:
  - `rnstatus`/`rnpath`: no announce, path request or burst statistics (`-a`, `-A`, `-P`, `-B`,
    `-b`, `-t`, `-p`, `-q`, `-z`); `held` is always 0.
  - `rnodeconf`: no firmware download, update, extraction, autoinstall, EEPROM provisioning,
    backup, dump or wipe, signing keys or trusted-keys directory. Flashing is a separate tool
    (`reticulum-c-flash`, ESP32 family) and the browser flasher.
  - `rncp`: files over 16 MiB are held in memory; there is no `--config` option.
  - `rnx`: commands stop after 25 s, requests and responses are limited to about 64 kB, and
    there is no accept-anyone mode.
  - `rnsh`: no line-interactive mode, no reload of the allowed file while running, no
    compression of sent stream data.
  - `rnid`: no editor for a message given on neither the command line nor a file; no network
    identity requests.
  - There is no interactive Python shell (`-i`); it is refused with a pointer to `reticulum-c-ctl`.
- **Fewer stand-alone examples.** Announce, request and echo have runnable examples. Ratchets,
  broadcast/PLAIN, GROUP, link, identification, channel and buffer are covered by library tests
  only.
- **API differences.** Events and polling replace Python callbacks. There is no per-link physical
  signal tracking by default. Bounded tables and queues have different capacities from the
  reference.
- **Small devices have small limits.** The MCU profile keeps paths for one day and evicts the
  least recently used route when its table is full. A gateway is a small bridge, not a repeater
  for a busy network. Transport is off in every mode except gateway. On the ESP32 Wi-Fi mode
  the image is much larger (about 775 KB against 251 KB) and it is a TCP client only (no access
  point, AutoInterface, UDP, TLS or IFAC).
- **Firmware security limits.** The Wi-Fi password and settings sit unencrypted in flash, and
  the TCP link is plaintext as in any Reticulum TCP interface. The firmware has no IFAC.
- **Thin hardware evidence.** Short bench runs exist for a T-Echo, a T-Beam Supreme and a Seeed XIAO nRF52840 with
  Wio-SX1262 and a Heltec V3 (dated list: "Bench record" in `mcu/README.md`). One of them found a real fault: the Supreme lost bytes
  over USB until 0.7.1. Range, sustained load and long-term reliability are not established. Wi-Fi mode, the ESP-IDF
  boards and the ESP32 BLE build are build-tested, not hardware-tested. The XIAO has not been checked with BLE
  against its SoftDevice 7.3.0 bootloader.
- **Stock RNode hardware is unverified.** The host RNode adapters were checked against this
  project's own RNode-mode firmware and an emulated RNode, not against a stock RNode device.
- **Young, small project.** The repository records no independent security audit of the
  cryptographic code. Two crypto backends exist (OpenSSL, and vendored Monocypher for the
  portable build), and each needs its own confidence.

## When to choose which

| You want to | Use |
| --- | --- |
| Run Reticulum on a microcontroller or a LoRa board | reticulum-c firmware |
| Turn a supported board into an RNode for a host | reticulum-c firmware in RNode mode |
| Run a transport node on a small or locked-down machine without Python | `reticulum-c-node` |
| Embed Reticulum in a C or C++ program | the reticulum-c library |
| Use Sideband, NomadNet, MeshChat or other Python applications | the reference RNS (this stack can be a peer or transport for them) |
| Have every reference utility option, or follow protocol changes first | the reference RNS |
| Mix both on one network | either; they interoperate |

## Corrections to other documents

- `spec-gap-list.md` records that host RNode adapters are unverified against stock RNode
  hardware. That remains true, but the project's own firmware has since been driven by both the
  reference RNS and `reticulum-c-node` over the air (XIAO to T-Beam Supreme, 915 MHz, 0.5.3).
